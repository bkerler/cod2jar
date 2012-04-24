#! /usr/bin/env python

# Copyright (c) 2012, derrotehund361@googlemail.com
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution. 
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
resolve: Tools for resolving the raw parsed bytes of a COD into high-level types.
"""

from bytecleaver import *
import format, utils, disasm
import itertools
import sys
import os.path
import cPickle
from struct import pack, unpack
import zipfile
from StringIO import StringIO

# Constants
#----------------------------------------------------------

ACC_FLAGS = ['public', 'private', 'protected', 'final']
MODE_FLAGS = ['static', 'abstract']

# Helpers
#----------------------------------------------------------
class LazyLoader(object):
    __slots__ = ['_lazy_module_name', '_lazy_name', '_lazy_loader', '_lazy_ref']

    def __init__(self, module_name, name, loader):
        self._lazy_module_name = module_name
        self._lazy_name = name
        self._lazy_loader = loader
        self._lazy_ref = None

    def _lazy_load(self):
        raise NotImplementedError("No lazy-loading logic defined for %s" % self.__class__)

    def __str__(self):
        ref = object.__getattribute__(self, '_lazy_ref')
        try:
            if ref is None:
                ref = object.__getattribute__(self, '_lazy_load')()
        except AttributeError:
            pass
        #return object.__getattribute__(self, '_lazy_name')
        return str(ref)

    def __repr__(self):
        ref = object.__getattribute__(self, '_lazy_ref')
        if ref is None:
            return "<lazy-loader: '%s'>" % object.__getattribute__(self, '_lazy_name')
        else:
            return repr(ref)

    def __getattribute__(self, name):
        ref = object.__getattribute__(self, '_lazy_ref') or object.__getattribute__(self, '_lazy_load')()
        return getattr(ref, name)

class LazyModule(LazyLoader):
    def _lazy_load(self):
        ref = object.__getattribute__(self, '_lazy_ref')
        if ref is None:
            # Get the loader object and the name of the module to load
            loader = object.__getattribute__(self, "_lazy_loader")
            mod_name = object.__getattribute__(self, "_lazy_name")

            # Load and set our internal reference
            ref = self._lazy_ref = loader.load_module(mod_name)

            # These are no longer needed here
            del self._lazy_loader
            del self._lazy_module_name
            del self._lazy_name
        return ref

class LazyClassDef(LazyLoader):
    def _lazy_load(self):
        ref = object.__getattribute__(self, '_lazy_ref')
        if ref is None:
            # Get the loader object and the [JTS] name of the class to load
            loader = object.__getattribute__(self, "_lazy_loader")
            base_module_name = object.__getattribute__(self, "_lazy_module_name")
            classpath = object.__getattribute__(self, "_lazy_name")

            # Load and set our internal reference
            ref = self._lazy_ref = loader.load_class(base_module_name, classpath)

            # These are no longer needed here
            del self._lazy_loader
            del self._lazy_module_name
            del self._lazy_name
        return ref

class LazyClassDefFromContext(LazyLoader):
    def _lazy_load(self):
        ref = object.__getattribute__(self, '_lazy_ref')
        if ref is None:
            # Get the loader object and the [JTS] name of the class to load
            loader = object.__getattribute__(self, "_lazy_loader")
            module_name = object.__getattribute__(self, "_lazy_module_name")
            classpath = object.__getattribute__(self, "_lazy_name")

            # Load and set our internal reference
            mod = loader.load_module(module_name)
            ref = self._lazy_ref = mod.load_class(classpath)

            # These are no longer needed here
            del self._lazy_loader
            del self._lazy_module_name
            del self._lazy_name
        return ref

class LazyRoutineDef(LazyLoader):
    def _lazy_load(self):
        ref = object.__getattribute__(self, '_lazy_ref')
        if ref is None:
            # Get the loader object and the JTS name/params/return of method to get
            loader = object.__getattribute__(self, "_lazy_loader")
            base_module_name = object.__getattribute__(self, "_lazy_module_name")
            method_signature = object.__getattribute__(self, "_lazy_name")

            # Load and set our internal reference
            ref = self._lazy_ref = loader.get_method(base_module_name, method_signature)

            # These are no longer needed here
            del self._lazy_loader
            del self._lazy_module_name
            del self._lazy_name
        return ref

class LazyFieldDef(LazyLoader):
    def _lazy_load(self):
        ref = object.__getattribute__(self, '_lazy_ref')
        if ref is None:
            # Get the loader object and the JTS name of field to get
            loader = object.__getattribute__(self, "_lazy_loader")
            base_module_name = object.__getattribute__(self, "_lazy_module_name")
            field_path = object.__getattribute__(self, "_lazy_name")

            # Load and set our internal reference
            ref = self._lazy_ref = loader.get_field(base_module_name, field_path)

            # These are no longer needed here
            del self._lazy_loader
            del self._lazy_module_name
            del self._lazy_name
        return ref


class LoadError(Exception): pass

class Loader(object):
    '''Context object used to manage the loading/resolving of COD modules (from COD or cache).'''

    def __init__(self, search_path=[], cache_root=None, name_db_path=None, auto_resolve=True, log_file=sys.stderr):
        if not isinstance(search_path, list):
            # in case we get '/home/user/blah'
            search_path = [search_path,]
        else:
            # in case we get ['',]
            search_path = [x for x in search_path if x]
        if '.' not in search_path:
            search_path = search_path + ['.',]
        self.search_path = search_path
        self.auto_resolve = auto_resolve
        self._log = log_file
        # dict of [module_name]
        self._modules = {}
        # dict of [base_module_name][classpath]
        self._classes = {}
        # dict of module_name -> base_module_name
        self._base_module_map = {}

        self.cache_root = None
        self._init_cache_root(cache_root)

        self.name_db_path = name_db_path
        self.name_db = None
        self.routine_name_db = {}
        self.field_name_db = {}
        if name_db_path:
            self.open_name_db(name_db_path)
        # a map of module names/aliases to their file system path, loaded or not
        self._module_path_map = {}
        self._init_module_path_map()
        # a map of module names/aliases to their cache location, loaded or not
        self._module_cache_map = {}
        self._init_module_cache_map()

    def _init_module_path_map(self):
        for search_path in self.search_path[::-1]:
            for filename in os.listdir(search_path):
                cod_path = os.path.join(search_path, filename)
                if cod_path.endswith('.cod') and os.path.isfile(cod_path):
                    # give it the file name just in case it is different
                    # this could lead to bad times if we mistakenly name a cod
                    # the same as another, but if we just use the embedded names
                    # (as we should) then we will be fine
                    if filename[:-4] not in self._module_path_map:
                        self._module_path_map[filename[:-4]] = cod_path
                    # do the embedded names next, these are authoritative!
                    for name in utils.quick_get_module_names(cod_path):
                        self._module_path_map[name] = cod_path

    def _init_module_cache_map(self):
        if self.cache_root is not None:
            if isinstance(self.cache_root, zipfile.ZipFile):
                cached_cod_names = self.cache_root.namelist()
                cached_cod_names = [x[:-7] for x in cached_cod_names if '/' not in x and x.endswith('.cod.db')]
            else:
                cached_cod_names = os.listdir(self.cache_root)
                cached_cod_names = [x for x in cached_cod_names if os.path.isfile(os.path.join(self.cache_root, x))]
                cached_cod_names = [x[:-7] for x in cached_cod_names if x.endswith('.cod.db')]
            for cached_cod_name in cached_cod_names:
                M = self._unpickle(cached_cod_name + '.cod.db')
                names = [M['name'],] + M['aliases']
                for name in names:
                    self._module_cache_map[name] = cached_cod_name
        
    def _init_cache_root(self, cache_root):
        assert self.cache_root is None
        if (cache_root is not None):
            if zipfile.is_zipfile(cache_root):
                self.cache_root = zipfile.ZipFile(cache_root, 'r')
            else:
                self.cache_root = cache_root
        else:
            self.cache_root = cache_root

    def _can_unpickle(self, rel_path):
        if self.cache_root is None:
            raise Exception("No cache is available")
        elif isinstance(self.cache_root, zipfile.ZipFile):
            try:
                self.cache_root.getinfo(rel_path)
                return True
            except KeyError:
                return False
        else:
            disk_path = os.path.join(self.cache_root, rel_path)
            return os.path.isfile(disk_path)

    def _unpickle(self, rel_path):
        if self.cache_root is None:
            raise Exception("No cache is available")
        elif isinstance(self.cache_root, zipfile.ZipFile):
            return cPickle.loads(self.cache_root.read(rel_path))
        else:
            disk_path = os.path.join(self.cache_root, rel_path)
            with open(disk_path, 'rt') as fd:
                return cPickle.load(fd)

    def _ds_export(self, export):
        '''Deserialize an ExportedItem from a depickled blob.'''
        X = ExportedItem(None, None)
        X.name, X.value = export
        return X

    def _ds_entry_point(self, entry_point, module):
        '''Deserialize an EntryPoint from a depickled blob.'''
        EP = EntryPoint(None, None)
        if entry_point:
            EP.name = entry_point[0]
            EP.param_types = self._ds_type_list(entry_point[1], module)
            EP.offset = entry_point[2]
            EP.empty = False
        else:
            EP.empty = True
        return EP

    def _ds_signature(self, sig):
        '''Deserialize a Signature from a depickled blob.'''
        Sig = Signature(None, None)
        Sig.type = sig[0]
        Sig.tag = sig[1]
        Sig.data = sig[2]
        return Sig

    def _ds_module(self, name):
        '''Deserialize a module from disk cache.'''
        # Open/unpickle it
        try:
            M = self._unpickle(name + ".cod.db")
        except Exception as ex:
            self.log("Unable to load module '%s' from cache: %s (%s)" % (name, ex, type(ex)))
            return None

        # Create an empty module object; populate its fields
        mod = Module(None, None)
        mod._R = None
        mod._L = self
        mod._resolved = mod._actualized = mod._disasmed = True

        mod.name, mod.version, mod.timestamp = M['name'], M['version'], M['timestamp']
        mod.attrs = dict((a, a) for a in M['attrs'])
        mod.siblings = M['siblings']
        mod.aliases = M['aliases']
        self._modules[mod.name] = mod
        for alias in mod.aliases:
            self._modules[alias] = mod
            self._base_module_map[alias] = mod.get_base_module_name()
        self._base_module_map[mod.name] = mod.get_base_module_name()
        for sibling in mod.siblings:
            self._base_module_map[sibling] = mod.get_base_module_name()
        mod.exports = [self._ds_export(X) for X in M['exports']]
        mod.statics = M['statics']
        mod.signatures = [self._ds_signature(S) for S in M['signatures']]

        # Create an array of lazy references to its imported modules
        mod.imports = map(self.ref_module, M['imports'])
        mod.import_versions = M['import_versions']

        # Create lazy references to its classes
        mod.classes = [self.ref_class(mod.get_base_module_name(), cl) for cl in M['classes']]

        # And to its routines
        mod.routines = [self.ref_method(mod.get_base_module_name(), jts) for offset, jts in M['routines']]
        mod._routine_map = dict((M['routines'][i][0], mod.routines[i]) for i in xrange(len(M['routines'])))

        # finally the entry point
        mod.entry_points = [self._ds_entry_point(EP, mod) for EP in M['entry_points']]

        # Make the rest of the module's fields empty (we didn't repopulate them)
        mod.iface_mrefs = mod.class_refs = \
            mod.field_fixups = mod.static_field_fixups = \
            mod.method_fixups = mod.virtual_method_fixups = \
            mod.static_method_fixups = mod.class_ref_fixups = \
            mod.mod_ref_fixups = []
        mod._crem = mod._mod_remap = {}

        return mod

    def ref_module(self, name):
        '''Return a lazy-loading Module matching the given module/file name.'''
        try:
            # If it's loaded, return the actual object
            return self._modules[name]
        except KeyError:
            # Otherwise, return a lazy-loading reference to the module
            return LazyModule(name, name, self)

    def load_codfile(self, filename):
        '''Load a module from an explicitly-named COD file.'''
        filename = os.path.split(filename)[1]
        if filename.endswith('.cod'):
            filename = filename[:-4]
        
        # replace it with the actual name if it is an aliased name
        if filename in self._module_path_map:
            filename = self._module_path_map[filename]
        if self.cache_root is not None:
            if filename in self._module_cache_map:
                filename = self._module_cache_map[filename]

        cf = utils.load_cod_file(filename)
        mod = Module(self, cf)

        if self.auto_resolve:
            mod.resolve()

        # Inject ourselves into the module cache
        self._modules[mod.name] = mod
        for alias in mod.aliases:
            self._modules[alias] = mod
            self._base_module_map[alias] = mod.get_base_module_name()
        self._base_module_map[mod.name] = mod.get_base_module_name()
        for sibling in mod.siblings:
            self._base_module_map[sibling] = mod.get_base_module_name()

        return mod

    def __contains__(self, item):
        '''Check the load path/cache for a module name, currently loaded or not.'''
        if isinstance(item, basestring):
            cod_name = os.path.split(item)[1]
            if cod_name.endswith('.cod'):
                cod_name = cod_name[:-4]
            elif cod_name.endswith('.cod.db'):
                cod_name = cod_name[:-7]

            if cod_name in self._module_path_map:
                return True
            if self.cache_root is not None:
                if cod_name in self._module_cache_map:
                    return True
        else:
            raise LoadError("Unknown type for __contains__ in loader: %s (%s)" % (str(item), str(type(item))))
        return False
        
    def unload_module(self, name):
        '''Unload a module and its classes from the memory cache'''
        name = os.path.splitext(os.path.basename(name))[0]
        if name in self._modules:
            for alias in self._modules[name].aliases:
                try:
                    del self._classes[alias]
                except KeyError:
                    pass
                del self._modules[alias]
            try:
                del self._classes[name]
            except KeyError:
                pass
            del self._modules[name]

    def load_module(self, name):
        '''Load a module from the search path'''
        # This line is convenient and fast (because it ignores the full path and just
        # tries to load a similarly-named module from cache), but it doesn't give full control...
        name = os.path.splitext(os.path.basename(name))[0]

        # TODO: remove
        '''
        if name not in self._modules:
            import traceback
            from StringIO import StringIO
            dump = StringIO()
            traceback.print_stack(file=dump)
            dump.seek(0)
            dump = dump.read()
            self.log('Loading module %s' % name)
            self.log(dump)
        '''
        
        try:
            # Try loading from memory cache...
            return self._modules[name]
        except KeyError:
            pass

        # Not in memory cache; must load from somewhere
        mod = None
        
        # Use disk cache (we must have a cache_root)
        if self.cache_root is not None:
            if name in self._module_cache_map:
                filename = os.path.split(self._module_cache_map[name])[-1]
                if filename != name + '.cod':
                    self.log("Loading module '%s' as '%s' from disk cache" % (self._module_cache_map[name], name))
                else:
                    self.log("Loading module '%s' from disk cache" % name)
                mod = self._ds_module(self._module_cache_map[name]) # This method also sticks the module into our memory cache

        # Failing that (if mod is still None), try loading from the original COD file
        if mod is None:
            if name in self._module_path_map:
                filename = os.path.split(self._module_path_map[name])[-1]
                if filename != name + '.cod':
                    self.log("Loading module '%s' as '%s' from COD" % (self._module_path_map[name], name))
                else:
                    self.log("Loading module '%s' from COD" % name)

                cf = utils.load_cod_file(self._module_path_map[name], self.search_path)
                mod = Module(self, cf)

                # Stick this module in memory cache
                self._modules[mod.name] = mod
                for alias in mod.aliases:
                    self._modules[alias] = mod
                    self._base_module_map[alias] = mod.get_base_module_name()
                self._base_module_map[mod.name] = mod.get_base_module_name()
                for sibling in mod.siblings:
                    self._base_module_map[sibling] = mod.get_base_module_name()

                # Resolve the module's external references AFTER it has been added to the loader's registry...
                if self.auto_resolve:
                    mod.resolve()
                    
        if mod is None:
            raise(LoadError("Could not load module %s from cache or search path" % name))
        return mod

    def _ds_type_token(self, type_token, module):
        '''Deserialize a TypeToken from a depickled Java Type String from the context of module.'''
        return utils.TypeToken.from_jts(type_token, module)

    def _ds_type_list(self, type_list, module):
        '''Deserialize a TypeList from a depickled Java Type String from the context of module.'''
        return utils.TypeList.from_jts(type_list, module)

    def _ds_field(self, parent, field_data):
        '''Deserialize a FieldDef from a depickled blob.'''
        fd = FieldDef(None, None, None)
        fd.parent = parent
        fd.name = field_data[2]
        fd.type = self._ds_type_list(field_data[1], fd.parent.module)
        fd.attrs = dict((a, a) for a in field_data[0])
        fd.address = None if (len(field_data) == 3) else field_data[3]
        return fd

    def _ds_sme(self, stack_map_entry, module):
        '''Deserialize a StackMapEntry from a depickled blob from the context of module.'''
        sme = StackMapEntry(None, None, None)
        sme.label = stack_map_entry[0]
        sme.type = self._ds_type_list(stack_map_entry[1], module)
        return sme

    def _ds_jts_ref(self, base_module_name, rtype, jts):
        try:
            if rtype == 'C':
                return self.ref_class(base_module_name, jts)
            elif rtype == 'M':
                return self.ref_method(base_module_name, jts)
            elif rtype == 'F':
                return self.ref_field(base_module_name, jts)
            else:
                raise ValueError("Invalid JTS reference type char '%s' (jts: '%s') in sibling of module %s" % (rtype, jts, base_module_name))
        except AssertionError as err:
            self.log("ERROR: malformed JTS reference (%s, %s) in sibling of module %s" % (rtype, jts, base_module_name))
            raise

    def _ds_instruction(self, in_data, module):
        '''Deserialize an Instruction from a depickled blob.'''
        inst = disasm.Instruction(None, None, None, None)

        if len(in_data) == 4:
            inst.offset, inst.opcode, ops, inst.totos = in_data
        else:
            inst.offset, inst.opcode, ops, inst.totos = in_data[0], in_data[1], [], in_data[2]

        inst._name = disasm._OPCODES[inst.opcode]
        inst.totos = self._ds_type_token(inst.totos, module) if (inst.totos is not None) else None

        inst.operands = []
        for op in ops:
            otype, oval = op[0], op[1]
            if otype == 'L':
                inst.operands.append(oval)
            elif otype == 'T':
                inst.operands.append(utils.TypeToken.from_jts(oval, module))
            else:
                base_module_name, oval = oval
                inst.operands.append(self._ds_jts_ref(base_module_name, otype, oval))

        return inst

    def _ds_handler(self, xh_data):
        xh = ExHandler(None, None, None)
        base_module_name = xh_data[1]
        xh.type = self.ref_class(base_module_name, xh_data[0])
        xh.scope = xh_data[2]
        xh.target = xh_data[3]
        return xh

    def _ds_method(self, parent, method_data):
        rd = RoutineDef(None, None)

        # Simple stuff
        rd.name = method_data['name']
        rd.parent = parent
        rd.module = parent.module
        rd.max_stack, rd.max_locals, rd.stack_size = method_data['limits']
        rd.offset = rd.code_offset = method_data['code_offset']
        rd.attrs = dict((a, a) for a in method_data['attrs'])

        # Type info
        rd.return_type = self._ds_type_list(method_data['return_type'], parent.module)
        rd.param_types = self._ds_type_list(method_data['param_types'], parent.module)
        rd.stack_map = [self._ds_sme(x, parent.module) for x in method_data['stack_map']]

        # Instructions/exception handlers
        rd.instructions = [self._ds_instruction(instr, parent.module) for instr in method_data['instructions']]
        rd.handlers = map(self._ds_handler, method_data['handlers'])

        # All ready to go!
        rd._disasmed = rd._resolved = True
        return rd

    def _ds_class(self, base_module_name, name):
        '''Deserialize a ClassDef from a depickled blob.'''
        cache_path = "%s/%s" % (base_module_name, name + ".cache")
        try:
            C = self._unpickle(cache_path)
        except Exception as ex:
            self.log("Unable to load cached class from '%s': %s (%s)" % (cache_path, ex, type(ex)))
            return None

        # Create an empty class def object (cache a reference to it)
        cd = ClassDef(None, None)
        cd.field_members = None
        cd.method_members = None

        # Populate our parent
        cd.module = self.ref_module(C['module'])

        # Populate all basic fields
        cd.name = C['name']
        if '/' in cd.name:
            cd.package = C['name'].rsplit('/', 1)[0]
        else:
            cd.package = ''
        cd.attrs = dict((a, a) for a in C['attrs'])

        # Populate simple type-based fields
        cd.superclass = self.ref_class(C['superclass_module'], C['superclass'])
        cd.ifaces = [self.ref_class(C['ifaces_modules'][i], C['ifaces'][i]) for i in range(len(C['ifaces']))]

        # Populate field/method lists
        cd.fields = [self._ds_field(cd, F) for F in C['fields']]
        cd.static_fields = [self._ds_field(cd, F) for F in C['static_fields']]
        cd.virtual_methods = [self._ds_method(cd, M) for M in C['virtual_methods']]
        cd.nonvirtual_methods = [self._ds_method(cd, M) for M in C['nonvirtual_methods']]
        cd.static_methods = [self._ds_method(cd, M) for M in C['static_methods']]
        cd._resolved = True

        # Reconstruct static-field-address map
        cd._static_address_map = dict((sf.address, sf) for sf in cd.static_fields)

        # Populate VFT and FFT (i.e., re-actualize)
        cd.vft = [self._ds_jts_ref(C['vft_modules'][i], 'M', C['vft'][i]) for i in range(len(C['vft']))]
        cd.fft = [self._ds_jts_ref(C['fft_modules'][i], 'F', C['fft'][i]) for i in range(len(C['fft']))]
        cd._actualized = True

        # Make sure this class ends up in the memory cache
        self.add_class_def(cd)

        # Return that sucker
        return cd

    def find_class_in_dependencies(self, module, classpath, preferred_mod_index = 0):
        ''' Return a the base module name containing a named class.
            The base module name is the first listed sibling in every COD.
            For example, the base module name of net_rim_cldc-16 is
            net_rim_cldc.
        '''
        # this function is an evil necessity because we don't fully
        # understand the mod_index in ClassRefs
        if module._resolved:
            dependencies = [module.name,] + [x.name for x in module.imports]
        else:
            dependencies = [module.name,] + module.raw_imports

        # make the common case FAST
        if preferred_mod_index:
            preferred_mod_name = dependencies.pop(preferred_mod_index - 1)
            dependencies.insert(0, preferred_mod_name)

        # go through loaded modules and locate this class symbolically
        visited = set()
        for mod_name in dependencies:
            if mod_name not in self._base_module_map:
                visited.add(mod_name)
                self.load_module(mod_name)
            base_module_name = self._base_module_map[mod_name]
            if base_module_name in self._classes:
                if classpath in self._classes[base_module_name]:
                    return base_module_name
            if self.cache_root:
                cache_path = "%s/%s" % (base_module_name, classpath + ".cache")
                if self._can_unpickle(cache_path):
                    return base_module_name

        # soooooo sloowwwwwwww
        # otherwise try to start loading modules to look
        for mod_name in dependencies:
            if mod_name not in visited:
                visited.add(mod_name)
                mod = self.load_module(mod_name)
                base_module_name = self._base_module_map[mod_name]
                if classpath in self._classes[base_module_name]:
                    return base_module_name
    
        # otherwise, desperately grab at siblings of dependencies
        # we really need to get rid of this
        for mod_name in dependencies:
            mod = self.load_module(mod_name)
            for sibling in mod.siblings:
                if sibling not in visited:
                    visited.add(sibling)
                    sibling_mod = self.load_module(sibling)
                    base_module_name = self._base_module_map[mod_name]
                    if classpath in self._classes[base_module_name]:
                        return base_module_name

        # what the?!
        with open("classdump.txt", 'wt') as fd:
            for mname in self._classes:
                for cname in self._classes[mname]:
                    if cname not in [None, 'None']:
                        print >> fd, mname, cname
        raise(LoadError("Could not locate class '%s' from module dependencies of %s" % (classpath, module.name)))
   
    def ref_class(self, base_module_name, name):
        ''' Return a lazy-loading ClassDef matching the given [dotted] class name.
            A class of "name" must exist in a sibling of "base_module_name".
        '''
        if not name:
            return None
        try:
            # If it's already loaded, return a straight reference
            return self._classes[base_module_name][name]
        except KeyError:
            return LazyClassDef(base_module_name, name, self)
   
    def ref_class_from_context(self, module, name):
        ''' Return a lazy-loading ClassDef matching the given [dotted] class name
            from the context of a specific module.
            A class of "name" must exist in "module" or an import of "module".
        '''
        if not name:
            return None
        # If it's already loaded, return a straight reference
        if module._resolved:
            module_names = [x.name for x in module.imports]
        else:
            module_names = module.raw_imports
        module_names = [module.name,] + module_names

        # go through and locate this class symbolically
        for mod_name in module_names:
            if mod_name in self._modules:
                base_module_name = self._base_module_map[mod_name]
                if base_module_name in self._classes:
                    if name in self._classes[base_module_name]:
                        return self._classes[base_module_name][name]

        # otherwise return a lazy reference
        return LazyClassDefFromContext(module.name, name, self)

    def load_class(self, base_module_name, full_name):
        '''Return a reference to a ClassDef instance matching the given [JTS] class name in a named module.'''
        if not full_name:
            return None
        try:
            # If we've loaded this class, return it
            return self._classes[base_module_name][full_name]
        except KeyError:
            # We may be able to load it from disk cache
            cdef = None

            if self.cache_root is not None:
                classpath = '%s/%s' % (base_module_name, full_name + '.cache')
                if self._can_unpickle(classpath):
                    # If we have a disk cache, try loading it from that
                    self.log("Loading class '%s' from disk cache" % full_name)
                    cdef = self._ds_class(base_module_name, full_name)
            
            # start loading the base module and siblings
            if cdef is None:
                # start loading sibling modules until we find it...
                mod = self.load_module(base_module_name)
                try:
                    return self._classes[base_module_name][full_name]
                except KeyError:
                    pass
                for sibling in mod.siblings[1:]:
                    # if we haven't loaded it...
                    if sibling not in self._modules:
                        # ...load it
                        sibling_mod = self.load_module(sibling)
                        try:
                            cdef = self._classes[base_module_name][full_name]
                        except KeyError:
                            pass

            if cdef is None:
                # Um...  We're out of luck here...
                with open("classdump.txt", 'wt') as fd:
                    for mname in self._classes:
                        for cname in self._classes[mname]:
                            if cname not in [None, 'None']:
                                print >> fd, mname, cname
                raise LoadError("Unable to load class '%s' in sibling of module %s!" % (full_name, base_module_name))

            return cdef

    def ref_method(self, base_module_name, method_signature):
        '''Get a lazy-loader for a RoutineDef matching the given JTS signature.'''
        return LazyRoutineDef(base_module_name, method_signature, self)

    def get_method(self, base_module_name, method_signature):
        '''Get a reference to a RoutineDef object matching the given JTS signature.'''
        method_name, rest = method_signature.split('(', 1)
        class_name, method_name = method_name.rsplit('/', 1)
        param_types, rest = rest.split(')', 1)

        C = self.load_class(base_module_name, class_name)
        param_types = self._ds_type_list(param_types, C.module)
        return C.get_member_by_name(method_name, param_types)

    def ref_field(self, base_module_name, field_path):
        '''Get a lazy-loader for a FieldDef matching the given JTS name.'''
        return LazyFieldDef(base_module_name, field_path, self)

    def get_field(self, base_module_name, field_path):
        '''Get a reference to a FieldDef matching the given JTS name.'''
        class_name, field_name = field_path.rsplit('/', 1)
        C = self.load_class(base_module_name, class_name)
        return C.get_member_by_name(field_name, None, True)

    def add_class_def(self, class_def):
        base_module_name = class_def.module.get_base_module_name()
        name = class_def.name
        if base_module_name in self._classes:
            if name in self._classes[base_module_name]:
                self.log("WARNING: redefinition of class '%s' by module '%s' (already defined in sibling of module '%s')" % (name, class_def.module, self._classes[base_module_name][name].module))
        if base_module_name not in self._classes:
            self._classes[base_module_name] = {None: None, 'None': None}
        #print 'Registering %s => %s of class from %s' % (base_module_name, name, class_def.module.name)
        self._classes[base_module_name][name] = class_def

    def add_new_search_path(self, new_path):
        self.search_path.append(new_path)
        self._init_module_path_map()

    def set_cache_root(self, cache_root):
        '''Initialization of a cache root after the loader has been created.'''
        assert self.cache_root == None
        self._init_cache_root(cache_root)
        self._init_module_path_map()

    def open_name_db(self, db_path):
        # if we already have one open, save and close it
        if self.name_db:
            self.save_name_db()
            self.name_db.close()

        if os.path.isfile(db_path):
            if not zipfile.is_zipfile(db_path):
                raise LoadError("Does not appear to be a zipped name database: %s" % db_path)

            self.name_db_path = db_path
            self.name_db = zipfile.ZipFile(db_path, 'r')
            self.routine_name_db = cPickle.loads(self.name_db.read('routine_names'))
            self.field_name_db = cPickle.loads(self.name_db.read('field_names'))
            self.name_db.close()
        else:
            # if it does not exists, create it
            self.name_db_path = db_path
            self.routine_name_db = {}
            self.field_name_db = {}
            self.save_name_db()

    def save_name_db(self):
        if self.name_db_path:
            self.name_db = zipfile.ZipFile(self.name_db_path, 'w')
            self.name_db.writestr('routine_names', cPickle.dumps(self.routine_name_db))
            self.name_db.writestr('field_names', cPickle.dumps(self.field_name_db))
            self.name_db.close()

    def get_routine_renaming_db(self):
        return self.routine_name_db

    def get_field_renaming_db(self):
        return self.field_name_db

    def rename_routine(self, base_module_name, routine_name, new):
        found_name = routine_name
        for accessor_name, name in self.routine_name_db.iteritems():
            #print '/'.join(accessor_name.split('(')[0].split('/')[:-1]) + '/' + name + '(' + accessor_name.split('(')[1]
            if routine_name == '/'.join(accessor_name.split('(')[0].split('/')[:-1]) + '/' + name + '(' + accessor_name.split('(')[1]:
                found_name = accessor_name
                break

        # verify that it is a routine
        class_name = '/'.join(routine_name.split('(')[0].split('/')[:-1])
        class_def = self.load_class(base_module_name, class_name)
        if routine_name not in [x.to_jts() for x in class_def.routines]:
            raise LoadError("Could not locate routine %s for renaming" % routine_name)

        self.routine_name_db[found_name] = new
        self.save_name_db()

    def rename_field(self, base_module_name, field_name, new):
        found_name = field_name
        for accessor_name, name in self.field_name_db.iteritems():
            #print '/'.join(accessor_name.split('/')[:-1]) + '/' + name
            if field_name == '/'.join(accessor_name.split('/')[:-1]) + '/' + name:
                found_name = accessor_name
                break

        # verify that it is a field
        class_name = '/'.join(field_name.split('(')[0].split('/')[:-1])
        class_def = self.load_class(base_module_name, class_name)
        if field_name not in [x.to_jts() for x in class_def.fields+class_def.static_fields]:
            raise LoadError("Could not locate field %s for renaming" % field_name)

        self.field_name_db[found_name] = new
        self.save_name_db()

    def log(self, msg):
        print >> self._log, msg
        self._log.flush()

class ResolutionError(Exception): pass

class Resolver(object):
    '''Context object used to resolve names/identifiers within/across COD modules.'''
    def __init__(self, module):
        self._M = module
        self._cf = module._cf
        self._db = Context.fromstring(self._cf.data.raw, LITTLE_ENDIAN)
        self._init_cache()

    def _init_cache(self):
        self._cache = {
            'lits': {},
            'ids': {},
            'blobs': {},
            'tlists': {},
            'crefs': {},
        }

    def log(self, msg):
        print >> sys.stderr, msg

    def get_id(self, offset):
        try:
            return self._cache['ids'][offset]
        except KeyError:
            x = utils.Identifier(self._db.seek(offset)).replace('.', '/') # We use JTS; RIM doesn't...
            self._cache['ids'][offset] = x
            return x

    def get_escaped_lit(self, offset, **options):
        try:
            return self._cache['lits'][offset]
        except KeyError:
            x = utils.EscapedLiteral(self._db.seek(offset), **options)
            self._cache['lits'][offset] = x
            return x

    def get_lit(self, offset, **options):
        try:
            return self._cache['lits'][offset]
        except KeyError:
            x = utils.Literal(self._db.seek(offset), **options)
            self._cache['lits'][offset] = x
            return x

    def get_blob(self, offset, length):
        try:
            return self._cache['blobs'][(offset, length)]
        except KeyError:
            x = string_f(length)(self._db.seek(offset))
            self._cache['blobs'][(offset, length)] = x
            return x

    def get_tlist(self, offset):
        try:
            return self._cache['tlists'][offset]
        except KeyError:
            if offset == 0xFFFF:
                # this is an empty type list
                x = utils.TypeList.from_jts("", self._M)
            else:
                x = utils.TypeList(self._db.seek(offset))
            self._cache['tlists'][offset] = x
            return x

    def get_class(self, class_):
        # this little disaster is how classes are born
        M = self._M
        if isinstance(class_, basestring):
            # Special case--if we need to resolve a type by name, try to use our module's loader
            try:
                return M.load_class(class_)
            except LoadError as err:
                # Hacky error return (since all our Unresolved/Bad class ref types expect a class-ref tuple)
                urc = utils.UnresolvedClass((-1, -1))
                urc.name = class_
                return urc
        elif isinstance(class_, utils.UnresolvedClass):
            mod_byte, class_byte = class_.class_id
        else:
            mod_byte, class_byte = class_

        # Maybe the class ref is stuffed in the "extra" class field
        # this is the case for raw cod sectors on phones
        # (And odd-ball cases off the phones, too.  Sigh...)
        if not M._disk:
            try:
                # the extra field matches our module:class reference
                # so, use this reference's index for our classes list
                return M._crem[(mod_byte, class_byte)].get_class()
            except KeyError:
                # So it wasn't there...
                pass

        # Unless the mod byte is 0 (local) or 255 (???) or a sibling
        if mod_byte not in (0, 255) and \
           M.imports[mod_byte - 1].name not in M.siblings:
            # Otherwise, start with a Class-Ref list lookup
            # class_byte maxes out at 255, while index may be > 255
            # Ergo, we must check all indices such that (index & 0xff) == class_byte
            index, max = class_byte, len(M.class_refs)
            while index < max:
                cr = M.class_refs[index]
                if (cr.mod_index == mod_byte) and (cr.extra == (0, 0)):
                    # If the module index of the ref matches the one in our class ID, it's the class
                    # (Unless its extra fields are not (0, 0); then it has been remapped somehow...)
                    return cr.get_class()
                # Otherwise, try the next possible match
                index += 256

        # Try a module-based lookup (if the mod-byte is not 255)
        if mod_byte != 255:
            # Do local and non-local searches a little differently...
            if mod_byte == 0:
                try:
                    return M.classes[class_byte]
                except IndexError:
                    self.log("Local-module class index [%d] out of range. (Mod:Class reference %d:%d)" % (class_byte, mod_byte, class_byte))
                    return utils.BadClassRef((0, class_byte))
            else:
                try:
                    ext_mod = M.imports[mod_byte - 1]
                except IndexError:
                    self.log("Foreign-module index [%d] out of range. (Mod:Class reference %d:%d)" % (mod_byte, mod_byte, class_byte))
                    return utils.BadClassRef((mod_byte, class_byte))
                try:
                    return ext_mod.classes[class_byte]
                except IndexError:
                    self.log("Foreign-module class index [%d] out of range. (Mod:Class reference %d:%d)" % (class_byte, mod_byte, class_byte))
                    return utils.BadClassRef((mod_byte, class_byte))

        if mod_byte == 255 and class_byte == 255:
            # No-such-class (e.g., the superclass of "java.lang.Object")
            return None

        # Out. Of. Luck.
        self.log("ERROR: Unresolvable class identifier: (%d:%d)" % (mod_byte, class_byte))
        return utils.UnresolvedClass((mod_byte, class_byte))


# Main COD abstract types
#----------------------------------------------------------

class Module(object):

    # Attribute bit meanings
    ATTRS = {
        0x01: "is_library", 0x02: "is_midlet", 0x04: "is_parseable",
        0x10: "is_brittle", 0x20: "is_platform"
    }

    def __init__(self, loader, cod_file):
        if (loader is None) and (cod_file is None): return

        self._cf = cod_file
        self._disk = (cod_file.hdr.section_num == 0)  # This COD is in disk, not heap, mode
        self._L = loader
        self._R = Resolver(self)
        R = self._R
        cs, ds = cod_file.code, cod_file.data

        # Start with the basics: our name/version/timestamp
        self.name, self.version = map(R.get_escaped_lit, ds.modules[0])
        self.timestamp = cod_file.hdr.timestamp

        # Things from the header
        self.attrs = utils.parse_flags(ds.hdr.flags, self.ATTRS)
        self.entry_points = [EntryPoint(self, ep) for ep in ds.hdr.entry_points if ep.offset]

        # Other module-wide stuff
        self.siblings = map(R.get_escaped_lit, ds.siblings)
        self.aliases = map(R.get_escaped_lit, ds.aliases)
        self.raw_imports = [R.get_escaped_lit(n) for n, v in ds.modules[1:]]
        self.raw_import_versions = [R.get_escaped_lit(v) for n, v in ds.modules[1:]]
        self.exports = [ExportedItem(self, off) for off in ds.exports]
        self.statics = [(sd.address, sd.value) for sd in ds.static_data] # Not sure what these are yet...

        # Load our routines before loading the classes
        # (They can get patched-up to go with their appropriate classes later)
        self.routines = [RoutineDef(self, rd) for rd in cs.routines]
        self._routine_map = dict((r.offset, r) for r in self.routines)

        # Load class definitions; register them with our loader
        self.classes = [ClassDef(self, cd) for cd in ds.class_defs]
        map(loader.add_class_def, self.classes)

        # Name-resolve lists of interface methods and classes referenced
        self.iface_mrefs = [InterfaceMethodRef(self, off) for off in ds.iface_method_refs]
        self.class_refs = [ClassRef(self, off) for off in ds.class_refs]

        # Create a offset-reference maps for class/ifacem-refs
        self._iface_mref_map = dict((imr.offset - ds._start, imr) for imr in self.iface_mrefs)
        self._class_ref_map = dict((cr.offset - ds._start, cr) for cr in self.class_refs)

        # Create a (class-ref-extra => class-ref) mapping for alternative class lookup code
        # (Isn't RIM wonderful?)
        if not self._disk:
            self._crem = dict((cr.extra, cr) for cr in self.class_refs if cr.extra != (0, 0))

        # Parse fixup references (i.e., what the fixups refer to) but don't resolve yet
        _instance_field_fixups = itertools.chain(ds.field_fixups, ds.local_field_fixups)
        self.field_fixups = [FixupField(self, fxp) for fxp in _instance_field_fixups]
        self.static_field_fixups = [FixupField(self, fxp) for fxp in ds.static_field_fixups]
        self.method_fixups = [FixupMethod(self, fxp) for fxp in ds.routine_fixups]
        self.virtual_method_fixups = [FixupMethod(self, fxp) for fxp in ds.virtual_routine_fixups]
        self.static_method_fixups = [FixupMethod(self, fxp, True) for fxp in ds.static_routine_fixups]
        self.class_ref_fixups = [FixupClassRef(self, fxp) for fxp in ds.class_ref_fixups]
        self.mod_ref_fixups = [FixupModRef(self, fxp) for fxp in ds.mod_code_fixups]

        # And grab our signatures (at least that's what I think they are...)
        self.signatures = [Signature(self, ti) for ti in cod_file.trailer.items]

        self._resolved = self._actualized = self._disasmed = False

    def get_base_module_name(self):
        return self.siblings[0]

    def get_class_resolver(self):
        return self._R.get_class

    def ref_class(self, classpath):
        ''' Return a lazy-loading ClassDef matching the given [dotted] class name
            from the context of this module.
        '''
        return self._L.ref_class_from_context(self, classpath)

    def load_class(self, classpath, preferred_mod_index = 0):
        '''Symbolically locates a class from the context of this module.'''
        base_module_name = self._L.find_class_in_dependencies(self, classpath, preferred_mod_index=preferred_mod_index)
        return self._L.load_class(base_module_name, classpath)

    def resolve(self):
        '''Resolve imports and external dependencies.'''
        if self._resolved: return self
        self._resolved = True
        ds, R = self._cf.data, self._R
        self._L.log("Resolving module '%s'" % self.name)

        # TODO: remove
        '''
        import traceback
        from StringIO import StringIO
        dump = StringIO()
        traceback.print_stack(file=dump)
        dump.seek(0)
        dump = dump.read()
        self._L.log(dump)
        '''

        # Load our siblings (this accounts for slight version differences
        # where a class moved to a different sibling)
        # For example,
        #   net/rim/device/alpha/ui/mediaanimation/CoordinatedAnimation
        # has moved from net_rim_ui_alpha to net_rim_ui_alpha-1
        # from 6.0.0.141 to 6.0.0.448
        # loading siblings like this takes some extra time,
        # but allows some symbolic flexibility between versions
        for sibling in self.siblings:
            m = self._L.load_module(sibling)
            m.resolve()

        # Load our imported modules
        self.imports = [self._L.load_module(n) for n in self.raw_imports]
        self.import_versions = [v for v in self.raw_import_versions]

        # Ensure our imports have been resolved
        for m in self.imports: m.resolve()

        # Resolve type references for routine parameters and interface method parameters
        _resolver = R.get_class
        for r in self.routines: r.resolve(_resolver)
        for imr in self.iface_mrefs: imr.resolve(_resolver)

        # Next step: resolve the classes
        for c in self.classes: c.resolve(_resolver)

        # Finally, resolve our entry points (their parameter lists may have class references)
        for ep in self.entry_points: ep.resolve(_resolver)

        # Remove some unneeded references so that the GC can clean up after us
        del self._cf, self._class_ref_map

        # Create a module-remapping table (we have no idea what we're doing here, but it might work...)
        if not self._disk:
            self._mod_remap = {}
            for (mod_byte, class_byte), cr in self._crem.iteritems():
                if mod_byte and (mod_byte not in self._mod_remap):
                    new_mod = cr.get_class().module
                    self._mod_remap[mod_byte] = new_mod

        return self

    def actualize(self):
        '''Perform class-actualization on all the classes we contain.'''
        if self._actualized: return self
        self._actualized = True
        self._L.log("Actualizing %d classes from module '%s'" % (len(self.classes), self.name))

        # Load our siblings (this accounts for slight version differences
        # where a class moved to a different sibling)
        # For example,
        #   net/rim/device/alpha/ui/mediaanimation/CoordinatedAnimation
        # has moved from net_rim_ui_alpha to net_rim_ui_alpha-1
        # from 6.0.0.141 to 6.0.0.448
        # loading siblings like this takes some extra time,
        # but allows some symbolic flexibility between versions
        for sibling in self.siblings:
            m = self._L.load_module(sibling)
            m.actualize()
        
        # Start with actualizing the fixups (creating an address-wise map of fixup references
        # and replacing FixupXXX objects in the fixup arrays with the objects they reference...
        def _actualize_fixup_list(f_list, f_map, resolver):
            for i in xrange(0, len(f_list)):
                f = f_list[i]
                f_obj = f.resolve(resolver)
                if f.offsets:
                    for o in f.offsets:
                        f_map[o] = f_obj
        _fixup_lists = (
            self.field_fixups,
            self.static_field_fixups,
            self.method_fixups,
            self.virtual_method_fixups,
            self.static_method_fixups,
            self.class_ref_fixups,
            self.mod_ref_fixups,
        )
        self._fixup_map = {}
        _resolver = self._R.get_class
        for f_list in _fixup_lists:
            _actualize_fixup_list(f_list, self._fixup_map, _resolver)

        # Now actualize the classes (compute VFTs, etc.)
        for c in self.classes:
            c.actualize()

        return self

    def disasm(self, auto_resolve = True):
        '''Trigger disassembly/fixup of all routines defined in this module.'''
        if self._disasmed: return self
        self._L.log("Disassembling %d routines from module '%s'" % (len(self.routines), self.name))

        for r in self.routines:
            r.disasm(auto_resolve = auto_resolve)

        if auto_resolve:
            del self._fixup_map, self._iface_mref_map
        self._disasmed = True
        return self


    def __str__(self):
        return "%s v. %s" % (self.name, self.version)

    def __repr__(self):
        return "<module: '%s'>" % str(self)


class EntryPoint(object):
    __slots__ = ['name', 'param_types', 'offset', 'empty']

    def __init__(self, module, raw_ep):
        if (module is None) and (raw_ep is None): return

        R = module._R
        if raw_ep.name:
            self.name = R.get_id(raw_ep.name)
            self.param_types = R.get_tlist(raw_ep.param_types)
            self.offset = raw_ep.offset
            self.empty = False
        else:
            self.empty = True

    def resolve(self, resolver):
        self.param_types.resolve(resolver)
        return self

    def __str__(self):
        if self.empty:
            return "None"
        else:
            return "%s(%s)" % (self.name, self.param_types)

    def __repr__(self):
        if self.empty:
            return "<None>"
        else:
            return "<entry-point: '%s' @ 0x%04x" % (str(self), self.offset)

    def serialize(self):
        if self.empty:
            return ()
        else:
            return (self.name, self.param_types.serialize(), self.offset)

class ExportedItem(object):
    __slots__ = ['name', 'value']

    def __init__(self, module, raw_exd):
        if (module is None) and (raw_exd is None): return

        R = module._R
        self.name = R.get_id(raw_exd.name)
        self.value = R.get_blob(raw_exd.data_offset, raw_exd.length)
        if not self.value:
            self.value = None
        elif len(self.value) == 1:
            self.value = ord(self.value)

    def __str__(self):
        return "%s=%r" % (self.name, self.value)

    def __repr__(self):
        return "<export: %s>" % str(self)

    def serialize(self):
        return (self.name, self.value)

class Fixup(object):
    __slots__ = []

    def resolve(self, resolver):
        return self

    def get_class(self):
        # Obviously, this won't work for base Fixup objects
        return self.class_.get_class()

    def get_item(self):
        # this must be resolved before we get the item
        assert self.item is not None
        return self.item

    def __repr__(self):
        return "<fixup: '%s'>" % str(self)

class FixupField(Fixup):
    __slots__ = ['offsets', 'class_', 'name', 'type', 'item']

    def __init__(self, module, raw_fxp):
        R = module._R
        mref, self.offsets = raw_fxp
        if isinstance(mref, format.FxpLocalMemberRef):
            self.class_ = utils.UnresolvedClass((0, mref.class_index))
            self.name = utils.UnresolvedLocalField(mref.field_index)
            self.type = None
        else:
            self.class_ = module._class_ref_map[mref.class_ref]
            self.name = R.get_id(mref.name)
            self.type = R.get_tlist(mref.type)
        self.item = None

    def resolve(self, resolver):
        if isinstance(self.class_, utils.UnresolvedClass):
            _cc = self.class_
            self.class_ = resolver(self.class_)
            try:
                _field = self.class_.get_class().fields[self.name.index]
            except IndexError:
                print >> sys.stderr, "Failed to get field %d for class %s (%s)" % (self.name.index, self.class_, _cc)
                return None
            self.name = _field.name
            self.type = _field.type
            self.item = _field
            return _field
        else:
            self.type.resolve(resolver)
            _field = self.class_.get_class().get_member_by_name(self.name, self.type, True)
            self.item = _field
            return _field

    def __str__(self):
        return "%s/%s" % (self.class_, self.name)

    def serialize(self):
        return ('F', str(self))

class FixupMethod(Fixup):
    __slots__ = ['offsets', 'class_', 'name', 'param_types', 'return_type', 'is_static', 'item']

    def __init__(self, module, raw_fxp, is_static=False):
        R = module._R
        mref, self.offsets = raw_fxp
        self.class_ = module._class_ref_map[mref.class_ref]
        self.name = R.get_id(mref.name)
        if isinstance(mref, format.FxpLongMemberRef):
            self.param_types = R.get_tlist(mref.param_types)
            self.return_type = R.get_tlist(mref.return_type)
        else:
            self.param_types = R.get_tlist(mref.type)
            self.return_type = None
        self.is_static = is_static
        self.item = None

    def resolve(self, resolver):
        self.param_types.resolve(resolver)
        if self.return_type is not None:
            self.return_type.resolve(resolver)
        _routine = self.class_.get_class().get_member_by_name(self.name, self.param_types)
        self.item = _routine
        return _routine

    def __str__(self):
        rtype = self.return_type.to_jts() if self.return_type is not None else ''
        return "%s/%s(%s)%s" % (self.class_, self.name, self.param_types.to_jts(), rtype)

    def serialize(self):
        return ('M', str(self))

class FixupClassRef(Fixup):
    __slots__ = ['class_', 'offsets', 'item']

    def __init__(self, module, raw_fxp):
        cr_off, self.offsets = raw_fxp
        self.class_ = module._class_ref_map[cr_off]
        self.item = None

    def resolve(self, resolver):
        if self.item is None:
            _class = self.class_.get_class()
            self.item = _class
        else:
            _class = self.item
        return _class

    def __str__(self):
        return str(self.class_)

    def serialize(self):
        return ('C', str(self.class_))

class FixupModRef(Fixup):
    __slots__ = ['mod_byte', 'offsets']

    def __init__(self, module, raw_fxp):
        self.mod_byte, self.offsets = raw_fxp

    def get_class(self):
        # n/a
        raise NotImplementedError()

    def __str__(self):
        return str(self.mod_byte)

    def serialize(self):
        raise NotImplementedError()

class RoutineDef(object):

    # Access flags
    ATTRS = {
        0x001: 'public', 0x002: 'private', 0x004: 'protected', 0x008: 'final',
        0x010: 'static', 0x020: 'abstract', 0x040: 'throws', 0x80: 'is_<init>',
        0x100: 'is_<clinit>',
    }

    def TYPE(self):
        return RoutineDef

    def __init__(self, module, raw_rd):
        # Bail out if deserializing
        if (module is None) and (raw_rd is None): return

        self.module = module
        R = module._R

        # We don't know what our parent/owning class is (yet)
        self.parent = None

        # We may need to look this routine up by address
        self.offset = raw_rd._start - module._cf.code._start

        # Get name/type/attribute information
        self.name = R.get_id(raw_rd.name)
        self.param_types = R.get_tlist(raw_rd.param_types)
        self.return_type = R.get_tlist(raw_rd.return_type)
        self.attrs = utils.parse_flags(raw_rd.attrs, self.ATTRS)

        # Get runtime constraints/initial state
        self.max_stack = raw_rd.max_stack
        self.max_locals = raw_rd.max_locals
        self.stack_size = raw_rd.stack_size

        # Get the stackmaps (if any)
        self.stack_map = [StackMapEntry(module, self, sme) for sme in raw_rd.stack_map]

        # Placeholder arrays for instructions/handlers
        self.instructions = self.handlers = []

        # Get the bytecode (to be disassembled later)
        self.code_offset = raw_rd.code_offset - module._cf.code._start
        self.code = raw_rd.byte_code

        # Keep a copy of the raw exception handlers (they'll be needed in disasm())
        # (Also keep track of the offset of where our code started)
        self._raw_handlers = raw_rd.handlers

        self._disasmed, self._resolved = False, False

    def set_parent(self, class_def):
        assert (self.parent is None), "Routine '%s' already associated with class '%s'!" % (self.get_name(), self.parent)
        self.parent = class_def

    def resolve(self, resolver):
        if self._resolved: return self
        self._resolved = True
        assert (self.parent is not None), "Routine must be associated with its parent class before resolution!"

        # Resolve type references in our metadata
        self.param_types.resolve(resolver)
        self.return_type.resolve(resolver)
        for sme in self.stack_map: sme.resolve(resolver)

        return self

    def disasm(self, auto_resolve = True):
        if self._disasmed: return self
        self._disasmed = True

        # Disassemble/fixup all instructions
        self.instructions = [instr for instr in disasm.disassembly(self)]
        # Fixup all instructions
        if auto_resolve:
            self.instructions = [instr.fixup(self, auto_resolve=auto_resolve) for instr in self.instructions]

        # Parse/fixup exception handlers
        if auto_resolve:
            self.handlers = [ExHandler(self.module, self, xh).fixup(self) for xh in self._raw_handlers]
        del self._raw_handlers  # No longer needed

        return self

    def get_access(self):
        access = utils.format_flags(self.attrs, ACC_FLAGS) or None
        return access

    def get_mode(self):
        mode = utils.format_flags(self.attrs, MODE_FLAGS) or None
        # if a synch or synch static instruction is present, then this is a synchronized function
        if len(self.instructions) > 1:
            names = [x._name for x in self.instructions]
            if 'synch' in names or 'synch_static' in names:
                # add the synchronized keyword
                if mode is None:
                    return 'synchronized'
                else:
                    return ' '.join(mode.split(' ') + ['synchronized'])
        return mode

    def java_def(self, full_name=True, params_on_newlines=True):
        access = self.get_access()
        mod = self.get_mode()
        name = self.get_name()
        prefix = ' '.join(filter(None, [access, mod, str(self.return_type), name]))
        params = self.param_types if ('static' in self.attrs) else self.param_types[1:]
        param_str = ', '.join(map(str, params))
        if params_on_newlines and (len(param_str) > 80 and len(params) > 1):
                # bring each param on a new line
                s = ',\n' + ' '*(len(prefix) + 1)
                param_str = s.join(param_str.split(', '))
        return "%s(%s)" % (prefix, param_str)

    def get_name(self):
        name_db = self.parent.module._L.get_routine_renaming_db()
        if name_db:
            try:
                return name_db[self.to_jts(False)]
            except KeyError:
                pass
        return self.name

    def __str__(self):
        name = "%s/%s" % (self.parent, self.get_name()) if (self.parent is not None) else self.get_name()
        rt = self.return_type if self.return_type else 'V'
        return "%s(%s)%s" % (name, self.param_types.to_jts(), rt)

    def __repr__(self):
        return "<method: '%s' @ 0x%04x>" % (str(self), self.offset)

    def serialize(self):
        '''Serialize a REFERENCE to ourselves (offset in module, full signature).'''
        return (self.offset, self.to_jts(False))

    def to_jts(self, actual=True, skip_first=False):
        name = self.name
        if actual:
            name = self.get_name()
        rt = self.return_type if self.return_type else 'V'
        return "%s/%s(%s)%s" % (
            self.parent.name,
            name,
            self.param_types.to_jts(skip_first=skip_first),
            rt,
        )

    def to_jasmin(self, log_file=sys.stderr):
        #.method <access_spec> <method_name> <descriptor>
        #    [<statement>]*
        #.end method

        #<statement> {
        #   .limit stack <integer>
        #   | .limit locals <integer>
        #   | .line <integer>
        #   | .var <var_number> is <var_name> <descriptor> [signature <sign>] from <label1> to <label2>
        #   | .var <var_number> is <var_name> <descriptor> [signature <sign>] from <offset1> to <offset2>
        #   | .throws <classname>
        #   | .catch <classname> from <label1> to <label2> using <label3>
        #   | .catch <classname> from <offset1> to <offset2> using <offset3>
        #   | .signature "<signature>"
        #   | .stack
        #         [offset {<pc> | <label>}]
        #         [locals <verification_type> [<verification_arg>]]
        #         (...)
        #         [stack  <verification_type> [<verification_arg>]]
        #         (...)
        #     .end stack
        #   | .stack use [n] locals
        #         (...)
        #     .end stack
        #   | <instruction> [<instruction_args>]
        #   | <Label>:
        #   | .deprecated
        #   | <generic> ; see below for the use of generic attributes

        buf = StringIO()
        access = self.get_access()
        mode = self.get_mode()
        prefix = ' '.join(filter(None, [access, mode]))
        skip_first = False
        if 'static' not in prefix:
            skip_first = True
        descriptor = self.to_jts(skip_first=skip_first)[len(self.parent.to_jts() + '/'):]
        print >>buf, ".method %s %s" % (prefix, descriptor)

        #print >>buf, "    .limit stack %d" % self.max_stack
        #print >>buf, "    .limit locals %d" %  self.max_locals

        # TODO: if we had or could collect this information
        #for throw in self.throws:
        #  print >>buf, "    .throws %s" % self.throw.to_jts()

        # collect any labels we may need
        label_locations = set()

        # exception handlers
        for handler in self.handlers:
            # Add both target address and scope ranges
            label_locations.add(handler.scope[0])
            label_locations.add(handler.scope[1])
            label_locations.add(handler.target)

            # if it's not a finally
            if handler.type:
                print >>buf, "    .catch %s from loc_%d to loc_%d using loc_%d" % (handler.type,
                                                                                   handler.scope[0],
                                                                                   handler.scope[1],
                                                                                   handler.target)
            else:
                print >>buf, "    .catch all from loc_%d to loc_%d using loc_%d" % (handler.scope[0],
                                                                                    handler.scope[1],
                                                                                    handler.target)

        # branch labels
        for instruction in self.instructions:
            for location in instruction.get_branch_locations():
                label_locations.add(location)

        skip = 0
        for i, instruction in enumerate(self.instructions):
            # create a label if some instruction branches here
            if instruction.offset in label_locations:
                print >>buf, "loc_%d:" % instruction.offset

            # print the original COD instruction for reference
            print >>buf, "    ;     %04d: %s" % (instruction.offset, str(instruction))

            # we may need to skip instructions if we already processed them
            if skip:
                skip -= 0
                continue

            # alter following instructions for "isreal" float and double specification
            if instruction._name == 'isreal':
                continue
            # incorporate this instruction into the checkcast branch
            if len(self.instructions) > i+1:
                if self.instructions[i+1]._name in ['checkcastbranch', 'checkcastbranch_lib', 'checkcastbranch_array']:
                    continue

            if i != 0:
                if self.instructions[i-1]._name == 'isreal':
                    type = instruction._name[0]
                    to_type = None
                    if type == 'i':
                        to_type = 'f'
                    elif type == 'l':
                        to_type = 'd'
                    if instruction._name in [
                                        'ireturn', 'lreturn',
                                        'iload_0', 'iload_1', 'iload_2', 'iload_3',
                                        'iload_4', 'iload_5', 'iload_6', 'iload_7',
                                        'istore_0', 'istore_1', 'istore_2', 'istore_3',
                                        'istore_4', 'istore_5', 'istore_6', 'istore_7',
                                        'iaload', 'iastore', 'lastore', 'laload',
                                        'iload', 'iload_wide', 'istore', 'istore_wide',
                                        'lload', 'lload_wide', 'lstore', 'lstore_wide',
                                    ]:
                        # simply convert it
                        print >>buf, "    %s" % (to_type + instruction.to_jasmin(log_file)[1:])
                    elif instruction._name == 'iconst_0':
                        print >>buf, "    fconst_0"
                    elif instruction._name == 'bipush' and instruction.operands == [0,]:
                        print >>buf, "    fconst_0"
                    elif instruction._name == 'iipush' and instruction.operands == [1065353216,]:
                        print >>buf, "    fconst_1"
                    elif instruction._name == 'iipush' and instruction.operands == [1073741824,]:
                        print >>buf, "    fconst_2"
                    elif instruction._name == 'iipush':
                        item = unpack('f', pack('i', instruction.operands[0]))[0]
                        op_str = '%E' % item
                        # workaround because jasmin can't handle NaN/Infinity
                        if 'IND' in op_str or 'NAN' in op_str:
                            # NaN
                            print >>buf, "    ldc 0x7fc00000"
                            print >>buf, "    invokestatic java/lang/Float/intBitsToFloat(I)F"
                        elif 'INF' in op_str:
                            if op_str[0] == '-':
                                # -Infinity
                                print >>buf, "    ldc -3.4028237E38"
                            else:
                                # Infinity
                                print >>buf, "    ldc 3.4028237E38"
                        else:
                            print >>buf, "    ldc %s" % op_str
                    elif instruction._name == 'lipush' and instruction.operands == [0,]:
                        print >>buf, "    dconst_0"
                    elif instruction._name == 'lipush' and instruction.operands == [4607182418800017408,]:
                        print >>buf, "    dconst_1"
                    elif instruction._name == 'lipush':
                        item = unpack('d', pack('q', instruction.operands[0]))[0]
                        op_str = '%E' % item
                        # workaround because jasmin can't handle NaN/Infinity
                        if 'IND' in op_str or 'NAN' in op_str:
                            # NaN
                            print >>buf, "    ldc2_w 0x7ff8000000000000"
                            print >>buf, "    invokestatic java/lang/Double/longBitsToDouble(J)D"
                        elif 'INF' in op_str:
                            if op_str[0] == '-':
                                # -Infinity
                                print >>buf, "    ldc2_w -1.797693134862316E308"
                            else:
                                # Infinity
                                print >>buf, "    ldc2_w 1.797693134862316E308"
                        else:
                            print >>buf, "    ldc2_w %s" % op_str
                    else:
                        raise Exception('isreal instruction expected int or long instruction, instead found %s' % instruction)
                    continue
                elif instruction._name in ['checkcastbranch', 'checkcastbranch_lib', 'checkcastbranch_array']:
                    # checkcastbranch* comes out to be a combination of isinstance and checkcast
                    # and needs to be handled at the method level because the object needs to be
                    # pushed back on the stack by using the preceding load instruction.
                    # we could just dup instead, but that might violate the max stack size...
                    if i == 0:
                        raise Exception('checkcastbranch instruction expected a preceding instruction')
                    if self.instructions[i-1]._name.startswith('aload') or\
                        self.instructions[i-1]._name in ['getfield', 'getfield_wide',
                                                         'getstatic', 'lgetstatic',
                                                         'lgetfield', 'lgetfield_wide',]:
                        offset = instruction.get_branch_locations()[0]
                        jas =        '%s' % self.instructions[i-1].to_jasmin()
                        jas += '\n    instanceof %s' % instruction.operands[0].to_jts()
                        jas += '\n    ifeq loc_%d' % offset
                        jas += '\n    %s' % self.instructions[i-1].to_jasmin()
                        jas += '\n    checkcast %s' % instruction.operands[0].to_jts()
                        print >>buf, "    %s" % jas
                        continue
                    else:
                        # otherwise this is more complicated...
                        # use dup???
                        jas =        '%s' % self.instructions[i-1].to_jasmin()
                        jas += '\n    %s' % instruction.to_jasmin()
                    #raise Exception('checkcastbranch instruction expected a preceding instruction')

            # otherwise convert this instruction
            try:
                jas = instruction.to_jasmin(log_file)
                assert jas is not None
            except Exception, e:
                import traceback
                dump = StringIO()
                traceback.print_exc(file=dump)
                dump.seek(0)
                dump = dump.read()
                print >>log_file, 'ERROR IN METHOD %s:' % str(self)
                print >>log_file, 'ERROR CONVERTING INSTRUCTION: %s' % str(instruction)
                print >>log_file, dump
                jas =  'nop    ; ERROR IN METHOD: %s' % str(self)
                jas += '\n           ; ERROR CONVERTING INSTRUCTION: %s' % str(instruction)
                jas += '\n           ; '
                jas += '\n           ; '.join(dump.splitlines())

            print >>buf, "    %s" % jas
        print >>buf, ".end method"

        return buf.getvalue()

class StackMapEntry(object):
    __slots__ = ['label', 'type']

    def __init__(self, module, routine, raw_xh):
        if (module is None) and (routine is None) and (raw_xh is None): return
        R = module._R
        self.label = raw_xh.label
        self.type = R.get_tlist(raw_xh.type)

    def resolve(self, resolver):
        self.type.resolve(resolver)

    def __str__(self):
        return "%s @ %05d" % (self.type.to_jts(), self.label)

    def __repr__(self):
        return "<stack-map: '%s'>" % str(self)

    def serialize(self):
        return (self.label, self.type.serialize())

class ExHandler(object):
    __slot__ = ['scope', 'target', '_type_id', '_type_offset', 'type']

    def __init__(self, module, routine, raw_xh):
        if (module is None) and (routine is None) and (raw_xh is None): return
        R = module._R
        self.scope = (raw_xh.start, raw_xh.end)
        self.target = raw_xh.target
        self._type_id = raw_xh.type
        self._type_offset = raw_xh.type_offset
        self.type = utils.UnresolvedClass(self._type_id)

    def fixup(self, routine):
        mod = routine.parent.module
        try:
            self.type = mod._fixup_map[self._type_offset]
            assert isinstance(self.type, (ClassDef, ClassRef))
        except KeyError:
            self.type = mod._R.get_class(self._type_id)
        except (NotImplementedError, AssertionError):
            mod._L.log("WARNING: detected non-class ('%s' [%s]) as a type-fixup for '%s' @ 0x%05x" % (self.type, type(self.type), self, self._type_offset))
            self.type = None

        return self

    def __str__(self):
        return "%s(%d..%d) => %d" % (self.type, self.scope[0], self.scope[1], self.target)

    def __repr__(self):
        return "<xh: '%s'>" % str(self)

    def serialize(self):
        return (
            str(self.type) if self.type is not None else None,
            self.type.module.get_base_module_name() if self.type is not None else None,
            self.scope,
            self.target
        )

class ClassDef(object):

    ATTRS = {
        0x001: 'public', 0x002: 'private', 0x004: 'protected', 0x008: 'final',
        0x010: 'abstract', 0x020: 'interface', 0x040: 'has_verify_error',
        0x080: 'is_persistable', 0x100: 'is_ungroupable', 0x200: 'is_inner',
    }

    def TYPE(self):
        return ClassDef

    def __init__(self, module, raw_cd):
        # Special case--if we are given None for module/raw_class, bail out now
        # (We're probably in the middle of being deserialized...)
        if (module is None) and (raw_cd is None):
            return

        R = module._R
        self.module = module

        # Handle name, hierarchy, and attributes
        self.package = R.get_id(raw_cd.pack_name)
        short_name = R.get_id(raw_cd.class_name)
        self.name = '%s/%s' % (self.package, short_name) if self.package else short_name
        self._superclass_id = raw_cd.superclass
        self.superclass = utils.UnresolvedClass(self._superclass_id)
        self._iface_ids = raw_cd.ifaces
        self.ifaces = [utils.UnresolvedClass(cid) for cid in self._iface_ids]
        self.attrs = utils.parse_flags(raw_cd.flags, self.ATTRS)

        # Handle fields (and their attributes, which are stored separate on disk)
        self.fields = [FieldDef(module, self, fd) for fd in raw_cd.fields]
        for i, f in enumerate(self.fields):
            f.set_attrs(raw_cd.field_attrs[i])
            if not f.name: f.name = "f_%03d" % (i + 1)
        self.static_fields = [FieldDef(module, self, fd) for fd in raw_cd.static_fields]
        for i, sf in enumerate(self.static_fields):
            sf.set_attrs(raw_cd.static_field_attrs[i])
            if not sf.name: sf.name = "sf_%03d" % (i + 1)

        # Create a static-field-address map
        self._static_address_map = dict((sf.address, sf) for sf in self.static_fields)

        # Handle methods (use the module's map of all routines by offset)
        _rmap = module._routine_map
        self.virtual_methods = [_rmap[offset] for offset in raw_cd.virtual_routines]
        self.nonvirtual_methods = [_rmap[offset] for offset in raw_cd.nonvirtual_routines]
        self.static_methods = [_rmap[offset] for offset in raw_cd.static_routines]

        # Name any un-named methods
        for i, m in enumerate(self.nonvirtual_methods):
            if not m.name: m.name = "m_%03d" % (i + 1)
        for i, vm in enumerate(self.virtual_methods):
            if not vm.name: vm.name = "vm_%03d" % (i + 1)
        for i, sm in enumerate(self.static_methods):
            if not sm.name: sm.name = "sm_%03d" % (i + 1)

        # Associate these methods with us (and only us)
        for m in itertools.chain(self.virtual_methods, self.nonvirtual_methods, self.static_methods):
            m.set_parent(self)

        # At first our virtual function table is empty (must wait until actualize()-time)
        self.vft = []

        # Same with our field-fixup table
        self.fft = []

        # Ditto our member-lookup table
        self.field_members = None
        self.method_members = None

        self._resolved = self._actualized = False

    @property
    def routines(self):
        return itertools.chain(self.virtual_methods, self.nonvirtual_methods, self.static_methods)

    @property
    def short_name(self):
        # Shouldn't need this a whole lot...
        try:
            return self.name.rsplit('/', 1)[1]
        except IndexError:
            return self.name

    def get_field_by_address(self, address):
        try:
            return self._static_address_map[address]
        except KeyError:
            return utils.UnresolvedStaticField(address)

    def get_member_by_name(self, m_name, m_type=None, is_field=False):
        assert (self._resolved), "Class '%s' must be resolved before by-name member lookup will work!" % self
        # we need to actualize in preparation to get inherited members
        self.actualize()

        # Make sure we have a member map
        if self.field_members is None:
            self.field_members = {}
            _all_members = itertools.chain(
                self.fields, self.static_fields,
            )
            for m in _all_members:
                try:
                    self.field_members[m.name].append(m)
                except KeyError:
                    self.field_members[m.name] = [m]
        if self.method_members is None:
            self.method_members = {}
            _all_members = itertools.chain(
                self.virtual_methods, self.nonvirtual_methods, self.static_methods,
            )
            for m in _all_members:
                try:
                    self.method_members[m.name].append(m)
                except KeyError:
                    self.method_members[m.name] = [m]
        try:
            if is_field:
                # Look up all members with this name
                candidates = self.field_members[m_name]

                # Do a field lookup (types ignored if we do not have it)
                if m_type:
                    c_fields = [c for c in candidates if isinstance(c, FieldDef) if c.type == m_type]
                    if len(c_fields) != 1:
                        # we need to be more OOPish
                        c_fields = [c for c in candidates if isinstance(c, FieldDef) if m_type.is_super_or_implements_or_equivalent(c.type)]
                else:
                    c_fields = [c for c in candidates if isinstance(c, FieldDef)]
                
                if m_type:
                    assert len(c_fields) == 1, "Class '%s' has %d fields named '%s' of type '%s' (Oops...)" % (self, len(c_fields), m_name, m_type)
                else:
                    assert len(c_fields) == 1, "Class '%s' has %d fields named '%s' (Oops...)" % (self, len(c_fields), m_name)
                return c_fields[0]
            else:
                # Look up all members with this name
                candidates = self.method_members[m_name]

                # Do a method lookup (types may be important, in case of overloading)
                c_methods = [c for c in candidates if isinstance(c, RoutineDef)]

                if m_type is None:
                    # There'd better be only 1!
                    assert len(c_methods) == 1, "Class '%s' has %d methods named '%s' (and I have no type data to disambiguate)" % (self, len(c_methods), m_name)
                    return c_methods[0]
                elif not len(c_methods):
                    raise KeyError()
                else:
                    # Try to match on types
                    for c in c_methods:
                        if m_type.is_super_or_implements_or_equivalent(c.param_types):
                            return c
                    '''
                    else:
                        try:
                            inherited_c = self.superclass.get_member_by_name(m_name, m_type, is_field)
                            if m_type.is_super_or_implements_or_equivalent(inherited_c.param_types):
                                return inherited_c
                        except ValueError:
                            pass

                    # ooooh, this is a bad bad thing
                    # return this if no better candidate is found
                    self.module._L.log("WARNING: Could not find match for %s(%s) in class %s in module %s... Selecting %s" % (m_name, m_type, self, str(self.module), c))
                    return c
                    '''
            raise KeyError()

        except KeyError as err:
            '''
            # TODO: remove
            if is_field:
                print >>sys.stderr, ""
                print >>sys.stderr, "Unresolved field name: (%s, %s, %s)" % (self, m_name, m_type)
                print >>sys.stderr, "Fields:"
                members = self.field_members.keys()
                members.sort()
                print >>sys.stderr, members
            else:
                print >>sys.stderr, ""
                print >>sys.stderr, "Unresolved method name: (%s, %s, %s)" % (self, m_name, m_type)
                print >>sys.stderr, "Methods:"
                members = self.method_members.keys()
                members.sort()
                print >>sys.stderr, members
                if m_name in self.method_members:
                    print >>sys.stderr, '**********************************************'
                    candidates = self.method_members[m_name]
                    c_methods = [c for c in candidates if isinstance(c, RoutineDef)]
                    for i, c in enumerate(c_methods):
                        print >>sys.stderr, i,
                        print >>sys.stderr, c.param_types
                    print '    Super:',
                    print [x.type.superclass for x in c.param_types][1]
                    print '    Iface:',
                    print [x.type.ifaces for x in c.param_types][1]
                    print repr(m_type[1])
                    print '    Super:',
                    print [x.type.superclass for x in m_type][1]
                    print '    Iface:',
                    print [x.type.ifaces for x in m_type][1]
                    print m_type.is_super_or_implements_or_equivalent(c.param_types)
                    #print utils.TypeList.from_jts(c.param_types, self.module)
                    #print utils.TypeList.from_jts(m_type, self.module)
                    print >>sys.stderr, '**********************************************'
                    #raw_input()
            '''
        
            # Try to see if we inherited this member
            if self.superclass:
                try:
                    return self.superclass.get_member_by_name(m_name, m_type, is_field)
                except ValueError:
                    # we want this error to happen on the original class
                    pass
            # interfaces inherit from other interfaces
            for iface in self.ifaces:
                try:
                    return iface.get_member_by_name(m_name, m_type, is_field)
                except ValueError:
                    # we want this error to happen on the original class
                    pass

        # If lookup failed, return a bad name ref
        if is_field:
            raise ValueError("Unresolved field name: (%s, %s, %s)" % (self, m_name, m_type))
        else:
            raise ValueError("Unresolved method name: (%s, %s, %s)" % (self, m_name, m_type))

    def _get_super_vft(self):
        '''Get our superclass's virtual function table (VFT).

            Returns [] if our superclass was None (i.e., if we are java.lang.Object).
            Ensures the superclass has been actualize()'d.
        '''
        _superclass = self.superclass.get_class() if (self.superclass is not None) else None
        if _superclass is not None:
            return _superclass.actualize().vft
        else:
            return []

    def resolve(self, resolver=None):
        if self._resolved: return self

        # Default to using our owning-module's resolver
        if resolver is None:
            resolver = self.module.get_class_resolver()

        # Resolve all simple types
        self.superclass = resolver(self._superclass_id)
        self.ifaces = map(resolver, self._iface_ids)
        for fd in self.fields: fd.resolve(resolver)
        for fd in self.static_fields: fd.resolve(resolver)

        # (Cannot delete static address map--modules that import us after we're resolved
        # may need that information...)
        self._resolved = True
        return self

    def actualize(self):
        '''Finalize out all computed attributes of our class (e.g., the VFT).

            This is a distinct step because:
                A: all modules/classes must be resolved prior to actualization
                B: all classes/routines must be actualized prior to disassembly
        '''
        if self._actualized: return self

        # Now that we know A: our super class and B: all our members' names, build
        # a virtual function table for this class...
        super_vft = self._get_super_vft()
        self.vft = super_vft[:]
        for vm in self.virtual_methods:
            for i in xrange(-1, -len(super_vft)-1, -1):
                _svm = super_vft[i]
                if (vm.name == _svm.name) and (vm.param_types[1:] == _svm.param_types[1:]):
                    self.vft[len(super_vft) + i] = vm
                    break
            else:
                self.vft.append(vm)

        # Likewise, compute the total number of fields we've inherited
        _class_chain = [self]
        _super = self.superclass
        while _super is not None:
            _class_chain.insert(0, _super)
            _super = _super.superclass
        for c in _class_chain:
            # Field lookup is slot-based, not index-based, so we double-insert wide fields
            for f in c.fields:
                if f.type.slots() == 2:
                    self.fft.append(f)
                self.fft.append(f)

        self._actualized = True
        return self

    def disasm(self, auto_resolve = True):
        '''Convert our routines' bytecode into disassembled (symbolic) pseudo-assembly code.

            All loaded classes/routines must be resolved+actualized prior to disassembly.
        '''
        for r in itertools.chain(self.virtual_methods, self.nonvirtual_methods, self.static_methods):
            r.disasm(auto_resolve = auto_resolve)

    def get_class(self):
        return self

    def java_def(self, full_name=True):
        access = utils.format_flags(self.attrs, ACC_FLAGS) or None
        mode = utils.format_flags(self.attrs, MODE_FLAGS) or None
        scope = '[inner]' if ('is_inner' in self.attrs) else None
        struct = 'interface' if ('interface' in self.attrs) else 'class'
        name = str(self) if full_name else self.name
        extends = ("extends %s" % self.superclass) if self.superclass else None
        implements = ("implements %s" % ', '.join(map(str, self.ifaces))) if self.ifaces else None
        return ' '.join(x for x in [access, mode, scope, struct, name, extends, implements] if x)

    def to_jts(self):
        # No longer messy!
        return self.name

    def to_jasmin(self, log_file=sys.stderr):
        buf = StringIO()
        print >>buf, ".bytecode 47.0"
        access = utils.format_flags(self.attrs, ACC_FLAGS) or None

        if 'interface' in self.attrs:
            # this is an interface
            if access:
                print >>buf, ".interface %s %s" % (access, self.to_jts())
            else:
                print >>buf, ".interface %s" % self.to_jts()
        else:
            # this is a class
            if access:
                print >>buf, ".class %s %s" % (access, self.to_jts())
            else:
                print >>buf, ".class %s" % self.to_jts()
        if self.superclass:
            print >>buf, ".super %s" % self.superclass.to_jts()
        else:
            print >>buf, ".super java/lang/Object"
        for iface in self.ifaces:
            print >>buf, ".implements %s" % iface.to_jts()
            # # TODO: interfaces can't have interfaces... superclass?
            #if 'interface' in self.attrs:
            #    print >>buf, ".super %s" % iface.to_jts()
            #else:
            #    print >>buf, ".implements %s" % iface.to_jts()
        #print >>buf, '.signature "<my::own>Signature()"'
        # TODO: implement enclosing method check
        #print >>buf, ".enclosing method foo/bar/Whatever/someMethod()"
        #print >>buf, '.debug "<debug_source_extension1>"'
        #print >>buf, '.debug "<debug_source_extension2>"'

        # we don't fully understand inner classes here...
        # for instance, the following two classes definitely exist:
        #     net/rim/device/apps/internal/mms/service/BackgroundTaskThread
        #     net/rim/device/apps/internal/mms/service/BackgroundTaskThread$1$TaskAppendingRunnable
        # however, the following class definitely does not exist (but it should according to the name!):
        #     net/rim/device/apps/internal/mms/service/BackgroundTaskThread$1
        # because this class does not exist, we can't find it with load_class and we crash
        # so we must temporarily disable inner class specification until we can figure this out...
        '''
        # if this class is an inner class or has inner classes
        if 'is_inner' in self.attrs:
            # outer classes
            inner_splits = self.to_jts().split('$')
            for i in range(1, len(inner_splits)):
                inner = '$'.join(inner_splits[:i+1])
                outer = '$'.join(inner_splits[:i])
                cl = self.module.load_class(inner)
                if 'interface' in cl.attrs:
                    print >>buf, '.inner interface %s inner %s outer %s' % (inner, inner, outer)
                else:
                    print >>buf, '.inner class %s inner %s outer %s' % (inner, inner, outer)
            # classes immediately inner to this class
            immediate_inners = [x for x in self.module.classes if x.to_jts().startswith(self.to_jts()+'$') and
                                                                  '$' not in x.to_jts()[len(self.to_jts())+1:] and
                                                                  not x.to_jts()[len(self.to_jts())+1:][0].isdigit()]
            for immediate_inner in immediate_inners:
                inner = immediate_inner.to_jts()
                outer = self.to_jts()
                if 'interface' in immediate_inner.attrs:
                    print >>buf, '.inner interface %s inner %s outer %s' % (inner, inner, outer)
                else:
                    print >>buf, '.inner class %s inner %s outer %s' % (inner, inner, outer)
        '''

        print >>buf, ""
        for field in self.fields:
            print >>buf, field.to_jasmin(log_file)
        for field in self.static_fields:
            print >>buf, field.to_jasmin(log_file)
        print >>buf, ""

        for routine in self.routines:
            print >>buf, routine.to_jasmin(log_file)
        print >>buf, ""

        return buf.getvalue()

    def is_super(self, other):
        '''Returns True if other is a superclass of self.'''
        sup = self.superclass
        while sup:
            if str(other) == str(sup):
                return True
            sup = sup.superclass
        return False

    def implements(self, other):
        '''Returns True if other is implemented by self.'''
        for iface in self.ifaces:
            # we implement it
            if str(iface) == str(other):
                return True
            # our interface is some subclass of it
            if iface.is_super(other):
                return True
            # maybe our interface implements it
            if iface.implements(other):
                return True
        return False

    def __cmp__(self, other):
        sself = str(self)
        sother = str(other)
        if str(self) == str(other):
            return 0
        # gt => more defined (ie String > Object)
        if self.is_super(other):
            return 1
        if other.is_super(self):
            return -1
        # gt => more defined (ie String > AbstractString)
        if self.implements(other):
            return 1
        if other.implements(self):
            return -1
        raise ValueError('Type compare mismatch: %s and %s' % (sself, sother))

    def __eq__(self, other):
        sself = str(self)
        sother = str(other)
        if str(self) == str(other):
            return True
        return False
    def __ne__(self, other):
        sself = str(self)
        sother = str(other)
        if str(self) != str(other):
            return True
        return False

    def __str__(self):
        # See how easy?!
        return self.name

    def __repr__(self):
        return "<class-def: '%s'>" % self

class FieldDef(object):
    __slots__ = ['parent', 'name', 'type', 'address', 'attrs']

    # Field access attributes
    ATTRS = { 0x01: 'public', 0x02: 'private', 0x04: 'protected', 0x08: 'final' }

    def TYPE(self):
        return FieldDef

    def __init__(self, module, parent, raw_fd):
        if (module is None) and (parent is None) and (raw_fd is None): return
        R = module._R
        self.parent = parent
        self.name = R.get_id(raw_fd.name)
        self.type = R.get_tlist(raw_fd.type)
        self.address = raw_fd.address if isinstance(raw_fd, format.CodStaticFieldDef) else None
        self.attrs = {}

    def set_attrs(self, attrs):
        self.attrs = utils.parse_flags(attrs, self.ATTRS)

    def resolve(self, resolver):
        self.type.resolve(resolver)

    def java_def(self, full_name=True):
        access = self.get_access()
        #access = utils.format_flags(self.attrs, ACC_FLAGS) or None
        #mode = 'static' if (self.address is not None) else None
        name = str(self) if full_name else self.get_name()
        return ' '.join(filter(None, [access, str(self.type), name]))

    def get_name(self):
        name_db = self.parent.module._L.get_field_renaming_db()
        if name_db:
            try:
                return name_db["%s/%s" % (self.parent, self.name)]
            except KeyError:
                pass
        return self.name

    def __str__(self):
        return "%s/%s" % (self.parent, self.get_name())

    def __repr__(self):
        if self.address:
            return "<field-def: '%s' @ 0x%04x>" % (self, self.address)
        else:
            return "<field-def: '%s'>" % self

    def get_access(self):
        access = utils.format_flags(self.attrs, ACC_FLAGS) or None
        # if static
        if self.address is not None:
            if access:
                return 'static ' + access
            else:
                return 'static'
        else:
            if not access:
                # TODO: both transient and volatile variables are 0... volatile?
                #return 'volatile'
                return None
        return access

    def to_jts(self, actual=True):
        if actual:
            return str(self)
        else:
            return "%s/%s" % (self.parent, self.name)

    def serialize(self):
        return (self.attrs.keys(), self.type.serialize(), self.name, self.address)

    def to_jasmin(self, log_file=sys.stderr):
        #.field <access_spec> <field_name> <descriptor> [signature <signature>] [ = <value> ]
        # |
        #.field <access_spec> <field_name> <descriptor> [signature <signature>] [ = <value> ]
        #    [<field_attribute>]
        #.end field
        access = self.get_access()
        if access is None:
            access = ''
        # TODO: get initialized values for static fields from cf.static_data
        return '.field %s %s %s' % (access, self.to_jts(), self.type.to_jts())
        #return '.field %s %s %s' % (access, name, self.type.to_jts())
        #return '.field %s %s %s' % (access, self.get_name(), self.type.to_jts())


class InterfaceMethodRef(object):
    __slots__ = ['_class_id', 'class_', 'offset', 'name', 'param_types', 'return_type']

    def __init__(self, module, raw_imr):
        R = module._R
        self.offset = raw_imr._start
        self._class_id = raw_imr.class_id
        self.class_ = utils.UnresolvedClass(self._class_id)
        self.name = R.get_id(raw_imr.name)
        self.param_types = R.get_tlist(raw_imr.param_types)
        self.return_type = R.get_tlist(raw_imr.return_type)

    def resolve(self, resolver):
        self.class_ = resolver(self._class_id)
        self.param_types.resolve(resolver)
        self.return_type.resolve(resolver)

    def get_method(self):
        return self.class_.get_member_by_name(self.name, self.param_types)

    def __str__(self):
        return "%s/%s(%s)%s" % (self.class_, self.name, self.param_types.to_jts(), self.return_type.to_jts())

    def __repr__(self):
        return "<iface-mref: %s>" % self

    def to_jts(self):
        return str(self)

class ClassRef(object):
    __slots__ = ['_loader', '_module', '_class_ref', 'offset', 'mod_index', 'package', 'class_', 'extra']

    def __init__(self, module, raw_cr):
        R = module._R
        self._loader = module._L
        # the module in which the class reference resides
        self._module = module
        self._class_ref = None
        self.offset = raw_cr._start

        self.mod_index = raw_cr.mod_index
        self.package = R.get_id(raw_cr.pack_name)
        self.class_ = R.get_id(raw_cr.class_name)
        self.extra = raw_cr.extra

    def get_class(self):
        if self._class_ref is None:
            # why doesn't this work!?!!? the mod_index does not always correspond
            # to an index into the imports table into this module's imports
            '''
            if self.mod_index == 0:
                base_module_name = self._module.get_base_module_name()
            else:
                base_module_name = self._module.imports[self.mod_index - 1].get_base_module_name()
            '''
            # rather than using module.load_class, we need to do this to
            # exploit the available mod_index
            self._class_ref = self._module.load_class(
                str(self),
                preferred_mod_index = self.mod_index,
            )
            '''
            # TODO: remove try..except
            try:
                self._class_ref = self._loader.load_class(base_module_name, str(self))
            except:
                self._loader.log('ERROR: class: %s' % str(self.class_))
                self._loader.log('ERROR: package: %s' % str(self.package))
                self._loader.log('ERROR: class ref module: %s' % str(self._module.name))
                self._loader.log('ERROR: imports: %s' % str([x.name for x in self._module.imports]))
                self._loader.log('ERROR: siblings: %s' % str(self._module.imports[self.mod_index - 1].siblings))
                self._loader.log('ERROR: module index: %s' % str(self.mod_index))
                self._loader.log('ERROR: extra: %s' % str(self.extra))
                self._loader.log('ERROR: module: %s' % self._module.imports[self.mod_index - 1].name)
                self._loader.log('ERROR: base module: %s' % base_module_name)
                raise
            '''
            del self._loader
            del self._module
        return self._class_ref

    def __str__(self):
        if self.package:
            return "%s/%s" % (self.package, self.class_)
        else:
            return self.class_

    def __repr__(self):
        return "<class-ref: [%03d] '%s' (%d:%d) @ 0x%04x>" % (self.mod_index, self, self.extra[0], self.extra[1], self.offset)

class Signature(object):
    __slots__ = ['type', 'tag', 'data']

    def __init__(self, module, raw_ti):
        if (module is None) and (raw_ti is None): return
        #assert (raw_ti.type == 1), "Unknown trailer item type code: %d" % raw_ti.type
        self.type = raw_ti.type
        self.tag = raw_ti.value[:4]
        self.data = raw_ti.value[4:]

    def __str__(self):
        return self.tag

    def __repr__(self):
        return "<sig: '%s' (%d bytes)>" % (self, len(self.data))

    def serialize(self):
        return (self.type, self.tag, self.data)
