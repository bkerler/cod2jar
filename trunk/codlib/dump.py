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
dump: Tool for dumping the parsed and/or resolved contents of a COD file.
"""

import sys
import os, os.path
import time
from subprocess import Popen, PIPE

class TextDumper(object):
    '''Base class for text-based dumpers.'''

    LINE = '-'*60

    def __init__(self, output_file, log_file=sys.stderr):
        self._out = output_file
        self._writer = output_file.write
        self._log = log_file
        self._indents = [0]
        self._i = ''

    def log(self, msg):
        print >> self._log, msg

    def indent(self, delta=2):
        self._indents.append(self._indents[-1] + delta)
        self._i = ' '*self._indents[-1]

    def dedent(self):
        assert (len(self._indents) > 0), "Indentation stack underflow!"
        self._indents.pop(-1)
        self._i = ' '*self._indents[-1]

    def out(self, *line_segs):
        _w = self._writer; _w(self._i);
        for ls in line_segs:
            _w(ls.replace('\n', '\n' + self._i))
        _w('\n')

    def hr(self):
        self.out(self.LINE)

class UnresolvedDumper(TextDumper):
    '''Dumper for unresolved modules/classes.'''
    def dump_module(self, M, verbose=False):
        M.disasm(auto_resolve=False)
        
        self.out("Module: %s (v. %s) @ %s" % (M.name, M.version, time.ctime(M.timestamp)))
        self.hr()
        if M.attrs:
            self.out("Attributes:"); self.indent();
            self.out(', '.join(M.attrs))
            self.dedent(); self.out()

        if M.exports:
            self.out("Exported Data:"); self.indent()
            for ed in M.exports:
                self.out("%s: %r" % (ed.name, ed.value))
            self.dedent(); self.out()

        if M.statics:
            self.out("Static Data:"); self.indent()
            for (address, value) in M.statics:
                self.out("0x%04x: %d" % (address, value))
            self.dedent(); self.out()

        if M.classes:
            self.out("Class Index:"); self.indent()
            for i, c in enumerate(M.classes):
                self.out("%4d. %s" % (i, c.java_def()))
            self.dedent(); self.out()

            self.out("Classes:"); self.indent()
            for c in M.classes:
                self.dump_class(c)
            self.dedent(); self.out()

        # This stuff is of interest only to devs/debuggers...
        if verbose:
            self.out("\n*** VERBOSE MODULE METADATA ***\n")
            if M.siblings:
                self.out("Siblings:"); self.indent()
                self.out(', '.join(M.siblings))
                self.dedent(); self.out()

            if M.aliases:
                self.out("Aliases:"); self.indent()
                self.out(', '.join(M.aliases))
                self.dedent(); self.out()

            if M.entry_points:
                self.out("Entry Points:"); self.indent()
                for i, ep in enumerate(M.entry_points):
                    self.out("%4d: %s" % (i, ep))
                self.dedent(); self.out()

            if hasattr(M, 'imports'):
                self.out("Imported Modules:"); self.indent()
                for i, imp in enumerate(M.imports):
                    self.out("%4d: %s (%s)" % (i+1, imp, M.import_versions[M.imports.index(imp)]))
                self.dedent(); self.out()
            else:
                imports = [(M._R.get_escaped_lit(n), M._R.get_escaped_lit(v)) for n,v in M._cf.data.modules[1:]]
                self.out("Imported Modules:"); self.indent()
                for i, (imp, ver) in enumerate(imports):
                    self.out("%4d: %s (%s)" % (i+1, imp, ver))
                self.dedent(); self.out()

            if M.iface_mrefs:
                self.out("Interface Method Refs:"); self.indent()
                for i, imr in enumerate(M.iface_mrefs):
                    #self.out("%4d: %s %s" % (i, imr.return_type, imr))
                    self.out("%4d: %s" % (i, imr))
                self.dedent(); self.out()

            if M.class_refs:
                self.out("Class Refs:"); self.indent()
                for i, cr in enumerate(M.class_refs):
                    self.out("%4d: %s [%s]" % (i, cr, cr.extra))
                self.dedent(); self.out()

            if M.field_fixups: self._dump_fixups("[Instance] Field Fixups:", M.field_fixups)
            if M.static_field_fixups: self._dump_fixups("Static Field Fixups:", M.static_field_fixups)
            if M.method_fixups: self._dump_fixups("Method Fixups:", M.method_fixups)
            if M.virtual_method_fixups: self._dump_fixups("Virtual Method Fixups:", M.virtual_method_fixups)
            if M.static_method_fixups: self._dump_fixups("Static Method Fixups:", M.static_method_fixups)
            if M.class_ref_fixups: self._dump_fixups("Class Ref Fixups:", M.class_ref_fixups)
            if M.mod_ref_fixups: self._dump_fixups("Module Ref Fixups:", M.mod_ref_fixups)

        self.hr()
        self.out()

    def _dump_fixups(self, header, fixups):
        self.out(header); self.indent()
        for fxp in fixups:
            self.out(str(fxp))
            if fxp.offsets:
                self.indent(); self.out(str(fxp.offsets)); self.dedent()
        self.dedent(); self.out()

    def dump_class(self, C, **kw):
        self.out(C.java_def(**kw), ' {'); self.indent()

        if C.vft:
            self.out(); self.out("// Virtual Funtion Table")
            for i, vm in enumerate(C.vft):
                self.out("// %3d: %s" % (i, vm.to_jts()))

        if C.fft:
            self.out(); self.out("// Field Lookup Table")
            skip = False
            for i, f in enumerate(C.fft):
                if skip:
                    skip = False
                    self.out("// %3d: (wide)" % i)
                else:
                    if f.type.slots() == 2:
                        skip = True
                    self.out("// %3d: %s {%s}" % (i, f.to_jts(), f.type))


        if C.fields:
            self.out(); self.out("// Non-static fields")
            for f in C.fields:
                self.dump_field(f, **kw)

        if C.static_fields:
            self.out(); self.out("// Static fields")
            for sf in C.static_fields:
                self.dump_field(sf, **kw)

        if C.nonvirtual_methods:
            self.out(); self.out("// Non-virtual methods")
            for m in C.nonvirtual_methods:
                self.dump_method(m, **kw)

        if C.virtual_methods:
            self.out(); self.out("// Virtual methods")
            for m in C.virtual_methods:
                self.dump_method(m, **kw)

        if C.static_methods:
            self.out(); self.out("// Static methods")
            for m in C.static_methods:
                self.dump_method(m, **kw)

        self.dedent(); self.out('}'); self.out()

    def dump_field(self, F, **kw):
        self.out(F.java_def(**kw), ';')

    def dump_method(self, M, **kw):
        self.out(M.java_def(**kw), ' {'); self.indent()

        if M.stack_map:
            for sme in M.stack_map:
                self.out("// ", str(sme))
            self.out("//", '-'*80)

        for i, instr in enumerate(M.instructions):
            self.out("// %3d. (%05d): %s" % (i, instr.offset, instr))

        if M.handlers:
            self.out("//", '-'*80)
            for xh in M.handlers:
                self.out("// ", str(xh))

        self.dedent(); self.out('}'); self.out()

class ResolvedDumper(TextDumper):
    '''Dumper for resolved modules/classes.'''
    def dump_module(self, M, verbose=False):
        # Make sure the module has been resolved before dumping it
        M.resolve()

        self.out("Module: %s (v. %s) @ %s" % (M.name, M.version, time.ctime(M.timestamp)))
        self.hr()
        if M.attrs:
            self.out("Attributes:"); self.indent();
            self.out(', '.join(M.attrs))
            self.dedent(); self.out()

        if M.exports:
            self.out("Exported Data:"); self.indent()
            for ed in M.exports:
                self.out("%s: %r" % (ed.name, ed.value))
            self.dedent(); self.out()

        if M.statics:
            self.out("Static Data:"); self.indent()
            for (address, value) in M.statics:
                self.out("0x%04x: %d" % (address, value))
            self.dedent(); self.out()

        if M.classes:
            self.out("Class Index:"); self.indent()
            for i, c in enumerate(M.classes):
                self.out("%4d. %s" % (i, c.java_def()))
            self.dedent(); self.out()

            self.out("Classes:"); self.indent()
            for c in M.classes:
                self.dump_class(c)
            self.dedent(); self.out()

        # This stuff is of interest only to devs/debuggers...
        if verbose:
            self.out("\n*** VERBOSE MODULE METADATA ***\n")
            if M.siblings:
                self.out("Siblings:"); self.indent()
                self.out(', '.join(M.siblings))
                self.dedent(); self.out()

            if M.aliases:
                self.out("Aliases:"); self.indent()
                self.out(', '.join(M.aliases))
                self.dedent(); self.out()

            if M.entry_points:
                self.out("Entry Points:"); self.indent()
                for i, ep in enumerate(M.entry_points):
                    self.out("%4d: %s" % (i, ep))
                self.dedent(); self.out()

            if hasattr(M, 'imports'):
                self.out("Imported Modules:"); self.indent()
                for i, imp in enumerate(M.imports):
                    self.out("%4d: %s (%s)" % (i+1, imp, M.import_versions[M.imports.index(imp)]))
                self.dedent(); self.out()
            else:
                imports = [(M._R.get_escaped_lit(n), M._R.get_escaped_lit(v)) for n,v in M._cf.data.modules[1:]]
                self.out("Imported Modules:"); self.indent()
                for i, (imp, ver) in enumerate(imports):
                    self.out("%4d: %s (%s)" % (i+1, imp, ver))
                self.dedent(); self.out()

            if M.iface_mrefs:
                self.out("Interface Method Refs:"); self.indent()
                for i, imr in enumerate(M.iface_mrefs):
                    #self.out("%4d: %s %s" % (i, imr.return_type, imr))
                    self.out("%4d: %s" % (i, imr))
                self.dedent(); self.out()

            if M.class_refs:
                self.out("Class Refs:"); self.indent()
                for i, cr in enumerate(M.class_refs):
                    self.out("%4d: %s [%s]" % (i, cr, cr.extra))
                self.dedent(); self.out()

            if M.field_fixups: self._dump_fixups("[Instance] Field Fixups:", M.field_fixups)
            if M.static_field_fixups: self._dump_fixups("Static Field Fixups:", M.static_field_fixups)
            if M.method_fixups: self._dump_fixups("Method Fixups:", M.method_fixups)
            if M.virtual_method_fixups: self._dump_fixups("Virtual Method Fixups:", M.virtual_method_fixups)
            if M.static_method_fixups: self._dump_fixups("Static Method Fixups:", M.static_method_fixups)
            if M.class_ref_fixups: self._dump_fixups("Class Ref Fixups:", M.class_ref_fixups)
            if M.mod_ref_fixups: self._dump_fixups("Module Ref Fixups:", M.mod_ref_fixups)

        self.hr()
        self.out()

    def _dump_fixups(self, header, fixups):
        self.out(header); self.indent()
        for fxp in fixups:
            self.out(str(fxp))
            if fxp.offsets:
                self.indent(); self.out(str(fxp.offsets)); self.dedent()
        self.dedent(); self.out()

    def dump_class(self, C, **kw):
        self.out(C.java_def(**kw), ' {'); self.indent()

        if C.vft:
            self.out(); self.out("// Virtual Funtion Table")
            for i, vm in enumerate(C.vft):
                self.out("// %3d: %s" % (i, vm.to_jts()))

        if C.fft:
            self.out(); self.out("// Field Lookup Table")
            skip = False
            for i, f in enumerate(C.fft):
                if skip:
                    skip = False
                    self.out("// %3d: (wide)" % i)
                else:
                    if f.type.slots() == 2:
                        skip = True
                    self.out("// %3d: %s {%s}" % (i, f.to_jts(), f.type))


        if C.fields:
            self.out(); self.out("// Non-static fields")
            for f in C.fields:
                self.dump_field(f, **kw)

        if C.static_fields:
            self.out(); self.out("// Static fields")
            for sf in C.static_fields:
                self.dump_field(sf, **kw)

        if C.nonvirtual_methods:
            self.out(); self.out("// Non-virtual methods")
            for m in C.nonvirtual_methods:
                self.dump_method(m, **kw)

        if C.virtual_methods:
            self.out(); self.out("// Virtual methods")
            for m in C.virtual_methods:
                self.dump_method(m, **kw)

        if C.static_methods:
            self.out(); self.out("// Static methods")
            for m in C.static_methods:
                self.dump_method(m, **kw)

        self.dedent(); self.out('}'); self.out()

    def dump_field(self, F, **kw):
        self.out(F.java_def(**kw), ';')

    def dump_method(self, M, **kw):
        self.out(M.java_def(**kw), ' {'); self.indent()

        if M.stack_map:
            for sme in M.stack_map:
                self.out("// ", str(sme))
            self.out("//", '-'*80)

        for i, instr in enumerate(M.instructions):
            self.out("// %3d. (%05d): %s" % (i, instr.offset, instr))

        if M.handlers:
            self.out("//", '-'*80)
            for xh in M.handlers:
                self.out("// ", str(xh))

        self.dedent(); self.out('}'); self.out()

class PackageDumper(object):
    def __init__(self, package_root='.', log_file=sys.stderr, force_update=True):
        self._root = package_root
        self._log = log_file
        self._force_update = force_update

    def log(self, msg):
        print >> self._log, msg

    def _class_src_file(self, class_def):
        packpath = class_def.package.replace('/', os.path.sep)
        dirpath = os.path.join(self._root, packpath)

        # POTENTIAL RACE CONDITION (which I don't really care about...)
        if not os.path.exists(dirpath):
            os.makedirs(dirpath)

        filename = "%s.java" % class_def.short_name
        return os.path.join(dirpath, filename)

    def std_comments(self, dumper):
        dumper.out("// Dumped by cod2jar @ %s" % time.ctime())

    def dump_class_file(self, class_def):
        if self._force_update or not os.path.isfile(self._class_src_file(class_def)):
            with open(self._class_src_file(class_def), 'w') as fd:
                D = ResolvedDumper(fd, self._log)
                #self.log("Dumping class '%s'..." % class_def)
                self.std_comments(D)
                D.out("// From '%r'" % class_def.module)
                D.out("package %s;" % class_def.package)
                D.out()
                D.dump_class(class_def, full_name=False)

class SerialDumper(object):
    '''Experimental serializing-dumper; works on COD modules.'''
    def __init__(self, cache_root='.', log_file=sys.stderr):
        self._root = cache_root
        self._log = log_file

    def log(self, msg):
        print >> self._log, msg

    def dump_module(self, M):
        import cPickle

        # Dump a module-index db file (a pickled-dictionary)
        module_db_path = os.path.join(self._root, M.name + ".cod.db")
        try:
            with open(module_db_path, 'wt') as fd:
                cPickle.dump({
                    'name': M.name,
                    'version': M.version,
                    'timestamp': M.timestamp,
                    'attrs': M.attrs.keys(),
                    'siblings': M.siblings,
                    'imports': [I.name for I in M.imports],
                    'import_versions': M.import_versions,
                    'aliases': M.aliases,
                    'exports': [X.serialize() for X in M.exports],
                    'entry_points': [EP.serialize() for EP in M.entry_points],
                    'statics': M.statics,
                    'classes': map(str, M.classes),
                    'routines': [R.serialize() for R in M.routines],
                    'signatures': [S.serialize() for S in M.signatures]
                }, fd)
        except:
            os.remove(module_db_path)
            raise

        # Then dump all the classes as .cache files (organized by package/class hierarchy)
        for C in M.classes:
            self.dump_class(C, M.name)

    def _class_cache_file(self, class_def):
        packpath = class_def.package.replace('/', os.path.sep)
        dirpath = os.path.join(self._root, class_def.module.get_base_module_name(), packpath)

        # POTENTIAL RACE CONDITION (which I don't really care about...)
        if not os.path.exists(dirpath):
            os.makedirs(dirpath)

        filename = "%s.cache" % class_def.short_name
        return os.path.join(dirpath, filename)

    def dump_class(self, C, module_name):
        import cPickle

        # NOTE: we could make this more efficient by making *_modules
        # an index into the imports list +1 rather than the full name
        # TODO: delete *_modules
        try:
            with open(self._class_cache_file(C), 'wt') as fd:
                cPickle.dump({
                    'module': module_name,
                    'name': str(C),
                    'superclass': str(C.superclass) if C.superclass else None,
                    'superclass_module': str(C.superclass.module.get_base_module_name()) if C.superclass else None,
                    'ifaces': map(str, C.ifaces),
                    'ifaces_modules': [str(iface.module.get_base_module_name()) for iface in C.ifaces],
                    'attrs': C.attrs.keys(),
                    'fields': [F.serialize() for F in C.fields],
                    'static_fields': [F.serialize() for F in C.static_fields],
                    'virtual_methods': map(self.dump_method, C.virtual_methods),
                    'nonvirtual_methods': map(self.dump_method, C.nonvirtual_methods),
                    'static_methods': map(self.dump_method, C.static_methods),
                    'vft': [vm.to_jts(False) for vm in C.vft],
                    'vft_modules': [vm.module.get_base_module_name() for vm in C.vft],
                    'fft': [f.to_jts(False) for f in C.fft],
                    'fft_modules': [f.parent.module.get_base_module_name() for f in C.fft],
                }, fd)
        except:
            os.remove(self._class_cache_file(C))
            raise

    def dump_method(self, M):
        return {
            'name': M.name,
            'param_types': M.param_types.serialize(),
            'return_type': M.return_type.serialize(),
            'attrs': M.attrs.keys(),
            'limits': (M.max_locals, M.max_stack, M.stack_size),
            'stack_map': [SM.serialize() for SM in M.stack_map],
            'code_offset': M.code_offset,
            'instructions': [I.serialize() for I in M.instructions],
            'handlers': [H.serialize() for H in M.handlers],
        }

class XMLDumper(object):
    '''XML-dumper for raw (unresolved) COD parse trees.
    '''
    def __init__(self, output_file, log_file=sys.stderr):
        from xml.etree.ElementTree import TreeBuilder
        self._out = output_file
        self._log = log_file
        self._tb = TreeBuilder()

    def log(self, msg):
        print >> self._log, msg

    def start(self, tag, **attrs):
        return self._tb.start(tag, dict((k, str(v)) for k, v in attrs.iteritems()))

    def data(self, data):
        self._tb.data(data)
        return self

    def end(self, tag):
        x = self._tb.end(tag)
        self.data('\n')
        return x

    def close(self):
        from xml.etree.ElementTree import TreeBuilder
        x = self._tb.close()
        self._tb = TreeBuilder()
        return x

    def dump_cod(self, cod_file):
        from xml.etree.ElementTree import ElementTree

        self.start(type(cod_file).__name__)
        self.dump_struct(cod_file)
        self.end(type(cod_file).__name__)

        etree = ElementTree(self.close())
        etree.write(self._out)
        return etree

    def dump_struct(self, struct):
        for name in struct:
            self.dump_field(name, getattr(struct, name))

    def dump_field(self, name, value):
        from bytecleaver import Struct

        attrs = {'name': name}
        #try:
        #    attrs['raw'] = repr(value._C.get_range(value._start, value._end))
        #except:
        #    pass
        if isinstance(value, Struct):
            attrs['start'] = str(value._start)
            attrs['end'] = str(value._end)
            attrs['length'] = str(len(value))

        self.start(type(value).__name__, **attrs)
        self.dump_value(value)
        self.end(type(value).__name__)

    def dump_value(self, value):
        from bytecleaver import Struct

        if isinstance(value, Struct):
            self.dump_struct(value)
        elif type(value) is list:
            for i, item in enumerate(value):
                self.start(type(item).__name__, index=str(i))
                self.dump_value(item)
                self.end(type(item).__name__)
        else:
            self.data(repr(value))

class BinaryDumper(object):
    '''Binary dumper for top level structures of raw (unresolved)
         COD parse trees.
    '''
    def __init__(self, output_file, log_file=sys.stderr):
        self._out = output_file
        self._log = log_file
        self._indent = 0

    def start(self):
        self._indent += 1

    def end(self):
        self._indent -= 1

    def log(self, msg):
        print >> self._out, msg

    def data(self, data):
        print >> self._out, repr(data)
        print >> self._out, ''

    def close(self):
        pass

    def dump_cod(self, cod_file):
        print >> self._out, type(cod_file).__name__ + ':'
        self.start()
        for name in cod_file:
            item = getattr(cod_file, name)
            print >> self._out, ('%s (%s)' % (name, type(item).__name__)) + ':'
            self.dump_value(item)
            self.dump_struct(item)
        self.end()

    def dump_struct(self, struct):
        for name in struct:
            self.dump_field(name, getattr(struct, name))

    def dump_field(self, name, value):
        self.start()
        print >> self._out, ('%s (%s)' % (name, type(value).__name__)) + ':'
        self.dump_value(value)
        self.end()

    def dump_value(self, value):
        from bytecleaver import Struct

        if isinstance(value, Struct):
            self.start()
            self.data(value._C.get_range(value._start, value._end))
            self.end()
        elif type(value) is list:
            for i, item in enumerate(value):
                self.start()
                print >> self._out, ('#%d, %s' % (i, type(item).__name__)) + ':'
                self.dump_value(item)
                self.end()
        else:
            #print 'Warning: non-structure encountered:',
            self.start()
            self.data(repr(value))
            self.end()

class JasminDumper(object):
    '''JasminXT file format dumper.'''
    def __init__(self, package_root='.', log_file=sys.stderr, application_level=False, force_update=True):
        self._root = package_root
        self._log = log_file
        self._application_level = application_level
        self._force_update = force_update

    def log(self, msg):
        print >> self._log, msg

    def _jasmin_src_file(self, class_def):
        packpath = class_def.package.replace('/', os.path.sep)
        if self._application_level:
            dirpath = os.path.join(self._root, class_def.module.get_base_module_name(), packpath)
        else:
            dirpath = os.path.join(self._root, packpath)

        # POTENTIAL RACE CONDITION (which I don't really care about...)
        if not os.path.exists(dirpath):
            os.makedirs(dirpath)

        filename = "%s.j" % class_def.short_name
        return os.path.join(dirpath, filename)

    def std_comments(self, class_def, fd):
        print >>fd, "; Dumped by cod2jar @ %s" % time.ctime()
        print >>fd, "; "
        print >>fd, "; From COD: %s" % str(class_def.module)
        print >>fd, ""

    def dump_class(self, class_def):
        if not self._force_update and not self._application_level and os.path.isfile(self._jasmin_src_file(class_def)):
            # this file already exists!!!
            # this means another application has a class with the same classpath
            self.log('WARNING: Jasmin dump of %s already exists. Consider dumping per application (-a argument in cod2jar) identical classpath dump names.' % str(class_def))
        if self._force_update or not os.path.isfile(self._jasmin_src_file(class_def)):
            with open(self._jasmin_src_file(class_def), 'w') as fd:
                self.std_comments(class_def, fd)
                print >>fd, class_def.to_jasmin(self._log)

class ClassDumper(object):
    '''JVM class file format dumper.'''
    def __init__(self, jasmin_root='.', log_file=sys.stderr, application_level=False, force_update=True):
        self._root = jasmin_root
        self._log = log_file
        self._application_level = application_level
        self._force_update = force_update
        # find jasmin.jar in the PATH environment variable
        self._jasmin_path = None
        for path in os.environ['PATH'].split(os.pathsep):
            path = os.path.join(path, 'jasmin.jar')
            if os.path.isfile(path):
                self._jasmin_path = path
        if not self._jasmin_path:
            raise(Exception('Could not find "jasmin.jar" in the PATH environment variable! Please add the Jasmin directory to your PATH.'))

    def log(self, msg):
        print >> self._log, msg

    '''
    def dump(self):
        for dirpath, dirnames, filenames in os.walk(self._root):
            for filename in filenames:
                source_file_path = os.path.join(dirpath, filename)
                if filename.endswith('.j'):
                    if self._force_update or not os.path.isfile(source_file_path[:-2]+'.class'):
                        if self._application_level:
                            dump_root = os.path.join(self._root)
                        else:
                            dump_root = self._root
                        # TODO:
                        sub = Popen(["java", "-jar", self._jasmin_path, "-d", dump_root, source_file_path], stdout=PIPE, stderr=PIPE, env=os.environ)
                        jout, jerr = sub.communicate()
                        print >> self._log, '\n'.join(filter(lambda x: x != '', [jout, jerr]))
                        if jerr:
                            raise(Exception('"' + jerr + '"'))
    '''

    def dump_class(self, class_def):
        if self._application_level:
            jasmin_path = os.path.join(self._root, class_def.module.get_base_module_name(), class_def.to_jts() + '.j')
            dump_root = os.path.join(self._root, class_def.module.get_base_module_name())
        else:
            jasmin_path = os.path.join(self._root, class_def.to_jts() + '.j')
            dump_root = self._root
        if not os.path.isfile(jasmin_path):
            jd = JasminDumper(self._root, self._log)
            jd.dump_class(class_def)
        sub = Popen(["java", "-jar", self._jasmin_path, "-d", dump_root, jasmin_path], stdout=PIPE, stderr=PIPE, env=os.environ)
        jout, jerr = sub.communicate()
        print >> self._log, '\n'.join(filter(lambda x: x != '', [jout, jerr]))
        if jerr:
            raise(Exception('"' + jerr + '"'))
