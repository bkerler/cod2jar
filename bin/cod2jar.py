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
Convert all CODs in a directory or create a comprehensive serialized class-cache.
Class-caches are useful for CODs that will be processed many times (like operating
system dependencies or standard libraries).
"""

import os, sys, traceback, glob, time, zipfile
from optparse import OptionParser
from StringIO import StringIO
import codlib

class Progress(object):
    def __init__(self, caption, total):
        self._caption = caption
        self._total = total
        self._start = time.time()

    def _format_timespan(self, secs):
        return "%02d:%02d" % divmod(secs, 60)

    def update(self, count, output=sys.stdout):
        if not self._total:
            return
        ratio = float(count) / self._total
        elapsed = time.time() - self._start
        if ratio != 0:
            eta = ((1.0 / ratio) * elapsed) - elapsed
        else:
            eta = 0
        percent = ratio * 100

        if eta > 0:
            eta = " ETA[%s]" % self._format_timespan(eta)
        else:
            eta = "           "  # "erase" the previous ETA

        output.write("\r%s: %d/%d (%.2f%%) Time[%s]%s" % (
            self._caption,
            count,
            self._total,
            percent,
            self._format_timespan(elapsed),
            eta
        ))

class Cod2Jar(object):

    DUMP_FORMATS = [
        'cache',
        'text',
        'xml',
        'jasmin',
        'class',
        'jar',
    ]

    def __init__(self, cods, options):
        # figure out what format we are dumping in
        format = options.format.lower()
        if format not in self.DUMP_FORMATS:
            print >>sys.stderr, "Dump format '%s' not supported" % format
            sys.exit()
        else:
            self._module_dumper = getattr(self, "do_%s_dump" % format)
            self._format = format

        self._out_path = os.path.abspath(options.out_path)
        # you must not be understanding me...
        if self._out_path.endswith('.jar') or \
           self._out_path.endswith('.zip') or \
           self._out_path.endswith('.xml') or \
           self._out_path.endswith('.txt') or \
           self._out_path.endswith('.text') or \
           self._out_path.endswith('.j') or \
           self._out_path.endswith('.jasmin') or \
           self._out_path.endswith('.class'):
            self._out_path = '.'.join(self._out_path.split('.')[:-1])

        # Slight race condition
        if not os.path.exists(self._out_path):
            os.makedirs(self._out_path)

        self._make_log = open(os.path.join(self._out_path, "cod2jar.log"), 'wt')
        self._loader_log = open(os.path.join(self._out_path, "loader.log"), 'wt')
        self._hiscan_log = open(os.path.join(self._out_path, "hiscan.log"), 'wt')

        # dump mode
        self.individual_mode = options.individual_mode
        if self._format == 'cache':
            self.individual_mode = True
            self.log("WARNING: reverting to individual dump mode for cache creation")

        # Expand the list of COD files
        if (len(cods) == 1) and (cods[0].lower() == 'all'):
            self._cods = None
        else:
            all_cods = []
            for c in cods:
                c_abs = os.path.abspath(c)
                if not os.path.exists(c_abs):
                    self.log("WARNING: input file/folder '%s' doesn't exist; ignoring..." % c)
                elif os.path.isdir(c_abs):
                    all_cods += glob.glob(os.path.join(c_abs, "*.cod"))
                else:
                    all_cods.append(c_abs)
            self._cods = all_cods

        # Check all our search paths
        if (len(cods) == 1) and (cods[0].lower() == 'all'):
            self._load_paths = []
        else:
            self._load_paths = cods
        for lp in options.load_path.split(';'):
            if not lp:
                continue    # Skip empty items
            elif not os.path.exists(lp):
                self.log("WARNING: load path '%s' doesn't exist; ignoring..." % lp)
            elif not os.path.isdir(lp):
                self.log("WARNING: load path '%s' isn't a directory; ignoring..." % lp)
            else:
                self._load_paths.append(lp)

        # force our cache to always be read-only
        self._read_only = True
        self._cache_root = None
        # Minor race condition here; don't run 2 cod2jars targeting the same cache root at the same time!
        if options.cache_root is not None:
            cache_root = os.path.abspath(options.cache_root)
            if (cache_root is not None) and (not os.path.exists(cache_root)):
                os.makedirs(cache_root)
            if cache_root is not None:
                self._cache_root = cache_root
                self._serializer = codlib.SerialDumper(cache_root, self._make_log)
                if not os.path.isdir(cache_root):
                    if zipfile.is_zipfile(cache_root):
                        self._read_only = True    # Force read-only mode for zipped caches
                    else:
                        self.log("WARNING: invalid cache path; '%s' is neither a folder or a Zip; ignoring..." % cache_root)
                        cache_root = None
                #else:
                #    self._read_only = options.read_only
            self._cache = (cache_root is not None)
        else:
            cache_root = None
            self._cache = False

        if (not self._cache) and (self._cods is None):
            self.log("ERROR: no [valid] cache path provided, but input is magic cache specifier 'ALL'; aborting...")
            self._cods = []

        name_db = options.name_db
        if (name_db is not None) and (not os.path.exists(name_db)):
            self.log("WARNING: renaming database '%s' does not exist; ignoring..." % name_db)
            name_db = None
        if name_db is not None:
            self._name_db = name_db
        self._names = (name_db is not None)

        self._loader = codlib.Loader(
            self._load_paths,
            cache_root=self._cache_root,
            name_db_path=self._names,
            auto_resolve=self.individual_mode,
            log_file=self._loader_log
        )

        #self._no_update = options.no_update
        self._hiscan = options.hiscan
        self._parse_only = False
        if self._format == 'xml':
            # we do not need to take the time to hiscan or resolve when dumping XML!
            self._parse_only = True

    def log(self, msg):
        print >> self._make_log, msg

    def diagnostics(self):
        print "INPUT: %d CODs to parse." % len(self._cods)
        print "Dumping output to '%s' in '%s' format" % (self._out_path, self._format)
        if self._cache:
            print "Caching enabled (cache root: '%s')" % self._cache_root
        if self._names:
            print "Stripped-member renaming enabled (name DB: '%s')" % self._name_db

    def do_text_dump(self, module):
        dump_file = os.path.join(self._out_path, module.name + ".cod.txt")
        with open(dump_file, 'wt') as fd:
            RD = codlib.ResolvedDumper(fd, self._make_log)
            RD.dump_module(module, True)

    def do_xml_dump(self, module):
        dump_file = os.path.join(self._out_path, module.name + ".cod.xml")
        with open(dump_file, 'wt') as fd:
            XD = codlib.XMLDumper(fd, self._make_log)
            XD.dump_cod(module._cf)

    def do_cache_dump(self, module):
        SD = codlib.SerialDumper(self._out_path, self._make_log)
        SD.dump_module(module)

    def do_jasmin_dump(self, module):
        try:
            JD = self._jasmin_dumper
        except AttributeError:
            #self._jasmin_dumper = JD = codlib.JasminDumper(self._out_path, self._make_log, self._no_update)
            self._jasmin_dumper = JD = codlib.JasminDumper(self._out_path, self._make_log)

        for cdef in module.classes:
            JD.dump_class(cdef)

    def do_class_dump(self, module):
        try:
            JD = self._jasmin_dumper
        except AttributeError:
            #self._jasmin_dumper = JD = codlib.JasminDumper(self._out_path, self._make_log, self._no_update)
            self._jasmin_dumper = JD = codlib.JasminDumper(self._out_path, self._make_log)

        try:
            CD = self._class_dumper
        except AttributeError:
            #self._class_dumper = CD = codlib.ClassDumper(self._out_path, self._make_log, self._no_update)
            self._class_dumper = CD = codlib.ClassDumper(self._out_path, self._make_log)

        error = None
        for cdef in module.classes:
            try:
                JD.dump_class(cdef)
                CD.dump_class(cdef)
            except Exception, e:
                if not error:
                    error = e
        if error:
            # if we got an exception, raise it now
            raise(error)

    def do_jar_dump(self, module):
        self.do_class_dump(module)

    def _load_named_cods(self):
        if not self._cods: return []

        # Load the specified COD files from disk
        P = Progress("Loading CODs", len(self._cods))
        loaded_cods = []
        ticks = 0
        P.update(ticks)
        for c in self._cods:
            try:
                loaded_cods.append(self._loader.load_codfile(c))
            except KeyboardInterrupt:
                raise
            except Exception as err:
                self.log("ERROR: failed to parse/load COD '%s'..." % c)
                traceback.print_exc(file=self._make_log)
            ticks += 1
            P.update(ticks)
        print
        return loaded_cods

    def _load_all_cached_cods(self):
        # Load all the modules in the module cache (either folder or Zip cache)
        if zipfile.is_zipfile(self._cache_root):
            ZF = zipfile.ZipFile(self._cache_root, 'r')
            mods = [mod[:-7] for mod in ZF.namelist() if mod.endswith(".cod.db")]
        else:
            mods = [os.path.basename(mod)[:-7] for mod in glob.glob(os.path.join(self._cache_root, "*.cod.db"))]

        P = Progress("Lazy-Loading CODs", len(mods))
        loaded_mods = []
        ticks = 0
        P.update(ticks)
        for m in mods:
            try:
                loaded_mods.append(self._loader.load_module(m))
            except KeyboardInterrupt:
                raise
            except Exception as err:
                self.log("ERROR: failed to load module '%s'..." % m)
                traceback.print_exc(file=self._make_log)
            ticks += 1
            P.update(ticks)
        print
        return loaded_mods

    def run(self):
        if self.individual_mode:
            self.run_individual_mode()
        else:
            self.run_batch_mode()

    def run_batch_mode(self):
        """ Perform the steps in order and on all CODs.  For example,
            Parse all CODs, then resolve all CODs, then hiscan all
            CODs, then dump all CODs.  This is much more visually
            appealing than performing these steps on a COD-by-COD
            basis, but we can easily run out of memory by batch
            processing a large group of CODs.
        """
        # Parse (but do not resolve, yet) all the cods we have
        if self._cods is None:
            # Magic shortcut to simply load all cached modules
            loaded_cods = self._load_all_cached_cods()
        else:
            loaded_cods = self._load_named_cods()

        # If we got no modules loaded, we're already done...
        if not loaded_cods:
            print "No CODs/Modules loaded; halting..."
            return

        # Resolve all modules/classes in turn
        num_classes = 0
        if not self._parse_only:
            P = Progress("Resolving modules", len(loaded_cods))
            ticks = 0
            P.update(ticks)
            for m in loaded_cods:
                m.resolve()
                ticks += 1
                P.update(ticks)
            print

            # Report on how many modules/classes have ACTUALLY been loaded by now
            print "\t(Loader stats: %d modules, %d classes loaded)" % (
                len(self._loader._modules),
                len(self._loader._classes)
            )

            # Compute the number of classes/routines we have
            num_classes = sum(len(mod.classes) for mod in loaded_cods)
            num_routines = sum(len(mod.routines) for mod in loaded_cods)

            # Actualize all modules in turn
            P = Progress("Actualizing classes", num_classes)
            ticks = 0
            P.update(ticks)
            for m in loaded_cods:
                m.actualize()
                ticks += len(m.classes)
                P.update(ticks)
            print

            # Disassemble all routines in turn
            P = Progress("Disassembling routines", num_routines)
            ticks = 0
            P.update(ticks)
            for m in loaded_cods:
                m.disasm()
                ticks += len(m.routines)
                P.update(ticks)
            print

            # If hiscan is enabled, HIScan all the routines in all our loaded modules
            if self._hiscan:
                H = codlib.HIScanner(self._loader, self._hiscan_log)
                P = Progress("Analyzing/scanning routines", num_routines)
                ticks = 0
                P.update(ticks)
                for m in loaded_cods:
                    for rdef in m.routines:
                        try:
                            sub = codlib.Subroutine(rdef)
                            H.scan(sub)
                        except KeyboardInterrupt:
                            raise
                        except Exception as err:
                            self.log("ERROR: failed to finish scanning routine '%s'..." % rdef)
                            traceback.print_exc(file=self._make_log)
                        finally:
                            ticks += 1
                            P.update(ticks)
                print
                H.dump_stats()
                H.dump_bad_subs()

            # If caching is enabled (and not read-only), dump our loaded modules into the cache
            # temporarily disabled to make things simpler
            """
            if self._cache and (not self._read_only):
                P = Progress("Caching classes", num_classes)
                ticks = 0
                P.update(ticks)
                for m in loaded_cods:
                    try:
                        self._serializer.dump_module(m)
                    except KeyboardInterrupt:
                            raise
                    except Exception as err:
                        self.log("ERROR: failed to finish caching module '%s'..." % m)
                        traceback.print_exc(file=self._make_log)
                    finally:
                        ticks += len(m.classes)
                        P.update(ticks)
                print
            """

        # Finally, generate our human-readable output (text dump, jasmin source, whatever)
        errors = 0
        P = Progress("Dumping classes in '%s' format" % self._format, num_classes)
        ticks = 0
        P.update(ticks)
        for m in loaded_cods:
            try:
                self._module_dumper(m)
            except KeyboardInterrupt:
                raise
            except Exception as err:
                errors += 1
                self.log("ERROR: failed to dump module %s in '%s' format" % (m, self._format))
                traceback.print_exc(file=self._make_log)
            finally:
                ticks += len(m.classes)
                P.update(ticks)

        self.wrap_up()
        if errors:
            print
            print 'There were %d errors while dumping modules.  See the log files in "%s" for details.' % (errors, self._out_path)
        print

    def run_individual_mode(self):
        """ Individual mode performs all steps on an individual COD
            basis.  This is helpful for processing large batches of
            COD files where we could easily run out of memory.
            If we do run out of memory, we simply clear out the
            loader and try again on the current module.
        """
        cods_to_dump = self._cods
        cods_to_dump.sort()

        errors = 0
        P = Progress("Dumping modules", len(cods_to_dump))
        ticks = 0
        P.update(ticks)
        retry = False
        while cods_to_dump and not retry:
            if retry:
                retry = False
            else:
                cod_name = cods_to_dump.pop(0)
                self.log("Dumping '%s'" % os.path.basename(cod_name))
            try:
                # resolve, actualize, disassemble
                m = self._loader.load_module(cod_name).resolve().actualize().disasm()
                # hiscan if we need to
                if self._hiscan:
                    H = codlib.HIScanner(self._loader, self._hiscan_log)
                    for rdef in m.routines:
                        try:
                            sub = codlib.Subroutine(rdef)
                            H.scan(sub)
                        except KeyboardInterrupt:
                            raise
                        except Exception as err:
                            self.log("ERROR: failed to finish scanning routine '%s'..." % rdef)
                            traceback.print_exc(file=self._make_log)
                # dump
                self._module_dumper(m)

                ticks += 1
                P.update(ticks)
            except MemoryError:
                # urgh, ran out of memory, throw it all away...
                del self._loader
                self.log("WARNING: ran out of memory on module '%s', refreshing loader..." % cod_name)
                self._loader = codlib.Loader(
                    self._load_paths,
                    cache_root=self._cache_root,
                    name_db_path=self._names,
                    auto_resolve=True,
                    log_file=self._loader_log
                )
                retry = True
            except KeyboardInterrupt:
                raise
            except Exception as err:
                self.log("ERROR: failed to dump COD '%s'..." % cod_name)
                traceback.print_exc(file=self._make_log)
                errors += 1

        self.wrap_up()
        if errors:
            print
            print 'There were %d errors while dumping modules.  See the log files in "%s" for details.' % (errors, self._out_path)
        print

    def wrap_up(self):
        # for jar and cache formats we need to zip up our results
        # after dumping the modules
        if self._format == 'jar':
            zf = zipfile.ZipFile(self._out_path + '.jar', 'w')
            for dirpath, dirnames, filenames in os.walk(self._out_path):
                for filename in filenames:
                    source_file_path = os.path.join(dirpath, filename)
                    relpath = os.path.relpath(source_file_path, self._out_path)
                    if filename.endswith('.class'):
                        zf.write(source_file_path, relpath)
            zf.close()
        elif self._format == 'cache':
            zf = zipfile.ZipFile(self._out_path + '.zip', 'w')
            for dirpath, dirnames, filenames in os.walk(self._out_path):
                for filename in filenames:
                    source_file_path = os.path.join(dirpath, filename)
                    relpath = os.path.relpath(source_file_path, self._out_path)
                    if filename.endswith('.cache') or filename.endswith('.db'):
                        zf.write(source_file_path, relpath)
            zf.close()


if __name__ == "__main__":
    OP = OptionParser(usage="usage: %prog [options] COD_PATH1 [COD_PATH2 [...]]")
    OP.add_option("-l", "--load-path", dest="load_path", default="", metavar="FOLDERS",
                    help="semi-colon-delimited list of FOLDERS from which to load COD dependencies")
    OP.add_option("-c", "--cache-root", dest="cache_root", default=None, metavar="FOLDER",
                    help="use FOLDER as a class/module cache dump (for loading/storing)")
    #OP.add_option("-r", "--read-only", dest="read_only", action="store_true", default=False,
    #                help="treat cache as read-only (i.e., do not update the cache)")
    OP.add_option("-n", "--name-db", dest="name_db", default=None, metavar="DB_FILE",
                    help="use DB_FILE field/method name database to rename stripped class members")
    OP.add_option("-o", "--output", dest="out_path", default="", metavar="PATH",
                    help="save output dump in PATH")
    OP.add_option("-f", "--format", dest="format", default="jar", metavar="FORMAT",
                    help="generate output dump a specific FORMAT: [%s]" % ', '.join(Cod2Jar.DUMP_FORMATS))
    OP.add_option("-i", "--individual-mode", dest="individual_mode", action="store_true", default=False,
                    help="Dumping mode resistant to running low on memory, yet less informative")
    #OP.add_option("-x", "--no-update", dest="no_update", action="store_false", default=True,
    #                help="Do not update dump files if they already exist (always perform a backup if in doubt)")
    OP.add_option("-s", "--no-hiscan", dest="hiscan", action="store_false", default=True,
                    help="Do not use heuristic instruction scanning to resolve dynamic type information")
    #OP.add_option("-z", "--zip-cache", dest="zip_cache", default=None, metavar="ZIPFILE",
    #                help="compress cache into ZIPFILE after completing job")
    opts, args = OP.parse_args()

    if len(args) == 0:
        OP.print_help()
        OP.error("Must specify at least one input COD file/folder (or the magic cache flag 'ALL')")
    if not opts.out_path:
        OP.error('Must specify an output path')
    if os.path.exists(opts.out_path):
        OP.error("'%s' already exists!" % opts.out_path)

    Cod2Jar(args, opts).run()
