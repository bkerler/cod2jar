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
his: Heuristic instruction scanner for RIM's JVM.
"""

import sys
from utils import Primitive, TypeToken, TypeList
from resolve import ClassDef, FieldDef, RoutineDef, LazyClassDef, LazyFieldDef, LazyRoutineDef
import traceback, struct
from itertools import combinations

# the maximum number of slots that can be on the stack before a
# stack overflow exception is thrown
GLOBAL_MAX_STACK = 0x200

# the maximum number of rescans of a basic block
GLOBAL_MAX_RESCAN = 50

class AbortScanning(Exception): pass

class UnknownTotos(AbortScanning): pass

class ScanningStackUnderflow(AbortScanning): pass

class ScanningStackOverflow(AbortScanning): pass

class FieldPatchFailed(AbortScanning): pass

class VirtualPatchFailed(AbortScanning): pass

class TStack(list):
    def push(self, value, count=1):
        assert isinstance(value, TypeToken), "Bad value (%s [%s]) pushed onto type stack!" % (value, type(value))
        # if long or double primitive, this is a wide (takes up two slots) value
        if value.code in (6, 12) and not value._array:
            count *= 2
        self += ([value] * count)
        if len(self) > GLOBAL_MAX_STACK:
            raise ScanningStackOverflow("Stack overflow while scanning instructions")
    
    def pop(self, count=None):
        if (count != 0) and (len(self) == 0):
            raise ScanningStackUnderflow("Stack underflow while scanning instructions")
        
        if count is None:
            return list.pop(self)
        elif count > 0:
            ret = self[-count:]
            del self[-count:]
            return ret
    
    def top(self, count=1):
        if len(self) == 0:
            return None
        elif count == 1:
            return self[-1]
        else:
            return self[-count:]
    
    def pop_push(self, new_top):
        self.pop()
        self.push(new_top)
    
    def copy(self):
        return TStack(self[:])
    
    def __str__(self):
        return "{%s}" % ''.join(map(str, self))

class HILogger(object):
    ''' Capture stats and error information for a series of HIScans. '''
    def __init__(self, logfile=sys.stderr):
        self._logfile = logfile
        self._indent = ''
        self._header = None
        self._stats = {
            'subs': 0,
            'codes': 0,
            'fields': 0,
            'virtuals': 0,
        }
        self._bad_subs = []
    
    def count(self, kind):
        self._stats[kind] += 1
    
    def log(self, msg=''):
        if self._header:
            print >> self._logfile, "SUB: %s" % self._header
            self._header = None
        _fputs = self._logfile.write
        _fputs(self._indent)
        _fputs(msg)
        _fputs('\n')
    
    def enter_sub(self, sub):
        self.count("subs")
        self._header = '%s in %s' % (str(sub.routine), str(sub.routine.module))
        self._indent = '\t'
    
    def error_sub(self, sub, err):
        from StringIO import StringIO
        import traceback
        dump = StringIO()
        traceback.print_exc(file=dump)
        dump.seek(0)
        dump = dump.read()
        sub_name = str(sub.routine)
        mod_name = str(sub.routine.module)
        self.log("ERROR: %s (aborting scan of '%s' in %s)" % (err, sub_name, mod_name))
        # uncomment for a traceback
        self.log(dump)
        self._bad_subs.append(sub_name)
        self._indent = ''
    
    def exit_sub(self, sub):
        self._indent = ''
    
    def dump_stats(self):
        self.log()
        self.log('*** HIScan Stats Summary ***')
        self.log('-'*60)
        self.log("Subs scanned: %d" % self._stats['subs'])
        lbs = len(self._bad_subs)
        self.log("Subs failed: %d (%.2f%%)" % (lbs, float(lbs) / self._stats['subs'] * 100))
        self.log("Instructions scanned: %d" % self._stats['codes'])
        self.log("Fields patched up: %d" % self._stats['fields'])
        self.log("Virtual methods patched up: %d" % self._stats['virtuals'])
        self.log()
    
    def dump_bad_subs(self):
        if self._bad_subs:
            self.log()
            self.log("*** HIScan Failed Subs ***")
            self.log('-'*60)
            for bs in self._bad_subs:
                self.log(bs)
            self.log()

class HIScanner(object):

    # RIM-JVM-type-ordinal -> JTS character mapping
    # (For when we need to create arrays based on a type ordinal value)
    TYPE_ORDINAL = {
        1: "Z",
        2: "B",
        3: "C",
        4: "S",
        5: "I",
        6: "J",
        10: "V",
        11: "F",
        12: "D",
        14: "Ljava/lang/String;",
    }

    # Common TypeToken types we will use, named appropriately
    CORE_TTS = {
        '*': '*',       # We don't know ANYTHING about this type
        'null': '?',    # Special: could be any kind of OBJECT
        'boolean': 'Z',
        'byte': 'B',
        'char': 'C',
        'short': 'S',
        'int': 'I',
        'long': 'J',
        'float': 'F',
        'double': 'D',
        'string': 'Ljava/lang/String;',
        'string[]': '[Ljava/lang/String;',
    }
    
    def __init__(self, loader, log_file=sys.stderr, debug_level=0):
        self._loader = loader
        self._logfile = log_file
        self._logger = HILogger(log_file)
        self.debug_level = debug_level
        
        # Precompute some common types
        self._tt = dict((k, self.mktt(v)) for k, v in self.CORE_TTS.iteritems())
    
    def log(self, msg):
        if not msg.startswith('DEBUG: '):
            self._logger.log(msg)
        elif self.debug_level:
            self._logger.log(msg)
    
    def count(self, kind):
        self._logger.count(kind)
    
    def dump_stats(self):
        self._logger.dump_stats()
    
    def dump_bad_subs(self):
        self._logger.dump_bad_subs()

    def mktt(self, tname, dims=0, class_name=False):
        if isinstance(tname, TypeToken):
            # Clone type token
            tt = tname.clone()
        elif isinstance(tname, (ClassDef, LazyClassDef)):
            # Object TypeToken of a given class type
            tt = TypeToken(None)
            tt._object = True
            tt._array = False
            tt.code = 7
            tt.type = tname
        elif isinstance(tname, Primitive):
            if str(tname) not in self._tt:
                raise ValueError("Primitive type %s cannot be a valid type token for scanning" % tname)
            tt = self._tt[str(tname)].clone()
        elif isinstance(tname, basestring):
            if class_name:
                # tname is a raw class name (i.e., "java/lang/String" instead of "Ljava/lang/String;")
                tt = TypeToken(None)
                tt._object = True
                tt._array = False
                tt.code = 7
                tt.type = self._loader.ref_class(tname)
            elif tname == '?':
                # Special null-object-ref wildcard (not just any type, any OBJECT type)
                tt = TypeToken.from_jts('*', self._loader)
                tt._object = True
            else:
                # Parse a fully-JTS-encoded type description
                tt = TypeToken.from_jts(tname, self._loader)
        elif isinstance(tname, (int, long)):
            # Ordinal [primitive] type code
            assert (tname in self.TYPE_ORDINAL), "Invalid RIM JVM type ordinal for mktt(): %d" % tname
            tt = TypeToken(None)
            tt._object = False
            tt._array = False
            tt.code = tname
            tt.type = Primitive(TypeToken.TYPE_NAME[tname])
        else:
            raise ValueError("Invalid argument to mktt(): %s (%s)" % (tname, type(tname)))
        
        # Apply dimensions (which may change the initial type shape)
        if dims:
            tt._array = True
            tt.dims = dims
        
        return tt

    def _merge_ttoken(self, tts, no_fail = False):
        ''' Merges a list of TypeTokens
        '''
        #self.log('Merging types:')
        #for tt in tts:
        #    self.log('  %s' % tt)
        if not no_fail:
            return max(tts)
        else:
            try:
                return max(tts)
            except:
                # we have incompatible types...
                # first, remove lesser types for more specific
                reduced_tts = set(tts)
                for t1, t2 in combinations(reduced_tts, 2):
                    try:
                        if cmp(t1, t2) == -1:
                            # t2 is more specific
                            reduced_tts.remove(t1)
                        else:
                            # t1 is more specific
                            reduced_tts.remove(t2)
                    except:
                        # we need to keep both incompatible
                        pass
                # otherwise take the most common or most defined
                max_count = 0
                max_tts = []
                for tt in reduced_tts:
                    count = tts.count(tt)
                    if count > max_count:
                        max_tts = [tt,]
                        max_count = count
                    elif count == max_count:
                        max_tts.append(tt)
                
                # grab the most common one deterministically
                # TODO: select this smartly
                max_tt = max_tts[0]
                return max_tt

    def _merge_tlists(self, tlists, no_fail = False):
        '''Merges a list of TStacks (stacks) or lists of TypeTokens (locals)
        '''
        tlists = [x for x in tlists if x]
        #self.log('Merging:')
        #for tlist in tlists:
        #    self.log('  %s' % tlist)
        if not tlists:
            return [] # err... may not return TStack... ugh.
        # assert that all lists are of equal size
        lengths = set(len(x) for x in tlists)
        tl = []
        if no_fail:
            max_length = max(lengths)
            for i in range(max_length):
                tl.append(self._merge_ttoken([x[i] for x in tlists if len(x) > i], no_fail))
        else:
            assert len(lengths) == 1
            for i in range(len(tlists[0])):
                tl.append(self._merge_ttoken([x[i] for x in tlists], no_fail))
        if isinstance(tlists[0], TStack):
            tl = TStack(tl)        
        return tl
    
    def _get_next_bb(self, candidates, visited, failed, last_scanned = None):
        '''Given a list of candidate BBs and a set of visited BBs, pick the next one to scan.
        
        Algorithm:
            1. Scan candidates in presented order
                1a. rescan candidates if the last basic_block scanned has generated better type info
                1b. scan a candidate if all parents have been scanned
                1c. if one is not found, continue to phase 2
            2. Remove/return first candidate from the list
        '''
        self.log("DEBUG: selecting from candidates: %s" % [str(x) for x in candidates])
        self.log("DEBUG: failed list: %s" % [str(x) for x in failed])
        # if we just finished scanning a parent of this candidate and
        # if we have better type info available now
        for c in candidates:
            parents = [p for why, p in c.entry]
            if c in visited or c in failed:
                parents_tstack = self._get_starting_tstacks(c)
                parents_tlocals = self._get_starting_tlocals(c)
                # TODO: improve with stack map info
                parents_merged_tstack = self._merge_tlists(parents_tstack, no_fail = True)
                parents_merged_tlocals = self._merge_tlists(parents_tlocals, no_fail = True)

                if parents_merged_tstack != c.starting_tstack or \
                   parents_merged_tlocals != c.starting_tlocals:
                    self.log("DEBUG: selected to rescan: %s" % c)
                    if parents_merged_tstack != c.starting_tstack:
                        self.log("DEBUG: new stack type information")
                        for i, parent_tstack in enumerate(parents_tstack):
                            self.log('DEBUG:     Parent %2d stack: %s' % (i, parent_tstack))
                        self.log('DEBUG:     Merged stack:     %s' % parents_merged_tstack)
                        self.log('DEBUG:     Starting stack:   %s' % c.starting_tstack)
                    if parents_merged_tlocals != c.starting_tlocals:
                        self.log("DEBUG: new locals type information")
                        self.log('DEBUG:     Merged locals:   %s' % parents_merged_tlocals)
                        self.log('DEBUG:     Starting locals: %s' % c.starting_tlocals)
                    candidates.remove(c)
                    return c
                #else:
                #    candidates.remove(c)

        # if all parents have been scanned
        for c in candidates:
            parents = [p for why, p in c.entry]
            if c not in visited:
                if c not in failed:
                    if all((p in visited) for p in parents):
                        self.log("DEBUG: selected to scan bb with all parents scanned: %s" % c)
                        candidates.remove(c)
                        return c
            else:
                candidates.remove(c)
        
        while candidates:
            c = candidates.pop(0)
            if c not in visited and c not in failed:
                self.log("DEBUG: selected to scan next available block: %s" % c)
                return c
        return None

    def _get_starting_tstacks(self, bb):
        '''Gathers a list of potential starting stacks based on parent exit stacks.
        '''
        pstacks = []
        for why, p in bb.entry:
            # If we get here via an exception thrown, construct an appropriate stack
            if isinstance(why, basestring) and why and (why != 'default'):
                if why == 'finally':
                    why = 'java/lang/Throwable';
                pstacks.append(TStack([self.mktt(why, class_name=True)]))
            elif p.tstack is not None:
                # If this instruction came from a checkcastbranch* that failed, pop the top
                if why is False and p.instructions[-1]._name.startswith('checkcastbranch'):
                    pstacks.append(TStack(p.tstack[:-1]))
                # Otherwise, just considered the ending typestack, if any
                else:
                    pstacks.append(TStack(p.tstack))
        return pstacks

    def _get_starting_tlocals(self, bb):
        '''Gathers a list of potential starting locals based on parent exit locals.
        '''
        plocals = []
        for why, p in bb.entry:
            # Always copy the locals over
            if p.tlocals is not None:
                plocals.append(p.tlocals)
        return plocals

    def _calculate_starting_tstack(self, bb):
        ''' Calculates the starting stack of a basic blocks based on parent exit stacks.
        '''
        pstacks = self._get_starting_tstacks(bb)
        
        # Check for initial-tstack mismatches among parent BBs
        try:
            tstack = TStack(self._merge_tlists(pstacks))
        except:
            tstack = TStack(self._merge_tlists(pstacks, no_fail = True))
        return tstack

    def _calculate_starting_tlocals(self, bb, routine = None):
        ''' Calculates the starting locals of a basic blocks based on parent exit locals.

            Optionally provide a RoutineDef to use stack map information if available.
        '''
        plocals = self._get_starting_tlocals(bb)
        if routine:
            pass
        
        # Initialize locals, then try to eliminate wildcard types by finding more
        # explicit type info from other parent BBs' locals
        try:
            tlocals = self._merge_tlists(plocals)
        except:
            tlocals = self._merge_tlists(plocals, no_fail = True)
        return tlocals

    def scan(self, sub, count=3, scanning_step_callback=None):
        ''' Compute type-on-top-of-stack values for the RIM-JVM instructions in an analysis.Subroutine.
        
            Blows away any previous .totos values for those instructions.
            Returns True if scan was successful, False otherwise.
        '''
        self._logger.enter_sub(sub)
        try:
            routine = sub.routine

            # Find the initial basic block; mark it as having an empty initial typestack
            # (Also, blow away the tstack snapshots in each BB)
            bb = None
            for b in sub.basic_blocks:
                #self.log('DEBUG: %s exits: %s' % (str(b), str([(why, str(next)) for why, next in b.exit.iteritems()])))
                # ending bb type information
                b.tstack = None
                b.tlocals = None
                # starting bb type information
                b.starting_tstack = None
                b.starting_tlocals = None
                # scan count
                b.scan_count = 0
                if b.is_initial():
                    bb = b
            if bb is None:
                raise AbortScanning("No initial BB found in %s" % routine)
            
            # Mark the basic blocks we've visited
            visited = set()
            # Mark the basic blocks that failed
            failed = set()
            
            # List BBs we want to visit
            last_scanned = None
            candidates = [bb]

            # Handle BBs until we're all out
            self._reals = False
            while candidates:
                # Get next BB to visit
                bb = self._get_next_bb(candidates, visited, failed, last_scanned)
                if not bb:
                    break

                # check to see if we are potentially in an infinite loop
                bb.scan_count += 1
                if bb.scan_count > GLOBAL_MAX_RESCAN:
                    raise AbortScanning("Maximum rescan count exceeded for basic block %s" % bb)

                if bb in failed:
                    failed.remove(bb)
                
                # If we have no parents, use and initial stack/localset
                if bb.is_initial():
                    # Allocate 256 local slots to be safe; pre-populate first slots with parameter types
                    tlocals = [self._tt['*'] for i in xrange(256)]
                    i = 0
                    for ptype in routine.param_types:
                        tlocals[i] = ptype
                        if ptype.slots() == 2:
                            tlocals[i+1] = ptype
                            i += 2
                        else:
                            i += 1
                    # Clean stack
                    tstack = TStack()
                else:
                    # Otherwise, compute our starting stack/local lists.
                    tstack = self._calculate_starting_tstack(bb)
                    tlocals = self._calculate_starting_tlocals(bb, routine = routine)
                    
                    # track starting type info so if we encounter this block later,
                    # we can compare to see if we have better info
                    bb.starting_tstack = tstack.copy()
                    bb.starting_tlocals = tlocals[:]
                    #self.log("DEBUG: starting stack: %s" % bb.starting_tstack)
                    #self.log("DEBUG: starting locals: %s" % bb.starting_tlocals)
                
                self.log("DEBUG: walking BB %s w/ %s" % (bb, tstack))
                
                # visualize this step of the scan
                if scanning_step_callback:
                    scanning_step_callback(sub, bb, candidates, visited, failed)
                try:
                    # Walk the instructions in the BB, tracking the scanned stack
                    for i, instr in enumerate(bb.instructions):
                        # "isreal" isn't a true instruction--just a prefix that sets a flag for the next one
                        if instr._name == 'isreal':
                            self._reals = True
                            continue
                        
                        # What is on the stack (typewise) when we start executing this instruction?
                        instr.totos = tstack.top()
                        
                        # Simulate the instruction's effect on the stack
                        try:
                            handler = getattr(self, '_%s' % instr._name)
                        except AttributeError:
                            # Implicit NO-OP
                            self.log("WARNING: unimplemented instruction type '%s'" % instr._name)
                            continue
                        
                        self.count("codes")
                        
                        # Exceptions are caught by the surrounding, method-wide try/except block
                        if self.debug_level > 1:
                            self.log("DEBUG: %05d: %s" % (instr.offset, instr))
                            self.log("DEBUG:     Pre locals (only 4): %s" % tlocals[:4])
                            self.log("DEBUG:     Pre stack: %s" % tstack)
                        handler(instr, tstack, tlocals)
                        if self.debug_level > 1:
                            self.log("DEBUG:     Post stack: %s" % tstack)
                        
                        # Clear the "isreal" flag
                        self._reals = False

                    # TODO: assert the ending stack is the same size as when we previously scanned
                    # this will catch infinite loops that cause the stack to grow uncontrollably
                    # maybe just do this if we aren't confused by an exception handler
                    #assert len(tstack) == len(bb.tstack), "Basic block stack size should not vary between scans"
                    # Set our BB's ending tstack/tlocals
                    bb.tstack = tstack
                    bb.tlocals = tlocals
                    last_scanned = bb
                    
                    # OK, we're done with the basic block
                    visited.add(bb)

                    # scan this basic block's exit points for new candidates
                    # sort the next basic blocks by their offset
                    #self.log('DEBUG: %s exits: %s' % (str(bb), str([(why, str(next_bb)) for why, next_bb in bb.exit.iteritems()])))
                    next_bbs = [(next_bb.instructions[0].offset, next_bb) for why, next_bb in bb.exit.iteritems()]
                    next_bbs += [(next_bb.instructions[0].offset, next_bb) for next_bb in candidates]
                    next_bbs += [(next_bb.instructions[0].offset, next_bb) for next_bb in failed]
                    next_bbs.sort()
                    next_bbs = [next_bb for offset, next_bb in next_bbs]
                    candidates = list(set(next_bbs))
                except Exception, e:
                    # let's see what caused this error
                    import traceback
                    from StringIO import StringIO
                    dump = StringIO()
                    traceback.print_exc(file=dump)
                    dump.seek(0)
                    dump = dump.read()
                    dump = 'DEBUG: ' + dump
                    dump = dump.replace('\n', '\nDEBUG:')
                    self.log(dump)

                    # add this to the failed list and try a different block
                    failed.add(bb)
                    candidates.append(bb)
                    
                    # ..unless there are no more to try
                    if not set(candidates) - set(failed):
                        raise e

            if failed:
                '''
                self.log('DEBUG: Remaining basic blocks:')
                remaining_bb = set(candidates + list(failed))
                for bb in remaining_bb:
                    parents = [p for why, p in bb.entry]
                    parents_tstack = [p.tstack for p in parents]
                    parents_tlocals = [p.tlocals for p in parents]
                    parents_merged_tstack = self._merge_tlists(parents_tstack, no_fail = True)
                    parents_merged_tlocals = self._merge_tlists(parents_tlocals, no_fail = True)
                    self.log('DEBUG: %s:' % str(bb))
                    self.log('DEBUG: Merged stack:    %s' % parents_merged_tstack)
                    self.log('DEBUG: Starting stack:  %s' % bb.starting_tstack)
                    self.log('DEBUG: Merged locals:   %s' % parents_merged_tlocals)
                    self.log('DEBUG: Starting locals: %s' % bb.starting_tlocals)
                '''
                    
                raise Exception('Exhausted basic block candidates while trying to scan failed basic blocks: %s' % [str(x) for x in failed])
        except Exception as err:
            print err
            if count:
                count -= 1
                self.log('WARNING: Attempting rescan (%d tries left)' % count)
                return self.scan(sub, count, scanning_step_callback)
            else:
                self._logger.error_sub(sub, err)
                return False
        # visualize the final step of scanning
        if scanning_step_callback:
            scanning_step_callback(sub, None, candidates, visited, failed)
        self._logger.exit_sub(sub)
        return True
    
    # Many instructions can be heuristically scanned using the
    # following set of simple type-stack operations
    ###########################################################
    def __nop(self, instr, tstack, tlocals):
        pass
    def __pop1(self, instr, tstack, tlocals):
        tstack.pop()
    def __pop2(self, instr, tstack, tlocals):
        tstack.pop(2)
    def __pop3(self, instr, tstack, tlocals):
        tstack.pop(3)
    def __push_int(self, instr, tstack, tlocals):
        if self._reals:
            tstack.push(self._tt['float'])
        else:
            tstack.push(self._tt['int'])
    def __push_long(self, instr, tstack, tlocals):
        if self._reals:
            tstack.push(self._tt['double'])
        else:
            tstack.push(self._tt['long'])
    def __push_float(self, instr, tstack, tlocals):
        tstack.push(self._tt['float'])
    def __push_double(self, instr, tstack, tlocals):
        tstack.push(self._tt['double'])
    
    # Common instructions (using one of the above methods)
    ###########################################################
    # TODO: errOp1 and errOp2
    
    _enter_narrow = _enter_wide = _xenter = _xenter_wide = _enter = __nop
    _iinc = _ineg = _goto = _goto_w = _i2b = _return = __nop
    _jmpback = _jmpforward = __nop
    _i2s = _lneg = _noenter_return = _dneg = __nop
    _fneg = _i2c = __nop
    _iinc_wide = _halt = _clinit_wait = _clinit_return = __nop
    _clinit = _clinit_lib = _synch = _synch_static = __nop
    _ireturn_bipush = _ireturn_sipush = _ireturn_iipush = __nop
    _invokenative = _iinvokenative = _linvokenative = __nop
    
    _ifeq = _ifne = _iflt = _ifge = _ifgt = _ifle = _ifnull = _ifnonnull = __pop1
    _iand = _ishl = _iushr = _isub = _ixor = __pop1
    _imul = _iadd = _ior = _lushr = _idiv = _pop = _ishr = _irem = __pop1
    _monitorenter = _monitorexit = __pop1
    _tableswitch = _lookupswitch = _lookupswitch_short = __pop1
    _lshl = _lshr = _lushr = __pop1
    _fadd = _fsub = _fmul = _fdiv = _frem = __pop1
    
    _if_acmpeq = _if_acmpne = _if_acmplt = _if_acmpge = _if_acmpgt = _if_acmple = __pop2
    _if_icmpeq = _if_icmpne = _if_icmplt = _if_icmpge = _if_icmpgt = _if_icmple = __pop2
    _pop2 = _ladd = _lsub = _lmul = _ldiv = __pop2
    _lor = _lrem = _lxor = _dadd = _dsub = _dmul = _ddiv = _drem = __pop2
    _land = __pop2
    
    _bastore = _iastore = _castore = _aastore = _sastore = __pop3
    
    _iconst_1 = _iconst_0 = __push_int
    _bipush = _sipush = _iipush = _iload = __push_int
    _iload_0 = _iload_1 = _iload_2 = _iload_3 = _iload_4 = _iload_5 = _iload_6 = _iload_7 = __push_int

    _lload = _lipush = __push_long
    
    _dconst_0 = _dconst_1 = __push_double
    _fconst_0 = _fconst_1 = _fconst_2 = __push_float
    
    # Instructions with specific type-stack implementations
    ###########################################################
    def _swap(self, instr, tstack, tlocals):
        assert (str(tstack[-1]) not in 'JD'), "invalid use of swap"
        assert (str(tstack[-2]) not in 'JD'), "invalid use of swap"
        t1 = tstack.pop()
        t2 = tstack.pop()
        tstack.push(t1)
        tstack.push(t2)

    def _aconst_null(self, instr, tstack, tlocals):
        tstack.push(self._tt['null'])

    # This is, perhaps, not such a good assumption...
    def _ldc(self, instr, tstack, tlocals):
        tstack.push(self._tt['string'])
    _ldc_nullstr = _ldc_unicode = _ldc
    
    # Push the type in that <tlocals> slot
    def _aload(self, instr, tstack, tlocals):
        tstack.push(tlocals[instr.operands[0]])
    
    def _aload_0(self, instr, tstack, tlocals):
        tstack.push(tlocals[0])
    def _aload_1(self, instr, tstack, tlocals):
        tstack.push(tlocals[1])
    def _aload_2(self, instr, tstack, tlocals):
        tstack.push(tlocals[2])
    def _aload_3(self, instr, tstack, tlocals):
        tstack.push(tlocals[3])
    def _aload_4(self, instr, tstack, tlocals):
        tstack.push(tlocals[4])
    def _aload_5(self, instr, tstack, tlocals):
        tstack.push(tlocals[5])
    def _aload_6(self, instr, tstack, tlocals):
        tstack.push(tlocals[6])
    def _aload_7(self, instr, tstack, tlocals):
        tstack.push(tlocals[7])
    
    def _istore(self, instr, tstack, tlocals):
        tstack.pop()
        if self._reals:
            tlocals[instr.operands[0]] = self._tt['float']
        else:
            tlocals[instr.operands[0]] = self._tt['int']
    
    def _astore(self, instr, tstack, tlocals):
        tlocals[instr.operands[0]] = tstack.pop()
    
    def _lstore(self, instr, tstack, tlocals):
        tstack.pop(2)
        local_index = instr.operands[0]
        if self._reals:
            tlocals[local_index] = tlocals[local_index+1] = self._tt['double']
        else:
            tlocals[local_index] = tlocals[local_index+1] = self._tt['long']
    
    def _istore_0(self, instr, tstack, tlocals):
        if self._reals:
            tt = self._tt['float']
        else:
            tt = self._tt['int']
        tstack.pop(); tlocals[0] = tt
    def _istore_1(self, instr, tstack, tlocals):
        if self._reals:
            tt = self._tt['float']
        else:
            tt = self._tt['int']
        tstack.pop(); tlocals[1] = tt
    def _istore_2(self, instr, tstack, tlocals):
        if self._reals:
            tt = self._tt['float']
        else:
            tt = self._tt['int']
        tstack.pop(); tlocals[2] = tt
    def _istore_3(self, instr, tstack, tlocals):
        if self._reals:
            tt = self._tt['float']
        else:
            tt = self._tt['int']
        tstack.pop(); tlocals[3] = tt
    def _istore_4(self, instr, tstack, tlocals):
        if self._reals:
            tt = self._tt['float']
        else:
            tt = self._tt['int']
        tstack.pop(); tlocals[4] = tt
    def _istore_5(self, instr, tstack, tlocals):
        if self._reals:
            tt = self._tt['float']
        else:
            tt = self._tt['int']
        tstack.pop(); tlocals[5] = tt
    def _istore_6(self, instr, tstack, tlocals):
        if self._reals:
            tt = self._tt['float']
        else:
            tt = self._tt['int']
        tstack.pop(); tlocals[6] = tt
    def _istore_7(self, instr, tstack, tlocals):
        if self._reals:
            tt = self._tt['float']
        else:
            tt = self._tt['int']
        tstack.pop(); tlocals[7] = tt
    
    def _astore_0(self, instr, tstack, tlocals):
        tlocals[0] = tstack.pop()
    def _astore_1(self, instr, tstack, tlocals):
        tlocals[1] = tstack.pop()
    def _astore_2(self, instr, tstack, tlocals):
        tlocals[2] = tstack.pop()
    def _astore_3(self, instr, tstack, tlocals):
        tlocals[3] = tstack.pop()
    def _astore_4(self, instr, tstack, tlocals):
        tlocals[4] = tstack.pop()
    def _astore_5(self, instr, tstack, tlocals):
        tlocals[5] = tstack.pop()
    def _astore_6(self, instr, tstack, tlocals):
        tlocals[6] = tstack.pop()
    def _astore_7(self, instr, tstack, tlocals):
        tlocals[7] = tstack.pop()
    
    def _getfield(self, instr, tstack, tlocals):
        field = instr.operands[0]
        if hasattr(field, 'type'):
            tstack.pop_push(field.type[0])
        else:
            totos = tstack.top()
            
            # Can we look up the field by index within TOTOS?
            if (totos.type is None) or (not hasattr(totos.type, 'fft')) or (len(totos.type.fft) <= field):
                # No way to know what goes here
                raise FieldPatchFailed("field lookup (%r) on unhelpful stack type (%s)" % (instr, totos))
            else:
                cdef = totos.type
                cdef.actualize()
                
                try:
                    assert (field >= 0), "Runtime field offset %d < 0" % field
                    fdef = cdef.fft[field]
                except (IndexError, AssertionError):
                    raise FieldPatchFailed("error looking up field %d for type %s" % (field, cdef))
                
                # Replace classref type with field type
                tstack.pop_push(fdef.type[0])
                
                # Also, patchup the instruction's operand list accordingly
                instr.operands[0] = fdef
                self.count("fields")
    _lgetfield = _getfield

    def _lreturn(self, instr, tstack, tlocals):
        totos = tstack.top()
        if self._reals and not totos:
          self.log("WARNING: expected double type on top of stack for return, got empty stack")
        if not self._reals and not totos:
          self.log("WARNING: expected long type on top of stack for return, got empty stack")
        if self._reals and str(totos) not in 'D':
          self.log("WARNING: expected double type on top of stack for return, instead got %s" % repr(totos))
        elif not self._reals and str(totos) not in 'J':
          self.log("WARNING: expected long type on top of stack for return, instead got %s" % repr(totos))
        tstack.pop(2)

    def _ireturn(self, instr, tstack, tlocals):
        totos = tstack.top()
        if self._reals and not totos:
          self.log("WARNING: expected float type on top of stack for return, got empty stack")
        if not self._reals and not totos:
          self.log("WARNING: expected int, short, byte, char or boolean type on top of stack for return, got empty stack")
        if self._reals and str(totos) not in 'F':
          self.log("WARNING: expected float type on top of stack for return, instead got %s" % repr(totos))
        elif not self._reals and str(totos) not in 'ISCBZ':
          self.log("WARNING: expected int, short, byte, char or boolean type on top of stack for return, instead got %s" % repr(totos))
        tstack.pop()

    def _ireturn_field(self, instr, tstack, tlocals):
        # calls getfield on self and then ireturns
        self._aload_0(instr, tstack, tlocals)
        self._getfield(instr, tstack, tlocals)
        self._ireturn(instr, tstack, tlocals)
    _ireturn_field_wide = _ireturn_field

    def _areturn(self, instr, tstack, tlocals):
        totos = tstack.top()
        if not totos:
          self.log("WARNING: expected object type on top of stack for return, got empty stack")
        if not totos._object and not totos._array:
          self.log("WARNING: expected object type on top of stack for return, got %s" % repr(totos))
        tstack.pop()

    def _areturn_field(self, instr, tstack, tlocals):
        # calls getfield on self and then areturns
        self._aload_0(instr, tstack, tlocals)
        self._getfield(instr, tstack, tlocals)
        self._areturn(instr, tstack, tlocals)
    _areturn_field_wide = _areturn_field

    def _aload_0_getfield(self, instr, tstack, tlocals):
        # Equivalent to "push tlocal[0]; getfield BLAH"
        tstack.push(tlocals[0])
        self._getfield(instr, tstack, tlocals)

    def _getstatic(self, instr, tstack, tlocals):
        if hasattr(instr.operands[0], 'type'):
            tstack.push(instr.operands[0].type[0])
        else:
            # Then we just don't know!
            self.log("WARNING: unknown static field '%s' for 'getstatic'; pushing *" % instr.operands[0])
            tstack.push(self._tt['*'])
    _lgetstatic_lib = _lgetstatic = _getstatic_lib = _getstatic
    
    def _putstatic(self, instr, tstack, tlocals):
        if hasattr(instr.operands[0], 'type'):
            tstack.pop()
        else:
            self.log("WARNING: unknown static field '%s' for 'putstatic'" % instr.operands[0])
            tstack.pop()
    _putstatic_lib = _putstatic

    def _lputstatic(self, instr, tstack, tlocals):
        if hasattr(instr.operands[0], 'type'):
            tstack.pop(2)
        else:
            self.log("WARNING: unknown static field '%s' for 'lputstatic'" % instr.operands[0])
            tstack.pop(2)
    _lputstatic_lib = _lputstatic
    
    def _arraylength(self, instr, tstack, tlocals):
        tstack.pop_push(self._tt['int'])
    
    # This is a non-standard JVM opcode; assuming it behaves like arraylength
    _stringlength = _arraylength
    
    def _new(self, instr, tstack, tlocals):
        tstack.push(self.mktt(instr.operands[0], class_name=True))
    _new_lib = _new
    
    def _baload(self, instr, tstack, tlocals):
        tstack.pop()
        if self._reals:
            tstack.pop_push(self._tt['float'])
        else:
            tstack.pop_push(self._tt['int'])
    _iaload = _saload = _caload = _baload
    
    def _newarray(self, instr, tstack, tlocals):
        tstack.pop_push(self.mktt(self._tt[instr.operands[0]], 1))
    
    def _dup(self, instr, tstack, tlocals):
        assert (str(tstack[-1]) not in 'JD'), "invalid use of dup"
        tstack.append(tstack.top())
    
    def _dup2(self, instr, tstack, tlocals):
        tstack += tstack[-2:]
    
    def _jumpspecial(self, instr, tstack, tlocals):
        # jump special appears to simply hand over control to the another function
        # with the current parameters pushed onto the stack:
        #
        # <init>() {
        #   //   0. (00009): jumpspecial_lib java/lang/Object/<init>(Ljava/lang/Object;)V
        # }
        #
        # .method <init>()V
        #    aload_0 ; met001_slot000
        #    invokespecial java/lang/Object.<init>()V
        #    return
        #
        # we need to go through the motions to adjust our max stack and local size
        tl_jts = instr.operands[0].to_jts().split('(')[1].split(')')[0]
        num_params = len(TypeList.split_jts(tl_jts))
        for i in range(num_params):
            tstack.push(tlocals[i])
    _jumpspecial_lib = _jumpspecial
    
    # TODO: implement arguments type verification
    def _invokevirtual(self, instr, tstack, tlocals):
        # If we already know what method we're dealing with, use its info for number of params
        # to pop and type of return value
        if hasattr(instr.operands[0], 'return_type'):
            rdef = instr.operands[0]
            tstack.pop(rdef.param_types.slots())
            ret_type = rdef.return_type
            if ret_type:  # It might be void, you know...
                tstack.push(ret_type[0])
        elif isinstance(instr.operands[0], (int, long)):
            # This is where it gets tricksy.  We look at the second parameter to see how far
            # down the stack "this" lives (and we hope this is right; I've seen it be wrong on
            # fixed-up method calls; maybe that's why they're fixed up???)  We pop the parameters
            # (including "this"), and go from there
            args = tstack.pop(instr.operands[1])
            this = None
            if args[0]._array:
                this = self._loader.ref_class('java/lang/Object')
            elif args[0]._object:
                this = args[0].type
                # we need to actualize this to get the virtual function table
                this.resolve().actualize()

            if (this is None) or (not hasattr(this, 'vft')) or (len(this.vft) <= instr.operands[0]):
                # No idea what should go here
                raise VirtualPatchFailed("virtual method call (%r) on unhelpful stack type (%s)" % (instr, args[0]))
            
            # Make sure it has been actualized
            this.actualize()
            
            try:
                vmindex = instr.operands[0]
                assert (vmindex >= 0), "Runtime VM index %d < 0" % vmindex
                vmethod = this.vft[vmindex]
            except (IndexError, AssertionError) as err:
                raise VirtualPatchFailed("error looking up virtual method %d for type %s" % (instr.operands[0], this))
            
            # Push the return type (if non-void)
            if vmethod.return_type:
                tstack.push(vmethod.return_type[0])
            
            # Fix-up this instruction so we know what call to make in the future (more easily)
            instr.operands[0] = vmethod
            self.count("virtuals")
        else:
            raise ValueError("Invalid virtual method: %r" % instr.operands[0])
    _invokevirtual_short = _invokevirtual

    def _invokestatic(self, instr, tstack, tlocals):
        # Assume we have a RoutineDef here...
        rdef = instr.operands[0]
        tstack.pop(rdef.param_types.slots())
        if rdef.return_type:
            tstack.push(rdef.return_type[0])
    _invokestaticqc_lib = _invokestaticqc = _invokestatic_lib = _invokestatic
    
    def _l2i(self, instr, tstack, tlocals):
        tstack.pop()
        tstack.pop_push(self._tt['int'])
    _d2i = _l2i
    
    def _arrayinit(self, instr, tstack, tlocals):
        tstack.push(self.mktt(self._tt[instr.operands[0]], 1))
    
    def _stringarrayinit(self, instr, tstack, tlocals):
        tstack.push(self._tt['string[]'])
    
    def _multianewarray(self, instr, tstack, tlocals):
        num_dims_given, dims, type = instr.operands
        # pop any specified dimension depths
        for i in range(num_dims_given):
            tstack.pop()
        tstack.push(self.mktt(self._tt[type], dims))
    
    def _multianewarray_object(self, instr, tstack, tlocals):
        type, num_dims_given, dims = instr.operands
        # pop any specified dimension depths
        for i in range(num_dims_given):
            tstack.pop()
        tstack.push(self.mktt(type, dims))
    _multianewarray_object_lib = _multianewarray_object

    def _i2l(self, instr, tstack, tlocals):
        tstack.pop()
        tstack.push(self._tt['long'])
    _f2l = _i2l
    
    def _dup2_x1(self, instr, tstack, tlocals):
        # Stupid category 2 computational types...
        assert (str(tstack[-3]) not in 'JD'), "invalid use of dup2_x1"
        if str(tstack[-2]) not in 'JD':
            # form 1
            tstack[-3:] = tstack[-2:] + tstack[-3:]
        else:
            assert str(tstack[-1]) == str(tstack[-2])
            # form 2
            tstack[-3:] = [tstack[-2], tstack[-1], tstack[-3], tstack[-2], tstack[-1]]

    def _dup2_x2(self, instr, tstack, tlocals):
        # Did I mention that category 2 computational types were a stupid idea?
        if str(tstack[-1]) not in 'JD' and str(tstack[-2]) not in 'JD' and str(tstack[-3]) not in 'JD' and str(tstack[-4]) not in 'JD':
            # form 1
            tstack[-4:] = tstack[-2:] + tstack[-4:]
        elif str(tstack[-1]) in 'JD' and str(tstack[-3]) not in 'JD' and str(tstack[-4]) not in 'JD':
            # form 2
            assert str(tstack[-1]) == str(tstack[-2])
            tstack[-4:] = tstack[-2:] + tstack[-4:-2] + tstack[-2:]
        elif str(tstack[-1]) not in 'JD' and str(tstack[-2]) not in 'JD' and str(tstack[-3]) in 'JD':
            # form 3
            assert str(tstack[-3]) == str(tstack[-4])
            tstack[-4:] = tstack[-2:] + tstack[-4:-2] + tstack[-2:]
        elif str(tstack[-1]) in 'JD' and str(tstack[-3]) in 'JD':
            # form 4
            assert str(tstack[-1]) == str(tstack[-2])
            assert str(tstack[-3]) == str(tstack[-4])
            tstack[-4:] = tstack[-2:] + tstack[-4:-2] + tstack[-2:]
    
    def _dup_x1(self, instr, tstack, tlocals):
        tstack.insert(-2, tstack[-1])
    
    def _dup_x2(self, instr, tstack, tlocals):
        # Is this the last one???
        assert (str(tstack[-1]) not in 'JD'), "invalid use of dup2_x2"
        if str(tstack[-2]) not in 'JD':
            # form 1
            tstack.insert(-3, tstack[-1])
        else:
            # form 2
            assert str(tstack[-2]) == str(tstack[-3])
            tstack[-3:] = [tstack[-1:], tstack[-3], tstack[-2], tstack[-1:]]
    
    def _lcmp(self, instr, tstack, tlocals):
        tstack.pop(4)
        tstack.push(self._tt['int'])
    
    def _invokenonvirtual(self, instr, tstack, tlocals):
        # Figure out the method being called
        rdef = instr.operands[0]
        
        # In any case, pop all the arguments
        tstack.pop(rdef.param_types.slots())
        
        # Handle pushing the return type
        if not hasattr(rdef, 'return_type'):
            raise UnknownTotos("unknown/corrupted return type for nonvirtual method '%s'; TOTOS undefined" % rdef)
        elif rdef.return_type:
            tstack.push(rdef.return_type[0])
    _invokespecial = _invokespecial_lib = _invokenonvirtual_lib = _invokenonvirtual

    def _athrow(self, instr, tstack, tlocals):
        exref = tstack.top()
        del tstack[:]   # Blow away the stack and push the exception object
        tstack.push(exref)
    
    def _aaload(self, instr, tstack, tlocals):
        tstack.pop()
        arrtype = tstack.pop()
        # Do we return an array type or an element-of-an-array type?  Check dims...
        if arrtype.type is None:
            # We have no idea what type would go here
            raise UnknownTotos("%r on indeterminate type; TOTOS undefined..." % instr)
        elif not arrtype._array:
            raise UnknownTotos("%r on non-array type '%s'; TOTOS undefined..." % (instr, arrtype))
        else:
            tstack.push(self.mktt(arrtype.type, arrtype.dims - 1))
    
    def _laload(self, instr, tstack, tlocals):
        tstack.pop(2)
        if self._reals:
            tstack.push(self._tt['double'])
        else:
            tstack.push(self._tt['long'])
    
    def _lastore(self, instr, tstack, tlocals):
        tstack.pop(4)
    
    def _checkcast(self, instr, tstack, tlocals):
        new_type = self.mktt(instr.operands[0], class_name=True)
        tstack.pop_push(new_type)
    _checkcastbranch_lib = _checkcastbranch = _checkcast_lib = _checkcast
    
    def _checkcast_array(self, instr, tstack, tlocals):
        tstack.pop_push(instr.operands[0])
    _checkcastbranch_array = _checkcast_array

    def _checkcast_arrayobject(self, instr, tstack, tlocals):
        new_type = self.mktt(instr.operands[0], instr.operands[1])
        tstack.pop_push(new_type)
    _checkcast_arrayobject_lib = _checkcast_arrayobject
    
    def _newarray_object(self, instr, tstack, tlocals):
        tstack.pop_push(self.mktt(instr.operands[0], 1, class_name=True))
    _newarray_object_lib = _newarray_object
    
    def _invokeinterface(self, instr, tstack, tlocals):
        # Pop instance/args
        tstack.pop(instr.operands[-2])
        
        # Figure out return type (if any)
        rdef = instr.operands[0]
        if not hasattr(rdef, 'return_type'):
            raise UnknownTotos("unknown/corrupted return type for interface method '%s'; TOTOS undefined" % rdef)
        elif rdef.return_type:
            tstack.push(rdef.return_type[0])

    def _i2f(self, instr, tstack, tlocals):
        tstack.pop_push(self._tt['float'])
    
    def _f2i(self, instr, tstack, tlocals):
        tstack.pop_push(self._tt['int'])
    
    def _f2d(self, instr, tstack, tlocals):
        tstack.pop()
        tstack.push(self._tt['double'])
    _i2d = _f2d
    
    def _l2d(self, instr, tstack, tlocals):
        tstack.pop(2)
        tstack.push(self._tt['double'])
    
    def _stringaload(self, instr, tstack, tlocals):
        # indexes a string
        tstack.pop()
        tstack.pop_push(self._tt['char'])
    
    def _dcmpl(self, instr, tstack, tlocals):
        tstack.pop(3)
        tstack.pop_push(self._tt['int'])
    _dcmpg = _dcmpl
    
    def _instanceof(self, instr, tstack, tlocals):
        tstack.pop_push(self._tt['int'])
    _instanceof_array = _instanceof_lib = _instanceof
    
    def _instanceof_arrayobject(self, instr, tstack, tlocals):
        tstack.pop_push(self._tt['int'])
    _instanceof_arrayobject_lib = _instanceof_arrayobject
    
    def _l2f(self, instr, tstack, tlocals):
        tstack.pop()
        tstack.pop_push(self._tt['float'])
    _d2f = _l2f
    
    def _fcmpl(self, instr, tstack, tlocals):
        tstack.pop()
        tstack.pop_push(self._tt['int'])
    _fcmpg = _fcmpl
    
    def _d2l(self, instr, tstack, tlocals):
        tstack.pop(2)
        tstack.push(self._tt['long'])
    
    def _putfield(self, instr, tstack, tlocals):
        field = instr.operands[0]
        value = tstack.pop() # the value we are "putting"
        this = tstack.pop() # the object we are "putting" into
        
        # If the field is an integer, that means we need to patch it up
        if isinstance(field, (int, long)):
            if (this.type is None) or (not hasattr(this.type, 'fft')) or (len(this.type.fft) <= field):
                raise FieldPatchFailed("field lookup (%r) on unhelpful stack type (%s)" % (instr, this))
            else:
                try:
                    assert (field >= 0), "Runtime field index %d < 0" % field
                    fdef = this.type.fft[field]
                except (IndexError, AssertionError) as err:
                    raise FieldPatchFailed("field (%d) lookup failed on type '%s'" % (field, this))
                
                instr.operands[0] = fdef
                self.count("fields")
    _putfield_wide = _putfield
    
    def _putfield_return(self, instr, tstack, tlocals):
        # calls putfield on object and then returns
        self._aload_0(instr, tstack, tlocals) # object
        self._aload_1(instr, tstack, tlocals) # value
        self._putfield(instr, tstack, tlocals)
    _putfield_return_wide = _putfield_return
    
    def _lputfield(self, instr, tstack, tlocals):
        # Same as putfield, but with 2 pops for the value
        tstack.pop()
        self._putfield(instr, tstack, tlocals)
    _lputfield_wide = _lputfield

    # TODO: not really sure about that...
    def _ldc_class(self, instr, tstack, tlocals):
        type = self.mktt(instr.operands[0], class_name=True)
        tstack.push(type)
    _ldc_class_lib = _ldc_class
