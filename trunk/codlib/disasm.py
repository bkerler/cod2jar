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
disasm: A byte-code disassembler for RIM's proprietary JVM.
"""

from bytecleaver import *
from utils import TypeToken, TypeList, Primitive
from instruction_reference import branches, conditional_branches, compound_branches
import sys
from struct import unpack

# Stand by for Python 2.6+ advanced metaclass juju in 3, 2, 1...
from abc import ABCMeta

_OPCODES = [
    'breakpoint', 'invokevirtual', 'invokeinterface', 'invokenonvirtual',
    'invokenonvirtual_lib', 'invokespecial', 'invokespecial_lib', 'invokestatic',
    'invokestatic_lib', 'iinvokenative', 'invokenative', 'linvokenative',
    'jumpspecial', 'jumpspecial_lib', 'enter', 'enter_wide', 'xenter',
    'xenter_wide', 'synch', 'synch_static', 'clinit_wait', 'ireturn_bipush',
    'ireturn_sipush', 'ireturn_iipush', 'ireturn', 'ireturn_field',
    'ireturn_field_wide', 'areturn', 'areturn_field', 'areturn_field_wide',
    'lreturn', 'return', 'clinit_return', 'noenter_return', 'aconst_null',
    'iconst_0', 'bipush', 'sipush', 'iipush', 'lipush', 'ldc', 'unused_29',
    'ldc_unicode', 'unused_2b', 'iconst_1', 'arrayinit', 'unused_2e',
    'tableswitch', 'unused_30', 'iload', 'iload_wide', 'aload', 'aload_wide',
    'lload', 'lload_wide', 'iload_0', 'iload_1', 'iload_2', 'iload_3',
    'iload_4', 'iload_5', 'iload_6', 'iload_7', 'aload_0', 'aload_1', 'aload_2',
    'aload_3', 'aload_4', 'aload_5', 'aload_6', 'aload_7', 'istore',
    'istore_wide', 'astore', 'astore_wide', 'lstore', 'lstore_wide', 'istore_0',
    'istore_1', 'istore_2', 'istore_3', 'istore_4', 'istore_5', 'istore_6',
    'istore_7', 'astore_0', 'astore_1', 'astore_2', 'astore_3', 'astore_4',
    'astore_5', 'astore_6', 'astore_7', 'putfield_return', 'putfield_return_wide',
    'putfield', 'putfield_wide', 'lputfield', 'lputfield_wide', 'getfield',
    'getfield_wide', 'lgetfield', 'lgetfield_wide', 'aload_0_getfield',
    'aload_0_getfield_wide', 'putstatic', 'putstatic_lib', 'lputstatic',
    'lputstatic_lib', 'getstatic', 'getstatic_lib', 'lgetstatic', 'lgetstatic_lib',
    'i2b', 'i2s', 'i2c', 'i2l', 'l2i', 'ineg', 'lneg', 'iinc', 'iinc_wide', 'iadd',
    'ladd', 'isub', 'lsub', 'imul', 'lmul', 'idiv', 'ldiv', 'irem', 'lrem', 'iand',
    'land', 'ior', 'lor', 'ixor', 'lxor', 'ishl', 'lshl', 'ishr', 'lshr', 'iushr',
    'lushr', 'lcmp', 'if_icmpeq', 'if_acmpeq', 'ifeq', 'if_icmpne', 'if_acmpne',
    'ifne', 'if_icmpgt', 'ifgt', 'if_icmpge', 'ifge', 'if_icmplt', 'iflt',
    'if_icmple', 'ifle', 'ifnull', 'ifnonnull', 'goto', 'goto_w',
    'lookupswitch_short', 'lookupswitch', 'newarray', 'multianewarray',
    'arraylength', 'newarray_object', 'newarray_object_lib',
    'multianewarray_object', 'multianewarray_object_lib', 'baload', 'saload',
    'caload', 'iaload', 'aaload', 'laload', 'bastore', 'castore', 'sastore',
    'iastore', 'aastore', 'lastore', 'new', 'new_lib', 'clinit', 'clinit_lib',
    'athrow', 'instanceof_array', 'checkcast_array', 'instanceof',
    'instanceof_lib', 'checkcast', 'checkcast_lib', 'checkcastbranch',
    'checkcastbranch_lib', 'checkcastbranch_array', 'instanceof_arrayobject',
    'instanceof_arrayobject_lib', 'checkcast_arrayobject',
    'checkcast_arrayobject_lib', 'monitorenter', 'monitorexit', 'nop', 'pop',
    'pop2', 'dup', 'dup2', 'dup_x1', 'dup_x2', 'dup2_x1', 'dup2_x2', 'swap',
    'unused_d6', 'isreal', 'op01xx', 'stringlength', 'stringaload',
    'invokestaticqc', 'invokestaticqc_lib', 'enter_narrow', 'invokevirtual_short',
    'ldc_nullstr', 'unused_e0', 'unused_e1', 'unused_e2', 'unused_e3', 'unused_e4',
    'unused_e5', 'unused_e6', 'unused_e7', 'unused_e8', 'unused_e9', 'unused_ea',
    'unused_eb', 'unused_ec', 'unused_ed', 'unused_ee', 'unused_ef', 'unused_f0',
    'unused_f1', 'unused_f2', 'unused_f3', 'unused_f4', 'unused_f5', 'unused_f6',
    'unused_f7', 'unused_f8', 'unused_f9', 'halt', 'threaddeath', 'errOp1',
    'errOp2', 'unused_fe', 'unused_ff', 'fadd', 'dadd', 'fsub', 'dsub', 'fmul',
    'dmul', 'fdiv', 'ddiv', 'frem', 'drem', 'fneg', 'dneg', 'i2f', 'i2d', 'l2f',
    'l2d', 'f2i', 'f2l', 'f2d', 'd2i', 'd2l', 'd2f', 'fcmpl', 'fcmpg', 'dcmpl',
    'dcmpg', 'stringarrayinit', 'jmpback', 'jmpforward', 'dconst_0', 'dconst_1',
    'fconst_0', 'fconst_1', 'fconst_2', 'ldc_class', 'ldc_class_lib',
]

# zero stands for variably-sized
_OPCODE_SIZES = [
    1, 4, 6, 4, 5, 4, 5, 4, 5, 4, 4, 4, 3, 4, 1, 4, 1, 4, 1, 2, 1, 2, 3, 5, 1, 2, 2,
    1, 2, 2, 1, 1, 1, 1, 1, 1, 2, 3, 5, 9, 3, 1, 5, 1, 1, 6, 1, 0, 1, 2, 3, 2, 3, 2,
    3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 2, 3, 2, 3, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4, 5, 4,
    5, 4, 5, 4, 5, 1, 1, 1, 1, 1, 1, 1, 3, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 0, 0, 2, 4, 1, 2, 3, 4, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 2, 3, 1,
    3, 3, 2, 3, 2, 3, 4, 5, 5, 3, 4, 3, 4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 4, 5, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 3, 3, 1, 1, 1, 1, 1, 2, 3,
]

# jasmin instruction conversion groups
_JVM_XLATE_OPCODES_SAME = [
    'aaload', 'aastore', 'aconst_null', 'aload_0', 'aload_1', 'aload_2',
    'aload_3', 'areturn', 'arraylength', 'astore_0', 'astore_1', 'astore_2', 'astore_3',
    'athrow', 'baload', 'bastore', 'bipush', 'breakpoint', 'caload', 'castore', 'd2f',
    'd2i', 'd2l', 'dadd', 'dcmpg', 'dcmpl', 'dconst_0', 'dconst_1', 'ddiv', 'dmul', 'dneg', 'drem',
    'dsub', 'dup', 'dup2', 'dup2_x1', 'dup2_x2', 'dup_x1', 'dup_x2', 'f2d',
    'f2i', 'f2l', 'fadd', 'fcmpg', 'fcmpl', 'fconst_0', 'fconst_1', 'fconst_2', 'fdiv', 'fmul', 'fneg', 'frem',
    'fsub', 'i2b', 'i2c', 'i2d', 'i2f', 'i2l', 'i2s', 'iadd', 'iaload',
    'iand', 'iastore', 'iconst_0', 'iconst_1', 'idiv', 'iload_0', 'iload_1', 'iload_2', 'iload_3',
    'imul', 'ineg', 'ior', 'irem', 'ireturn', 'ishl', 'ishr', 'istore_0',
    'istore_1', 'istore_2', 'istore_3', 'isub', 'iushr', 'ixor', 'l2d',
    'l2f', 'l2i', 'ladd', 'laload', 'land', 'lastore', 'lcmp', 'ldiv',
    'lmul', 'lneg','lor', 'lrem', 'lreturn', 'lshl', 'lshr', 'lsub',
    'lushr', 'lxor', 'monitorenter', 'monitorexit', 'nop', 'pop', 'pop2',
    'return', 'saload', 'sastore', 'sipush', 'swap',
]

_JVM_XLATE_OPCODES_SAME_BRANCHES = [
    'if_acmpeq', 'if_acmpne', 'if_icmpeq', 'if_icmpge', 'if_icmpgt',
    'if_icmple', 'if_icmplt', 'if_icmpne', 'ifeq', 'ifge', 'ifgt', 'ifle',
    'iflt', 'ifne', 'ifnonnull', 'ifnull',
    'goto', 'goto_w',    
]

_JVM_XLATE_OPCODES_WIDE_SHORTHAND = [
    'aload_4', 'aload_5', 'aload_6', 'aload_7',
    'astore_4', 'astore_5', 'astore_6', 'astore_7',
    'iload_4', 'iload_5', 'iload_6', 'iload_7',
    'istore_4', 'istore_5', 'istore_6', 'istore_7',
]

_JVM_XLATE_OPCODES_SHORTHANDABLE = [
    'aload', 'aload_wide', 'astore', 'astore_wide', 
    'iload', 'iload_wide', 'istore', 'istore_wide', 
    'lload', 'lload_wide', 'lstore', 'lstore_wide',
]

_JVM_XLATE_OPCODES_NOPS = [
    'enter_narrow', 'enter', 'enter_wide', 'xenter', 'xenter_wide',

    # these instructions are created by using the synchronized keyword
    # in method declarations and can be ignored
    'synch', 'synch_static',
    
    # ignore class initialization waits
    'clinit_wait',
]

# "Shift" byte used to extend the range of a subsequent opcode's value
_ESC_BYTE = 216

# Opcode clusters corresponding to equivalent types of operand processing
_BRANCH_NEAR = frozenset(range(145, 162))
_BRANCH_FAR = (162,)
_BRANCH_UP = (283,)
_BRANCH_DOWN = (284,)
_SINGLE_UBYTE_OP = frozenset([49, 51, 53, 71, 73, 75,])
_SINGLE_SBYTE_OP = (21, 36)
_SINGLE_SWORD_OP = (22, 37)
_SINGLE_UWORD_OP = frozenset([50, 52, 54, 72, 74, 76])
_SINGLE_INT_OP = (23, 38)
_STRING_ARRAY_INIT_OP = (282,)
_ARRAY_INIT_OP = (45,)
_CONSTRAINTS_OP = (15, 17)
_LOOKUPSWITCH_OP = (163, 164); _LOOKUPSWITCH_EXTRA = (163,)
_TABLESWITCH_OP = (47,)
_TWO_BYTE_OP = (120,)
_TWO_WORD_OP = (121,)
_SINGLE_SLONG_OP = (39,)
_CLASS_FIELDREF_OP = frozenset(range(105, 113)); _CLASS_FIELDREF_EXTRA = (106, 108, 110, 112)
_REL_FIELDREF_OP = frozenset([25, 28, 93, 95, 97, 99, 101, 103])
_REL_FAR_FIELDREF_OP = frozenset([26, 29, 94, 96, 98, 100, 102, 104])
_INVOKESTATIC_OP = (7, 8, 219, 220); _INVOKESTATIC_EXTRA = (8, 220)
_INVOKENATIVE_OP = (9, 10, 11)
_JUMPSPECIAL_OP = (12, 13); _JUMPSPECIAL_EXTRA = (13,)
_INVOKESPECIAL_OP = (3, 4, 5, 6); _INVOKESPECIAL_EXTRA = (4, 6)
_INVOKEVIRTUAL_OP = (1,)
_INVOKEVIRTUAL_SHORT_OP = (222,)
_INVOKEINTERFACE_OP = (2,)
_LDC_OP = (40, 42); _LDC_EXTRA = (42,)
_CLASSREF_OP = frozenset([19, 168, 169, 184, 185, 186, 187, 191, 192, 193, 194, 290, 291]); _CLASSREF_EXTRA = frozenset([169, 185, 187, 192, 194, 291])
_CLASSREF_CHECK_OP = (198, 199, 200, 201); _CLASSREF_CHECK_EXTRA = (199, 201)
_NEWARRAY_OP = (165,)
_MULTINEWARRAY_OP = (166,)
_MULTINEWARRAY_OBJ_OP = (170, 171); _MULTINEWARRAY_OBJ_EXTRA = (171,)
_CHECKCASTBRANCH_OP = (195, 196); _CHECKCASTBRANCH_EXTRA = (196,)
_TYPECHECK_ARRAY_OP = (189, 190, 197); _TYPECHECK_ARRAY_OP_EXTRA = (197,)
_BAD_OPS = frozenset([41, 43, 46, 48, 214] + range(224, 250) + range(251, 256))
# enter_wide and xenter_wide have three parameters: num_locals>>8, num_params>>8, and max_stack>>8

_ARRAY_TYPES = {
    1: "boolean",
    2: "byte",
    3: "char",
    4: "short",
    5: "int",
    6: "long",
    11: "float",
    12: "double",
}
_ARRAY_SIZES = {
    1: 1,
    2: 1,
    3: 1,
    4: 2,
    5: 4,
    6: 8,
    11: 4,
    12: 8,
}
_ARRAY_UNPACK_CODES = {
    1: 'b',
    2: 'b',
    3: 'b',
    4: 'h',
    5: 'i',
    6: 'q',
    11: 'f',
    12: 'd',
}

class BadOpcodeError(Exception): pass

# Operands referencing CODng member types (ClassDef/RoutineDef/FieldDef or a LazyXXX reference to one)
class RefOperand:
    __metaclass__ = ABCMeta
    
    # Do this check dynamically rather than with .register() since we cannot import
    # anything from resolve at load time...
    @classmethod
    def __subclasshook__(cls, C):
        from resolve import ClassDef, RoutineDef, FieldDef, LazyClassDef, LazyRoutineDef, LazyFieldDef
        if cls is RefOperand:
            if C in (ClassDef, RoutineDef, FieldDef, LazyClassDef, LazyRoutineDef, LazyFieldDef):
                return True
        return NotImplemented

# Non-CODng-member-reference operands
class LitOperand:
    __metaclass__ = ABCMeta
LitOperand.register(tuple)
LitOperand.register(list)
LitOperand.register(int)
LitOperand.register(long)
LitOperand.register(float)
LitOperand.register(basestring)

class BadOperand(object):
    def __init__(self, op):
        self.op = op
    
    def __str__(self):
        return "ERROR(%s)" % self.op
    
    def __repr__(self):
        return "<bad-op: '%s'>" % self.op

class Instruction(object):
    __slots__ = ['offset', 'opcode', '_name', '_ops', '_fixups', 'operands',  'totos']
    
    def __init__(self, offset, opcode, operands, fixups):
        if (offset is None) and (opcode is None) and (operands is None) and (fixups is None): return
        self.offset = offset
        self.opcode = opcode
        try:
            self._name = _OPCODES[opcode]
        except IndexError:
            raise Exception('Invalid opcode %d encountered during disassembly' % opcode)
        self._ops = operands
        self._fixups = fixups
        self.operands = self._ops[:]
        
        # Type-on-Top-of-Stack is always unknown initially
        self.totos = None
    
    def fixup(self, routine):
        parent = routine.parent
        mod = routine.module
        assert (mod is parent.module), "Module mismatch ('%s' vs. '%s') for routine '%s'!!!!" % (mod.name, parent.module.name, routine.name)
        assert hasattr(mod, '_routine_map'), "Module '%s' does not have a _routine_map--cannot fixup routine '%s'!" % (mod.name, routine.name)
        R = mod._R
        _fixed = [False for i in xrange(len(self._ops))]
        _num_fixed = 0
        
        # Do we have a potentially-fixup-able field?
        if self._fixups:
            _fmap = mod._fixup_map
            # For each fixup we have...
            for i, offset in enumerate(self._fixups):
                if not offset: continue
                # Search the module's fixup map for the offset
                try:
                    self.operands[i] = _fmap[offset]
                    _fixed[i] = True
                    _num_fixed += 1
                except KeyError:
                    # No cigar
                    continue
        
        # If we "fixed" all raw operands, bail now
        if _num_fixed == len(self._ops): return self
        
        # Opcode-specific manual fixups if auto-fixup fails
        _op = self.opcode
        if (_op in _CLASS_FIELDREF_OP) and (not _fixed[0]):
            try:
                mod_byte, class_byte = self._ops[0].class_id
                if mod_byte == 255:
                    # Indexed lookup
                    self.operands[0] = mod.static_field_fixups[self._ops[1]].get_item()
                else:
                    # Address lookup
                    self.operands[0] = R.get_class(self._ops[0]).get_class().get_field_by_address(self._ops[1])
            except Exception as e:
                mod._L.log("WARNING: failed to fixup class-fieldref (%r): %s (%s)" % (self, e, type(e)))
                self.operands[0] = BadOperand(e)
        elif ((_op in _REL_FIELDREF_OP) or (_op in _REL_FAR_FIELDREF_OP)) and (not _fixed[0]):
            offset = self._ops[0]
            
            # If the offset < -1, flip it and use it to look up the field in our field_fixups table
            if offset < -1:
                findex = -(offset + 2)
                try:
                    self.operands[0] = mod.field_fixups[findex]
                except IndexError as err:
                    # Must not be in the fixups list; convert to unsigned byte and leave to runtime fixup
                    self.operands[0] = offset & 0xff
            else:
                self.operands[0] = offset # Normal runtime (i.e., dynamic) fixup
        elif ((_op in _INVOKESTATIC_OP) or (_op in _JUMPSPECIAL_OP) or (_op in _INVOKESPECIAL_OP)) and (not _fixed[0]):
            try:
                if len(self._ops[0]) == 3:
                    mod_byte, class_byte, routine_word = self._ops[0]
                else:
                    mod_byte, routine_word = self._ops[0]

                if mod_byte == 255:
                    # Indexed fixup-lookup
                    self.operands[0] = mod.method_fixups[routine_word].get_item()
                    #mod._L.log("DEBUG: call-lookup; method_fixup[%d] := %s" % (routine_word, self.operands[0]))
                elif mod_byte == 0:
                    # Address routine lookup within our own module (already resolved, for sure)
                    self.operands[0] = mod._routine_map[routine_word]
                    #mod._L.log("DEBUG: call-lookup; method_offset[%d] := %s" % (routine_word, self.operands[0]))
                elif mod_byte <= len(mod.imports):
                    # Address routine lookup within an import module
                    try:
                        imod = mod.imports[mod_byte - 1]
                    except IndexError as err:
                        raise Exception("bad_call_ref[%d:%s:%d]" % (mod_byte, class_byte if (len(self._ops[0]) == 3) else '', routine_word))
                    self.operands[0] = imod._routine_map[routine_word]
                    #mod._L.log("DEBUG: call-lookup; module[%d].offset[%d] := %s" % (mod_byte, routine_word, self.operands[0]))
                elif not mod._disk:
                    # Try module-remapping (only in heap-mode)
                    try:
                        imod = mod._mod_remap[mod_byte] # NOT (mod_byte - 1)!!!  Trust me!
                    except KeyError as err:
                        raise Exception("bad_call_ref[%d:%s:%d]" % (mod_byte, class_byte if (len(self._ops[0]) == 3) else '', routine_word))
                    self.operands[0] = imod._routine_map[routine_word]
                    #mod._L.log("DEBUG: call-lookup; module_remap[%d].offset[%d] := %s" % (mod_byte, routine_word, self.operands[0]))
            except Exception as e:
                mod._L.log("WARNING: %s" % e)
                self.operands[0] = BadOperand(e)
            
            # If we KNOW this is getting invoked like a static method, make sure that operands[0] is
            # actually a static method (a hack, but hey, it works)
            # (don't think this is necessary anymore--lazy references have eliminated the need
            # for keeping FixupXXX instances around in most circumstances)
            #if (_op in _INVOKESTATIC_OP):
            #  from resolve import FixupMethod
            #  if self.operands[0].op, FixupMethod):
            #    self.operands[0].is_static = True
            
        elif ((_op in _INVOKEVIRTUAL_OP) or (_op in _INVOKEVIRTUAL_SHORT_OP)) and (not _fixed[0]):
            offset = self._ops[0]
            
            # If this offset is < -1, we need to look it up in our virtual_method_fixup table
            if offset < -1:
                mindex = -(offset + 2)
                try:
                    self.operands[0] = mod.virtual_method_fixups[mindex]
                except IndexError as err:
                    mod._L.log("WARNING: bad_vmethod_fixup[%d:%d]" % (offset, mindex))
                    self.operands[0] = self._ops[0]  # No can fixup, Kemosabe (no, I did not copy/paste this comment)
            else:
                self.operands[0] = self._ops[0] # No go; have to fix it at "runtime" using heuristic instruction scanning
        elif ((_op in _CLASSREF_OP) or (_op in _CLASSREF_CHECK_OP) or (_op in _CHECKCASTBRANCH_OP)) and (not _fixed[0]):
            self.operands[0] = R.get_class(self._ops[0])
        elif _op in _INVOKEINTERFACE_OP:
            try:
                self.operands[0] = mod._iface_mref_map[self._ops[0]].get_method()
            except KeyError as e:
                mod._L.log("WARNING: bad_ifacemethod_fixup[%s]" % self._ops[0])
                self.operands[0] = BadOperand(e)
        elif _op in _MULTINEWARRAY_OBJ_OP and (not _fixed[0]):
            self.operands[0] = R.get_class(self._ops[0])    
        
        # Eliminate things we don't need...
        del self._ops,  self._fixups
        return self
    
    def __str__(self):
        comment = '' if (self.totos is None) else (' ; %s' % self.totos.to_jts())
        if self.operands:
            ops = ' '.join(
                str(op) if not isinstance(op, basestring) else repr(op)
                    for op in self.operands
            )
            return "%s %s%s" % (self._name, ops, comment)
        else:
            return self._name + comment
    
    def __repr__(self):
        return "<instr: %s @ %06d>" % (self._name, self.offset)
    
    def serialize(self):
        from resolve import RoutineDef, ClassDef, FieldDef
        
        s_ops = []
        for op in self.operands:
            # We have to serialize these ourselves
            if isinstance(op, RefOperand):
                ot = op.TYPE()
                
                if ot is ClassDef:
                    char = 'C'
                elif ot is RoutineDef:
                    char = 'M'
                elif ot is FieldDef:
                    char = 'F'
                else:
                    raise ValueError("Invalid RefOperand type '%s' for instruction %r" % (ot, self))
                
                s_ops.append((char, op.to_jts()))
            
            # Python knows how to pickle these suckers
            elif isinstance(op, LitOperand):
                s_ops.append(('L', op))
            
            # We occasionally have TypeTokens as operands
            elif isinstance(op, TypeToken):
                s_ops.append(('T', op.serialize()))
            
            # Uh-oh...
            else:
                raise NotImplementedError("Unexpected operand type '%s' in instruction %r" % (type(op), self))
        
        assert ((self.totos is None) or isinstance(self.totos, TypeToken)), "Bad TOTOS @ %06d" % self.offset
        if s_ops:
            return (self.offset, self.opcode, s_ops, self.totos.serialize() if self.totos else None)
        else:
            return (self.offset, self.opcode, self.totos.serialize() if self.totos else None)

    def to_jasmin(self, log_file=sys.stderr):
        ''' Returns Jasmin equivalent instruction statement for
                this instruction if possible, None otherwise.
        '''
        # start off by getting the instruction in string form
        if self.operands:
            ops = ' '.join(op.to_jts() if hasattr(op, 'to_jts') else str(op) if not isinstance(op, basestring) else '"%s"' % op.replace('"', '\\"') for op in self.operands)
            istr = "%s %s" % (self._name, ops)
        else:
            istr = self._name

        # same as JVM spec
        if self._name in _JVM_XLATE_OPCODES_SAME:
            return istr
        elif self._name == 'isreal':
            # this instruction modifies the following instruction
            return None
        elif self._name in _JVM_XLATE_OPCODES_SAME_BRANCHES:
            # change the branch to point to the label instead of an offset
            # NOTE: branching label convention is "loc_%d:" % self.offset
            branches = self.get_branch_locations()
            assert len(branches) == 1
            branch = branches[0]
            return '%s loc_%d' % (self._name, branch)
        elif self._name == 'jmpback':
            return 'goto loc_%d' % offsets[0]
        elif self._name == 'jmpforward':
            return 'goto loc_%d' % offsets[0]
        elif self._name == 'tableswitch':
            offsets = self.get_branch_locations()
            # if there is only one branch, just convert it into a goto
            if len(offsets) == 1:
                return 'goto loc_%d' % offsets[0]
            default_offset = offsets.pop(0)
            new_instr = 'tableswitch %s' % (self.operands[1]+1)
            for i, offset in enumerate(offsets):
                new_instr += '\n                  loc_%d ; %s' % (offset, self.operands[1]+i+1)
            new_instr += '\n        default : loc_%d' % default_offset
            return new_instr
        elif self._name in ['lookupswitch', 'lookupswitch_short']:
            offsets = self.get_branch_locations()
            # if there is only one branch, just convert it into a goto
            if len(offsets) == 1:
                return 'goto loc_%d' % offsets[0]
            switches = []
            for j, offset in enumerate(offsets[1:]):
                case = self.operands[-2][j][0]
                switches.append((case, offset))
            # do additional default case field as well
            default_offset = offsets.pop(0)
            new_instr = 'lookupswitch'
            for case, offset in switches:
                new_instr += '\n        %7d : loc_%d' % (case, offset)
            new_instr += '\n        default : loc_%d' % default_offset
            return new_instr
        elif self._name in _JVM_XLATE_OPCODES_WIDE_SHORTHAND:
            instruction_name, index = self._name.split('_')
            return "%s %s" % (instruction_name, index)
        elif self._name in _JVM_XLATE_OPCODES_SHORTHANDABLE:
            # convert to a shorthand version if possible
            if self.operands[0] in [0, 1, 2, 3]:
                return "%s_%d" % (self._name.replace('_wide', ''),
                                                    self.operands[0])
            else:
                return "%s" % istr.replace('_wide', '')
        elif self._name in _JVM_XLATE_OPCODES_NOPS:
            return "; nop"
        elif self._name in ['iinc', 'iinc_wide']:
            return "iinc %d %d" % tuple(self.operands)
        elif self._name == 'iipush':
            return "ldc %s" % self.operands[0]
        elif self._name == 'lipush':
            return "ldc2_w %s" % self.operands[0]
        elif self._name == 'ldc':
            if not isinstance(self.operands[0], basestring):
                op_str = str(self.operands[0])
            elif repr(self.operands[0])[0] == '"':
                # NOTE: java ldc can't handle \x??, so replace it
                op_str = '"%s"' % repr(self.operands[0])[1:-1].replace('\\x', '\\\\x')
            else:
                op_str = '"%s"' % repr(self.operands[0])[1:-1].replace('"', '\\"').replace('\\x', '\\\\x')
            return "ldc %s" % op_str
        elif self._name == 'ldc_unicode':
            if not isinstance(self.operands[0], basestring):
                op_str = str(self.operands[0])
            elif repr(self.operands[0])[0] == '"':
                # NOTE: java ldc can't handle \x??, so replace it
                op_str = '"%s"' % repr(self.operands[0])[1:-1].replace('\\x', '\\\\x')
            else:
                op_str = '"%s"' % repr(self.operands[0])[1:-1].replace('"', '\\"').replace('\\x', '\\\\x')
            return "ldc %s" % op_str
        elif self._name == 'ldc_nullstr':
            return 'ldc ""'
        elif self._name in ['ldc_class', 'ldc_class_lib']:
            return 'ldc %s' % self.operands[0].to_jts()
        elif self._name == 'invokenative':
            new_instr =  '; NATIVE METHOD CALL #%d' % self.operands[-1]
            new_instr += '\n    return'
            return new_instr
        elif self._name == 'iinvokenative':
            new_instr =  '; NATIVE METHOD CALL #%d' % self.operands[-1]
            new_instr += '\n    iconst_0'
            new_instr += '\n    ireturn'
            return new_instr
        elif self._name == 'linvokenative':
            new_instr =  '; NATIVE METHOD CALL #%d' % self.operands[-1]
            new_instr += '\n    lconst_0'
            new_instr += '\n    lreturn'
            return new_instr
        elif self._name in ['invokevirtual', 'invokevirtual_short']:
            return "invokevirtual %s" % self.operands[0].to_jts(skip_first=True)
        elif self._name == 'invokeinterface':
            return "invokeinterface %s %d" % (self.operands[0].to_jts(skip_first=True), self.operands[1] - 1)
        elif self._name in ['invokenonvirtual', 'invokenonvirtual_lib']:
            return "invokenonvirtual %s" % self.operands[0].to_jts(skip_first=True)
        elif self._name in ['invokestatic', 'invokestatic_lib',
                                                'invokestaticqc', 'invokestaticqc_lib']:
            return "invokestatic %s" % self.operands[0].to_jts()
        elif self._name in ['invokespecial', 'invokespecial_lib']:
            return "invokespecial %s" % self.operands[0].to_jts(skip_first=True)
        elif self._name in ['jumpspecial', 'jumpspecial_lib']:
            tl_jts = self.operands[0].to_jts().split('(')[1].split(')')[0]
            num_params = len(TypeList.split_jts(tl_jts))
            new_instr = ""
            for i in range(num_params):
                if i < 4:
                    new_instr += "aload_%d\n    " % i
                else:
                    new_instr += "aload %d\n    " % i
            new_instr +=  "invokespecial %s" % self.operands[0].to_jts(skip_first=True)
            new_instr +=  "\n    return"
            return new_instr
        elif self._name in ['aload_0_getfield', 'aload_0_getfield_wide']:
            return "aload_0\n    getfield %s %s" % (self.operands[0].to_jts(), self.operands[0].type.to_jts())
        elif self._name == 'ireturn_bipush':
            return "bipush %s\n    ireturn" % str(self.operands[0])
        elif self._name == 'ireturn_sipush':
            return "sipush %s\n    ireturn" % str(self.operands[0])
        elif self._name == 'ireturn_iipush':
            return "ldc %s\n    ireturn" % str(self.operands[0])
        elif self._name in ['ireturn_field', 'ireturn_field_wide']:
            return "aload_0\n    getfield %s %s\n    ireturn" % (self.operands[0].to_jts(), self.operands[0].type.to_jts())
        elif self._name in ['areturn_field', 'areturn_field_wide']:
            return "aload_0\n    getfield %s %s\n    areturn" % (self.operands[0].to_jts(), self.operands[0].type.to_jts())
        elif self._name in ['putfield_return', 'putfield_return_wide']:
            return "aload_0\n    aload_1\n    putfield %s %s\n    return" % (self.operands[0].to_jts(), self.operands[0].type.to_jts())
        elif self._name in ['putfield', 'putfield_wide', 'lputfield', 'lputfield_wide']:
            return "putfield %s %s" % (self.operands[0].to_jts(), self.operands[0].type.to_jts())
        elif self._name in ['getfield', 'getfield_wide', 'lgetfield', 'lgetfield_wide']:
            return "getfield %s %s" % (self.operands[0].to_jts(), self.operands[0].type.to_jts())
        elif self._name in ['putstatic', 'putstatic_lib', 'lputstatic', 'lputstatic_lib']:
            return "putstatic %s %s" % (self.operands[0].to_jts(), self.operands[0].type.to_jts())
        elif self._name in ['getstatic', 'getstatic_lib', 'lgetstatic', 'lgetstatic_lib']:
            return "getstatic %s %s" % (self.operands[0].to_jts(), self.operands[0].type.to_jts())
        elif self._name == 'noenter_return':
            return "return"
        elif self._name == 'newarray':
            return "newarray %s" % self.operands[0]
        elif self._name in ['newarray_object', 'newarray_object_lib']:
            return "anewarray %s" % self.operands[0].to_jts()
        elif self._name == 'multianewarray':
            jts = '[' * self.operands[1] + Primitive.TYPE_CHAR[self.operands[2]]
            return "multianewarray %s %s" % (jts, self.operands[0])
        elif self._name in ['multianewarray_object', 'multianewarray_object_lib']:
            jts = '[' * self.operands[2] + 'L' + self.operands[0].to_jts() + ';'
            return "multianewarray %s %s" % (jts, self.operands[1])
        elif self._name == 'arrayinit':
            type = self.operands[0]
            array = self.operands[1]
            new_instr = 'ldc %s' % len(array)
            new_instr += '\n    newarray %s' % type
            for i, item in enumerate(array):
                    if type not in ['boolean', 'byte', 'char', 'short', 'int', 'long', 'float', 'double']:
                        raise Exception('Unexpected type for arrayinit instruction: %s' % type)
                    new_instr += '\n    dup'
                    new_instr += '\n    ldc %s' % i
                    if type in ['boolean', 'byte', 'char',]:
                        new_instr += '\n    bipush %s' % item
                    elif type == 'short':
                        new_instr += '\n    sipush %s' % item
                    elif type in ['int',]:
                        new_instr += '\n    ldc %s' % item
                    elif type in ['float']:
                        op_str = '%E' % item
                        # workaround because jasmin can't handle NaN/Infinity
                        if '#IND' in op_str or '#QNAN' in op_str:
                            # NaN
                            new_instr += "\n    ldc 0x7fc00000"
                            new_instr += "\n    invokestatic java/lang/Float/intBitsToFloat(I)F"
                        elif '#INF' in op_str:
                            if op_str[0] == '-':
                                # -Infinity
                                new_instr += "\n    ldc -3.4028237E38"
                            else:
                                # Infinity
                                new_instr += "\n    ldc 3.4028237E38"
                        else:
                            new_instr += "\n    ldc %s" % op_str
                    elif type in ['long',]:
                        new_instr += '\n    ldc2_w %s' % item
                    elif type in ['double']:
                        op_str = '%E' % item
                        # workaround because jasmin can't handle NaN/Infinity
                        if '#IND' in op_str or '#QNAN' in op_str:
                            # NaN
                            new_instr += "\n    ldc2_w 0x7ff8000000000000"
                            new_instr += "\n    invokestatic java/lang/Double/longBitsToDouble(J)D"
                        elif '#INF' in op_str:
                            if op_str[0] == '-':
                                # -Infinity
                                new_instr += "\n    ldc2_w -1.797693134862316E308"
                            else:
                                # Infinity
                                new_instr += "\n    ldc2_w 1.797693134862316E308"
                        else:
                            new_instr += "\n    ldc2_w %s" % op_str
                    new_instr += '\n    %castore' % type[0]
            return new_instr
        elif self._name == 'stringarrayinit':
            array = self.operands[0]
            new_instr = 'ldc %s' % len(array)
            new_instr += '\n    anewarray java/lang/String'        

            for i, item in enumerate(array):
                new_instr += '\n    dup'
                new_instr += '\n    ldc %s' % i
                if repr(item)[0] == '"':
                    # NOTE: java ldc can't handle \x??, so replace it
                    op_str = '"%s"' % repr(item)[1:-1].replace('\\x', '\\\\x')
                else:
                    op_str = '"%s"' % repr(item)[1:-1].replace('"', '\\"').replace('\\x', '\\\\x')
                new_instr += '\n    ldc %s' % op_str
                new_instr += '\n    aastore'
            return new_instr
        elif self._name == 'stringlength':
            return 'invokevirtual java/lang/String.length()I'
        elif self._name == 'stringaload':
            return 'invokevirtual java/lang/String.charAt(I)C'
        elif self._name in ['new', 'new_lib']:
            return "new %s" % self.operands[0].to_jts()
        elif self._name in ['instanceof', 'instanceof_lib', 'instanceof_array']:
            return "instanceof %s" % self.operands[0].to_jts()
        elif self._name in ['instanceof_arrayobject', 'instanceof_arrayobject_lib',]:
            return "instanceof %s" % ('['*self.operands[1] + 'L' + self.operands[0].to_jts() + ';')
        elif self._name in ['checkcast', 'checkcast_lib', 'checkcast_array']:
            return "checkcast %s" % self.operands[0].to_jts()
        elif self._name in ['checkcast_arrayobject', 'checkcast_arrayobject_lib']:
            return "checkcast %s" % ('['*self.operands[1] + 'L' + self.operands[0].to_jts() + ';')
        elif self._name in ['checkcastbranch', 'checkcastbranch_lib', 'checkcastbranch_array']:
            offset = self.get_branch_locations()[0]
            # this dup might violate the max stack size...
            new_instr =        'dup'
            new_instr += '\n    instanceof %s' % self.operands[0].to_jts()
            new_instr += '\n    ifne loc_%d_ccb_true' % self.offset
            new_instr += '\n    pop'
            new_instr += '\n    goto loc_%d' % offset
            new_instr += '\nloc_%d_ccb_true:' % self.offset
            new_instr += '\n    checkcast %s' % self.operands[0].to_jts()
            return new_instr
        elif self._name == 'clinit_return':
            return 'return'
        elif self._name in ['clinit', 'clinit_lib']:
            return 'invokespecial %s/<clinit>()V' % self.operands[0].to_jts()
        elif self._name == 'halt':
            # halt is used in abstract methods, the proper way to declare an abstract method
            # is to leave the body empty of instructions, so a nop for halt is not appropriate
            return '; NO INSTRUCTION'
        else:
            raise Exception('Unexpected instruction encountered during Jasmin instruction conversion: %s' % str(self))
            #return 'nop    ; NOT IMPLEMENTED: %s' % istr

    def get_branch_locations(self):
        """ If this instruction branches return all possible locations.
        """
        if self._name in branches:
            # this instruction unconditionally branches to another instruction
            offset = self.operands[-1]
            return [offset,]
        elif self._name in conditional_branches:
            # this instruction can branch or fall through
            if self._name == 'checkcastbranch':
                offset = self.offset + self.operands[-1] + 2
                return [offset,]
            elif self._name == 'checkcastbranch_lib' or self._name == 'checkcastbranch_array':
                offset = self.offset + self.operands[-1] + 3
                return [offset,]
            elif self._name.startswith('if'):
                offset = self.operands[-1]
                return [offset,]
        elif self._name in compound_branches:
            # this instruction can branch to one or more locations
            if self._name == 'tableswitch':
                base_value = self.operands[-2]
                offsets = []
                for j, offset in enumerate(self.operands[-1]):
                    case_offset = self.offset + 7 + 2*j + offset
                    offsets.append(case_offset)
                return offsets
            elif self._name == 'lookupswitch':
                offsets = []
                for j, (case, offset) in enumerate(self.operands[-2]):
                    case_offset = self.offset + 7 + 6*j + offset
                    offsets.append(case_offset)

                # do additional default case field as well
                case_offset = self.offset + 3 + 6*self.operands[-3] + self.operands[-1]
                offsets.insert(0, case_offset)
                return offsets
            elif self._name == 'lookupswitch_short':
                offsets = []
                for j, (case, offset) in enumerate(self.operands[-2]):
                    case_offset = self.offset + 5 + 4*j + offset
                    offsets.append(case_offset)

                # do additional default case field as well
                case_offset = self.offset + 3 + 4*self.operands[-3] + self.operands[-1]
                offsets.insert(0, case_offset)
                return offsets
            else:
                raise(Exception('Unknown compound branch instruction %s' % str(self)))
        return []
            
from utils import UnresolvedClass, UnresolvedLocalField, UnresolvedName, UnresolvedStaticField

def disassembly(routine):
    R = routine.module._R
    C = Context.fromstring(routine.code)
    is_brittle = ('is_brittle' in routine.module.attrs)
    _code_start = routine.code_offset
    
    esc = 0
    while True:
        # Read next opcode
        try:
            if esc == 0:
                offset = C.tell()
            opcode = BYTE(C)
        except EOFError:
            return
        
        if opcode == _ESC_BYTE:
            esc = 256
            continue
        else:
            opcode, esc, fixups = opcode + esc, 0, None
            
            if opcode in _BRANCH_NEAR:
                ops = [_code_start + offset + (signed_char(C) + 1)]
                
            elif opcode in _BRANCH_FAR:
                ops = [_code_start + offset + (signed_short(C) + 1)]
                
            elif opcode in _BRANCH_UP:
                ops = [_code_start + offset + (-WORD(C) + 1)]
                
            elif opcode in _BRANCH_DOWN:
                ops = [_code_start + offset + (WORD(C) + 1)]
                
            elif opcode in _SINGLE_UBYTE_OP:
                ops = [BYTE(C)]
                
            elif opcode in _SINGLE_SBYTE_OP:
                ops = [signed_char(C)]
                
            elif opcode in _SINGLE_SWORD_OP:
                ops = [signed_short(C)]
                
            elif opcode in _SINGLE_UWORD_OP:
                ops = [WORD(C)]
                
            elif opcode in _SINGLE_INT_OP:
                ops = [int_(C)]
            
            elif opcode in _STRING_ARRAY_INIT_OP:
                num_lits = WORD(C)
                ops = [[R.get_lit(off, needs_header=True) for off in array_f(WORD, num_lits)(C)],]
            
            elif opcode in _ARRAY_INIT_OP:
                tc = BYTE(C)
                length = WORD(C)
                blob = R.get_blob(WORD(C), length)
                size = _ARRAY_SIZES[tc]
                assert len(blob) % size == 0
                unpack_code = _ARRAY_UNPACK_CODES[tc]
                unpack_string = '<' + unpack_code * (len(blob)/size)
                inits = list(unpack(unpack_string, blob))
                ops = [_ARRAY_TYPES[tc], inits]
            
            elif opcode in _CONSTRAINTS_OP:
                ops = array_f(BYTE, 3)(C)
            
            elif opcode in _LOOKUPSWITCH_OP:
                range_getter = signed_short if (opcode in _LOOKUPSWITCH_EXTRA) else signed_int
                num_lookups = WORD(C)
                lookups = []
                for i in xrange(num_lookups):
                    lookups.append((range_getter(C), signed_short(C)))
                default = signed_short(C)
                ops = [num_lookups, lookups, default]
            
            elif opcode in _TABLESWITCH_OP:
                num_targets = WORD(C)
                default = signed_int(C)
                targets = array_f(signed_short, num_targets)(C)
                ops = [num_targets, default, targets]
            
            elif opcode in _TWO_BYTE_OP:
                ops = [BYTE(C), signed_char(C)]
            
            elif opcode in _TWO_WORD_OP:
                ops = [WORD(C), signed_short(C)]
            
            elif opcode in _SINGLE_SLONG_OP:
                ops = [signed_long_long(C)]
            
            elif opcode in _CLASS_FIELDREF_OP:
                fixups = [C.tell() + _code_start]
                mod_byte = BYTE(C) if (opcode in _CLASS_FIELDREF_EXTRA) else 0
                class_byte = BYTE(C)
                field_address = WORD(C)
                ops = [UnresolvedClass((mod_byte, class_byte)), field_address]
            
            elif opcode in _REL_FIELDREF_OP:
                fixups = [C.tell() + _code_start]
                field_offset = BYTE(C) if is_brittle else signed_char(C)
                ops = [field_offset]
            
            elif opcode in _REL_FAR_FIELDREF_OP:
                fixups = [C.tell() + _code_start]
                field_offset = BYTE(C) if is_brittle else (signed_char(C) + 256)
                ops = [field_offset]
            
            elif opcode in _INVOKESTATIC_OP:
                fixups = [C.tell() + _code_start]
                mod_byte = BYTE(C) if (opcode in _INVOKESTATIC_EXTRA) else 0
                class_byte = BYTE(C)
                method_index = WORD(C)
                ops = [(mod_byte, class_byte, method_index)]
            
            elif opcode in _INVOKENATIVE_OP:
                ops = [BYTE(C), WORD(C)]
            
            elif opcode in _JUMPSPECIAL_OP:
                fixups = [C.tell() + _code_start]
                mod_byte = BYTE(C) if (opcode in _JUMPSPECIAL_EXTRA) else 0
                method_word = WORD(C)
                ops = [(mod_byte, method_word)]
            
            elif opcode in _INVOKESPECIAL_OP:
                fixups = [C.tell() + _code_start, None]
                mod_byte = BYTE(C) if (opcode in _INVOKESPECIAL_EXTRA) else 0
                method_word = WORD(C)
                local_count = BYTE(C)
                ops = [(mod_byte, method_word), local_count]
            
            elif opcode in _INVOKEVIRTUAL_OP:
                fixups = [C.tell() + _code_start, 0]
                method_addr = signed_short(C)
                local_count = BYTE(C)
                ops = [method_addr, local_count]
            
            elif opcode in _INVOKEVIRTUAL_SHORT_OP:
                bits = BYTE(C)
                short_voffset = bits >> 2
                local_count = (bits & 3) + 1
                ops = [short_voffset, local_count]
            
            elif opcode in _INVOKEINTERFACE_OP:
                ops = [WORD(C), BYTE(C), WORD(C)]
            
            elif opcode in _LDC_OP:
                is_unicode = (opcode in _LDC_EXTRA)
                _unused = WORD(C) if is_unicode else 0
                ops = [R.get_lit(WORD(C), is_unicode=is_unicode, needs_header=True)]
            
            elif opcode in _CLASSREF_OP:
                fixups = [C.tell() + _code_start]
                mod_byte = BYTE(C) if (opcode in _CLASSREF_EXTRA) else 0
                class_byte = BYTE(C)
                ops = [UnresolvedClass((mod_byte, class_byte))]
            
            elif opcode in _CLASSREF_CHECK_OP:
                fixups = [C.tell() + _code_start, None]
                mod_byte = BYTE(C) if (opcode in _CLASSREF_CHECK_EXTRA) else 0
                class_byte = BYTE(C)
                dims_byte = BYTE(C)
                ops = [UnresolvedClass((mod_byte, class_byte)), dims_byte]
            
            elif opcode in _NEWARRAY_OP:
                ops = [_ARRAY_TYPES[BYTE(C)],]

            elif opcode in _MULTINEWARRAY_OP:
                ops = [BYTE(C), BYTE(C), _ARRAY_TYPES[BYTE(C)]]
            
            elif opcode in _MULTINEWARRAY_OBJ_OP:
                fixups = [C.tell() + _code_start]
                mod_byte = BYTE(C) if (opcode in _MULTINEWARRAY_OBJ_EXTRA) else 0
                class_byte = BYTE(C)
                ops = [UnresolvedClass((mod_byte, class_byte)), BYTE(C), BYTE(C)]
            
            elif opcode in _CHECKCASTBRANCH_OP:
                fixups = [C.tell() + _code_start]
                mod_byte = BYTE(C) if (opcode in _CHECKCASTBRANCH_EXTRA) else 0
                ops = [(mod_byte, BYTE(C)), signed_short(C)]
            
            elif opcode in _TYPECHECK_ARRAY_OP:
                dims, tc = BYTE(C), BYTE(C)
                tt = TypeToken(None)
                tt._object = False
                tt._array = True
                tt.code = tc
                tt.type = Primitive(TypeToken.TYPE_NAME[tc])
                tt.dims = dims
                
                if opcode in _TYPECHECK_ARRAY_OP_EXTRA:
                    ops = [tt, signed_short(C)]
                else:
                    ops = [tt]

            elif opcode in _BAD_OPS:
                raise BadOpcodeError("0x%02x @ 0x%04x" % (opcode, offset))
            
            else:
                # No operands
                ops = []
            
            yield Instruction(offset + _code_start, opcode, ops, fixups)
