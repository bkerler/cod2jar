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
instruction_reference: RIM JVM instruction set reference material.
"""

# threaddeath?
terminals = [
    'ireturn_bipush', 'ireturn_sipush', 'ireturn_iipush', 'ireturn',
    'ireturn_field', 'ireturn_field_wide', 'areturn', 'areturn_field',
    'areturn_field_wide', 'lreturn', 'return', 'clinit_return',
    'noenter_return', 'jumpspecial', 'jumpspecial_lib', 'halt',
    'putfield_return',
]

branches = [
    'goto', 'goto_w', 'jmpback', 'jmpforward',
]

conditional_branches = [
    'if_icmpeq', 'if_acmpeq', 'ifeq', 'if_icmpne', 'if_acmpne',
    'ifne', 'if_icmpgt', 'ifgt', 'if_icmpge', 'ifge', 'if_icmplt', 'iflt',
    'if_icmple', 'ifle', 'ifnull', 'ifnonnull',
    'checkcastbranch', 'checkcastbranch_lib', 'checkcastbranch_array',
]

compound_branches = [
    'tableswitch', 'lookupswitch_short', 'lookupswitch',
]

throwers = [
    'athrow',
]

potential_throwers = [
    'invokevirtual', 'invokeinterface', 'invokenonvirtual',
    'invokenonvirtual_lib', 'invokespecial', 'invokespecial_lib',
    'invokestatic', 'invokestatic_lib', 'iinvokenative', 'invokenative',
    'linvokenative', 'invokestaticqc', 'invokestaticqc_lib',
    'invokevirtual_short',
]

# these instructions only throw specific exceptions
restricted_throwers = {
    'monitorenter': ['java/lang/NullPointerException', 'java/lang/IllegalMonitorStateException', 'java/lang/Exception',],
    'monitorexit': ['java/lang/NullPointerException', 'java/lang/IllegalMonitorStateException',],
    
    'baload': ['java/lang/ArrayIndexOutOfBoundsException', 'java/lang/IndexOutOfBoundsException', 'java/lang/Exception',],
    'saload': ['java/lang/ArrayIndexOutOfBoundsException', 'java/lang/IndexOutOfBoundsException', 'java/lang/Exception',],
    'caload': ['java/lang/ArrayIndexOutOfBoundsException', 'java/lang/IndexOutOfBoundsException', 'java/lang/Exception',],
    'iaload': ['java/lang/ArrayIndexOutOfBoundsException', 'java/lang/IndexOutOfBoundsException', 'java/lang/Exception',],
    'aaload': ['java/lang/ArrayIndexOutOfBoundsException', 'java/lang/IndexOutOfBoundsException', 'java/lang/Exception',],
    'laload': ['java/lang/ArrayIndexOutOfBoundsException', 'java/lang/IndexOutOfBoundsException', 'java/lang/Exception',],
    'bastore': ['java/lang/ArrayIndexOutOfBoundsException', 'java/lang/IndexOutOfBoundsException', 'java/lang/Exception',],
    'castore': ['java/lang/ArrayIndexOutOfBoundsException', 'java/lang/IndexOutOfBoundsException', 'java/lang/Exception',],
    'sastore': ['java/lang/ArrayIndexOutOfBoundsException', 'java/lang/IndexOutOfBoundsException', 'java/lang/Exception',],
    'iastore': ['java/lang/ArrayIndexOutOfBoundsException', 'java/lang/IndexOutOfBoundsException', 'java/lang/Exception',],
    'aastore': ['java/lang/ArrayIndexOutOfBoundsException', 'java/lang/IndexOutOfBoundsException', 'java/lang/Exception',],
    'lastore': ['java/lang/ArrayIndexOutOfBoundsException', 'java/lang/IndexOutOfBoundsException', 'java/lang/Exception',],
    'stringaload': ['java/lang/StringIndexOutOfBoundsException', 'java/lang/ArrayIndexOutOfBoundsException', 'java/lang/IndexOutOfBoundsException', 'java/lang/Exception',],
    
    'checkcast': ['java/lang/ClassCastException', 'java/lang/Exception',],
    'checkcast_lib': ['java/lang/ClassCastException', 'java/lang/Exception',],
    'checkcast_arrayobject': ['java/lang/ClassCastException', 'java/lang/Exception',],
    'checkcast_arrayobject_lib': ['java/lang/ClassCastException', 'java/lang/Exception',],

    'ireturn_field': ['java/lang/NullPointerException', 'java/lang/Exception',],
    'ireturn_field_wide': ['java/lang/NullPointerException', 'java/lang/Exception',],
    'areturn_field': ['java/lang/NullPointerException', 'java/lang/Exception',],
    'areturn_field_wide': ['java/lang/NullPointerException', 'java/lang/Exception',],
    
    'putfield_return': ['net.rim.device.api.system.ObjectGroupReadOnlyException', 'java/lang/NullPointerException', 'java/lang/Exception',],
    'putfield_return_wide': ['net.rim.device.api.system.ObjectGroupReadOnlyException', 'java/lang/NullPointerException', 'java/lang/Exception',],
    'putfield': ['net.rim.device.api.system.ObjectGroupReadOnlyException', 'java/lang/NullPointerException', 'java/lang/Exception',],
    'putfield_wide': ['net.rim.device.api.system.ObjectGroupReadOnlyException', 'java/lang/NullPointerException', 'java/lang/Exception',],
    'lputfield': ['net.rim.device.api.system.ObjectGroupReadOnlyException', 'java/lang/NullPointerException', 'java/lang/Exception',],
    'lputfield_wide': ['net.rim.device.api.system.ObjectGroupReadOnlyException', 'java/lang/NullPointerException', 'java/lang/Exception',],
    'getfield': ['java/lang/NullPointerException', 'java/lang/Exception',],
    'getfield_wide': ['java/lang/NullPointerException', 'java/lang/Exception',],
    'lgetfield': ['java/lang/NullPointerException', 'java/lang/Exception',],
    'lgetfield_wide': ['java/lang/NullPointerException', 'java/lang/Exception',],
    'aload_0_getfield': ['java/lang/NullPointerException', 'java/lang/Exception',],
    'aload_0_getfield_wide': ['java/lang/NullPointerException', 'java/lang/Exception',],

    'new': ['java/lang/OutOfMemoryError',],
    'new_lib': ['java/lang/OutOfMemoryError',],
    'newarray': ['java/lang/OutOfMemoryError',],
    'newarray_object': ['java/lang/OutOfMemoryError',],
    'newarray_object_lib': ['java/lang/OutOfMemoryError',],
}

