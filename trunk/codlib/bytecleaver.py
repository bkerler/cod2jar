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
Bytecleaver: A semi-declarative binary structure parser for Python.
"""

import struct as _struct

# Assorted constants and utilities
############################################################

EOF = EOFError
ASRT = AssertionError

NATIVE_ENDIAN = '='
BIG_ENDIAN = '>'
NET_ENDIAN = '!'
LITTLE_ENDIAN = '<'

def _gg(fmt):
    '''Given a format string, create a getter function for use with a Context.'''
    size = _struct.calcsize(fmt)
    def _getter(C, **kw):
        return _struct.unpack(C.end + fmt, C.read(size))[0]
    return _getter

def xEND(getter, x_endian):
    def _getter(C, **kw):
        end = C.set_end(x_endian)
        data = getter(C, **kw)
        C.set_end(end)
        return data
    return _getter

def LEND(getter):
    return xEND(getter, LITTLE_ENDIAN)

def BEND(getter):
    return xEND(getter, BIG_ENDIAN)

# Primitive type getters
############################################################
char = _gg('c')
signed_char = _gg('b')
unsigned_char = _gg('B')
BYTE = unsigned_char

short = _gg('h')
signed_short = short
unsigned_short = _gg('H')
WORD = unsigned_short

int_ = _gg('i')
signed_int = int_
unsigned_int = _gg('I')
size_t = unsigned_int
DWORD = unsigned_int

long_ = _gg('l')
signed_long = long_
unsigned_long = _gg('L')

long_long = _gg('q')
signed_long_long = long_long
unsigned_long_long = _gg('Q')
QWORD = unsigned_long_long

float_ = _gg('f')
double = _gg('d')

# Array helpers
############################################################
def array_f(getter, count):
    '''Return a fixed-length array getter.

        New getter will read <count> elements of type <getter>.
    '''
    def _get_array_f(C, **kw):
        start = C.tell()
        data = [getter(C, **kw) for i in xrange(count)]
        C._last_read = start
        return data
    return _get_array_f

def array_b(getter, ending_offset):
    '''Return a new bounded-array getter.

        New getter will read elements of type <getter> until
    the context pointer >= <ending_offset>.
    '''
    def _get_array_b(C, **kw):
        start = C.tell()
        _check_point = C.tell()
        data = [getter(C, **kw)]
        while C.tell() < ending_offset:
            _check_point = C.tell()
            data.append(getter(C, **kw))
        if C.tell() > ending_offset:
            data.pop(-1)
            C.seek(_check_point)
        C._last_read = start
        return data
    return _get_array_b

def array_t(getter, terminator):
    '''Return a new terminated-array getter.

        New getter will read elements of type <getter> until
    reading a value == <terminator>.    The terminator is NOT
    returned, but the context file pointer is not rewound to
    point at the terminator again.
    '''
    def _get_array_t(C, **kw):
        start = C.tell()
        data = [getter(C, **kw)]
        while data[-1] != terminator:
            data.append(getter(C, **kw))
        data.pop(-1)
        C._last_read = start
        return data
    return _get_array_t

def array_x(getter, *errors):
    '''Return a new exception-bounded array getter.

        New getter will read <getter>'s until an exception type listed
    in <errors> is thrown; the context pointer will be rewound to the
    point preceding the error that resulted in the error, and the items
    read (up to the point of the error) will be returned.
    '''
    errors = tuple(errors)
    def _get_array_x(C, **kw):
        start = C.tell()
        data = []
        while True:
            _checkpoint = C.tell()
            try:
                data.append(getter(C, **kw))
            except errors, e:
                C.seek(_checkpoint)
                break
        C._last_read = start
        return data
    return _get_array_x

# String helpers
############################################################
def string_f(length):
    '''Return a fixed-length ASCII string getter.'''
    def _get_string_f(C, **kw):
        return C.read(length)
    return _get_string_f

def string_b(ending_offset):
    '''Return an offset-bounded ASCII string getter.'''
    def _get_string_b(C, **kw):
        assert ending_offset >= C.tell(), "Cannot read negative-length string_b!"
        return C.read(ending_offset - C.tell())
    return _get_string_b

def string_t(terminator='\0'):
    '''Return a [probably-NUL-] value-terminated ASCII string getter.'''
    def _get_string_t(C, **kw):
        return ''.join(array_t(char, terminator)(C))
    return _get_string_t

def string_x(*errors):
    '''Return an error-terminated ASCII string getter.'''
    def _get_string_x(C, **kw):
        return ''.join(array_x(char, *errors)(C))
    return _get_string_x


# Structure helpers
############################################################
class Struct(object):
    def __init__(self, C, **kw):
        self._field_order = []
        self._C = C
        self._kw = kw
        self._start = C.tell()
        self.load(C, **kw)
        self._end = C.tell()

    def __len__(self):
        return self._end - self._start

    def __iter__(self):
        return iter(self._field_order)

    def add_context(self, **kw):
        '''Add some key-value pairs to context for each subsequent read.'''
        self._kw.update(kw)

    def field(self, name, getter):
        '''Use <getter> to populate and save an ordered field <name>.'''
        self._field_order.append(name)
        setattr(self, name, getter(self._C, **self._kw))

    def field_value(self, name, value):
        '''For adding an ordered-field with a predetermined value.'''
        self._field_order.append(name)
        setattr(self, name, value)

    def F(self, name, getter):
        '''Quick alias for self.field().'''
        self.field(name, getter)

    def FV(self, name, value):
        '''Quick alias for self.field_value().'''
        self.field_value(name, value)

    def fields(self, name_type_pairs):
        '''Apply a list of (name, getter) pairs to self.field().'''
        for name, getter in name_type_pairs:
            self.field(name, getter)

    def load(self, C, **kw):
        '''Do loading logic in subclasses.'''
        raise NotImplementedError("Please implement in a subclass.")

    def __str__(self):
        return '%s{ ' % self.__class__.__name__ + '; '.join("%s: %r" % (k, getattr(self, k)) for k in self._field_order) + ' }'

    def __repr__(self):
        return str(self)

class StaticStruct(Struct):
    # Define fields as class variables in subclasses like this:
    # FIELDS = [
    #     (name1, type1),
    #     (name2, type2),
    #     ...
    # ]
    # (Provide a "verify(self, **kw)" method to do any post-load
    # processing required...)
    def load(self, C, **kw):
        # Load the statically-defined fields
        self.fields(self.FIELDS)

        # If the user provided the subclass with a "verify()" method, call it
        try:
            self.verify(**kw)
        except AttributeError:
            pass

def SS(struct_name, name_type_pairs):
    '''Utility StaticStruct generator function.'''
    class _StaticStructType(StaticStruct):
        FIELDS = name_type_pairs
    _StaticStructType.__name__ = struct_name
    return _StaticStructType

# Central context & I/O class
############################################################
class Context(object):
    '''File and repetition operations for an ongoing bytecleaver operation.'''
    def __init__(self, input_file, endian="="):
        '''Initialize context using input file (stored as "self.f").'''
        self.f = input_file
        self.end = endian
        self._marks = []
        self.data = None
        self.filename = None
        if 'name' in dir(input_file):
                self.filename = self.f.name
        else:
                saved_loc = self.f.tell()
                self.data = self.f.read()
                self.f.seek(saved_loc)

    @staticmethod
    def fromstring(data, endian="="):
        import StringIO
        return Context(StringIO.StringIO(data), endian)

    @staticmethod
    def fromfile(filename, endian="="):
        return Context(file(filename, 'rb'), endian)

    def get_range(self, start, end):
        size = end - start
        data = None
        if self.data:
            data = self.data[start:end]
        elif self.filename:
            if self.f.closed:
                f = file(self.filename, 'rb')
                f.seek(start)
                data = f.read(size)
                f.close()
            else:
                saved_loc = self.f.tell()
                self.f.seek(start)
                data = self.f.read(size)
                self.f.seek(saved_loc)
        return data

    def get_cstr(self, start):
        data = None
        if self.data:
            data = self.data[start:
                             start + self.data[start:].index('\x00')]
        elif self.filename:
            if self.f.closed:
                f = file(self.filename, 'rb')
                f.seek(start)
                data = ''
                c = f.read(1)
                while c not in ('\x00', ''):
                        data += c
                        c = f.read(1)
                f.close()
            else:
                saved_loc = self.f.tell()
                self.f.seek(start)
                data = ''
                c = self.f.read(1)
                while c not in ('\x00', ''):
                        data += c
                        c = self.f.read(1)
                self.f.seek(saved_loc)
        return data

    def reopen(self, start=0):
        if self.filename:
            if self.f.closed:
                f = file(self.filename, 'rb')
                f.seek(start)

    def close(self):
        if self.filename:
            self.f.close()

    def set_end(self, endian):
        '''Set new endianness; return old endianness.'''
        x, self.end = self.end, endian
        return x

    def mark(self):
        self._marks.append(self.tell())
        return self

    def unmark(self):
        self._marks.pop()
        return self

    def revert(self):
        self.seek(self._marks.pop())
        return self

    def seek(self, index):
        '''Chainable wrapper for self.f.seek().'''
        self.f.seek(index)
        return self

    def skip(self, span):
        '''Move forward (or back) x bytes; chainable.'''
        self.f.seek(self.f.tell() + span)
        return self

    def tell(self):
        '''Wrapper for self.f.tell().'''
        return self.f.tell()

    def align(self, byte_alignment):
        '''Align the file pointer for the next read; return self.'''
        pos = self.tell()
        diff = pos % byte_alignment
        if diff != 0:
            self.seek(pos + (byte_alignment - diff))
        return self

    def slack(self, byte_alignment):
        '''Return the bytes between self.tell() and the next aligned offset.

        If we are already aligned, returns ''.
        '''
        pos = self.tell()
        diff = pos % byte_alignment
        if diff:
            slack = self.read(byte_alignment - diff)
            self.seek(pos)
        else:
            slack = ''
        return slack

    def is_aligned(self, byte_alignment):
        '''Return True if (self.tell() % byte_alignment) == 0.'''
        return (self.tell() % byte_alignment == 0)

    def read(self, bytes=None):
        '''Wrapper around self.f.read(); raises EOFError on EOF.'''
        self._last_read = self.tell()
        data = self.f.read(bytes)
        if bytes and (len(data) != bytes):
            raise EOFError()
        return data
