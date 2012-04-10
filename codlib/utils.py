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
utils: Constants and utility functions for CODng.
"""

from struct import unpack
from bytecleaver import *

# Quick, limited parsers
#----------------------------------------------------------
def quick_get_module_names(cod_path):
    '''Quickly parse out the module name and aliases from a COD.'''
    def _get_lit(f, offset):
        f.seek(offset)
        data = ''
        c = f.read(1)
        while c != '\x00' and c != '':
            data += c
            c = f.read(1)
        return data
    
    f = open(cod_path, 'rb')
    # read data section offset
    f.seek(38)
    # header size + code size
    ds_offset = 44 + unpack('H', f.read(2))[0]
    # read info from the data header
    f.seek(ds_offset + 4)
    num_mods = unpack('B', f.read(1))[0]
    num_classes = unpack('B', f.read(1))[0]
    f.seek(ds_offset + 6)
    exports_offset = unpack('H', f.read(2))[0]
    f.seek(ds_offset + 28)
    aliases_offset = unpack('H', f.read(2))[0]
    # data section offset + data header size + class offsets size
    f.seek(ds_offset + 52 + 2*num_classes)
    mod_offset = unpack('H', f.read(2))[0]
    # data section offset + aliases offset
    f.seek(ds_offset + aliases_offset)
    num_aliases = (exports_offset - aliases_offset) / 2
    aliases_offsets = []
    for i in range(num_aliases):
        aliases_offsets.append(unpack('H', f.read(2))[0])
    
    # finally, retrieve the names
    names = [_get_lit(f, ds_offset + mod_offset)]
    for each in aliases_offsets:
        names.append(_get_lit(f, ds_offset + each))
    return names

# Utility loading code
#----------------------------------------------------------
def load_cod_file(cod_name, search_path=[]):
    '''Load a COD file by name.

    If the cod_name does not end with ".cod", the extension is
    added.  Tries a direct open, then falls back to the search
    path.
    '''
    from format import CodFile
    import os.path

    if not cod_name.endswith(".cod"):
        cod_name = cod_name + ".cod"

    try:
        C = Context.fromfile(cod_name)
    except IOError:
        for p in search_path:
            try:
                C = Context.fromfile(os.path.join(p, cod_name))
                break
            except IOError:
                pass
        else:
            raise IOError("Could not find '%s' anywhere!" % cod_name)

    cf = CodFile(C)
    C.close()
    return cf

def load_cod_raw(cod_data):
    '''Load a COD file by raw data.
    '''
    from format import CodFile

    C = Context.fromstring(cod_data)
    cf = CodFile(C)
    C.close()
    return cf

# Data item header helpers and getters
#----------------------------------------------------------

def sizeof_data_type(array_type):
    if array_type in (3, 4):
        return 2
    elif array_type == 5:
        return 4
    elif array_type == 6:
        return 8
    else:
        return 1

def parse_data_header(C):
    header = unsigned_int(C)
    data_type, data_length = (header & 0x1E0000) >> 17, (header & 0x1FFFF)
    return (data_type, data_length * sizeof_data_type(data_type))

def unescape(s):
    '''Unescaped a '$' escaped string.'''
    us = ''
    skip = 0
    for i, c in enumerate(s):
        if skip:
            skip -= 1
            continue
        if c == '$':
            if s[i+1] == '$':
                us += '$'
                skip = 1
            else:
                us += chr(int(s[i+1:i+3], 16))
                skip = 2
        else:
            us += c
    return us

def Identifier(C, **kw):
    '''Get a packed, NUL-terminated Identifier string.'''
    from bytecleaver import array_t, BYTE
    return decode_identifier(array_t(BYTE, 0)(C, **kw))

def Literal(C, is_unicode=False, needs_header=False, explicit_length=None, **kw):
    '''Read a string literal (ASCII/Unicode, with/without header).'''
    from bytecleaver import array_t, array_f, WORD, BYTE
    # Figure out our element type/size and length (if any)
    length = explicit_length

    if needs_header:
        C.skip(-4)
        data_type, byte_length = parse_data_header(C)
        is_unicode = (sizeof_data_type(data_type) == 2)
        length = byte_length / sizeof_data_type(data_type)

    # Read the raw data accordingly
    element = WORD if is_unicode else BYTE
    data = array_f(element, length)(C, **kw) if (length is not None) else array_t(element, 0)(C, **kw)

    # Convert to a string
    return (u''.join(map(unichr, data))) if is_unicode else (''.join(map(chr, data)))

def EscapedLiteral(C, is_unicode=False, needs_header=False, explicit_length=None, **kw):
    '''Read a string literal (ASCII/Unicode, with/without header).'''
    from bytecleaver import array_t, array_f, WORD, BYTE
    # Figure out our element type/size and length (if any)
    length = explicit_length

    if needs_header:
        C.skip(-4)
        data_type, byte_length = parse_data_header(C)
        is_unicode = (sizeof_data_type(data_type) == 2)
        length = byte_length / sizeof_data_type(data_type)

    # Read the raw data accordingly
    element = WORD if is_unicode else BYTE
    data = array_f(element, length)(C, **kw) if (length is not None) else array_t(element, 0)(C, **kw)

    # Convert to a string
    s = (u''.join(map(unichr, data))) if is_unicode else (''.join(map(chr, data)))

    # unescape '$' characters (ex: "a$2dr"=> "a-r")
    us = unescape(s)
    return us

# "Unresolved" type placeholders (used by resolve.py)
#----------------------------------------------------------
class UnresolvedClass(object):
    __slots__ = ['class_id', 'name']

    def __init__(self, class_id):
        self.class_id = class_id
        self.name = "class(%d:%d)" % class_id

    def get_class(self):
        raise TypeError("Cannot get the class of an unresolved type reference!")

    def __str__(self):
        return self.name

    def __repr__(self):
        return "<UR-class: '%s'>" % str(self)

class BadClassRef(UnresolvedClass):
    __slots__ = ['class_id', 'name']

    def __init__(self, class_id):
        self.class_id = class_id
        self.name = "ERROR(bad_class[%d:%d])" % class_id

class UnresolvedLocalField(object):
    __slots__ = ['index']

    def __init__(self, index):
        self.index = index

    def __str__(self):
        return str(self.index)

    def __repr__(self):
        return "<UR-local-field: '%s'>" % str(self)

class UnresolvedStaticField(object):
    __slots__ = ['address']

    def __init__(self, address):
        self.address = address

    def __str__(self):
        return str(self.address)

    def __repr__(self):
        return "<UR-static-field: '%s'>" % str(self)

class UnresolvedMethod(object):
    __slots__ = ['_class', '_method']
    def __init__(self, class_id, method_num):
        self._class = UnresolvedClass(class_id)
        self._method = method_num

    def __str__(self):
        return "%s.%s" % (self._class, self._method)

    def __repr__(self):
        return "<UR-method: '%s'>" % str(self)

class UnresolvedName(object):
    __slots__ = ['_class', '_name', '_type', '_is_field']
    def __init__(self, _class, _name, _type=None, _is_field=False):
        self._class = _class
        self._name = _name
        self._type = _type
        self._is_field = _is_field

    def __str__(self):
        if self._is_field:
            return "%s/%s" % (self._class, self._name)
        else:
            return "%s/%s(%s)" % (self._class, self._name, self._type if (self._type is not None) else '')

    def __repr__(self):
        return "<UR-name: '%s'>" % str(self)

# Packed-Identifier decoding code
#----------------------------------------------------------
def _BYTE_TUPLE(C, **kw):
    return (BYTE(C), BYTE(C))

class Primitive(object):
    __slots__ = ['name']

    # Chars for java type primitives
    TYPE_CHAR = {
        'boolean': 'Z',
        'byte': 'B',
        'char': 'C',
        'short': 'S',
        'int': 'I',
        'long': 'J',
        'void': 'V',
        'float': 'F',
        'double': 'D',
    }

    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name

    def __repr__(self):
        return "<prim: '%s'>" % str(self)

    def to_jts(self):
        '''See TypeToken.to_jts() for details.'''
        return self.TYPE_CHAR[self.name]

class TypeToken(object):
    '''A COD type reference object.'''
    __slots__ = ['code', 'type', '_array', '_object', 'dims', '_class_id']

    # Names for type codes
    TYPE_NAME = {
        0: "???",              # Wildcard type for heuristic instruction scanning
        1: "boolean",
        2: "byte",
        3: "char",
        4: "short",
        5: "int",
        6: "long",
        7: "class",
        8: "array",
        9: "class",
        10: "void",
        11: "float",
        12: "double",
        14: "java/lang/String", # Not a primitive type at all, but this is how RIM treats code 14
    }

    # Names/codes for JTS type characters
    JTS_TYPES = {
        '*': (None, 0),            # Wildcard type for heuristic instruction scanning
        'Z': ('boolean', 1),
        'B': ('byte', 2),
        'C': ('char', 3),
        'S': ('short', 4),
        'I': ('int', 5),
        'J': ('long', 6),
        'V': ('void', 10),
        'F': ('float', 11),
        'D': ('double', 12),
    }

    def __init__(self, C, **kw):
        if C is None: return

        # Back up to read our header byte
        C.skip(-1)
        hdr_byte = BYTE(C)

        # Get type code
        tc = hdr_byte & 0x0f
        self.code = tc
        try:
            self.type = Primitive(self.TYPE_NAME[tc])
        except KeyError:
            raise TypeError("bad_type_code[%d@0x%05x]" % (tc, C.tell()))
        self._array, self._object = False, False

        # Array logic
        if tc == 8:
            self._array = True
            self.dims, self.code = _BYTE_TUPLE(C)
            # Array of objects...
            if self.code == 7:
                self._object = True
                self._class_id = _BYTE_TUPLE(C)
                self.type = UnresolvedClass(self._class_id)
            else:
                try:
                    self.type = Primitive(self.TYPE_NAME[self.code])
                except KeyError:
                    raise TypeError("bad_array_type_code[%d@0x%05x]" % (self.code, C.tell() - 1))
        elif tc in (7, 9):
            self._object = True
            self._class_id = _BYTE_TUPLE(C)
            self.type = UnresolvedClass(self._class_id)
        elif tc == 14:
            # We'll use by-name resolution to look up the actual classdef at resolve() time
            self._class_id = self.type
            self._object = True

    def __str__(self):
        '''Convert to standard JVM type-string.

            E.g.:
                int[][] -> "[[I"
                java.lang.String -> "Ljava/lang/String;"
        '''
        if self.type is None:
            # A non-standard special case for stack-maps and other places where we can
            # have "wildcard" types in a list...
            base = '*'
        elif self._object:
            # We know how to handle class names
            try:
                base = "L%s;" % self.type.name
            except AttributeError:
                raise ValueError("Trying to JTS-ize an invalid type: %s (%s)" % (self.type, type(self.type)))
        else:
            # Must be a primitive
            base = self.type.to_jts()

        if self._array:
            return ('[' * self.dims) + base
        else:
            return base

    def __repr__(self):
        return "<tt: '%s'>" % str(self)

    def __cmp__(self, other):
        # gt implies more defined (ie bool > int)
        TYPE_CMP = {
            ('I', 'S'): -1,
            ('I', 'C'): -1,
            ('I', 'B'): -1,
            ('I', 'Z'): -1,
            ('S', 'I'): 1,
            ('C', 'I'): 1,
            ('B', 'I'): 1,
            ('Z', 'I'): 1,
        }

        sself = str(self)
        sother = str(other)

        if sself == sother:
            return 0
        if sself == '*' and sother != '*':
            return -1
        if sself != '*' and sother == '*':
            return 1

        if self._array and other._array:
            # they both are arrays
            if self.dims == other.dims:
                if self._object and other._object:
                    # gt implies more defined (ie String > Object)
                    # TODO: prioritize non-exceptions over exceptions?
                    return self.type.__cmp__(other.type)
                else:
                    self_base = self.type.to_jts()
                    other_base = self.type.to_jts()
                    if self._array and other._array:
                        if self.dims == other.dims:
                            if (self_base, other_base) in TYPE_CMP:
                                return TYPE_CMP(self_base, other_base)
                    elif not self._array and not other._array:
                        if (self_base, other_base) in TYPE_CMP:
                            return TYPE_CMP(self_base, other_base)
        elif not self._array and not other._array:
            # they both aren't arrays
            if self._object and other._object:
                # gt implies more defined (ie String > Object)
                # TODO: prioritize non-exceptions over exceptions?
                return self.type.__cmp__(other.type)
            else:
                self_base = self.type.to_jts()
                other_base = self.type.to_jts()
                if (self_base, other_base) in TYPE_CMP:
                    return TYPE_CMP(self_base, other_base)
        # otherwise these types are apples and oranges...
        raise ValueError('Type compare mismatch: %s and %s' % (sself, sother))

    def __eq__(self, other):
        return str(self) == str(other)    # Hacky/inefficient, but it works in all the corner cases...

    def __ne__(self, other):
        return str(self) != str(other)    # Hacky/inefficient, but it works in all the corner cases...

    def resolve(self, resolver):
        if self._object:
            self.type = resolver(self._class_id)

    def serialize(self):
        return self.to_jts()

    def slots(self):
        if self.code in (6, 12) and not self._array:
            return 2
        elif self.code == 10:     # "void", which should never actually exist in a real type list...
            return 0
        else:
            return 1

    def to_jts(self):
        return str(self)

    @staticmethod
    def from_jts(jts, loader):
        '''Parse a TypeToken from a Java Type String.'''
        assert isinstance(jts, basestring), "JTS must be string!"
        tt = TypeToken(None)

        # Parse array dimensions
        i = 0
        tt.dims = 0
        while jts[i] == '[':
            tt.dims += 1
            i += 1
        tt._array = (i > 0)

        # Parse type
        _tchar = jts[i]
        if _tchar == 'L':
            # Object type
            assert jts[-1] == ';', "JTS syntax error in '%s' (no trailing ';')" % jts
            tt.type = loader.ref_class(jts[i+1:-1])
            tt.code = 7
            tt._object = True
        elif _tchar == '*':
            # Wildcard/unknown type
            tt.type = None
            tt.code = 0
            tt._object = False
        else:
            # Primitive type
            try:
                _tname, tt.code = TypeToken.JTS_TYPES[_tchar]
                tt.type = Primitive(_tname)
                tt._object = False
            except KeyError:
                raise AssertionError("JTS syntax error (unknown type '%s') in '%s'" % (_tchar, jts))

        return tt

    def clone(self):
        tt = TypeToken(None)
        tt.code = self.code
        tt.type = self.type
        tt._object = self._object
        tt._array = self._array
        if self._array:
            tt.dims = self.dims
        return tt

class TypeList(list):
    def __init__(self, C, **kw):
        if C is None: return

        _start = C.tell()

        # Read list header
        len_hdr = BYTE(C)

        # Figure out (based on bit settings) how long the list is
        if len_hdr & 0x80:
            length = len_hdr & 0x7f
            len_hdr = BYTE(C)
            if length & 0x40:
                length &= 0xbf    # Mask out 0x40
                length <<= 4
                length += (len_hdr & 0xf0) >> 4     # Add in next nybble
            length -= 1
        else:
            length = (len_hdr & 0x70) >> 4

        if length > 0:
            length -= 1
            end = C.tell() + length

            try:
                self.append(TypeToken(C))

                while C.tell() < end:
                    rle_hdr = BYTE(C)
                    item = TypeToken(C)
                    self += [item] * ((rle_hdr >> 4) + 1)
            except Exception as ex:
                raise TypeError("bad_type_list[0x%05x:0x%05x; '%s']" % (_start, end, ex))

    def __str__(self):
        return ''.join(tt.to_jts() if (tt is not None) else '*' for tt in self)

    def resolve(self, resolver):
        for token in self:
            assert isinstance(token, TypeToken), "TypeList elements must be TypeTokens!"
            token.resolve(resolver)

    def serialize(self):
        return self.to_jts()

    def slots(self):
        return sum(t.slots() for t in self)

    def to_jts(self, skip_first=False):
        if skip_first:
            return ''.join(tt.to_jts() if (tt is not None) else '*' for tt in self[1:])
        else:
            return str(self)

    def is_super_or_implements_or_equivalent(self, other):
        '''Returns True if every item in other TypeList is super, implements, or equivalent to every item in this TypeList'''
        if len(self) != len(other):
            return False
        for i in range(len(self)):
            try:
                    if self[i] < other[i]:
                        # self is super or equivalent to other
                        return False
            except ValueError:
                # total type mismatch (like comparing bool to java/lang/String)
                return False
        return True

    @staticmethod
    def from_jts(jts, loader):
        '''Parse a concatenated list of JTS-formatted TypeTokens; return a TypeList.'''
        jts_list = TypeList.split_jts(jts)
        tl = TypeList(None)
        for x in jts_list:
            tl.append(TypeToken.from_jts(x, loader))
        return tl

    @staticmethod
    def split_jts(jts):
        '''Parse a concatenated list of JTS-formatted TypeTokens; return a list of JTS strings.'''
        _primitives = TypeToken.JTS_TYPES
        i, imax = 0, len(jts)

        jts_list = []
        mark = 0
        while i < imax:
            c = jts[i]
            if c == 'L':
                # Starting a class-type token--continue until we hit ';' (or EOS--which is an error)
                i += 1
                while i < imax:
                    c = jts[i]
                    i += 1
                    if c == ';': break
                else:
                    raise AssertionError("JTS syntax error in '%s'; no terminator for class name!" % jts)
                jts_list.append(jts[mark:i])
                mark = i
            elif c in _primitives:
                i += 1
                jts_list.append(jts[mark:i])
                mark = i
            elif c == '[':
                i += 1
            else:
                raise AssertionError("JTS syntax error in '%s'; unexpected character '%s'!" % (jts, c))
        return jts_list

class BadType(TypeList):
    def __init__(self, msg):
        self.msg = msg

    def resolve(self, resolver):
        pass

    def __str__(self):
        return "ERROR(bad_type[%s])" % self.msg

    def __repr__(self):
        return "<bad-type: '%s'>" % str(self)

# Packed-Identifier decoding code
#----------------------------------------------------------

DECODE_TABLE = [
    "", "in", "et", "it", "init", "init>", "de", "ce", "get", "cl",
    "<init>", "er", "re", "<cl", "<clinit>", "im", "on", "at", "vi", "en",
    "vice", "rim", "net", "device", "ap", "or", "api", "st", "ion", "pt",
    "set", "al", "ro", "an", "ec", "ed", "$", "ad", "St", "th",
    "In", "ss", "ert", "Pro", "am", "ry", ".", "ord", "0", "1",
    "2", "3", "4", "5", "6", "7", "8", "9", "ata", "em",
    "<", "rypt", ">", "ut", "ar", "A", "B", "C", "D", "E",
    "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
    "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y",
    "Z", "co", "pert", "ic", "crypt", "_", "us", "a", "b", "c",
    "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
    "n", "o", "p", "q", "r", "s", "t", "u", "v", "w",
    "x", "y", "z", "Propert", "Property", "ey", "le", "Data", "va", "se",
    "ate", "ava", "ing", "Rec", "Val", "java", "ption", "oc", "ent", "el",
    "ang", "io", "id", "um", "rit", "crypto", "yst", "ystem", "Ex", "Record",
    "ch", "Exce", "Exception", "read", "is", "gth", "ort", "ength", "ist", "int",
    "Re", "Key", "un", "mp", "writ", "write", "Co", "la", "By", "Length",
    "ui", "gr", "ress", "ac", "ur", "gram", "to", "ig", "Fi", "add",
    "ex", "dex", "Datagram", "PropertyVal", "Ch", "iv", "Index", "ring", "ont", "od",
    "eld", "Field", "String", "ase", "ation", "ect", "ll", "Of", "ocus", "ag",
    "List", "end", "Ad", "cld", "cldc", "lic", "ra", "up", "comp", "rec",
    "ran", "record", "Focus", "ow", "rans", "ext", "te", "ew", "getP", "il",
    "ener", "umb", "op", "iz", "getM", "lang", "system", "System", "base", "age",
    "der", "ip", "No", "He", "key", "Listener", "ize", "ub", "thumb", "Up",
    "Stre", "Id", "pa", "Stream", "open", "ess", "Stat", "out", "ange", "send",
    "port", "idth", "essage", "ition", "ime", "\377"
]

def decode_identifier(ident):
    buff = []
    if isinstance(ident, str):
        ident = [ord(x) for x in ident]
    idx, end = 0, len(ident)
    while idx < end:
        byte = ident[idx]
        if byte == 0xFF:
            buff.append(chr(ident[idx + 1]))
            idx += 1
        else:
            buff.append(DECODE_TABLE[byte])
        idx += 1
    return ''.join(buff)


# Random utilities
#----------------------------------------------------------

def parse_flags(flags, flag_map):
    '''Turn a bitmask into a self-mapping of strings.

        Given an integer and a dictionary mapping powers of 2 to names,
    returns a dictionary mapping strings whose corresponding bits are SET in
    the <flags> integer to themselves.
    '''
    return dict((v, v) for k, v in flag_map.iteritems() if (flags & k))

def format_flags(flags, order, glue=' '):
    '''Format a flag-value-mapping into the specified order.

        * <flags> should be a dictionary of the form output by
                parse_flags()
        * <order> should be a list of flag names in
                the order desired for output
        * <glue> (the optional keyword argument) specifies what string
                is used to join() all the collected flag names

        If <order> includes a name which is not in <flags>, we
    substitute the empty string for that flag in the output.
    '''
    return glue.join(filter(None, (flags.get(o) for o in order)))
