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
format: Raw file parsing types and code.
"""

from bytecleaver import *
import utils

# Constants
#----------------------------------------------------------
SUPPORTED_COD_VERSIONS = [78, 79]
SUPPORTED_DATA_VERSIONS = [5, 6]

# Custom bytecleaver getters and small file structure types
#----------------------------------------------------------
def CLASS_ID(C, **kw):
    '''Get a tuple of 2 bytes: (module_index, class_index).'''
    return (BYTE(C), BYTE(C))

def PUS(C):
    '''"Packed Unsigned Short" getter.

    Algorithm:
        * read bytes until (MSB == 0)
        * construct integer (endian-appropriate) with lower 7 bits of each
        * mask integer with 0xffff (return unsigned short)
    '''
    total, bits = 0, 0
    while True:
        byte = BYTE(C)
        # (Little endian--the only gender used in the COD format)
        total = ((byte & 0x7f) << bits) + total
        bits += 7

        # Terminal condition (MSB == 0)
        if byte & 0x80 == 0:
            break
    return total & 0xffff

def CodFixupOffsetVector(C):
    '''Getter for a vector of packed fixup offsets (unsigned shorts).'''
    size = PUS(C)
    end = C.tell() + size
    deltas = array_b(PUS, end)(C)
    offsets = []
    if deltas:
        offsets.append(deltas[0])
        for d in deltas[1:]:
            offsets.append(offsets[-1] + d)
    return offsets

class CodEntryPoint(StaticStruct):
    FIELDS = [('offset', WORD), ('name', WORD), ('param_types', WORD)]

class CodExportedData(StaticStruct):
    FIELDS = [('name', WORD), ('length', WORD), ('data_offset', WORD)]

class CodStaticData(StaticStruct):
    FIELDS = [('address', WORD), ('value', int_)]

class CodIfaceMethodRef(StaticStruct):
    FIELDS = [
        ('class_id', CLASS_ID), ('name', WORD),
        ('param_types', WORD), ('return_type', WORD)
    ]

class CodClassRef(StaticStruct):
    FIELDS = [
        ('mod_index', WORD), ('pack_name', WORD),
        ('class_name', WORD), ('extra', CLASS_ID),
    ]

class CodFieldDef(StaticStruct):
    FIELDS = [('name', WORD), ('type', WORD)]

class CodStaticFieldDef(StaticStruct):
    FIELDS = [('name', WORD), ('type', WORD), ('address', WORD)]


class FxpMemberRef(StaticStruct):
    FIELDS = [('class_ref', WORD), ('name', WORD), ('type', WORD)]

class FxpLongMemberRef(StaticStruct):
    FIELDS = [
        ('class_ref', WORD), ('name', WORD),
        ('param_types', WORD), ('return_type', WORD),
    ]

class FxpLocalMemberRef(StaticStruct):
    FIELDS = [('class_index', BYTE), ('field_index', BYTE)]

def xFixupList(count_type, ref_type, align=1, explicit=False):
    def _fixup_getter(C, **kw):
        cnt = count_type(C, **kw)
        has_offsets = (explicit or (cnt < 0))
        fxps = []
        for i in xrange(abs(cnt)):
            C.align(align)
            member = ref_type(C, **kw)
            offsets = CodFixupOffsetVector(C) if has_offsets else None
            fxps.append((member, offsets))
        return fxps
    return _fixup_getter

# Main file structure types
#----------------------------------------------------------

class CodFile(Struct):
    '''Master structure encapsulating an entire COD file.'''
    def load(self, C, **kw):
        # Pass ourselves as context information to all subsequent Struct-managed bytecleaver calls
        self.add_context(cod_file=self)

        # Parse header and data sections first
        self.F('hdr', CodHeader)
        C.seek(len(self.hdr) + self.hdr.code_size)
        self.F('data', CodDataSection)

        # Skip back to the code section and parse out the routines
        C.seek(len(self.hdr))
        self.F('code', CodCodeSection)

        # Skip to the trailer
        C.seek(len(self.hdr) + self.hdr.code_size + self.hdr.data_size)
        self.F('trailer', CodTrailer)

class CodHeader(StaticStruct):
    FIELDS = [
        ('flashid', unsigned_int), ('section_num', unsigned_int), ('vtable_ptr', unsigned_int),
        ('timestamp', unsigned_int), ('user_version', unsigned_int), ('fieldref_ptr', unsigned_int),
        ('max_typelist_size', WORD), ('reserved', short), ('data_section', int_),
        ('mod_info', int_), ('version', WORD), ('code_size', WORD), ('data_size', WORD),
        ('flags', WORD),
    ]
    def verify(self, **kw):
        assert (self.flashid == 0xFFFFC0DE), "Not a valid COD header!"
        assert (self.version in SUPPORTED_COD_VERSIONS), "Unsupported COD file version '%d'!" % self.version

class CodDataSection(Struct):
    def load(self, C, **kw):
        # Grab a local reference to the "cod_file" context variable passed into us
        cod_file = kw['cod_file']

        # Local reference to our starting point\
        # (many of our reads will be offset-from-start-of-data-section-based)
        _ds = self._start

        # Read the entire data section into "raw" (for later data-pool/class-def/type-list lookups)
        # (This is a non-public, non-schematic field--do not use the self.F() mechanism)
        C.mark()
        self.raw = string_f(cod_file.hdr.data_size)(C)
        C.revert()

        # Read the header
        self.F('hdr', CodDataHeader)

        # Read classes (fixed-length array of offsets to class defs)
        self.F('class_offsets', array_f(WORD, self.hdr.num_classes))

        # Read modules (2 fixed-length arrays of offsets to Literals; need to zip them up)
        m_names = array_f(WORD, self.hdr.num_mods)(C)
        m_versions = array_f(WORD, self.hdr.num_mods)(C)
        self.FV('modules', zip(m_names, m_versions))

        # These sections are optional and contiguous
        self.F('siblings', array_b(WORD, self.hdr.off_aliases + _ds))
        self.F('aliases', array_b(WORD, self.hdr.off_exports + _ds))
        self.F('exports', array_b(CodExportedData, self.hdr.off_data_pool + _ds))

        # Skip the data pool section (already in "raw")
        C.seek(self.hdr.off_static_data + _ds)

        # Read [optional] static data up to the class defs area
        self.F('static_data', array_b(CodStaticData, self.hdr.off_class_defs + _ds))

        # Read each class definition (using the class_offsets array as a guide)
        _classes = []
        for coff in self.class_offsets:
            C.seek(coff + _ds)
            _classes.append(CodClassDef(C, **kw))
        self.FV('class_defs', _classes)

        # Skip the type def areas, since we'll look up that stuff in the "raw" data bytes
        C.seek(self.hdr.off_iface_method_refs + _ds)

        # Read the interface method and class reference arrays
        self.F('iface_method_refs', array_b(CodIfaceMethodRef, self.hdr.off_class_refs + _ds))
        self.F('class_refs', array_b(CodClassRef, self.hdr.off_routine_fxps + _ds))

        # Set controls flags for parsing fixups (based on version information)
        _long_refs = (self.hdr.version == 6)
        _imp_routines = (self.hdr.version == 5)
        _imp_static_fields = (self.hdr.version == 5)
        _imp_class_refs = (self.hdr.version == 5)

        # Parse routine (method) fixup lists
        _mref_type = FxpLongMemberRef if _long_refs else FxpMemberRef
        self._check_fixup_alignment(C, self.hdr.off_routine_fxps, "routine fixups")
        self.F('routine_fixups', xFixupList(signed_short, _mref_type, align=2, explicit=(not _imp_routines)))
        self._check_fixup_alignment(C, self.hdr.off_static_routine_fxps, "static routine fixups")
        self.F('static_routine_fixups', xFixupList(signed_short, _mref_type, align=2, explicit=(not _imp_routines)))
        self._check_fixup_alignment(C, self.hdr.off_virtual_routine_fxps, "virtual routine fixups")
        self.F('virtual_routine_fixups', xFixupList(signed_short, _mref_type, align=2, explicit=True))

        # Parse the class-ref fixup list
        self._check_fixup_alignment(C, self.hdr.off_class_ref_fxps, "class ref fixups")
        self.F('class_ref_fixups', xFixupList(WORD, WORD, align=2, explicit=(not _imp_class_refs)))

        # Parse normal/local field fixup lists
        self._check_fixup_alignment(C, self.hdr.off_field_fxps, "field fixups")
        self.F('field_fixups', xFixupList(signed_short, FxpMemberRef, align=2, explicit=True))
        self._check_fixup_alignment(C, self.hdr.off_local_field_fxps, "local field fixups")
        self.F('local_field_fixups', xFixupList(WORD, FxpLocalMemberRef, align=1, explicit=True))

        # Parse static field fixup list
        self._check_fixup_alignment(C, self.hdr.off_static_field_fxps, "static field fixups")
        self.F('static_field_fixups', xFixupList(signed_short, FxpMemberRef, align=2, explicit=(not _imp_static_fields)))

        # Parse "module code" fixups
        self._check_fixup_alignment(C, self.hdr.off_mod_code_fxps, "module code fixups")
        self.F('mod_code_fixups', xFixupList(WORD, BYTE, align=1, explicit=True))

        # Seek to the end of our space to make sure our _end gets reported properly
        C.seek(_ds + cod_file.hdr.data_size)

        # Before we're done, grab and store the cod module name and version
        self.cod_module_name = utils.unescape(C.get_cstr(self._start + self.modules[0][0]))
        self.cod_module_version = utils.unescape(C.get_cstr(self._start + self.modules[0][1]))

    def _check_fixup_alignment(self, C, fixup_offset, fixup_name):
        C.align(2); assert (C.tell() == (fixup_offset + self._start)), "%s misaligned!" % fixup_name

class CodDataHeader(StaticStruct):
    FIELDS = [
        ('flags', BYTE), ('version', BYTE), ('num_icalls', WORD), ('num_mods', BYTE), ('num_classes', BYTE),
        ('off_exports', WORD), ('off_data_pool', WORD), ('off_static_data', WORD), ('off_class_defs', WORD),
        ('off_type_lists', WORD), ('off_iface_method_refs', WORD), ('off_class_refs', WORD),
        ('off_routine_fxps', WORD), ('off_static_routine_fxps', WORD), ('off_virtual_routine_fxps', WORD),
        ('off_class_ref_fxps', WORD), ('off_aliases', WORD), ('off_field_fxps', WORD),
        ('off_local_field_fxps', WORD), ('off_static_field_fxps', WORD), ('off_mod_code_fxps', WORD),
        ('static_size', WORD), ('entry_points', array_f(CodEntryPoint, 2)),
    ]
    def verify(self, **kw):
        assert (self.version in SUPPORTED_DATA_VERSIONS), "Unsupported Data section version '%d'!" % self.version

class CodClassDef(Struct):
    def load(self, C, **kw):
        # Do all our static fields in one shot
        self.fields([
            ('pack_name', WORD), ('class_name', WORD), ('superclass', CLASS_ID),
            ('static_start', WORD), ('clinit_offset', WORD), ('init_offset', WORD),
            ('create_size', WORD), ('secure_index', WORD), ('index', WORD),
            ('code_start', WORD), ('code_end', WORD), ('flags', WORD),
            ('off_virtual_routines', WORD), ('off_nonvirtual_routines', WORD),
            ('off_static_routines', WORD), ('off_fields', WORD), ('off_static_fields', WORD),
            ('off_ifaces', WORD), ('off_field_attrs', WORD), ('off_static_field_attrs', WORD),
        ])

        # Member offsets are relative to our offsets

        # Read routine-offset arrays
        C.seek(self.off_virtual_routines + self._start)
        self.F('virtual_routines', array_b(WORD, self.off_nonvirtual_routines + self._start))
        self.F('nonvirtual_routines', array_b(WORD, self.off_static_routines + self._start))
        self.F('static_routines', array_b(WORD, self.off_fields + self._start))

        # Read the field and static-field definition arrays
        self.F('fields', array_b(CodFieldDef, self.off_static_fields + self._start))
        self.F('static_fields', array_b(CodStaticFieldDef, self.off_ifaces + self._start))

        # Read the "interfaces" array (a list of 2-byte class IDs)
        self.F('ifaces', array_b(CLASS_ID, self.off_field_attrs + self._start))

        # Read the field/static-field attribute arrays
        self.F('field_attrs', array_f(BYTE, len(self.fields)))
        self.F('static_field_attrs', array_f(BYTE, len(self.static_fields)))

class CodCodeSection(Struct):
    def load(self, C, **kw):
        # Get a local reference to the containing module and our starting location
        cod_file = kw['cod_file']
        _cs = self._start
        kw['code_section'] = self

        # Read all routines from all classes defined in the data section
        _routines = []
        for class_def in cod_file.data.class_defs:
            for roff in (class_def.virtual_routines + class_def.nonvirtual_routines + class_def.static_routines):
                C.seek(roff + _cs)
                _routines.append(CodRoutineDef(C, **kw))
        self.FV('routines', _routines)

        # Seek to the end of the code section (to make sure _end is accurate)
        C.seek(_cs + cod_file.hdr.code_size)

class CodRoutineDef(Struct):
    def load(self, C, **kw):
        cod_file = kw['cod_file']
        offset = self._start

        # Determine our header size (short or long)
        short_header = (BYTE(C.skip(-5)) > 1)
        header_offset = offset - (9 if short_header else 14)
        self._header_start = header_offset

        # This field technically comes first, so insert it here with an empty value
        self.FV('stack_map', [])

        # Read the header
        C.seek(header_offset)
        if short_header:
            self.F('return_type', WORD)
            self.F('param_types', WORD)
            self.FV('code_size', BYTE(C) - 2)
            self.F('attrs', BYTE)
            self.F('name', WORD)
            x = BYTE(C)
            self.FV('stack_size', (x >> 6) & 3)
            self.FV('max_locals', (x >> 4) & 3)
            self.FV('max_stack', x & 3)
        else:
            self.fields([
                ('name', WORD), ('param_types', WORD), ('return_type', WORD),
                ('code_size', WORD), ('attrs', WORD), ('stack_size', BYTE),
                ('max_locals', BYTE), ('_unused', BYTE), ('max_stack', BYTE),
            ])

        # Reach back and read the "stack map" entries, if any
        if self.stack_size > 0:
            C.mark()
            C.seek(header_offset - (self.stack_size * 4))
            self.stack_map = array_f(CodStackMapEntry, self.stack_size)(C)
            C.revert()

        # Read the byte code
        self.code_offset = C.tell()
        self.F('byte_code', string_f(self.code_size))

        # Read the exception handlers
        _handlers = []
        if self.attrs & 0x40:
            xh = WORD(C)
            while xh != 0xFFFF:
                raw_xh = CodExHandler(C, **kw)
                raw_xh.type_offset -= kw['code_section']._start
                _handlers.append(raw_xh)
                xh = WORD(C)
        self.FV('handlers', _handlers)

class CodStackMapEntry(StaticStruct):
    FIELDS = [('label', WORD), ('type', WORD)]

class CodExHandler(Struct):
    def load(self, C, **kw):
        C.skip(-2)
        self.fields([
            ('start', WORD), ('end', WORD),
            ('target', WORD), ('type', CLASS_ID),
        ])
        self.type_offset = C.tell() - 2

class CodTrailer(Struct):
    def load(self, C, **kw):
        self.F('items', array_x(CodTrailerItem, EOF))

class CodTrailerItem(Struct):
    def load(self, C, **kw):
        self.F('type', WORD)
        self.F('length', WORD)
        self.F('value', string_f(self.length))

