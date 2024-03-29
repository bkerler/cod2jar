#!/usr/bin/env python

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
Parses a standalone COD for commonly needed information like dependencies.
"""

from optparse import OptionParser
from time import ctime
from hashlib import sha1
import os
import codlib

if __name__ == '__main__':
    OP = OptionParser(usage="usage: %prog [options] COD_FILE")
    opts, args = OP.parse_args()

    # Parse args
    if len(args) != 1:
        OP.error("Missing COD_FILE argument!")
    else:
        path = args[0]

    _SEARCH_PATH = [os.path.split(path)[0],]
    cf = codlib.load_cod_file(path)

    names = codlib.utils.quick_get_module_names(path)
    module_name = names[0]
    aliases = names[1:]
    print 'Name:         %s' % module_name
    if aliases:
        print 'Aliases:'
        for alias in aliases:
            print '    %s' % alias
    exports = codlib.utils.quick_get_exports(path)
    vendor_names = [value for name, value in exports if name == '_vendor']
    if vendor_names:
        vendor_name = vendor_names[0]
        print 'Vendor:       "%s"' % vendor_name[2:]
    print 'Version:      %s' % cf.data.cod_module_version
    print 'Compile time: %s' % ctime(cf.hdr.timestamp)
    data = open(path, 'rb').read(cf.trailer._start)
    print 'Hash:         %s' % sha1(data).digest().encode('hex')
    print 'Siblings:'
    siblings = codlib.utils.quick_get_siblings(path)
    for i, sibling in enumerate(siblings):
        print '    %d: %s' % (i, sibling)
    print 'Dependencies:'
    imports = codlib.utils.quick_get_imports(path)
    for i, (n, v) in enumerate(imports):
        print '    %d: %s (%s)' % (i, n, v)
    signer_names = []
    for trailer in cf.trailer.items:
        signer_name = trailer.value[:4].strip('\x00')
        signer_names.append(signer_name)
    signer_names.sort()
    print 'Signatures:'
    for signer_name in signer_names:
        print '    %s' % signer_name
    if not signer_names:
        print '    No signatures'
