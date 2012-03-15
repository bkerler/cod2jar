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
Distutils setup file for cod2jar.
"""

import os
from distutils.core import setup

SCRIPTS = [
    'bin/cod_explorer.py',
    'bin/cod_extract.py',
    'bin/cod_info.py',
    'bin/cod2jar.py',
    'bin/download_jad.py',
]
if os.name == "nt":
    SCRIPTS += [
        'bin/cod_explorer.bat',
        'bin/cod_extract.bat',
        'bin/cod_info.bat',
        'bin/cod2jar.bat',
        'bin/download_jad.bat',
    ]

setup(
    name = 'cod2jar',
    version = '1.0',
    packages = [
        'codlib',
    ],
    scripts = SCRIPTS,
    description = 'BlackBerry cod file format analysis tools',
    author = 'derrotehund361',
    author_email = 'derrotehund361@googlemail.com',
    url = 'http://code.google.com/p/cod2jar/',
    license = 'New BSD',
)
