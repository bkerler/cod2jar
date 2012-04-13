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
Python BlackBerry jad OTA downloader
"""

import urllib
import os, sys, re
from time import sleep

COD_REGEX = 'RIM-COD-URL.*: (.*)'
MIDLET_REGEX = 'MIDlet-Jar-URL.*: (.*)'

class AppURLopener(urllib.FancyURLopener):
    version = 'BlackBerry8830/4.2.2 Profile/MIDP-2.0 Configuration/CLOC-1.1 VendorID/105'

def get_url(url):
    print 'Downloading %s' % repr(url.split('/')[-1])
    urllib.urlcleanup()
    f = urllib.urlopen(url)
    res = f.read()
    f.close()

    if '404' in res:
        print 'Warning: 404 detected in %s' % url
    return res

def download_jad(jad_url, path = '.'):
    try: os.makedirs(path)
    except: pass
    base_url = '/'.join(jad_url.split('/')[:-1])
    jad_name = jad_url.split('/')[-1]
    jad = get_url(jad_url)
    
    open(os.path.join(path, jad_name), 'wb').write(jad)
    jad = jad.replace('\r', '')
    # dl all cods
    for each in re.findall(COD_REGEX, jad):
        cod = get_url(base_url + '/' + each)
        open(os.path.join(path, each), 'wb').write(cod)

    # dl all midlets
    for each in re.findall(MIDLET_REGEX, jad):
        midlet = get_url(base_url + '/' + each)
        open(os.path.join(path, each), 'wb').write(midlet)

if __name__ == '__main__':
    urllib._urlopener = AppURLopener()

    if len(sys.argv) == 3:
        url = sys.argv[1]
        path = sys.argv[2]
    else:
        print 'usage: %s url download_path' % sys.argv[0]
        sys.exit()

    download_jad(url, path)
