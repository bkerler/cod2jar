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

import os, sys
import shutil
from zipfile import ZipFile
from optparse import OptionParser

def extract_subfiles(source_path, dest_path, verbose=False):
    if os.path.isdir(source_path):
        for dirpath, dirnames, filenames in os.walk(source_path):
            relpath = os.path.relpath(dirpath, source_path)
            new_dir_path = os.path.join(dest_path, relpath)
            if not os.path.isdir(new_dir_path):
                os.mkdir(new_dir_path)
            for filename in filenames:
                try:
                    source_file_path = os.path.join(dirpath, filename)
                    relpath = os.path.relpath(source_file_path, source_path)
                    dest_file_path = os.path.join(dest_path, relpath)
                    print dest_file_path
                    if dest_file_path.endswith('.cod'):
                        zip = ZipFile(source_file_path)
                        for info in zip.infolist():
                            if verbose:
                                print '    %s (extracted)' % info.filename
                            dest_unzip_path = os.path.split(dest_file_path)[0] 
                            if not os.path.realpath(os.path.join(dest_unzip_path, info.filename)).startswith(os.path.realpath(dest_unzip_path)):
                                raise(Exception('Security exception: zip file %s attempted to extract to a non-local location' % info.filename))
                            zip.extract(info, path = dest_unzip_path)
                    else:
                        shutil.copyfile(source_file_path, dest_file_path)
                except Exception, e:
                    if str(e) == 'File is not a zip file':
                        # this is a cod file or some other file
                        shutil.copyfile(source_file_path, dest_file_path)
                    else:
                        if verbose:
                            print >>sys.stderr, 'Error:',
                            print >>sys.stderr, str(e)
                        raise(e)
    elif os.path.isfile(source_path):
        try:
            source_file_path = source_path
            relpath = os.path.relpath(source_file_path, source_path)
            dest_file_path = os.path.join(dest_path, relpath)
            if source_file_path.endswith('.cod'):
                zip = ZipFile(source_file_path)
                for info in zip.infolist():
                    if verbose:
                        print '    %s (extracted)' % info.filename
                    dest_unzip_path = os.path.split(dest_file_path)[0] 
                    if not os.path.realpath(os.path.join(dest_unzip_path, info.filename)).startswith(os.path.realpath(dest_unzip_path)):
                        raise(Exception('Security exception: zip file %s attempted to extract to a non-local location' % info.filename))
                    zip.extract(info, path = dest_unzip_path)
            else:
                shutil.copyfile(source_file_path, dest_file_path)
        except Exception, e:
            if str(e) == 'File is not a zip file':
                # this is a cod file or some other file
                shutil.copyfile(source_file_path, dest_file_path)
            else:
                if verbose:
                    print >>sys.stderr, 'Error:',
                    print >>sys.stderr, str(e)
                raise(e)
    

if __name__ == '__main__':
    usage = 'usage: %prog [options] source_path dest_path'
    parser = OptionParser(usage)

    (options, args) = parser.parse_args()
    if len(args) != 2:
        parser.error('incorrect number of arguments')

    source_path = args[0]
    dest_path = args[1]
    if not os.path.exists(source_path):
        parser.error('source path does not exist')
    if os.path.isdir(dest_path):
        parser.error('destination path already exists')
    else:
        os.mkdir(dest_path)

    extract_subfiles(source_path, dest_path, verbose=True)
