#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
#    Copyright 2008, Lukas Lueg, lukas.lueg@gmail.com
#
#    This file is part of Pyrit.
#
#    Pyrit is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Pyrit is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Pyrit.  If not, see <http://www.gnu.org/licenses/>.


from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext
from distutils.command.clean import clean
import os
import re
import subprocess
import sys
import zlib

OPENCL_INC_DIRS = []
for path in ('/usr/local/opencl/OpenCL/common/inc','/opt/opencl/OpenCL/common/inc'):
    if os.path.exists(path):
        OPENCL_INC_DIRS.append(path)
        break
else:
    print >>sys.stderr, "The headers required to build the OpenCL-kernel were not found. Trying to continue anyway..."


try:
    svn_info = subprocess.Popen(('svn', 'info'), stdout=subprocess.PIPE).stdout.read()
    version_string = '0.2.5-dev (svn r%i)' % int(re.compile('Revision: ([0-9]*)').findall(svn_info)[0])
except:
    version_string = '0.2.5-dev'
EXTRA_COMPILE_ARGS = ['-DVERSION="%s"' % version_string]


class GPUBuilder(build_ext):
    def run(self):
        f = open("_cpyrit_opencl.h", 'rb')
        header = f.read()
        f.close()
        f = open("_cpyrit_oclkernel.cl", 'rb')
        kernel = f.read()
        f.close()
        oclkernel_program = header + '\n' + kernel + '\x00'
        oclkernel_packed = zlib.compress(oclkernel_program)        
        f = open("_cpyrit_oclkernel.cl.h", 'wb')
        f.write("unsigned char oclkernel_packedprogram[] = {")
        f.write(",".join(("0x%02X%s" % (ord(c), "\n" if i % 16 == 0 else "") for i, c in enumerate(oclkernel_packed))))
        f.write("};\nsize_t oclkernel_size = %i;\n" % len(oclkernel_program))
        f.close()
        
        print "Building modules..."
        build_ext.run(self)


class GPUCleaner(clean):
    def _unlink(self, node):
        try:
            if os.path.isdir(node):
                os.rmdir(node)
            else:
                os.unlink(node)
        except OSError:
            pass
    
    def run(self):
        print "Removing temporary files and pre-built GPU-kernels..."
        try:
            for f in ('_cpyrit_oclkernel.cl.h',):
                self._unlink(f)
        except Exception, (errno, sterrno):
            print >>sys.stderr, "Exception while cleaning temporary files ('%s')" % sterrno
        clean.run(self)


opencl_extension = Extension('cpyrit._cpyrit_opencl',
                    libraries = ['ssl', 'OpenCL', 'z'],
                    sources = ['_cpyrit_opencl.c'],
                    include_dirs = OPENCL_INC_DIRS,
                    extra_compile_args = EXTRA_COMPILE_ARGS)

setup_args = dict(
        name = 'CPyrit-OpenCL',
        version = '0.2.5',
        description = 'GPU-accelerated attack against WPA-PSK authentication',
        license = 'GNU General Public License v3',
        author = 'Lukas Lueg',
        author_email = 'lukas.lueg@gmail.com',
        url = 'http://pyrit.googlecode.com',
        ext_modules = [opencl_extension],
        cmdclass = {'build_ext':GPUBuilder, 'clean':GPUCleaner},
        options = {'install':{'optimize':1},'bdist_rpm':{'requires':'Pyrit = 0.2.5-1'}}
        )
        
if __name__ == "__main__":
    setup(**setup_args)
