#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
#    Copyright 2008, 2009, Lukas Lueg, knabberknusperhaus@yahoo.de
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
import sys
import subprocess

# Options to use for all modules
EXTRA_COMPILE_ARGS = ['-O2']
LIBRARY_DIRS = []
INCLUDE_DIRS = []

# Try to find the Brook+ library and headers
STREAM_LIB_DIRS = []
STREAM_INC_DIRS = []
BRCC = 'brcc'
for path in ('/usr/local/atibrook/sdk','/opt/atibrook/sdk'):
    if os.path.exists(path):
        STREAM_LIB_DIRS.append(os.path.sep.join((path, 'lib')))
        STREAM_INC_DIRS.append(os.path.sep.join((path, 'include')))
        BRCC = os.path.sep.join((path, 'bin', 'brcc'))
        break
else:
    print >>sys.stderr, "The AMD-Stream compiler, headers and libraries required to build the kernel were not found. Trying to continue anyway..."


class GPUBuilder(build_ext):
    def _call(self, comm):
        p = subprocess.Popen(comm, stdout=subprocess.PIPE, shell=True)
        stdo, stde = p.communicate()
        if p.returncode == 0:
            return stdo
        else:
            print >>sys.stderr, "%s\nFailed to execute command '%s'" % (stde, comm)
            return None
            
    def _makedirs(self, pathname):
        try:
            os.makedirs(pathname)
        except OSError:
            pass

    def run(self):
        if '_brook_tmp' in os.listdir('./') and '_stream.cpp' in os.listdir('_brook_tmp'):
            print "Skipping rebuild of AMD-Stream kernel ..."
        else:
            print "Preprocessing AMD-Stream kernel..."
            self._makedirs('./_brook_tmp')
            cpp_o = self._call('cpp -P cpyrit_stream.br')
            if cpp_o is None:
                raise SystemError, 'Failed to preprocess AMD-Stream kernel'
            f = file('./_brook_tmp/cpyrit_stream_pp.br', 'w')
            f.write(re.sub("W\[(.+?)\]", lambda x: "W_" + str(eval(x.group(1))), cpp_o)) # hack to convert W[21-3] to W_18
            f.close()
            print "Compiling AMD-Stream kernel..."
            subprocess.check_call(BRCC + ' -p cal -r -o ./_brook_tmp/_stream ./_brook_tmp/cpyrit_stream_pp.br', shell=True)
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
            for f in ('_brook_tmp/_stream.h', '_brook_tmp/_stream_gpu.h', '_brook_tmp/_stream.cpp', '_brook_tmp/cpyrit_stream_pp.br', '_brook_tmp'):
                self._unlink(f)
        except Exception, (errno, sterrno):
            print >>sys.stderr, "Exception while cleaning temporary files ('%s')" % sterrno
        clean.run(self)


# ... _brook_tmp/_stream.cpp is put in place by GPUBuilder
stream_extension = Extension('_cpyrit._cpyrit_stream',
                    libraries = ['ssl', 'dl', 'brook'],
                    sources = ['cpyrit_stream.cpp', '_brook_tmp/_stream.cpp'],
                    extra_compile_args = EXTRA_COMPILE_ARGS,
                    include_dirs = INCLUDE_DIRS + STREAM_INC_DIRS + ['_brook_tmp'],
                    library_dirs = LIBRARY_DIRS + STREAM_LIB_DIRS)

setup_args = dict(
        name = 'CPyrit-Stream',
        version = '0.2.3',
        description = 'GPU-accelerated attack against WPA-PSK authentication',
        license = 'GNU General Public License v3',
        author = 'Lukas Lueg',
        author_email = 'knabberknusperhaus@yahoo.de',
        url = 'http://pyrit.googlecode.com',
        ext_modules = [stream_extension],
        cmdclass = {'build_ext':GPUBuilder, 'clean':GPUCleaner},
        options = {'install':{'optimize':1},'bdist_rpm':{'requires':'Pyrit = 0.2.3-1, libaticalcl.so'}}
        )
        
if __name__ == "__main__":
    setup(**setup_args)
