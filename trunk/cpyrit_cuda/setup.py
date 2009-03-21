#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
#    Copyright 2008, Lukas Lueg, knabberknusperhaus@yahoo.de
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
import sys, subprocess, re, os

EXTRA_COMPILE_ARGS = ['-O2']
LIBRARY_DIRS = []
INCLUDE_DIRS = []

# Try to find the CUDA headers (part of the Toolkit)
NVIDIA_INC_DIRS = []
NVCC = 'nvcc'
for path in ('/usr/local/cuda','/opt/cuda'):
    if os.path.exists(path):
        NVIDIA_INC_DIRS.append(os.path.sep.join((path, 'include')))
        NVCC = os.path.sep.join((path, 'bin', 'nvcc'))
        break
else:
    print >>sys.stderr, "The CUDA compiler and headers required to build the kernel were not found. Trying to continue anyway..."

# Custom build_ext phase to create the GPU code with special compilers before building the whole thing
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
        # The code which includes the CUDA-kernel gets passed through nvcc...
        if '_cpyrit_cudakernel.cubin.h' in os.listdir('./'):
            print "Skipping rebuild of Nvidia CUDA kernel ..."
        else:
            nvcc_o = self._call(NVCC + ' -V')
            if nvcc_o is not None:
                nvcc_version = nvcc_o.split()[-1]
            else:
                raise SystemError, "Nvidia's CUDA-compiler 'nvcc' can't be found. Make sure it's available to $PATH. " \
                                    "It is part of the CUDA Toolkit (not the SDK)."
            print "Compiling CUDA module using nvcc %s..." % nvcc_version
            nvcc = NVCC + ' --host-compilation C -Xptxas "-v" --opencc-options "-WOPT:expr_reass=off" -Xcompiler "-fPIC" --cubin ./_cpyrit_cudakernel.cu'
            subprocess.check_call(nvcc, shell=True)
            f = open("_cpyrit_cudakernel.cubin", "rb")
            cubin_img = f.read()
            f.close()
            cubin_inc = ",".join(("0x%02X%s" % (ord(c), "\n" if i % 16 == 0 else "") for i, c in enumerate(cubin_img)))
            f = open("_cpyrit_cudakernel.cubin.h", "wb")
            f.write("const char __cudakernel_module[] = {")
            f.write(cubin_inc)
            f.write("};\n\n")
            f.close()

        # Now build the rest
        print "Building modules..."
        build_ext.run(self)


# Custom clean phase to remove nvcc cruft. Only remove files that we know!
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
            for f in ('_cpyrit_cudakernel.linkinfo', '_cpyrit_cudakernel.cubin', '_cpyrit_cudakernel.cubin.h'):
                self._unlink(f)
        except Exception, (errno, sterrno):
            print >>sys.stderr, "Exception while cleaning temporary files ('%s')" % sterrno

        clean.run(self)


cuda_extension = Extension('_cpyrit._cpyrit_cuda',
                    libraries = ['ssl', 'cuda'],
                    sources = ['_cpyrit_cuda.c'],
                    extra_compile_args = EXTRA_COMPILE_ARGS,
                    include_dirs = INCLUDE_DIRS + NVIDIA_INC_DIRS,
                    library_dirs = LIBRARY_DIRS)

setup_args = dict(
        name = 'CPyrit-CUDA',
        version = '0.2.2',
        description = 'GPU-accelerated attack against WPA-PSK authentication',
        license = 'GNU General Public License v3',
        author = 'Lukas Lueg',
        author_email = 'knabberknusperhaus@yahoo.de',
        url = 'http://pyrit.googlecode.com',
        ext_modules = [cuda_extension],
        cmdclass = {'build_ext':GPUBuilder, 'clean':GPUCleaner},
        options = {'install':{'optimize':1},'bdist_rpm':{'requires':'Pyrit = 0.2.2-1'}}
        )
        
if __name__ == "__main__":
    setup(**setup_args)
