#!/usr/bin/python
from distutils.core import setup, Extension
import sys
import subprocess

libraries = ['ssl']
library_dirs = ['/usr/lib']
include_dirs = ['/usr/include']
extra_objects = []
extra_compile_args = ['-O2']
if 'HAVE_CUDA' in sys.argv:
    sys.argv.remove('HAVE_CUDA')
    print "Compiling CUDA kernel..."
    subprocess.check_call('nvcc -Xcompiler "-fPIC -DHAVE_CUDA" -c cpyrit_cuda.cu', shell=True)
    print "... done."
    libraries.extend(['cuda', 'cudart'])
    extra_compile_args.append('-DHAVE_CUDA')
    include_dirs.append('/usr/local/cuda/include')
    library_dirs.append('/usr/local/cuda/lib')
    extra_objects.append('cpyrit_cuda.o')
if 'HAVE_PADLOCK' in sys.argv:
    sys.argv.remove('HAVE_PADLOCK')
    print "Compiling with Via padlock support"
    extra_compile_args.append('-DHAVE_PADLOCK')

cmodule = Extension('_cpyrit',
                    libraries = libraries,
                    sources = ['cpyrit.c'],
                    extra_compile_args = extra_compile_args,
                    include_dirs = include_dirs,
                    library_dirs = library_dirs,
                    extra_objects = extra_objects
                    )

setup (name = 'cpyrit',
       version = '1.0',
       description = 'Computational cores for Pyrit',
       author = 'Lukas Lueg',
       author_email = 'knabberknusperhaus@yahoo.de',
       url = 'http://pyrit.googlecode.com',
       py_modules = ['cpyrit'],
       ext_modules = [cmodule]) 
