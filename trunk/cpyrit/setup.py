#!/usr/bin/python
from distutils.core import setup, Extension
import sys
import subprocess

libraries = ['ssl']
include_dirs = ['/usr/include']
extra_objects = []
extra_compile_args = ['-O0','-ggdb']
if 'HAVE_CUDA' in sys.argv:
    sys.argv.remove('HAVE_CUDA')
    print "Compiling CUDA kernel..."
    subprocess.check_call('nvcc -Xcompiler "-fPIC -DHAVE_CUDA" -Xptxas "-maxrregcount=42" -c cpyrit_cuda.cu', shell=True)
    print "... done."
    libraries.extend(['cuda', 'cudart'])
    extra_compile_args.append('-DHAVE_CUDA')
    include_dirs.append('/usr/local/cuda/include')
    extra_objects.append('cpyrit_cuda.o')

cmodule = Extension('_cpyrit',
                    libraries = libraries,
                    sources = ['cpyrit.c'],
                    extra_compile_args = extra_compile_args,
                    include_dirs = include_dirs,
                    extra_objects = extra_objects
                    )

setup (name = 'cpyrit',
       version = '1.0',
       description = 'Fast WPA/WPA2 HMAC through openssl',
       py_modules = ['cpyrit'],
       ext_modules = [cmodule]) 
