#!/usr/bin/env python

from distutils.core import setup, Extension
import sys
import subprocess
import re

def replace_eval(match):
    return "W_" + str(eval(match.group(1)))

libraries = ['ssl']
library_dirs = ['/usr/lib']
include_dirs = ['/usr/include','/usr/local/include']
extra_objects = []
extra_compile_args = ['-O2']
if 'HAVE_CUDA' in sys.argv:
    sys.argv.remove('HAVE_CUDA')
    print "Compiling CUDA kernel..."
    subprocess.check_call('nvcc --opencc-options "-WOPT:expr_reass=off" -Xcompiler "-fPIC -DHAVE_CUDA" -c cpyrit_cuda.cu', shell=True)
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
if 'HAVE_STREAM' in sys.argv:
    sys.argv.remove('HAVE_STREAM');
    print "Compiling Stream kernel..."
    subprocess.check_call('cpp -P -o cpyrit_stream_pp.br cpyrit_stream.br', shell=True);
    f = file('cpyrit_stream_pp.br', 'r+')
    s = f.read()
    f.truncate(0)
    f.seek(0)
    f.write(re.sub("W\[(.+?)\]", replace_eval, s))
    f.close()
    subprocess.check_call('mkdir -p brook',shell=True);
    subprocess.check_call('/usr/local/amdbrook/sdk/bin/brcc -p cal -r -o brook/cpyrit cpyrit_stream_pp.br', shell=True);
    print "... done."
    subprocess.check_call('g++ -O2 -I/usr/local/amdbrook/sdk/include/ -Ibrook -o brook/cpyrit.o -c brook/cpyrit.cpp',shell=True);
    subprocess.check_call('g++ -O2 -I/usr/local/amdbrook/sdk/include/ -Ibrook -c cpyrit_stream.cpp',shell=True);
    libraries.extend(['brook'])
    extra_compile_args.append('-DHAVE_STREAM')
    include_dirs.append('/usr/local/amdbrook/sdk/include')
    library_dirs.append('/usr/local/amdbrook/sdk/lib')
    extra_objects.append('cpyrit_stream.o')
    extra_objects.append('brook/cpyrit.o')    
    
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
