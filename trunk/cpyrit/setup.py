from distutils.core import setup, Extension

cmodule = Extension('_cpyrit',
                    libraries = ['cuda','cudart','ssl'],
                    sources = ['cpyrit.c'],
                    extra_compile_args = ['-O0','-ggdb'],
                    include_dirs = ['/usr/local/cuda/include'],
                    extra_objects = ['cpyrit_cuda.o']
                    )

setup (name = 'cpyrit',
       version = '1.0',
       description = 'Fast WPA/WPA2 HMAC through openssl',
       py_modules = ['cpyrit'],
       ext_modules = [cmodule]) 
