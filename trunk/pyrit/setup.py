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

# Options to use for all modules
EXTRA_COMPILE_ARGS = ['-O2', '-Werror']
LIBRARY_DIRS = ['/usr/lib']
INCLUDE_DIRS = ['/usr/include','/usr/local/include']

# The default module; always built
cpu_extension = Extension(name='_cpyrit._cpyrit_cpu',
                    libraries = ['ssl'],
                    sources = ['_cpyrit/_cpyrit_cpu.c'],
                    extra_compile_args = EXTRA_COMPILE_ARGS,
                    include_dirs = INCLUDE_DIRS,
                    library_dirs = LIBRARY_DIRS)

setup_args = dict(
        name = 'Pyrit',
        version = '0.2',
        description = 'GPU-accelerated attack against WPA-PSK authentication',
        license = 'GNU General Public License v3',
        author = 'Lukas Lueg',
        author_email = 'knabberknusperhaus@yahoo.de',
        url = 'http://pyrit.googlecode.com',
        packages = ['_cpyrit'],
        py_modules = ['cpyrit'],
        scripts = ['pyrit'],
        ext_modules = [cpu_extension],
        options = {'install':{'optimize':1}}
        )
        
if __name__ == "__main__":
    setup(**setup_args)
