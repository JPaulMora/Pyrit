# -*- coding: UTF-8 -*-
#
#    Copyright 2008, 2009, Lukas Lueg, lukas.lueg@gmail.com
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

from __future__ import with_statement

import os
import sys

def default_config():
    config = {'default_storage': 'file://', \
              'rpc_server': 'true', \
              'rpc_announce': 'true', \
              'rpc_knownclients': ''}
    return config

def read_configfile(filename):
    config = default_config()
    with open(filename, 'rb') as f:
        for line in f:
            if line.startswith('#') or '=' not in line:
                continue
            option, value = map(str.strip, line.split('=', 1))
            if option in config:
                config[option] = value
            else:
                print >>sys.stderr, "WARNING: Unknown option '%s' " \
                                    "in configfile '%s'" % (option, filename)
    return config

def write_configfile(config, filename):
    with open(filename, 'wb') as f:
        for option, value in sorted(config.items()):
            f.write("%s = %s\n" % (option, value))
    
default_configfile = os.path.expanduser(os.path.join('~', '.pyrit', 'config'))

if os.path.exists(default_configfile):
    config = read_configfile(default_configfile)
else:
    config = default_config()
    write_configfile(config, default_configfile)
