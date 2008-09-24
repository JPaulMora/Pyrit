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


import _cpyrit
import threading, time, hashlib, os

class CUDACore(object):
    name = "Nvidia CUDA"
    description = "Yeah"
    def __init__(self):
        assert 'calc_cuda' in dir(_cpyrit)
        self.gpu_perf = (0, 0)
        self.cpu_perf = (0, 0)
        
    def solve(self, essid, password):
        assert isinstance(essid, str)
        if isinstance(password, str):
            return _cpyrit.calc_pmk(essid, password)
        assert isinstance(password, list)
        
        return _cpyrit.calc_cuda(essid, password)

class CPUCore(object):
    name = "Standard CPU"
    description = "Yeah!"
    def __init__(self):
        assert 'calc_pmklist' in dir(_cpyrit)
        
    def solve(self, essid, password):
        assert isinstance(essid, str)
        if isinstance(password, list):
            return _cpyrit.calc_pmklist(essid, password)
        elif isinstance(password, str):
            return _cpyrit.calc_pmk(essid, password)
        else:
            raise TypeError, "Password parameter must be string or list"
    

class CPyrit(object):
    """
    The CPyrit class takes the _cpyrit-module into the python world.
    It's much easier to do some of the task in python than in C.
    
    IMPORTANT: Given a list of ['foo1','foo2'], the Core-classes always
    return lists of tuples such as [(foo1, bar1), (foo2, bar2)].
    There is no guarantee that the order of 'foo' in the result-list
    is the same as in the input-list!
    
    """
    def __init__(self, ncpus=None):
        self.cores = {}
        avail = dir(_cpyrit)
        assert 'calc_pmk' in avail
        assert 'calc_pmklist' in avail
        
        md = hashlib.md5()
        md.update(_cpyrit.calc_pmklist('foo', ['bar'])[0][1])
        if md.hexdigest() != 'a99415725d7003510eb37382126338f3':
            raise SystemError, "WARNING: CPyrit's CPU-core is apparently broken. We can't continue..."
        self.cores[CPUCore.name] = CPUCore
        self.core = CPUCore
        
        if 'calc_cuda' in avail:
            md = hashlib.md5()
            md.update(_cpyrit.calc_cuda('foo', ['bar'])[0][1])
            if md.hexdigest() != 'a99415725d7003510eb37382126338f3':
                print "WARNING: CPyrit's Nvidia-CUDA GPU-core is apparently broken and will be unavailable."
            else:
                self.cores[CUDACore.name] = CUDACore
                self.core = CUDACore

        if ncpus is None or ncpus not in range(1,33):
            ncpus = self.__detect_ncpus()
        self.ncpus = _cpyrit.set_numThreads(ncpus)
        
    def listCores(self):
        return self.cores.items()
        
    def getCore(self, core=None):
        if core is None:
            return self.core()
        else:
            return self.cores[core]()
            
    def __detect_ncpus(self):
        """Detect the number of effective CPUs in the system"""
        # Snippet taken from ParallelPython
        # For Linux, Unix and MacOS
        if hasattr(os, "sysconf"):
            if "SC_NPROCESSORS_ONLN" in os.sysconf_names:
                #Linux and Unix
                ncpus = os.sysconf("SC_NPROCESSORS_ONLN")
                if isinstance(ncpus, int) and ncpus > 0:
                    return ncpus
            else:
                #MacOS X
                return int(os.popen2("sysctl -n hw.ncpu")[1].read())
        #for Windows
        if "NUMBER_OF_PROCESSORS" in os.environ:
            ncpus = int(os.environ["NUMBER_OF_PROCESSORS"])
            if ncpus > 0:
                return ncpus
        #return the default value
        return 1
