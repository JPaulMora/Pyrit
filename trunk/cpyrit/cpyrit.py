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
import time, hashlib, os, sys

class CUDACore(object):
    name = "Nvidia CUDA"
    ctype = "GPU"
    def __init__(self):
        assert 'calc_cuda' in dir(_cpyrit)
        self.buffersize = 2048
        props = _cpyrit.cudaprops()
        self.devicename = props[2]
        self.devicemem = int(props[3] / 1024.0 / 1024.0)
        self.deviceclock = int(props[5] / 1024.0)
        
    def solve(self, essid, password):
        assert isinstance(essid, str)
        if isinstance(password, str):
            return _cpyrit.calc_pmk(essid, password)
        assert isinstance(password, list)
        
        # The kernel allows a max. execution time of 5 seconds per call (usually) so we have to
        # limit the input-buffer to some degree. However the size of the input-buffer is crucial
        # to overall performance. Therefor buffersize is to be calibrated somewhere near
        # it's maximum value allowed. Target is 3.0 seconds execution time.
        res = []
        i = 0
        while i < len(password):
            t = time.time()
            pwslice = password[i:i+self.buffersize]
            res.extend(_cpyrit.calc_cuda(essid, pwslice))
            i += self.buffersize
            if len(pwslice) >= 2048:
                self.buffersize = int(max(2048, min(20480, (2 * self.buffersize + (3.0 / (time.time() - t) * self.buffersize)) / 3)))
        return res


class CPUCore(object):
    name = "Standard CPU"
    ctype = "CPU"
    def __init__(self):
        assert 'calc_pmklist' in dir(_cpyrit)
        
    def solve(self, essid, password):
        assert isinstance(essid, str)
        if isinstance(password, list):
            # slicing gives better interactivity to signals as _cpyrit's functions won't listen to them
            res = []
            for pwslice in xrange(0, len(password), 1000):
                res.extend(_cpyrit.calc_pmklist(essid, password[pwslice:pwslice+1000]))
            return res
        elif isinstance(password, str):
            return _cpyrit.calc_pmk(essid, password)

        else:
            raise TypeError, "Password parameter must be string or list"

class NullCore(object):
    name = "The dummy-core"
    ctype = "CPU"
    def __init__(self):
        print >>sys.stderr, "WARNING: The NullCore has been initialized. Be aware!"
        
    def solve(self, essid, password):
        assert isinstance(password, list)
        return [(pw, '\00'*32) for pw in password]


class CPyrit(object):
    """
    The CPyrit class takes the _cpyrit-module into the python world.
    It's much easier to do some of the task in python than in C.
    
    IMPORTANT: Given a list of ['foo1','foo2'], the Core-classes always
    return lists of tuples such as [(foo1, bar1), (foo2, bar2)].
    There is no guarantee that the order of 'foo' in the result-list
    is the same as in the input-list!
    
    """
    
    cores = {}
    def __init__(self, ncpus=None):
        avail = dir(_cpyrit)
        assert 'calc_pmk' in avail
        assert 'calc_pmklist' in avail
        
        # Each core is tested only the first time the CPyrit-class is instantiated for performance reasons
        if len(CPyrit.cores) == 0:
            md = hashlib.md5()
            md.update(_cpyrit.calc_pmklist('foo', ['bar'])[0][1])
            if md.hexdigest() != 'a99415725d7003510eb37382126338f3':
                raise SystemError, "WARNING: CPyrit's CPU-core is apparently broken. We can't continue..."
            CPyrit.cores[CPUCore.name] = CPUCore
            self.core = CPUCore
            
            if 'calc_cuda' in avail:
                md = hashlib.md5()
                md.update(_cpyrit.calc_cuda('foo', ['bar'])[0][1])
                if md.hexdigest() != 'a99415725d7003510eb37382126338f3':
                    print >>sys.stderr, "WARNING: CPyrit's Nvidia-CUDA GPU-core is apparently broken and will be unavailable."
                else:
                    CPyrit.cores[CUDACore.name] = CUDACore
                    self.core = CUDACore

        if ncpus is None or ncpus not in range(1,33):
            ncpus = self.__detect_ncpus()
        self.ncpus = _cpyrit.set_numThreads(ncpus)
        
    def listCores(self):
        return CPyrit.cores.items()
        
    def getCore(self, core=None):
        if core is None:
            return self.core()
        else:
            return CPyrit.cores[core]()
            
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
