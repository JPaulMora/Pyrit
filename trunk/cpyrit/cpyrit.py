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
import threading, time, hashlib

class MicroCore(threading.Thread):
    """
    Used by GPU-kernels to spread work between CPU and GPU
    """
    def __init__(self, func, blocksize, workcontrol):
        threading.Thread.__init__(self)
        self.workcontrol = workcontrol
        self.comptime = 0
        self.results = 0
        self.blocksize = blocksize
        self.func = func
        
    def run(self):
        lock = self.workcontrol[0]
        while (self.workcontrol[2] < len(self.workcontrol[1])-1):
            lock.acquire()
            idx = self.workcontrol[2]
            self.workcontrol[2] += self.blocksize
            pws = self.workcontrol[1][idx:idx+self.blocksize]
            lock.release()
            
            t = time.time()
            res = self.func(self.workcontrol[3], pws)
            self.comptime += time.time() - t
            self.results += len(pws)
            
            lock.acquire()
            self.workcontrol[4].extend(res)
            lock.release()

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
        
        if 'calc_pmklist' not in dir(_cpyrit) or len(password) < 1000:
            return _cpyrit.calc_cuda(essid, password)

        workcontrol = [threading.Lock(), password, 0, essid, []]

        gpu_mcore = MicroCore(_cpyrit.calc_cuda, 1024, workcontrol)
        cpu_mcore = MicroCore(_cpyrit.calc_pmklist, 250, workcontrol)
        t = time.time()
        gpu_mcore.start()
        cpu_mcore.start()
        gpu_mcore.join()
        cpu_mcore.join()
        t = time.time() - t
        
        #print "\nGPU occupancy: %.2f%%" % (gpu_mcore.comptime / t * 100)
        #print "CPU occupancy: %.2f%%" % (cpu_mcore.comptime / t * 100)
        
        self.gpu_perf = (self.gpu_perf[0] + gpu_mcore.results, self.gpu_perf[1] + gpu_mcore.comptime)
        self.cpu_perf = (self.cpu_perf[0] + cpu_mcore.results, self.cpu_perf[1] + cpu_mcore.comptime)
        
        #print "GPU performance: %.2f/sec" % (self.gpu_perf[0] / self.gpu_perf[1])
        #print "CPU performance: %.2f/sec\n" % (self.cpu_perf[0] / self.cpu_perf[1])
        
        return workcontrol[4]


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
    def __init__(self):
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
        
    def listCores(self):
        return self.cores.items()
        
    def getCore(self, core=None):
        if core is None:
            return self.core()
        else:
            return self.cores[core]()
