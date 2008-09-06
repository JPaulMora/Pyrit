# -*- coding: UTF-8 -*-


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
import threading
import time

class MicroCore(threading.Thread):
""" Used by GPU-kernels to spread work between CPU and GPU"""
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

        gpu_mcore = MicroCore(_cpyrit.calc_cuda, 1000, workcontrol)
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
""" The CPyrit class takes the _cpyrit-module into the python world.
    It's much easier to do some of the task in python than in c."""
    def __init__(self):
        self.cores = {}
        avail = dir(_cpyrit)
        assert 'calc_pmk' in avail
        for fname, c in [('calc_cuda', CUDACore), ('calc_pmklist', CPUCore)]:
            if fname in avail:
                self.cores[c.name] = c
                self.core = c
        
    def listCores(self):
        return self.cores.items()
        
    def getCore(self, core=None):
        if core is None:
            return self.core()
        else:
            return self.cores[core]()
