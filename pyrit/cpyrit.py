# -*- coding: UTF-8 -*-
#
#    Copyright 2008, 2009, Lukas Lueg, knabberknusperhaus@yahoo.de
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

import time, Queue, threading, sys, os
try:
    import _cpyrit
except ImportError:
    print >>sys.stderr, "Failed to load the internal _cpyrit module. Check your installation."
    raise


TV_ESSID = 'foo'
TV_PASSWD = 'barbarbar'
TV_PMK = [6,56,101,54,204,94,253,3,243,250,132,170,142,162,204,132,8,151,61,243,75,216,75,83,128,110,237,48,35,205,166,126]
def _testComputeFunction(func, i):
    for pmk in func(TV_ESSID, [TV_PASSWD]*i):
        if [ord(x) for x in pmk] != TV_PMK:
            raise Exception, "Test-vector does not result in correct result."


_avail_cores = []

class Core(threading.Thread):
    def __init__(self, inQueue, callback, name, **kwargs):
        threading.Thread.__init__(self)
        self.name = name
        self.minBufferSize = 20000
        self.inQueue = inQueue
        self.callback = callback
        self.resCount = 0
        self.compTime = 0
        self.setDaemon(True)

    def run(self):
        while True:
            essid_dict = {}
            while sum((len(pwlist) for pwlist,slices in essid_dict.values())) < self.minBufferSize:
                try:
                    wu_idx, (wu_essid, wu_pwlist) = self.inQueue.get(block=len(essid_dict) == 0, timeout=1.0)
                    try:
                        pwlist, slices = essid_dict[wu_essid]
                    except KeyError:
                        essid_dict[wu_essid] = (pwlist, slices) = [], []
                    slices.append((wu_idx, len(pwlist), len(wu_pwlist)))
                    pwlist.extend(wu_pwlist)
                except Queue.Empty:
                    break
            t = time.time()
            for essid, (pwlist, slicelist) in essid_dict.items():
                results = self.solve(essid, pwlist)
                for wu_idx, start, length in slicelist:
                    self.callback(wu_idx, results[start:start+length])
                self.resCount += len(results)
            self.compTime += time.time() - t

    def __repr__(self):
        return self.name

    def getStats(self):
        return (self.resCount, self.compTime)


## Create the CPU-driven core
try:
    from _cpyrit import _cpyrit_cpu
    _testComputeFunction(_cpyrit_cpu.calc_pmklist, 21)
except:
    print >>sys.stderr, "Failed to load Pyrit's CPU-driven core; this module should always be available. Sorry, we can't continue."
    raise
class CPUCore(Core):
    def __init__(self, inqueue, callback, name):
        Core.__init__(self, inqueue, callback, name)
        self.minBufferSize = 500
        self.start()

    def solve(self, essid, passwordlist):
        return tuple(['\x00'*32]*len(passwordlist))
        #return _cpyrit_cpu.calc_pmklist(essid, passwordlist)

_avail_cores.append(('CPU', CPUCore, "CPU-Core (%s)" % _cpyrit_cpu.getPlatform(), {}))


## Try creating the CUDA-Core. Failure is acceptable.
try:
    from _cpyrit import _cpyrit_cuda
    for dev_idx, device in enumerate(_cpyrit_cuda.listDevices()):
        d = _cpyrit_cuda.CUDADevice(dev_idx)
        _testComputeFunction(d.calc_pmklist, 101)
except ImportError:
    pass
except Exception, e:
    print >>sys.stderr, "Failed to load CUDA-core (%s)." % e.message
else:
    class CUDACore(Core):
        def __init__(self, inqueue, callback, name, dev):
            Core.__init__(self, inqueue, callback, name)
            self.CUDADev = _cpyrit_cuda.CUDADevice(dev)
            self.minBufferSize = 20480
            self.buffersize = 2048
            self.start()
            
        def solve(self, essid, passwordlist):
            # The kernel allows a max. execution time of 5 seconds per call (when X11 is loaded) so we have to
            # limit the input-buffer to some degree. However the size of the input-buffer is crucial
            # to overall performance. Therefor buffersize is to be calibrated somewhere near
            # it's maximum value allowed. Target is 3.0 seconds execution time.
            res = []
            i = 0
            while i < len(passwordlist):
                t = time.time()
                pwslice = passwordlist[i:i+self.buffersize]
                res.extend(self.CUDADev.calc_pmklist(essid, pwslice))
                i += self.buffersize
                if len(pwslice) >= 2048:
                    self.buffersize = int(max(2048, min(20480, (2 * self.buffersize + (3.0 / (time.time() - t) * self.buffersize)) / 3)))
            return tuple(res)
    
    for dev_idx, device in enumerate(_cpyrit_cuda.listDevices()):
        _avail_cores.append(('GPU', CUDACore, "CUDA-Device #%i '%s'" % (dev_idx+1,device[0]), {'dev':dev_idx}))


## Try creating the Stream-Core. Failure is acceptable.
try:
    from _cpyrit import _cpyrit_stream
    _testComputeFunction(_cpyrit_stream.calc_pmklist, 101)
except ImportError:
    pass
except Exception, e:
    print >>sys.stderr, "Failed to load Stream-core ('%s')" % e
else:
    class StreamCore(Core):
        def __init__(self, inqueue, callback, name, dev):
            Core.__init__(self, inqueue, callback, name)
            self.dev = dev
            self.minBufferSize = 20480
            self.start()

        def run(self):
            _cpyrit_stream.setDevice(self.dev)
            Core.run(self)

        def solve(self, essid, passwordlist):
            res = []
            i = 0
            while i < len(passwordlist):
                res.extend(_cpyrit_stream.calc_pmklist(essid, passwordlist[i:i+8192]))
                i += 8192
            return tuple(res)

    for dev_idx in range(_cpyrit_stream.getDeviceCount()):        
        _avail_cores.append(('GPU', StreamCore, "AMD-Stream device #%i" % dev_idx, {'dev':dev_idx}))


class CPyrit(object):
    def __init__(self):
        self.inqueue = Queue.Queue()
        self.outbuffer = {}
        self.cv = threading.Condition()
        self.in_idx = 0
        self.out_idx = 0
        self.maxSize = 5
        self.cores = []

    # Snippet taken from ParallelPython
    def _detect_ncpus(self):
        """Detect the number of effective CPUs in the system"""
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

    def _autoconfig(self):
        ncpus = self._detect_ncpus()
        for coretype, coreclass, name, kwargs in _avail_cores:
            if coretype == 'GPU':
                self.cores.append(coreclass(self.inqueue, self._res_callback, name, **kwargs))
                ncpus -= 1
        coretype, coreclass, name, kwargs = _avail_cores[0]
        for i in xrange(ncpus):
            self.cores.append(coreclass(self.inqueue, self._res_callback, name, **kwargs))
    
    def _res_callback(self, wu_idx, results):
        self.cv.acquire()
        try:
            assert wu_idx not in self.outbuffer
            self.outbuffer[wu_idx] = results
            self.cv.notifyAll()
        finally:
            self.cv.release()
 
    def _check_cores(self):
        if len(self.cores) == 0:
            self._autoconfig()
        for core in self.cores:
            if not core.isAlive():
                raise SystemError, "A core has died unexpectedly."
    
    def availableCores(self):
        return tuple((c[2] for c in _avail_cores))
    
    def enqueue(self, essid, passwordlist, block=False):
        if type(essid) is not str:
            raise TypeError, "ESSID must be a string"
        if type(passwordlist) is not list:
            raise TypeError, "passwordlist must be a list"
        self.cv.acquire()
        try:
            if block:
                while self.inqueue.qsize() > self.maxSize:
                    self.cv.wait(0.5)
                    self._check_cores()
            self.inqueue.put((self.in_idx, (essid, passwordlist)))
            self.in_idx += 1;
        finally:
            self.cv.release()
        
    def dequeue(self, block=True, timeout=None):
        self.cv.acquire()
        try:
            assert self.out_idx <= self.in_idx
            if self.out_idx == self.in_idx or (self.out_idx not in self.outbuffer and not block):
                return None
            while self.out_idx not in self.outbuffer:
                self.cv.wait(0.5)
                self._check_cores()
                if timeout is not None and time.time() - t > timeout:
                    return None
            results = self.outbuffer.pop(self.out_idx)
            self.out_idx += 1
            return results
        finally:
            self.cv.release() 

    def __len__(self):
        return self.inqueue.qsize()

    def __iter__(self):
        while True:
            r = self.dequeue()
            if r is None:
                break
            yield r

