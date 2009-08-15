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

"""Abstracted hardware-access for Pyrit.
   
   Core is a base-class to glue hardware-modules into python.
   
   CPUCore, CUDACore, StreamCore, OpenCLCore and NetworkCore are subclasses of
   Core and provide access to their respective hardware-platforms. 
   
   CPyrit enumerates the available cores and schedules workunits among them.
"""

from __future__ import with_statement

import sys
import time
import threading
import util

class Core(threading.Thread):
    """The class Core provides basic scheduling and testing. It should not be used directly
       but through sub-classes.
       
       Subclasses must mix-in a .solve()-function and should set the .buffersize-,
       .minBufferSize- and .maxBufferSize-attributes. The default .run() provided
       here calibrates itself to pull work from the queue worth 3 seconds of
       execution time in .solve() 
    """ 
    TV_ESSID = 'foo'
    TV_PASSWD = 'barbarbar'
    TV_PMK = ''.join(map(chr, (6,56,101,54,204,94,253,3,243,250,132,170,142,162,204,132,8,
                                151,61,243,75,216, 75,83,128,110,237,48,35,205,166,126)))
    def __init__(self, queue):
        """Create a new Core that pulls work from the given CPyrit instance."""
        threading.Thread.__init__(self)
        self.queue = queue
        self.compTime = self.resCount = self.callCount = 0
        self.buffersize = 4096
        """Number of passwords currently pulled by calls to _gather()
           This number is dynamically adapted in run() but limited by .minBufferSize
           and .maxBufferSize.
        """
        self.minBufferSize = 128
        """Minimum number of passwords that will get pulled in one call to _gather."""
        self.maxBufferSize = 20480
        """Maximum number of passwords that will get pulled in one call to _gather."""
        self.setDaemon(True)

    def _testComputeFunction(self, i):
        if any((pmk != Core.TV_PMK for pmk in self.solve(Core.TV_ESSID, [Core.TV_PASSWD]*i))):
            raise ValueError, "Test-vector does not result in correct PMK."

    def resetStatistics(self):
        self.compTime = self.resCount = self.callCount = 0
            
    def run(self):
        self._testComputeFunction(101)
        while True:
            essid, pwlist = self.queue._gather(self.buffersize)
            t = time.time()
            res = self.solve(essid, pwlist)
            self.compTime += time.time() - t
            self.resCount += len(res)
            self.callCount += 1
            self.buffersize = int(max(self.minBufferSize, min(self.maxBufferSize, (2 * self.buffersize + (self.resCount / self.compTime * 3.0)) / 3)))
            self.queue._scatter(essid, pwlist, res)

    def __str__(self):
        return self.name


## CPU
try:
    import _cpyrit_cpu
except:
    print >>sys.stderr, "Failed to load Pyrit's CPU-driven core; this module should always be available. Sorry, we can't continue."
    raise
class CPUCore(Core, _cpyrit_cpu.CPUDevice):
    """Standard-CPU implementation. The underlying C-code may use VIA Padlock,
       SSE2 or a generic OpenSSL-interface to compute results."""
    def __init__(self, queue):
        Core.__init__(self, queue)
        _cpyrit_cpu.CPUDevice.__init__(self)
        self.buffersize = 512
        self.name = "CPU-Core (%s)" % _cpyrit_cpu.getPlatform()
        self.start()


## CUDA
try:
    import _cpyrit_cuda
    cpyrit_cuda_ver = getattr(_cpyrit_cuda, "VERSION", "unknown")
    if cpyrit_cuda_ver != util.VERSION:
        print >>sys.stderr, "WARNING: Version mismatch between main module ('%s') and CPyrit-CUDA ('%s')\n"\
                            % (util.VERSION, cpyrit_cuda_ver)
except ImportError:
    pass
except Exception, e:
    print >>sys.stderr, "Failed to load Pyrit's CUDA-driven core ('%s')." % e
else:
    class CUDACore(Core, _cpyrit_cuda.CUDADevice):
        """Computes results on Nvidia-CUDA capable devices."""
        def __init__(self, queue, dev_idx):
            Core.__init__(self, queue)
            _cpyrit_cuda.CUDADevice.__init__(self, dev_idx)
            self.name = "CUDA-Device #%i '%s'" % (dev_idx+1, self.deviceName)
            self.minBufferSize = 1024
            self.buffersize = 4096
            self.maxBufferSize = 40960
            self.start()


## OpenCL
try:
    import _cpyrit_opencl
    cpyrit_opencl_ver = getattr(_cpyrit_opencl, "VERSION", "unknown")
    if cpyrit_opencl_ver != util.VERSION:
        print >>sys.stderr, "WARNING: Version mismatch between main module ('%s') and CPyrit-OpenCL ('%s')\n"\
                            % (util.VERSION, cpyrit_opencl_ver)
except ImportError:
    pass
except Exception, e:
    print >>sys.stderr, "Failed to load Pyrit's OpenCL-driven core ('%s')." % e
else:
    class OpenCLCore(Core, _cpyrit_opencl.OpenCLDevice):
        """Computes results on OpenCL-capable devices."""
        def __init__(self, queue, dev_idx):
            Core.__init__(self, queue)
            _cpyrit_opencl.OpenCLDevice.__init__(self, dev_idx)
            self.name = "OpenCL-Device #%i '%s'" % (dev_idx+1, self.deviceName)
            self.minBufferSize = 1024
            self.buffersize = 4096
            self.maxBufferSize = 40960
            self.start()


## Stream
try:
    import _cpyrit_stream
    cpyrit_stream_ver = getattr(_cpyrit_stream, "VERSION", "unknown")
    if cpyrit_stream_ver != util.VERSION:
        print >>sys.stderr, "WARNING: Version mismatch between main module ('%s') and CPyrit-Stream ('%s')\n"\
                            % (util.VERSION, cpyrit_stream_ver)
except ImportError:
    pass
except Exception, e:
    print >>sys.stderr, "Failed to load Pyrit's Stream-driven core ('%s')" % e
else:
    class StreamCore(Core, _cpyrit_stream.StreamDevice):
        """Computes results on ATI-Stream devices."""
        def __init__(self, queue, dev_idx):
            Core.__init__(self, queue)
            _cpyrit_stream.StreamDevice.__init__(self)
            self.name = "ATI-Stream device %i" % (dev_idx+1)
            self.dev_idx = dev_idx
            self.maxBufferSize = 8192 # Capped by _cpyrit_stream
            self.start()

        def run(self):
            _cpyrit_stream.setDevice(self.dev_idx)
            Core.run(self)


## The Dummy-Device.
try:
    import _cpyrit_null
except ImportError:
    pass
else:
    class NullCore(Core, _cpyrit_null.NullDevice):
        """Dummy-Device that returns zero'ed results instead of PMKs. For testing and
           demonstration only...
        """
        def __init__(self, queue):
            raise RuntimeError, "The Null-Core should never get initialized!"
            Core.__init__(self, queue)
            _cpyrit_null.NullDevice.__init__(self)
            self.name = "Null-Core"
            self.start()


class CPyrit(object):
    """Enumerates and manages all available hardware resources provided in
       the module and does most of the scheduling-magic.
       
       The class provides FIFO-scheduling of workunits towards the 'host'
       which can use .enqueue() and corresponding calls to .dequeue().
       Scheduling towards the hardware is provided by _gather(), _scatter() and
       _revoke().
    """
    def __init__(self):
        """Create a new instance that blocks calls to .enqueue() when more than
           the given amount of passwords are currently waiting to be scheduled
           to the hardware.
        """
        self.inqueue = []
        self.outqueue = {}
        self.workunits = []
        self.slices = {}
        self.in_idx = 0
        self.out_idx = 0
        self.cores = []
        self.cv = threading.Condition()

        ncpus = util.ncpus
        # CUDA
        if 'cpyrit._cpyrit_cuda' in sys.modules:
            for dev_idx, device in enumerate(_cpyrit_cuda.listDevices()):
                self.cores.append(CUDACore(queue=self, dev_idx=dev_idx))
                ncpus -= 1
        # OpenCL
        if 'cpyrit._cpyrit_opencl' in sys.modules:
            for dev_idx, device in enumerate(_cpyrit_opencl.listDevices()):
                if device[1] != 'NVIDIA Corporation' or '_cpyrit._cpyrit_cuda' not in sys.modules:
                    self.cores.append(OpenCLCore(queue=self, dev_idx=dev_idx))
                    ncpus -= 1
        # ATI
        if 'cpyrit._cpyrit_stream' in sys.modules:
            for dev_idx in xrange(_cpyrit_stream.getDeviceCount()):
                self.cores.append(StreamCore(queue=self, dev_idx=dev_idx))
                ncpus -= 1
        #CPUs
        for i in xrange(ncpus):
            self.cores.append(CPUCore(queue=self))

    def _check_cores(self):
        for core in self.cores:
            if not core.isAlive():
                raise SystemError, "The core '%s' has died unexpectedly." % core

    def _len(self):
        return sum((sum((len(pwlist) for pwlist in pwdict.itervalues())) for essid, pwdict in self.inqueue))

    def __len__(self):
        """Return the number of passwords that currently wait to be transfered
           to the hardware."""
        with self.cv:
            return self._len()

    def __iter__(self):
        """Iterates over all pending results. Blocks until no further workunits
           or results are currently queued.
        """
        while True:
            r = self.dequeue(block=True)
            if r is None:
                break
            yield r
            
    def waitForSchedule(self, maxBufferSize):
        """Block until less than the given number of passwords wait for being scheduled
           to the hardware.
        """
        assert maxBufferSize >= 0
        with self.cv:
            while self._len() > maxBufferSize:
                self.cv.wait(2)
                self._check_cores()
            
    def resetStatistics(self):
        """Reset all cores' statistics"""
        for core in self.cores:
            core.resetStatistics()

    def getPeakPerformance(self):
        """Return the summed peak performance of all cores.
        
           The number returned is based on the performance all cores would have
           with 100% occupancy. The real performance is lower if the caller fails
           to keep the pipeline filled.
        """
        return sum([(core.resCount / core.compTime) for core in self.cores if core.compTime])

    def enqueue(self, essid, passwords, block=True):
        """Enqueue the given ESSID and iterable of passwords for processing.
           
           The call may block if block is True and the number of passwords
           currently waiting for being scheduled to the hardware is higher than
           five times the current peak performance.
           Calls to .dequeue() correspond in a FIFO-manner.
        """
        with self.cv:
            if self._len() > 0:
                while self.getPeakPerformance() == 0 or self._len() > self.getPeakPerformance() * 5:
                    self.cv.wait(2)
                    self._check_cores()
            passwordlist = list(passwords)
            if len(self.inqueue) > 0 and self.inqueue[-1][0] == essid:
                self.inqueue[-1][1][self.in_idx] = passwordlist
            else:
                self.inqueue.append((essid, {self.in_idx: passwordlist}))
            self.workunits.append(len(passwordlist))
            self.in_idx += len(passwordlist)
            self.cv.notifyAll()
        
    def dequeue(self, block=True, timeout=None):
        """Receive the results corresponding to a previous call to .enqueue().
           
           The function returns None if block is False and the respective results
           have not yet been completed. Otherwise the call blocks.
           The function may return None if block is True and the call waited longer
           than timeout.
           Calls to .enqueue() correspond in a FIFO-manner.
        """
        t = time.time()
        with self.cv:
            if len(self.workunits) == 0:
                return
            while True:
                wu_length = self.workunits[0]
                if self.out_idx not in self.outqueue or len(self.outqueue[self.out_idx]) < wu_length:
                    self._check_cores()
                    if block:
                        if timeout:
                            while time.time() - t > timeout:
                                self.cv.wait(0.1)
                                if self.out_idx in self.outqueue and len(self.outqueue[self.out_idx]) >= wu_length:
                                    break
                            else:
                                return None
                        else:
                            self.cv.wait(3)
                    else:
                        return None
                else:
                    reslist = self.outqueue[self.out_idx]
                    del self.outqueue[self.out_idx]
                    results = reslist[:wu_length]
                    self.out_idx += wu_length
                    self.outqueue[self.out_idx] = reslist[wu_length:]
                    self.workunits.pop(0)
                    self.cv.notifyAll()
                    return tuple(results)
        
    def _gather(self, desired_size):
        """Try to accumulate the given number of passwords for a single ESSID
           in one workunit. Return a tuple containing the ESSID and a tuple of
           passwords.
           
           The call blocks if no work is available and may return less than the
           desired number of passwords. The caller should compute the corresponding
           results and call _scatter() or _revoke() with the (ESSID,passwords)-tuple
           returned by this call as parameters.
        """
        with self.cv:
            passwords = []
            pwslices = []
            cur_essid = None
            restsize = desired_size
            while True:
                self._check_cores()
                for essid, pwdict in self.inqueue:
                    for idx, pwslice in sorted(pwdict.items()):
                        if len(pwslice) > 0:
                            if cur_essid is None:
                                cur_essid = essid
                            elif cur_essid != essid:
                                break
                            newslice = pwslice[:restsize]
                            del pwdict[idx]
                            if len(pwslice[len(newslice):]) > 0:
                                pwdict[idx+len(newslice)] = pwslice[len(newslice):]
                            pwslices.append((idx, len(newslice)))
                            passwords.extend(newslice)
                            restsize -= len(newslice)
                            if restsize <= 0:
                                break
                    if len(pwdict) == 0:
                        self.inqueue.remove((essid,pwdict))
                    if restsize <= 0:
                        break
                if len(passwords) > 0:
                    wu = (cur_essid, tuple(passwords))
                    try:
                        self.slices[wu].append(pwslices)
                    except KeyError:
                        self.slices[wu] = [pwslices]
                    self.cv.notifyAll()
                    return wu
                else:
                    self.cv.wait(3)

    def _scatter(self, essid, passwords, results):
        """Spray the given results back to their corresponding workunits.
           
           The caller must use the (ESSID,passwords)-tuple returned by _gather()
           to indicate which workunit it is returning results for.
        """
        assert len(results) == len(passwords)
        with self.cv:
            wu = (essid, passwords)
            slices = self.slices[wu].pop(0)
            if len(self.slices[wu]) == 0:
                del self.slices[wu]
            ptr = 0
            for idx, length in slices:
                self.outqueue[idx] = list(results[ptr:ptr+length])
                ptr += length
            for idx in sorted(self.outqueue.iterkeys(), reverse=True)[1:]:
                res = self.outqueue[idx]
                o_idx = idx + len(res)
                if o_idx in self.outqueue:
                    res.extend(self.outqueue[o_idx])
                    del self.outqueue[o_idx]
            self.cv.notifyAll()

    def _revoke(self, essid, passwords):
        """Re-insert the given workunit back into the global queue so it may
           be processed by other Cores.
           
           Should be used if the Core that pulled the workunit is unable to
           process it. It is the Core's responsibility to ensure that it stops
           pulling work from the queue in such situations.
        """
        with self.cv:
            wu = (essid, passwords)
            slices = self.slices[wu].pop()
            if len(self.slices[wu]) == 0:
                del self.slices[wu]
            passwordlist = list(passwords)
            if len(self.inqueue) > 0 and self.inqueue[0][0] == essid:
                d = self.inqueue[0][1]
            else:
                d = {}
                self.inqueue.insert(0, (essid, d))
            ptr = 0
            for idx, length in slices:
                d[idx] = passwordlist[ptr:ptr+length]
                ptr += length
            self.cv.notifyAll()

