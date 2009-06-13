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

import httplib
import hashlib
import os
import sys
import Queue
import time
import threading
import urllib2
import zlib

try:
    import _cpyrit
except ImportError:
    print >>sys.stderr, "Failed to load the internal _cpyrit module. Check your installation."
    raise

TV_ESSID = 'foo'
TV_PASSWD = 'barbarbar'
TV_PMK = (6,56,101,54,204,94,253,3,243,250,132,170,142,162,204,132,8,151,61,243,75,216,75,83,128,110,237,48,35,205,166,126)
def _testComputeFunction(func, i):
    for pmk in func(TV_ESSID, [TV_PASSWD]*i):
        if tuple(map(ord, pmk)) != TV_PMK:
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

    def _gather(self):
            essid_dict = {}
            while sum((len(pwlist) for pwlist,slices in essid_dict.itervalues())) < self.minBufferSize:
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
            for essid, (pwlist, slicelist) in essid_dict.iteritems():
                yield essid, pwlist, slicelist

    def run(self):
        while True:
            for essid, pwlist, slicelist in self._gather():
                t = time.time()
                results = self.solve(essid, pwlist)
                self.compTime += time.time() - t
                for wu_idx, start, length in slicelist:
                    self.callback(wu_idx, results[start:start+length])
                self.resCount += len(results)

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
        return _cpyrit_cpu.calc_pmklist(essid, passwordlist)

_avail_cores.append(('CPU', CPUCore, "CPU-Core (%s)" % _cpyrit_cpu.getPlatform(), {}))


## Try creating the CUDA-Core. Failure is acceptable.
try:
    from _cpyrit import _cpyrit_cuda
except ImportError:
    pass
except Exception, e:
    print >>sys.stderr, "Failed to load Pyrit's CUDA-driven core ('%s')." % e
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
        try:
            d = _cpyrit_cuda.CUDADevice(dev_idx)
            _testComputeFunction(d.calc_pmklist, 101)
        except Exception, e:
            print >>sys.stderr, "Failed to load CUDA-device '%s': '%s'" % (device[0], e)
        else:
            _avail_cores.append(('GPU', CUDACore, "CUDA-Device #%i '%s'" % (dev_idx+1,device[0]), {'dev':dev_idx}))


## Try creating the OpenCL-Core. Failure is acceptable.
try:
    from _cpyrit import _cpyrit_opencl
except ImportError:
    pass
except Exception, e:
    print >>sys.stderr, "Failed to load Pyrit's OpenCL-driven core ('%s')." % e
else:
    class OpenCLCore(Core):
        def __init__(self, inqueue, callback, name, dev):
            Core.__init__(self, inqueue, callback, name)
            self.OpenCLDev = _cpyrit_opencl.OpenCLDevice(dev)
            self.minBufferSize = 20480
            self.buffersize = 2048
            self.start()
            
        def solve(self, essid, passwordlist):
            res = []
            i = 0
            while i < len(passwordlist):
                t = time.time()
                pwslice = passwordlist[i:i+self.buffersize]
                res.extend(self.OpenCLDev.calc_pmklist(essid, pwslice))
                i += self.buffersize
                if len(pwslice) >= 2048:
                    self.buffersize = int(max(2048, min(20480, (2 * self.buffersize + (3.0 / (time.time() - t) * self.buffersize)) / 3)))
            return tuple(res)
    
    for dev_idx, device in enumerate(_cpyrit_opencl.listDevices()):
        if device[1] != 'NVIDIA Corporation' or '_cpyrit._cpyrit_cuda' not in sys.modules:
            try:
                d = _cpyrit_opencl.OpenCLDevice(dev_idx)
                _testComputeFunction(d.calc_pmklist, 101)
            except Exception, e:
                print >>sys.stderr, "Failed to load OpenCL-device '%s': '%s'" % (device[0], e)
            else:
                _avail_cores.append(('GPU', OpenCLCore, "OpenCL-Device #%i '%s'" % (dev_idx+1, device[0]), {'dev':dev_idx}))


## Try creating the Stream-Core. Failure is acceptable.
try:
    from _cpyrit import _cpyrit_stream
    _testComputeFunction(_cpyrit_stream.calc_pmklist, 101)
except ImportError:
    pass
except Exception, e:
    print >>sys.stderr, "Failed to load Pyrit's Stream-driven core ('%s')" % e
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
        try:
            d = _cpyrit_stream.StreamCore(dev_idx)
            _testComputeFunction(d.calc_pmklist, 101)
        except Exception, e:
            print >>sys.stderr, "Failed to load Stream-device '%s': '%s'" % (device[0], e)
        else:        
            _avail_cores.append(('GPU', StreamCore, "AMD-Stream device #%i" % dev_idx, {'dev':dev_idx}))


## Create Network-Cores as described in the config-file.
class NetworkCore(Core):
    def __init__(self, inqueue, callback, name, host):
        Core.__init__(self, inqueue, callback, name)
        self.minBufferSize = 20480
        self.host = host
        self.uuid = None
        self.start()
    
    def _enqueue_on_host(self, essid, pwlist):
        pwbuffer = zlib.compress('\n'.join(pwlist), 1)
        digest = hashlib.sha1()
        digest.update(essid)
        digest.update(pwbuffer)
        req = urllib2.urlopen('http://%s:19935/ENQUEUE?client=%s' % (self.host, self.uuid), digest.digest() + '\n'.join((essid, pwbuffer)))
        if req.code != httplib.OK:
            raise Exception, "Enqueue on host '%s' failed with status %s (%s)" % (self.host, req.code, req.msg)
        return int(req.read())
    
    def _dequeue_from_host(self):
        try:
            req = urllib2.urlopen('http://%s:19935/DEQUEUE?client=%s' % (self.host, self.uuid))
        except urllib2.HTTPError, e:
            if e.code == httplib.PROCESSING:
                return None
            else:
                raise
        if req.code == httplib.OK:
            buf = req.read()
            digest = hashlib.sha1()
            digest.update(buf[digest.digest_size:])
            if buf[:digest.digest_size] != digest.digest():
                raise Exception, "Digest check failed."
            buf = buf[digest.digest_size:]
            assert len(buf) % 32 == 0
            return [buf[i*32:i*32 + 32] for i in xrange(len(buf) / 32)]
        else:
            raise Exception, "Dequeue from host '%s' failed with status %s (%s)" % (self.host, req.code, req.msg)
    
    def run(self):
        workbuffer = []
        while True:
            try:
                req = urllib2.urlopen('http://%s:19935/REGISTER' % self.host)
            except urllib2.URLError, e:
                time.sleep(5)
            else:
                self.uuid = req.read()
                break
        self._enqueue_on_host(TV_ESSID, [TV_PASSWD]*101)
        while True:
            res = self._dequeue_from_host()
            if res is not None:
                break
        for pmk in res:
            if tuple(map(ord, pmk)) != TV_PMK:
                raise Exception, "Test-vector does not result in correct result."
        
        server_queue_length = 0
        while True:
            if server_queue_length < 3:
                for essid, pwlist, slicelist in self._gather():
                    workbuffer.append(slicelist)
                    server_queue_length = self._enqueue_on_host(essid, pwlist)
            if len(workbuffer) != 0:
                t = time.time()
                results = self._dequeue_from_host()
                self.compTime += time.time() - t
                if results is not None:
                    server_queue_length -= 1
                    for wu_idx, start, length in workbuffer.pop(0):
                        self.callback(wu_idx, results[start:start+length])
                    self.resCount += len(results)

hostfile = os.path.expanduser(os.path.join('~','.pyrit','hosts'))
if os.path.exists(hostfile):
    for host in set([host.strip() for host in open(hostfile, "r") if len(host.strip()) > 0 and not host.startswith('#')]):
        _avail_cores.append(('NET', NetworkCore, "Network-Core @%s" % (host), {'host': host}))
else:
    f = open(hostfile, "w")
    f.write('## List of known Pyrit-servers; one IP/hostname per line...\n'
            '## lines that start with # are ignored.\n')
    f.close()

## The CPyrit-class puts everything together...
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

    def _autoconfig(self, ignore_types=()):
        ncpus = self._detect_ncpus()
        for coretype, coreclass, name, kwargs in _avail_cores:
            if coretype not in ignore_types and coretype != 'CPU':
                self.cores.append(coreclass(self.inqueue, self._res_callback, name, **kwargs))
                if coretype == 'GPU':
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
                raise SystemError, "The core '%s' has died unexpectedly." % core
    
    def availableCores(self):
        self._check_cores()
        return tuple([core.name for core in self.cores])
    
    def enqueue(self, essid, passwordlist, block=False):
        self.cv.acquire()
        try:
            if block:
                while self.inqueue.qsize() > self.maxSize:
                    self.cv.wait(0.05)
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
            t = time.time()
            while self.out_idx not in self.outbuffer:
                self.cv.wait(0.05)
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

