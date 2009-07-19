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

"""The cpyrit module provides means to moderate hardware-access.
   
   Core is the base-class for standard-driven hardware modules.
   
   CPUCore, CUDACore, StreamCore, OpenCLCore and NetworkCore are subclasses of
   Core and provide access to their respective hardware-platforms. 
   
   CPyrit enumerates the available cores and schedules workunits among them.
"""

import BaseHTTPServer
import hashlib
import httplib
import os
import Queue
import SocketServer
import sys
import time
import threading
import uuid
import urlparse
import urllib2
import cpyrit_util as util

# Snippet taken from ParallelPython
def _detect_ncpus():
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


class Core(threading.Thread):
    """Core provides threaded scheduling and testing. It should not be used directly.
       
       Subclasses must mix-in a .solve()-function and the .buffersize
       attribute. The default .run() provided here calibrates itself to pull work
       from the queue worth 3 seconds of execution time in .solve() 
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
        self.name = "Unnamed Core"
        self.setDaemon(True)

    def _testComputeFunction(self, i):
        if any((pmk != Core.TV_PMK for pmk in self.solve(Core.TV_ESSID, [Core.TV_PASSWD]*i))):
            raise ValueError, "Test-vector does not result in correct PMK."
            
    def run(self):
        self._testComputeFunction(101)
        while True:
            essid, pwlist = self.queue._gather(self.buffersize)
            t = time.time()
            res = self.solve(essid, pwlist)
            self.compTime += time.time() - t
            self.resCount += len(res)
            self.callCount += 1
            self.buffersize = int(max(128, min(20480, (2 * self.buffersize + (self.resCount / self.compTime * 3.0)) / 3)))
            self.queue._scatter(essid, pwlist, res)

    def __str__(self):
        return self.name



## CPU
try:
    from _cpyrit import _cpyrit_cpu
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
    from _cpyrit import _cpyrit_cuda
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
            self.buffersize = 4096
            self.start()


## OpenCL
try:
    from _cpyrit import _cpyrit_opencl
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
            self.buffersize = 4096
            self.start()


## Stream
try:
    from _cpyrit import _cpyrit_stream
except ImportError:
    pass
except Exception, e:
    print >>sys.stderr, "Failed to load Pyrit's Stream-driven core ('%s')" % e
else:
    class StreamCore(Core, _cpyrit_stream.StreamDevice):
        """Computes results on ATI-Stream devices.
        
           Comes with it's own scheduling as the underlying implementation is
           fixed to a maximum input size; computes with fixed blocks of 8192 passwords.
        """
        def __init__(self, queue, dev_idx):
            Core.__init__(self, queue)
            _cpyrit_stream.StreamDevice.__init__(self)
            self.name = "ATI-Stream device %i" % (dev_idx+1)
            self.dev_idx = dev_idx
            self.start()

        def run(self):
            _cpyrit_stream.setDevice(self.dev_idx)
            self._testComputeFunction(101)
            while True:
                essid, pwlist = self.queue._gather(8192)
                t = time.time()
                res = self.solve(essid, pwlist)
                self.compTime += time.time() - t
                self.resCount += len(res)
                self.callCount += 1
                self.queue._scatter(essid, pwlist, res)


## Network
class NetworkCore(Core):
    def __init__(self, queue, host):
        Core.__init__(self, queue)
        self.name = "Network-Core @%s" % host
        self.buffersize = 20480
        self.host = host
        self.uuid = None
        self.start()
    
    def _enqueue_on_host(self, essid, pwlist):
        pwbuffer = '\n'.join(pwlist)
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
        self._enqueue_on_host(Core.TV_ESSID, [Core.TV_PASSWD]*101)
        while True:
            res = self._dequeue_from_host()
            if res is not None:
                break
        if any((pmk != Core.TV_PMK for pmk in res)):
            raise Exception, "Test-vector does not result in correct result."

        server_queue_length = 0
        while True:
            if server_queue_length < 50000:
                essid, pwlist = self.queue._gather(8192)
                workbuffer.append((essid, pwlist))
                server_queue_length = self._enqueue_on_host(essid, pwlist)
                self.callCount += 1
            t = time.time()
            results = self._dequeue_from_host()
            self.compTime += time.time() - t
            if results is not None:
                server_queue_length -= len(results)
                self.resCount += len(results)
                essid, pwlist = workbuffer.pop(0)
                self.queue._scatter(essid, pwlist, results)


class CPyrit(object):
    """Enumerates and manages all available hardware resources provided in
       the module and does most of the scheduling-magic.
       
       The class provides FIFO-scheduling of workunits towards the 'host'
       which can use .enqueue() and corresponding calls to .dequeue().
       Scheduling towards the hardware is provided by _gather(), _scatter() and
       _revoke().
    """
    def __init__(self, maxBufferSize=50000):
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
        self.maxBufferSize = maxBufferSize
        self.cores = []
        self.cv = threading.Condition()

        ncpus = _detect_ncpus()
        # CUDA
        if '_cpyrit._cpyrit_cuda' in sys.modules:
            for dev_idx, device in enumerate(_cpyrit_cuda.listDevices()):
                self.cores.append(CUDACore(queue=self, dev_idx=dev_idx))
                ncpus -= 1
        # OpenCL
        if '_cpyrit._cpyrit_opencl' in sys.modules:
            for dev_idx, device in enumerate(_cpyrit_opencl.listDevices()):
                if device[1] != 'NVIDIA Corporation' or '_cpyrit._cpyrit_cuda' not in sys.modules:
                    self.cores.append(OpenCLCore(queue=self, dev_idx=dev_idx))
                    ncpus -= 1
        # ATI
        if '_cpyrit._cpyrit_stream' in sys.modules:
            for dev_idx in xrange(_cpyrit_stream.getDeviceCount()):
                self.cores.append(StreamCore(queue=self, dev_idx=dev_idx))
                ncpus -= 1
        #CPUs
        for i in xrange(ncpus):
            self.cores.append(CPUCore(queue=self))
        #Network
        configpath = os.path.expanduser(os.path.join('~','.pyrit'))
        if not os.path.exists(configpath):
            os.makedirs(configpath)
        hostfile = os.path.join(configpath, 'hosts')
        if os.path.exists(hostfile):
            hosts = set()
            for host in open(hostfile, 'r'):
                if not host.startswith('#') and len(host.strip()) > 0:
                    hosts.add(host.strip())
            for host in hosts:
                self.cores.append(NetworkCore(queue=self, host=host))
        else:
            f = open(hostfile, 'w')
            f.write('## List of known Pyrit-servers; one IP/hostname per line...\n'
                    '## lines that start with # are ignored.\n')
            f.close()

    def _check_cores(self):
        for core in self.cores:
            if not core.isAlive():
                raise SystemError, "The core '%s' has died unexpectedly." % core

    def _len(self):
        return sum((sum((len(pwlist) for pwlist in pwdict.itervalues())) for essid, pwdict in self.inqueue))

    def __len__(self):
        """Returns the number of passwords that currently wait to be transfered
           to the hardware."""
        self.cv.acquire()
        try:
            return self._len()
        finally:
            self.cv.release()

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
        """Blocks until less than the given number of passwords wait to be scheduled
           to the hardware.
        """
        assert maxBufferSize >= 0
        self.cv.acquire()
        try:
            while self._len() > maxBufferSize:
                self.cv.wait(2)
                self._check_cores()
        finally:
            self.cv.release()

    def enqueue(self, essid, passwords, block=False):
        """Enqueues the given ESSID and iterable of passwords for processing.
           
           The call may block if block is True and the number of passwords
           currently waiting for being processed is higher than allowed for
           this instance.
           Calls to .dequeue() correspond in a FIFO-manner.
        """ 
        self.cv.acquire()
        try:
            if self.maxBufferSize and block:
                while self._len() > self.maxBufferSize:
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
        finally:
            self.cv.release()
        
    def dequeue(self, block=True, timeout=None):
        """Receives the results corresponding to previous calls to .enqueue().
           
           The function returns None if block is False and the respective results
           have not yet been completed. Otherwise the call blocks.
           The function may return None if block is True and the call waited longer
           than timeout.
           Calls to .enqueue() correspond in a FIFO-manner.
        """
        self.cv.acquire()
        t = time.time()
        try:
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
        finally:
            self.cv.release()
        
    def _gather(self, desired_size):
        """Try to accumulate the given number of passwords for a single ESSID
           in one workunit. Return a tuple containing the ESSID and a tuple of
           passwords.
           
           The call blocks if no work is available and may return less than the
           desired number of passwords. The caller should compute the corresponding
           results and call _scatter() or _revoke() with the (ESSID,passwords)-tuple
           returned by this call as parameters.
        """
        self.cv.acquire()
        try:
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
        finally:
            self.cv.release()

    def _scatter(self, essid, passwords, results):
        """Spray the given results back to their corresponding workunits.
           
           The caller must use the (ESSID,passwords)-tuple returned by _gather()
           to indicate which workunit it is returning results for.
        """
        assert len(results) == len(passwords)
        self.cv.acquire()
        try:
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
        finally:
            self.cv.release()

    def _revoke(self, essid, passwords):
        """Re-insert the given workunit back into the global queue so it may
           be processed by other Cores.
           
           Should be used if the Core that pulled the workunit is unable to
           process it. It is the Core's responsibility to ensure that it stops
           pulling work from the queue in such situations.
        """
        self.cv.acquire()
        try:
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
        finally:
            self.cv.release()

class PyritHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        self.parsed_path = urlparse.urlparse(self.path)
        self.params = {}
        if len(self.parsed_path.query) > 0:
            self.params.update([x.split('=') for x in self.parsed_path.query.split("&")])

        if self.parsed_path.path == "/":
            self.send_response(httplib.OK)
            self.end_headers()
            self.wfile.write('%s, started %s\n\nActive cores:\n' % (self.server.name, time.ctime(self.server.started)))
            for i, core in enumerate(self.server.cp.cores):
                self.wfile.write(" #%i '%s', did %i PMKs so far\n" % (i, core, core.resCount))
            self.wfile.write('\nActive clients:\n')
            for i, (name, joined, lastseen, inCount, outCount) in enumerate(self.server.getClientStats()):
                self.wfile.write(" #%i '%s'\n  Joined %s, last seen %s\n  %i passwords queued, %i processed\n\n" %
                                    (i, name, time.ctime(joined), time.ctime(lastseen), inCount, outCount))

        elif self.parsed_path.path == "/ENQUEUE":
            if 'client' not in self.params or self.params['client'] not in self.server.clients:
                self.send_response(httplib.FORBIDDEN)
                self.end_headers()
            else:
                buf = self.rfile.read(int(self.headers.getheader('Content-Length')))
                digest = hashlib.sha1()
                essid, pwbuffer = buf[digest.digest_size:].split('\n', 1)
                digest.update(essid)
                digest.update(pwbuffer)
                if digest.digest() != buf[:digest.digest_size]:
                    raise Exception, "Digest check failed."
                self.server.enqueue(self.params['client'], essid, pwbuffer.split('\n'))
                self.send_response(httplib.OK)
                self.end_headers()
                self.wfile.write(str(len(self.server)))

        elif self.parsed_path.path == "/DEQUEUE":
            if 'client' not in self.params or self.params['client'] not in self.server.clients:
                self.send_response(httplib.FORBIDDEN)
                self.end_headers()
            else:
                t = time.time()
                while True:
                    res = self.server.dequeue(self.params['client'])
                    if res is not None or time.time() - t > 3.0:
                        break
                    else:
                        time.sleep(0.1)
                if res is None:
                    self.send_response(httplib.PROCESSING)
                    self.end_headers()
                else:
                    buf = ''.join(res)
                    digest = hashlib.sha1()
                    digest.update(buf)
                    self.send_response(httplib.OK)
                    self.end_headers()
                    self.wfile.write(digest.digest())
                    self.wfile.write(buf)

        elif self.parsed_path.path == "/REGISTER":
            client = self.server.registerClient(self.client_address[0])
            self.send_response(httplib.OK)
            self.end_headers()
            self.wfile.write(client.uuid)

        else:
            self.send_response(httplib.NOT_FOUND)
            self.end_headers()
    do_POST = do_GET


class PyritServerCleaner(threading.Thread):
    def __init__(self, server):
        threading.Thread.__init__(self)
        self.server = server
        self.setDaemon(True)
        self.start()
        
    def run(self):
        while True:
            self.server.cv.acquire()
            try:
                for client_uuid, client in self.server.clients.items():
                    if time.time() - client.lastseen > 60:
                        del self.server.clients[client_uuid]
            finally:
                self.server.cv.release()
            time.sleep(15)


class PyritClient(object):
    def __init__(self, host):
        self.host = host
        self.uuid = str(uuid.uuid4())
        self.joined = self.lastseen = time.time()
        self.inCount = self.outCount = 0
        self.outQueue = []
        
    def __repr__(self):
        return '%s@%s' % (self.host, self.uuid)


class PyritServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    def __init__(self):
        BaseHTTPServer.HTTPServer.__init__(self, ('', 19935), PyritHandler)
        self.cp = CPyrit()
        self.started = time.time()
        self.clients = {}
        self.wu_clients = []
        self.cv = threading.Condition()
        self.name = "Pyrit %s" % util.VERSION
        self.cleaner = PyritServerCleaner(self)

    def registerClient(self, host):
        self.cv.acquire()
        try:
            client = PyritClient(host)
            self.clients[client.uuid] = client
            return client
        finally:
            self.cv.release()
    
    def getClientStats(self):
        self.cv.acquire()
        try:
            return tuple([(str(c), c.joined, c.lastseen, c.inCount, c.outCount) for c in self.clients.itervalues()])
        finally:
            self.cv.release()

    def enqueue(self, client_uuid, essid, passwordlist):
        assert self.cleaner.isAlive()
        self.cv.acquire()
        try:
            if client_uuid not in self.clients:
                raise KeyError, "Client not registered"
            client = self.clients[client_uuid]
            self.cp.enqueue(essid, passwordlist, block=False)
            self.wu_clients.append(client_uuid)
            client.lastseen = time.time()
            client.inCount += len(passwordlist)
        finally:
            self.cv.release()
        
    def dequeue(self, client_uuid):
        assert self.cleaner.isAlive()
        self.cv.acquire()
        try:
            if client_uuid not in self.clients:
                raise KeyError, "Client not registered"
            while True:
                results = self.cp.dequeue(block=False)
                if results is None:
                    break
                else:
                    wu_client_uuid = self.wu_clients.pop(0)
                    if wu_client_uuid in self.clients:
                        wu_client = self.clients[wu_client_uuid]
                        wu_client.outQueue.append(results)
                        wu_client.outCount += len(results)
            client = self.clients[client_uuid]
            client.lastseen = time.time()
            if len(client.outQueue) > 0:
                return client.outQueue.pop(0)
            else:
                return None
        finally:
            self.cv.release() 

    def __len__(self):
        self.cv.acquire()
        try:
            return len(self.cp)
        finally:
            self.cv.release()

