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

"""Various utility- and backend- related classes and data for Pyrit.

   EssidStore and PasswordStore are the primary storage classes. Details of
   their implementation are reasonably well hidden behind the concept of
   key:value interaction.
   
   AsyncFileWriter is used for threaded, buffered output.
   
   StorageIterator and PassthroughIterator encapsulate the repetitive task of
   getting workunits from the database, passing them to the hardware if necessary
   and yielding the results to a client.
   
   CowpattyWriter eases writing files in cowpatty's binary format.
   
   ncpus equals the number of available CPUs in the system.
   
   PMK_TESTVECTORS has two ESSIDs and ten password:PMK pairs each to verify
   local installations.
"""

from __future__ import with_statement

import cStringIO
import gzip
import hashlib
import itertools
import os
import Queue
import struct
import sys
import threading
import zlib

import _util
from _util import VERSION

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

ncpus = _detect_ncpus()
""" Number of effective CPUs (in the moment the module was loaded)."""

def str2hex(string):
    """Convert a string to it's hex-decimal representation."""
    return ''.join('%02x' % c for c in map(ord, string))


class ScapyImportError(ImportError):
    """ ScapyImportError is used to indicate failure to import scapy's modules.
        It's main use is to separate other ImportErrors so code that tries to
        import pckttools can continue in case Scapy is simply not installed.
    """
    pass


class StorageIterator(object):
    """Iterates over the database, computes new Pairwise Master Keys if necessary
       and requested and yields tuples of (password,PMK)-tuples.
    """
    def __init__(self, storage, essid, yieldOldResults=True, yieldNewResults=True):
        self.cp = None
        self.workunits = []
        self.essid = essid
        self.storage = storage
        self.keys = iter(list(self.storage.passwords))
        self.yieldOldResults = yieldOldResults
        self.yieldNewResults = yieldNewResults
        
    def __iter__(self):
        return self
        
    def next(self):
        for key in self.keys:
            if self.storage.essids.containskey(self.essid, key):
                if self.yieldOldResults:
                    return self.storage.essids[self.essid, key]
            else:
                if self.yieldNewResults:
                    if self.cp is None:
                        import cpyrit
                        self.cp = cpyrit.CPyrit()
                    passwords = self.storage.passwords[key]
                    self.workunits.append((self.essid, key, passwords))
                    self.cp.enqueue(self.essid, passwords)
                    solvedPMKs = self.cp.dequeue(block=False)
                    if solvedPMKs is not None:
                        solvedEssid, solvedKey, solvedPasswords = self.workunits.pop(0)
                        solvedResults = zip(solvedPasswords, solvedPMKs)
                        self.storage.essids[solvedEssid, solvedKey] = solvedResults
                        return solvedResults
        if self.yieldNewResults and self.cp is not None:
            for solvedPMKs in self.cp:
                solvedEssid, solvedKey, solvedPasswords = self.workunits.pop(0)
                solvedResults = zip(solvedPasswords, solvedPMKs)
                self.storage.essids[solvedEssid, solvedKey] = solvedResults
                return solvedResults
        raise StopIteration


class PassthroughIterator(object):
    """A iterator that takes an ESSID and an iterable of passwords, computes the
       corresponding Pairwise Master Keys and and yields tuples of
       (password,PMK)-tuples.
    """
    def __init__(self, essid, iterable, buffersize=20000):
        import cpyrit
        self.cp = cpyrit.CPyrit()
        self.essid = essid
        self.iterator = iter(iterable)
        self.workunits = []
        self.buffersize = buffersize

    def __iter__(self):
        return self
        
    def next(self):
        pwbuffer = []
        for line in self.iterator:
            pw = line.strip()[:63]
            if len(pw) >= 8:
                pwbuffer.append(pw)
            if len(pwbuffer) > self.buffersize:
                self.workunits.append(pwbuffer)
                self.cp.enqueue(self.essid, self.workunits[-1])
                pwbuffer = []
                solvedPMKs = self.cp.dequeue(block=False)
                if solvedPMKs is not None:
                    return zip(self.workunits.pop(0), solvedPMKs)
        if len(pwbuffer) > 0:
            self.workunits.append(pwbuffer)
            self.cp.enqueue(self.essid, self.workunits[-1])
        for solvedPMKs in self.cp:
            return zip(self.workunits.pop(0), solvedPMKs)
        raise StopIteration


class CowpattyWriter(object):
    """ A simple file-like object that writes (password,PMK)-tuples
        to a file or another file-like object in cowpatty's binary format.
    """
    def __init__(self, essid, f):
        self.f = open(f, 'wb') if isinstance(f, str) else f
        self.f.write("APWC\00\00\00" + chr(len(essid)) + essid + '\00'*(32-len(essid)))
        
    def write(self, results):
        self.f.write(_util.genCowpEntries(results))
        
    def close(self):
        self.f.close()

    def __enter__(self):
        return self
    
    def __exit__(self, type, value, traceback):
        self.close()


class AsyncFileWriter(threading.Thread):
    """A buffered, asynchronous file-like object.
    
       Writing to this object will only block if the internal buffer
       exceeded it's maximum size. The call to .write() is done in a seperate thread.
    """ 
    def __init__(self, f, maxsize=10*1024**2):
        """Create a instance writing to the given file-like-object and buffering
           maxsize before blocking."""
        threading.Thread.__init__(self)
        if isinstance(f, str):
            if f == '-':
                self.filehndl = sys.stdout
            else:
                self.filehndl = gzip.open(f, 'wb') if f.endswith('.gz') else open(f, 'wb')
        else:
            self.filehndl = f
        self.shallstop = False
        self.hasstopped = False
        self.maxsize = maxsize
        self.excp = None
        self.buf = cStringIO.StringIO()
        self.cv = threading.Condition()
        self.start()
    
    def __enter__(self):
        with self.cv:
            if self.shallstop:
                raise RuntimeError,"Writer has already been closed"
        return self
    
    def __exit__(self, type, value, traceback):
        self.close()
        
    def close(self):
        """Stop the writer and wait for it to finish.
        
           The file handle that was used for initialization is closed.
           Exceptions in the writer-thread are re-raised after the writer is closed.
        """
        with self.cv:
            self.shallstop = True
            self.cv.notifyAll()
            while not self.hasstopped:
                self.cv.wait()
            self.filehndl.close()
            self._raise()

    def write(self, data):
        """Write data to the buffer, block if necessary.
        
           Exceptions in the writer-thread are re-raised in the caller's thread
           before the data is written.
        """
        with self.cv:
            self._raise()
            while self.buf.tell() > self.maxsize:
                self.cv.wait()
                if self.shallstop:
                    raise RuntimeError, "Writer has already been closed."
            self.buf.write(data)
            self.cv.notifyAll()
            
    def closeAsync(self):
        """Signal the writer to stop and return to caller immediately.
        
           The file handle that was used for initialization is not closed by a
           call to closeAsync().
           The caller must call join() before trying to close the file handle
           to prevent this instance from writing to a closed file handle.
           Exceptions are not re-raised.
        """
        with self.cv:
            self.shallstop = True
            self.cv.notifyAll()
    
    def join(self):
        """Wait for the writer to stop.
        
           Exceptions in the writer-thread are re-raised in the caller's thread
           after writer has stopped.
        """
        with self.cv:
            while not self.hasstopped:
                self.cv.wait()
            self._raise()

    def _raise(self):
        # Assumes we hold self.cv
        if self.excp:
            e = self.excp
            self.excp = None
            self.shallstop = True
            self.cv.notifyAll()
            raise e

    def run(self):
        try:
            while True:
                with self.cv:
                    data = None
                    if self.buf.tell() == 0:
                        if self.shallstop:
                            break
                        else:
                            self.cv.wait()
                    else:
                        data = self.buf.getvalue()
                        self.buf = cStringIO.StringIO()
                        self.cv.notifyAll()
                if data:
                    self.filehndl.write(data)
            self.filehndl.flush()
        except Exception, e:
            self.excp = type(e)(str(e)) # Re-create a 'trans-thread-safe' instance
        finally:
            with self.cv:
                self.shallstop = self.hasstopped = True
                self.cv.notifyAll()


class Storage(object):
    def __init__(self, basepath=os.path.expanduser(os.path.join('~','.pyrit','blobspace'))):
        self.essids = EssidStore(os.path.join(basepath, 'essid'))
        self.passwords = PasswordStore(os.path.join(basepath, 'password'))

    def iterresults(self, essid):
        return self.essids.iterresults(essid)
        
    def iterpasswords(self):
        return self.passwords.iterpasswords()


class EssidStore(object):
    """Storage-class responsible for ESSID and PMKs.
    
       Callers can use the iterator to cycle over available ESSIDs.
       Results are indexed by keys and returned as iterables of tuples. The keys may be
       received from .iterkeys() or from PasswordStore.
    """
    _pyr_preheadfmt = '<4sH'
    _pyr_preheadfmt_size = struct.calcsize(_pyr_preheadfmt)
    def __init__(self, basepath):
        self.basepath = basepath
        if not os.path.exists(self.basepath):
            os.makedirs(self.basepath)
        self.essids = {}
        for essid_hash in os.listdir(self.basepath):
            essidpath = os.path.join(self.basepath, essid_hash)
            with open(os.path.join(essidpath, 'essid'), 'rb') as f:
                essid = f.read()
            if essid_hash == hashlib.md5(essid).hexdigest()[:8]:
                self.essids[essid] = (essidpath, {})
                for pyrfile in [p for p in os.listdir(essidpath) if p[-4:] == '.pyr']:
                    self.essids[essid][1][pyrfile[:len(pyrfile)-4]] = os.path.join(essidpath, pyrfile)
            else:
                print >>sys.stderr, "ESSID %s seems to be corrupted." % essid_hash

    def __getitem__(self, (essid, key)):
        """Receive a iterable of (password,PMK)-tuples stored under
           the given ESSID and key.
           
           Returns a empty iterable if the key is not stored. Raises a KeyError
           if the ESSID is not stored.
        """
        if not self.containskey(essid, key):
            return ()
        try:
            with open(self.essids[essid][1][key], 'rb') as f:
                buf = f.read()
            md = hashlib.md5()
            magic, essidlen = struct.unpack(EssidStore._pyr_preheadfmt, buf[:EssidStore._pyr_preheadfmt_size])
            if magic == 'PYR2' or magic == 'PYRT':
                headfmt = "<%ssi%ss" % (essidlen, md.digest_size)
                headsize = struct.calcsize(headfmt)
                file_essid, numElems, digest = struct.unpack(headfmt, buf[EssidStore._pyr_preheadfmt_size:EssidStore._pyr_preheadfmt_size+headsize])
                if file_essid != essid:
                    raise IOError, "ESSID in result-file mismatches."
                pmkoffset = EssidStore._pyr_preheadfmt_size + headsize
                pwoffset = pmkoffset + numElems * 32
                md.update(file_essid)
                if magic == 'PYR2':
                    md.update(buf[pmkoffset:])
                    if md.digest() != digest:
                        raise IOError, "Digest check failed on PYR2-file '%s'." % filename
                    results = tuple(zip(zlib.decompress(buf[pwoffset:]).split('\n'),
                                  [buf[pmkoffset + i*32:pmkoffset + i*32 + 32] for i in xrange(numElems)]))
                elif magic == 'PYRT':
                    pmkbuffer = buf[pmkoffset:pwoffset]
                    assert len(pmkbuffer) % 32 == 0
                    md.update(pmkbuffer)
                    pwbuffer = zlib.decompress(buf[pwoffset:]).split('\00')
                    assert len(pwbuffer) == numElems
                    md.update(''.join(pwbuffer))
                    if md.digest() != digest:
                        raise IOError, "Digest check failed on PYRT-file '%s'." % filename
                    results = tuple(zip(pwbuffer, [pmkbuffer[i*32:i*32+32] for i in xrange(numElems)]))
            else:
                raise IOError, "File-format for '%s' unknown." % filename
            if len(results) != numElems:
                raise IOError, "Header announced %i results but %i unpacked" % (numElems, len(results))
            return results
        except:
            print >>sys.stderr, "Error while loading results %s for ESSID '%s'" % (key, essid)
            raise
    
    def __setitem__(self, (essid, key), results):
        """Store a iterable of (password,PMK)-tuples under the given ESSID and key."""
        if essid not in self.essids:
            raise KeyError, "ESSID not in store."
        pws, pmks = zip(*results)
        pwbuffer = zlib.compress('\n'.join(pws), 1)
        # Sanity check. Accept keys coming from PAWD- and PAW2-format.
        if hashlib.md5(pwbuffer).hexdigest() != key and hashlib.md5(''.join(pws)).hexdigest() != key:
            raise ValueError, "Results and key mismatch."
        pmkbuffer = ''.join(pmks)
        md = hashlib.md5()
        md.update(essid)
        md.update(pmkbuffer)
        md.update(pwbuffer)        
        filename = os.path.join(self.essids[essid][0], key) + '.pyr'
        with open(filename, 'wb') as f:
            f.write(struct.pack('<4sH%ssi%ss' % (len(essid), md.digest_size), 'PYR2', len(essid), essid, len(pws), md.digest()))
            f.write(pmkbuffer)
            f.write(pwbuffer)
        self.essids[essid][1][key] = filename
        
    def __len__(self):
        """Return the number of ESSIDs currently stored."""
        return len(self.essids)

    def __iter__(self):
        """Iterate over all essids currently stored."""
        return sorted(self.essids).__iter__()
            
    def __contains__(self, essid):
        """Return True if the given ESSID is currently stored."""
        return essid in self.essids

    def __delitem__(self, essid):
        """Delete the given ESSID and all results from the storage."""
        if essid not in self:
            raise KeyError, "ESSID not in store."
        essid_root, pyrfiles = self.essids[essid]
        del self.essids[essid]
        for fname in pyrfiles.itervalues():
            os.unlink(fname)
        os.unlink(os.path.join(essid_root, 'essid'))
        os.rmdir(essid_root)

    def containskey(self, essid, key):
        """Return True if the given (ESSID,key) combination is stored."""
        if essid not in self.essids:
            raise KeyError, "ESSID not in store."
        return key in self.essids[essid][1]

    def keys(self, essid):
        """Returns a collection of keys that can currently be used to receive results
           for the given ESSID.
        """
        if essid not in self.essids:
            raise KeyError, "ESSID not in store."
        return frozenset(self.essids[essid][1])
        
    def iterresults(self, essid):
        """Iterate over all results currently stored for the given ESSID."""
        for key in self.keys(essid):
            yield self[essid, key]

    def iteritems(self, essid):
        """Iterate over all keys and results currently stored for the given ESSID."""
        for key in self.keys(essid):
            yield (key, self[essid, key])

    def create_essid(self, essid):
        """Create the given ESSID in the storage.
        
           Re-creating a ESSID is a no-op.
        """
        if len(essid) < 1 or len(essid) > 32:
            raise ValueError, "ESSID invalid."
        essid_root = os.path.join(self.basepath, hashlib.md5(essid).hexdigest()[:8])
        if not os.path.exists(essid_root):
            os.makedirs(essid_root)
            with open(os.path.join(essid_root, 'essid'), 'wb') as f:
                f.write(essid)
            self.essids[essid] = (essid_root, {})


class PasswordStore(object):
    """Storage-class responsible for passwords.
    
       Passwords are indexed by keys and are returned as iterables.
       The iterator cycles over all available keys.
    """
    h1_list = ["%02.2X" % i for i in xrange(256)]
    del i
    def __init__(self, basepath):
        self.basepath = basepath
        if not os.path.exists(self.basepath):
            os.makedirs(self.basepath)
        self.pwbuffer = {}
        self.pwfiles = {}
        for pw_h1 in os.listdir(self.basepath):
            if pw_h1 not in PasswordStore.h1_list:
                continue
            pwpath = os.path.join(self.basepath, pw_h1)
            for pwfile in os.listdir(pwpath):
                if pwfile[-3:] != '.pw':
                    continue
                self.pwfiles[pwfile[:len(pwfile)-3]] = pwpath

    def __contains__(self, key):
        """Return True if the given key is currently in the storage."""
        return key in self.pwfiles

    def __iter__(self):
        """Iterate over all keys that can be used to receive password-sets."""
        return self.pwfiles.keys().__iter__()

    def __len__(self):
        """Return the number of keys that can be used to receive password-sets."""
        return len(self.pwfiles)

    def __getitem__(self, key):
        """Return the collection of passwords indexed by the given key.""" 
        filename = os.path.join(self.pwfiles[key], key) + '.pw'
        with open(filename, 'rb') as f:
            buf = f.read()
        if buf[:4] == "PAW2":
            md = hashlib.md5()
            md.update(buf[4+md.digest_size:])
            if md.digest() != buf[4:4+md.digest_size]:
                raise IOError, "Digest check failed for %s" % filename
            if md.hexdigest() != key:
                raise IOError, "File '%s' doesn't match the key '%s'." % (filename, md.hexdigest())
            return tuple(zlib.decompress(buf[4+md.digest_size:]).split('\n'))
        elif buf[:4] == "PAWD":
            md = hashlib.md5()
            inp = tuple(buf[4+md.digest_size:].split('\00'))
            md.update(''.join(inp))
            if buf[4:4+md.digest_size] != md.digest():
                raise IOError, "Digest check failed for %s" % filename
            if filename[-3-md.digest_size*2:-3] != key:
                raise IOError, "File '%s' doesn't match the key '%s'." % (filename, md.hexdigest())
            return inp
        else:
            raise IOError, "'%s' is not a PasswordFile." % filename

    def iterkeys(self):
        """Equivalent to self.__iter__"""
        return self.__iter__()
    
    def iterpasswords(self):
        """Iterate over all available passwords-sets."""
        for key in self:
            yield self[key]

    def iteritems(self):
        """Iterate over all keys and password-sets."""
        for key in self:
            yield (key, self[key])

    def _flush_bucket(self, pw_h1, bucket):
        if len(bucket) == 0:
            return
        for key, pwpath in self.pwfiles.iteritems():
            if pwpath.endswith(pw_h1):
                bucket.difference_update(self[key])
                if len(bucket) == 0:
                    return
        pwpath = os.path.join(self.basepath, pw_h1)
        if not os.path.exists(pwpath):
            os.makedirs(pwpath)
        b = zlib.compress('\n'.join(sorted(bucket)), 1)
        md = hashlib.md5(b)
        key = md.hexdigest()
        with open(os.path.join(pwpath, key) + '.pw', 'wb') as f:
            f.write('PAW2')
            f.write(md.digest())
            f.write(b)
        self.pwfiles[key] = pwpath

    def flush_buffer(self):
        """Flush all passwords currently buffered to the storage.
           
           For efficiency reasons this function should not be called if the
           caller wants to add more passwords in the foreseeable future.
        """
        for pw_h1, pw_bucket in self.pwbuffer.iteritems():
            self._flush_bucket(pw_h1, pw_bucket)
            self.pwbuffer[pw_h1] = set()

    def store_password(self, passwd):
        """Add the given password to storage. The implementation ensures that
           passwords remain unique over the entire storage.
           
           Passwords passed to this function are buffered in memory for better
           performance and efficiency. It is the caller's responsibility to
           call .flush_buffer() when he is done.
        """
        passwd = passwd.strip()
        if len(passwd) < 8 or len(passwd) > 63:
            return
        pw_h1 = PasswordStore.h1_list[hash(passwd) & 0xFF]
        pw_bucket = self.pwbuffer.setdefault(pw_h1, set())
        pw_bucket.add(passwd)
        if len(pw_bucket) >= 20000:
            self._flush_bucket(pw_h1, pw_bucket)
            self.pwbuffer[pw_h1] = set()


PMK_TESTVECTORS = {
    'foo': {
        'soZcEvntHVrGRDIxNaBCyUL': (247,210,173,42,68,187,144,253,145,93,126,250,16,188,100,55,89,153,135,155,198,86,124,33,45,16,9,54,113,194,159,211),
        'EVuYtpQCAZzBXyWNRGTI': (5,48,168,39,10,98,151,201,8,80,23,138,19,24,24,50,66,214,189,180,159,97,194,27,212,124,114,100,253,62,50,170),
        'XNuwoiGMnjlkxBHfhyRgZrJItFDqQVESm': (248,208,207,115,247,35,170,203,214,228,228,21,40,214,165,0,98,194,136,62,110,253,69,205,67,215,119,109,72,226,255,199),
        'bdzPWNTaIol': (228,236,73,0,189,244,21,141,84,247,3,144,2,164,99,205,37,72,218,202,182,246,227,84,24,58,147,114,206,221,40,127),
        'nwUaVYhRbvsH': (137,21,14,210,213,68,210,123,35,143,108,57,196,47,62,161,150,35,165,197,154,61,76,14,212,88,125,234,51,38,159,208),
        'gfeuvPBbaDrQHldZzRtXykjFWwAhS': (88,127,99,35,137,177,147,161,244,32,197,233,178,1,96,247,5,109,163,250,35,222,188,143,155,70,106,1,253,79,109,135),
        'QcbpRkAJerVqHz': (158,124,37,190,197,150,225,165,3,34,104,147,107,253,233,127,33,239,75,11,169,187,127,171,187,165,166,187,95,107,137,212),
        'EbYJsCNiwXDmHtgkFVacuOv': (136,5,34,189,145,60,145,54,179,198,195,223,34,180,144,3,116,102,39,134,68,82,210,185,190,199,36,25,136,152,0,111),
        'GpIMrFZwLcqyt': (28,144,175,10,200,46,253,227,219,35,98,208,220,11,101,95,62,244,80,221,111,49,206,255,174,100,240,240,33,229,172,207),
        'tKxgswlaOMLeZVScGDW': (237,62,117,60,38,107,65,166,113,174,196,221,128,227,69,89,23,77,119,234,41,176,145,105,92,40,157,151,229,50,81,65)
        },
    'bar': {
        'zLwSfveNskZoR': (38,93,196,77,112,65,163,197,249,158,180,107,231,140,188,60,254,77,12,210,77,185,233,59,79,212,222,181,44,19,127,220),
        'lxsvOCeZXop': (91,39,98,36,82,2,162,106,12,244,4,113,155,120,131,133,11,209,12,12,240,213,203,156,129,148,28,64,31,61,162,13),
        'tfHrgLLOA': (110,72,123,80,222,233,150,54,40,99,205,155,177,157,174,172,87,11,247,164,87,85,136,165,21,107,93,212,71,133,145,211),
        'vBgsaSJrlqajUlQJM': (113,110,180,150,204,221,61,202,238,142,147,118,177,196,65,79,102,47,179,80,175,95,251,35,227,220,47,121,50,125,55,16),
        'daDIHwIMKSUaKWXS': (33,87,211,99,26,70,123,19,254,229,148,97,252,182,3,44,228,125,85,141,247,223,166,133,246,37,204,145,100,218,66,70),
        'agHOeAjOpK': (226,163,62,215,250,63,6,32,130,34,117,116,189,178,245,172,74,26,138,10,106,119,15,214,210,114,51,94,254,57,81,200),
        'vRfEagJIzSohxsakj': (61,71,159,35,233,27,138,30,228,121,38,201,57,83,192,211,248,207,149,12,147,70,190,216,52,14,165,190,226,180,62,210),
        'PuDomzkiwsejblaXs': (227,164,137,231,16,31,222,169,134,1,238,190,55,126,255,88,178,118,148,119,244,130,183,219,124,249,194,96,94,159,163,185),
        'RErvpNrOsW': (24,145,197,137,14,154,1,36,73,148,9,192,138,157,164,81,47,184,41,75,225,34,71,153,59,253,127,179,242,193,246,177),
        'ipptbpKkCCep': (81,34,253,39,124,19,234,163,32,10,104,88,249,29,40,142,24,173,1,68,187,212,21,189,74,88,83,228,7,100,23,244)
        }
    }
for essid in PMK_TESTVECTORS:
    for pw in PMK_TESTVECTORS[essid]:
        PMK_TESTVECTORS[essid][pw] = ''.join(map(chr, PMK_TESTVECTORS[essid][pw]))
del essid
del pw

