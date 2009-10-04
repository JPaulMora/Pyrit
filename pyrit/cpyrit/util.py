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

   AsyncFileWriter is used for threaded, buffered output.

   StorageIterator and PassthroughIterator encapsulate the repetitive task of
   getting workunits from the database, passing them to the hardware if
   necessary and yielding the results to a client.

   CowpattyWriter eases writing files in cowpatty's binary format.

   ncpus equals the number of available CPUs in the system.

   PMK_TESTVECTORS has two ESSIDs and ten password:PMK pairs each to verify
   local installations.
"""

from __future__ import with_statement

import cStringIO
import gzip
import os
import Queue
import sys
import threading

import _cpyrit_cpu
from _cpyrit_cpu import VERSION


def _detect_ncpus():
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

ncpus = _detect_ncpus()
""" Number of effective CPUs (in the moment the module was loaded)."""


def str2hex(string):
    """Convert a string to it's hex-decimal representation."""
    return ''.join('%02x' % c for c in map(ord, string))


class ScapyImportError(ImportError):
    """ ScapyImportError is used to indicate failure to import scapy's modules.
        Used to o separate other ImportErrors so code that tries to
        import pckttools can continue in case Scapy is simply not installed.
    """
    pass


class StorageIterator(object):
    """Iterates over the database, computes new Pairwise Master Keys if
       necessary and requested and yields tuples of (password,PMK)-tuples.
    """

    def __init__(self, storage, essid, \
                 yieldOldResults=True, yieldNewResults=True):
        self.cp = None
        self.workunits = []
        self.essid = essid
        self.storage = storage
        self.keys = iter(self.storage.passwords)
        self.len = len(self.storage.passwords)
        self.yieldOldResults = yieldOldResults
        self.yieldNewResults = yieldNewResults

    def __len__(self):
        return self.len

    def __iter__(self):
        return self

    def next(self):
        for key in self.keys:
            if self.storage.essids.containskey(self.essid, key):
                if self.yieldOldResults:
                    return self.storage.essids[self.essid, key]
                else:
                    self.len -= 1
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
                        solvedEssid, solvedKey, solvedPasswords = \
                            self.workunits.pop(0)
                        solvedResults = zip(solvedPasswords, solvedPMKs)
                        self.storage.essids[solvedEssid, solvedKey] = \
                            solvedResults
                        return solvedResults
        if self.yieldNewResults and self.cp is not None:
            for solvedPMKs in self.cp:
                solvedEssid, solvedKey, solvedPasswords = self.workunits.pop(0)
                solvedResults = zip(solvedPasswords, solvedPMKs)
                self.storage.essids[solvedEssid, solvedKey] = solvedResults
                return solvedResults
        raise StopIteration


class PassthroughIterator(object):
    """A iterator that takes an ESSID and an iterable of passwords, computes
       the corresponding Pairwise Master Keys and and yields tuples of
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


class FileReader(object):
    """A wrapper for easy stdin/gzip-reading"""

    def __init__(self, filename, mode='rb'):
        if isinstance(filename, str):
            if filename == '-':
                self.f = sys.stdin
            elif filename.endswith('.gz'):
                self.f = gzip.open(filename, mode)
            else:
                self.f = open(filename, mode)
        else:
            self.f = filename

    def close(self):
        self.f.close()
        
    def __enter__(self):
        return self
        
    def __exit__(self, type, value, traceback):
        self.close()
        
    def __iter__(self):
        return self.f.__iter__()


class CowpattyWriter(object):
    """A simple file-like object that writes (password,PMK)-tuples
       to a file or another file-like object in cowpatty's binary format.
    """

    def __init__(self, essid, f):
        self.f = open(f, 'wb') if isinstance(f, str) else f
        self.f.write("APWC\00\00\00" + \
                    chr(len(essid)) + essid + \
                    '\00' * (32 - len(essid)))

    def write(self, results):
        self.f.write(_cpyrit_cpu.genCowpEntries(results))

    def close(self):
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()


class AsyncFileWriter(threading.Thread):
    """A buffered, asynchronous file-like object.

       Writing to this object will only block if the internal buffer
       exceeded it's maximum size. The call to .write() is done in a seperate
       thread.
    """

    def __init__(self, f, maxsize=10 * 1024**2):
        """Create a instance writing to the given file-like-object and
           buffering maxsize before blocking.
        """
        threading.Thread.__init__(self)
        if isinstance(f, str):
            if f == '-':
                self.filehndl = sys.stdout
            elif f.endswith('gz'):
                self.filehndl = gzip.open(f, 'wb')
            else:
                self.filehndl = open(f, 'wb')
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
                raise RuntimeError("Writer has already been closed")
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        """Stop the writer and wait for it to finish.

           The file handle that was used for initialization is closed.
           Exceptions in the writer-thread are re-raised after the writer is
           closed.
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
                    raise RuntimeError("Writer has already been closed.")
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
            # Re-create a 'trans-thread-safe' instance
            self.excp = type(e)(str(e))
        finally:
            with self.cv:
                self.shallstop = self.hasstopped = True
                self.cv.notifyAll()


PMK_TESTVECTORS = {
    'foo': {
        'soZcEvntHVrGRDIxNaBCyUL':
            (247, 210, 173, 42, 68, 187, 144, 253, 145, 93, 126, 250, 16, 188,
             100, 55, 89, 153, 135, 155, 198, 86, 124, 33, 45, 16, 9, 54, 113,
             194, 159, 211),
        'EVuYtpQCAZzBXyWNRGTI':
            (5, 48, 168, 39, 10, 98, 151, 201, 8, 80, 23, 138, 19, 24, 24, 50,
             66, 214, 189, 180, 159, 97, 194, 27, 212, 124, 114, 100, 253, 62,
             50, 170),
        'XNuwoiGMnjlkxBHfhyRgZrJItFDqQVESm':
            (248, 208, 207, 115, 247, 35, 170, 203, 214, 228, 228, 21, 40, 214,
             165, 0, 98, 194, 136, 62, 110, 253, 69, 205, 67, 215, 119, 109,
             72, 226, 255, 199),
        'bdzPWNTaIol':
            (228, 236, 73, 0, 189, 244, 21, 141, 84, 247, 3, 144, 2, 164, 99,
             205, 37, 72, 218, 202, 182, 246, 227, 84, 24, 58, 147, 114, 206,
             221, 40, 127),
        'nwUaVYhRbvsH':
            (137, 21, 14, 210, 213, 68, 210, 123, 35, 143, 108, 57, 196, 47,
             62, 161, 150, 35, 165, 197, 154, 61, 76, 14, 212, 88, 125, 234,
             51, 38, 159, 208),
        'gfeuvPBbaDrQHldZzRtXykjFWwAhS':
            (88, 127, 99, 35, 137, 177, 147, 161, 244, 32, 197, 233, 178, 1,
             96, 247, 5, 109, 163, 250, 35, 222, 188, 143, 155, 70, 106, 1,
             253, 79, 109, 135),
        'QcbpRkAJerVqHz':
            (158, 124, 37, 190, 197, 150, 225, 165, 3, 34, 104, 147, 107, 253,
             233, 127, 33, 239, 75, 11, 169, 187, 127, 171, 187, 165, 166, 187,
             95, 107, 137, 212),
        'EbYJsCNiwXDmHtgkFVacuOv':
            (136, 5, 34, 189, 145, 60, 145, 54, 179, 198, 195, 223, 34, 180,
             144, 3, 116, 102, 39, 134, 68, 82, 210, 185, 190, 199, 36, 25,
             136, 152, 0, 111),
        'GpIMrFZwLcqyt':
            (28, 144, 175, 10, 200, 46, 253, 227, 219, 35, 98, 208, 220, 11,
             101, 95, 62, 244, 80, 221, 111, 49, 206, 255, 174, 100, 240, 240,
             33, 229, 172, 207),
        'tKxgswlaOMLeZVScGDW':
            (237, 62, 117, 60, 38, 107, 65, 166, 113, 174, 196, 221, 128, 227,
             69, 89, 23, 77, 119, 234, 41, 176, 145, 105, 92, 40, 157, 151,
             229, 50, 81, 65)},
    'bar': {
        'zLwSfveNskZoR':
            (38, 93, 196, 77, 112, 65, 163, 197, 249, 158, 180, 107, 231, 140,
             188, 60, 254, 77, 12, 210, 77, 185, 233, 59, 79, 212, 222, 181,
             44, 19, 127, 220),
        'lxsvOCeZXop':
            (91, 39, 98, 36, 82, 2, 162, 106, 12, 244, 4, 113, 155, 120, 131,
             133, 11, 209, 12, 12, 240, 213, 203, 156, 129, 148, 28, 64, 31,
             61, 162, 13),
        'tfHrgLLOA':
            (110, 72, 123, 80, 222, 233, 150, 54, 40, 99, 205, 155, 177, 157,
             174, 172, 87, 11, 247, 164, 87, 85, 136, 165, 21, 107, 93, 212,
             71, 133, 145, 211),
        'vBgsaSJrlqajUlQJM':
            (113, 110, 180, 150, 204, 221, 61, 202, 238, 142, 147, 118, 177,
             196, 65, 79, 102, 47, 179, 80, 175, 95, 251, 35, 227, 220, 47,
             121, 50, 125, 55, 16),
        'daDIHwIMKSUaKWXS':
            (33, 87, 211, 99, 26, 70, 123, 19, 254, 229, 148, 97, 252, 182, 3,
             44, 228, 125, 85, 141, 247, 223, 166, 133, 246, 37, 204, 145, 100,
             218, 66, 70),
        'agHOeAjOpK':
            (226, 163, 62, 215, 250, 63, 6, 32, 130, 34, 117, 116, 189, 178,
             245, 172, 74, 26, 138, 10, 106, 119, 15, 214, 210, 114, 51, 94,
             254, 57, 81, 200),
        'vRfEagJIzSohxsakj':
            (61, 71, 159, 35, 233, 27, 138, 30, 228, 121, 38, 201, 57, 83, 192,
             211, 248, 207, 149, 12, 147, 70, 190, 216, 52, 14, 165, 190, 226,
             180, 62, 210),
        'PuDomzkiwsejblaXs':
            (227, 164, 137, 231, 16, 31, 222, 169, 134, 1, 238, 190, 55, 126,
             255, 88, 178, 118, 148, 119, 244, 130, 183, 219, 124, 249, 194,
             96, 94, 159, 163, 185),
        'RErvpNrOsW':
            (24, 145, 197, 137, 14, 154, 1, 36, 73, 148, 9, 192, 138, 157, 164,
             81, 47, 184, 41, 75, 225, 34, 71, 153, 59, 253, 127, 179, 242,
             193, 246, 177),
        'ipptbpKkCCep':
            (81, 34, 253, 39, 124, 19, 234, 163, 32, 10, 104, 88, 249, 29, 40,
             142, 24, 173, 1, 68, 187, 212, 21, 189, 74, 88, 83, 228, 7, 100,
             23, 244)}}
for essid in PMK_TESTVECTORS:
    for pw in PMK_TESTVECTORS[essid]:
        PMK_TESTVECTORS[essid][pw] = \
                                ''.join(map(chr, PMK_TESTVECTORS[essid][pw]))
del essid
del pw
