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


from zlib import compress,decompress
from md5 import md5
import fcntl
from struct import pack,unpack,calcsize
import StringIO
from random import choice
from cpyrit import CPyrit

class PyrFile(object):
    def __init__(self,essid,infile):
        self.results = {}
        self.essid = essid
        self.f = None
        self.openfile(infile)
        self.ccore = CPyrit()

    def close(self):
        if self.f is not None:
            fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
            self.f.close()
            self.f = None

    def openfile(self,infile):
        self.close()
        f = open(infile, "a+b")
        fcntl.flock(f.fileno(), fcntl.LOCK_SH)
        f.seek(0)
        try:
            preheadfmt = "<4sH"
            prehead = f.read(calcsize(preheadfmt))
            if len(prehead) == 0:
                self.f = f
            else:
                magic,essidlen = unpack(preheadfmt, prehead)
                if magic <> "PYRT":
                    raise Exception, "Oh no! It's not a pyrit binary file."
                infile_digest = md5()
                nextheadfmt = "<%ssi%ss" % (essidlen,infile_digest.digest_size)
                essid, inplength, digest = unpack(nextheadfmt,f.read(calcsize(nextheadfmt)))
                assert essid == self.essid
                infile_digest.update(essid)

                pmkbuffer = []
                for p in xrange(inplength):
                    pmkbuffer.append(f.read(32))

                inp = decompress(f.read()).split("\00")

                map(infile_digest.update, pmkbuffer)
                map(infile_digest.update, inp)
                if infile_digest.digest() == digest:
                    results = zip(inp,pmkbuffer)
                    pick = choice(results)
                    assert CPyrit().getCore().solve(essid,pick[0]) == pick[1]
                    self.essid = essid
                    self.results = dict(results)
                    self.f = f
                else:
                    raise Exception, "Digest check failed."
        except:
            print "Exception while opening PyrFile '%s', file not loaded." % infile
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            f.close()
            raise

    def savefile(self):
        if self.f is None:
            raise Exception, "No file opened."
        if self.essid is None or len(self.essid) == 0:
            raise Exception, "ESSID not set."
        fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
        self.f.truncate(0)
        pwbuffer,pmkbuffer = zip(*self.results.iteritems())
        raw_digest = md5()
        raw_digest.update(self.essid)
        map(raw_digest.update, pmkbuffer)
        map(raw_digest.update, pwbuffer)
        headfmt = "<4sH%ssi%ss" % (len(self.essid),raw_digest.digest_size)
        self.f.write(pack(headfmt, "PYRT", len(self.essid), self.essid, len(pmkbuffer), raw_digest.digest()))
        map(self.f.write, pmkbuffer)
        self.f.write(compress("\00".join(pwbuffer)))
        self.f.flush()
        fcntl.flock(self.f.fileno(), fcntl.LOCK_SH)
