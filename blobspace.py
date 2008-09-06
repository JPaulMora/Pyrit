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


from struct import pack,unpack,calcsize
from md5 import md5
import os
import fcntl
from time import time
from random import sample
from pyrfile import PyrFile
import re

class Callable:
    def __init__(self, anycallable):
        self.__call__ = anycallable

class ESSID(object):
    def __init__(self,path):
        self.path = path
        self.f = open(os.path.join(path,"essid"), "rb")
        fcntl.flock(self.f.fileno(), fcntl.LOCK_SH)
        self.essid = self.f.read()

    def __del__(self):
        self.close()

    def close(self):
        if self.f is not None:
            fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
            self.f.close()
            self.f = None
            self.path = None
            self.essid = None

    def refresh(self):
        if self.f is None:
            raise Exception, "ESSID not locked."
        return frozenset([x[:len(x)-4] for x in os.listdir(self.path) if x[-4:] == '.pyr'])

    def open_result(self, key):
        if self.f is None:
            raise Exception, "ESSID not locked."
        return PyrFile(self.essid, os.path.join(self.path, key+".pyr"))
 
    results = property(fget=refresh)

class EssidStore(object):
    def __init__(self,basepath):
        self.essidpath = basepath
        self.makedir(self.essidpath)

    def makedir(self,pathname):
        try:
            os.makedirs(pathname)
        except OSError, (errno, sterrno):
            if errno == 17:
                pass
            else:
                raise

    def _getessidroot(self,essid):
        return os.path.join(self.essidpath,md5(essid).hexdigest()[:8])

    def refresh(self):
        essids = set()
        for essid_hash in os.listdir(self.essidpath):
            f = open(os.path.join(self.essidpath, essid_hash,'essid'),"rb")
            essid = f.read()
            f.close()
            if essid_hash == md5(essid).hexdigest()[:8]:
                essids.add(essid)
            else:
                #pass
                print "ESSID %s seems to be corrupted." % essid_hash
        return frozenset(essids)

    def create_essid(self,essid):
        if len(essid) < 3 or len(essid) > 32:
            raise Exception, "ESSID invalid."
        essid_root = self._getessidroot(essid)
        self.makedir(essid_root)
        f = open(os.path.join(essid_root,'essid'),"wb")
        f.write(essid)
        f.close()

    def open_essid(self,essid):
        return ESSID(self._getessidroot(essid))

    essids = property(fget=refresh)

class PasswordFile(object):
    def _pwdigest(passwd):
        return "%02.2X" % (hash(passwd) & 0xFF)
    _pwdigest = Callable(_pwdigest)

    def __init__(self, filename):
        self.pw_h1 = None
        self.f = None
        self.bucket = set()

        f = open(filename, "a+b")
        fcntl.flock(f.fileno(), fcntl.LOCK_SH)
        f.seek(0)
        self.f = f
        try:
            inp = set()
            md = md5()
            head = f.read(4)
            if len(head) > 0:
                assert head == "PAWD"
                digest = f.read(md.digest_size)
                inp = f.read().split("\00")
                map(md.update, inp)
                if self.pw_h1 is None:
                    self.pw_h1 = PasswordFile._pwdigest(inp[0])
                if digest == md.digest():
                    if len([x for x in sample(inp, min(5,len(inp))) if PasswordFile._pwdigest(x) != self.pw_h1]) <> 0:
                        raise Exception, "At least some passwords in file '%s' don't belong into this instance of type %s." % (filename, self.pw_h1)
                    if filename[-3-len(md.hexdigest()):-3] != md.hexdigest():
                        raise Exception, "File '%s' doesn't match the key '%s'." % (filename,md.hexdigest())
                    self.bucket = frozenset(inp)
                else:
                    print "Digest check failed for %s" % filename
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    f.close()
                    self.f = None
        except:
            print "Exception while opening PasswordFile '%s', file not loaded." % filename
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            f.close()
            self.f = None
            raise

    def __del__(self):
        self.close()

    def close(self):
        if self.f is not None:
            fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
            self.f.close()
            self.f = None

    def yieldPassword(self):
        ret = set()
        for pw in self.bucket:
            for f in [str.lower, str.upper, str.capitalize]:
                ret.add(f(pw)[:63])
                for s in ["1","2","123"]:
                    ret.add(f(pw+s)[:63])
        for pw in ret:
            yield pw

    def savefile(self):
        if self.f is None:
            raise Exception, "No file opened."
        fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
        md = md5()
        b = list(self.bucket)
        map(md.update, b)
        self.f.truncate(0)
        self.f.write("PAWD")
        self.f.write(md.digest())
        self.f.write("\00".join(b))
        self.f.flush()
        fcntl.flock(self.f.fileno(), fcntl.LOCK_SH)

class PasswordStore(object):
    def __init__(self,basepath):
        self.passwdpath = basepath
        self.makedir(self.passwdpath)
        self.pwbuffer = {}
        self.pwpattern = re.compile("([a-zöäüß ]+)")

    def makedir(self,pathname):
        try:
            os.makedirs(pathname)
        except OSError, (errno, sterrno):
            if errno == 17:
                pass

    def refresh(self, pw_param=None):
        passwords = {}
        for pw_h1 in [x for x in os.listdir(self.passwdpath) if (pw_param is None or x == pw_param)]:
            for pw in [x for x in os.listdir(os.path.join(self.passwdpath,pw_h1)) if x[-3:] == '.pw']:
                passwords[pw[:len(pw)-3]] = os.path.join(self.passwdpath, pw_h1, pw)
        return passwords

    def getPWFile(self,pwid):
        return PasswordFile(self.passwords[pwid])

    def flush_bucket(self, bucket):
        if len(bucket) == 0:
            return
        pwlist = sorted(list(bucket))
        md = md5()
        map(md.update, pwlist)
        pw_h1 = PasswordFile._pwdigest(pwlist[0])
        assert all([PasswordFile._pwdigest(x) == pw_h1 for x in pwlist])
        if md.hexdigest() in self.refresh(pw_h1).keys():
            return

        pwset = set(bucket)
        for pwfile in self.refresh(pw_h1).values():
            f = PasswordFile(pwfile)
            pwset -= f.bucket
            f.close()
        if len(pwset) == 0:
            return

        destpath = os.path.join(self.passwdpath,pw_h1)
        self.makedir(destpath)

        f = PasswordFile(os.path.join(destpath, md.hexdigest() + ".pw"))
        f.bucket = pwlist
        f.savefile()
        f.close()

    def flush_buffer(self):
        for pw_h1 in self.pwbuffer.keys():
            pwbucket = list(self.pwbuffer[pw_h1])
            map(self.flush_bucket, [set(pwbucket[x:x+10000]) for x in xrange(0,len(pwbucket), 10000)])
        self.pwbuffer = {}

    def store_password(self,passwd):
        pwstrip = str(passwd).lower().strip()
        pwgroups = self.pwpattern.search(pwstrip)
        if pwgroups is None:
            #print "Password '%s'('%s') ignored." % (pwstrip,passwd)
            return
        pwstrip = pwgroups.groups()[0]

        if len(pwstrip) < 8 or len(pwstrip) > 63:
            #print "Password '%s'('%s') has invalid length." % (pwstrip,passwd)
            return

        pw_h1 = PasswordFile._pwdigest(pwstrip)
        pw_bucket = self.pwbuffer.setdefault(pw_h1, set())

        if pwstrip not in pw_bucket:
            pw_bucket.add(pwstrip)
            if len(pw_bucket) >= 10000:
                self.flush_bucket(pw_bucket)
                self.pwbuffer[pw_h1] = set()

    passwords = property(fget=refresh)
