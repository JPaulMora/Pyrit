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

import hashlib
import os
import struct
import zlib

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

