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


from cpyrit import CPyrit
import zlib, hashlib, fcntl, StringIO, os, re, struct, random, threading

class Pyrit(object):
    """
    The Pyrit class is a further abstraction of general tasks from the blobspace class.
    The commandline-client and to-be-written GUIs are built upon this common codebase.
    """
    
    try:
        from pysqlite2 import dbapi2 as sqlite
    except:
        pass
    
    def __init__(self, essidstore_path='blobspace/essid', pwstore_path='blobspace/password'):
        self.pwstore = PasswordStore(pwstore_path)
        self.essidstore = EssidStore(essidstore_path)
        
    def import_password(self, password):
        self.pwstore.store_password(password)
        
    def import_passwords(self, fileobject):
        try:
            for line in fileobject.readlines():
                self.pwstore.store_password(line)
        finally:
            self.pwstore.flush_buffer()
    
    def export_passwords(self):
        for pw_idx, pwfile in reversed(list(enumerate(self.pwstore.passwords.values()))):
            f = PasswordFile(pwfile)
            s = set(f.yieldPassword())
            f.close()
            yield (pw_idx, s)
            
    def enum_results(self, essid):
        essid_obj = self.essidstore.open_essid(essid)
        for idx, result in reversed(list(enumerate(essid_obj.results))):
            pyr_obj = essid_obj.open_result(result)
            s = pyr_obj.results.items()
            pyr_obj.close()
            yield (idx, s)
    
    def export_cowpatty(self, essid):
        essid_obj = self.essidstore.open_essid(essid)
        idx = len(essid_obj.results) - 1
        yield((idx, struct.pack("<i", 0x43575041)))
        yield((idx, chr(0)*3))
        yield((idx, struct.pack("<b32s", len(essid_obj.essid), essid_obj.essid)))
        for idx, result in self.enum_results(essid):
            for r in result:
                yield (idx, struct.pack("<b%ss32s" % len(r[0]), len(r[0]) + 32 + 1, r[0], r[1]))
    
    def eval_results(self, essid=None):
        if essid is not None:
            if essid not in self.essidstore.essids:
                raise Exception, "ESSID parameter not in store."
            essid = [essid]
        else:
            essid = self.essidstore.essids
        for e_idx, essid_name in reversed(list(enumerate(essid))):
            essid_obj = self.essidstore.open_essid(essid_name)
            results = essid_obj.results
            pwcount = 0
            rescount = 0
            for pw in self.pwstore.passwords.keys():
                pwfile = PasswordFile(self.pwstore.passwords[pw])
                pws = set([x for x in pwfile.yieldPassword()])
                pwfile.close()
                pwcount += len(pws)
                
                if pw in results:
                    pyrfile = essid_obj.open_result(pw)
                    rescount += len(pws.intersection(set(pyrfile.results.keys())))
                    pyrfile.close()
                    
            yield (e_idx, essid_name, pwcount, rescount)
    
    def list_essids(self):
        return list(self.essidstore.essids)
        
    def list_passwords(self):
        return list(self.pwstore.passwords.keys())
        
    def open_essid(self, essid):
        return self.essidstore.open_essid(essid)
        
    def open_password(self, key):
        return self.pwstore.getPWFile(key)
    
    def create_essid(self, essid):
        if essid not in self.essidstore.essids:
            self.essidstore.create_essid(essid)
            
    def solve(self, essid, passwordlist, corename=None):
        """
        This function is only here for convenience-reasons. One should
        use the CPyrit himself and get a core there to avoid overhead.
        """
        return CPyrit().getCore(corename).solve(essid, passwordlist)

    if 'sqlite' in locals():
        def export_hashdb(self, essid, hashdbfile):
            con = self.sqlite.connect(hashdbfile)
            cur = con.cursor()
            try:
                cur.execute('INSERT OR IGNORE INTO essid (essid) VALUES (?)', (essid,))
                essid_id = cur.execute('SELECT essid_id FROM essid WHERE essid = ?', (essid,)).fetchone()[0]
                print "Reading..."
                cur.execute('CREATE TEMPORARY TABLE import (passwd_id int key, passwd text key, pmk blob)')
                for idx, result in self.enum_results(essid):
                    cur.executemany('INSERT INTO import (passwd, pmk) VALUES (?,?)', ((pw, buffer(res)) for pw,res in result))
                print "Updating references..."
                cur.execute('UPDATE import SET passwd_id = (SELECT passwd.passwd_id FROM passwd WHERE passwd.passwd = import.passwd)')
                print "Inserting..."
                cur.execute('INSERT INTO passwd (passwd) SELECT passwd FROM import WHERE passwd_id IS NULL')
                print "Updating again..."
                cur.execute('UPDATE import SET passwd_id = (SELECT passwd.passwd_id FROM passwd WHERE passwd.passwd = import.passwd) WHERE passwd_id IS NULL')
                print "Writing..."
                cur.execute('INSERT OR IGNORE INTO pmk (essid_id,passwd_id,pmk) SELECT ?, passwd_id, pmk FROM import', (essid_id,))
                cur.execute('DROP TABLE import')
                print "Done."
                con.commit()
            except:
                con.rollback()
                cur.close()
                con.close()
                print "There was an error while exporting. The database has not been modified..."
                raise
            cur.close()
            con.close()

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
            prehead = f.read(struct.calcsize(preheadfmt))
            if len(prehead) == 0:
                self.f = f
            else:
                magic,essidlen = struct.unpack(preheadfmt, prehead)
                if magic <> "PYRT":
                    raise Exception, "Oh no! It's not a pyrit binary file."
                infile_digest = hashlib.md5()
                nextheadfmt = "<%ssi%ss" % (essidlen,infile_digest.digest_size)
                essid, inplength, digest = struct.unpack(nextheadfmt, f.read(struct.calcsize(nextheadfmt)))
                assert essid == self.essid
                infile_digest.update(essid)

                pmkbuffer = []
                for p in xrange(inplength):
                    pmkbuffer.append(f.read(32))

                inp = zlib.decompress(f.read()).split("\00")

                map(infile_digest.update, pmkbuffer)
                map(infile_digest.update, inp)
                if infile_digest.digest() == digest:
                    results = zip(inp,pmkbuffer)
                    pick = random.choice(results)
                    assert CPyrit().getCore().solve(essid, pick[0]) == pick[1]
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
        raw_digest = hashlib.md5()
        raw_digest.update(self.essid)
        map(raw_digest.update, pmkbuffer)
        map(raw_digest.update, pwbuffer)
        headfmt = "<4sH%ssi%ss" % (len(self.essid),raw_digest.digest_size)
        self.f.write(struct.pack(headfmt, "PYRT", len(self.essid), self.essid, len(pmkbuffer), raw_digest.digest()))
        map(self.f.write, pmkbuffer)
        self.f.write(zlib.compress("\00".join(pwbuffer)))
        self.f.flush()
        fcntl.flock(self.f.fileno(), fcntl.LOCK_SH)

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
        return os.path.join(self.essidpath, hashlib.md5(essid).hexdigest()[:8])

    def refresh(self):
        essids = set()
        for essid_hash in os.listdir(self.essidpath):
            f = open(os.path.join(self.essidpath, essid_hash,'essid'),"rb")
            essid = f.read()
            f.close()
            if essid_hash == hashlib.md5(essid).hexdigest()[:8]:
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
            md = hashlib.md5()
            head = f.read(4)
            if len(head) > 0:
                assert head == "PAWD"
                digest = f.read(md.digest_size)
                inp = f.read().split("\00")
                map(md.update, inp)
                if self.pw_h1 is None:
                    self.pw_h1 = PasswordFile._pwdigest(inp[0])
                if digest == md.digest():
                    if len([x for x in random.sample(inp, min(5, len(inp))) if PasswordFile._pwdigest(x) != self.pw_h1]) <> 0:
                        raise Exception, "At least some passwords in file '%s' don't belong into this instance of type %s." % (filename, self.pw_h1)
                    if filename[-3-len(md.hexdigest()):-3] != md.hexdigest():
                        raise Exception, "File '%s' doesn't match the key '%s'." % (filename, md.hexdigest())
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
        md = hashlib.md5()
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
        md = hashlib.md5()
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

