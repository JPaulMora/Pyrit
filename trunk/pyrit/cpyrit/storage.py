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

"""EssidStore and PasswordStore are the primary storage classes. Details of
   their implementation are reasonably well hidden behind the concept of
   key:value interaction.

"""

from __future__ import with_statement

import hashlib
import os
import random
import struct
import sys
import zlib

import util

try:
    import sqlalchemy as sql
except ImportError:
    pass
else:
    from sqlalchemy import orm


def getStorage(url):
    if not '://' in url:
        raise ValueError("URL must be of form [protocol]://" \
                         "[connection-string]")
    protocol, conn = url.split('://', 1)
    if protocol == 'file':
        return FSStorage(url)
    elif protocol == 'network':
        raise RuntimeError("Yada yada yada")
    elif protocol in ('sqlite', 'mysql', 'postgres', 'oracle', 'mssql', \
                      'firebird'):
        if 'sqlalchemy' not in sys.modules:
            raise util.SqlalchemyImportError()
        return SQLStorage(url)
    else:
        raise RuntimeError("The protocol '%s' is unsupported." % protocol)


class ResultCollection(object):
    """A abstract collection of (Password,PMK)-tuples"""

    def __init__(self, essid=None, results=None):
        self.results = results
        self.essid = essid

    def __iter__(self):
        return self.results.__iter__()

    def __len__(self):
        return len(self.results)


class PasswordCollection(object):
    """An abstract collection of passwords."""

    def __init__(self, collection=None):
        if collection is not None:
            self.collection = sorted(collection)

    def __len__(self):
        return len(self.collection)

    def __iter__(self):
        return self.collection.__iter__()


class BasePYR_Buffer(object):
    """The common parts of the PYRT- and PYR2-binary format."""
    pyr_head = '<4sH'
    pyr_len = struct.calcsize(pyr_head)

    def unpack(self, buf):
            md = hashlib.md5()
            magic, essidlen = struct.unpack(self.pyr_head, buf[:self.pyr_len])
            if magic == 'PYR2':
                delimiter = '\n'
            elif magic == 'PYRT':
                delimiter = '\00'
            else:
                raise ValueError("Not a PYRT- or PYR2-buffer.")
            headfmt = "<%ssi%ss" % (essidlen, md.digest_size)
            headsize = struct.calcsize(headfmt)
            header = struct.unpack(headfmt, \
                                   buf[self.pyr_len:self.pyr_len + headsize])
            self.essid, numElems, digest = header
            pmkoffset = self.pyr_len + headsize
            pwoffset = pmkoffset + numElems * 32
            pmkbuffer = buf[pmkoffset:pwoffset]
            if len(pmkbuffer) % 32 != 0:
                raise RuntimeError("pmkbuffer seems truncated")
            pwbuffer = zlib.decompress(buf[pwoffset:]).split(delimiter)
            if len(pwbuffer) != numElems:
                raise RuntimeError("Wrong number of elements")
            md.update(self.essid)
            if magic == 'PYR2':
                md.update(buf[pmkoffset:])
            else:
                md.update(pmkbuffer)
                md.update(''.join(pwbuffer))
            if md.digest() != digest:
                raise IOError("Digest check failed")
            results = []
            for i in xrange(numElems):
                results.append((pwbuffer[i], pmkbuffer[i*32:i*32+32]))
            self.results = tuple(results)


class PYRT_Buffer(ResultCollection, BasePYR_Buffer):
    pass


class PYR2_Buffer(ResultCollection, BasePYR_Buffer):

    def pack(self):
        pws, pmks = zip(*self.results)
        pwbuffer = zlib.compress('\n'.join(pws), 1)
        pmkbuffer = ''.join(pmks)
        md = hashlib.md5()
        md.update(self.essid)
        md.update(pmkbuffer)
        md.update(pwbuffer)
        essidlen = len(self.essid)
        b = struct.pack('<4sH%ssi%ss' % (essidlen, md.digest_size), 'PYR2', \
                        essidlen, self.essid, len(pws), md.digest())
        return b + pmkbuffer + pwbuffer


class PAWD_Buffer(PasswordCollection):

    def unpack(self, buf):
        if buf[:4] != "PAWD":
            raise ValueError("Not a PAWD-buffer.")
        md = hashlib.md5()
        inp = tuple(buf[4 + md.digest_size:].split('\00'))
        md.update(''.join(inp))
        if buf[4:4 + md.digest_size] != md.digest():
            raise IOError("Digest check failed.")
        self.collection = inp
        self.key = md.hexdigest()


class PAW2_Buffer(PasswordCollection):

    def pack(self):
        b = zlib.compress('\n'.join(self.collection), 1)
        md = hashlib.md5(b)
        self.key = md.hexdigest()
        return (md.hexdigest(), 'PAW2' + md.digest() + b)

    def unpack(self, buf):
        if buf[:4] != "PAW2":
            raise ValueError("Not a PAW2-buffer.")
        md = hashlib.md5()
        md.update(buf[4 + md.digest_size:])
        if md.digest() != buf[4:4 + md.digest_size]:
            raise IOError("Digest check failed.")
        inp = tuple(zlib.decompress(buf[4 + md.digest_size:]).split('\n'))
        self.collection = inp
        self.key = md.hexdigest()


class ESSIDStore(object):
    """Storage-class responsible for ESSID and PMKs.

       Callers can use the iterator to cycle over available ESSIDs.
       Results are indexed by keys and returned as iterables of tuples. The
       keys may be received from .iterkeys() or from PasswordStore.
    """

    def iterresults(self, essid):
        """Iterate over all results currently stored for the given ESSID."""
        for key in self.iterkeys(essid):
            yield self[essid, key]

    def iteritems(self, essid):
        """Iterate over all keys and results currently stored for the given
           ESSID.
        """
        for key in self.iterkeys(essid):
            yield (key, self[essid, key])


class PasswordStore(object):
    """Storage-class responsible for passwords.

       Passwords are indexed by keys and are returned as iterables.
       The iterator cycles over all available keys.
    """
    h1_list = ["%02.2X" % i for i in xrange(256)]
    del i

    def __init__(self):
        self.pwbuffer = {}

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


class FSStorage(object):
    """Storage-class that uses the filesystem

       Connection strings must be in the form of file://...
       The special character '~' is automatically expanded to the user's
       home directory.
    """

    def __init__(self, url):
        if not url.startswith('file://'):
            raise ValueError("Connection-string must be of form 'file://'")
        path = url.split('file://')[1]
        if path == '':
            path = os.path.join('~', '.pyrit', 'blobspace')
        path = os.path.expanduser(path)
        self.essids = FSEssidStore(os.path.join(path, 'essid'))
        self.passwords = FSPasswordStore(os.path.join(path, 'password'))

    def iterresults(self, essid):
        return self.essids.iterresults(essid)

    def iterpasswords(self):
        return self.passwords.iterpasswords()


class FSEssidStore(ESSIDStore):

    def __init__(self, basepath):
        ESSIDStore.__init__(self)
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
                for pyrfile in os.listdir(essidpath):
                    if pyrfile.endswith('.pyr'):
                        self.essids[essid][1][pyrfile[:len(pyrfile)-4]] = \
                                            os.path.join(essidpath, pyrfile)
            else:
                print >>sys.stderr, "ESSID %s is corrupted." % essid_hash

    def __getitem__(self, (essid, key)):
        """Receive a iterable of (password,PMK)-tuples stored under
           the given ESSID and key.

           Returns a empty iterable if the key is not stored. Raises KeyError
           if the ESSID is not stored.
        """
        if not self.containskey(essid, key):
            return ()
        try:
            with open(self.essids[essid][1][key], 'rb') as f:
                buf = f.read()
            if buf.startswith('PYR2'):
                results = PYR2_Buffer()
            elif buf.startswith('PYRT'):
                results = PYRT_Buffer()
            else:
                raise IOError("File-format for '%s' unknown." % filename)
            results.unpack(buf)
            if results.essid != essid:
                raise RuntimeError("Invalid ESSID in result-collection")
            return results
        except:
            print >>sys.stderr, "Error while loading results %s for " \
                                "ESSID '%s'" % (key, essid)
            raise

    def __setitem__(self, (essid, key), results):
        """Store a iterable of (password,PMK)-tuples under the given
           ESSID and key.
        """
        if essid not in self.essids:
            raise KeyError("ESSID not in store.")
        filename = os.path.join(self.essids[essid][0], key) + '.pyr'
        with open(filename, 'wb') as f:
            f.write(PYR2_Buffer(essid, results).pack())
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
            raise KeyError("ESSID not in store.")
        essid_root, pyrfiles = self.essids[essid]
        del self.essids[essid]
        for fname in pyrfiles.itervalues():
            os.unlink(fname)
        os.unlink(os.path.join(essid_root, 'essid'))
        os.rmdir(essid_root)

    def containskey(self, essid, key):
        """Return True if the given (ESSID,key) combination is stored."""
        if essid not in self.essids:
            raise KeyError("ESSID not in store.")
        return key in self.essids[essid][1]

    def keycount(self, essid):
        """Returns the number of keys that can currently be used to receive
           results for the given ESSID.
        """
        if essid not in self.essids:
            raise KeyError("ESSID not in store.")
        return len(self.essids[essid][1])

    def iterkeys(self, essid):
        """Iterate over all keys that can be used to receive results."""
        if essid not in self.essids:
            raise KeyError("ESSID not in store.")
        return tuple(self.essids[essid][1]).__iter__()

    def create_essid(self, essid):
        """Create the given ESSID in the storage.

           Re-creating a ESSID is a no-op.
        """
        if len(essid) < 1 or len(essid) > 32:
            raise ValueError("ESSID invalid.")
        root = os.path.join(self.basepath, hashlib.md5(essid).hexdigest()[:8])
        if not os.path.exists(root):
            os.makedirs(root)
            with open(os.path.join(root, 'essid'), 'wb') as f:
                f.write(essid)
            self.essids[essid] = (root, {})


class FSPasswordStore(PasswordStore):

    def __init__(self, basepath):
        PasswordStore.__init__(self)
        self.basepath = basepath
        if not os.path.exists(self.basepath):
            os.makedirs(self.basepath)
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
        """Return the number of keys that can be used to receive
           password-sets.
        """
        return len(self.pwfiles)

    def __getitem__(self, key):
        """Return the collection of passwords indexed by the given key."""
        filename = os.path.join(self.pwfiles[key], key) + '.pw'
        try:
            with open(filename, 'rb') as f:
                buf = f.read()
            if buf[:4] == "PAW2":
                inp = PAW2_Buffer()
            elif buf[:4] == "PAWD":
                inp = PAWD_Buffer()
            else:
                raise IOError("'%s' is not a PasswordFile." % filename)
            inp.unpack(buf)
            if inp.key != key:
                raise IOError("File doesn't match the key '%s'." % inp.key)
        except:
            print >>sys.stdout, "Error while opening '%s'" % filename
            raise
        return inp

    def size(self, key):
        """Return the number of passwords indexed by the given key."""
        return len(self[key])

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
        key, b = PAW2_Buffer(bucket).pack()
        with open(os.path.join(pwpath, key) + '.pw', 'wb') as f:
            f.write(b)
        self.pwfiles[key] = pwpath


if 'sqlalchemy' in sys.modules:
    metadata = sql.MetaData()

    essids_table = sql.Table('essids', metadata, \
                        sql.Column('essid_id', sql.Integer, primary_key=True),
                        sql.Column('essid', sql.Binary(32), nullable=False),
                        sql.Column('uid', sql.String(32), unique=True, \
                                    nullable=False), \
                        mysql_engine='InnoDB')

    passwords_table = sql.Table('passwords', metadata, \
                        sql.Column('_key', sql.String(32), primary_key=True),
                        sql.Column('h1', sql.String(2), nullable=False),
                        sql.Column('numElems', sql.Integer, nullable=False),
                        sql.Column('collection_buffer', sql.Binary(2**24-1), \
                                   nullable=False), \
                        mysql_engine='InnoDB')

    results_table = sql.Table('results', metadata, \
                        sql.Column('_key', sql.String(32), \
                                   sql.ForeignKey('passwords._key'), \
                                   primary_key=True),
                        sql.Column('essid_id', sql.Integer, \
                                   sql.ForeignKey('essids.essid_id'), \
                                   primary_key=True),
                        sql.Column('numElems', sql.Integer, nullable=False),
                        sql.Column('results_buffer', sql.Binary(2**24-1), \
                                   nullable=False), \
                        mysql_engine='InnoDB')

    class ESSID_DBObject(object):

        def __init__(self, essid):
            if len(essid) < 1 or len(essid) > 32:
                raise ValueError("ESSID invalid")
            self.essid = essid
            self.uid = hashlib.md5(essid).hexdigest()

        def __str__(self):
            return str(self.essid)


    class PAW2_DBObject(object):

        def __init__(self, h1, collection):
            self.h1 = h1
            self.collection = tuple(collection)
            self.numElems = len(self.collection)
            key, collection_buffer = PAW2_Buffer(self.collection).pack()
            self.key, self.collection_buffer = key, collection_buffer

        def __len__(self):
            return self.numElems

        def __iter__(self):
            if not hasattr(self, 'collection'):
                self.collection = PAW2_Buffer()
                self.collection.unpack(self.collection_buffer)
                assert len(self.collection) == self.numElems
            return self.collection.__iter__()


    class PYR2_DBObject(object):

        def __init__(self, essid_obj, key, results):
            self.essid = essid_obj
            self.results = tuple(results)
            self.key = key
            self.pack(results)

        def pack(self, results):
            self.numElems = len(results)
            self.results_buffer = PYR2_Buffer(str(self.essid), results).pack()

        def __len__(self):
            return self.numElems

        def __iter__(self):
            if not hasattr(self, 'results'):
                self.results = PYR2_Buffer()
                self.results.unpack(self.results_buffer)
                assert len(self.results) == self.numElems
            return self.results.__iter__()


    orm.mapper(ESSID_DBObject, \
               essids_table, \
               properties={'results': orm.relation(PYR2_DBObject, \
                                          backref='essid', \
                                          cascade='all,delete,delete-orphan')})
    orm.mapper(PAW2_DBObject, \
               passwords_table, \
               properties={'results': orm.relation(PYR2_DBObject, \
                                          cascade='all,delete,delete-orphan'),
                           '_key': orm.synonym('key', map_column=True)})
    orm.mapper(PYR2_DBObject, \
               results_table, \
               properties={'_key': orm.synonym('key', map_column=True)})


    class SessionContext(object):
        """A wrapper around classes given by sessionmake to add a
          context-manager.
        """

        def __init__(self, SessionClass):
            self.session = SessionClass()

        def __enter__(self):
            return self.session

        def __exit__(self, type, value, traceback):
            if type is not None:
                self.session.rollback()
            self.session.close()


    class SQLStorage(object):

        def __init__(self, url):
            engine = sql.create_engine(url, echo=False)
            metadata.create_all(engine)
            self.SessionClass = orm.sessionmaker(bind=engine)
            self.essids = SQLEssidStore(self.SessionClass)
            self.passwords = SQLPasswordStore(self.SessionClass)

        def iterresults(self, essid):
            return self.essids.iterresults(essid)

        def iterpasswords(self):
            return self.passwords.iterpasswords()


    class SQLEssidStore(ESSIDStore):

        def __init__(self, session_class):
            ESSIDStore.__init__(self)
            self.SessionClass = session_class

        def __contains__(self, essid):
            """Return True if the given ESSID is currently stored."""
            with SessionContext(self.SessionClass) as session:
                q = session.query(ESSID_DBObject)
                return q.filter(ESSID_DBObject.essid == essid).count() == 1

        def __iter__(self):
            """Iterate over all essids currently stored."""
            with SessionContext(self.SessionClass) as session:
                essids = session.query(ESSID_DBObject.essid)
            return (str(c[0]) for c in essids)

        def __len__(self):
            """Return the number of ESSIDs currently stored."""
            with SessionContext(self.SessionClass) as session:
                return session.query(ESSID_DBObject).count()

        def __getitem__(self, (essid, key)):
            """Receive a iterable of (password,PMK)-tuples stored under
               the given ESSID and key.

               Returns a empty iterable if the key is not stored. Raises
               KeyError if the ESSID is not stored.
            """
            with SessionContext(self.SessionClass) as session:
                q = session.query(PYR2_DBObject).join(ESSID_DBObject)
                result = q.filter(sql.and_(ESSID_DBObject.essid == essid, \
                                           PYR2_DBObject.key == key)).first()
                if result is None:
                    return ()
                else:
                    return result

        def __setitem__(self, (essid, key), results):
            """Store a iterable of (password,PMK)-tuples under the given
               ESSID and key.
            """
            with SessionContext(self.SessionClass) as session:
                q = session.query(ESSID_DBObject)
                essid_obj = q.filter(ESSID_DBObject.essid == essid).one()
                q = session.query(PYR2_DBObject).join(ESSID_DBObject)
                q = q.filter(sql.and_( \
                                    ESSID_DBObject.essid == essid_obj.essid, \
                                    PYR2_DBObject.key == key))
                result_obj = q.first()
                if result_obj is None:
                    session.add(PYR2_DBObject(essid_obj, key, results))
                    try:
                        session.commit()
                    except sql.exc.IntegrityError:
                        # Assume we hit a concurrent insert that causes
                        # a constraint-error on (essid-key).
                        session.rollback()
                        q = session.query(PYR2_DBObject).join(ESSID_DBObject)
                        q = q.filter(sql.and_( \
                                     ESSID_DBObject.essid == essid_obj.essid, \
                                     PYR2_DBObject.key == key))
                        result_obj = q.one()
                        result_obj.pack(results)
                        session.commit()
                else:
                    result_obj.pack(results)
                    session.commit()

        def __delitem__(self, essid):
            """Delete the given ESSID and all results from the storage."""
            with SessionContext(self.SessionClass) as session:
                q = session.query(ESSID_DBObject)
                essid_obj = q.filter(ESSID_DBObject.essid == essid).one()
                session.delete(essid_obj)
                session.commit()

        def containskey(self, essid, key):
            """Return True if the given (ESSID,key) combination is stored."""
            with SessionContext(self.SessionClass) as session:
                q = session.query(PYR2_DBObject).join(ESSID_DBObject)
                q = q.filter(sql.and_(ESSID_DBObject.essid == essid, \
                                      PYR2_DBObject.key == key))
                return q.count() == 1

        def iterkeys(self, essid):
            """Iterate over all keys that can be used to receive
               results.
            """
            with SessionContext(self.SessionClass) as session:
                q = session.query(PAW2_DBObject.key)
                q = q.join(PYR2_DBObject).join(ESSID_DBObject)
                q = q.filter(ESSID_DBObject.essid == essid)
                keys = q.all()
            return (c[0] for c in keys)

        def keycount(self, essid):
            """Returns the number of keys that can currently be used to receive
               results for the given ESSID.
            """
            with SessionContext(self.SessionClass) as session:
                q = session.query(PAW2_DBObject.key)
                q = q.join(PYR2_DBObject).join(ESSID_DBObject)
                q = q.filter(ESSID_DBObject.essid == essid)
                return q.count()

        def create_essid(self, essid):
            """Create the given ESSID in the storage.

               Re-creating a ESSID is a no-op.
            """
            with SessionContext(self.SessionClass) as session:
                essid_obj = ESSID_DBObject(essid)
                session.add(essid_obj)
                session.commit()


    class SQLPasswordStore(PasswordStore):

        def __init__(self, session_class):
            PasswordStore.__init__(self)
            self.SessionClass = session_class

        def __contains__(self, key):
            """Return True if the given key is currently in the storage."""
            with SessionContext(self.SessionClass) as session:
                q = session.query(PAW2_DBObject)
                return q.filter(PAW2_DBObject.key == key).count() == 1

        def __iter__(self):
            """Iterate over all keys that can be used to receive
               password-sets.

               The order of the keys is randomized on every call to __iter__
            """
            with SessionContext(self.SessionClass) as session:
                keys = session.query(PAW2_DBObject.key)
            keys = [c[0] for c in keys]
            random.shuffle(keys)
            return keys.__iter__()

        def __len__(self):
            """Return the number of keys that can be used to receive
           password-sets.
           """
            with SessionContext(self.SessionClass) as session:
                return session.query(PAW2_DBObject).count()

        def __getitem__(self, key):
            """Return the collection of passwords indexed by the given key."""
            with SessionContext(self.SessionClass) as session:
                q = session.query(PAW2_DBObject)
                return q.filter(PAW2_DBObject.key == key).one()

        def size(self, key):
            """Return the number of passwords indexed by the given key."""
            with SessionContext(self.SessionClass) as session:
                q = session.query(PAW2_DBObject.numElems)
                return q.filter(PAW2_DBObject.key == key).one()[0]

        def _flush_bucket(self, pw_h1, bucket):
            if len(bucket) == 0:
                return
            with SessionContext(self.SessionClass) as session:
                q = session.query(PAW2_DBObject)
                for db_bucket in q.filter(PAW2_DBObject.h1 == pw_h1):
                    bucket.difference_update(db_bucket)
                    if len(bucket) == 0:
                        return
                session.add(PAW2_DBObject(pw_h1, bucket))
                session.commit()
