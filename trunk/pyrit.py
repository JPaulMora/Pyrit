#!/usr/bin/python
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


import cpyrit
import time, zlib, getopt, hashlib, fcntl, os, re, struct, random, sys, threading
try:
    from pysqlite2 import dbapi2 as sqlite
except:
    pass

class Pyrit_CLI(object):
    class options(object):
        def __init__(self):
            self.essidstore_path = 'blobspace/essid'
            self.passwdstore_path = 'blobspace/password'
            self.core_name = None
            self.essid = None
            self.file = None
            self.ncpus = None
            self.verbose = True
    
    def __init__(self):
        # I *hate* the lookup syntax in the code further below if options is a dict
        self.options = self.options()
        
    def tell(self, text, sep=' ', end='\n', stream=sys.stdout, flush=False):
        if self.options.verbose or stream != sys.stdout:
            stream.write(text)
            if end is not None:
                stream.write(end)
            else:
                if sep is not None:
                    stream.write(sep)
            if flush or end is None:
                stream.flush()
        
    def init(self):
        options, commands = getopt.getopt(sys.argv[1:], "u:v:c:e:f:n:")
        for option, value in dict(options).items():
            if option == '-u':
                self.options.essidstore_path = value
            elif option == '-v':
                self.options.passwdstore_path = value
            elif option == '-c':
                self.options.core_name = value
            elif option == '-e':
                self.options.essid = value
            elif option == '-f':
                self.options.file = value
            elif option == '-n':
                self.options.ncpus = int(value)
            else:
                self.tell("Option '%s' not known. Ignoring..." % option)
        
        if self.options.file == "-":
            self.options.verbose = False

        self.essidstore = EssidStore(self.options.essidstore_path)
        self.passwdstore = PasswordStore(self.options.passwdstore_path)

        self.tell("The Pyrit commandline-client (C) 2008 Lukas Lueg http://pyrit.googlecode.com" \
                "\nThis code is distributed under the GNU General Public License v3\n")

        if len(self.essidstore) == 0 and len(commands) > 0 and commands[0] != "create_essid":
            self.tell("The ESSID-blobspace seems to be empty; you should create an ESSID...", stream=sys.stderr)

        func = {'export_cowpatty': self.export_cowpatty,
                'export_hashdb': self.export_hashdb,
                'export_passwords': self.export_passwords,
                'import_passwords': self.import_passwords,
                'list_essids': self.list_essids,
                'create_essid': self.create_essid,
                'eval': self.eval_results,
                'batch': self.batchprocess,
                'batchprocess': self.batchprocess,
                'benchmark': self.benchmark,
                'help': self.print_help
                }.setdefault(commands[0] if len(commands) > 0 else 'help', self.print_help)
        func()

    def print_help(self):
        self.tell("usage: pyrit_cli [options] command " \
            "\n\nRecognized options:" \
            "\n    -u    : path to the ESSID-blobspace" \
            "\n    -v    : path to the Password-blobspace" \
            "\n    -c    : name of the core to use. 'Standard CPU' is default" \
            "\n    -e    : ESSID for the command" \
            "\n    -f    : filename for the command ('-' is stdin/stdout)" \
            "\n    -n    : number of CPUs to use" \
            "\n\nRecognized commands:" \
            "\n    benchmark          : Benchmark a core (-c and -n are optional)" \
            "\n    batch              : Start batchprocessing (-c, -u, -v, -n, -f and -e are optional)" \
            "\n    list_essids        : List all ESSIDs in the ESSID-blobspace" \
            "\n    eval               : Count the passwords available and the results already computed (-e is optional)" \
            "\n    import_passwords   : Import passwords into the Password-blobspace (-f is mandatory)" \
            "\n    create_essid       : Create a new ESSID (-e is mandatory)" \
            "\n    export_cowpatty    : Export into a new cowpatty file (-e and -f are mandatory)" \
            "\n    export_hashdb      : Export into an existing airolib database (-e is optional, -f is mandatory)")

    def create_essid(self):
        essid = self.options.essid
        if essid is None:
            self.tell("One must specify a ESSID using the -e option. See 'help'", stream=sys.stderr)
        elif essid in self.essidstore:
            self.tell("ESSID already created", stream=sys.stderr)
        else:
            self.essidstore.create_essid(essid)
            self.tell("Created ESSID '%s'" % essid)

    def list_essids(self):
        self.tell("Listing ESSIDs...")
        for i,e in enumerate(self.essidstore):
            self.tell("#%i:  '%s'" % (i, e))
            
    def import_passwords(self):
        if self.options.file is None:
            self.tell("One must specify a filename using the -f options. See 'help'", stream=sys.stderr)
        else:
            self.tell("Importing from ", end=None)
            if self.options.file == "-":
                self.tell("stdin.")
                f = sys.stdin
            else:
                self.tell("'%s'" % self.options.file)
                f = open(self.options.file, "r")
            i = 0
            for line in f:
                self.passwdstore.store_password(line)
                i += 1
                if i % 10000 == 0:
                    self.tell("\r%i lines read." % i, end=None, flush=True)
            self.passwdstore.flush_buffer()
            self.tell("\r%i lines read. All done." % i)
            if f != sys.stdin:
                f.close()

    def eval_results(self):
        if self.options.essid is None:
            essids = self.essidstore
        else:
            essids = [self.options.essid]
        for essid in essids:
            self.tell("ESSID:\t '%s'" % essid)
            essid_obj = self.essidstore[essid]
            pwcount = 0
            rescount = 0
            for pwfile in self.passwdstore:
                pws = set(pwfile)
                pwcount += len(pws)
                rescount += len(pws.intersection(set(essid_obj[pwfile.key].keys())))
            self.tell("Passwords available:\t %i" % pwcount)
            self.tell("Passwords done so far:\t %i (%.2f%%)" % (rescount, (rescount * 100.0 / pwcount) if pwcount > 0 else 0.0))
            self.tell("")
    
    def export_passwords(self):
        if self.options.file is None:
            self.tell("One must specify a filename using the -f option. See 'help'", stream=sys.stderr)
            return
        if self.options.file == "-":
            for pwfile in self.passwdstore:
                for row in pwfile:
                    sys.stdout.write(row+"\n")
            sys.stdout.flush()
        else:
            f = open(self.options.file,"w")
            self.tell("Exporting to '%s'..." % self.options.file)
            max_idx = 0
            lines = 0
            for pwfile in self.passwdstore:
                for row in pwfile:
                    f.write(row+"\n")
                    lines += 1
                self.tell("%i lines written\r" % lines, end=None)
            f.close()
            self.tell("\nAll done")
    
    def _genCowpatty(self, essid_obj):
        yield struct.pack("<i3s", 0x43575041, '\00'*3)
        yield struct.pack("<b32s", len(essid_obj.essid), essid_obj.essid)
        for key, result in essid_obj:
            for r in result.items():
                yield struct.pack("<b%ss32s" % len(r[0]), len(r[0]) + 32 + 1, r[0], r[1])
    
    def export_cowpatty(self):
        if self.options.file is None:
            self.tell("One must specify a filename using the -f option. See 'help'", stream=sys.stderr)
            return
        if self.options.essid is None:
            self.tell("The cowpatty-format only supports one ESSID per file. Please specify one using the -e option.", stream=sys.stderr)
            return
        if self.options.file == "-":
            try:
                for row in self._genCowpatty(self.essidstore[self.options.essid]):
                    sys.stdout.write(row)
                sys.stdout.flush()
            except IOError:
                self.tell("IOError while exporting to stdout ignored...", stream=sys.stderr)
        else:
            f = open(self.options.file, "w")
            self.tell("Exporting to '%s'..." % self.options.file)
            lines = 0
            for row in self._genCowpatty(self.essidstore[self.options.essid]):
                f.write(row)
                lines += 1
                if lines % 1000 == 0:
                    self.tell("\r%i entries written..." % lines, end=None, flush=True)
            self.tell("\r%i entries written. All done." % lines)
            f.close()

    def export_hashdb(self):
        if 'sqlite' in locals():
            self.tell("Support for SQLite seems to be missing. Please check if the pysqlite2 module is available to python.", stream=sys.stderr)
            return
        if self.options.file is None:
            self.tell("You must specify the database filename using the -f option. See 'help'", stream=sys.stderr)
            return
        if self.options.essid is None:
            essids = self.essidstore
        else:
            essids = [self.options.essid]

        con = sqlite.connect(self.options.file)
        cur = con.cursor()
        cur.execute('SELECT * FROM sqlite_master')
        tbls = [x[1] for x in cur.fetchall() if x[0] == u'table']
        if u'pmk' not in tbls or u'essid' not in tbls or u'passwd' not in tbls:
            raise Exception, "The database '%s' seems to be uninitialized. Pyrit won't do that for you. Use the proper tools to create a new database." % self.options.file

        for essid in essids:
            self.tell("Exporting ESSID '%s'" % essid)
            essid_obj = self.essidstore[essid]
            try:
                cur.execute('INSERT OR IGNORE INTO essid (essid) VALUES (?)', (essid,))
                essid_id = cur.execute('SELECT essid_id FROM essid WHERE essid = ?', (essid,)).fetchone()[0]
                cur.execute('CREATE TEMPORARY TABLE import (passwd_id int key, passwd text key, pmk blob)')
                for key, result in essid_obj:
                    cur.executemany('INSERT INTO import (passwd, pmk) VALUES (?,?)', ((pw, buffer(res)) for pw, res in result.items()))
                cur.execute('UPDATE import SET passwd_id = (SELECT passwd.passwd_id FROM passwd WHERE passwd.passwd = import.passwd)')
                cur.execute('INSERT INTO passwd (passwd) SELECT passwd FROM import WHERE import.passwd_id IS NULL')
                cur.execute('UPDATE import SET passwd_id = (SELECT passwd.passwd_id FROM passwd WHERE passwd.passwd = import.passwd) WHERE passwd_id IS NULL')
                cur.execute('INSERT OR IGNORE INTO pmk (essid_id,passwd_id,pmk) SELECT ?, passwd_id, pmk FROM import', (essid_id,))
                cur.execute('DROP TABLE import')
            except:
                con.rollback()
                cur.close()
                con.close()
                self.tell("There was an error while exporting. The database has not been modified...", stream=sys.stderr)
                raise
        con.commit()
        cur.close()
        con.close()

    def batchprocess(self):
        if self.options.file == "-" and self.options.essid is None:
            self.tell("Results will be written to stdout while batchprocessing. This requires to specify a ESSID.", stream=sys.stderr) 
            return
            
        cp = cpyrit.CPyrit(ncpus = self.options.ncpus)
        if self.options.core_name is not None:
            core = cp.getCore(self.options.core_name)
            self.tell("Selected core '%s'" % core.name, end=None)
        else:
            core = cp.getCore()
            self.tell("Using default core '%s'" % core.name, end=None)
        if core.ctype == 'GPU':
            self.tell("(Device '%s')" % core.devicename)
        else:
            self.tell("(%i CPUs)" % cp.ncpus)

        if self.options.essid is not None:
            if self.options.essid not in self.essidstore:
                self.tell("The ESSID '%s' is not found in the repository" % self.options.essid, stream=sys.stderr)
                return
            else:
                essids = [self.options.essid]
        else:
            essids = self.essidstore

        try: 
            for essid in essids:
                essid_object = self.essidstore[essid]
                self.tell("Working on ESSID '%s'" % essid_object.essid)
                if self.options.file == "-":
                    import struct
                    sys.stdout.write(struct.pack("<i3s", 0x43575041, '\00'*3))
                    sys.stdout.write(struct.pack("<b32s", len(essid_object.essid), essid_object.essid))
                    sys.stdout.flush()

                def _compute(pwbuffer, core, essid_obj):
                    passwords = []
                    for p in pwbuffer.values():
                        passwords.extend(p)
                    if len(passwords) > 0:
                        results = {}
                        t = time.time()
                        self.tell("")
                        for pwslice in xrange(0, len(passwords), 20480):
                            self.tell("\r Computing %i PMKs in %i workunits -> %.2f%% done." % (len(passwords), sum([1 if len(pwbuffer[p]) > 0 else 0 for p in pwbuffer]) , pwslice * 100.0 / len(passwords)), end=None)
                            results.update(core.solve(essid_object.essid, passwords[pwslice:pwslice+20480]))
                        self.tell("\r All done, computed %i PMKs in %.2f seconds, %.2f PMKs/s)" % (len(passwords), time.time() - t, len(passwords) / (time.time() - t)))
                    for pwfile_inst in pwbuffer:
                        res = essid_obj[pwfile_inst]
                        if len(pwbuffer[pwfile_inst]) > 0:
                            res.update(((pw, results[pw]) for pw in pwbuffer[pwfile_inst]))
                            essid_obj[pwfile_inst] = res
                        if self.options.file == "-":
                            try:
                                for r in res.items():
                                    sys.stdout.write(struct.pack("<b%ss32s" % len(r[0]), len(r[0]) + 32 + 1, r[0], r[1]))
                            except IOError:
                                self.tell("IOError while writing to stdout; batchprocessing will continue silently...", stream=sys.stderr)
                                self.options.file = ""
                            sys.stdout.flush()    

                pwbuffer = {}
                for pwfile in self.passwdstore:
                    unsolved = list(set(pwfile).difference(set(essid_object[pwfile].keys())))
                    pwbuffer[pwfile] = unsolved
                    buffersize = sum((len(x) for x in pwbuffer.values()))
                    self.tell(" \rReading unit '%s' (%i passwords buffered)" % (pwfile.key, buffersize), end=None)
                    if buffersize >= 20480*2:
                        _compute(pwbuffer, core, essid_object)
                        pwbuffer.clear()
                _compute(pwbuffer, core, essid_object)
                
                self.tell("")

        except (KeyboardInterrupt, SystemExit):
            self.tell("Exiting...")
        except:
            self.tell("Unhandled exception while batchprocessing '%s'" % pwfile, stream=sys.stderr)
            raise        
        self.tell("Batchprocessing done.")

    def benchmark(self):
        def runbench(core):
            pws = ["bar_%i" % i for i in xrange(10000)]
            t = time.time()
            res = sorted(core.solve('foo', pws))
            t = time.time() - t
            md = hashlib.md5()
            map(md.update, [x[1] for x in res])
            return (len(pws) / t, md.hexdigest() == "ef747d123821851a9bd1d1e94ba048ac")
            
        c = cpyrit.CPyrit(ncpus = self.options.ncpus)
        self.tell("Available cores: " + ", ".join(["'%s'" % core[0] for core in c.listCores()]))

        core = c.getCore('Standard CPU')
        self.tell("Testing CPU-only core '%s' (%i CPUs)... " % (core.name, c.ncpus), end=None, flush=True)
        perf, chk = runbench(core)
        if chk:
            self.tell("%.2f PMKs/s" % perf)
        else:
            self.tell("FAILED")
        self.tell("")
                
        if 'Nvidia CUDA' in [x[0] for x in c.listCores()]:
            core = c.getCore('Nvidia CUDA')
            self.tell("Testing GPU core '%s' (Device '%s')... " % (core.name, core.devicename), end=None)
            sys.stdout.flush()
            # For GPUs the benchmark runs twice as the core needs to be
            # calibrated before giving correct performance-data
            perf, chk = runbench(core)
            if chk:
                perf, chk = runbench(core)
                if chk:
                    self.tell("%.2f PMKs/s" % perf)
                else:
                    self.tell("FAILED")
            else:
                self.tell("FAILED")
            self.tell("")


class PyrFile(object):
    def __init__(self, essid, infile):
        self.results = {}
        self.essid = essid
        self.f = None
        self.key = None
        self.ccore = cpyrit.CPyrit()

        f = open(infile, "a+b")
        fcntl.flock(f.fileno(), fcntl.LOCK_SH)
        f.seek(0)
        try:
            preheadfmt = "<4sH"
            prehead = f.read(struct.calcsize(preheadfmt))
            if len(prehead) == 0:
                self.f = f
            else:
                magic, essidlen = struct.unpack(preheadfmt, prehead)
                assert magic == "PYRT"
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
                    results = zip(inp, pmkbuffer)
                    pick = random.choice(results)
                    assert cpyrit.CPyrit().getCore('Standard CPU').solve(essid, pick[0]) == pick[1]
                    self.essid = essid
                    self.results = dict(results)
                    self.f = f
                    self.key = infile.split(os.path.sep)[-1][:-4]
                    
                else:
                    raise Exception, "Digest check failed."
        except:
            print >>sys.stderr, "Exception while opening PyrFile '%s', file not loaded." % infile
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            f.close()
            raise

    def close(self):
        if self.f is not None:
            fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
            self.f.close()
            self.f = None

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


class FileReadStreamer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.cv = threading.Condition()
        self.buffer = []
        self.setDaemon(True)
        
    def readItem(self, key):
        return None
        
    def run(self):
        for key in self.generator:
            self.cv.acquire()
            if len(self.buffer) > 3:
                self.cv.wait()
            self.buffer.append(self.readItem(key))
            if len(self.buffer) > 0:
                self.cv.notifyAll()
            self.cv.release()
        
        self.cv.acquire()
        self.cv.notifyAll()
        self.cv.release()

    def __iter__(self):
        while True:
            self.cv.acquire()
            if len(self.buffer) == 0:
                if not self.isAlive():
                    break
                else:
                    self.cv.notifyAll()
                    self.cv.wait()
                    if len(self.buffer) == 0:
                        break
            ret = self.buffer.pop()
            self.cv.notifyAll()
            self.cv.release()
            yield ret


class FileWriteStreamer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.cv = threading.Condition()
        self.buffer = []
        self.setDaemon(True)
        self.closed = False        
   
    def __del__(self):
        self.close()
    
    def run(self):
        self.cv.acquire()
        while True:
            if len(self.buffer) > 0:
                inst = self.buffer.pop()
                inst.savefile()
            else:
                if self.closed:
                    break
                else:
                    self.cv.notifyAll()
                    self.cv.wait()
        self.cv.notifyAll()
        self.cv.release()
        
    def savefile(self, inst):
        if self.closed:
            raise AssertionError, "FileWriteStreamer '%s' was already closed when called. Instance will not be saved." % self
        self.cv.acquire()
        while len(self.buffer) > 3:
            self.cv.notifyAll()
            self.cv.wait()
        self.buffer.append(inst)
        self.cv.notifyAll()
        self.cv.release()

    def sync(self):
        self.cv.acquire()
        while len(self.buffer) > 0:
            self.notifyAll()
            self.wait()
        self.cv.release()

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.sync()
        if len(self.buffer) > 0:
            print >>sys.stderr, "WARNING: FileWriteStreamer '%s' closed with instances still in buffer. This should not happen." % self        


class ESSID(object):
    class ResultReadStreamer(FileReadStreamer):
        def __init__(self, essid_obj):
            FileReadStreamer.__init__(self)
            self.obj = essid_obj
            self.generator = (x[:-4] for x in os.listdir(self.obj.path) if x[-4:] == '.pyr')
            self.start()
            
        def readItem(self, key):
            return self.obj._getPyrFile(key)

    class ResultWriteStreamer(FileWriteStreamer):
        def __init__(self):
            FileWriteStreamer.__init__(self)
            self.start()

    def __init__(self, path):
        self.path = path
        try:
            self.f = open(os.path.join(path, "essid"), "rb")
            fcntl.flock(self.f.fileno(), fcntl.LOCK_SH)
        except IOError:
            raise IOError, "ESSID not found or not accessible."
        self.essid = self.f.read()
        self.resultwriter = self.ResultWriteStreamer()

    def __del__(self):
        try:
            self.close()
        except:
            pass
            
    def __len__(self):
        return len([x[:-4] for x in os.listdir(self.path) if x[-4:] == '.pyr'])

    def __iter__(self):
        if self.f is None:
            raise Exception, "ESSID not locked."
        for resultfile in self.ResultReadStreamer(self):
            yield (resultfile.key, resultfile.results)

    def __getitem__(self, key):
        return self._getPyrFile(key).results
        
    def __setitem__(self, key, value):
        assert isinstance(value, dict)
        pyrfile = self._getPyrFile(key)
        pyrfile.results = value
        self.resultwriter.savefile(pyrfile)

    def close(self):
        self.resultwriter.close()
        if self.f is not None:
            fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
            self.f.close()
        self.f = None
        self.path = None
        self.essid = None
     
    def _getPyrFile(self, key):
        if self.f is None:
            raise Exception, "ESSID not locked."
        if isinstance(key, str):
            fname = key
        elif isinstance(key, PasswordFile):
            fname = key.key
        else:
            raise AssertionError, "Don't know how to handle parameter of class '%s'." % key.__class__
        return PyrFile(self.essid, os.path.join(self.path, fname+".pyr"))

class EssidStore(object):
    def __init__(self,basepath):
        self.essidpath = basepath
        self._makedir(self.essidpath)

    def _makedir(self,pathname):
        try:
            os.makedirs(pathname)
        except OSError, (errno, sterrno):
            if errno == 17:
                pass
            else:
                raise

    def _getessidroot(self,essid):
        return os.path.join(self.essidpath, hashlib.md5(essid).hexdigest()[:8])

    def __getitem__(self, essid):
        return ESSID(self._getessidroot(essid))

    def __len__(self):
        return len([x for x in self])

    def __iter__(self):
        for essid_hash in os.listdir(self.essidpath):
            f = open(os.path.join(self.essidpath, essid_hash,'essid'),"rb")
            essid = f.read()
            f.close()
            if essid_hash == hashlib.md5(essid).hexdigest()[:8]:
                yield essid
            else:
                print >>sys.stderr, "ESSID %s seems to be corrupted." % essid_hash

    def create_essid(self,essid):
        if len(essid) < 3 or len(essid) > 32:
            raise Exception, "ESSID invalid."
        essid_root = self._getessidroot(essid)
        self._makedir(essid_root)
        f = open(os.path.join(essid_root,'essid'),"wb")
        f.write(essid)
        f.close()


class PasswordFile(object):
    def __init__(self, filename):
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
                inp = sorted(f.read().split("\00"))
                map(md.update, inp)
                if digest == md.digest():
                    if filename[-3-len(md.hexdigest()):-3] != md.hexdigest():
                        raise Exception, "File '%s' doesn't match the key '%s'." % (filename, md.hexdigest())
                    self.bucket = frozenset(inp)
                    self.key = md.hexdigest()
                else:
                    print >>sys.stderr, "Digest check failed for %s" % filename
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    f.close()
                    self.f = None
        except:
            print >>sys.stderr, "Exception while opening PasswordFile '%s', file not loaded." % filename
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            f.close()
            self.f = None
            raise
            
    def __repr__(self):
        return self.f.__repr__()

    def __del__(self):
        if self.f is not None:
            fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
            self.f.close()

    def __iter__(self):
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
        b = sorted(list(self.bucket))
        map(md.update, b)
        self.f.truncate(0)
        self.f.write("PAWD")
        self.f.write(md.digest())
        self.f.write("\00".join(b))
        self.f.flush()
        fcntl.flock(self.f.fileno(), fcntl.LOCK_SH)

class PasswordStore(object):
    class PWFileReadStreamer(FileReadStreamer):
        def __init__(self, pwstore):
            FileReadStreamer.__init__(self)
            self.obj = pwstore
            self.generator = (x for x in self.obj._getfiles().keys())
            self.start()
            
        def readItem(self, key):
            return self.obj[key]

    def __init__(self,basepath):
        self.passwdpath = basepath
        self._makedir(self.passwdpath)
        self.pwbuffer = {}
        self.pwpattern = re.compile("([a-zöäüß ]+)")

    def __del__(self):
        self.flush_buffer()

    def _makedir(self,pathname):
        try:
            os.makedirs(pathname)
        except OSError, (errno, sterrno):
            if errno == 17:
                pass

    def _getfiles(self):
        pwfiles = {}
        for pw_h1 in [x for x in os.listdir(self.passwdpath)]:
            for pw in [x for x in os.listdir(os.path.join(self.passwdpath, pw_h1)) if x[-3:] == '.pw']:
                pwfiles[pw[:len(pw)-3]] = os.path.join(self.passwdpath, pw_h1, pw)
        return pwfiles

    def __iter__(self):
        for pwf in self.PWFileReadStreamer(self):
            yield pwf

    def __getitem__(self, key):
        return PasswordFile(self._getfiles()[key])

    def _flush_bucket(self, bucket):
        if len(bucket) == 0:
            return
        pw_h1 = "%02.2X" % (hash(list(bucket)[0]) & 0xFF)
        assert all(("%02.2X" % (hash(pw) & 0xFF) == pw_h1 for pw in bucket))

        for pwfile in self._getfiles().values():
            if pwfile.split(os.path.sep)[-2] == pw_h1:
                bucket -= PasswordFile(pwfile).bucket
        if len(bucket) == 0:
            return
            
        md = hashlib.md5()
        map(md.update, sorted(list(bucket)))
        destpath = os.path.join(self.passwdpath, pw_h1)
        self._makedir(destpath)
        f = PasswordFile(os.path.join(destpath, md.hexdigest() + ".pw"))
        f.bucket.update(bucket)
        f.savefile()
        bucket = set()

    def flush_buffer(self):
        for pw_h1 in self.pwbuffer.keys():
            pwbucket = list(self.pwbuffer[pw_h1])
            map(self._flush_bucket, [set(pwbucket[x:x+10000]) for x in xrange(0,len(pwbucket), 10000)])

    def store_password(self, passwd):
        pwstrip = str(passwd).lower().strip()
        pwgroups = self.pwpattern.search(pwstrip)
        if pwgroups is None:
            #print "Password '%s'('%s') ignored." % (pwstrip,passwd)
            return
        pwstrip = pwgroups.groups()[0]

        if len(pwstrip) < 8 or len(pwstrip) > 63:
            #print "Password '%s'('%s') has invalid length." % (pwstrip,passwd)
            return

        pw_h1 = "%02.2X" % (hash(pwstrip) & 0xFF)
        pw_bucket = self.pwbuffer.setdefault(pw_h1, set())
        if pwstrip not in pw_bucket:
            pw_bucket.add(pwstrip)
            if len(pw_bucket) >= 10000:
                self._flush_bucket(pw_bucket)

if __name__ == "__main__":
    p = Pyrit_CLI()
    p.init()

