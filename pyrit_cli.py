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

from pyrit import Pyrit
import cpyrit
import sys, getopt, random, time, md5

def tform(i):
    y = ["%.2f %s" % (i / x[1], x[0]) for x in [('secs',1),('mins',60.0**1),('hrs',60**2),('days',24*(60**2))] if i / x[1] >= 1.00]
    if len(y) > 0:
        return y[-1]
    else:
        return "NaN"


class Pyrit_CLI(object):
    def __init__(self):
        self.options = {"essidstore_path": 'blobspace/essid',
                        "passwdstore_path": 'blobspace/password',
                        "core_name": None,
                        "essid": None,
                        "file": None,
                        "ncpus": 1}
        self.pyrit_obj = None
        
    def progressbar(self, idx, max_idx):
        return "[" + '#' * int((max_idx - idx) * 30.0 / max_idx) + "-" * (30 - int((max_idx - idx) * 30.0 / max_idx)) + "]"
        
    def init(self, argv):
        print "The Pyrit commandline-client (C) 2008 Lukas Lueg http://pyrit.googlecode.com", \
            "\nThis code is distributed under the GNU General Public License v3\n"

        options, commands = getopt.getopt(sys.argv[1:], "u:v:c:e:f:n:")
        for option, value in dict(options).items():
            if option == '-u':
                self.options["essidstore_path"] = value
            elif option == '-v':
                self.options["passwdstore_path"] = value
            elif option == '-c':
                self.options["core_name"] = value
            elif option == '-e':
                self.options["essid"] = value
            elif option == '-f':
                self.options["file"] = value
            elif option == '-n':
                self.options["ncpus"] = int(value)
            else:
                print "Option '%s' not known. Ignoring..." % option
                
        self.pyrit_obj = Pyrit(self.options["essidstore_path"], self.options["passwdstore_path"])        
        
        func = {'export_cowpatty': self.export_cowpatty,
                'export_hashdb': self.export_hashdb,
                'export_passwords': self.export_passwords,
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
        print "usage: pyrit_cli [options] command", \
            "\n\nRecognized options:", \
            "\n    -u    : path to the ESSID-blobspace", \
            "\n    -v    : path to the Password-blobspace", \
            "\n    -c    : specifes the name of the core to use. 'Standard CPU' is default", \
            "\n    -e    : specifies an ESSID for the command", \
            "\n    -f    : specifies a filename for the command ('-' is stdin/stdout)", \
            "\n\nRecognized commands:", \
            "\n    benchmark          : Benchmark a core (-c and -n are optional)", \
            "\n    batch              : Start batchprocessing (-c, -u, -v, -n and -e are optional)", \
            "\n    eval               : Count the passwords available and the results already computed (-e is optional)", \
            "\n    import_passwords   : Import passwords into the Password-blobspace (-f is mandatory)", \
            "\n    create_essid       : Create a new ESSID (-e is mandatory)", \
            "\n    export_cowpatty    : Export into a new cowpatty file (-e and -f are mandatory)", \
            "\n    export_hashdb      : Export into an existing airolib database (-e is optional, -f is mandatory)"

    def create_essid(self):
        essid = self.options["essid"]
        if essid is None:
            print "One must specify a ESSID using the -e option. See 'help'"
        elif essid in self.pyrit_obj.list_essids():
            print "ESSID already created"
        else:
            self.pyrit_obj.create_essid(essid)
            print "Created ESSID '%s'" % essid

    def list_essids(self):
        print "Listing ESSIDs"
        for i,e in enumerate(self.pyrit_obj.list_essids()):
            print "#%i:  '%s'" % (i, e)
            
    def import_passwords(self):
        if self.options["file"] is None:
            print "One must specify a filename using the -f options. See 'help'"
        else:
            print "Importing from",
            if self.options["file"] == "-":
                print "stdin."
                self.pyrit_obj.import_passwords(sys.stdin)
            else:
                print "'%s'" % self.options["file"]
                f = open(self.options["file"], "r")
                self.pyrit_obj.import_passwords(f)
                f.close()
            print "Done"

    def eval_results(self):
        for e in self.pyrit_obj.eval_results(self.options["essid"]):
            print "ESSID:\t '%s'" % e[1]
            print "Passwords available:\t %i" % e[2]
            print "Passwords done so far:\t %i (%.2f%%)" % (e[3], (e[3] * 100.0 / e[2]) if e[2] > 0 else 0.0)
            print ""
    
    def export_passwords(self):
        if self.options["file"] is None:
            print "One must specify a filename using the -f option. See 'help'"
            return
        if self.options["file"] == "-":
            for idx, rowset in self.pyrit_obj.export_passwords():
                for row in rowset:
                    sys.stdout.write(row+"\n")
            sys.stdout.flush()
        else:
            f = open(self.options["file"],"w")
            print "Exporting to '%s'..." % self.options["file"]
            max_idx = 0
            lines = 0
            for idx, rowset in self.pyrit_obj.export_passwords():
                max_idx = max(idx, max_idx)
                print self.progressbar(idx, max_idx),
                print "%i lines written (%.2f%%)\r" % (lines, (max_idx - idx) * 100.0 / max_idx),
                for row in rowset:
                    f.write(row+"\n")
                lines += len(rowset)
                sys.stdout.flush()
            f.close()
            print "\nAll done"
        
    def export_cowpatty(self):
        if self.options["file"] is None:
            print "One must specify a filename using the -f option. See 'help'"
            return
        if self.options["essid"] is None:
            print "The cowpatty-format only supports one ESSID per file. Please specify one using the -e option."
            return
        if self.options["file"] == "-":
            for idx, row in self.pyrit_obj.export_cowpatty(self.options["essid"]):
                sys.stdout.write(row)
            sys.stdout.flush()
        else:
            f = open(self.options["file"],"w")
            print "Exporting to '%s'..." % self.options["file"]
            max_idx = 0
            lines = 0
            for idx, row in self.pyrit_obj.export_cowpatty(self.options["essid"]): 
                max_idx = max(idx, max_idx)
                f.write(row)
                lines += 1
                if lines % 1000 == 0:
                    print self.progressbar(idx, max_idx),
                    print "%i lines written (%.2f%%)\r" % (lines, (max_idx - idx) * 100.0 / max_idx),
                    sys.stdout.flush()
            f.close()
            print "\nAll done."

    def export_hashdb(self):
        if 'export_hashdb' not in dir(self.pyrit_obj):
            print "Support for SQLite seems to be missing. Please check if the pysqlite2 module is available to python."
            return
        if self.options["file"] is None:
            print "You must specify the database filename using the -f option. See 'help'"
            return
        if self.options["essid"] is None:
            essids = self.pyrit_obj.list_essids()
        else:
            essids = [self.options["essid"]]
        for essid in essids:
            print "Exporting ESSID '%s'" % essid
            self.pyrit_obj.export_hashdb(essid, self.options["file"])


    def batchprocess(self):
        cp = cpyrit.CPyrit(ncpus = self.options["ncpus"])
        if self.options["core_name"] is not None:
            core = cp.getCore(self.options["core_name"])
            print "Selected core '%s' (%i CPUs)" % (core.name, cp.ncpus)
        else:
            core = cp.getCore()
            print "Using default core '%s' (%i CPUs)" % (core.name, cp.ncpus)
        comptime = 0
        rescount = 0    
        essids = self.pyrit_obj.list_essids()
        if self.options["essid"] is not None:
            if self.options["essid"] not in essids:
                print "The ESSID '%s' is not found in the repository" % self.options["essid"]
                return
            else:
                essids = [self.options["essid"]]
        else:
            random.shuffle(essids)
        
        for essid in essids:
            essid_object = self.pyrit_obj.open_essid(essid)
            essid_results = essid_object.results
            print "Working on ESSID '%s'" % essid_object.essid
            pwfiles = self.pyrit_obj.list_passwords()
            random.shuffle(pwfiles)
            for pwfile_e in enumerate(pwfiles):
                print " Working on unit '%s' (%i/%i)," % (pwfile_e[1], pwfile_e[0], len(pwfiles)),
                try:
                    pwfile = self.pyrit_obj.open_password(pwfile_e[1])
                    pyr_obj = essid_object.open_result(pwfile_e[1])
                    known_pw = set(pyr_obj.results.keys())
                    passwords = [x for x in pwfile.yieldPassword() if x not in known_pw]
                    print "%i PMKs to do." % len(passwords)

                    if len(passwords) > 0:
                        #We slice the workunit to smaller parts since calc_pmklist won't return on KeyboardInterrupt
                        #the overhead of slicing is minimal
                        for pwslice in xrange(0,len(passwords), 15000):
                            pwset = passwords[pwslice:pwslice+15000]
                            t = time.time()
                            pyr_obj.results.update(core.solve(essid_object.essid, pwset))
                            comptime += time.time() - t
                            rescount += len(pwset)
                            print "\r  -> %.2f%% done" % (pwslice * 100.0 / len(passwords)),
                            if (comptime > 5):
                                print "(%.2f PMK/sec, %.2f SHA1/sec, %s left)." % (rescount / comptime, rescount * 8192*2 / comptime, tform((len(passwords) - pwslice) / (rescount / comptime))),
                            else:
                                print "", 
                            sys.stdout.flush()
                        print "\r  -> All done. (%s, %.2f PMK/sec, %.2f SHA1/sec)" % (tform(comptime), rescount / comptime, rescount * 8192*2 / comptime)
                        pyr_obj.savefile()
                    pyr_obj.close()
                except:
                    print "Unhandled exception while working on workunit '%s'" % pwfile_e[1]
                    raise


    def benchmark(self):
        c = cpyrit.CPyrit(ncpus = self.options["ncpus"])
        print "Available cores:", ", ".join(["'%s'" % core[0] for core in c.listCores()]), "\n"

        pws = ["bar_%i" % i for i in xrange(10000)]
        
        core = c.getCore('Standard CPU')
        print "Testing CPU-only core '%s' (%i CPUs)..." % (core.name, c.ncpus)
        t = time.time()
        res = sorted(core.solve('foo', pws))
        t = time.time() - t
        print "%i PMKs in %.2f seconds: %.2f PMKs/s" % (len(pws), t, len(pws) / t)
        md = md5.new()
        map(md.update, [x[1] for x in res])
        print "Result hash: %s" % md.hexdigest(), {True: "OK", False: "FAILED"}[md.hexdigest() == "ef747d123821851a9bd1d1e94ba048ac"]
        print ""
        
        if 'Nvidia CUDA' in [x[0] for x in c.listCores()]:
            core = c.getCore('Nvidia CUDA')
            print "Testing GPU core '%s'..." % core.name
            t = time.time()
            res = sorted(core.solve('foo', pws))
            t = time.time() - t
            print "%i PMKs in %.2f seconds: %.2f PMKs/s" % (len(pws), t, len(pws) / t)
            md = md5.new()
            map(md.update, [x[1] for x in res])
            print "Result hash: %s" % md.hexdigest(), {True: "OK", False: "FAILED"}[md.hexdigest() == "ef747d123821851a9bd1d1e94ba048ac"]
            print ""
            
if __name__ == "__main__":
    p = Pyrit_CLI()
    p.init(sys.argv)
