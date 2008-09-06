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
import sys
import getopt
import random, time

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
                        "file": None}
        
        self.pyrit_obj = None
        
    def init(self, argv):
        options, commands = getopt.getopt(sys.argv[1:], "u:v:c:e:f:")
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
            else:
                print "Option '%s' not known. Ignoring..." % option
                
        self.pyrit_obj = Pyrit(self.options["essidstore_path"], self.options["passwdstore_path"])        
        
        if len(commands) == 0:
            command = "help"
        else:
            command = commands[0]
        if command == "export_cowpatty":
            if self.options["file"] is None:
                print "One must specify a filename using the -f option. See 'help'"
            else:
                if self.options["essid"] is None:
                    print "The cowpatty-format only supports one ESSID per file. Please specify one using the -e option."
                else:
                    self.export_cowpatty()
        
        elif command == "import_cowpatty":
            pass
        
        elif command == "import_passwords":
            self.import_passwords()
        
        elif command == "export_passwords":
            if self.options["file"] is None:
                print "One must specify a filename using the -f option. See 'help'"
            else:
                self.export_passwords()

        elif command == "list_essids":
            for e in pyrit_obj.list_essids():
                print e
                
        elif command == "create_essid":
            essid = self.options["essid"]
            if essid is None:
                print "One must specify a ESSID using the -e option. See 'help'"
            elif essid in self.pyrit_obj.list_essids():
                print "ESSID already created"
            else:
                self.pyrit_obj.create_essid(essid)
                print "Created ESSID '%s'" % essid
        
        elif command == "eval_results":
            self.eval_results()
            
        elif command == "batchprocess":
            self.batchprocess()
        
        elif command == 'help':
            print "The Pyrit commandline-client.\nSomeone write some help here."
        
        else:
            print "Don't know that command. See valid commands with 'help'"
        
        
    def import_passwords(self):
        if self.options["file"] is None:
            print "One must specify a filename using the -f options. See 'help'"
        else:
            print "Importing from",
            if self.options["file"] == "-":
                print "stdin."
                f = sys.stdin
            else:
                print "'%s'" % self.options["file"]
                f = open(self.options["file"], "r")
            self.pyrit_obj.import_passwords(f)
            if f != sys.stdin:
                f.close()
            print "Done"

    def eval_results(self):
        for e in self.pyrit_obj.eval_results(self.options["essid"]):
            print "ESSID:\t '%s'" % e[1]
            print "Passwords available:\t %i" % e[2]
            print "Passwords done so far:\t %i (%.2f%%)" % (e[3], e[3] / e[2])
            print ""
    
    def export_passwords(self):
        if self.options["file"] == "-":
            f = sys.stdout
            for idx, rowset in self.pyrit_obj.export_passwords():
                for row in rowset:
                    f.write(row+"\n")
            sys.stdout.flush()
        else:
            f = open(self.options["file"],"w")
            print "Exporting to '%s'..." % self.options["file"]
            max_idx = 0
            lines = 0
            for idx, rowset in self.pyrit_obj.export_passwords():
                max_idx = max(idx, max_idx)
                print "[" + '#' * int((max_idx - idx) * 20.0 / max_idx) + "-" * (20 - int((max_idx - idx) * 20.0 / max_idx)) + "]",
                print "%i lines written (%.2f%%)\r" % (lines, (max_idx - idx) * 100.0 / max_idx),
                for row in rowset:
                    f.write(row+"\n")
                lines += len(rowset)
                sys.stdout.flush()
            f.close()
            print "\nAll done"
        
    def export_cowpatty(self):
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
                    print "[" + '#' * int((max_idx - idx) * 20.0 / max_idx) + "-" * (20 - int((max_idx - idx) * 20.0 / max_idx)) + "]",
                    print "%i lines written (%.2f%%)\r" % (lines, (max_idx - idx) * 100.0 / max_idx),
                    sys.stdout.flush()
            f.close()
            print "\nAll done."

    def batchprocess(self):
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
                            pyr_obj.results.update(self.pyrit_obj.solve(essid_object.essid, pwset))
                            comptime += time.time() - t
                            rescount += len(pwset)
                            print "\r  -> %.2f%% done" % (pwslice * 100.0 / len(passwords)),
                            if (comptime > 5):
                                print "(%.2f PMK/sec, %.2f SHA1/sec, %s left)." % (rescount / comptime, rescount * 8192 / comptime, tform((len(passwords) - pwslice) / (rescount / comptime))),
                            else:
                                print "", 
                            sys.stdout.flush()
                        print "\r  -> All done. (%s, %.2f PMK/sec, %.2f SHA1/sec)" % (tform(comptime), rescount / comptime, rescount * 8192 / comptime)
                        pyr_obj.savefile()
                    pyr_obj.close()
                except:
                    print "Unhandled exception while working on workunit '%s'" % pwfile_e[1]
                    raise

if __name__ == "__main__":
    print "This is Pyrit"
    p = Pyrit_CLI()
    p.init(sys.argv)
