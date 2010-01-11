# -*- coding: UTF-8 -*-
#
#    Copyright 2008-2010, Lukas Lueg, lukas.lueg@gmail.com
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

from __future__ import with_statement

import getopt
import glob
import gzip
import hashlib
import itertools
import os
import random
import sys
import threading
import time

import cpyrit.cpyrit
import cpyrit.config
import cpyrit.util
import cpyrit.storage


class PyritRuntimeError(RuntimeError):
    pass


class Pyrit_CLI(object):

    def __init__(self):
        self.verbose = True

    def tell(self, text, sep=' ', end='\n', stream=sys.stdout, flush=False):
        if self.verbose or stream != sys.stdout:
            stream.write(text)
            if end is not None:
                stream.write(end)
            else:
                if sep is not None:
                    stream.write(sep)
            if flush or end is None:
                stream.flush()

    def initFromArgv(self):
        self.tell("Pyrit %s (C) 2008-2010 Lukas Lueg " \
                  "http://pyrit.googlecode.com\n" \
                  "This code is distributed under the GNU General Public " \
                  "License v3+\n" % cpyrit.util.VERSION, stream=sys.stderr)
        options = {}
        args, commands = getopt.getopt(sys.argv[1:], 'u:v:c:e:i:o:r:b:')
        args = dict(args)

        if len(commands) == 1 and commands[0] in self.commands:
            command = commands[0]
        else:
            command = 'help'
            args = {}
        func = self.commands[command]

        req_params, opt_params = func.cli_options
        if '-u' not in args and '-u' in req_params:
            args['-u'] = cpyrit.config.cfg['default_storage']
        for param in req_params:
            if param not in args:
                raise PyritRuntimeError("The command '%s' requires the " \
                                        "option '%s'. See 'help'." % \
                                        (command, param))
        for arg, value in args.iteritems():
            if arg in req_params or arg in opt_params:
                if arg == '-e':
                    options['essid'] = value
                elif arg == '-b':
                    options['bssid'] = str(value).lower()
                elif arg == '-i':
                    options['infile'] = value
                elif arg == '-o':
                    options['outfile'] = value
                    # Prevent messages from corrupting stdout
                    if value == '-':
                        self.verbose = False
                elif arg == '-r':
                    options['capturefile'] = value
                elif arg == '-u':
                    options['storage'] = self._getStorage(value)
            else:
                raise PyritRuntimeError("The command '%s' ignores the " \
                                        "option '%s'." % (command, arg))

        self.tell('')
        func(self, **options)

    def print_help(self):
        """Print this help"""
        self.tell('Usage: pyrit [options] command'
            '\n'
            '\nRecognized options:'
            '\n  -e    : Filters AccessPoint by ESSID'
            '\n  -b    : Filters AccessPoint by BSSID'
            "\n  -i    : Filename for input ('-' is stdin)"
            "\n  -o    : Filename for output ('-' is stdout)"
            "\n  -r    : Packet capture source in pcap-format"
            "\n  -u    : URL of the storage-system to use"
            '\n'
            '\nRecognized commands:')
        m = max([len(command) for command in self.commands])
        for command, func in sorted(self.commands.items()):
            self.tell('  %s%s : %s' % (command, \
                                        ' ' * (m - len(command)), \
                                        func.__doc__))
    print_help.cli_options = ((), ())

    def requires_pckttools(*params):
        """Decorate a function to check for cpyrit.cpyrit_pckttools
           before execution.
        """

        def check_pkttools(f):

            def new_f(*args, **kwds):
                try:
                    import cpyrit.pckttools
                except cpyrit.util.ScapyImportError:
                    raise PyritRuntimeError("Scapy 2.x is required to use " \
                                            "Pyrit's analyze/attack " \
                                            "functions but seems to be " \
                                            "unavailable.")
                f(*args, **kwds)
            new_f.func_name = f.func_name
            new_f.__doc__ = f.__doc__
            return new_f
        return check_pkttools

    def _getParser(self, capturefilemask):
        filelist = glob.glob(capturefilemask)
        if len(filelist) == 0:
            raise PyritRuntimeError("No file found that matches '%s'" % \
                                    capturefilemask)
        parser = cpyrit.pckttools.PacketParser()
        for idx, capturefile in enumerate(filelist):
            self.tell("Parsing file '%s' (%i/%i)..." % (capturefile, idx + 1, \
                                                        len(filelist)))
            parser.parse_file(capturefile)
        self.tell("%i packets (%i 802.11-packets), %i APs\n" % \
                    (parser.pcktcount, parser.dot11_pcktcount, len(parser)))
        return parser

    def _fuzzyGetAP(self, parser, bssid=None, essid=None):
        if bssid is None and essid is None:
            for ap in parser:
                if ap.isCompleted() and ap.essid is not None:
                    self.tell("Picked AccessPoint %s ('%s') automatically." % \
                                (ap, ap.essid))
                    return ap
            raise PyritRuntimeError("Specify an AccessPoint's BSSID or " \
                                    "ESSID using the options -b and -e. " \
                                    "See 'help'")
        if bssid is not None:
            if bssid not in parser:
                raise PyritRuntimeError("No AccessPoint with BSSID '%s' " \
                                        "found in the capture file..." % \
                                        bssid)
            ap = parser[bssid]
        else:
            ap = None
        if essid is not None:
            if ap is None:
                aps = filter(lambda ap: (ap.essid is None
                                          or ap.essid == essid)
                                        and ap.isCompleted(),
                                        parser)
                if len(aps) > 0:
                    ap = aps[0]
                    self.tell("Picked AccessPoint %s automatically..." % ap)
                else:
                    raise PyritRuntimeError("No suitable AccessPoint with " \
                                            "that ESSID in the capture file.")
            else:
                if ap.essid is not None and ap.essid != essid:
                    self.tell("Warning: AccessPoint %s has ESSID '%s'. " \
                              "Using '%s' anyway." % (ap, ap.essid, essid), \
                              stream=sys.stderr)
        else:
            if ap.essid is None:
                raise PyritRuntimeError("The ESSID for AccessPoint %s is " \
                                        "not known from the capture file. " \
                                        "Specify it using the option -e." % ap)
        return ap

    def _getStorage(self, url):
        self.tell("Connecting to storage at '%s'... " % url, end=None)
        storage = cpyrit.storage.getStorage(url)
        self.tell("connected.")
        return storage

    def create_essid(self, storage, essid):
        """Create a new ESSID"""
        if essid in storage.essids:
            self.tell("ESSID already created")
        else:
            storage.essids.create_essid(essid)
            self.tell("Created ESSID '%s'" % essid)
    create_essid.cli_options = (('-e', '-u'), ())

    def delete_essid(self, storage, essid, confirm=True):
        """Delete a ESSID from the database"""
        if essid not in storage.essids:
            raise PyritRuntimeError("ESSID not found...")
        else:
            if confirm:
                self.tell("All results for ESSID '%s' will be deleted! " \
                          "Continue? [y/N]" % essid, end=None)
                if sys.stdin.readline().strip() != 'y':
                    raise PyritRuntimeError("aborted.")
            self.tell("deleting...")
            del storage.essids[essid]
            self.tell("Deleted ESSID '%s'." % essid)
    delete_essid.cli_options = (('-e', '-u'), ())

    def list_cores(self):
        """List available cores"""
        from cpyrit import cpyrit
        cp = cpyrit.CPyrit()
        self.tell("The following cores seem available...")
        for i, core in enumerate(cp.cores):
            self.tell("#%i:  '%s'" % (i + 1, core))
    list_cores.cli_options = ((), ())

    def list_essids(self, storage):
        """List all ESSIDs but don't count matching results"""
        self.tell("Listing ESSIDs...\n")
        for essid in sorted(storage.essids):
            self.tell("ESSID '%s'" % essid)
        self.tell("")
    list_essids.cli_options = (('-u', ), ())

    def eval_results(self, storage):
        """Count the available passwords and matching results"""
        self.tell("Querying...", end=None, flush=True)
        pwcount, essid_results = storage.getStats()
        self.tell("\rPasswords available: %i\n" % pwcount)
        if len(essid_results) > 0:
            m = max(len(essid) for essid in essid_results.iterkeys())
            n = max(len(str(c)) for c in essid_results.itervalues())
            for essid, rescnt in sorted(essid_results.iteritems()):
                self.tell("ESSID '%s'%s : %s%i (%.2f%%)" % (essid, \
                            ' ' * (m - len(essid)), \
                            ' ' * (n - len(str(rescnt))), rescnt, \
                            (rescnt * 100.0 / pwcount) if pwcount > 0 else 0))
            self.tell('')
    eval_results.cli_options = (('-u', ), ())

    def import_passwords(self, storage, infile, unique_check=True):
        """Import passwords from a file-like source"""
        i = 0
        storage.passwords.unique_check = unique_check
        perfcounter = cpyrit.util.PerformanceCounter()
        with cpyrit.util.FileWrapper(infile) as reader:
            with storage.passwords as pwstore:
                for i, line in enumerate(reader):
                    pwstore.store_password(line)
                    if i % 100000 == 0:
                        perfcounter += 100000
                        self.tell("\r%i lines read (%.1f lines/s)..." % \
                                  (i, perfcounter.avg), end=None, flush=True)
                self.tell("\r%i lines read. Flushing buffers..." % (i + 1))
        self.tell('All done.')
    import_passwords.cli_options = (('-i', '-u'), ())

    def import_unique_passwords(self, storage, infile):
        """Import unique passwords from a file-like source"""
        self.import_passwords(storage, infile, unique_check=False)
    import_unique_passwords.cli_options = (('-i', '-u'), ())

    def export_passwords(self, storage, outfile):
        """Export passwords to a file"""
        perfcounter = cpyrit.util.PerformanceCounter()
        with cpyrit.util.AsyncFileWriter(outfile) as awriter:
            for idx, pwset in enumerate(storage.iterpasswords()):
                awriter.write('\n'.join(pwset))
                awriter.write('\n')
                perfcounter += len(pwset)
                self.tell("%i lines written (%.1f lines/s, %.1f%%)\r" % \
                            (perfcounter.total, perfcounter.avg, \
                            (idx + 1) * 100.0 / len(storage.passwords)), \
                            end=None, sep=None)
        self.tell("\nAll done")
    export_passwords.cli_options = (('-o', '-u'), ())

    def export_cowpatty(self, storage, essid, outfile):
        """Export results to a new cowpatty file"""
        if essid not in storage.essids:
            raise PyritRuntimeError("The ESSID you specified can't be found.")
        perfcounter = cpyrit.util.PerformanceCounter()
        self.tell("Exporting to '%s'..." % outfile)
        with cpyrit.util.AsyncFileWriter(outfile) as filewriter:
            with cpyrit.util.CowpattyFile(filewriter, 'w', essid) as cowpwriter:
                try:
                    for results in storage.iterresults(essid):
                        cowpwriter.write(results)
                        perfcounter += len(results)
                        self.tell("\r%i entries written (%.1f/s)..." % \
                                   (perfcounter.total, perfcounter.avg), \
                                  end=None, sep=None)
                except IOError:
                    self.tell("IOError while exporting to " \
                              "stdout ignored...", stream=sys.stderr)
        self.tell("\r%i entries written. All done." % perfcounter.total)
    export_cowpatty.cli_options = (('-u', '-e', '-o'), ())

    @requires_pckttools()
    def analyze(self, capturefile):
        """Analyze a packet-capture file"""
        parser = self._getParser(capturefile)
        for i, ap in enumerate(parser):
            self.tell("#%i: AccessPoint %s ('%s')" % (i + 1, ap, ap.essid))
            for j, sta in enumerate(ap):
                self.tell("  #%i: Station %s" % (j, sta), end=None, sep=None)
                self.tell(", handshake found" if sta.isCompleted() else '')
        if not any(ap.isCompleted() and ap.essid is not None for ap in parser):
            raise PyritRuntimeError("No valid EAOPL-handshake detected.")
    analyze.cli_options = (('-r', ), ())

    @requires_pckttools()
    def stripCapture(self, capturefile, outfile, bssid=None, essid=None):
        """Strip packet-capture files to the relevant packets"""
        parser = self._getParser(capturefile)
        if essid is not None or bssid is not None:
            ap_iter = (self._fuzzyGetAP(parser, bssid, essid), )
        else:
            ap_iter = parser
        with cpyrit.pckttools.Dot11PacketWriter(outfile) as writer:
            for i, ap in enumerate(ap_iter):
                self.tell("#%i: AccessPoint %s ('%s')" % (i + 1, ap, ap.essid))
                if ap.essidframe:
                    writer.write(ap.essidframe)
                for j, sta in enumerate(ap):
                    if not sta.isCompleted():
                        continue
                    self.tell("  #%i: Station %s (%i authentications)" % \
                                (j, sta, len(sta)))
                    for auth in sta:
                        for idx in xrange(3):
                            if auth.frames[idx] is not None:
                                writer.write(auth.frames[idx])
        self.tell("\nNew pcap-file '%s' written (%i out of %i packets)" % \
                    (outfile, writer.pcktcount, parser.pcktcount))
    stripCapture.cli_options = (('-r', '-o'), ('-e', '-b'))

    @requires_pckttools()
    def stripLive(self, capturefile, outfile):
        """Capture relevant packets from a live capture-source"""

        def __new_ap(self, parser, writer, ap):
            writer.write(ap.essidframe)
            self.tell("%i/%i: New AccessPoint %s ('%s')" % \
                        (writer.pcktcount, parser.pcktcount, ap, ap.essid))

        def __new_sta(self, parser, writer, sta):
            self.tell("%i/%i: New Station %s (AP %s)" % \
                        (writer.pcktcount, parser.pcktcount, sta, sta.ap))

        def __new_auth(self, parser, writer, auth):
            for i in xrange(3):
                if auth.frames[i] is not None:
                    writer.write(auth.frames[i])
            self.tell("%i/%i: Auth AP %s <-> STA %s" % \
                        (writer.pcktcount, parser.pcktcount, auth.station.ap, \
                        auth.station))

        writer = cpyrit.pckttools.Dot11PacketWriter(outfile)
        parser = cpyrit.pckttools.PacketParser()
        parser.new_ap_callback = lambda ap: __new_ap(self, parser, writer, ap)
        parser.new_station_callback = lambda sta: __new_sta(self, parser, \
                                                            writer, sta)
        parser.new_auth_callback = lambda auth: __new_auth(self, parser, \
                                                            writer, auth)
        self.tell("Parsing packets from '%s'..." % capturefile)
        try:
            parser.parse_file(capturefile)
        except (KeyboardInterrupt, SystemExit):
            self.tell("\nInterrupted...\n")
        else:
            self.tell("\nCapture-source was closed...\n")
        finally:
            writer.close()

        for i, ap in enumerate(parser):
            self.tell("#%i: AccessPoint %s ('%s')" % (i + 1, ap, ap.essid))
            for j, sta in enumerate(ap):
                if sta.isCompleted():
                    self.tell("  #%i: Station %s (%i authentications)" % \
                                (j, sta, len(sta)))
        self.tell("\nNew pcap-file '%s' written (%i out of %i packets)" % \
                    (outfile, writer.pcktcount, parser.pcktcount))
    stripLive.cli_options = (('-r', '-o'), ())

    def export_hashdb(self, storage, outfile, essid=None):
        """Export results to an airolib database"""
        import sqlite3
        if essid is None:
            essids = storage.essids
        else:
            essids = [essid]
        con = sqlite3.connect(outfile)
        con.text_factory = str
        cur = con.cursor()
        cur.execute('SELECT * FROM sqlite_master')
        tbls = [x[1] for x in cur.fetchall() if x[0] == u'table']
        if u'pmk' not in tbls or u'essid' not in tbls or u'passwd' not in tbls:
            self.tell("The database '%s' seems to be uninitialized. " % \
                      outfile)
            self.tell("Trying to create default table-layout...", end=None)
            try:
                cur.execute("CREATE TABLE essid (" \
                            "essid_id INTEGER PRIMARY KEY AUTOINCREMENT," \
                            "essid TEXT," \
                            "prio INTEGER DEFAULT 64)")

                cur.execute("CREATE TABLE passwd (" \
                            "passwd_id INTEGER PRIMARY KEY AUTOINCREMENT, " \
                            "passwd TEXT)")

                cur.execute("CREATE TABLE pmk (" \
                            "pmk_id INTEGER PRIMARY KEY AUTOINCREMENT, " \
                            "passwd_id INTEGER, " \
                            "essid_id INTEGER, " \
                            "pmk BLOB)")

                cur.execute("CREATE TABLE workbench (" \
                            "wb_id INTEGER PRIMARY KEY AUTOINCREMENT, " \
                            "essid_id INTEGER, " \
                            "passwd_id INTEGER, " \
                            "lockid INTEGER DEFAULT 0)")

                cur.execute("CREATE INDEX lock_lockid ON workbench (lockid);")
                cur.execute("CREATE UNIQUE INDEX essid_u ON essid (essid)")
                cur.execute("CREATE UNIQUE INDEX passwd_u ON passwd (passwd)")
                cur.execute("CREATE UNIQUE INDEX ep_u ON pmk " \
                            "(essid_id, passwd_id)")

                cur.execute("CREATE UNIQUE INDEX wb_u ON workbench " \
                            "(essid_id, passwd_id)")

                cur.execute("CREATE TRIGGER delete_essid DELETE ON essid " \
                            "BEGIN DELETE FROM pmk " \
                            "WHERE pmk.essid_id = OLD.essid_id;" \
                            "DELETE FROM workbench " \
                            "WHERE workbench.essid_id = OLD.essid_id;" \
                            "END")

                cur.execute("CREATE TRIGGER delete_passwd DELETE ON passwd " \
                            "BEGIN DELETE FROM pmk " \
                            "WHERE pmk.passwd_id = OLD.passwd_id;" \
                            "DELETE FROM workbench " \
                            "WHERE workbench.passwd_id = OLD.passwd_id;" \
                            "END")

                self.tell("Tables created...")
            except:
                con.rollback()
                cur.close()
                con.close()
                self.tell("Failed to initialize the database.", \
                            stream=sys.stderr)
                raise
        try:
            cur.execute("PRAGMA synchronous = 1")
            i = 0
            self.tell("Writing passwords...")
            for pwset in storage.iterpasswords():
                i += len(pwset)
                cur.executemany("INSERT OR IGNORE INTO passwd " \
                                "(passwd) VALUES (?)", [(p, ) for p in pwset])
                self.tell("Wrote %i lines...\r" % i, end=None, sep=None)
            self.tell("\nWriting ESSIDs and results...")
            for cur_essid in essids:
                self.tell("Writing '%s'..." % cur_essid)
                cur.execute("INSERT OR IGNORE INTO essid " \
                            "(essid) VALUES (?)", (cur_essid, ))
                essid_id = cur.execute("SELECT essid_id FROM essid " \
                                        "WHERE essid = ?", \
                                            (cur_essid, )).fetchone()[0]
                i = 0
                for results in storage.iterresults(cur_essid):
                    i += len(results)
                    cur.executemany("INSERT OR IGNORE INTO pmk " \
                                    "(essid_id, passwd_id, pmk) " \
                                    "SELECT ?, passwd_id, ? FROM passwd " \
                                    "WHERE passwd = ?", \
                                        ((essid_id, buffer(pmk), pw) \
                                            for pw, pmk in results))
                    self.tell("Wrote %i lines...\r" % i, end=None, sep=None)
            self.tell("\nAll done.")
        except:
            con.rollback()
            self.tell("There was an error while exporting. The database has " \
                      "not been modified...", stream=sys.stderr)
            raise
        else:
            con.commit()
        finally:
            cur.close()
            con.close()
    export_hashdb.cli_options = (('-u', '-o', ), ('-e', ))

    def passthrough(self, essid, infile, outfile):
        """Compute PMKs and write results to a file"""
        perfcounter = cpyrit.util.PerformanceCounter()
        with cpyrit.util.FileWrapper(infile) as reader:
            try:
                with cpyrit.util.AsyncFileWriter(outfile) as writer:
                    with cpyrit.util.CowpattyFile(writer, 'w', essid) as cowpwriter:
                        for results in cpyrit.util.PassthroughIterator(essid, reader):
                            cowpwriter.write(results)
                            perfcounter += len(results)
                            self.tell("Computed %i PMKs so far; %i PMKs per " \
                                      "second\r" % (perfcounter.total, \
                                                    perfcounter.avg), \
                                      end=None, sep=None)
            except IOError:
                self.tell("IOError while writing to stdout ignored.", \
                            stream=sys.stderr)
            finally:
                self.tell("Computed %i PMKs total; %i PMKs per second" % \
                          (perfcounter.total, perfcounter.avg))
    passthrough.cli_options = (('-i', '-o', '-e'), ())

    def batchprocess(self, storage, essid=None, outfile=None):
        """Batchprocess the database"""
        if outfile is not None and essid is None:
            raise PyritRuntimeError("Results will be written to a file " \
                                    "while batchprocessing. This requires " \
                                    "to specify a single ESSID.")
        if essid is not None:
            if essid not in storage.essids:
                storage.essids.create_essid(essid)
            essids = [essid]
        else:
            essids = []
            pwcount, essid_results = storage.getStats()
            if len(essid_results) == 0:
                raise PyritRuntimeError("No ESSID in storage. Use 'create_" \
                                        "essid' first.")
            for e, rescount in essid_results.iteritems():
                if rescount < pwcount:
                    essids.append(e)
        if outfile is not None:
            outfilewriter = cpyrit.util.AsyncFileWriter(outfile)
            cowpwriter = cpyrit.util.CowpattyFile(outfilewriter, 'w', essid)
        else:
            cowpwriter = None
        for cur_essid in essids:
            perfcounter = cpyrit.util.PerformanceCounter()
            self.tell("Working on ESSID '%s'" % cur_essid)
            dbiterator = cpyrit.util.StorageIterator(storage, cur_essid, \
                                    yieldOldResults=cowpwriter is not None)
            totalKeys = len(dbiterator)
            for results in dbiterator:
                perfcounter += len(results)
                if cowpwriter is not None:
                    try:
                        cowpwriter.write(results)
                    except IOError:
                        self.tell("IOError while batchprocessing...")
                        raise SystemExit
                solvedKeys = dbiterator.keycount()
                self.tell("Processed %i/%i workunits so far (%.1f%%); " \
                          "%i PMKs per second.\r" % (solvedKeys, \
                            totalKeys, \
                            100.0 * solvedKeys / totalKeys, \
                            perfcounter.avg), \
                          end = None, sep = None)
            self.tell("Processed all workunits for ESSID '%s'; " \
                      "%i PMKs per second." % \
                      (cur_essid, perfcounter.avg))
            self.tell('')
        if cowpwriter is not None:
            cowpwriter.close()
        self.tell("Batchprocessing done.")
    batchprocess.cli_options = (('-u', ), ('-e', '-o'))

    def relay(self, storage):
        """Relay a storage-url via RPC"""
        rpcd = cpyrit.storage.RPCServer(storage)
        self.tell("Server started...")
        try:
            rpcd.serve_forever()
        except KeyboardInterrupt, SystemExit:
            pass
        self.tell("Server closed")
    relay.cli_options = (('-u', ), ())

    def serve(self):
        """Serve local hardware to other Pyrit clients"""
        server = cpyrit.network.NetworkServer()
        listener = cpyrit.network.NetworkAnnouncementListener()
        perfcounter = cpyrit.util.PerformanceCounter()
        try:
            while server.isAlive():
                addr = listener.waitForAnnouncement(block=True, timeout=1.0)
                if addr is not None and addr not in server:
                    server.addClient(addr)
                perfcounter.addAbsolutePoint(server.stat_scattered)
                if perfcounter.avg > 0:
                    y = (server.stat_gathered - server.stat_enqueued) / perfcounter.avg
                else:
                    y = 0
                self.tell("\rServing %i active clients; %i PMKs/s; %.1f TTS" % (len(server), perfcounter.avg, y), end=None)
        except KeyboardInterrupt, SystemExit:
            self.tell("\nShutdown with %i active clients..." % len(server))
            listener.shutdown()
            server.shutdown()
    serve.cli_options = ((), ())

    @requires_pckttools()
    def attack_passthrough(self, infile, capturefile, \
                            essid=None, bssid=None):
        """Attack a handshake with passwords from a file"""
        ap = self._fuzzyGetAP(self._getParser(capturefile), bssid, essid)
        if not ap.isCompleted():
            raise PyritRuntimeError("No valid handshakes for AccessPoint %s " \
                                    "found in the capture file." % ap)
        if essid is None:
            essid = ap.essid
        perfcounter = cpyrit.util.PerformanceCounter()
        crackers = []
        for auth in ap.getCompletedAuthentications():
            crackers.append(cpyrit.pckttools.EAPOLCracker(auth))
        with cpyrit.util.FileWrapper(infile) as reader:
            resultiterator = cpyrit.util.PassthroughIterator(essid, reader)
            for results in resultiterator:
                for cracker in crackers:
                    cracker.enqueue(results)
                perfcounter += len(results)
                self.tell("Tried %i PMKs so far; %i PMKs per second.\r" % \
                            (perfcounter.total, perfcounter.avg),
                          end=None, sep=None)
                if any(cracker.solution is not None for cracker in crackers):
                    break
        self.tell("Tried %i PMKs so far; %i PMKs per second." % \
                    (perfcounter.total, perfcounter.avg))
        for cracker in crackers:
            cracker.join()
            if cracker.solution is not None:
                self.tell("\nThe password is '%s'.\n" % cracker.solution)
                break
        else:
            raise PyritRuntimeError("\nPassword was not found.\n")
    attack_passthrough.cli_options = (('-i', '-r'), ('-e', '-b'))

    @requires_pckttools()
    def attack_batch(self, storage, capturefile, essid=None, bssid=None):
        """Attack a handshake with PMKs/passwords from the db"""
        ap = self._fuzzyGetAP(self._getParser(capturefile), bssid, essid)
        if not ap.isCompleted():
            raise PyritRuntimeError("No valid handshakes for AccessPoint %s " \
                                    "found in the capture file." % ap)
        if essid is None:
            essid = ap.essid
        if essid not in storage.essids:
            storage.essids.create_essid(essid)
        perfcounter = cpyrit.util.PerformanceCounter()
        for auth in ap.getCompletedAuthentications():
            with cpyrit.pckttools.EAPOLCracker(auth) as cracker:
                dbiterator = cpyrit.util.StorageIterator(storage, essid)
                self.tell("Attacking handshake with Station %s" % auth.station)
                for idx, results in enumerate(dbiterator):
                    cracker.enqueue(results)
                    perfcounter += len(results)
                    self.tell("Tried %i PMKs so far (%.1f%%); " \
                              "%i PMKs per second.\r" % (perfcounter.total,
                                100.0 * (idx+1) / len(storage.passwords),
                                perfcounter.avg),
                              end=None, sep=None)
                    if cracker.solution:
                        break
                self.tell('')
            if cracker.solution is not None:
                self.tell("\nThe password is '%s'.\n" % cracker.solution)
                break
        else:
            raise PyritRuntimeError("\nThe password was not found.\n")
    attack_batch.cli_options = (('-r', '-u'), ('-e', '-b'))

    @requires_pckttools()
    def attack_db(self, storage, capturefile, bssid=None, essid=None):
        """Attack a handshake with PMKs from the db"""
        ap = self._fuzzyGetAP(self._getParser(capturefile), bssid, essid)
        if not ap.isCompleted():
            raise PyritRuntimeError("No valid handshakes for AccessPoint " \
                                    "%s found in the capture file." % ap)
        if essid is None:
            essid = ap.essid
        if essid not in storage.essids:
            raise PyritRuntimeError("The ESSID '%s' can't be found in the " \
                                    "database." % essid)
        WUcount = storage.essids.keycount(essid)
        perfcounter = cpyrit.util.PerformanceCounter()
        for auth in ap.getCompletedAuthentications():
            with cpyrit.pckttools.EAPOLCracker(auth) as cracker:
                self.tell("Attacking handshake with " \
                          "Station %s..." % auth.station)
                for idx, results in enumerate(cpyrit.util.StorageIterator(
                                                storage, essid,
                                                yieldNewResults=False)):
                    cracker.enqueue(results)
                    perfcounter += len(results)
                    self.tell("Tried %i PMKs so far (%.1f%%); " \
                              "%i PMKs per second.\r" % (perfcounter.total,
                                100.0 * (idx+1) / WUcount,
                                perfcounter.avg),
                              end=None, sep=None)
                    if cracker.solution is not None:
                        break
                self.tell('')
            if cracker.solution is not None:
                self.tell("\nThe password is '%s'.\n" % cracker.solution)
                break
        else:
            raise PyritRuntimeError("\nPassword was not found.\n")
    attack_db.cli_options = (('-r', '-u'), ('-e', '-b'))

    @requires_pckttools()
    def attack_cowpatty(self, capturefile, infile, bssid=None, essid=None):
        """Attack a handshake with PMKs from a cowpatty-file"""
        with cpyrit.util.CowpattyFile(infile) as cowreader:
            if essid is None:
                essid = cowreader.essid
            ap = self._fuzzyGetAP(self._getParser(capturefile), bssid, essid)
            if not ap.isCompleted():
                raise PyritRuntimeError("No valid handshakes for " \
                                        "AccessPoint %s found in the " \
                                        "capture file." % ap)
            if essid is None:
                essid = ap.essid
            if essid != cowreader.essid:
                raise PyritRuntimeError("Chosen ESSID '%s' and file's ESSID " \
                                        "'%s' do not match" % \
                                        (essid, cowreader.essid))
            perfcounter = cpyrit.util.PerformanceCounter()
            for auth in ap.getCompletedAuthentications():
                with cpyrit.pckttools.EAPOLCracker(auth) as cracker:
                    self.tell("Attacking handshake with " \
                              "Station %s..." % auth.station)
                    for results in cowreader:
                        cracker.enqueue(results)
                        perfcounter += len(results)
                        self.tell("Tried %i PMKs so far; " \
                                  "%i PMKs per second.\r" % (perfcounter.total,
                                                             perfcounter.avg),
                                  end=None, sep=None)
                        if cracker.solution is not None:
                            break
                    self.tell('')
                if cracker.solution is not None:
                    self.tell("\nThe password is '%s'.\n" % cracker.solution)
                    break
            else:
                raise PyritRuntimeError("\nPassword was not found.\n")
    attack_cowpatty.cli_options = (('-r', '-i'), ('-e', '-b'))

    def benchmark(self, timeout=60):
        """Determine performance of available cores"""
        from cpyrit import cpyrit
        cp = cpyrit.CPyrit()
        # 'Burn-in' so that all modules are forced to load and buffers can
        # calibrate to optimal size
        self.tell("Calibrating...", end=None)
        t = time.time()
        while time.time() - t < 3:
            cp.enqueue('foo', ['barbarbar']*1500)
            cp.dequeue(block=False)
        for r in cp:
            pass
        # Minimize scheduling overhead...
        buffersize = max(min(int(cp.getPeakPerformance()), 50000), 500)
        cp.resetStatistics()
        cycler = itertools.cycle(('\\|/-'))
        t = time.time()
        perfcounter = cpyrit.util.PerformanceCounter()
        while time.time() - t < timeout:
            pws = ["barbarbar%s" % random.random() for i in xrange(buffersize)]
            cp.enqueue('foo', pws)
            r = cp.dequeue(block=False)
            if r is not None:
                perfcounter += len(r)
            self.tell("\rRunning benchmark (%.1f PMKs/s)... %s" % \
                    (perfcounter.avg, cycler.next()), end=None)
        self.tell('')
        for r in cp:
            pass
        self.tell("\nComputed %.2f PMKs/s total." % perfcounter.avg)
        for i, core in enumerate(cp.cores):
            if core.compTime > 0:
                perf = core.resCount / core.compTime
            else:
                perf = 0
            if core.callCount > 0 and perf > 0:
                rtt = (core.resCount / core.callCount) / perf
            else:
                rtt = 0
            self.tell("#%i: '%s': %.1f PMKs/s (RTT %.1f)" % \
                        (i + 1, core.name, perf, rtt))
    benchmark.cli_options = ((), ())

    def selftest(self, timeout=60):
        """Test hardware to ensure it computes correct results"""
        from cpyrit import cpyrit
        cp = cpyrit.CPyrit()
        self.tell("Cores incorporated in the test:")
        for i, core in enumerate(cp.cores):
            self.tell("#%i:  '%s'" % (i+1, core))
        self.tell("\nRunning selftest...")
        workunits = []
        t = time.time()
        err = False
        while time.time() - t < timeout and not err:
            essid = random.choice(cpyrit.util.PMK_TESTVECTORS.keys())
            pws = []
            for i in xrange(random.randrange(10, 1000)):
                pws.append(random.choice(cpyrit.util.PMK_TESTVECTORS[essid].keys()))
            workunits.append((essid, pws))
            cp.enqueue(essid, pws)
            while True:
                solvedPMKs = cp.dequeue(block=False)
                if solvedPMKs is not None:
                    essid, pws = workunits.pop(0)
                    for i, pw in enumerate(pws):
                        if cpyrit.util.PMK_TESTVECTORS[essid][pw] != solvedPMKs[i]:
                            err = True
                            break
                if err or not solvedPMKs:
                    break
        if not err:
            for solvedPMKs in cp:
                essid, pws = workunits.pop(0)
                for i, pw in enumerate(pws):
                    if cpyrit.util.PMK_TESTVECTORS[essid][pw] != solvedPMKs[i]:
                        err = True
                        break
        if err or len(workunits) != 0 or len(cp) != 0:
            raise PyritRuntimeError("\n!!! WARNING !!!\nAt least some " \
                                    "results seem to be invalid. This may " \
                                    "be caused by a bug in Pyrit, faulty " \
                                    "hardware or malicious network clients. " \
                                    "Do not trust this installation...\n")
        else:
            self.tell("\nAll results verified. Your installation seems OK.")
    selftest.cli_options = ((), ())

    def verify(self, storage, essid=None):
        """Verify 10% of the results by recomputation"""
        from cpyrit import cpyrit
        cp = cpyrit.CPyrit()
        if essid is not None:
            if essid not in storage.essids:
                raise PyritRuntimeError("The ESSID '%s' is not found in the " \
                                        "repository" % essid)
            else:
                essids = [essid]
        else:
            essids = storage.essids
        err = False
        perfcounter = cpyrit.util.PerformanceCounter()
        workunits = []
        for essid in essids:
            self.tell("Verifying ESSID '%s'" % essid)
            for key, results in storage.essids.iteritems(essid):
                sample = random.sample(results, int(len(results) * 0.1))
                if len(sample) > 0:
                    pws, pmks = zip(*sample)
                    workunits.append((essid, key, tuple(pmks)))
                    cp.enqueue(essid, pws)
                    solvedPMKs = cp.dequeue(block=False)
                    if solvedPMKs is not None:
                        perfcounter += len(solvedPMKs)
                        testedEssid, testedKey, testedPMKs = workunits.pop(0)
                        if testedPMKs != solvedPMKs:
                            self.tell("Workunit %s for ESSID '%s' seems " \
                                      "corrupted" % (testedKey, testedEssid), \
                                      stream=sys.stderr)
                            err = True
                self.tell("Computed %i PMKs so far; %i PMKs per second.\r" % \
                            (perfcounter.total, perfcounter.avg), \
                          end=None, sep=None)
            for solvedPMKs in cp:
                perfcounter += len(solvedPMKs)
                testedEssid, testedKey, testedPMKs = workunits.pop(0)
                if testedPMKs != solvedPMKs:
                    self.tell("Workunit %s for ESSID '%s' seems corrupted." % \
                            (testedKey, testedEssid), stream=sys.stderr)
                    err = True
        self.tell("\nVerified %i PMKs with %i PMKs/s." % \
                (perfcounter.total, perfcounter.avg))
        if err:
            raise PyritRuntimeError(
                    "\nAt least one workunit-file contains invalid results." \
                    " There are two options now:\n" \
                    "* The results on the disk are corrupted or invalid. " \
                    "You should mistrust the entire repository but at least " \
                    "delete and recompute the offending ESSIDs.\n" \
                    "* The result on the disk are correct but your " \
                    "installation is broken and currently computes invalid " \
                    "results.\nRun 'selftest' for an extensive self-test " \
                    "in order to tell the two options apart.")
        else:
            self.tell("Everything seems OK.")
    verify.cli_options = (('-u', ), ('-e', ))

    commands = {'analyze': analyze,
                'attack_batch': attack_batch,
                'attack_cowpatty': attack_cowpatty,
                'attack_db': attack_db,
                'attack_passthrough': attack_passthrough,
                'batch': batchprocess,
                'benchmark': benchmark,
                'create_essid': create_essid,
                'delete_essid': delete_essid,
                'eval': eval_results,
                'export_cowpatty': export_cowpatty,
                'export_hashdb': export_hashdb,
                'export_passwords': export_passwords,
                'help': print_help,
                'import_passwords': import_passwords,
                'import_unique_passwords': import_unique_passwords,
                'list_cores': list_cores,
                'list_essids': list_essids,
                'passthrough': passthrough,
                'relay': relay,
                'selftest': selftest,
                'serve': serve,
                'strip': stripCapture,
                'stripLive': stripLive,
                'verify': verify}
