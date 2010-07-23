#!/usr/bin/env python
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

import os
import shutil
import random
import unittest
import cStringIO
import tempfile

import cpyrit.config
import cpyrit.util
import cpyrit.storage
import pyrit_cli

cpyrit.config.cfg["rpc_server"] = "false"


class Pyrit_CLI_TestFunctions(unittest.TestCase):

    def setUp(self):
        self.storage_path = tempfile.mkdtemp()
        self.tempfile1 = os.path.join(self.storage_path, 'testfile1')
        self.tempfile2 = os.path.join(self.storage_path, 'testfile2')
        self.cli = pyrit_cli.Pyrit_CLI()
        self.cli.verbose = False

    def tearDown(self):
        shutil.rmtree(self.storage_path)

    def _createPasswords(self, filename):
        test_passwds = ['test123%i' % i for i in xrange(5000-5)]
        test_passwds += ['dictionary', 'helium02', 'MOM12345', \
                         'preinstall', 'password']
        random.shuffle(test_passwds)
        with cpyrit.util.AsyncFileWriter(filename) as f:
            f.write('\n'.join(test_passwds))
        return test_passwds

    def _createDatabase(self, storage):
        self.cli.create_essid(storage, 'linksys')
        self._createPasswords(self.tempfile1)
        self.cli.import_passwords(storage, self.tempfile1)
        
    def _computeDatabase(self, storage, essid):
        self.cli.create_essid(storage, essid)
        l = 0
        with cpyrit.util.StorageIterator(storage, essid) as dbiter:
            for results in dbiter:
                l += len(results)
        self.assertEqual(l, 5000)

    def testListEssids(self):
        storage = self.getStorage()
        self._createDatabase(storage)
        self.cli.list_essids(storage)

    def testCreateAndDeleteEssid(self):
        storage = self.getStorage()
        # EssidStore should be empty
        self.assertEqual(len(storage.essids), 0)
        self.assertFalse('testessid' in storage.essids)
        # Add one ESSID
        self.cli.create_essid(storage, essid='testessid')
        self.assertEqual(len(storage.essids), 1)
        self.assertTrue('testessid' in storage.essids)
        # Adding it second time should not cause an error
        self.cli.create_essid(storage, 'testessid')
        self.cli.delete_essid(storage, 'testessid', confirm=False)
        # EssidStore should be empty again
        self.assertEqual(len(storage.essids), 0)
        self.assertTrue('testessid' not in storage.essids)

    def testImportPasswords(self):
        storage = self.getStorage()
        self.assertEqual(len(storage.passwords), 0)
        # valid_passwds should get accepted, short_passwds ignored
        valid_passwds = ['test123%i' % i  for i in xrange(100000)]
        short_passwds = ['x%i' % i for i in xrange(30000)]
        test_passwds = valid_passwds + short_passwds
        random.shuffle(test_passwds)
        with cpyrit.util.AsyncFileWriter(self.tempfile1) as f:
            f.write('\n'.join(test_passwds))
        self.cli.import_passwords(storage, self.tempfile1)
        new_passwds = set()
        for key, pwset in storage.passwords.iteritems():
            new_passwds.update(pwset)
        self.assertEqual(new_passwds, set(valid_passwds))
        # There should be no duplicates
        random.shuffle(test_passwds)
        with cpyrit.util.FileWrapper(self.tempfile1, 'a') as f:
            f.write('\n')
            f.write('\n'.join(test_passwds))
        self.cli.import_passwords(storage, self.tempfile1)
        new_passwds = set()
        i = 0
        for key, pwset in storage.passwords.iteritems():
            new_passwds.update(pwset)
            i += len(pwset)
        self.assertEqual(i, len(valid_passwds))
        self.assertEqual(new_passwds, set(valid_passwds))

    def testAttackDB(self):
        storage = self.getStorage()
        self._createDatabase(storage)
        self._computeDatabase(storage, 'linksys')
        self.cli.attack_db(storage, 'wpapsk-linksys.dump.gz')
        self.cli.attack_db(storage, 'wpa2psk-linksys.dump.gz')
        self._computeDatabase(storage, 'MOM1')
        self.cli.attack_db(storage, 'wpa2psk-MOM1.dump.gz')
        self._computeDatabase(storage, '2WIRE972')
        self.cli.attack_db(storage, 'wpa2psk-2WIRE972.dump.gz')
        self._computeDatabase(storage, 'Red Apple')
        self.cli.attack_db(storage, 'wpa2psk-Red_Apple.dump.gz', 'Red Apple', '00:1d:7e:2c:b1:af')
        self._computeDatabase(storage, 'virgin broadband')
        self.cli.attack_db(storage, 'wpapsk-virgin_broadband.dump.gz')

    def testAttackCowpatty(self):
        storage = self.getStorage()
        self._createDatabase(storage)
        self._computeDatabase(storage, 'linksys')
        self.cli.export_cowpatty(storage, 'linksys', self.tempfile1)
        self.cli.attack_cowpatty('wpapsk-linksys.dump.gz', self.tempfile1)
        self.cli.attack_cowpatty('wpa2psk-linksys.dump.gz', self.tempfile1)
        self._computeDatabase(storage, 'MOM1')
        self.cli.export_cowpatty(storage, 'MOM1', self.tempfile1)
        self.cli.attack_cowpatty('wpa2psk-MOM1.dump.gz', self.tempfile1)
        self._computeDatabase(storage, '2WIRE972')
        self.cli.export_cowpatty(storage, '2WIRE972', self.tempfile1)
        self.cli.attack_cowpatty('wpa2psk-2WIRE972.dump.gz', self.tempfile1)
        self._computeDatabase(storage, 'Red Apple')
        self.cli.export_cowpatty(storage, 'Red Apple', self.tempfile1)
        self.cli.attack_cowpatty('wpa2psk-Red_Apple.dump.gz', self.tempfile1, 'Red Apple', '00:1d:7e:2c:b1:af')
        self._computeDatabase(storage, 'virgin broadband')
        self.cli.export_cowpatty(storage, 'virgin broadband', self.tempfile1)
        self.cli.attack_cowpatty('wpapsk-virgin_broadband.dump.gz', self.tempfile1)

    def testAttackBatch(self):
        storage = self.getStorage()
        self._createPasswords(self.tempfile1)
        self.cli.import_passwords(storage, self.tempfile1)
        self.cli.attack_batch(storage, 'wpapsk-linksys.dump.gz')
        self.cli.attack_batch(storage, 'wpa2psk-linksys.dump.gz')
        self.cli.attack_batch(storage, 'wpa2psk-2WIRE972.dump.gz')
        self.cli.attack_batch(storage, 'wpa2psk-MOM1.dump.gz')
        self.cli.attack_batch(storage, 'wpa2psk-Red_Apple.dump.gz', 'Red Apple', '00:1d:7e:2c:b1:af')
        self.cli.attack_batch(storage, 'wpapsk-virgin_broadband.dump.gz')

    def testPassthrough(self):
        storage = self.getStorage()
        self._createDatabase(storage)
        self.cli.passthrough('linksys', self.tempfile1, self.tempfile2)
        fileresults = []
        for results in cpyrit.util.CowpattyFile(self.tempfile2):
            fileresults.extend(results)
        dbresults = []
        with cpyrit.util.StorageIterator(storage, 'linksys', \
                                            yieldNewResults=True) as dbiter:
            for results in dbiter:
                dbresults.extend(results)
        self.assertEqual(sorted(fileresults), sorted(dbresults))

    def testBatch(self):
        storage = self.getStorage()
        test_passwds = self._createPasswords(self.tempfile1)
        self.cli.import_passwords(storage, self.tempfile1)
        self.cli.create_essid(storage, 'test1234')
        self.cli.batchprocess(storage)
        self.assertEqual(len(storage.passwords), \
                         storage.essids.keycount('test1234'))
        keys = list(storage.essids.iterkeys('test1234'))
        for key in keys:
            self.assertTrue(key in storage.passwords)
        for key in storage.passwords:
            self.assertTrue(key in keys)
            passwds = storage.passwords[key]
            r = storage.essids['test1234', key]
            self.assertTrue(sorted((pw for pw, pmk in r)) == sorted(passwds))

    def testBatchWithFile(self):
        storage = self.getStorage()
        test_passwds = self._createPasswords(self.tempfile1)
        self.cli.import_passwords(storage, self.tempfile1)
        self.cli.create_essid(storage, 'test1234')
        self.cli.batchprocess(storage, 'test1234', self.tempfile1)
        self.assertEqual(len(storage.passwords), \
                         storage.essids.keycount('test1234'))
        fileresults = []
        for results in cpyrit.util.CowpattyFile(self.tempfile1):
            fileresults.extend(results)
        dbresults = []
        with cpyrit.util.StorageIterator(storage, 'test1234', \
                                            yieldNewResults=False) as dbiter:
            for results in dbiter:
                dbresults.extend(results)
        self.assertEqual(sorted(fileresults), sorted(dbresults))

    def testEval(self):
        storage = self.getStorage()
        self._createDatabase(storage)
        self._computeDatabase(storage, 'test1')
        self._computeDatabase(storage, 'test2')
        self.cli.eval_results(storage)

    def testVerify(self):
        storage = self.getStorage()
        self._createDatabase(storage)
        self._computeDatabase(storage, 'test')
        # Should be OK
        self.cli.verify(storage)
        keys = list(storage.essids.iterkeys('test')) 
        for i in xrange(25):
            key = random.choice(keys)
            results = storage.essids['test', key]
            corrupted = tuple((pw, 'x'*32) for pw, pmk in results)
            storage.essids['test', key] = corrupted
        # Should fail
        self.assertRaises(pyrit_cli.PyritRuntimeError, self.cli.verify, storage)

    def testExportPasswords(self):
        storage = self.getStorage()
        test_passwds = self._createPasswords(self.tempfile1)
        self.cli.import_passwords(storage, self.tempfile1)
        self.cli.export_passwords(storage, self.tempfile1)
        with cpyrit.util.FileWrapper(self.tempfile1) as f:
            new_passwds = map(str.strip, f.readlines())
        self.assertEqual(sorted(test_passwds), sorted(new_passwds))

    def testExportCowpatty(self):
        storage = self.getStorage()
        self._createDatabase(storage)
        self._computeDatabase(storage, 'test')
        self.cli.export_cowpatty(storage, 'test', self.tempfile1)
        fileresults = []
        for results in cpyrit.util.CowpattyFile(self.tempfile1):
            fileresults.extend(results)
        dbresults = []
        with cpyrit.util.StorageIterator(storage, 'test', \
                                            yieldNewResults=False) as dbiter:
            for results in dbiter:
                dbresults.extend(results)
        self.assertEqual(sorted(fileresults), sorted(dbresults))

    def testExportHashdb(self):
        storage = self.getStorage()
        self._createDatabase(storage)
        self._computeDatabase(storage, 'test')
        os.unlink(self.tempfile1)
        self.cli.export_hashdb(storage, self.tempfile1)


class Pyrit_CLI_DB_TestFunctions(Pyrit_CLI_TestFunctions):

    def getStorage(self):
        return cpyrit.storage.getStorage('sqlite:///:memory:')


class Pyrit_CLI_FS_TestFunctions(Pyrit_CLI_TestFunctions):

    def getStorage(self):
        return cpyrit.storage.getStorage('file://' + self.storage_path)

    def testListCores(self):
        self.cli.list_cores()

    def testPrintHelp(self):
        self.cli.print_help()

    def testSelfTest(self):
        self.cli.selftest(timeout=3)

    def testBenchmark(self):
        self.cli.benchmark(timeout=3)

    def testAnalyze(self):
        self.cli.analyze(capturefile='wpapsk-linksys.dump.gz')
        self.cli.analyze(capturefile='wpa2psk-linksys.dump.gz')
        self.cli.analyze(capturefile='wpa2psk-MOM1.dump.gz')
        self.cli.analyze(capturefile='wpa2psk-2WIRE972.dump.gz')
        self.cli.analyze(capturefile='wpapsk-virgin_broadband.dump.gz')

    def testStripCapture(self):
        self.cli.stripCapture('wpapsk-linksys.dump.gz', self.tempfile1)
        parser = self.cli._getParser(self.tempfile1)
        self.assertTrue('00:0b:86:c2:a4:85' in parser)
        self.assertEqual(parser['00:0b:86:c2:a4:85'].essid, 'linksys')
        self.assertTrue('00:13:ce:55:98:ef' in parser['00:0b:86:c2:a4:85'])
        self.assertTrue(parser['00:0b:86:c2:a4:85'].isCompleted())
        self._createPasswords(self.tempfile2)
        self.cli.attack_passthrough(self.tempfile2, self.tempfile1)
        self.cli.stripCapture('wpa2psk-linksys.dump.gz', self.tempfile1)
        self.cli.attack_passthrough(self.tempfile2, self.tempfile1)
        self.cli.stripCapture('wpa2psk-linksys.dump.gz', self.tempfile1)
        self.cli.attack_passthrough(self.tempfile2, self.tempfile1)
        self.cli.stripCapture('wpa2psk-MOM1.dump.gz', self.tempfile1)
        self.cli.attack_passthrough(self.tempfile2, self.tempfile1)
        self.cli.stripCapture('wpa2psk-2WIRE972.dump.gz', self.tempfile1)
        self.cli.attack_passthrough(self.tempfile2, self.tempfile1)
        self.cli.stripCapture('wpa2psk-Red_Apple.dump.gz', self.tempfile1)
        self.cli.attack_passthrough(self.tempfile2, self.tempfile1, "Red Apple", '00:1d:7e:2c:b1:af')
        self.cli.stripCapture('wpapsk-virgin_broadband.dump.gz', self.tempfile1)
        self.cli.attack_passthrough(self.tempfile2, self.tempfile1)

    def testStripLive(self):
        self.cli.stripLive('wpa2psk-linksys.dump.gz', self.tempfile1)
        parser = self.cli._getParser(self.tempfile1)
        self.assertTrue('00:0b:86:c2:a4:85' in parser)
        self.assertEqual(parser['00:0b:86:c2:a4:85'].essid, 'linksys')
        self.assertTrue('00:13:ce:55:98:ef' in parser['00:0b:86:c2:a4:85'])
        self.assertTrue(parser['00:0b:86:c2:a4:85'].isCompleted())
        self._createPasswords(self.tempfile2)
        self.cli.attack_passthrough(self.tempfile2, self.tempfile1)
        self.cli.stripLive('wpa2psk-linksys.dump.gz', self.tempfile1)
        self.cli.attack_passthrough(self.tempfile2, self.tempfile1)
        self.cli.stripLive('wpa2psk-linksys.dump.gz', self.tempfile1)
        self.cli.attack_passthrough(self.tempfile2, self.tempfile1)
        self.cli.stripCapture('wpa2psk-MOM1.dump.gz', self.tempfile1)
        self.cli.attack_passthrough(self.tempfile2, self.tempfile1)
        self.cli.stripLive('wpa2psk-2WIRE972.dump.gz', self.tempfile1)
        self.cli.attack_passthrough(self.tempfile2, self.tempfile1)
        self.cli.stripLive('wpa2psk-Red_Apple.dump.gz', self.tempfile1)
        self.cli.attack_passthrough(self.tempfile2, self.tempfile1, 'Red Apple', '00:1d:7e:2c:b1:af')
        self.cli.stripLive('wpapsk-virgin_broadband.dump.gz', self.tempfile1)
        self.cli.attack_passthrough(self.tempfile2, self.tempfile1)

    def testAttackPassthrough(self):
        self._createPasswords(self.tempfile1)
        self.cli.attack_passthrough(self.tempfile1, 'wpapsk-linksys.dump.gz')
        self.cli.attack_passthrough(self.tempfile1, 'wpa2psk-linksys.dump.gz')
        self.cli.attack_passthrough(self.tempfile1, 'wpa2psk-MOM1.dump.gz')
        self.cli.attack_passthrough(self.tempfile1, 'wpa2psk-2WIRE972.dump.gz')
        self.cli.attack_passthrough(self.tempfile1, 'wpa2psk-Red_Apple.dump.gz', 'Red Apple', '00:1d:7e:2c:b1:af')
        self.cli.attack_passthrough(self.tempfile1, 'wpapsk-virgin_broadband.dump.gz')


if __name__ == "__main__":
    print "Testing with filesystem-storage..."
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(Pyrit_CLI_FS_TestFunctions)
    unittest.TextTestRunner(verbosity=2).run(suite)

    try:
        storage = cpyrit.storage.getStorage('sqlite:///:memory:')
    except cpyrit.util.SqlalchemyImportError:
        print "SQLAlchemy seems to be unavailable; skipping tests..."
    else:
        print "Testing with database-storage..."
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromTestCase(Pyrit_CLI_DB_TestFunctions)
        unittest.TextTestRunner(verbosity=2).run(suite)
