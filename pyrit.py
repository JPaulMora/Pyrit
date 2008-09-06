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


from blobspace import *
from cpyrit import CPyrit

class Pyrit(object):
    """
    The Pyrit class is a further abstraction of general tasks from the blobspace class.
    The commandline-client and to-be-written GUIs are built upon this common codebase.
    """
    
    def __init__(self, essidstore_path='blobspace/essid', pwstore_path='blobspace/password'):
        self.pwstore = PasswordStore(pwstore_path)
        self.essidstore = EssidStore(essidstore_path)
        
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
    
    def export_cowpatty(self, essid):
        essid_obj = self.essidstore.open_essid('linksys-den')
        idx = len(essid_obj.results) - 1
        yield((idx, pack("<i", 0x43575041)))
        yield((idx, chr(0)*3))
        yield((idx, pack("<b32s", len(essid_obj.essid), essid_obj.essid)))
        for result in essid_obj.results:
            pyr_obj = essid_obj.open_result(result)
            for r in pyr_obj.results.items():
                yield (idx, pack("<b%ss32s" % len(r[0]), len(r[0]) + 32 + 1, r[0], r[1]))
            idx -= 1
            pyr_obj.close()
    
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
        return CPyrit().getCore(corename).solve(essid, passwordlist)


