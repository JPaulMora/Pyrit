#!/usr/bin/python
from pysqlite2 import dbapi2 as sqlite
from sys import argv

if len(argv) != 2:
    print "Usage: create_hashdb.py {dbname}"
    exit()
print "Creating '%s'" % argv[1]
con = sqlite.connect(argv[1])
x = con.execute
x('CREATE TABLE essid (essid_id INTEGER PRIMARY KEY AUTOINCREMENT, essid TEXT, prio INTEGER DEFAULT 64)')
x('CREATE TABLE passwd (passwd_id INTEGER PRIMARY KEY AUTOINCREMENT, passwd TEXT)')
x('CREATE TABLE pmk (pmk_id INTEGER PRIMARY KEY AUTOINCREMENT, passwd_id INTEGER, essid_id INTEGER, pmk BLOB)')
x('CREATE TABLE workbench (wb_id INTEGER PRIMARY KEY AUTOINCREMENT, essid_id INTEGER, passwd_id INTEGER, lockid INTEGER DEFAULT 0)')
x('CREATE INDEX lock_lockid ON workbench (lockid)')
x('CREATE INDEX pmk_id ON pmk (passwd_id)')
x('CREATE UNIQUE INDEX essid_u ON essid (essid)')
x('CREATE UNIQUE INDEX passwd_u ON passwd (passwd)')
x('CREATE UNIQUE INDEX ep_u ON pmk (essid_id, passwd_id)')
x('CREATE UNIQUE INDEX wb_u ON workbench (essid_id, passwd_id)')
x('CREATE TRIGGER delete_essid DELETE ON essid BEGIN DELETE FROM pmk WHERE pmk.essid_id = OLD.essid_id; DELETE FROM workbench WHERE workbench.essid_id = OLD.essid_id; END')
x('CREATE TRIGGER delete_passwd DELETE ON passwd BEGIN DELETE FROM pmk WHERE pmk.passwd_id = OLD.passwd_id; DELETE FROM workbench WHERE workbench.passwd_id = OLD.passwd_id; END')
con.commit()
con.close()
print "Done"
