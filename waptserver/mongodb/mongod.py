#!python

import iniparse
import os
import subprocess
import sys
import time

myname = sys.argv[0]

FAKE_SECTION = 'dummy'

class FakeSection:
    def __init__(self, file_obj):
        self.file = file_obj
        self.fake = FAKE_SECTION
    def readline(self):
        if self.fake is not None:
            ret = '[' + self.fake + ']'
            self.fake = None
        else:
            ret = self.file.readline()
        return ret

def cleanup():
    config = iniparse.RawConfigParser()
    config.readfp(FakeSection(file(sys.argv[2])))
    dbpath = config.get(FAKE_SECTION, 'dbpath')
    dblock = os.path.join(dbpath, 'mongod.lock')
    if os.path.exists(dblock) and os.path.getsize(dblock) > 0:
        try:
            print >> sys.stderr, myname, "let's try to read what's in the lockfile"
            # Here we get an exception if the file is currently locked by a process
            junk = file(dblock, 'rU').read()
            print >> sys.stderr, myname, "OK, let's remove the lock"
            os.remove(dblock)
            time.sleep(2)
        except Exception as e:
            return False
        output = ''
        try:
            print >> sys.stderr, myname, "let's attempt to repair the database"
            output = subprocess.check_output([sys.argv[1], '--config', sys.argv[2], '--repair'])
        except subprocess.CalledProcessError as cpe:
            print >> sys.stderr, "ERROR when running --repair"
        return True
    return False

if len(sys.argv) != 3:
    raise Exception("Two arguments expected: /path/to/mongodb.exe /path/to/mongod.cfg")
        
for iteration in [1, 2, 3]:
    try:
        print >> sys.stderr, myname, "trying to start mongodb"
        subprocess.check_output([sys.argv[1], '--config', sys.argv[2]])
        print >> sys.stderr, myname, "regular mongodb run returned with no error"
        break
    except Exception as e:
        print >> sys.stderr, myname, "EXCEPTION:", str(e)
        if not cleanup():
            break
    time.sleep(2)
