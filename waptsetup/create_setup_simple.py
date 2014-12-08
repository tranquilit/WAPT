#!/usr/bin/env python

import os
import subprocess
import sys

def programfiles32():
    """Return 32bits applications folder."""
    if 'PROGRAMW6432' in os.environ and 'PROGRAMFILES(X86)' in os.environ:
        return os.environ['PROGRAMFILES(X86)']
    else:
        return os.environ['PROGRAMFILES']

if __name__ == '__main__':
    if len(sys.argv) != 1 or sys.argv[1] == "--help":
        print >> sys.stderr, "Usage: %s installer_name[.exe]"

    installer = sys.argv[1]
    if installer.endswith(".exe"):
        installer = installer[0:installer.rfind(".exe")]

    iss_file = installer + ".iss"
    issc_binary = os.path.join(programfiles32(),'Inno Setup 5','ISCC.exe')

    cmd = '"%(issc_binary)s" %(issfile)s' % {
        'issc_binary':issc_binary,
        'issfile':iss_file
    }

    print subprocess.check_output(cmd)


