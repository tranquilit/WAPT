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

    installer = sys.argv[1]
    if installer.endswith(".exe"):
        installer = installer[0:installer.rfind(".exe")]

    rev_file = file(os.path.join(os.path.dirname(installer), '..', 'revision.txt'), 'w')
    git = os.path.join(programfiles32(), 'Git', 'git.exe')
    subprocess.check_call([git, 'rev-parse', '--short', 'HEAD'], stdout=rev_file)
    rev_file.close()

    iss_file = installer + ".iss"
    issc_binary = os.path.join(programfiles32(),'Inno Setup 5','ISCC.exe')

    cmd = '"%(issc_binary)s" %(issfile)s' % {
        'issc_binary':issc_binary,
        'issfile':iss_file
    }

    print subprocess.check_output(cmd)


