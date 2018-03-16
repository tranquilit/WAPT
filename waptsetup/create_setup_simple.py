#!/usr/bin/env python

import os
import subprocess
import sys
from git.repo import Repo

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

    #git = os.path.join(programfiles32(), 'Git', 'bin', 'git.exe')
    #subprocess.check_call([git, 'rev-parse', '--short', 'HEAD'], stdout=rev_file)
    r = Repo(search_parent_directories=True)
    with open(os.path.join(os.path.dirname(installer), '..', 'revision.txt'), 'w') as rev_file:
        rev_file.write(r.head.object.hexsha[:8])

    iss_file = installer + ".iss"
    issc_binary = os.path.join(os.path.dirname(__file__),'innosetup','ISCC.exe')

    cmd = '"%(issc_binary)s" %(issfile)s' % {
        'issc_binary':issc_binary,
        'issfile':iss_file
    }

    subprocess.check_call(cmd)
