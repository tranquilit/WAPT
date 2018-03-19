#!/usr/bin/env python

import os
import subprocess
import sys
from optparse import OptionParser
from git.repo import Repo

import waptutils

try:
    wapt_root_dir = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

__doc__ = """\
%prog <isc_filepath>

Build installer
"""

def main():
    parser=OptionParser(usage=__doc__)
    parser.add_option("-l","--iscc-binary", dest="iscc_binary", default=os.path.join(os.path.dirname(__file__),'innosetup','ISCC.exe'), help="Path to ISCC compiler (default: %default)")
    parser.add_option("-v","--wapt-version", dest="waptversion", default=waptutils.__version__, help="Wapt edition to build (community, enterprise...).  (default: %default)")
    parser.add_option("-e","--wapt-edition", dest="waptedition", default='community', help="Wapt edition to build (community, enterprise...).  (default: %default)")
    parser.add_option("-c","--compress", action='store_true', type='boolean', dest="compress", default=True, help="Compress with UPX.  (default: %default)")
    (options,args) = parser.parse_args()

    if len(args) != 1:
        parser.usage
        sys.exit(1)

    for iss_path in args:
        iss_path = os.path.abspath(iss_path)
        (iss_rootname,issext) = os.path.splitext(iss_path)

        # add a revision.txt file with git short
        r = Repo(search_parent_directories=True)
        rev_file = open(os.path.join(os.path.dirname(iss_path), '..', 'revision.txt'), 'w')
        rev_file.write(r.head.object.hexsha[:8])
        rev_file.close()
        r.close()

        iss_file = iss_rootname + ".iss"

        cmd = '"%(issc_binary)s" %(issfile)s /Dwapt%(waptedition)s' % {
            'issc_binary':options.iscc_binary,
            'issfile':iss_file,
            'waptedition':options.waptedition.lower()
            }
        subprocess.check_call(cmd)


if __name__ == "__main__":
    main()
