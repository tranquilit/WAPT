#!/usr/bin/env python

import os
import subprocess
import sys
from optparse import OptionParser
from git.repo import Repo
import setuphelpers

import waptutils

try:
    wapt_root_dir = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

__doc__ = """\
%prog <isc_filepath>

Build installer
"""

def sign_exe(exe_path,p12path,p12password):
    KSIGN = os.path.join(setuphelpers.programfiles32,'kSign','kSignCMD.exe')

    for attempt in [1, 2, 3]:
        try:
            print "Signing attempt #" + str(attempt)
            setuphelpers.run(r'"%s" /f "%s" /p"%s" "%s"' % (KSIGN,p12path,p12password,exe_path),return_stderr=False)
            break
        except subprocess.CalledProcessError as cpe:
            cpe.cmd =  cpe.cmd.replace(p12password, '********')
            cpe.output = cpe.output.replace(p12password, '********')
            print "Got CalledProcessError from subprocess.check_output: %s" % str(cpe)
        except Exception as e:
            print "Got an exception from subprocess.check_output"
            raise


def main():
    parser=OptionParser(usage=__doc__)
    parser.add_option("-l","--iscc-binary", dest="iscc_binary", default=os.path.join(os.path.dirname(__file__),'innosetup','ISCC.exe'), help="Path to ISCC compiler (default: %default)")
    parser.add_option("-v","--wapt-version", dest="waptversion", default=waptutils.__version__, help="Wapt edition to build (community, enterprise...).  (default: %default)")
    parser.add_option("-e","--wapt-edition", dest="waptedition", default='community', help="Wapt edition to build (community, enterprise...).  (default: %default)")
    parser.add_option("-k","--sign-key", dest="sign_key_path", help="Sign with this  key.  (default: %default)")
    parser.add_option("-w","--sign-key-pwd-path", dest="sign_key_pwd_path", help="Path to password file. (default: %default)")
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

        cmd = '"%(issc_binary)s" /Dwapt%(waptedition)s %(issfile)s' % {
            'issc_binary':options.iscc_binary,
            'issfile':iss_file,
            'waptedition':options.waptedition.lower()
            }
        res = setuphelpers.run(cmd)
        exe_fn = res.splitlines()[-1]
        if options.sign_key_path:
            sign_exe(exe_fn,options.sign_key_path,open(options.sign_key_pwd_path,'rb').read())


if __name__ == "__main__":
    main()
