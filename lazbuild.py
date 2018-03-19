#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      htouvet
#
# Created:     19/03/2018
# Copyright:   (c) htouvet 2018
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import os
import sys

import xml.etree.ElementTree as etree
from datetime import datetime

try:
    wapt_root_dir = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

from optparse import OptionParser
import waptutils
import waptcrypto
import setuphelpers

__doc__ = """\
%prog <lazarus_lpi_filepath>

Configure and Build a Lazarus app
"""

def set_lpi_options(lpi_fn,waptedition,waptversion):
    """Change the product name and product version of lazarus lpi project"""
    lpi = etree.parse(lpi_fn)
    major = lpi.find('ProjectOptions/VersionInfo/MajorVersionNr').attrib['Value'] = waptversion.members[0]
    minor = lpi.find('ProjectOptions/VersionInfo/MinorVersionNr').attrib['Value'] = waptversion.members[1]
    revision = lpi.find('ProjectOptions/VersionInfo/RevisionNr').attrib['Value'] = waptversion.members[2]
    build = lpi.find('ProjectOptions/VersionInfo/BuildNr').attrib['Value'] = waptversion.members[3]
    st = lpi.find('ProjectOptions/VersionInfo/StringTable')
    st.attrib['ProductName'] = 'WAPT %s Edition' % waptedition.capitalize()
    st.attrib['ProductVersion'] = '%s.%s.%s' % (major,minor,revision)
    st.attrib['LegalCopyright'] = 'Tranquil IT Systems 2012-%s' % (datetime.now().year )
    compiler_custom_options = lpi.find('CompilerOptions/Other/CustomOptions')
    if compiler_custom_options is not None:
        compiler_custom_options.attrib['Value'] = "-dUseCThreads -d%s" % waptedition.upper()
    else:
        print('WARNING: No compiler options')
    print("Compiler special options: %s" % (compiler_custom_options is not None and compiler_custom_options.items(),))
    lpi.write(lpi_fn)

def update_hash_file(filepath):
    if os.path.isfile(filepath):
        files = open(filepath,'r').read().splitlines()
        with open(filepath+'.new','w') as new:
            for hash_fn in files:
                if hash_fn and ' ' in hash_fn:
                    (old_hash,fn) = hash_fn.split('  ')
                    fn_rel_path = os.path.relpath(fn,os.path.dirname(filepath))
                    if os.path.isfile(fn):
                        filesha256 = waptcrypto.sha256_for_file(fn)
                    else:
                        filesha256 = waptcrypto.sha256_for_data('')
                    new.write((u'%s  %s\n' % (filesha256,fn_rel_path)).encode('utf8'))
                elif hash_fn.strip():
                    raise Exception('Bad line format for %s' % hash_fn)
        if os.path.exists(filepath+'.bak'):
            os.unlink(filepath+'.bak')
        os.rename(filepath,filepath+'.bak')
        os.rename(filepath+'.new',filepath)
    else:
        print('No %s hash file to process' % filepath)

def main():
    parser=OptionParser(usage=__doc__)
    parser.add_option("-l","--laz-build-path", dest="lazbuildpath", default=r'C:\codetyphon\typhon\bin32\typhonbuild.exe', help="Path to lazbuild or typhonbuild.exe (default: %default)")
    parser.add_option("-p","--primary-config-path", dest="primary_config_path", default='%APPDATA%\\typhon32', help="Path to lazbuild primary config dir. (default: %default)")
    parser.add_option("-v","--wapt-version", dest="waptversion", default=waptutils.__version__, help="Wapt edition to build (community, enterprise...).  (default: %default)")
    parser.add_option("-e","--wapt-edition", dest="waptedition", default='community', help="Wapt edition to build (community, enterprise...).  (default: %default)")
    parser.add_option("-u","--update-hash-file", dest="update_hash_filepath", default=r'{lpi_dirname}\\..\\{lpi_name}.sha256',help="Hash file to update vars (lpi_rootname,lpi_name,lpi_path,lpi_dirname,lpi_basename) (default: <lpi-base-name>.sha256")
    parser.add_option("-t","--target-dir", dest="target_dir", help="Target exe directory (default: ")
    (options,args) = parser.parse_args()

    if len(args) != 1:
        parser.usage
        sys.exit(1)

    for lpi_path in args:
        lpi_path = os.path.abspath(lpi_path)
        (lpi_rootname,lpi_ext) = os.path.splitext(lpi_path)
        lpi_dirname = os.path.dirname(lpi_path)
        lpi_basename = os.path.basename(lpi_path)
        (lpi_name,lpi_ext) = os.path.splitext(os.path.basename(lpi_path))
        print('Configure %s' % lpi_path)
        set_lpi_options(lpi_path,options.waptedition,waptutils.Version(options.waptversion,4))
        update_hash_file(os.path.abspath(options.update_hash_filepath.format(**locals())))
        cmd = '"%s" --primary-config-path="%s" -B "%s"'% (os.path.expandvars(options.lazbuildpath),os.path.expandvars(options.primary_config_path),os.path.expandvars(lpi_path))
        print(u'Running: %s' % cmd)
        setuphelpers.run(cmd)


if __name__ == "__main__":
    main()
