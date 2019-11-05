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
from __future__ import absolute_import
from __future__ import print_function

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
import subprocess
from git import Repo


__doc__ = """\
%prog <lazarus_lpi_filepath>

Configure and Build a Lazarus app
"""

def set_lpi_options(lpi_fn,waptedition,waptversion,buildnr=None):
    """Change the product name and product version of lazarus lpi project"""
    lpi = etree.parse(lpi_fn)
    vi = lpi.find('ProjectOptions/VersionInfo')
    major = lpi.find('ProjectOptions/VersionInfo/MajorVersionNr').attrib['Value'] = waptversion.members[0]
    minor = lpi.find('ProjectOptions/VersionInfo/MinorVersionNr').attrib['Value'] = waptversion.members[1]
    et_revision = lpi.find('ProjectOptions/VersionInfo/RevisionNr')
    if et_revision is None:
        et_revision = etree.SubElement(vi,'RevisionNr')
    revision = et_revision.attrib['Value'] = waptversion.members[2]
    et_build = lpi.find('ProjectOptions/VersionInfo/BuildNr')
    if et_build is None:
        et_build = etree.SubElement(vi,'BuildNr')
    if buildnr is None:
        build = et_build.attrib['Value'] = waptversion.members[3]
    else:
        build = et_build.attrib['Value'] = buildnr
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

def get_lpi_output(lpi_fn):
    lpi = etree.parse(lpi_fn)
    return lpi.find('CompilerOptions/Target/Filename').attrib['Value']

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
                        new.write((u'%s  %s\n' % (filesha256,fn_rel_path)).encode('utf8'))
                elif hash_fn.strip():
                    raise Exception('Bad line format for %s' % hash_fn)
        if os.path.exists(filepath+'.bak'):
            os.unlink(filepath+'.bak')
        os.rename(filepath,filepath+'.bak')
        os.rename(filepath+'.new',filepath)
    else:
        print('No %s hash file to process' % filepath)

def sign_exe(exe_path,p12path,p12password):
    #SIGNTOOL = os.path.join(setuphelpers.programfiles64,'Microsoft SDKs','Windows','v7.1','Bin','signtool.exe')
    SIGNTOOL = os.path.join(wapt_root_dir,'utils','signtool.exe')
    if not os.path.exists(SIGNTOOL):
      SIGNTOOL = os.path.join(setuphelpers.programfiles32,'wapt','utils','signtool.exe')
    if not os.path.exists(SIGNTOOL):
      SIGNTOOL = os.path.join(r'c:\wapt','utils','signtool.exe')

    for attempt in [1, 2, 3]:
        try:
            print("Signing attempt #" + str(attempt))
            setuphelpers.run(r'"%s" sign /f "%s" /p "%s" /t http://timestamp.verisign.com/scripts/timstamp.dll "%s"' % (SIGNTOOL,p12path,p12password,exe_path),return_stderr=False)
            break
        except subprocess.CalledProcessError as cpe:
            cpe.cmd =  cpe.cmd.replace(p12password, '********')
            cpe.output = cpe.output.replace(p12password, '********')
            print("Got CalledProcessError from subprocess.check_output: %s" % str(cpe))
        except Exception as e:
            print("Got an exception from subprocess.check_output")
            raise

def set_app_ico(lpi_path,edition):
    (lpi_rootname,lpi_ext) = os.path.splitext(lpi_path)
    appico_path = lpi_rootname+'.ico'
    if not lpi_rootname.endswith('waptself'):
        source_ico = setuphelpers.makepath(wapt_root_dir,'wapt-%s.ico'%edition)
        if not os.path.isfile(source_ico):
            source_ico = setuphelpers.makepath(wapt_root_dir,'wapt.ico')
    else:
        source_ico = setuphelpers.makepath(wapt_root_dir,'waptself','waptself-%s.ico' % edition.lower())
        if not os.path.isfile(source_ico):
            source_ico = setuphelpers.makepath(wapt_root_dir,'waptself','waptself-community.ico')
    setuphelpers.filecopyto(source_ico,appico_path)


def main():
    parser=OptionParser(usage=__doc__)
    parser.add_option("-l","--laz-build-path", dest="lazbuildpath", default=r'C:\lazarus\lazbuild.exe', help="Path to lazbuild or lazbuild.exe (default: %default)")
    parser.add_option("-p","--primary-config-path", dest="primary_config_path", default='%LOCALAPPDATA%\\lazarus', help="Path to lazbuild primary config dir. (default: %default)")
    parser.add_option("-v","--wapt-version", dest="waptversion", default=waptutils.__version__, help="Wapt version to put in exe metadata. (default: %default)")
    parser.add_option("-b","--build-nr", dest="buildnr", default=None, help="Wapt compile build  to put in exe metadata. (default: %default)")
    parser.add_option("-e","--wapt-edition", dest="waptedition", default='community', help="Wapt edition to build (community, enterprise...).  (default: %default)")
    parser.add_option("-u","--update-hash-file", dest="update_hash_filepath", default=r'{lpi_dirname}\\..\\{lpi_name}.sha256',help="Hash file to update vars (lpi_rootname,lpi_name,lpi_path,lpi_dirname,lpi_basename) (default: <lpi-base-name>.sha256")
    parser.add_option("-c","--compress", action='store_true', dest="compress", default=False, help="Compress with UPX.  (default: %default)")
    parser.add_option("-k","--sign-key", dest="sign_key_path", help="Sign with this  key.  (default: %default)")
    parser.add_option("-w","--sign-key-pwd-path", dest="sign_key_pwd_path", help="Path to password file. (default: %default)")
    parser.add_option("-t","--target-dir", dest="target_dir", help="Target exe directory (default: ")
    (options,args) = parser.parse_args()

    if len(args) != 1:
        parser.usage
        sys.exit(1)


    if options.buildnr is None:
        r = Repo(wapt_root_dir,search_parent_directories = True)
        options.buildnr = str(r.active_branch.commit.count())


    for lpi_path in args:
        lpi_path = os.path.abspath(lpi_path)
        (lpi_rootname,lpi_ext) = os.path.splitext(lpi_path)
        lpi_dirname = os.path.dirname(lpi_path)
        lpi_basename = os.path.basename(lpi_path)
        (lpi_name,lpi_ext) = os.path.splitext(os.path.basename(lpi_path))
        print('Configure %s' % lpi_path)
        set_lpi_options(lpi_path,options.waptedition,waptutils.Version(options.waptversion,4),options.buildnr)
        set_app_ico(lpi_path,options.waptedition)

        update_hash_file(os.path.abspath(options.update_hash_filepath.format(**locals())))
        cmd = '"%s" --primary-config-path="%s" -B "%s"'% (os.path.expandvars(options.lazbuildpath),os.path.expandvars(options.primary_config_path),os.path.expandvars(lpi_path))
        print(u'Running: %s' % cmd)
        setuphelpers.run(cmd,cwd = os.path.dirname(os.path.expandvars(options.lazbuildpath)))
        (fn,ext) = os.path.splitext(get_lpi_output(lpi_path))
        if ext in ('','.'):
            ext = '.exe'
        exe_fn = os.path.abspath(os.path.abspath(os.path.join(lpi_dirname,fn+ext)))

        if options.compress:
            print(u'Compress %s  with UPX' % exe_fn)
            setuphelpers.run('"%s" "%s"' % (os.path.join(setuphelpers.programfiles32,'upx','upx.exe'),exe_fn))

        if options.sign_key_path:
            sign_exe(exe_fn,options.sign_key_path,open(options.sign_key_pwd_path,'rb').read())



if __name__ == "__main__":
    main()
