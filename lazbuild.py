#-------------------------------------------------------------------------------
# Name:        lazbuild
# Purpose:
#
# Author:      htouvet
#
# Created:     19/03/2018
# Copyright:   (c) htouvet 2018
# Licence:     <your licence>
#-------------------------------------------------------------------------------
from __future__ import absolute_import

import os
import sys

import xml.etree.ElementTree as etree
from datetime import datetime

try:
    wapt_root_dir = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

from optparse import OptionParser
import subprocess
import shutil
import types
import hashlib
from git import Repo


__doc__ = """\
%prog <lazarus_lpi_filepath>

Configure and Build a Lazarus app
"""

def get_sha256(afile = '',BLOCK_SIZE=2**20):
        file_hash=hashlib.sha256()
        with open(afile,'rb') as f:
            fb=f.read(BLOCK_SIZE)
            while len(fb)>0:
                file_hash.update(fb)
                fb=f.read(BLOCK_SIZE)
            return file_hash.hexdigest()

class Version(object):
    """Version object of form 0.0.0
    can compare with respect to natural numbering and not alphabetical

    Args:
        version (str) : version string
        member_count (int) : number of version memebers to take in account.
                             If actual members in version is less, add missing memeber with 0 value
                             If actual members count is higher, removes last ones.

    >>> Version('0.10.2') > Version('0.2.5')
    True
    >>> Version('0.1.2') < Version('0.2.5')
    True
    >>> Version('0.1.2') == Version('0.1.2')
    True
    >>> Version('7') < Version('7.1')
    True

    .. versionchanged:: 1.6.2.5
        truncate version members list to members_count if provided.
    """

    def __init__(self,version,members_count=None):
        if version is None:
            version = ''
        assert isinstance(version,types.ModuleType) or isinstance(version,bytes) or isinstance(version,bytes) or isinstance(version,Version)
        if isinstance(version,types.ModuleType):
            self.versionstring =  getattr(version,'__version__',None)
        elif isinstance(version,Version):
            self.versionstring = getattr(version,'versionstring',None)
        else:
            self.versionstring = version
        self.members = [ v.strip() for v in self.versionstring.split('.')]
        self.members_count = members_count
        if members_count is not None:
            if len(self.members)<members_count:
                self.members.extend(['0'] * (members_count-len(self.members)))
            else:
                self.members = self.members[0:members_count]

    def __cmp__(self,aversion):
        def nat_cmp(a, b):
            a = a or ''
            b = b or ''

            def convert(text):
                if text.isdigit():
                    return int(text)
                else:
                    return text.lower()

            def alphanum_key(key):
                return [convert(c) for c in re.split('([0-9]+)', key)]

            return cmp(alphanum_key(a), alphanum_key(b))

        if not isinstance(aversion,Version):
            aversion = Version(aversion,self.members_count)
        for i in range(0,max([len(self.members),len(aversion.members)])):
            if i<len(self.members):
                i1 = self.members[i]
            else:
                i1 = ''
            if i<len(aversion.members):
                i2 = aversion.members[i]
            else:
                i2=''
            v = nat_cmp(i1,i2)
            if v:
                return v
        return 0

    def __str__(self):
        return '.'.join(self.members)

    def __repr__(self):
        return "Version('{}')".format('.'.join(self.members))

def programfiles32():
    if 'PROGRAMW6432' in os.environ and 'PROGRAMFILES(X86)' in os.environ:
        return os.environ['PROGRAMFILES(X86)']
    else:
        return os.environ['PROGRAMFILES']

def get_version():
    for line in open('%s/waptutils.py' % wapt_root_dir):
        if line.strip().startswith('__version__'):
            return str(Version(line.split('=')[1].strip().replace('"', '').replace("'", ''),3))

def run(*args, **kwargs):
    return subprocess.check_output(*args, shell=True, **kwargs)

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
    st.attrib['ProductVersion'] = '%s.%s.%s' % (major, minor, revision)
    st.attrib['LegalCopyright'] = 'Tranquil IT Systems 2012-%s' % (datetime.now().year)
    compiler_custom_options = lpi.find('CompilerOptions/Other/CustomOptions')
    if compiler_custom_options is not None:
        compiler_custom_options.attrib['Value'] = "-dUseCThreads -d%s" % waptedition.upper()
    else:
        print('WARNING: No compiler options')
    print("Compiler special options: %s" % (compiler_custom_options is not None and compiler_custom_options.items(),))
    if os.name != 'nt':
        output_filename = lpi.find('CompilerOptions/Target/Filename')
        if not output_filename.attrib['Value'].endswith('.bin'):
            output_filename.attrib['Value'] = output_filename.attrib['Value']+'.bin'
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
                        filesha256 = get_sha256(fn)
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
    SIGNTOOL = os.path.join(wapt_root_dir,'utils','signtool.exe')
    if not os.path.exists(SIGNTOOL):
      SIGNTOOL = os.path.join(programfiles32(),'wapt','utils','signtool.exe')
    if not os.path.exists(SIGNTOOL):
      SIGNTOOL = os.path.join(r'c:\wapt','utils','signtool.exe')

    for attempt in [1, 2, 3]:
        try:
            print("Signing attempt #" + str(attempt))
            run(r'"%s" sign /f "%s" /p "%s" /t http://timestamp.globalsign.com/scripts/timestamp.dll "%s"' % (SIGNTOOL,p12path,p12password,exe_path))
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
        source_ico = os.path.join(wapt_root_dir,'wapt-%s.ico'%edition)
        if not os.path.isfile(source_ico):
            source_ico = os.path.join(wapt_root_dir,'wapt.ico')
    else:
        source_ico = os.path.join(wapt_root_dir,'waptself','waptself-%s.ico' % edition.lower())
        if not os.path.isfile(source_ico):
            source_ico = os.path.join(wapt_root_dir,'waptself','waptself-community.ico')
    shutil.copyfile(source_ico,appico_path)


def main():
    parser=OptionParser(usage=__doc__)
    parser.add_option("-l","--laz-build-path", dest="lazbuildpath", default=r'C:\lazarus\lazbuild.exe' if os.name=='nt' else "lazbuild", help="Path to lazbuild or lazbuild.exe (default: %default)")
    parser.add_option("-p","--primary-config-path", dest="primary_config_path", default='%LOCALAPPDATA%\\lazarus' if os.name=='nt' else os.path.join(os.path.expanduser("~"),".lazarus"), help="Path to lazbuild primary config dir. (default: %default)")
    parser.add_option("-v","--wapt-version", dest="waptversion", default=get_version(), help="Wapt version to put in exe metadata. (default: %default)")
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
        options.buildnr = '%04d' % (r.active_branch.commit.count(),)


    for lpi_path in args:
        lpi_path = os.path.abspath(lpi_path)
        (lpi_rootname,lpi_ext) = os.path.splitext(lpi_path)
        lpi_dirname = os.path.dirname(lpi_path)
        lpi_basename = os.path.basename(lpi_path)
        (lpi_name,lpi_ext) = os.path.splitext(os.path.basename(lpi_path))
        print('Configure %s' % lpi_path)
        set_lpi_options(lpi_path,options.waptedition,Version(options.waptversion,4),options.buildnr)
        set_app_ico(lpi_path,options.waptedition)

        update_hash_file(os.path.abspath(options.update_hash_filepath.format(**locals())))
        cmd = '"%s" --primary-config-path="%s" -B "%s"%s' % (os.path.expandvars(options.lazbuildpath), os.path.expandvars(options.primary_config_path), os.path.expandvars(lpi_path), '' if sys.platform != 'darwin' else ' --ws=cocoa')
        print(u'Running: %s' % cmd)
        run(cmd)
        (fn,ext) = os.path.splitext(get_lpi_output(lpi_path))
        if ext in ('','.'):
            ext = '.exe'
        exe_fn = os.path.abspath(os.path.abspath(os.path.join(lpi_dirname,fn+ext)))

        if options.compress:
            print(u'Compress %s  with UPX' % exe_fn)
            run('"%s" "%s"' % (os.path.join(programfiles32(),'upx','upx.exe'),exe_fn))

        if options.sign_key_path:
            sign_exe(exe_fn,options.sign_key_path,open(options.sign_key_pwd_path,'rb').read())



if __name__ == "__main__":
    main()
