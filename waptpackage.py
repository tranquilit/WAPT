#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013  Tranquil IT Systems http://www.tranquil.it
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users PC.
#
#    WAPT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    WAPT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with WAPT.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------
__version__ = "1.5.0.5"

__all__ = [
    'control_to_dict',
    'md5_for_file',
    'parse_major_minor_patch_build',
    'make_version',
    'datetime2isodate',
    'httpdatetime2isodate',
    'PackageRequest',
    'PackageEntry',
    'WaptBaseRepo',
    'WaptLocalRepo',
    'default_http_headers',
    'wget',
    'WaptRemoteRepo',
    'update_packages',
    'REGEX_PACKAGE_VERSION',
    'REGEX_PACKAGE_CONDITION',
    'EWaptBadSignature',
    'EWaptCorruptedFiles',
    'EWaptNotSigned',
    'EWaptBadControl',
    'EWaptBadSetup',
    'EWaptNeedsNewerAgent',
    'EWaptDiskSpace',
    'EWaptBadTargetOS',
    'EWaptNotAPackage',
    'EWaptDownloadError',
]

import os
import custom_zip as zipfile
import StringIO
import hashlib
import logging
import glob
import codecs
import re
import time
import json
import sys
import types
import requests
import email
import datetime
import tempfile
import email.utils
import shutil
from waptcrypto import *
from waptutils import *

logger = logging.getLogger()


def md5_for_file(fname, block_size=2**20):
    f = open(fname,'rb')
    md5 = hashlib.md5()
    while True:
        data = f.read(block_size)
        if not data:
            break
        md5.update(data)
    return md5.hexdigest()

# From Semantic Versioning : http://semver.org/ by Tom Preston-Werner,
# valid : 0.0-0  0.0.0-0 0.0.0.0-0
REGEX_PACKAGE_VERSION = re.compile(r'^(?P<major>[0-9]+)'
                    '(\.(?P<minor>[0-9]+))?'
                    '(\.(?P<patch>[0-9]+))?'
                    '(\.(?P<subpatch>[0-9]+))?'
                    '(\-(?P<packaging>[0-9A-Za-z]+(\.[0-9A-Za-z]+)*))?$')

# tis-exodus (>2.3.4-10)
REGEX_PACKAGE_CONDITION = re.compile(r'(?P<package>[^\s()]+)\s*(\(\s*(?P<operator>[<=>]?)\s*(?P<version>\S+)\s*\))?')


def parse_major_minor_patch_build(version):
    """Parse version to major, minor, patch, pre-release, build parts.
    """
    match = REGEX_PACKAGE_VERSION.match(version)
    if match is None:
        raise ValueError(u'%s is not valid SemVer string' % version)

    verinfo = match.groupdict()

    def int_or_none(name):
        if name in verinfo and verinfo[name] != None :
            return int(verinfo[name])
        else:
            return None
    verinfo['major'] = int_or_none('major')
    verinfo['minor'] = int_or_none('minor')
    verinfo['patch'] = int_or_none('patch')
    verinfo['subpatch'] = int_or_none('subpatch')

    return verinfo


def make_version(major_minor_patch_build):
    p1 = u'.'.join( [ "%s" % major_minor_patch_build[p] for p in ('major','minor','patch','subpatch') if major_minor_patch_build[p] != None])
    if major_minor_patch_build['packaging'] != None:
        return '-'.join([p1,major_minor_patch_build['packaging']])
    else:
        return p1

ArchitecturesList = ('all','x86','x64')

class EWaptBadSignature(Exception):
    pass

class EWaptDownloadError(Exception):
    pass

class EWaptCorruptedFiles(Exception):
    pass

class EWaptNotSigned(Exception):
    pass

class EWaptBadControl(Exception):
    pass

class EWaptBadSetup(Exception):
    pass

class EWaptNeedsNewerAgent(Exception):
    pass

class EWaptDiskSpace(Exception):
    pass

class EWaptBadTargetOS(Exception):
    pass

class EWaptNotAPackage(Exception):
    pass

class EWaptNotSourcesDirPackage(Exception):
    pass


class EWaptPackageSignError(Exception):
    pass

class EWaptInstallError(Exception):
    """Exception raised during installation of package
        msg is logged in local install database
        if retry_count is None, install will be retried indefinitely until success
        else install is retried at most retry_count times/
    """
    def __init__(self,msg,install_status='ERROR',retry_count=None):
        Exception.__init__(self,msg)
        self.install_status = install_status
        self.retry_count = retry_count


class EWaptInstallPostponed(EWaptInstallError):
    def __init__(self,msg,install_status='POSTPONED',retry_count=5,grace_delay=3600):
        EWaptInstallError.__init__(self,msg,install_status,retry_count)
        self.grace_delay = grace_delay

class EWaptUnavailablePackage(EWaptInstallError):
    pass

class EWaptRemoveError(Exception):
    pass

class EWaptConfigurationError(Exception):
    pass

class PackageRequest(object):
    """Package and version request / condition

    >>> PackageRequest('7-zip( >= 7.2)')
    PackageRequest('7-zip (>=7.2)')
    """
    def __init__(self,package_request):
        self.package_request = package_request
        parts = REGEX_PACKAGE_CONDITION.match(self.package_request).groupdict()
        self.package = parts['package']
        self.operator = parts['operator'] or '='
        self.version = Version(parts['version'])

    def __cmp__(self,other):
        if isinstance(other,str) or isinstance(other,unicode):
            other = PackageRequest(other)
        return cmp((self.package,self.version,self.operator),(other.package,other.version,other.operator))

    def __str__(self):
        return self.package_request

    def __repr__(self):
        return "PackageRequest('{package} ({operator}{version})')".format(package=self.package,operator=self.operator,version=self.version)

def control_to_dict(control,int_params=('size','installed_size')):
    """Convert a control file like object
          key1: value1
          key2: value2
          ...
        list of lines into a dict
        multilines strings begins with a space

        breaks when an empty line is reached (limit between 2 package in Packages indexes)
    Args:
        control (file): file like object to read control from (until an empty line is reached)
        int_params (list): attributes which must be converted to int

    Returns:
        dict
    """
    result = {}
    (key,value) = ('','')
    while 1:
        line = control.readline()
        if not line or not line.strip():
            break
        if line.startswith(' '):
            # additional lines begin with a space!
            value = result[key]
            value += '\n'
            value += line.strip()
            result[key] = value
        else:
            sc = line.find(':')
            if sc<0:
                raise EWaptBadControl(u'Invalid line (no ":" found) : %s' % line)
            (key,value) = (line[:sc].strip(),line[sc+1:].strip())
            key = key.lower()
            if key in int_params:
                try:
                    value = int(value)
                except:
                    pass
            result[key] = value
    return result

class PackageEntry(object):
    """Package attributes coming from either control files in WAPT package or local DB

    """
    required_attributes = ['package','version','architecture','section','priority']
    optional_attributes = ['maintainer','description','depends','conflicts','maturity',
        'locale','min_os_version','max_os_version','min_wapt_version',
        'sources','installed_size',
        'signer','signer_fingerprint','signature','signature_date']
    non_control_attributes = ['localpath','filename','size','repo_url','md5sum','repo',]
    signed_attributes = required_attributes+['depends','conflicts','maturity']

    # these attributes are not kept when duplicating / editing a package
    not_duplicated_attributes =  ['signature','signer','signer_fingerprint','signature_date']

    manifest_filename_excludes = ['WAPT/signature','WAPT/manifest.sha1']

    @property
    def all_attributes(self):
        return self.required_attributes + self.optional_attributes + self.non_control_attributes + self._calculated_attributes

    def __init__(self,package='',version='0',repo='',waptfile=None):
        self.package=package
        self.version=version
        self.architecture='all'
        self.section='base'
        self.priority='optional'
        self.maintainer=''
        self.description=''
        self.depends=''
        self.conflicts=''
        self.sources=''
        self.filename=''
        self.size=None
        self.maturity=''
        self.signer=''
        self.signer_fingerprint=''
        self.signature=''
        self.signature_date=''
        self.locale=''
        self.min_os_version=''
        self.max_os_version=''
        self.min_wapt_version=''
        self.installed_size=''

        self.md5sum=''
        self.repo_url=''
        self.repo=repo

        # full filename of package if built
        self.localpath=None
        # directory if unzipped package files
        self.sourcespath=None

        self._calculated_attributes=[]
        if waptfile:
            if os.path.isfile(waptfile):
                self.load_control_from_wapt(waptfile)
            elif os.path.isdir(waptfile):
                self.load_control_from_wapt(waptfile)
            else:
                raise EWaptBadControl(u'Package filename or directory %s does not exist' % waptfile)

    def parse_version(self):
        """Parse version to major, minor, patch, pre-release, build parts.

        """
        return parse_major_minor_patch_build(self.version)

    def __getitem__(self,name):
        if name is str or name is unicode:
            name = name.lower()
        if hasattr(self,name):
            return getattr(self,name)
        else:
            raise Exception(u'No such attribute : %s' % name)

    def __iter__(self):
        for key in self.all_attributes:
            yield (key, getattr(self,key))

    def as_dict(self):
        return dict(self)

    def __unicode__(self):
        return self.ascontrol(with_non_control_attributes=True)

    def __str__(self):
        return self.__unicode__()

    def __repr__(self):
        return u"PackageEntry('%s','%s') %s" % (self.package,self.version,
            ','.join(["%s=%s"%(key,getattr(self,key)) for key in ('architecture','maturity','locale') if (getattr(self,key) and getattr(self,key) != 'all')]))

    def get(self,name,default=None):
        """Get PackageEntry property.

        Args:
            name (str): property to get. name is forced to lowercase.
            default (any) : value to return in case the property doesn't not exist.

        Returns:
            any : property value
        """
        if name is str or name is unicode:
            name = name.lower()
        if hasattr(self,name):
            return getattr(self,name)
        else:
            return default

    def __setitem__(self,name,value):
        if name is str or name is unicode:
            name = name.lower()
        if name not in self.all_attributes:
            self._calculated_attributes.append(name)
        setattr(self,name,value)

    def __len__(self):
        return len(self.all_attributes)

    def __cmp__(self,entry_or_version):
        def nat_cmp(a, b):
            a, b = a or '', b or ''

            def convert(text):
                if text.isdigit():
                    return int(text)
                else:
                    return text.lower()
            alphanum_key = lambda key: [convert(c) for c in re.split('([0-9]+)', key)]
            return cmp(alphanum_key(a), alphanum_key(b))

        def compare_by_keys(d1, d2):
            for key in ['major', 'minor', 'patch','subpatch']:
                i1,i2  = d1.get(key), d2.get(key)
                # compare to partial version number (kind of wilcard)
                if i1 is not None and i2 is None and not isinstance(entry_or_version,PackageEntry):
                    return 0
                v = cmp(i1,i2)
                if v:
                    return v
            # package version
            pv1, pv2 = d1.get('packaging'), d2.get('packaging')
            # compare to partial version number (kind of wilcard)
            if pv1 is not None and pv2 is None and not isinstance(entry_or_version,PackageEntry):
                return 0
            else:
                pvcmp = nat_cmp(pv1, pv2)
                return pvcmp or 0
        try:
            if isinstance(entry_or_version,PackageEntry):
                result = cmp(self.package,entry_or_version.package)
                if result == 0:
                    v1, v2 = self.parse_version(), entry_or_version.parse_version()
                    return compare_by_keys(v1, v2)
                else:
                    return result
            else:
                v1, v2 = self.parse_version(), parse_major_minor_patch_build(entry_or_version)
                return compare_by_keys(v1, v2)
        except ValueError as e:
            logger.warning("%s" % e)
            if isinstance(entry_or_version,PackageEntry):
                return cmp((self.package,self.version),(entry_or_version.package,entry_or_version.version))
            else:
                return cmp(self.version,entry_or_version)

    def match(self, match_expr):
        """Return True if package entry match a package string like 'tis-package (>=1.0.1-00)

        """
        pcv = REGEX_PACKAGE_CONDITION.match(match_expr).groupdict()
        if pcv['package'] != self.package:
            return False
        else:
            if 'operator' in pcv and pcv['operator']:
                return self.match_version(pcv['operator']+pcv['version'])
            else:
                return True

    def match_version(self, match_expr):
        """Return True if package entry match a version string condition like '>=1.0.1-00'

        """
        prefix = match_expr[:2]
        if prefix in ('>=', '<=', '=='):
            match_version = match_expr[2:]
        elif prefix and prefix[0] in ('>', '<', '='):
            prefix = prefix[0]
            match_version = match_expr[1:]
        else:
            raise ValueError(u"match_expr parameter should be in format <op><ver>, "
                             "where <op> is one of ['<', '>', '==', '<=', '>=']. "
                             "You provided: %r" % match_expr)

        possibilities_dict = {
            '>': (1,),
            '<': (-1,),
            '=': (0,),
            '==': (0,),
            '>=': (0, 1),
            '<=': (-1, 0)
        }

        possibilities = possibilities_dict[prefix]
        cmp_res = self.__cmp__(match_version)

        return cmp_res in possibilities

    def match_search(self,search):
        """Return True if entry contains the words in search in correct order and at word boundaries"""
        if not search:
            return True
        else:
            found = re.search(r'\b{}'.format(search.replace(' ',r'.*\b')),u'%s %s' % (self.package,self.description),re.IGNORECASE)
            return found is not None


    def load_control_from_dict(self,adict):
        for k in adict:
            setattr(self,k,adict[k])
            if not k in self.all_attributes:
                self._calculated_attributes.append(k)
        return self

    def load_control_from_wapt(self,fname,calc_md5=True):
        """Load package attributes from the control file (utf8 encoded) included in WAPT zipfile fname

          fname can be
           - the path to WAPT file itelsef (zip file)
           - a list with the lines from control file
           - a path to the directory of wapt file unzipped content (debugging)
        """
        if isinstance(fname,list):
            control =  StringIO.StringIO(u'\n'.join(fname))
        elif os.path.isfile(fname):
            with zipfile.ZipFile(fname,'r',allowZip64=True) as myzip:
                control = StringIO.StringIO(myzip.open(u'WAPT/control').read().decode('utf8'))
        elif os.path.isdir(fname):
            control = codecs.open(os.path.join(fname,'WAPT','control'),'r',encoding='utf8')
        else:
            raise EWaptBadControl(u'Bad or no control found for %s' % (fname,))

        self.load_control_from_dict(control_to_dict(control))

        if isinstance(fname,list):
            self.filename = self.make_package_filename()
            self.localpath = ''
        elif os.path.isfile(fname):
            if calc_md5:
                self.md5sum = md5_for_file(fname)
            else:
                self.md5sum = ''
            self.size = os.path.getsize(fname)
            self.filename = os.path.basename(fname)
            self.localpath = os.path.abspath(fname)
        elif os.path.isdir(fname):
            self.filename = None
            self.localpath = None
            self.sourcespath = os.path.abspath(fname)
        return self

    def wapt_fullpath(self):
        """return full local path of wapt package if built"""
        return self.localpath

    def save_control_to_wapt(self,fname):
        """Save package attributes to the control file (utf8 encoded)

          fname can be
           - the path to WAPT file itelsef (zip file)
           - a path to the directory of wapt file unzipped content (debugging)
        """
        if os.path.isdir(fname):
            with codecs.open(os.path.join(fname,u'WAPT','control'),'w',encoding='utf8') as control_file:
                control_file.write(self.ascontrol())
        else:
            myzip = None
            try:
                if os.path.isfile(fname):
                    myzip = zipfile.ZipFile(fname,'a',allowZip64=True,compression=zipfile.ZIP_DEFLATED)
                    try:
                        zi = myzip.getinfo(u'WAPT/control')
                        control_exist = True
                    except:
                        control_exist = False
                        self.filename = os.path.basename(fname)
                        self.localpath = os.path.abspath(fname)
                    if control_exist:
                        raise Exception(u'control file already exist in WAPT file %s' % fname)
                else:
                    myzip = zipfile.ZipFile(fname,'w',allowZip64=True,compression=zipfile.ZIP_DEFLATED)
                myzip.writestr(u'WAPT/control',self.ascontrol().encode('utf8'))
            finally:
                if myzip:
                    myzip.close()

    def ascontrol(self,with_non_control_attributes = False,with_empty_attributes=False):
        val = []

        def escape_cr(s):
            # format multi-lines description with a space at each line start
            if s and (isinstance(s,str) or isinstance(s,unicode)):
                return re.sub(r'$(\n)(?=^\S)',r'\n ',s,flags=re.MULTILINE)
            else:
                if s is None:
                    return ''
                else:
                    return s

        for att in self.required_attributes+self.optional_attributes:
            if att in self.signed_attributes or with_empty_attributes or getattr(self,att):
                val.append(u"%-18s: %s" % (att, escape_cr(getattr(self,att))))

        if with_non_control_attributes:
            for att in self.non_control_attributes:
                if getattr(self,att):
                    val.append(u"%-18s: %s" % (att, escape_cr(getattr(self,att))))
        return u'\n'.join(val)

    def make_package_filename(self):
        """Return the standard package filename based on current attributes

        Returns:
            str:  standard package filename
                  - packagename_version_arch.wapt for softwares
                  - packagename.wapt for group and host.
        """
        if self.section not in ['host','group'] and not (self.package and self.version and self.architecture):
            raise Exception(u'Not enough information to build the package filename for %s (%s)'%(self.package,self.version))
        if self.section == 'host':
            return self.package+'.wapt'
        elif self.section ==  'group':
            # we don't keep version for group
            return '_'.join([f for f in (self.package,self.architecture,self.maturity,self.locale) if (f and f != 'all')]) + '.wapt'
        else:
            # includes only non empty fields
            return '_'.join([f for f in (self.package,self.version,self.architecture,self.maturity,self.locale) if f]) + '.wapt'

    def make_package_edit_directory(self):
        """Return the standard package directory to edit the package based on current attributes

        Returns:
            str:  standard package filename
                  - packagename_arch_maturity_locale-wapt for softwares and groups
                  - packagename-wapt for host.
        """
        if not (self.package):
            raise Exception(u'Not enough information to build the package directory for %s'%(self.package))
            # includes only non empty fields
        return '_'.join([f for f in (self.package,self.architecture,self.maturity,self.locale) if (f and f != 'all')]) + '-wapt'

    def asrequirement(self):
        """resturn package and version for designing this package in depends or install actions

        Returns:
            str: "packagename (=version)"
        """
        return "%s (=%s)" % (self.package,self.version)

    @property
    def download_url(self):
        return self.repo_url+'/'+self.filename.strip('./')

    def inc_build(self):
        """Increment last number part of version"""
        version_parts = self.parse_version()
        for part in ('packaging','subpatch','patch','minor','major'):
            if part in version_parts and version_parts[part] != None and\
                (isinstance(version_parts[part],int) or version_parts[part].isdigit()):
                version_parts[part] = "%i" % (int(version_parts[part])+1,)
                self.version = make_version(version_parts)
                return
        raise EWaptBadControl(u'no build/packaging part in version number %s' % self.version)

    def signed_content(self):
        return {att:getattr(self,att,None) for att in self.signed_attributes}

    def get_signature(self,private_key):
        signed_content = private_key.sign_content(self.signed_content())
        return signed_content


    def build_package(self,excludes=['.svn','.git','.gitignore','setup.pyc'],target_directory=None):
        """Build the WAPT package, stores the result in target_directory

        Zip the content of directory.

        Args:
            directoryname (str): source root directory of package to build

        Returns:
            str: waptfilename
        """

        result_filename = u''

        # some checks
        if not self.sourcespath:
            raise EWaptNotSourcesDirPackage('Error building package : There is no WAPT directory in %s' % self.sourcespath)

        if not os.path.isdir(os.path.join(self.sourcespath,'WAPT')):
            raise EWaptNotSourcesDirPackage('Error building package : There is no WAPT directory in %s' % self.sourcespath)

        control_filename = os.path.join(self.sourcespath,'WAPT','control')
        if not os.path.isfile(control_filename):
            raise EWaptNotSourcesDirPackage('Error building package : There is no control file in WAPT directory')

        force_utf8_no_bom(control_filename)

        # check version syntax
        parse_major_minor_patch_build(self.version)

        # check architecture
        if not self.architecture in ArchitecturesList:
            raise EWaptBadControl(u'Architecture should one of %s' % (ArchitecturesList,))

        self.filename = self.make_package_filename()

        logger.debug(u'Control data : \n%s' % self.ascontrol())
        if target_directory is None:
            target_directory = os.path.abspath(os.path.join(self.sourcespath,'..'))

        if not os.path.isdir(target_directory):
            raise Exception('Bad target directory %s for package build' % target_directory)

        result_filename = os.path.abspath(os.path.join(target_directory,self.filename))
        if os.path.isfile(result_filename):
            logger.warning('Target package already exists, removing %s' % result_filename)
            os.unlink(result_filename)

        self.localpath = result_filename

        allfiles = create_recursive_zip(
            zipfn = result_filename,
            source_root = self.sourcespath,
            target_root = '' ,
            excludes=excludes)
        return result_filename

    def sign_control(self,private_key,certificate):
        """Sign the contractual attributes of the control file using
            the provided key, add certificate Fingerprint and CN too

        Args:
            private_key (SSLPrivateKey)
            certificate (SSLCertificate)

        Returns:
            None
        """
        self.signature = self.get_signature(private_key).encode('base64')[0:-1]
        self.signature_date = time.strftime('%Y%m%d-%H%M%S')
        self.signer = certificate.cn
        self.signer_fingerprint = certificate.fingerprint

    def check_control_signature(self,public_certs):
        """Check control signature against a list of public certificates

        Args:
            public_certs (list of crt paths or SSLCertificate instances)

        Returns:
            matchine SSLCertificate

        >>> from waptpackage import *
        >>> from common import SSLPrivateKey,SSLCertificate
        >>> k = SSLPrivateKey('c:/private/test.pem')
        >>> c = SSLCertificate('c:/private/test.crt')

        >>> p = PackageEntry('test',version='1.0-0')
        >>> p.depends = 'test'
        >>> p.sign_control(k,c)
        >>> p.check_control_signature(c)
        """
        if not self.signature:
            raise EWaptNotSigned('Package control %s on repo %s is not signed' % (self.asrequirement(),self.repo))
        signed_content = self.signed_content()
        signature_raw = self.signature.decode('base64')
        if not isinstance(public_certs,list):
            public_certs = [public_certs]
        for public_cert in public_certs:
            try:
                if isinstance(public_cert,SSLCertificate):
                    crt = public_cert
                elif os.path.isfile(public_cert):
                    crt = SSLCertificate(public_cert)
                else:
                    raise EWaptMissingCertificate('The public cert %s is neither a cert file nor a SSL Certificate object' % public_cert)
                if crt.verify_content(signed_content,signature_raw):
                    return crt
            except SSLVerifyException:
                pass
        raise SSLVerifyException('SSL signature verification failed for control %s, either none public certificates match signature or signed content has been changed' % self.asrequirement())

    def build_manifest(self,exclude_filenames = None,block_size=2**20,forbidden_files=[]):
        if not os.path.isfile(self.wapt_fullpath()):
            raise Exception(u"%s is not a Wapt package" % self.wapt_fullpath())
        if exclude_filenames is None:
            exclude_filenames = self.manifest_filename_excludes
        waptzip = zipfile.ZipFile(self.wapt_fullpath(),'r',allowZip64=True)
        manifest = {}
        for fn in waptzip.filelist:
            if not fn.filename in exclude_filenames:
                if fn.filename in forbidden_files:
                    raise EWaptPackageSignError('File %s is not allowed.'% fn.filename)
                shasum = hashlib.sha1()
                file_data = waptzip.open(fn)
                while True:
                    data = file_data.read(block_size)
                    if not data:
                        break
                    shasum.update(data)
                shasum.update(data)
                manifest[fn.filename] = shasum.hexdigest()
        return manifest

    def sign_package(self,private_key,certificate):
        """Append control, manifest.sha1 and signature to zip apt package
            If these files are already in the package, they are first removed.
        """
        if not os.path.isfile(self.localpath) and not os.path.isdir(self.localpath):
            raise Exception(u"%s is not a Wapt package" % self.localpath)
        start_time = time.time()
        package_fn = self.localpath
        logger.debug('Signing %s with key %s, and certificate CN "%s"' % (package_fn,private_key,certificate.cn))
        # sign the control
        self.sign_control(private_key,certificate)

        control = self.ascontrol().encode('utf8')
        excludes = self.manifest_filename_excludes
        excludes.append('WAPT/control')

        forbidden_files = []
        # removes setup.py
        # if file is in forbidden_files, raise an exception.
        if not certificate.is_code_signing:
            forbidden_files.append('setup.py')
        try:
            manifest_data = self.build_manifest(exclude_filenames = excludes,forbidden_files = forbidden_files)
        except EWaptPackageSignError as e:
            raise EWaptBadCertificate('Certificate %s doesn''t allow to sign packages with setup.py file.' % certificate.public_cert_filename)

        manifest_data['WAPT/control'] = sha1_for_data(control)
        # convert to list of list...
        wapt_manifest = json.dumps( manifest_data.items())
        signature = private_key.sign_content(wapt_manifest)
        waptzip = zipfile.ZipFile(self.localpath,'a',allowZip64=True)
        with waptzip:
            filenames = waptzip.namelist()

            if 'WAPT/control' in filenames:
                waptzip.remove('WAPT/control')
            waptzip.writestr('WAPT/control',control)

            if 'WAPT/manifest.sha1' in filenames:
                waptzip.remove('WAPT/manifest.sha1')
            waptzip.writestr('WAPT/manifest.sha1',wapt_manifest)

            if 'WAPT/signature' in filenames:
                waptzip.remove('WAPT/signature')
            waptzip.writestr('WAPT/signature',signature.encode('base64'))

        return signature.encode('base64')

    def change_prefix(self,new_prefix):
        """Change prefix of package name to new_prefix and return True if
            it was really changed.
        """
        if '-' in self.package:
            (old_prefix,name) = self.package.split('-',1)
            if old_prefix != new_prefix:
                self.package = '%s-%s' % (new_prefix,name)
                return True
            else:
                return False
        else:
            return False

    def invalidate_signature(self):
        self.signature = None
        self.signature_date = None
        self.signer = None
        self.signer_fingerprint = None

    def list_corrupted_files(self):
        """check hexdigest sha for the files in manifest
        returns a list of non matching files (corrupted files)"""
        if not os.path.isdir(self.sourcespath):
            raise EWaptNotSourcesDirPackage(u'Check package files : %s is not a valid package directory.'%self.sourcespath)

        manifest_filename = os.path.join(self.sourcespath,'WAPT','manifest.sha1')
        if not os.path.isfile(manifest_filename):
            raise EWaptBadSignature(u'Check package files : not manifest file in %s directory.'%self.sourcespath)

        with open(manifest_filename,'r') as manifest_file:
            manifest = json.loads(manifest_file.read())
            if not isinstance(manifest,list):
                raise EWaptBadSignature(u'Check package files : manifest file in %s is invalid.'%self.sourcespath)

        errors = []
        expected = []

        for (filename,sha1) in manifest:
            fullpath = os.path.abspath(os.path.join(self.sourcespath,filename))
            expected.append(fullpath)
            if sha1 != sha1_for_file(fullpath):
                errors.append(filename)

        files = list(find_all_files(ensure_unicode(self.sourcespath)))
        # removes files which are not in manifest by design
        for fn in ('WAPT/signature','WAPT/manifest.sha1'):
            full_fn = os.path.abspath(os.path.join(self.sourcespath,fn))
            if full_fn in files:
                files.remove(full_fn)
        # add in errors list files found but not expected...
        errors.extend([ fn for fn in files if fn not in expected])
        return errors

    def check_package_signature(self,public_certs):
        """Check the hash of files in unzipped package_dir and the manifest signature
           against the authorized keys
        Args:
            public_certs (list) ; list of authorized certificate filepaths

        Returns:
            SSLcertificate : matching certificate

        Raise Exception if no certificate match is found.
        """
        if not public_certs:
            raise EWaptBadCertificate('No certificate to check package signature')
        if not isinstance(public_certs,list):
            public_certs = [public_certs]

        if not self.sourcespath:
            raise EWaptNotSourcesDirPackage(u'Check package signature : Package entry is is not a unzipped sources package directory.')

        if not os.path.isdir(self.sourcespath):
            raise EWaptNotAPackage(u'Check package signature : %s is not a valid package directory.'%self.sourcespath)

        verified_by = None

        manifest_filename = os.path.join(self.sourcespath,'WAPT','manifest.sha1')
        if os.path.isfile(manifest_filename):
            manifest_data = open(manifest_filename,'r').read()
            manifest_filelist = json.loads(manifest_data)

            has_setup_py = os.path.isfile(os.path.join(self.sourcespath,'setup.py'))
            if has_setup_py:
                logger.info('Package has a setup.py, code signing certificate required')

            signature_filename = os.path.join(self.sourcespath,'WAPT','signature')
            # if public key provided, and signature in wapt file, check it
            if os.path.isfile(signature_filename):
                # first check if signature can be decrypted by one of the public keys
                with open(signature_filename,'r') as signature_file:
                    signature = signature_file.read().decode('base64')
                try:
                    for cert in reversed(sorted(public_certs)):
                        logger.debug('Checking with %s' % cert)
                        if cert.verify_content(manifest_data,signature):
                            if has_setup_py and cert.is_code_signing:
                                logger.debug('OK with %s' % cert)
                                verified_by = cert
                                break
                            else:
                                logger.debug('signature OK but not a code signing certificate, skipping: %s' % cert)
                    if verified_by:
                        logger.info(u'Package issued by %s' % (verified_by.subject,))
                    else:
                        raise EWaptBadSignature('No matching certificate found or bad signature')
                except:
                    raise EWaptBadSignature(u'Package file %s signature is invalid.\n\nThe signer "%s" is not accepted by one the following public keys:\n%s' % \
                        (self.sourcespath,self.signer,u'\n'.join([u'%s' % cert for cert in public_certs])))

                # now check the integrity files
                errors = self.list_corrupted_files()
                if errors:
                    raise EWaptCorruptedFiles(u'Error in package dir %s, files corrupted, SHA not matching for %s' % (self.sourcespath,errors,))
                return verified_by
            else:
                raise EWaptNotSigned(u'The package dir in %s does not contain a signature' % self.sourcespath)
        else:
            raise EWaptNotSigned(u'The package dir in %s does not contain the manifest.sha1 file with content fingerprints' % self.sourcespath)


    def unzip_package(self,target_dir=None,check_with_certs=None):
        """Unzip package and optionnally check content

        Args:
            target_dir (str): where to unzip package content. If Noe, a temp dir is created
            check_with_certs (list) : list of Certificates to check content. If None, no check is done

        Returns:
            str : path to unzipped files

        Exceptions:
            EWaptNotAPackage, EWaptBadSignature,EWaptCorruptedFiles
            if check is not successful, unzipped files are deleted.
        """
        if not os.path.isfile(self.localpath):
            raise EWaptNotAPackage('unzip_package : Package %s does not exists' % ensure_unicode(self.localpath))
        if not target_dir:
            target_dir = tempfile.mkdtemp(prefix="wapt")
        else:
            target_dir = os.path.abspath(target_dir)

        if check_with_certs is not None and not isinstance(check_with_certs,list):
            check_with_certs = [check_with_certs]

        logger.info(u'Unzipping package %s to directory %s' % (self.wapt_fullpath(),ensure_unicode(target_dir)))
        with ZipFile(self.localpath) as zip:
            try:
                zip.extractall(path=target_dir)
                self.sourcespath = target_dir
                if check_with_certs is not None:
                    verified_by = self.check_package_signature(check_with_certs)
                    logger.info(u'Unzipped files verified by certificate %s' % verified_by)
            except Exception as e:
                if os.path.isdir(target_dir):
                    try:
                        shutil.rmtree(target_dir)
                    except Exception as e:
                        logger.critical(u'Unable to remove temprary files %s' % repr(target_dir))
                raise
        return self.sourcespath

    def remove_localsources(self):
        """Remove the unzipped local directory
        """
        if self.sourcespath and os.path.isdir(self.sourcespath):
            try:
                shutil.rmtree(self.sourcespath)
                self.sourcespath = None
            except Exception as e:
                pass

class WaptPackageDev(PackageEntry):
    """Source package directory"""

    def build_package(self,directoryname,inc_package_release=False,excludes=['.svn','.git','.gitignore','setup.pyc'],
                target_directory=None):
        raise NotImplementedError()


class WaptPackage(PackageEntry):
    """Built Wapt package zip file"""

    def __init__(self,package_filename):
        PackageEntry.__init__(self)
        self.package_filename = package_filename



def extract_iconpng_from_wapt(fname):
    """Return the content of WAPT/icon.png if it exists, a unknown.png file content if not

    """
    iconpng = None
    if os.path.isfile(fname):
        with zipfile.ZipFile(fname,'r',allowZip64=True) as myzip:
            try:
                iconpng = myzip.open(u'WAPT/icon.png').read()
            except:
                pass
    elif os.path.isdir(fname):
        png_path = os.path.join(fname,'WAPT','icon.png')
        if os.path.isfile(png_path):
            iconpng = open(u'WAPT/icon.png','rb').read()

    if not iconpng:
        unknown_png_path = os.path.join(os.path.dirname(__file__),'icons','unknown.png')
        if os.path.isfile(unknown_png_path):
            iconpng = open(unknown_png_path,'rb').read()

    if not iconpng:
        raise Exception(u'no icon.png found in package name {}'.format(fname))

    return iconpng


class WaptBaseRepo(object):
    """Base abstract class for a Wapt Packages repository
    """
    def __init__(self,name='abstract',public_certs=None):
        self.name = name
        self._packages = None
        self._index = {}
        self._packages_date = None

        # if not None, control's signature will be check against this certificates list
        self.public_certs = public_certs

    def _load_packages_index(self):
        self._packages = []
        self._packages_date = None

    def update(self):
        return self._load_packages_index()

    @property
    def packages(self):
        if self._packages is None:
            self._load_packages_index()
        return self._packages

    @property
    def packages_date(self):
        if self._packages is None:
            self._load_packages_index()
        return self._packages_date

    def is_available(self):
        # return isodate of last updates of the repo is available else None
        return self.packages_date

    def need_update(self,last_modified=None):
        """Check if packges index has changed on repo and local db needs an update

        Compare date on local package index DB with the Packages file on remote
          repository with a HEAD http request.

        Args:
            last_modified (str): iso datetime of last known update of packages.

        Returns
            bool:   True if either Packages was never read or remote date of Packages is
                    more recent than the provided last_modifed date.

        >>> repo = WaptRemoteRepo(name='main',url='http://wapt/wapt',timeout=4)
        >>> waptdb = WaptDB('c:/wapt/db/waptdb.sqlite')
        >>> res = repo.need_update(waptdb.read_param('last-%s'% repo.url))
        >>> isinstance(res,bool)
        True
        """
        if not last_modified and not self._packages_date:
            logger.debug(u'need_update : no last_modified date provided, update is needed')
            return True
        else:
            if not last_modified:
                last_modified = self._packages_date
            if last_modified:
                logger.debug(u'Check last-modified header for %s to avoid unecessary update' % (self.name,))
                current_update = self.is_available()
                if current_update == last_modified:
                    logger.info(u'Index from %s has not been updated (last update %s), skipping update' % (self.name,current_update))
                    return False
                else:
                    return True
            else:
                return True

    def search(self,searchwords = [],sections=[],newest_only=False):
        """Return list of package entries
            with description or name matching all the searchwords and section in
            provided sections list

        >>> r = WaptRemoteRepo(name='test',url='http://wapt.tranquil.it/wapt')
        >>> r.search('test')
        """
        searchwords = ensure_list(searchwords)
        sections = ensure_list(sections)
        words = [ w.lower() for w in searchwords ]

        result = []
        for package in self.packages:
            selected = True
            for w in words:
                if w not in (package.description+' '+package.package).lower():
                    selected = False
                    break
            if sections:
                if package.section not in sections:
                    selected = False
            if selected:
                result.append(package)
        if newest_only:
            filtered = []
            last_package_name = None
            for package in sorted(result,reverse=True):
                if package.package != last_package_name:
                    filtered.append(package)
                last_package_name = package.package
            return list(reversed(filtered))
        else:
            return sorted(result)


    def packages_matching(self,package_cond):
        """Return an ordered list of available packages entries which match
            the condition "packagename[([=<>]version)]?"
            version ascending
        >>> from waptpackage import *
        >>> r = WaptRemoteRepo('http://wapt.tranquil.it/wapt')
        >>> r.packages_matching('tis-firefox (>=20)')
        [PackageEntry('tis-firefox','20.0.1-02'),
         PackageEntry('tis-firefox','21.0.0-00'),
         ...]
        """
        pcv_match = REGEX_PACKAGE_CONDITION.match(package_cond)
        if pcv_match:
            pcv = pcv_match.groupdict()
            result = [ pe for pe in self.packages if pe.package == pcv['package'] and pe.match(package_cond)]
            result.sort()
            return result
        else:
            return []

    def __iter__(self):
        # ensure packages is loaded
        if self._packages is None:
            self._load_packages_index()
        return self._index.__iter__()


    def __getitem__(self,packagename):
        # ensure packages is loaded
        if self._packages is None:
            self._load_packages_index()
        return self._index[packagename]

    def get(self,packagename,default=None):
        # ensure packages is loaded
        if self._packages is None:
            self._load_packages_index()
        return self._index.get(packagename,default)


class WaptLocalRepo(WaptBaseRepo):
    """Index of Wapt local repository.
        Index of packages is located in a Packages zip file, having one
            Packages file, containing the concatenated content of "control"
            files of the packages.

            A blank line means new package.
    >>> localrepo = WaptLocalRepo('c:/wapt/cache')
    >>> localrepo.update()
    """
    def __init__(self,localpath='/var/www/wapt',name='waptlocal',public_certs=None):
        WaptBaseRepo.__init__(self,name=name,public_certs=public_certs)
        self.localpath = localpath.rstrip(os.path.sep)
        self.packages_path = os.path.join(self.localpath,'Packages')

    def _load_packages_index(self):
        """Parse Packages index from local repo Packages file

        Packages file is zipped file with one file named Packages.

        This files is the concatenation of control files of each package
          in the repository

        >>> repo = WaptLocalRepo(localpath='c:\\wapt\\cache')
        >>> repo._load_packages_index()
        >>> isinstance(repo.packages,list)
        True
        """
        # Packages file is a zipfile with one Packages file inside
        if os.path.isfile(self.packages_path):
            self._packages_date = datetime2isodate(datetime.datetime.utcfromtimestamp(os.stat(self.packages_path).st_mtime))
            with zipfile.ZipFile(self.packages_path) as packages_file:
                packages_lines = packages_file.read(name='Packages').decode('utf8').splitlines()

            if self._packages is not None:
                del(self._packages[:])
            else:
                self._packages = []
            self._index.clear()

            startline = 0
            endline = 0

            def add(start,end):
                if start != end:
                    package = PackageEntry()
                    package.load_control_from_wapt(packages_lines[start:end])
                    logger.debug(u"%s (%s)" % (package.package,package.version))
                    package.repo_url = 'file:///%s'%(self.localpath.replace('\\','/'))
                    package.repo = self.name
                    package.filename = package.make_package_filename()
                    package.localpath = None
                    self._packages.append(package)
                    # index last version
                    if package.package not in self._index or self._index[package.package] < package:
                        self._index[package.package] = package

            for line in packages_lines:
                if line.strip()=='':
                    add(startline,endline)
                    endline += 1
                    startline = endline
                # add ettribute to current package
                else:
                    endline += 1
            # last one
            add(startline,endline)
        else:
            self._packages = []
            self._index.clear()
            self._packages_date = None

    def update_packages_index(self,force_all=False):
        """Scan self.localpath directory for WAPT packages and build a Packages (utf8) zip file with control data and MD5 hash

        Extract icons from packages (WAPT/icon.png) and stores them in <repo path>/icons/<package name>.png

        """
        packages_fname = os.path.abspath(os.path.join(self.localpath,'Packages'))
        icons_path = os.path.abspath(os.path.join(self.localpath,'icons'))
        if not os.path.isdir(icons_path):
            os.makedirs(icons_path)

        if force_all:
            self._packages = []

        old_entries = {}
        for package in self.packages:
            # keep only entries which are older than index. Other should be recalculated.
            localwaptfile = os.path.abspath(os.path.join(self.localpath,os.path.basename(package.filename)))
            if os.path.isfile(localwaptfile):
                if fileisoutcdate(localwaptfile) <= self._packages_date:
                    old_entries[os.path.basename(package.filename)] = package
                else:
                    logger.info("Don't keep old entry for %s, wapt package is newer than index..." % package.asrequirement())
            else:
                logger.info('Stripping entry without matching file : %s'%localwaptfile)

        if not os.path.isdir(self.localpath):
            raise Exception(u'%s is not a directory' % (self.localpath))

        waptlist = glob.glob(os.path.abspath(os.path.join(self.localpath,'*.wapt')))
        packages_lines = []
        kept = []
        processed = []
        errors = []
        if self._packages is None:
            self._packages = []
        else:
            del(self._packages[:])
        self._index.clear()

        for fname in waptlist:
            try:
                package_filename = os.path.basename(fname)
                entry = PackageEntry()
                if package_filename in old_entries:
                    entry.load_control_from_wapt(fname,calc_md5=False)
                    if not force_all and entry == old_entries[package_filename] and \
                                entry.signature == old_entries[package_filename].signature and \
                                entry.signature_date == old_entries[package_filename].signature_date:
                        logger.debug(u"  Keeping %s" % package_filename)
                        kept.append(fname)
                        entry = old_entries[package_filename]
                    else:
                        logger.info(u"  Processing %s" % fname)
                        entry.load_control_from_wapt(fname)
                        processed.append(fname)
                else:
                    logger.info(u"  Processing %s" % fname)
                    entry.load_control_from_wapt(fname)
                    processed.append(fname)
                    theoritical_package_filename =  entry.make_package_filename()
                    if package_filename != theoritical_package_filename:
                        logger.warning('Package filename %s should be %s to comply with control metadata. Renaming...'%(package_filename,theoritical_package_filename))
                        os.rename(fname,os.path.join(os.path.dirname(fname),theoritical_package_filename))

                packages_lines.append(entry.ascontrol(with_non_control_attributes=True))
                # add a blank line between each package control
                packages_lines.append('')

                self._packages.append(entry)
                # index last version
                if entry.package not in self._index or self._index[entry.package] < entry:
                    self._index[entry.package] = entry

                # looks for an icon in wapt package
                icon_fn = os.path.join(icons_path,"%s.png"%entry.package)
                if entry.section not in ['group','host'] and (force_all or not os.path.isfile(icon_fn)):
                    try:
                        icon = extract_iconpng_from_wapt(fname)
                        open(icon_fn,'wb').write(icon)
                    except Exception as e:
                        logger.debug(r"Unable to extract icon for %s:%s"%(fname,e))

            except Exception as e:
                print(e)
                logger.critical("package %s: %s" % (fname,e))
                errors.append(fname)

        logger.info(u"Writing new %s" % packages_fname)
        tmp_packages_fname = packages_fname+'.%s'%datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        try:
            with zipfile.ZipFile(tmp_packages_fname, "w",compression=zipfile.ZIP_DEFLATED) as  myzipfile:
                zi = zipfile.ZipInfo(u"Packages",date_time = time.localtime())
                zi.compress_type = zipfile.ZIP_DEFLATED
                myzipfile.writestr(zi,u'\n'.join(packages_lines).encode('utf8'))
            if os.path.isfile(packages_fname):
                os.unlink(packages_fname)
            os.rename(tmp_packages_fname,packages_fname)
            logger.info(u"Finished")
        except Exception as e:
            if os.path.isfile(tmp_packages_fname):
                os.unlink(tmp_packages_fname)
            logger.critical('Unable to create new Packages file : %s' % e)
            raise
        return {'processed':processed,'kept':kept,'errors':errors,'packages_filename':packages_fname}

    def is_available(self):
        """Check if repo is reachable an return last update date.
        """
        if os.path.isfile(self.packages_path):
            return self._packages_date
        else:
            return None


class WaptRemoteRepo(WaptBaseRepo):
    """Gives access to a remote http repository, with a zipped Packages packages index

    >>> repo = WaptRemoteRepo(name='main',url='http://wapt/wapt',timeout=4)
    >>> last_modified = repo.is_available()
    >>> isinstance(last_modified,str)
    True
    """

    def __init__(self,url=None,name='',proxies={'http':None,'https':None},timeout = 2,public_certs=None):
        """Initialize a repo at url "url".

        Args:
            name (str): internal local name of this repository
            url  (str): http URL to the repository.
                 If url is None, the url is requested from DNS by a SRV query
            proxies (dict): configuration of http proxies as defined for requests
            timeout (float): timeout in seconds for the connection to the rmeote repository
        """
        WaptBaseRepo.__init__(self,name=name,public_certs=public_certs)
        if url and url[-1]=='/':
            url = url.rstrip('/')
        self._repo_url = url

        self._packages_date = None
        self._packages = None

        self.proxies = proxies
        self.verify_cert = False
        self.timeout = timeout

    @property
    def repo_url(self):
        return self._repo_url

    @repo_url.setter
    def repo_url(self,value):
        if value:
            value = value.rstrip('/')

        if value != self._repo_url:
            self._repo_url = value
            self._packages = None
            self._packages_date = None

    def load_config(self,config,section=None):
        """Load waptrepo configuration from inifile section.

                Use name of repo as section name if section is not provided.
                Use 'global' if no section named section in ini file
        Args:
            config (RawConfigParser): ini configuration
            section (str)           : section where to loads parameters
                                      defaults to name of repository

        Returns:
            WaptRemoteRepo: return itself to chain calls.
        """
        if not section:
             section = self.name
        if not config.has_section(section):
            section = 'global'

        if config.has_option(section,'repo_url'):
            self.repo_url = config.get(section,'repo_url')

        if config.has_option(section,'verify_cert'):
            try:
                self.verify_cert = config.getboolean(section,'verify_cert')
            except:
                self.verify_cert = config.get(section,'verify_cert')
        else:
            self.verify_cert = False

        if config.has_option(section,'use_http_proxy_for_repo') and config.getboolean(section,'use_http_proxy_for_repo'):
            if config.has_option(section,'http_proxy'):
                # force a specific proxy from wapt conf
                self.proxies = {'http':config.get(section,'http_proxy'),'https':config.get(section,'http_proxy')}
            else:
                # use default windows proxy ?
                self.proxies = None
        else:
            # force to not use proxy, even if one is defined in windows
            self.proxies = {'http':None,'https':None}

        if config.has_option(section,'timeout'):
            self.timeout = config.getfloat(section,'timeout')
        return self

    @property
    def packages_url(self):
        """return url of Packages index file

        >>> repo = WaptRemoteRepo(name='main',url='http://wapt/wapt',timeout=4)
        >>> repo.packages_url
        'http://wapt/wapt/Packages'

        hardcoded path to the Packages index.
        """
        return self.repo_url + '/Packages'

    def is_available(self):
        """Check if repo is reachable an return createion date of Packages.

        Try to access the repo and return last modified date of repo index or None if not accessible

        Returns:
            str: Iso creation date of remote Package file as returned in http headers

        >>> repo = WaptRemoteRepo(name='main',url='http://wapt/wapt',timeout=1)
        >>> repo.is_available() <= datetime2isodate()
        True
        >>> repo = WaptRemoteRepo(name='main',url='http://badwapt/wapt',timeout=1)
        >>> repo.is_available() is None
        True
        """
        logger.debug(u'Checking availability of %s' % (self.packages_url,))
        try:
            req = requests.head(
                self.packages_url,
                timeout=self.timeout,
                proxies=self.proxies,
                verify=self.verify_cert,
                headers=default_http_headers()
                )
            req.raise_for_status()
            packages_last_modified = req.headers['last-modified']
            return httpdatetime2isodate(packages_last_modified)
        except requests.RequestException as e:
            logger.debug(u'Repo packages index %s is not available : %s'%(self.packages_url,e))
            return None

    def _load_packages_index(self):
        """Try to load index of packages as PackageEntry list from repository

        HTTP Get remote Packages zip file and parses the entries.

        The list of package entries is stored in the packages property.

        Returns
            dict: list of added or removed packages and create date {'added':list,'removed':list,'last-modified':isodatetime}
        """
        if self._packages is None:
            self._packages = []
        if not self.repo_url:
            raise Exception('Repository URL for %s is not defined' % self.name)

        new_packages = []
        logger.debug(u'Read remote Packages zip file %s' % self.packages_url)
        packages_answer = requests.get(self.packages_url,proxies=self.proxies,timeout=self.timeout, verify=self.verify_cert,headers=default_http_headers())
        packages_answer.raise_for_status()

        # Packages file is a zipfile with one Packages file inside
        packages_lines = codecs.decode(zipfile.ZipFile(
              StringIO.StringIO(packages_answer.content)
            ).read(name='Packages'),'UTF-8').splitlines()

        startline = 0
        endline = 0

        def add(start,end):
            if start != end:
                package = PackageEntry()
                package.load_control_from_wapt(packages_lines[start:end])
                logger.debug(u"%s (%s)" % (package.package,package.version))
                package.repo_url = self.repo_url
                package.repo = self.name
                if self.public_certs is None or package.check_control_signature(self.public_certs):
                    new_packages.append(package)
                else:
                    logger.critical("Control data of package %s on repository %s is either corrupted or doesn't match any of the expected certificates %s" % (package.asrequirement(),self.name,self.public_certs))

        for line in packages_lines:
            if line.strip()=='':
                add(startline,endline)
                endline += 1
                startline = endline
            # add ettribute to current package
            else:
                endline += 1
        # last one
        add(startline,endline)
        added = [ p for p in new_packages if p not in self._packages]
        removed = [ p for p in self._packages if p not in new_packages]
        self._packages = new_packages
        self._packages_date = httpdatetime2isodate(packages_answer.headers['last-modified'])
        return {'added':added,'removed':removed,'last-modified': self.packages_date }

    @property
    def packages(self):
        if self._packages is None:
            self._load_packages_index()
        return self._packages

    def as_dict(self):
        result = {
            'name':self.name,
            'repo_url':self._repo_url,
            'proxies':self.proxies,
            'timeout':self.timeout,
            }
        return result

    def download_packages(self,package_requests,target_dir=None,usecache=True,printhook=None):
        r"""Download a list of packages (requests are of the form packagename (>version) )
           returns a dict of {"downloaded,"skipped","errors"}

        >>> repo = WaptRemoteRepo(url='http://wapt.tranquil.it/wapt')
        >>> wapt.download_packages(['tis-firefox','tis-waptdev'],printhook=nullhook)
        {'downloaded': [u'c:/wapt\\cache\\tis-firefox_37.0.2-9_all.wapt', u'c:/wapt\\cache\\tis-waptdev.wapt'], 'skipped': [], 'errors': []}
        """
        if not isinstance(package_requests,(list,tuple)):
            package_requests = [ package_requests ]
        if not target_dir:
            target_dir = tempfile.mkdtemp()

        downloaded = []
        skipped = []
        errors = []
        packages = []
        for p in package_requests:
            if isinstance(p,str) or isinstance(p,unicode):
                mp = self.packages_matching(p)
                if mp:
                    packages.append(mp[-1])
                else:
                    errors.append((p,u'Unavailable package %s' % (p,)))
                    logger.critical(u'Unavailable package %s' % (p,))
            elif isinstance(p,PackageEntry):
                packages.append(p)
            else:
                raise Exception('Invalid package request %s' % p)
        for entry in packages:
            packagefilename = entry.filename.strip('./')
            download_url = entry.repo_url+'/'+packagefilename
            fullpackagepath = os.path.join(target_dir,packagefilename)
            skip = False
            if usecache and os.path.isfile(fullpackagepath) and os.path.getsize(fullpackagepath)>0:
                # check version
                try:
                    cached = PackageEntry()
                    cached.load_control_from_wapt(fullpackagepath,calc_md5=True)
                    if entry == cached:
                        if entry.md5sum == cached.md5sum:
                            skipped.append(fullpackagepath)
                            logger.info(u"  Use cached package file from " + fullpackagepath)
                            skip = True
                        else:
                            logger.critical(u"Cached file MD5 doesn't match MD5 found in packages index. Discarding cached file")
                            os.remove(fullpackagepath)
                except Exception as e:
                    # error : reload
                    logger.debug(u'Cache file %s is corrupted, reloading it. Error : %s' % (fullpackagepath,e) )

            if not skip:
                logger.info(u"  Downloading package from %s" % download_url)
                try:
                    def report(received,total,speed,url):
                        try:
                            if total>1:
                                stat = u'%s : %i / %i (%.0f%%) (%.0f KB/s)\r' % (url,received,total,100.0*received/total, speed)
                                print(stat)
                            else:
                                stat = ''
                        except:
                            pass
                    if not printhook:
                        printhook = report

                    wget(download_url,target_dir,proxies=self.proxies,printhook = printhook,connect_timeout=self.timeout,verify_cert = self.verify_cert)
                    downloaded.append(fullpackagepath)
                except Exception as e:
                    if os.path.isfile(fullpackagepath):
                        os.remove(fullpackagepath)
                    logger.critical(u"Error downloading package from http repository, please update... error : %s" % e)
                    errors.append((download_url,"%s" % e))
        return {"downloaded":downloaded,"skipped":skipped,"errors":errors}

def update_packages(adir,force=False):
    """Helper function to update a local packages index

    This function is used on repositories to rescan all packages and
      update the Packages index.

    >>> if os.path.isdir('c:\\wapt\\cache'):
    ...     repopath = 'c:\\wapt\\cache'
    ... else:
    ...     repopath = '/var/www/wapt'
    >>> p = PackageEntry()
    >>> p.package = 'test'
    >>> p.version = '10'
    >>> new_package_fn = os.path.join(repopath,p.make_package_filename())
    >>> if os.path.isfile(new_package_fn):
    ...     os.unlink(new_package_fn)
    >>> res = update_packages(repopath)
    >>> os.path.isfile(res['packages_filename'])
    True
    >>> r = WaptLocalRepo(localpath=repopath)
    >>> l1 = r.packages
    >>> res = r.update_packages_index()
    >>> l2 = r.packages
    >>> [p for p in l2 if p not in l1]
    ["test (=10)"]
    """
    repo = WaptLocalRepo(localpath=os.path.abspath(adir))
    return repo.update_packages_index(force_all=force)

if __name__ == '__main__':
    import doctest
    import sys
    reload(sys)
    sys.setdefaultencoding("UTF-8")
    import doctest
    doctest.ELLIPSIS_MARKER = '???'
    doctest.testmod(optionflags=doctest.ELLIPSIS)
    sys.exit(0)
