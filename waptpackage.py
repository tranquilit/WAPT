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
__version__ = "1.2.1"

import os
import zipfile
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
REGEX_PACKAGE_CONDITION = re.compile(r'(?P<package>[^\s()]+)\s*(\(\s*(?P<operator>[<=>]+)\s*(?P<version>\S+)\s*\))?')


def parse_major_minor_patch_build(version):
    """
    Parse version to major, minor, patch, pre-release, build parts.
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


class Version(object):
    """Version object of form 0.0.0
        can compare with respect to natural numbering and not alphabetical

    >>> Version('0.10.2') > Version('0.2.5')
    True
    >>> Version('0.1.2') < Version('0.2.5')
    True
    >>> Version('0.1.2') == Version('0.1.2')
    True
    """

    def __init__(self,versionstring):
        if versionstring is None:
            versionstring = ''
        assert isinstance(versionstring,types.ModuleType) or isinstance(versionstring,str) or isinstance(versionstring,unicode)
        if isinstance(versionstring,types.ModuleType):
            versionstring = versionstring.__version__
        self.members = [ v.strip() for v in versionstring.split('.')]

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
            aversion = Version(aversion)
        for i in range(0,min([len(self.members),len(aversion.members)])):
            i1,i2  = self.members[i], aversion.members[i]
            v = nat_cmp(i1,i2)
            if v:
                return v
        return 0

    def __str__(self):
        return '.'.join(self.members)

    def __repr__(self):
        return "Version('{}')".format('.'.join(self.members))


class PackageRequest(object):
    """Package and version request / condition

    >>> PackageRequest('7-zip( >= 7.2)')
    PackageRequest('7-zip (>=7.2)')
    """
    def __init__(self,package_request):
        self.package_request = package_request
        parts = REGEX_PACKAGE_CONDITION.match(self.package_request).groupdict()
        self.package = parts['package']
        self.operator = parts['operator']
        self.version = Version(parts['version'])

    def __cmp__(self,other):
        if isinstance(other,str) or isinstance(other,unicode):
            other = PackageRequest(other)
        return cmp((self.package,self.version,self.operator),(other.package,other.version,other.operator))

    def __str__(self):
        return self.package_request

    def __repr__(self):
        return "PackageRequest('{package} ({operator}{version})')".format(package=self.package,operator=self.operator,version=self.version)

class PackageEntry(object):
    """Package attributes coming from either control files in WAPT package or local DB

    """
    required_attributes = ['package','version','architecture',]
    optional_attributes = ['section','priority','maintainer','description','depends','conflicts','sources','installed_size']
    non_control_attributes = ['localpath','filename','size','repo_url','md5sum','repo',]

    @property
    def all_attributes(self):
        return self.required_attributes + self.optional_attributes + self.non_control_attributes + self.calculated_attributes

    def __init__(self,package='',version='0',repo=''):
        self.package=package
        self.version=version
        self.architecture='all'
        self.section=''
        self.priority=''
        self.maintainer=''
        self.description=''
        self.depends=''
        self.conflicts=''
        self.sources=''
        self.filename=''
        self.size=''
        self.md5sum=''
        self.repo_url=''
        self.repo=repo
        self.localpath=''
        self.installed_size=''
        self.calculated_attributes=[]

    def parse_version(self):
        """Parse version to major, minor, patch, pre-release, build parts.

        """
        return parse_major_minor_patch_build(self.version)

    def __getitem__(self,name):
        name = name.lower()
        if hasattr(self,name):
            return getattr(self,name)
        else:
            raise Exception(u'No such attribute : %s' % name)

    def get(self,name,default=None):
        name = name.lower()
        if hasattr(self,name):
            return getattr(self,name)
        else:
            return default

    def __setitem__(self,name,value):
        name = name.lower()
        if not name in self.all_attributes:
            self.calculated_attributes.append(name)
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
        except ValueError,e:
            logger.warning("%s" % e)
            if isinstance(entry_or_version,PackageEntry):
                return cmp((self.package,self.version),(entry_or_version.package,entry_or_version.version))
            else:
                return cmp(self.version,entry_or_version)

    def match(self, match_expr):
        """Return True if package entry match a package string like 'tis-package (>=1.0.1-00)"""
        pcv = REGEX_PACKAGE_CONDITION.match(match_expr).groupdict()
        if pcv['package'] != self.package:
            return False
        else:
            if 'operator' in pcv and pcv['operator']:
                return self.match_version(pcv['operator']+pcv['version'])
            else:
                return True

    def match_version(self, match_expr):
        """Return True if package entry match a version string condition like '>=1.0.1-00'"""
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
            result = re.match(r'\b{}'.format(search.replace(' ',r'.*\b')),self.description,re.IGNORECASE)

    def load_control_from_dict(self,adict):
        for k in adict:
            setattr(self,k,adict[k])
            if not k in self.all_attributes:
                self.calculated_attributes.append(k)
        return self

    def load_control_from_wapt(self,fname,calc_md5=True):
        """Load package attributes from the control file (utf8 encoded) included in WAPT zipfile fname

          fname can be
           - the path to WAPT file itelsef (zip file)
           - a list with the lines from control file
           - a path to the directory of wapt file unzipped content (debugging)
        """
        if type(fname) is list:
            control =  StringIO.StringIO(u'\n'.join(fname))
        elif os.path.isfile(fname):
            myzip = zipfile.ZipFile(fname,'r',allowZip64=True)
            control = StringIO.StringIO(myzip.open(u'WAPT/control').read().decode('utf8'))
        elif os.path.isdir(fname):
            control = codecs.open(os.path.join(fname,'WAPT','control'),'r',encoding='utf8')
        else:
            raise Exception(u'No control found for %s' % (fname,))

        (param,value) = ('','')
        while 1:
            line = control.readline()
            if not line or not line.strip():
                break
            if line.startswith(' '):
                # additional lines begin with a space!
                value = getattr(self,param)
                value += '\n '
                value += line.strip()
                setattr(self,param,value)
            else:
                sc = line.find(':')
                if sc<0:
                    raise Exception(u'Invalid line (no ":" found) : %s' % line)
                (param,value) = (line[:sc].strip(),line[sc+1:].strip())
                param = param.lower()
                setattr(self,param,value)

        if not type(fname) is list and os.path.isfile(fname):
            if calc_md5:
                self.md5sum = md5_for_file(fname)
            else:
                self.md5sum = ''
            self.size = os.path.getsize(fname)
            self.filename = os.path.basename(fname)
            self.localpath = os.path.dirname(os.path.abspath(fname))
        else:
            self.filename = self.make_package_filename()
            self.localpath = ''
        return self

    def wapt_fullpath(self):
        """return full local path of wapt package if built"""
        return os.path.join(self.localpath,self.filename)

    def save_control_to_wapt(self,fname):
        """Save package attributes to the control file (utf8 encoded)

          fname can be
           - the path to WAPT file itelsef (zip file)
           - a path to the directory of wapt file unzipped content (debugging)
        """
        if os.path.isdir(fname):
            codecs.open(os.path.join(fname,u'WAPT','control'),'w',encoding='utf8').write(self.ascontrol())
        else:
            if os.path.isfile(fname):
                myzip = zipfile.ZipFile(fname,'a',allowZip64=True,compression=zipfile.ZIP_DEFLATED)
                try:
                    zi = myzip.getinfo(u'WAPT/control')
                    control_exist = True
                except:
                    control_exist = False
                    self.filename = os.path.basename(fname)
                    self.localpath = os.path.dirname(os.path.abspath(fname))
                if control_exist:
                    myzip.close()
                    raise Exception(u'control file already exist in WAPT file %s' % fname)
            else:
                myzip = zipfile.ZipFile(fname,'w',allowZip64=True,compression=zipfile.ZIP_DEFLATED)
            myzip.writestr(u'WAPT/control',self.ascontrol().encode('utf8'))
            myzip.close()

    def ascontrol(self,with_non_control_attributes = False):
        val = u"""\
package      : %(package)s
version      : %(version)s
architecture : %(architecture)s
section      : %(section)s
priority     : %(priority)s
maintainer   : %(maintainer)s
description  : %(description)s
depends      : %(depends)s
conflicts    : %(conflicts)s
sources      : %(sources)s
"""  % self.__dict__
        if with_non_control_attributes:
            for att in self.non_control_attributes:
                val += u"%-13s: %s\n" % (att, getattr(self,att))
        return val

    def make_package_filename(self):
        """Return the standard package filename based on current attributes

        Returns:
            str:  standard package filename packagename_version_arch.wapt for
                    softwares
                  packagename.wapt for group and host.
        """
        if not self.section in ['host','group'] and not (self.package and self.version and self.architecture):
            raise Exception(u'Not enough information to build the package filename for %s (%s)'%(self.package,self.version))
        if self.section in ['host','group']:
            return self.package+'.wapt'
        else:
            return self.package + '_' + self.version + '_' +  self.architecture  + '.wapt'

    def asrequirement(self):
        """resturn package and version for designing this package in depends or install actions

        Returns:
            str: "packagename (=version)"
        """
        return "%s (=%s)" % (self.package,self.version)

    property
    def download_url(self):
        return self.repo_url+'/'+self.filename.strip('./')

    def as_dict(self):
        result ={}
        for k in self.all_attributes:
            result[k] = getattr(self,k)
        return result

    def __unicode__(self):
        return self.ascontrol(with_non_control_attributes=True)

    def __str__(self):
        return self.__unicode__()

    def __repr__(self):
        return u"PackageEntry('%s','%s')" % (self.package,self.version)

    def inc_build(self):
        """Increment last number part of version"""
        version_parts = self.parse_version()
        for part in ('packaging','subpatch','patch','minor','major'):
            if part in version_parts and version_parts[part] != None and\
                (isinstance(version_parts[part],int) or version_parts[part].isdigit()):
                version_parts[part] = "%i" % (int(version_parts[part])+1,)
                self.version = make_version(version_parts)
                return
        raise Exception(u'no build/packaging part in version number %s' % self.version)


def extract_iconpng_from_wapt(fname):
    """Return the content of WAPT/icon.png if it exists, a unknown.png file content if not

    """
    iconpng = None
    if os.path.isfile(fname):
        myzip = zipfile.ZipFile(fname,'r',allowZip64=True)
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


class WaptLocalRepo(object):
    def __init__(self,localpath='/var/www/wapt',name='waptlocal'):
        self.name = name
        localpath = localpath.rstrip(os.path.sep)
        self.localpath = localpath
        self.packages = []
        self.index = {}

    def load_packages(self):
        """Parse Packages index from local repo Packages file

        Packages file is zipped file with one file named Packages.

        This files is the concatenation of control files of each package
          in the repository

        >>> repo = WaptLocalRepo(localpath='c:\\wapt\\cache')
        >>> repo.load_packages()
        >>> isinstance(repo.packages,list)
        True
        """
        # Packages file is a zipfile with one Packages file inside
        if os.path.isfile(os.path.join(self.localpath,'Packages')):
            packages_file = zipfile.ZipFile(os.path.join(self.localpath,'Packages'))
            try:
                packages_lines = packages_file.read(name='Packages').decode('utf8').splitlines()
            finally:
                packages_file.close()
            del(self.packages[:])
            self.index.clear()

            startline = 0
            endline = 0

            def add(start,end):
                if start != end:
                    package = PackageEntry()
                    package.load_control_from_wapt(packages_lines[start:end])
                    logger.info(u"%s (%s)" % (package.package,package.version))
                    package.repo_url = 'file:///%s'%(self.localpath.replace('\\','/'))
                    package.repo = self.name
                    package.localpath = self.localpath
                    package.filename = package.make_package_filename()
                    self.packages.append(package)
                    # index last version
                    if not package.package in self.index or self.index[package.package] < package:
                        self.index[package.package] = package

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

    def update_packages_index(self,force_all=False):
        """Scan self.localpath directory for WAPT packages and build a Packages (utf8) zip file with control data and MD5 hash

        Extract icons from packages (WAPT/icon.png) and stores them in <repo path>/icons/<package name>.png

        """
        packages_fname = os.path.join(self.localpath,'Packages')
        icons_path = os.path.join(self.localpath,'icons')
        if not os.path.isdir(icons_path):
            os.makedirs(icons_path)

        if not force_all and not self.packages:
            self.load_packages()
        old_entries = {}
        for package in self.packages:
            old_entries[os.path.basename(package.filename)] = package

        if not os.path.isdir(self.localpath):
            raise Exception(u'%s is not a directory' % (self.localpath))

        waptlist = glob.glob(os.path.join(self.localpath,'*.wapt'))
        packages_lines = []
        kept = []
        processed = []
        errors = []
        del(self.packages[:])
        self.index.clear()

        for fname in waptlist:
            try:
                entry = PackageEntry()
                if os.path.basename(fname) in old_entries:
                    entry.load_control_from_wapt(fname,calc_md5=False)
                    if not force_all and entry == old_entries[os.path.basename(fname)]:
                        logger.info(u"  Keeping %s" % fname)
                        kept.append(fname)
                        entry = old_entries[os.path.basename(fname)]
                    else:
                        logger.info(u"  Processing %s" % fname)
                        entry.load_control_from_wapt(fname)
                        processed.append(fname)
                else:
                    logger.info(u"  Processing %s" % fname)
                    entry.load_control_from_wapt(fname)
                    processed.append(fname)
                packages_lines.append(entry.ascontrol(with_non_control_attributes=True))
                self.packages.append(entry)
                # index last version
                if not package.package in self.index or self.index[package.package] < package:
                    self.index[package.package] = package

                # looks for an icon in wapt package
                icon_fn = os.path.join(icons_path,"%s.png"%entry.package)
                if not entry.section in ['group','host'] and (force_all or not os.path.isfile(icon_fn)):
                    try:
                        icon = extract_iconpng_from_wapt(fname)
                        open(icon_fn,'wb').write(icon)
                    except Exception as e:
                        logger.critical(r"Unable to extract icon for %s:%s"%(fname,e))

            except Exception,e:
                print e
                logger.critical("package %s: %s" % (fname,e))
                errors.append(fname)

        logger.info(u"Writing new %s" % packages_fname)
        myzipfile = zipfile.ZipFile(packages_fname, "w",compression=zipfile.ZIP_DEFLATED)
        try:
            zi = zipfile.ZipInfo(u"Packages",date_time = time.localtime())
            zi.compress_type = zipfile.ZIP_DEFLATED
            myzipfile.writestr(zi,u'\n'.join(packages_lines).encode('utf8'))
            logger.info(u"Finished")
        finally:
            myzipfile.close()
        return {'processed':processed,'kept':kept,'errors':errors,'packages_filename':packages_fname}


def update_packages(adir):
    """Update packages index

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
    >>> r.load_packages()
    >>> l1 = r.packages
    >>> p.save_control_to_wapt(os.path.join(repopath,p.make_package_filename()))
    >>> res = r.update_packages_index()
    >>> l2 = r.packages
    >>> [p for p in l2 if p not in l1]
    ["test (=10)"]
    """
    repo = WaptLocalRepo(localpath=adir)
    return repo.update_packages_index()

if __name__ == '__main__':
    import doctest
    import sys
    reload(sys)
    sys.setdefaultencoding("UTF-8")
    import doctest
    doctest.ELLIPSIS_MARKER = '???'
    doctest.testmod(optionflags=doctest.ELLIPSIS)
    sys.exit(0)
