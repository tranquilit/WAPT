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
import os
import zipfile
import StringIO
import hashlib
import logging
import glob
import codecs
import re

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
                    '\.(?P<minor>[0-9]+)'
                    '(\.(?P<patch>[0-9]+))?'
                    '(\.(?P<subpatch>[0-9]+))?'
                    '(\-(?P<packaging>[0-9A-Za-z]+(\.[0-9A-Za-z]+)*))?$')

# tis-exodus (>2.3.4-10)
REGEX_PACKAGE_CONDITION = re.compile(r'(?P<package>[^\s()]+)\s*(\((?P<operator>[<=>]+)\s*(?P<version>\S+)\))?')

if 'cmp' not in __builtins__:
    cmp = lambda a,b: (a > b) - (a < b)

def parse_major_minor_patch_build(version):
    """
    Parse version to major, minor, patch, pre-release, build parts.
    """
    match = REGEX_PACKAGE_VERSION.match(version)
    if match is None:
        raise ValueError('%s is not valid SemVer string' % version)

    verinfo = match.groupdict()
    def int_or_none(name):
        if name in verinfo and verinfo[name] <> None :
            return int(verinfo[name])
        else:
            return None
    verinfo['major'] = int_or_none('major')
    verinfo['minor'] = int_or_none('minor')
    verinfo['patch'] = int_or_none('patch')
    verinfo['subpatch'] = int_or_none('subpatch')

    return verinfo


class PackageEntry(object):
    """Package attributes coming from either control files in WAPT package or local DB"""
    required_attributes = ['package','version','architecture',]
    optional_attributes = ['section','priority','maintainer','description','depends','sources',]
    non_control_attributes = ['filename','size','repo_url','md5sum',]

    @property
    def all_attributes(self):
        return self.required_attributes + self.optional_attributes + self.non_control_attributes + self.calculated_attributes

    def __init__(self):
        self.package=''
        self.version=''
        self.architecture=''
        self.section=''
        self.priority=''
        self.maintainer=''
        self.description=''
        self.depends=''
        self.sources=''
        self.filename=''
        self.size=''
        self.md5sum=''
        self.repo_url=''
        self.calculated_attributes=[]

    def parse_version(self):
        """
        Parse version to major, minor, patch, pre-release, build parts.
        """
        return parse_major_minor_patch_build(self.version)

    def __getitem__(self,name):
        name = name.lower()
        if hasattr(self,name):
            return getattr(self,name)
        else:
            raise Exception('No such attribute : %s' % name)

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
        if pcv['package'] <> self.package:
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
            raise ValueError("match_expr parameter should be in format <op><ver>, "
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

    def load_control_from_dict(self,adict):
        for k in adict:
            if hasattr(self,k):
                setattr(self,k,adict[k])

    def load_control_from_wapt(self,fname):
        """Load package attributes from the control file (utf8 encoded) included in WAPT zipfile fname
          fname can be
           - the path to WAPT file itelsef (zip file)
           - a list with the lines from control file
           - a path to the directory of wapt file unzipped content (debugging)
        """
        if type(fname) is list:
            control =  StringIO.StringIO(u'\n'.join(fname))
        elif os.path.isfile(fname):
            myzip = zipfile.ZipFile(fname,'r')
            control = StringIO.StringIO(myzip.open('WAPT/control').read().decode('utf8'))
        elif os.path.isdir(fname):
            control = codecs.open(os.path.join(fname,'WAPT','control'),'r',encoding='utf8')

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
                    raise Exception('Invalid line (no ":" found) : %s' % line)
                (param,value) = (line[:sc].strip(),line[sc+1:].strip())
                param = param.lower()
                setattr(self,param,value)

        if not type(fname) is list and os.path.isfile(fname):
            self.md5sum = md5_for_file(fname)
            self.size = os.path.getsize(fname)
            self.filename = os.path.basename(fname)
        else:
            self.filename = self.make_package_filename()

        return self

    def save_control_to_wapt(self,fname):
        """Load package attributes from the control file (utf8 encoded) included in WAPT zipfile fname
          fname can be
           - the path to WAPT file itelsef (zip file)
           - a path to the directory of wapt file unzipped content (debugging)
        """
        if os.path.isdir(fname):
            codecs.open(os.path.join(fname,'WAPT','control'),'w',encoding='utf8').write(self.ascontrol())
        else:
            if os.path.isfile(fname):
                myzip = zipfile.ZipFile(fname,'a')
            else:
                myzip = zipfile.ZipFile(fname,'w')
            try:
                myzip.writestr('WAPT/control',self.ascontrol().encode('utf8'),compress_type=zipfile.ZIP_STORED)
            except:
                myzip.writestr('WAPT/control',self.ascontrol().encode('utf8'))

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
sources      : %(sources)s
"""  % self.__dict__
        if with_non_control_attributes:
            for att in self.non_control_attributes:
                val += u"%-13s: %s\n" % (att, getattr(self,att))
        return val

    def make_package_filename(self):
        """Return the standard package filename based on current attributes"""
        if not (self.package and self.version and self.architecture):
            raise Exception('Not enough information to build the package filename')
        return self.package + '_' + self.version + '_' +  self.architecture  + '.wapt'

    def __str__(self):
        return self.ascontrol(with_non_control_attributes=True)

    def __repr__(self):
        return "%s (%s):%s" % (self.package,self.version,self.architecture)
        #return self.ascontrol(with_non_control_attributes=True).encode('utf8')


def update_packages(adir):
    """Scan adir directory for WAPT packages and build a Packages (utf8) zip file with control data and MD5 hash"""
    packages_fname = os.path.join(adir,'Packages')
    previous_packages=''
    previous_packages_mtime = 0
    if os.path.exists(packages_fname):
        try:
            logger.info("Reading old Packages %s" % packages_fname)
            previous_packages = codecs.decode(zipfile.ZipFile(packages_fname).read(name='Packages'),'utf-8')
            previous_packages_mtime = os.path.getmtime(packages_fname)
        except Exception,e:
            logger.warning('error reading old Packages file. Reset... (%s)' % e)

    old_entries = {}
    # we get old list to not recompute MD5 if filename has not changed
    logger.debug("parsing old entries...")

    # last line
    def add_package(lines):
        package = PackageEntry()
        package.load_control_from_wapt(lines)
        package.filename = package.make_package_filename()
        old_entries[package.filename] = package
        logger.debug("Package %s added" % package.filename)

    try:
        lines = []
        for line in previous_packages.splitlines():
            # new package
            if line.strip()=='':
                add_package(lines)
                lines = []
            # add ettribute to current package
            else:
                lines.append(line)
        # last
        if lines:
            add_package(lines)
            lines = []
    except Exception,e:
        logger.critical('Unable to read old entries... : %s' % e)
        old_entries = {}

    if not os.path.isdir(adir):
        raise Exception('%s is not a directory' % (adir))

    waptlist = glob.glob(os.path.join(adir,'*.wapt'))
    packages = []
    for fname in waptlist:
        if os.path.basename(fname) in old_entries:
            logger.info("  Keeping %s" % fname)
            entry = old_entries[os.path.basename(fname)]
        else:
            logger.info("  Processing %s" % fname)
            entry = PackageEntry()
            entry.load_control_from_wapt(fname)
        packages.append(entry.ascontrol(with_non_control_attributes=True).encode('utf8'))

    logger.info("Writing new %s" % packages_fname)
    myzipfile = zipfile.ZipFile(packages_fname, "w")
    try:
        myzipfile.writestr("Packages",'\n'.join(packages),compress_type=zipfile.ZIP_DEFLATED)
    except:
        myzipfile.writestr("Packages",'\n'.join(packages))
    myzipfile.close()
    logger.info("Finished")


if __name__ == '__main__':
    w = PackageEntry()
    w.load_control_from_wapt(r'C:\shapers\openproj-wapt')

    w2=PackageEntry()
    w2.load_control_from_wapt(r'c:\shapers\openproj_1.4.0-00_all.wapt')

    assert w>w2

    w.description = u'Package testé'
    w.package = 'wapttest'
    w.architecture = 'All'
    w.version='0.1.0-10'
    w.depends=''
    w.maintainer = 'TIS'
    print w.ascontrol()
    w['install_date'] = '20120501'
    for a in w.all_attributes:
        print "%s: %s" % (a,w[a])
    assert w['install_date'] == '20120501'
    w.install_date == '20120501'
    w.install_date == '20120501'

    assert w.match('wapttest (>= 0.1.0-2)')
    assert w.match('wapttest (>0.1.0-9)')
    assert w.match('wapttest (>0.0.1-10)')
    assert w.match('wapttest(=%s)' % w.version)
    assert w.match('wapttest(<= 0.1.0)')
    assert w.match('wapttest (=0.1.0)')
    assert w.match('wapttest')
    import tempfile
    wfn = tempfile.mktemp(suffix='.wapt')
    w.save_control_to_wapt(wfn)
    update_packages(os.path.dirname(wfn))
    w.load_control_from_wapt(wfn)
    print w.ascontrol(with_non_control_attributes=True)
    os.remove(wfn)
