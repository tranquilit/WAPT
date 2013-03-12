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
_REGEX = re.compile(r'^(?P<major>[0-9]+)'
                    '\.(?P<minor>[0-9]+)'
                    '\.(?P<patch>[0-9]+)'
                    '(\-(?P<package>[0-9A-Za-z]+(\.[0-9A-Za-z]+)*))?$')

if 'cmp' not in __builtins__:
    cmp = lambda a,b: (a > b) - (a < b)


def parse_major_minor_patch_build(version):
    """
    Parse version to major, minor, patch, pre-release, build parts.
    """
    match = _REGEX.match(version)
    if match is None:
        raise ValueError('%s is not valid SemVer string' % version)

    verinfo = match.groupdict()

    verinfo['major'] = int(verinfo['major'])
    verinfo['minor'] = int(verinfo['minor'])
    verinfo['patch'] = int(verinfo['patch'])

    return verinfo


class Package_Entry:
    """Package attributes coming from either control files in WAPT package or local DB"""
    required_attributes = ['Package','Version','Architecture',]
    optional_attributes = ['Section','Priority','Maintainer','Description','Depends','Sources',]
    non_control_attributes = ['Filename','Size','repo_url','MD5sum',]
    all_attributes = required_attributes + optional_attributes + non_control_attributes
    def __init__(self):
        self.Package=''
        self.Version=''
        self.Architecture=''
        self.Section=''
        self.Priority=''
        self.Maintainer=''
        self.Description=''
        self.Depends=''
        self.Sources=''
        self.Filename=''
        self.Size=''
        self.MD5sum=''
        self.repo_url=''

    def parse_version(self):
        """
        Parse version to major, minor, patch, pre-release, build parts.
        """
        return parse_major_minor_patch_build(self.Version)

    def __cmp__(self,entry_or_version):
        def nat_cmp(a, b):
            a, b = a or '', b or ''
            convert = lambda text: text.isdigit() and int(text) or text.lower()
            alphanum_key = lambda key: [convert(c) for c in re.split('([0-9]+)', key)]
            return cmp(alphanum_key(a), alphanum_key(b))

        def compare_by_keys(d1, d2):
            for key in ['major', 'minor', 'patch']:
                v = cmp(d1.get(key), d2.get(key))
                if v:
                    return v
            # package version
            pv1, pv2 = d1.get('package'), d2.get('package')
            pvcmp = nat_cmp(pv1, pv2)
            if not pv1:
                return 1
            elif not pv2:
                return -1
            return pvcmp or 0
        try:
            if isinstance(entry_or_version,Package_Entry):
                result = cmp(self.Package,entry_or_version.Package)
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
            if isinstance(entry_or_version,Package_Entry):
                return cmp((self.Package,self.Version),(entry_or_version.Package,entry_or_version.Version))
            else:
                return cmp(self.Version,entry_or_version)


    def match(self, match_expr):
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
                param = param
                setattr(self,param,value)

        if not type(fname) is list and os.path.isfile(fname):
            self.MD5sum = md5_for_file(fname)
            self.Size = os.path.getsize(fname)
            self.Filename = os.path.basename(fname)
        else:
            self.Filename = self.make_package_filename()

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
            myzip.writestr('WAPT/control',self.ascontrol().encode('utf8'),compress_type=zipfile.ZIP_STORED)


    def ascontrol(self,with_non_control_attributes = False):
        val = u"""\
Package      : %(Package)s
Version      : %(Version)s
Architecture : %(Architecture)s
Section      : %(Section)s
Priority     : %(Priority)s
Maintainer   : %(Maintainer)s
Description  : %(Description)s
Depends      : %(Depends)s
Sources      : %(Sources)s
"""  % self.__dict__
        if with_non_control_attributes:
            for att in self.non_control_attributes:
                val += u"%-13s: %s\n" % (att, getattr(self,att))
        return val

    def make_package_filename(self):
        """Return the standard package filename based on current attributes"""
        if not (self.Package and self.Version and self.Architecture):
            raise Exception('Not enough information to build the package filename')
        return self.Package + '_' + self.Version + '_' +  self.Architecture  + '.wapt'

    def __str__(self):
        return self.ascontrol(with_non_control_attributes=True)

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
    package = Package_Entry()
    for line in previous_packages.splitlines():
        # new package
        if line.strip()=='':
            package.Filename = package.make_package_filename()
            old_entries[package.Filename] = package
            logger.debug("Package %s added" % package.Filename)
            package = Package_Entry()
        # add ettribute to current package
        else:
            splitline= line.split(':')
            name = splitline[0].strip()
            value = splitline[1].strip()
            setattr(package,name,value)

    # last one
    if package.Package:
        package.Filename = package.make_package_filename()
        old_entries[package.Filename] = package
        logger.debug("Package %s added" % package.Filename)

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
            entry = Package_Entry()
            entry.load_control_from_wapt(fname)
        packages.append(entry.ascontrol(with_non_control_attributes=True).encode('utf8'))

    logger.info("Writing new %s" % packages_fname)
    myzipfile = zipfile.ZipFile(packages_fname, "w")
    #myzipfile.writestr("Packages",'\n'.join(packages),compress_type=zipfile.ZIP_DEFLATED)
    myzipfile.writestr("Packages",'\n'.join(packages))
    myzipfile.close()
    logger.info("Finished")


if __name__ == '__main__':
    w = Package_Entry()
    w.Description = u'Package testé'
    w.Package = 'wapttest'
    w.Architecture = 'All'
    w.Version='0.1.0-10'
    w.Depends=''
    w.Maintainer = 'TIS'
    print w.ascontrol()
    assert w.match('>=0.1.0-2')
    assert w.match('>0.1.0-9')
    assert w.match('=0.1.0-10')
    assert w.match('<0.1.0')
    import tempfile
    wfn = tempfile.mktemp(suffix='.wapt')
    w.save_control_to_wapt(wfn)
    update_packages(os.path.dirname(wfn))
    w.load_control_from_wapt(wfn)
    print w.ascontrol(with_non_control_attributes=True)
    os.remove(wfn)
