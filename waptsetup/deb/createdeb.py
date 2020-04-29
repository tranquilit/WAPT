#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013-2014  Tranquil IT Systems http://www.tranquil.it
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
from __future__ import print_function
import sys
import os
import platform
import logging
import re
import types

import shutil
import subprocess
import argparse
import stat
import glob
import jinja2

from git import Repo

makepath = os.path.join
from shutil import copyfile

def run(*args, **kwargs):
    return subprocess.check_output(*args, shell=True, **kwargs)

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def mkdir(path):
    if not os.path.isdir(path):
        os.makedirs(path)

def debian_major():
    return platform.linux_distribution()[1].split('.')[0]

def get_distrib():
    return platform.linux_distribution()[0].lower()

def git_hash():
    r = Repo('.',search_parent_directories=True)
    return '%s' % (r.active_branch.object.name_rev[:8],)

def dev_revision():
    return '%s' % (git_hash())

def setloglevel(alogger,loglevel):
    """set loglevel as string"""
    if loglevel in ('debug','warning','info','error','critical'):
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % loglevel)
        alogger.setLevel(numeric_level)

def rsync(src, dst, excludes=[]):
    excludes_list = ['*.pyc','*~','.svn','deb','.git','.gitignore']
    excludes_list.extend(excludes)

    rsync_source = src
    rsync_destination = dst
    rsync_options = ['-a','--stats']
    for x in excludes_list:
        rsync_options.extend(['--exclude',x])

    rsync_command = ['/usr/bin/rsync'] + rsync_options + [rsync_source,rsync_destination]
    eprint(rsync_command)
    return subprocess.check_output(rsync_command)

def add_symlink(link_target,link_name):
    if link_target.startswith('/'):
        link_target = link_target[1:]
    relative_link_target_path = os.path.join('builddir',link_target)
    eprint("adding symlink %s -> %s" % (link_name, relative_link_target_path ))
    mkdir(os.path.dirname(relative_link_target_path))

    if not os.path.exists(relative_link_target_path):
        cmd = 'ln -s %s %s ' % (relative_link_target_path,link_name)
        eprint(cmd)
        eprint(subprocess.check_output(cmd))

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

current_path = os.path.realpath(__file__)
wapt_source_dir = os.path.abspath(os.path.join(os.path.dirname(current_path),'../..'))

parser = argparse.ArgumentParser(u'Build a Debian package with already compiled executables in root directory.')
parser.add_argument('-l', '--loglevel', help='Change log level (error, warning, info, debug...)')
parser.add_argument('-r', '--revision',default=dev_revision(), help='revision to append to package version')
options = parser.parse_args()

logger = logging.getLogger()
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
if options.loglevel is not None:
    setloglevel(logger,options.loglevel)

if platform.system() != 'Linux':
    logger.error("This script should be used on Debian Linux")
    sys.exit(1)

SETUP_UNIX=os.environ.get('SETUP_UNIX','FALSE')

#########################################
BDIR = './builddir/'
if SETUP_UNIX=='TRUE':
    dict_agent = {
    'WAPTAGENT_RPM':'waptagent.rpm',
    'WAPTAGENT_PKG':'waptagent.pkg',
    'WAPTAGENT_DEB8':'waptagent_debian8.deb',
    'WAPTAGENT_DEB9':'waptagent_debian9.deb',
    'WAPTAGENT_DEB10':'waptagent_debian10.deb',
    'WAPTAGENT_UB18':'waptagent_ubuntu18.deb',
    'WAPTAGENT_UB20':'waptagent_ubuntu20.deb',
    }
else:
    dict_agent = {
    'WAPTSETUP':'waptsetup-tis.exe',
    'WAPTDEPLOY':'waptdeploy.exe',
    }

WAPTEDITION=os.environ.get('WAPTEDITION','community')

#########################################
logger.debug('Getting version from waptutils')
for line in open(os.path.join(wapt_source_dir,"waptutils.py")):
    if line.strip().startswith('__version__'):
        wapt_version = str(Version(line.split('=')[1].strip().replace('"', '').replace("'", ''),3))

if not wapt_version:
    eprint(u'version not found in %s/config.py' % os.path.abspath('..'))
    sys.exit(1)

r = Repo('.',search_parent_directories=True)
rev_count = '%04d' % (r.active_branch.commit.count(),)

wapt_version = wapt_version +'.'+rev_count

if options.revision:
    full_version = wapt_version + '-' + options.revision
else:
    full_version = wapt_version

logger.info('Create templates for control and postinst')

jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader('./debian/'))
template_control = jinja_env.get_template('control.tmpl')
template_postinst = jinja_env.get_template('postinst.tmpl')
template_vars = {
    'UNIX': SETUP_UNIX,
    'version': wapt_version,
    'list_agents': [os.path.join('/var/www/wapt/',dict_agent[akey]) for akey in dict_agent.keys()],
    'description': 'WAPT setup executable for Windows\n' if SETUP_UNIX=='TRUE' else 'WAPT agent packages for Linux/MacOS\n',
}
render_control = template_control.render(template_vars)
render_postinst = template_postinst.render(template_vars)

if os.path.exists(BDIR):
    shutil.rmtree(BDIR)
os.makedirs(os.path.join(BDIR,'DEBIAN'))

with open(os.path.join(BDIR,'DEBIAN','control'),'w') as f_control:
    f_control.write(render_control)

with open(os.path.join(BDIR,'DEBIAN','postinst'),'w') as f_postinst:
    f_postinst.write(render_postinst)

os.chmod(os.path.join(BDIR,'DEBIAN/'), 0755)
os.chmod(os.path.join(BDIR,'DEBIAN','postinst'), 0755)

# creates package file structure
mkdir(BDIR + 'var/www/wapt/')
www_path = os.path.join(BDIR,'var/www/wapt/')
for afile in dict_agent.keys():
    os.chmod(dict_agent[afile],0644)
    shutil.copy(dict_agent[afile],www_path)

# build
if WAPTEDITION=='enterprise':
    package_filename = 'tis-waptsetup-%senterprise-%s.deb' % ('linux_mac-' if SETUP_UNIX=='TRUE' else 'windows-',full_version)
else:
    package_filename = 'tis-waptsetup-%s%s.deb' % ('linux_mac-' if SETUP_UNIX=='TRUE' else 'windows-',full_version)
eprint(subprocess.check_output(['dpkg-deb', '--build', BDIR, package_filename]))
print(package_filename)
