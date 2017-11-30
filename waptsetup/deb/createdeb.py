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

import shutil
import subprocess
import argparse
import stat
import glob
import pefile

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

def git_hash():
    r = Repo('.',search_parent_directories = True)
    return '%04d_%s' % (r.active_branch.commit.count(),r.active_branch.object.name_rev[:8])

def dev_revision():
    return 'tisdeb%s-%s' % (debian_major(), git_hash())

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

parser = argparse.ArgumentParser(u'Build a Debian package with already compiled executables in root directory.')
parser.add_argument('-l', '--loglevel', help='Change log level (error, warning, info, debug...)')
parser.add_argument('-r', '--revision',default=dev_revision(), help='revision to append to package version')
options = parser.parse_args()

logger = logging.getLogger()
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
if options.loglevel is not None:
    setloglevel(logger,options.loglevel)

if platform.system() != 'Linux':
    logger.error("this script should be used on debian linux")
    sys.exit(1)

#########################################
BDIR = './builddir/'
WAPTSETUP = 'waptsetup-tis.exe'
WAPTDEPLOY = 'waptdeploy.exe'

#########################################
logger.debug('Getting version from executable')
pe = pefile.PE(WAPTSETUP)
version = pe.FileInfo[0].StringTable[0].entries['ProductVersion'].strip()
logger.debug('%s version: %s', WAPTSETUP, version)

if options.revision:
    full_version = version + '-' + options.revision
else:
    full_version = version

#########################################
logger.info('Creating .deb')
shutil.copytree('./debian/', BDIR + 'DEBIAN/')
os.chmod(BDIR + 'DEBIAN/', 0755)
os.chmod(BDIR + 'DEBIAN/postinst', 0755)

#########################################
# update Control version
control = open(BDIR + 'DEBIAN/control','r').read()
open(BDIR + 'DEBIAN/control','w').write(re.sub('Version: .*','Version: %s' % full_version,control))

# creates package file structure
mkdir(BDIR + 'var/www/wapt/')
shutil.copy(WAPTSETUP, BDIR + 'var/www/wapt/')
os.chmod(BDIR + 'var/www/wapt/' + WAPTSETUP, 0644)
shutil.copy(WAPTDEPLOY, BDIR + 'var/www/wapt/')
os.chmod(BDIR + 'var/www/wapt/' + WAPTDEPLOY, 0644)

# build
package_filename = 'tis-waptsetup-%s.deb' % (full_version)
eprint(subprocess.check_output(['dpkg-deb', '--build', BDIR, package_filename]))
print(package_filename)
