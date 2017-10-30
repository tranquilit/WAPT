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

from git import Repo

makepath = os.path.join
from shutil import copyfile

def run(*args, **kwargs):
    return subprocess.check_output(*args, shell=True, **kwargs)

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def mkdir_p(path):
    if not os.path.isdir(path):
        os.makedirs(path)

def debian_major():
    return platform.linux_distribution()[1].split('.')[0]

def git_hash():
    r = Repo('.',search_parent_directories = True)
    return r.active_branch.object.name_rev[:8]

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
    mkdir_p(os.path.dirname(relative_link_target_path))

    if not os.path.exists(relative_link_target_path):
        cmd = 'ln -s %s %s ' % (relative_link_target_path,link_name)
        eprint(cmd)
        eprint(subprocess.check_output(cmd))

parser = argparse.ArgumentParser(u'Build a waptrepo Debian package.')
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


###################################
# wapt
wapt_source_dir = os.path.abspath('../..')

# waptrepo
source_dir = os.path.abspath('..')

wapt_version = None
for line in file('../../waptpackage.py', 'r').readlines():
    if line.strip().startswith('__version__'):
        wapt_version = line.split('=')[1].strip().replace('"','').replace("'","")

if wapt_version is None:
    eprint('version "%s" incorrecte/non trouvee dans waptpackage.py' % str(wapt_version))
    sys.exit(1)

if options.revision:
    full_version = wapt_version + '-' + options.revision
else:
    full_version = wapt_version

######################"

new_umask = 022
old_umask = os.umask(new_umask)
if new_umask != old_umask:
    eprint('umask fixed (previous %03o, current %03o)' % (old_umask, new_umask))

# remove old debs
for filename in glob.glob("tis-waptrepo*.deb"):
    eprint("destruction de %s" % filename)
    os.remove(filename)
if os.path.exists("builddir"):
    shutil.rmtree("builddir")

eprint(u'creation de l\'arborescence')
os.makedirs("builddir")
os.makedirs("builddir/DEBIAN")
os.makedirs("builddir/opt")
os.makedirs("builddir/opt/wapt")
os.makedirs("builddir/opt/wapt/waptrepo/")
os.makedirs("builddir/opt/wapt/lib")
os.makedirs("builddir/opt/wapt/lib/site-packages")

# for some reason the virtualenv does not build itself right if we don't
# have pip systemwide...
eprint(run('sudo apt-get install -y python-virtualenv python-setuptools python-pip python-dev libpq-dev libffi-dev'))

eprint('Create a build environment virtualenv. May need to download a few libraries, it may take some time')
eprint(run(r'virtualenv ./builddir/opt/wapt --system-site-packages'))

eprint('Install additional libraries in build environment virtualenv')
eprint(run(r'./builddir/opt/wapt/bin/pip install setuptools --upgrade -i https://pypi.python.org/simple/'))

run(r'./builddir/opt/wapt/bin/pip install -r ../../requirements-repo.txt -t ./builddir/opt/wapt/lib/site-packages -i https://pypi.python.org/simple/')

open(os.path.join('./builddir/opt/wapt/waptrepo','VERSION'),'w').write(full_version)

eprint('copie des fichiers waptrepo')
copyfile(makepath(wapt_source_dir,'waptcrypto.py'),
         './builddir/opt/wapt/waptcrypto.py')
copyfile(makepath(wapt_source_dir,'waptutils.py'),
         './builddir/opt/wapt/waptutils.py')
copyfile(makepath(wapt_source_dir,'custom_zip.py'),
         './builddir/opt/wapt/custom_zip.py')
copyfile(makepath(wapt_source_dir,'waptpackage.py'),
         './builddir/opt/wapt/waptpackage.py')
copyfile(makepath(wapt_source_dir,'wapt-scanpackages.py'),
         './builddir/opt/wapt/wapt-scanpackages.py')
copyfile(makepath(wapt_source_dir,'wapt-signpackages.py'),
         './builddir/opt/wapt/wapt-signpackages.py')

eprint('cryptography patches')
copyfile(makepath(wapt_source_dir,'utils','patch-cryptography','__init__.py'),
         './builddir/opt/wapt/lib/site-packages/cryptography/x509/__init__.py')
copyfile(makepath(wapt_source_dir,'utils','patch-cryptography','verification.py'),
         './builddir/opt/wapt/lib/site-packages/cryptography/x509/verification.py')

add_symlink('./opt/wapt/wapt-signpackages.py','./usr/bin/wapt-signpackages')
add_symlink('./opt/wapt/wapt-scanpackages.py','./usr/bin/wapt-scanpackages')

os.chmod('./builddir/opt/wapt/wapt-scanpackages.py',0o755)
os.chmod('./builddir/opt/wapt/wapt-signpackages.py',0o755)

eprint('copie des fichiers control et postinst')
copyfile('./DEBIAN/control','./builddir/DEBIAN/control')
copyfile('./DEBIAN/postinst','./builddir/DEBIAN/postinst')

control_file = './builddir/DEBIAN/control'
eprint(u'inscription de la version dans le fichier de control. new version: ' + full_version)

# update Control version
control = open(control_file,'r').read()
open(control_file,'w').write(re.sub('Version: .*','Version: %s' % full_version,control))

eprint(u'creation du paquet Deb')
os.chmod('./builddir/DEBIAN/postinst',
         stat.S_IRWXU
         | stat.S_IXGRP | stat.S_IRGRP
         | stat.S_IROTH | stat.S_IXOTH
         )

# build
package_filename = 'tis-waptrepo-{}.deb'.format(full_version)
eprint(subprocess.check_output(['dpkg-deb','--build','builddir',package_filename]))
shutil.rmtree("builddir")
print(package_filename)
