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
import fileinput
import glob
import os
import shutil
import stat
import subprocess
import sys
import platform

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def replaceAll(file,searchExp,replaceExp):
    for line in fileinput.input(file, inplace=1):
        if searchExp in line:
            line = line.replace(searchExp,replaceExp)
        sys.stdout.write(line)

def rsync(src,dst):
    rsync_option = ' '.join([
        "--exclude '.svn'",
        "--exclude 'deb'",
        "--exclude 'rpm'",
        "--exclude '.git'",
        "--exclude '.gitignore'",
        "-aP",
    ])
    rsync_source = src
    rsync_destination = dst
    rsync_command = '/usr/bin/rsync %s "%s" "%s" 1>&2' % (
        rsync_option,rsync_source,rsync_destination)
    os.system(rsync_command)

if os.name!='posix':
    eprint("script has to be run on CentOS")
    sys.exit(1)

makepath = os.path.join
from shutil import copyfile

# wapt
wapt_source_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

# waptrepo
source_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
eprint('Source dir: ',wapt_source_dir)
sys.path.insert(0, wapt_source_dir)

def get_wapt_version():
    """get wapt version from waptpackage file without importing it (otherwinse
       we get import error on build farm due to M2Crypto
       it would be better to reimplement this using an AST
       """
    with open('%s/waptutils.py' % wapt_source_dir,'r') as file_source :
        for line in file_source.readlines():
            if line.strip().startswith('__version__'):
                version =  line.split('=')[1].strip()
                break
    # we should check the version number is well formated
    return version

wapt_version = get_wapt_version()

if not wapt_version:
    eprint('version "%s" incorrecte dans waptpackage.py' % (wapt_version,))
    sys.exit(1)

new_umask = 022
old_umask = os.umask(new_umask)
if new_umask != old_umask:
    print >> sys.stderr, 'umask fixed (previous %03o, current %03o)' % (old_umask, new_umask)

if os.path.exists('BUILDROOT'):
    shutil.rmtree('BUILDROOT')

eprint(u'creation de l\'arborescence')
os.makedirs("BUILDROOT")
os.makedirs("BUILDROOT/opt")
os.makedirs("BUILDROOT/opt/wapt")
os.makedirs("BUILDROOT/opt/wapt/waptrepo/")

version_file = open(os.path.join('BUILDROOT/opt/wapt/waptrepo','VERSION'),'w')
version_file.write(wapt_version)
version_file.close()

os.makedirs("BUILDROOT/opt/wapt/lib/site-packages")

# we use pip and virtualenv to get the wapt dependencies. virtualenv usage here is a bit awkward, it can probably be improved. For instance, it install a outdated version of pip that cannot install Rocket dependencies...
# for some reason the virtualenv does not build itself right if we don't
# have pip systemwide...

if os.path.exists("pylibs"):
    shutil.rmtree("pylibs")
eprint(
    'Create a build environment virtualenv. May need to download a few libraries, it may take some time')
subprocess.check_output(
    r'virtualenv ./pylibs --system-site-packages', shell=True)
eprint('Install additional libraries in build environment virtualenv')
eprint(subprocess.check_output(
    r'source ./pylibs/bin/activate ; pip install --upgrade pip', shell=True))
eprint(subprocess.check_output(
    r'source ./pylibs/bin/activate ; pip install -r ../../requirements-repo.txt -t ./BUILDROOT/opt/wapt/lib/site-packages', shell=True))
rsync('./pylibs/lib/', './BUILDROOT/opt/wapt/lib/')

eprint('copie des fichiers waptrepo')
rsync(source_dir,'BUILDROOT/opt/wapt/')
copyfile(makepath(wapt_source_dir,'waptcrypto.py'),
         'BUILDROOT/opt/wapt/waptcrypto.py')
copyfile(makepath(wapt_source_dir,'waptutils.py'),
         'BUILDROOT/opt/wapt/waptutils.py')
copyfile(makepath(wapt_source_dir,'waptpackage.py'),
         'BUILDROOT/opt/wapt/waptpackage.py')
copyfile(makepath(wapt_source_dir,'wapt-scanpackages.py'),
         'BUILDROOT/opt/wapt/wapt-scanpackages.py')
copyfile(makepath(wapt_source_dir,'wapt-signpackages.py'),
         'BUILDROOT/opt/wapt/wapt-signpackages.py')
copyfile(makepath(wapt_source_dir,'custom_zip.py'),
         'BUILDROOT/opt/wapt/custom_zip.py')

print('cryptography patches')
copyfile(makepath(wapt_source_dir,'utils','patch-cryptography','__init__.py'),
         'BUILDROOT/opt/wapt/lib/site-packages/cryptography/x509/__init__.py')
copyfile(makepath(wapt_source_dir,'utils','patch-cryptography','verification.py'),
         'BUILDROOT/opt/wapt/lib/site-packages/cryptography/x509/verification.py')

if platform.dist()[0] in ('debian','ubuntu'):
    os.makedirs('BUILDROOT/var/www/wapt')
    os.makedirs('BUILDROOT/var/www/waptwua')
    os.makedirs('BUILDROOT/var/www/waptdev')
    os.makedirs('BUILDROOT/var/www/wapt-host')
    os.makedirs('BUILDROOT/var/www/wapt-group')
elif platform.dist()[0] in ('centos','redhat','ubuntu'):
    os.makedirs('BUILDROOT/var/www/html/wapt')
    os.makedirs('BUILDROOT/var/www/html/waptwua')
    os.makedirs('BUILDROOT/var/www/html/waptdev')
    os.makedirs('BUILDROOT/var/www/html/wapt-host')
    os.makedirs('BUILDROOT/var/www/html/wapt-group')
else:
    eprint("distrib not supported")
    sys.exit(1)
