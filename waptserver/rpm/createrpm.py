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
import os
import glob
import sys
import stat
import shutil
import fileinput
import subprocess
import platform
import errno

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def replaceAll(file, searchExp, replaceExp):
    for line in fileinput.input(file, inplace=1):
        if searchExp in line:
            line = line.replace(searchExp, replaceExp)
        sys.stdout.write(line)


def rsync(src, dst, excludes=[]):
    rsync_option = " --exclude 'postconf' --exclude 'mongodb' --exclude 'rpm' --exclude '*.pyc' --exclude '*.pyo' --exclude '.svn' --exclude 'apache-win32' --exclude 'deb' --exclude '.git' --exclude '.gitignore' -a --stats"
    if excludes:
        rsync_option = rsync_option + \
            ' '.join(" --exclude '%s'" % x for x in excludes)
    rsync_source = src
    rsync_destination = dst
    rsync_command = '/usr/bin/rsync %s "%s" "%s" 1>&2' % (
        rsync_option, rsync_source, rsync_destination)
    eprint(rsync_command)
    os.system(rsync_command)


makepath = os.path.join
from shutil import copyfile

# wapt
wapt_source_dir = os.path.abspath('../..')

# waptrepo
source_dir = os.path.abspath('..')

if platform.system() != 'Linux':
    eprint('this script should be used on debian linux')
    sys.exit(1)

if len(sys.argv) > 2:
    eprint('wrong number of parameters (0 or 1)')
    sys.exit(1)

new_umask = 022
old_umask = os.umask(new_umask)
if new_umask != old_umask:
    eprint('umask fixed (previous %03o, current %03o)' %
          (old_umask, new_umask))

for line in open('%s/waptserver.py' % source_dir):
    if line.strip().startswith('__version__'):
        wapt_version = line.split('=')[
            1].strip().replace('"', '').replace("'", '')

if not wapt_version:
    eprint(u'version not found in %s/waptserver.py' %
          os.path.abspath('..'))
    sys.exit(1)


def check_if_package_is_installed(package_name):
    # issue with yum module in buildbot, using dirty subprocess way...
    try:
        data = subprocess.check_output('rpm -q %s' % package_name, shell=True)
    except:
        return False
    if data.strip().startswith('%s-' % package_name):
        return True
    else:
        return False


if (not check_if_package_is_installed('python-virtualenv')
    or not check_if_package_is_installed('gcc')
    or not check_if_package_is_installed('openssl-devel')
    or not check_if_package_is_installed('libffi-devel')
    or not check_if_package_is_installed('openldap-devel')
    ):
    eprint("""
######################################################################################
     Please install build time packages first:
        yum install -y python-virtualenv gcc libffi-devel openssl-devel openldap-devel
######################################################################################
""")
    sys.exit(1)

eprint('creating the package tree')

if os.path.exists('builddir'):
    eprint('cleaning up builddir directory')
    shutil.rmtree('builddir')

mkdir_p('builddir/opt/wapt/lib')
mkdir_p('builddir/opt/wapt/conf')
mkdir_p('builddir/opt/wapt/log')
mkdir_p('builddir/opt/wapt/lib/site-packages')

# we use pip and virtualenv to get the wapt dependencies. virtualenv usage here is a bit awkward, it can probably be improved. For instance, it install a outdated version of pip that cannot install Rocket dependencies...
# for some reason the virtualenv does not build itself right if we don't
# have pip systemwide...
if os.path.exists('pylibs'):
    shutil.rmtree('pylibs')
eprint(
    'Create a build environment virtualenv. May need to download a few libraries, it may take some time')
subprocess.check_output(
    r'virtualenv ./pylibs --system-site-packages', shell=True)
eprint('Install additional libraries in build environment virtualenv')
eprint(subprocess.check_output(
    r'source ./pylibs/bin/activate ; pip install --upgrade pip -i https://pypi.python.org/simple/', shell=True))
eprint(subprocess.check_output(
    r'source ./pylibs/bin/activate ; pip install -r ../../requirements-server.txt -t ./builddir/opt/wapt/lib/site-packages -i https://pypi.python.org/simple/', shell=True))
rsync('./pylibs/lib/', './builddir/opt/wapt/lib/')
eprint('copying the waptserver files')
rsync(source_dir, './builddir/opt/wapt/',
      excludes=['postconf', 'mongod.exe', 'bin', 'include','spnego-http-auth-nginx-module'])

eprint('cryptography patches')
mkdir_p('./builddir/opt/wapt/lib/site-packages/cryptography/x509/')
copyfile(makepath(wapt_source_dir, 'utils', 'patch-cryptography', '__init__.py'),
         'builddir/opt/wapt/lib/site-packages/cryptography/x509/__init__.py')
copyfile(makepath(wapt_source_dir, 'utils', 'patch-cryptography', 'verification.py'),
         'builddir/opt/wapt/lib/site-packages/cryptography/x509/verification.py')


eprint('copying files formerly from waptrepo')
copyfile(makepath(wapt_source_dir, 'waptcrypto.py'),
         'builddir/opt/wapt/waptcrypto.py')
copyfile(makepath(wapt_source_dir, 'waptutils.py'),
         'builddir/opt/wapt/waptutils.py')
copyfile(makepath(wapt_source_dir, 'waptpackage.py'),
         'builddir/opt/wapt/waptpackage.py')
copyfile(makepath(wapt_source_dir, 'wapt-scanpackages.py'),
         'builddir/opt/wapt/wapt-scanpackages.py')
copyfile(makepath(wapt_source_dir, 'wapt-signpackages.py'),
         'builddir/opt/wapt/wapt-signpackages.py')
copyfile(makepath(wapt_source_dir, 'custom_zip.py'),
         'builddir/opt/wapt/custom_zip.py')


eprint('copying systemd startup script')
build_dest_dir = './builddir/usr/lib/systemd/system/'
try:
    mkdir_p(build_dest_dir)
    copyfile('../scripts/waptserver.service', os.path.join(build_dest_dir, 'waptserver.service'))
except Exception as e:
    eprint (sys.stderr, 'error: \n%s' % e)
    exit(1)

eprint ('copying logrotate script /etc/logrotate.d/waptserver')
try:
    mkdir_p('./builddir/etc/logrotate.d/')
    shutil.copyfile('../scripts/waptserver-logrotate',
                    './builddir/etc/logrotate.d/waptserver')
    subprocess.check_output(
        'chown root:root ./builddir/etc/logrotate.d/waptserver', shell=True)
except Exception as e:
    eprint ('error: \n%s' % e)
    exit(1)

eprint('copying logrotate script /etc/rsyslog.d/waptserver.conf')
try:
    mkdir_p('./builddir/etc/rsyslog.d/')
    shutil.copyfile('../scripts/waptserver-rsyslog',
                    './builddir/etc/rsyslog.d/waptserver.conf')
    subprocess.check_output(
        'chown root:root ./builddir/etc/rsyslog.d/waptserver.conf', shell=True)
except Exception as e:
    eprint('error: \n%s' % e)
    exit(1)

eprint('adding symlink for wapt-serverpostconf')
mkdir_p('builddir/usr/bin')
os.symlink('/opt/wapt/waptserver/scripts/postconf.py',
           'builddir/usr/bin/wapt-serverpostconf')

eprint('copying nginx-related goo')
try:
    ssl_dir = './builddir/opt/wapt/waptserver/ssl/'
    mkdir_p(ssl_dir)
    subprocess.check_output(['chmod', '0700', ssl_dir])
    mkdir_p('./builddir/etc/systemd/system/nginx.service.d')
    copyfile('../scripts/nginx_worker_files_limit.conf', './builddir/etc/systemd/system/nginx.service.d/nginx_worker_files_limit.conf')
except Exception as e:
    eprint('error: \n%s' % e)
    exit(1)
