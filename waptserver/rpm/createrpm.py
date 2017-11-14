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

def run(*args, **kwargs):
    return subprocess.check_output(*args, shell=True, **kwargs)

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def run_verbose(*args, **kwargs):
    output =  subprocess.check_output(*args, shell=True, **kwargs)
    eprint(output)
    return output

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
        data = run('rpm -q %s' % package_name)
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
run_verbose(r'virtualenv ./pylibs')
eprint('Install additional libraries in build environment virtualenv')
run_verbose(r'source ./pylibs/bin/activate ;curl https://bootstrap.pypa.io/ez_setup.py | python')
run_verbose(r'source ./pylibs/bin/activate ;pip install pip setuptools --upgrade')


eprint('Temporay fix : download, patch and install Rocket outside of requirement-server.txt because of bug https://github.com/explorigin/Rocket/commit/fb8bd8f1b979faef8733853065536fc7db111612')
# temporary fix for Rocket package : current pip package has a hardcoded http (non ssl) url to pipy. Pipy does not accept this kind of url anymore. Rocket package is patched upstream on Github, but not yet pushed to pipy
run_verbose('rm -Rf ./Rocket-1.2.4/')
run_verbose('wget https://pypi.python.org/packages/72/5a/efc43e5d8a7ef27205a4c7c4978ebaa812418e2151e7edb26ff3143b29eb/Rocket-1.2.4.zip#md5=fa611955154b486bb91e632a43e90f4b -O Rocket-1.2.4.zip')
# should check md5 hash
run_verbose("unzip Rocket-1.2.4.zip")
run_verbose("sed -i 's#http://pypi.python.org/packages/source/d/distribute/#https://pypi.python.org/packages/source/d/distribute/#' Rocket-1.2.4/distribute_setup.py")
run_verbose("pip install -t ./builddir/opt/wapt/lib/site-packages Rocket-1.2.4/")

# fix for psycopg install because of ImportError: libpq-9c51d239.so.5.9: ELF load command address/offset not properly aligned
#run_verbose(r'yum install postgresql.x86_64 postgresql-devel.x86_64 -y')
run_verbose(r'pip install -t ./builddir/opt/wapt/lib/site-packages psycopg2==2.7.3.2 --no-binary :all: ')

run_verbose(r'source ./pylibs/bin/activate ; pip install -r ../../requirements-server.txt -t ./builddir/opt/wapt/lib/site-packages')

rsync('./pylibs/lib/', './builddir/opt/wapt/lib/')

eprint('copying the waptserver files')

rsync(source_dir, './builddir/opt/wapt/',excludes=['postconf', 'mongod.exe', 'bin', 'include','spnego-http-auth-nginx-module'])

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
    run('chown root:root ./builddir/etc/logrotate.d/waptserver')
except Exception as e:
    eprint ('error: \n%s' % e)
    exit(1)

eprint('copying logrotate script /etc/rsyslog.d/waptserver.conf')
try:
    mkdir_p('./builddir/etc/rsyslog.d/')
    shutil.copyfile('../scripts/waptserver-rsyslog',
                    './builddir/etc/rsyslog.d/waptserver.conf')
    run('chown root:root ./builddir/etc/rsyslog.d/waptserver.conf')
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
    run('chmod 0700 "%s"' % ssl_dir)
    mkdir_p('./builddir/etc/systemd/system/nginx.service.d')
    copyfile('../scripts/nginx_worker_files_limit.conf', './builddir/etc/systemd/system/nginx.service.d/nginx_worker_files_limit.conf')
except Exception as e:
    eprint('error: \n%s' % e)
    exit(1)
