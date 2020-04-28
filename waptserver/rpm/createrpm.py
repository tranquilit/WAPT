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
import types
import re

from git import Repo

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
        assert isinstance(version,types.ModuleType) or isinstance(version,str) or isinstance(version,unicode) or isinstance(version,Version)
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

for line in open('%s/config.py' % source_dir):
    if line.strip().startswith('__version__'):
        wapt_version = str(Version(line.split('=')[1].strip().replace('"', '').replace("'", ''),3))

if not wapt_version:
    eprint(u'version not found in %s/config.py' %
          os.path.abspath('..'))
    sys.exit(1)

r = Repo('.',search_parent_directories=True)
rev_count = '%04d' % (r.active_branch.commit.count(),)

wapt_version = wapt_version +'.'+rev_count

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


if (not (check_if_package_is_installed('python2-virtualenv') or (check_if_package_is_installed('python-virtualenv')))
    or not check_if_package_is_installed('gcc')
    or not check_if_package_is_installed('openssl-devel')
    or not check_if_package_is_installed('libffi-devel')
    or not check_if_package_is_installed('openldap-devel')
    or not (check_if_package_is_installed('python2-psycopg2') or (check_if_package_is_installed('python-psycopg2')))
    ):
    eprint("""
#########################################################################################################################
     Please install build time packages first:
        yum install -y python2-virtualenv gcc libffi-devel openssl-devel openldap-devel python2-pip postgresql-devel python2-psycopg2
#########################################################################################################################
""")
    sys.exit(1)

eprint('creating the package tree')

#if os.path.exists('builddir'):
#    eprint('cleaning up builddir directory')
#    shutil.rmtree('builddir')

mkdir_p('builddir/opt/wapt/lib')
mkdir_p('builddir/opt/wapt/conf')
mkdir_p('builddir/opt/wapt/log')
mkdir_p('builddir/opt/wapt/db')
mkdir_p('builddir/opt/wapt/lib/python2.7/site-packages')
mkdir_p('builddir/usr/bin')

WAPTEDITION=os.environ.get('WAPTEDITION','community')
if WAPTEDITION=='enterprise':
    mkdir_p('builddir/opt/wapt/waptenterprise')

# we use pip and virtualenv to get the wapt dependencies. virtualenv usage here is a bit awkward, it can probably be improved. For instance, it install a outdated version of pip that cannot install Rocket dependencies...
# for some reason the virtualenv does not build itself right if we don't
# have pip systemwide...
eprint(
    'Create a build environment virtualenv. May need to download a few libraries, it may take some time')

#run_verbose('pip install --upgrade pip')

run_verbose(r'python2 -m virtualenv ./builddir/opt/wapt/')
run_verbose(r'python2 -m virtualenv ./builddir/opt/wapt/ --always-copy')
eprint('Install additional libraries in build environment virtualenv')

#run_verbose(r'source ./builddir/opt/wapt/bin/activate ;curl https://bootstrap.pypa.io/ez_setup.py | python')
#run_verbose(r'source ./builddir/opt/wapt/bin/activate ;pip install pip setuptools --upgrade')

# fix for psycopg install because of ImportError: libpq-9c51d239.so.5.9: ELF load command address/offset not properly aligned
#run_verbose(r'source ./builddir/opt/wapt/bin/activate ;pip install --upgrade psycopg2')
run_verbose(r'./builddir/opt/wapt/bin/python -m pip install -r ../../requirements-server.txt')

eprint('copying the waptserver files')

# python dialog
copyfile(makepath(wapt_source_dir, 'lib', 'site-packages', 'dialog.py'),'builddir/opt/wapt/lib/python2.7/site-packages/dialog.py')

# psycopg2 from distribution RPM into virtualenv...
rsync('/usr/lib64/python2.7/site-packages/psycopg2','./builddir/opt/wapt/lib/python2.7/site-packages/')

rsync(source_dir, './builddir/opt/wapt/',excludes=['postconf', 'mongod.exe', 'include','spnego-http-auth-nginx-module','*.bat'])

eprint('cryptography patches')
mkdir_p('./builddir/opt/wapt/lib/python2.7/site-packages/cryptography/x509/')
copyfile(makepath(wapt_source_dir, 'utils', 'patch-cryptography', '__init__.py'),
         'builddir/opt/wapt/lib/python2.7/site-packages/cryptography/x509/__init__.py')
copyfile(makepath(wapt_source_dir, 'utils', 'patch-cryptography', 'verification.py'),
         'builddir/opt/wapt/lib/python2.7/site-packages/cryptography/x509/verification.py')

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

if WAPTEDITION=='enterprise':
    eprint('copying the waptserver enterprise files')
    rsync(wapt_source_dir+'/waptenterprise/', './builddir/opt/wapt/waptenterprise/',
          excludes=[' ','waptservice','postconf', 'repository', 'rpm', 'deb', 'spnego-http-auth-nginx-module', '*.bat'])

# cleanup
for fn in (
   "builddir/opt/wapt/include",
   "builddir/opt/wapt/pip-selfcheck.json",
   "builddir/opt/wapt/share"):
   try:
       shutil.rmtree(fn)
   except:
       os.unlink(fn)

copyfile(makepath(wapt_source_dir, 'runwaptserver.sh'),'./builddir/opt/wapt/runwaptserver.sh')
copyfile(makepath(wapt_source_dir, 'runwapttasks.sh'),'./builddir/opt/wapt/runwapttasks.sh')
copyfile(makepath(wapt_source_dir, 'wapt-scanpackages'),'./builddir/usr/bin/wapt-scanpackages')
copyfile(makepath(wapt_source_dir, 'wapt-signpackages'),'./builddir/usr/bin/wapt-signpackages')
copyfile(makepath(wapt_source_dir, 'waptpython'),'./builddir/usr/bin/waptpython')
os.chmod('./builddir/opt/wapt/runwaptserver.sh', 0o755)
os.chmod('./builddir/opt/wapt/runwapttasks.sh', 0o755)
os.chmod('./builddir/usr/bin/wapt-scanpackages', 0o755)
os.chmod('./builddir/usr/bin/wapt-signpackages', 0o755)
os.chmod('./builddir/usr/bin/waptpython', 0o755)

eprint('copying systemd startup script')
build_dest_dir = './builddir/usr/lib/systemd/system/'
try:
    mkdir_p(build_dest_dir)
    copyfile('../scripts/waptserver.service', os.path.join(build_dest_dir, 'waptserver.service'))
    copyfile('../scripts/wapttasks.service', os.path.join(build_dest_dir, 'wapttasks.service'))
except Exception as e:
    eprint (sys.stderr, 'error: \n%s' % e)
    exit(1)

eprint ('copying logrotate script /etc/logrotate.d/waptserver')
try:
    mkdir_p('./builddir/etc/logrotate.d/')
    shutil.copyfile('../scripts/waptserver-logrotate',
                    './builddir/etc/logrotate.d/waptserver')
except Exception as e:
    eprint ('error: \n%s' % e)
    exit(1)

eprint('copying logrotate script /etc/rsyslog.d/waptserver.conf')
try:
    mkdir_p('./builddir/etc/rsyslog.d/')
    shutil.copyfile('../scripts/waptserver-rsyslog',
                    './builddir/etc/rsyslog.d/waptserver.conf')
except Exception as e:
    eprint('error: \n%s' % e)
    exit(1)

eprint('adding symlink for wapt-serverpostconf')
mkdir_p('builddir/usr/bin')
os.symlink('/opt/wapt/waptserver/scripts/postconf.sh',
           'builddir/usr/bin/wapt-serverpostconf')

eprint('copying nginx-related goo')
try:
    ssl_dir = './builddir/opt/wapt/waptserver/ssl/'
    mkdir_p(ssl_dir)
    mkdir_p('./builddir/etc/systemd/system/nginx.service.d')
    copyfile('../scripts/nginx_worker_files_limit.conf', './builddir/etc/systemd/system/nginx.service.d/nginx_worker_files_limit.conf')
except Exception as e:
    eprint('error: \n%s' % e)
    exit(1)
