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
from __future__ import absolute_import
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
import types

makepath = os.path.join
from shutil import copyfile

def run(*args, **kwargs):
    return subprocess.check_output(*args, shell=True, **kwargs)

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

eprint(run('sudo pip install gitpython'))
from git import Repo

def run_verbose(*args, **kwargs):
    output =  subprocess.check_output(*args, shell=True, **kwargs)
    eprint(output)
    return output

def mkdir_p(path):
    if not os.path.isdir(path):
        os.makedirs(path)

def debian_major():
    return platform.linux_distribution()[1].split('.')[0]

def git_hash():
    r = Repo('.',search_parent_directories=True)
    return '%s' % (r.active_branch.object.name_rev[:8],)

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

parser = argparse.ArgumentParser(u'Build a WaptAgent RPM package.')
parser.add_argument('-l', '--loglevel', help='Change log level (error, warning, info, debug...)')
parser.add_argument('-r', '--revision',default=dev_revision(), help='revision to append to package version')
options = parser.parse_args()

logger = logging.getLogger()
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
if options.loglevel is not None:
    setloglevel(logger,options.loglevel)

if platform.system() != 'Linux':
    logger.error("this script should be used on Debian or CentOS")
    sys.exit(1)

revision = options.revision

####################""
# wapt
wapt_source_dir = os.path.abspath('../..')

# waptrepo
source_dir = os.path.abspath('..')

new_umask = 0o22
old_umask = os.umask(new_umask)
if new_umask != old_umask:
    eprint('umask fixed (previous %03o, current %03o)' % (old_umask, new_umask))

for line in open('%s/../waptutils.py' % source_dir):
    if line.strip().startswith('__version__'):
        wapt_version = str(Version(line.split('=')[1].strip().replace('"', '').replace("'", ''),3))

if not wapt_version:
    eprint(u'version not found in %s/config.py' % os.path.abspath('..'))
    sys.exit(1)

r = Repo('.',search_parent_directories=True)
rev_count = '%04d' % (r.active_branch.commit.count(),)

wapt_version = wapt_version +'.'+rev_count

with open(os.path.join(wapt_source_dir,'version-full'),'w') as file_version:
    file_version.write(wapt_version)

if options.revision:
    full_version = wapt_version + '-' + options.revision
else:
    full_version = wapt_version

for filename in glob.glob('tis-waptagent*.deb'):
    eprint('Removing %s' % filename)
    os.remove(filename)

if os.path.exists('builddir'):
    shutil.rmtree('builddir')

eprint('creating the package tree')
mkdir_p('builddir/opt/wapt/conf')
mkdir_p('builddir/opt/wapt/lib')
mkdir_p('builddir/opt/wapt/log')
mkdir_p('builddir/opt/wapt/db')
mkdir_p('builddir/opt/wapt/lib/python2.7/site-packages')
mkdir_p('builddir/usr/bin')
mkdir_p('builddir/opt/wapt/templates')

WAPTEDITION=os.environ.get('WAPTEDITION','community')
if WAPTEDITION=='enterprise':
    mkdir_p('builddir/opt/wapt/waptenterprise')

# for some reason the virtualenv does not build itself right if we don't
# have pip systemwide...

##check linux distrib
if platform.linux_distribution()[0].startswith('CentOS'):
    eprint(run('sudo yum install -y python-virtualenv python-setuptools gcc python-pip python-devel postgresql-devel libffi-devel openldap-devel openssl-devel python-psycopg2 yum-utils'))
    eprint('Create a build environment virtualenv. May need to download a few libraries, it may take some time')
    run_verbose('pip install --upgrade pip')
    run_verbose('pip install distribute')
    run_verbose(r'virtualenv ./builddir/opt/wapt/')
    run_verbose(r'virtualenv ./builddir/opt/wapt/ --always-copy')
    eprint('Install additional libraries in build environment virtualenv')
    run_verbose(r'source ./builddir/opt/wapt/bin/activate; pip install -r ../../requirements.txt -r ../../requirements-linux.txt')
    
    run('cp -ruf /usr/lib/python2.7/site-packages/yum* ./builddir/opt/wapt/lib/python2.7/site-packages/')
    run('cp -ruf /usr/lib64/python2.7/site-packages/yum* ./builddir/opt/wapt/lib64/python2.7/site-packages/')
    run('cp -ruf /usr/lib/python2.7/site-packages/rpm* ./builddir/opt/wapt/lib/python2.7/site-packages/')
    run('cp -ruf /usr/lib64/python2.7/site-packages/rpm* ./builddir/opt/wapt/lib64/python2.7/site-packages/')
    run('cp -ruf /usr/lib/python2.7/site-packages/urlgrabber* ./builddir/opt/wapt/lib/python2.7/site-packages/')
    run('cp -ruf /usr/lib64/python2.7/site-packages/pycurl* ./builddir/opt/wapt/lib64/python2.7/site-packages/')
    run('cp -ruf /usr/lib64/python2.7/site-packages/sqlitecachec* ./builddir/opt/wapt/lib64/python2.7/site-packages/')
    run('cp -ruf /usr/lib64/python2.7/site-packages/_sqlitecache* ./builddir/opt/wapt/lib/python2.7/site-packages/')
    

    # python dialog
    copyfile(makepath(wapt_source_dir, 'lib', 'site-packages', 'dialog.py'),'builddir/opt/wapt/lib/python2.7/site-packages/dialog.py')

    # psycopg2 from distribution RPM into virtualenv...
    rsync('/usr/lib64/python2.7/site-packages/psycopg2','./builddir/opt/wapt/lib/python2.7/site-packages/')
else:
    eprint('Wrong linux distribution script only for CentOs, yours : \n')
    eprint(platform.linux_distribution())
    sys.exit(1)

eprint('copying the waptservice files')
files_to_copy = ['version-full','waptcrypto.py','waptutils.py','common.py','custom_zip.py','waptpackage.py','setuphelpers.py','setuphelpers_linux.py','setuphelpers_windows.py','setuphelpers_unix.py','setuphelpers_macos.py','wapt-get.py']
for afile in files_to_copy:
    copyfile(makepath(wapt_source_dir, afile),os.path.join('./builddir/opt/wapt/',afile))

# a voir si c'est encore necessaire
eprint('cryptography patches')
copyfile(makepath(wapt_source_dir, 'utils', 'patch-cryptography', '__init__.py'),'./builddir/opt/wapt/lib/python2.7/site-packages/cryptography/x509/__init__.py')
copyfile(makepath(wapt_source_dir, 'utils', 'patch-cryptography', 'verification.py'),'./builddir/opt/wapt/lib/python2.7/site-packages/cryptography/x509/verification.py')

eprint('Patch memory leak')
copyfile(makepath(wapt_source_dir,'utils','patch-socketio-client-2','__init__.py'),'./builddir/opt/wapt/lib/python2.7/site-packages/socketIO_client/__init__.py')
copyfile(makepath(wapt_source_dir,'utils','patch-socketio-client-2','transports.py'),'./builddir/opt/wapt/lib/python2.7/site-packages/socketIO_client/transports.py')

# delete pythonwheels
if os.path.exists(makepath('builddir','opt','wapt', 'share/')):
	shutil.rmtree(makepath('builddir','opt','wapt', 'share/'))

eprint('copying the waptservice files')
rsync(source_dir, './builddir/opt/wapt/',
      excludes=['postconf', 'repository', 'rpm', 'deb','pkg', 'spnego-http-auth-nginx-module', '*.bat'])
      
eprint('copying the templates files')
rsync(makepath(wapt_source_dir,'templates/'),'./builddir/opt/wapt/templates/', excludes=[])

if WAPTEDITION=='enterprise':
    eprint('copying the waptserver enterprise files')
    rsync(makepath(wapt_source_dir,'waptenterprise/'), './builddir/opt/wapt/waptenterprise/',
          excludes=[' ','waptwua','waptconsole', 'includes', 'waptserver'])


# script to run waptagent in foreground mode
copyfile(makepath(wapt_source_dir, 'runwaptagent.sh'),'./builddir/opt/wapt/runwaptagent.sh')
copyfile(makepath(wapt_source_dir, 'wapt-get.sh'),'./builddir/opt/wapt/wapt-get.sh')
copyfile(makepath(wapt_source_dir, 'waptpython'),'./builddir/usr/bin/waptpython')

for lib in ('dialog.py', ):
    rsync(makepath(wapt_source_dir, 'lib', 'site-packages', lib),
          './builddir/opt/wapt/lib/python2.7/site-packages/')
          
eprint(run(r'python -m compileall %(pth)s/waptenterprise/ %(pth)s/waptservice/ %(pth)s/lib/python2.7/site-packages/cryptography/x509/verification.py' % {'pth':'./builddir/opt/wapt'}))
eprint(run(r'python -m compileall -l ./builddir/opt/wapt/'))

eprint(run(r'find ./builddir/opt/wapt/ -type f -exec chmod 644 {} \;'))
eprint(run(r'find ./builddir/opt/wapt/ -type d -exec chmod 755 {} \;'))

eprint('copying systemd startup script + session_setup script')
systemd_build_dest_dir = './builddir/usr/lib/systemd/system/'
env_file = './builddir/opt/wapt.env'
etc_profile_d = './builddir/etc/profile.d/'
try:
    mkdir_p(systemd_build_dest_dir)
    mkdir_p(etc_profile_d)
    copyfile('../scripts/.env',env_file)
    copyfile('../scripts/wapt_session_setup.sh',os.path.join(etc_profile_d,'wapt_session_setup.sh'))
    copyfile('../scripts/waptservice.service', os.path.join(systemd_build_dest_dir, 'waptservice.service'))
except Exception as e:
    eprint('error: \n%s' % e)
    exit(1)

eprint('copying logrotate script /etc/logrotate.d/waptservice')
try:
    mkdir_p('./builddir/etc/logrotate.d/')
    shutil.copyfile('../scripts/waptservice-logrotate',
                    './builddir/etc/logrotate.d/waptservice')
    #eprint(run('chown root:root ./builddir/etc/logrotate.d/waptserver'))
except Exception as e:
    eprint('error: \n%s' % e)
    exit(1)

eprint('copying logrotate script /etc/rsyslog.d/waptservice.conf')
try:
    mkdir_p('./builddir/etc/rsyslog.d/')
    shutil.copyfile('../scripts/waptservice-rsyslog',
                    './builddir/etc/rsyslog.d/waptservice.conf')
    #eprint(run('chown root:root ./builddir/etc/rsyslog.d/waptserver.conf'))
except Exception as e:
    eprint('error: \n%s' % e)
    exit(1)

#delete locale
if os.path.exists(makepath('builddir','opt','wapt', 'local/')):
	shutil.rmtree(makepath('builddir','opt','wapt', 'local/'))

#delete include
if os.path.exists(makepath('builddir','opt','wapt', 'include/')):
	shutil.rmtree(makepath('builddir','opt','wapt', 'include/'))

#delete pip selfcheck
if os.path.exists('builddir/opt/wapt/pip-selfcheck.json'):
    os.remove('builddir/opt/wapt/pip-selfcheck.json')

for fn in glob.glob('./builddir/opt/wapt/bin/*'):
    os.chmod(fn, 0o755)
