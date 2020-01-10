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
import types

from git import Repo
from xml.dom import minidom
import plistlib

makepath = os.path.join
from shutil import copyfile

def run(*args, **kwargs):
    return subprocess.check_output(*args, shell=True, **kwargs)

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def run_verbose(*args, **kwargs):
    output = subprocess.check_output(*args, shell=True, **kwargs)
    eprint(output)
    return output

def mkdir_p(path):
    if not os.path.isdir(path):
        os.makedirs(path)

def git_hash():
    from git import Repo
    r = Repo('.', search_parent_directories=True)
    return '%s' % (r.active_branch.object.name_rev[:8],)

def dev_revision():
    return 'tismacos-%s' % (git_hash())

def setloglevel(alogger,loglevel):
    """set loglevel as string"""
    if loglevel in ('debug', 'warning', 'info', 'error', 'critical'):
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % loglevel)
        alogger.setLevel(numeric_level)

def rsync(src, dst, excludes=[]):
    excludes_list = ['*.pyc', '*~', '.svn', 'deb', '.git', '.gitignore']
    excludes_list.extend(excludes)

    rsync_source = src
    rsync_destination = dst
    rsync_options = ['-a', '--stats']
    for x in excludes_list:
        rsync_options.extend(['--exclude',x])

    rsync_command = ['/usr/bin/rsync'] + rsync_options + [rsync_source,rsync_destination]
    eprint(rsync_command)
    return subprocess.check_output(rsync_command)


def add_symlink(link_target, link_name, tmp_dir_name):
    if link_target.startswith('/'):
        link_target = link_target[1:]
    relative_link_target_path = os.path.join(tmp_dir_name + '/payload',link_target)
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

    def __init__(self, version, members_count=None):
        if version is None:
            version = ''
        assert isinstance(version, types.ModuleType) or isinstance(version,str) or isinstance(version,unicode) or isinstance(version,Version)
        if isinstance(version, types.ModuleType):
            self.versionstring = getattr(version, '__version__',None)
        elif isinstance(version, Version):
            self.versionstring = getattr(version, 'versionstring',None)
        else:
            self.versionstring = version
        self.members = [v.strip() for v in self.versionstring.split('.')]
        self.members_count = members_count
        if members_count is not None:
            if len(self.members) < members_count:
                self.members.extend(['0'] * (members_count-len(self.members)))
            else:
                self.members = self.members[0:members_count]

    def __cmp__(self, aversion):
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

        if not isinstance(aversion, Version):
            aversion = Version(aversion, self.members_count)
        for i in range(0, max([len(self.members), len(aversion.members)])):
            if i < len(self.members):
                i1 = self.members[i]
            else:
                i1 = ''
            if i < len(aversion.members):
                i2 = aversion.members[i]
            else:
                i2 = ''
            v = nat_cmp(i1,i2)
            if v:
                return v
        return 0

    def __str__(self):
        return '.'.join(self.members)

    def __repr__(self):
        return "Version('{}')".format('.'.join(self.members))

parser = argparse.ArgumentParser(u'Build a WaptAgent MacOS package.')
parser.add_argument('-l', '--loglevel', help='Change log level (error, warning, info, debug...)')
parser.add_argument('-r', '--revision',default=dev_revision(), help='revision to append to package version')
parser.add_argument('-p', '--python_version',default='2',help='python version for WAPT service')
options = parser.parse_args()

logger = logging.getLogger()
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
if options.loglevel is not None:
    setloglevel(logger,options.loglevel)

if platform.system() != 'Darwin':
    logger.error("this script should be used on macOS")
    sys.exit(1)

revision = options.revision
python_version = options.python_version

run_verbose('pip{} install gitpython'.format(python_version))
run_verbose('pip{} install virtualenv'.format(python_version))

####################
# wapt
wapt_source_dir = os.path.abspath('../..')

# waptrepo
source_dir = os.path.abspath('..')

new_umask = 022
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

wapt_version = wapt_version + '.' + rev_count
full_version = wapt_version
if options.revision:
    full_version = full_version + '-' + options.revision

for filename in glob.glob('tis-waptagent*.pkg'):
    eprint('Removing %s' % filename)
    os.remove(filename)

eprint('creating the package tree')

WAPTEDITION=os.environ.get('WAPTEDITION','community')
if WAPTEDITION=='enterprise':
    tmp_dir_name = 'tis-waptagent-enterprise'
    mkdir_p('./tmpbuild/payload/opt/wapt/waptenterprise')
else:
    tmp_dir_name = 'tis-waptagent'

if os.path.exists('tmpbuild'):
    shutil.rmtree('tmpbuild')

# dmidecode : installé avec homebrew (cavalier/dmidecode/dmidecode)
dependencies = ['dmidecode']
for dep in dependencies:
    if subprocess.call("which " + dep, shell=True) != 0:
        shutil.copy(makepath(os.path.abspath('.'), dep), '/usr/local/bin/' + dep)

# munkipkg : https://github.com/munki/munki-pkg
run_verbose('./munkipkg --create tmpbuild')

opt_dirs = ['conf', 'lib', 'log', 'db', 'waptagent']
if python_version == '3':
    opt_dirs.append('usr/local/lib/python3/site-packages')
else:
    opt_dirs.append('usr/local/lib/python2.7/site-packages')

for d in opt_dirs:
    mkdir_p('./tmpbuild/payload/opt/wapt/' + d)
mkdir_p('./tmpbuild/payload/usr/local/bin/')


# for some reason the virtualenv does not build itself right if we don't
# have pip systemwide...

run_verbose('pip{} install setuptools'.format(python_version))
eprint('Create a build environment virtualenv. May need to download a few libraries, it may take some time')
if python_version=='3':
    run_verbose(r'virtualenv -p /usr/local/bin/python3 ./tmpbuild/payload/opt/wapt --always-copy')
else:
    run_verbose(r'virtualenv -p /usr/bin/python2.7 ./tmpbuild/payload/opt/wapt') #--always-copy')
eprint('Install additional libraries in build environment virtualenv')
run_verbose('./tmpbuild/payload/opt/wapt/bin/pip install pip setuptools --upgrade')
# qq libs a rajouter
lib_python=next(os.walk('./tmpbuild/payload/opt/wapt/lib/'))[1][0]
run('./tmpbuild/payload/opt/wapt/bin/pip{} install -r ../../requirements.txt -r ../../requirements-linux.txt -t ./tmpbuild/payload/opt/wapt/lib/{}/site-packages'.format(python_version, lib_python))

run_verbose(r'virtualenv ./tmpbuild/payload/opt/wapt --relocatable')

eprint('copying the waptservice files')
files_to_copy = ['waptcrypto.py','waptutils.py','common.py','custom_zip.py','waptpackage.py','setuphelpers.py','setuphelpers_linux.py','setuphelpers_windows.py','setuphelpers_unix.py','setuphelpers_macos.py','wapt-get.py']
for afile in files_to_copy:
    copyfile(makepath(wapt_source_dir, afile),os.path.join('./builddir/opt/wapt/',afile))

# delete pythonwheels
if os.path.exists(makepath('./tmpbuild/payload', 'opt', 'wapt', 'share/')):
    shutil.rmtree(makepath('./tmpbuild/payload', 'opt', 'wapt', 'share/'))

# a voir si c'est encore necessaire
eprint('cryptography patches')
copyfile(makepath(wapt_source_dir, 'utils', 'patch-cryptography', '__init__.py'), './tmpbuild/payload/opt/wapt/lib/{}/site-packages/cryptography/x509/__init__.py'.format(lib_python))
copyfile(makepath(wapt_source_dir, 'utils', 'patch-cryptography', 'verification.py'), './tmpbuild/payload/opt/wapt/lib/{}/site-packages/cryptography/x509/verification.py'.format(lib_python))

eprint('Patch memory leak')
copyfile(makepath(wapt_source_dir, 'utils', 'patch-socketio-client-2', '__init__.py'), './tmpbuild/payload/opt/wapt/lib/{}/site-packages/socketIO_client/__init__.py'.format(lib_python))
copyfile(makepath(wapt_source_dir, 'utils', 'patch-socketio-client-2', 'transports.py'), './tmpbuild/payload/opt/wapt/lib/{}/site-packages/socketIO_client/transports.py'.format(lib_python))

eprint('copying the waptserver files')
rsync(source_dir, './tmpbuild/payload/opt/wapt',
      excludes=['postconf', 'repository', 'rpm', 'deb', 'spnego-http-auth-nginx-module', '*.bat'])

if WAPTEDITION=='enterprise':
    eprint('copying the waptserver enterprise files')
    rsync(wapt_source_dir + '/waptenterprise/', './tmpbuild/payload/opt/wapt/waptenterprise/',
          excludes = [' ','waptwua', 'waptconsole', 'includes', 'waptserver'])

# script to run waptagent in foreground mode
copyfile(makepath(wapt_source_dir, 'runwaptagent.sh'),'./tmpbuild/payload/opt/wapt/runwaptagent.sh')
copyfile(makepath(wapt_source_dir, 'wapt-get.sh'),'./tmpbuild/payload/opt/wapt/wapt-get.sh')
copyfile(makepath(wapt_source_dir, 'waptpython'),'./tmpbuild/payload/usr/local/bin/waptpython')

for lib in ('dialog.py', ):
    rsync(makepath(wapt_source_dir, 'lib', 'site-packages', lib),
          './tmpbuild/payload/opt/wapt/lib/{}/site-packages/'.format(lib_python))

eprint('copying preinst and postinst package metadata')
copyfile('./postinstall', './tmpbuild/scripts/postinstall')
copyfile('./preinstall', './tmpbuild/scripts/preinstall')


eprint(run(r'find ./tmpbuild/payload/opt/wapt -type f -exec chmod 644 tmpbuild \;'))
eprint(run(r'find ./tmpbuild/payload/opt/wapt -type d -exec chmod 755 tmpbuild \;'))

eprint('copying logrotate script /etc/logrotate.d/waptagent')
try:
    mkdir_p('./tmpbuild/payload/etc/logrotate.d/')
    shutil.copyfile('../Scripts/waptservice-logrotate',
                    './tmpbuild/payload/etc/logrotate.d/waptagent')
    #eprint(run('chown root:root ./tmpbuild/payload/etc/logrotate.d/waptserver'))
except Exception as e:
    eprint('error: \n%s' % e)
    exit(1)

eprint('copying logrotate script /etc/rsyslog.d/waptservice.conf')
try:
    mkdir_p('./tmpbuild/payload/etc/rsyslog.d/')
    shutil.copyfile('../Scripts/waptservice-rsyslog',
                    './tmpbuild/payload/etc/rsyslog.d/waptservice.conf')
    #eprint(run('chown root:root ./tis-waptagent/payload/etc/rsyslog.d/waptserver.conf'))
except Exception as e:
    eprint('error: \n%s' % e)
    exit(1)

for fn in glob.glob('./tmpbuild/payload/opt/wapt/bin/*'):
    os.chmod(fn, 0o755)

shutil.copytree(makepath(wapt_source_dir, 'templates'), './tmpbuild/payload/opt/wapt/templates/')

os.chmod('./tmpbuild/scripts/postinstall', 0o755)
os.chmod('./tmpbuild/scripts/preinstall', 0o755)

# build
if WAPTEDITION=='enterprise':
    package_filename = 'tis-waptagent-enterprise-{}.pkg'.format(full_version)
else:
    package_filename = 'tis-waptagent-{}.pkg'.format(full_version)


package_info_file = './tmpbuild/build-info.plist'
plist_obj = plistlib.readPlist(package_info_file)
plist_obj['name'] = package_filename
plist_obj['version'] = full_version
plistlib.writePlist(plist_obj, package_info_file)


# The pkgbuild solution :
'''
run_verbose(['pkgbuild','--root','builddir',
                        '--identifier', package_filename,
                        '--version', full_version,
                        '--scripts', scripts,
                        '--install-location', '/opt/wapt',
                        package_filename + '.pkg']))
'''

run_verbose("./munkipkg ./tmpbuild")

run_verbose("cp tmpbuild/build/{} .".format(package_filename))
run_verbose("cp ./wapt.plist /Library/LaunchDaemons")

print("Package created.")