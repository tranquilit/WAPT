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
import sys


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


def add_symlink(link_target, link_name):
    if link_target.startswith('/'):
        link_target = link_target[1:]
    relative_link_target_path = os.path.join('builddir', link_target)
    print('adding symlink %s -> %s' % (link_name, relative_link_target_path))
    mkdir_p(os.path.dirname(relative_link_target_path))

    if not os.path.exists(relative_link_target_path):
        cmd = 'ln -s %s %s ' % (relative_link_target_path, link_name)
        print(cmd)
        print(subprocess.check_output(cmd))


def rsync(src, dst, excludes=[]):
    rsync_option = " --exclude '*.pyc' --exclude '*~' --exclude '.svn' --exclude 'deb' --exclude '.git' --exclude '.gitignore' -a --stats"
    if excludes:
        rsync_option = rsync_option + \
            ' '.join(" --exclude '%s'" % x for x in excludes)
    rsync_source = src
    rsync_destination = dst
    rsync_command = '/usr/bin/rsync %s "%s" "%s"' % (
        rsync_option, rsync_source, rsync_destination)
    print(rsync_command, file=sys.stderr)
    os.system(rsync_command)


makepath = os.path.join
from shutil import copyfile

# wapt
wapt_source_dir = os.path.abspath('../..')

# waptrepo
source_dir = os.path.abspath('..')

if platform.system() != 'Linux':
    print('this script should be used on debian linux', file=sys.stderr)
    sys.exit(1)

if len(sys.argv) > 2:
    print('wrong number of parameters (0 or 1)', file=sys.stderr)
    sys.exit(1)

def git_hash():
    from git import Repo
    r = Repo('.',search_parent_directories = True)
    return r.active_branch.object.name_rev[:8]

deb_revision = None
if len(sys.argv) >= 2:
    deb_revision = sys.argv[1]
else:
    deb_revision = git_hash()

new_umask = 022
old_umask = os.umask(new_umask)
if new_umask != old_umask:
    print('umask fixed (previous %03o, current %03o)' %
          (old_umask, new_umask), file=sys.stderr)

for line in open('%s/waptserver.py' % source_dir):
    if line.strip().startswith('__version__'):
        wapt_version = line.split('=')[
            1].strip().replace('"', '').replace("'", '')

if not wapt_version:
    print(u'version not found in %s/waptserver.py' %
          os.path.abspath('..'), file=sys.stderr)
    sys.exit(1)

control_file = './builddir/DEBIAN/control'

for filename in glob.glob('tis-waptserver*.deb'):
    print('Removing %s' % filename, file=sys.stderr)
    os.remove(filename)

if os.path.exists('builddir'):
    shutil.rmtree('builddir')

print('creating the package tree', file=sys.stderr)
mkdir_p('builddir/DEBIAN')
mkdir_p('builddir/opt/wapt/conf')
mkdir_p('builddir/opt/wapt/lib')
mkdir_p('builddir/opt/wapt/log')
mkdir_p('builddir/opt/wapt/lib/site-packages')
mkdir_p('builddir/opt/wapt/waptserver')

# for some reason the virtualenv does not build itself right if we don't
# have pip systemwide...
subprocess.check_output(
    r'sudo apt-get install -y python-virtualenv python-setuptools python-pip python-dev libpq-dev libffi-dev libldap2-dev libsasl2-dev', shell=True)

print(
    'Create a build environment virtualenv. May need to download a few libraries, it may take some time')
subprocess.check_output(
    r'virtualenv ./builddir/opt/wapt --distribute', shell=True)

print('Install additional libraries in build environment virtualenv')
subprocess.check_output(
    r'./builddir/opt/wapt/bin/pip install -r ../../requirements-server.txt -t ./builddir/opt/wapt/lib/site-packages', shell=True)

print('copying the waptrepo files', file=sys.stderr)
copyfile(makepath(wapt_source_dir, 'waptcrypto.py'),
         './builddir/opt/wapt/waptcrypto.py')
copyfile(makepath(wapt_source_dir, 'waptutils.py'),
         './builddir/opt/wapt/waptutils.py')
copyfile(makepath(wapt_source_dir, 'custom_zip.py'),
         './builddir/opt/wapt/custom_zip.py')
copyfile(makepath(wapt_source_dir, 'waptpackage.py'),
         './builddir/opt/wapt/waptpackage.py')
copyfile(makepath(wapt_source_dir, 'wapt-scanpackages.py'),
         './builddir/opt/wapt/wapt-scanpackages.py')
copyfile(makepath(wapt_source_dir, 'wapt-signpackages.py'),
         './builddir/opt/wapt/wapt-signpackages.py')

print('cryptography patches')
copyfile(makepath(wapt_source_dir, 'utils', 'patch-cryptography', '__init__.py'),
         './builddir/opt/wapt/lib/site-packages/cryptography/x509/__init__.py')
copyfile(makepath(wapt_source_dir, 'utils', 'patch-cryptography', 'verification.py'),
         './builddir/opt/wapt/lib/site-packages/cryptography/x509/verification.py')


print('Add symlink for wapt-scanpackages and wapt-signpackages')
add_symlink('./opt/wapt/wapt-signpackages.py', './usr/bin/wapt-signpackages')
add_symlink('./opt/wapt/wapt-scanpackages.py', './usr/bin/wapt-scanpackages')


print('copying the waptserver files', file=sys.stderr)
rsync(source_dir, './builddir/opt/wapt/',
      excludes=['apache-win32', 'mongodb', 'postconf', 'repository', 'rpm', 'uninstall-services.bat', 'deb', 'spnego-http-auth-nginx-module'])
for lib in ('dialog.py', ):
    rsync(makepath(wapt_source_dir, 'lib', 'site-packages', lib),
          './builddir/opt/wapt/lib/site-packages/')

print('copying control and postinst package metadata', file=sys.stderr)
copyfile('./DEBIAN/control', './builddir/DEBIAN/control')
copyfile('./DEBIAN/postinst', './builddir/DEBIAN/postinst')
copyfile('./DEBIAN/preinst', './builddir/DEBIAN/preinst')

subprocess.check_output(
    r'find ./builddir/opt/wapt/ -type f -exec chmod 644 {} \;', shell=True)
subprocess.check_output(
    r'find ./builddir/opt/wapt/ -type d -exec chmod 755 {} \;', shell=True)

print('copying systemd startup script', file=sys.stderr)
systemd_build_dest_dir = './builddir/usr/lib/systemd/system/'
try:
    mkdir_p(systemd_build_dest_dir)
    copyfile('../scripts/waptserver.service', os.path.join(systemd_build_dest_dir, 'waptserver.service'))
except Exception as e:
    print (sys.stderr, 'error: \n%s' % e, file=sys.stderr)
    exit(1)

print('copying logrotate script /etc/logrotate.d/waptserver', file=sys.stderr)
try:
    mkdir_p('./builddir/etc/logrotate.d/')
    shutil.copyfile('../scripts/waptserver-logrotate',
                    './builddir/etc/logrotate.d/waptserver')
    subprocess.check_output(
        'chown root:root ./builddir/etc/logrotate.d/waptserver', shell=True)
except Exception as e:
    print('error: \n%s' % e, file=sys.stderr)
    exit(1)

print('copying logrotate script /etc/rsyslog.d/waptserver.conf',
      file=sys.stderr)
try:
    mkdir_p('./builddir/etc/rsyslog.d/')
    shutil.copyfile('../scripts/waptserver-rsyslog',
                    './builddir/etc/rsyslog.d/waptserver.conf')
    subprocess.check_output(
        'chown root:root ./builddir/etc/rsyslog.d/waptserver.conf', shell=True)
except Exception as e:
    print('error: \n%s' % e, file=sys.stderr)
    exit(1)

add_symlink('opt/wapt/waptserver/scripts/postconf.py', '/usr/bin/wapt-serverpostconf')
os.chmod('./builddir/opt/wapt/waptserver/scripts/postconf.py', 0o755)

print('copying nginx-related goo', file=sys.stderr)
try:
    apache_dir = './builddir/opt/wapt/waptserver/apache/'
    mkdir_p(apache_dir + '/ssl')
    subprocess.check_output(['chmod', '0700', apache_dir + '/ssl'])
    copyfile('../apache-win32/conf/httpd.conf.j2',
             apache_dir + 'httpd.conf.j2')

    mkdir_p('./builddir/etc/systemd/system/nginx.service.d')
    copyfile('../scripts/nginx_worker_files_limit.conf', './builddir/etc/systemd/system/nginx.service.d/nginx_worker_files_limit.conf')
except Exception as e:
    print('error: \n%s' % e, file=sys.stderr)
    exit(1)

print(sys.stderr, 'Overriding VCS revision.', file=sys.stderr)
rev_file = file('builddir/opt/wapt/revision.txt', 'w')
try:
    git_hash = subprocess.check_call(
        ['git', 'rev-parse', '--short', 'HEAD'], stdout=rev_file)
except Exception:
    print('Could not retrieve the hash of the current git commit.',
          file=sys.stderr)
    print(sys.stderr, 'Is git(1) installed?', file=sys.stderr)
    raise
rev_file.close()

deb_version = wapt_version
if deb_revision:
    deb_version += '-' + str(deb_revision)

print('replacing the revision in the control file', file=sys.stderr)
replaceAll(control_file, '0.0.7', deb_version)

os.chmod('./builddir/DEBIAN/postinst', stat.S_IRWXU |
         stat.S_IXGRP | stat.S_IRGRP | stat.S_IROTH | stat.S_IXOTH)
os.chmod('./builddir/DEBIAN/preinst', stat.S_IRWXU |
         stat.S_IXGRP | stat.S_IRGRP | stat.S_IROTH | stat.S_IXOTH)

print('creating the Debian package', file=sys.stderr)
output_file = 'tis-waptserver-%s.deb' % (deb_version)
dpkg_command = 'dpkg-deb --build builddir %s' % output_file
status = os.system(dpkg_command)
if status == 0:
    os.link(output_file, 'tis-waptserver.deb')
else:
    print('error while building package')
sys.exit(status)
