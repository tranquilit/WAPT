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

import os,glob,sys,stat
import shutil
import fileinput
import subprocess
import platform, errno

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise

def replaceAll(file,searchExp,replaceExp):
    for line in fileinput.input(file, inplace=1):
        if searchExp in line:
            line = line.replace(searchExp,replaceExp)
        sys.stdout.write(line)

def rsync(src,dst,excludes=[]):
    rsync_option = " --exclude 'postconf' --exclude 'mongodb' --exclude 'rpm' --exclude '*.pyc' --exclude '*.pyo' --exclude '.svn' --exclude 'apache-win32' --exclude 'deb' --exclude '.git' --exclude '.gitignore' -aP"
    if excludes:
        rsync_option = rsync_option + ' '.join(" --exclude '%s'" % x for x in excludes)
    rsync_source = src
    rsync_destination = dst
    rsync_command = '/usr/bin/rsync %s "%s" "%s"'%(rsync_option,rsync_source,rsync_destination)
    print >> sys.stderr, rsync_command
    os.system(rsync_command)

makepath = os.path.join
from shutil import copyfile

# wapt
wapt_source_dir = os.path.abspath('../..')

# waptrepo
source_dir = os.path.abspath('..')

if platform.system()!='Linux':
    print >> sys.stderr, "this script should be used on debian linux"
    sys.exit(1)

if len(sys.argv) > 2:
    print >> sys.stderr, "wrong number of parameters (0 or 1)"
    sys.exit(1)

new_umask = 022
old_umask = os.umask(new_umask)
if new_umask != old_umask:
    print >> sys.stderr, 'umask fixed (previous %03o, current %03o)' % (old_umask, new_umask)

for line in open('%s/waptserver.py'% source_dir):
    if line.strip().startswith('__version__'):
        wapt_version = line.split('=')[1].strip().replace('"','').replace("'","")

if not wapt_version:
    print >> sys.stderr, u'version not found in %s/waptserver.py' % os.path.abspath('..')
    sys.exit(1)

# gcc is for pip package install
print(subprocess.check_output("yum install -y python-virtualenv gcc",shell=True))

print >> sys.stderr, 'creating the package tree'
mkdir_p("builddir/opt/wapt/lib")
mkdir_p("builddir/opt/wapt/lib/site-packages")

# we use pip and virtualenv to get the wapt dependencies. virtualenv usage here is a bit awkward, it can probably be improved. For instance, it install a outdated version of pip that cannot install Rocket dependencies...
# for some reason the virtualenv does not build itself right if we don't have pip systemwide...
#subprocess.check_output(r'sudo yum install -y python-virtualenv python-setuptools python-pip python-devel',shell=True)
if os.path.exists("pylibs"):
    shutil.rmtree("pylibs")
print('Create a build environment virtualenv. May need to download a few libraries, it may take some time')
subprocess.check_output(r'virtualenv ./pylibs --system-site-packages',shell=True)
print('Install additional libraries in build environment virtualenv')
print(subprocess.check_output(r'source ./pylibs/bin/activate ; pip install --upgrade pip ' ,shell=True))
print(subprocess.check_output(r'source ./pylibs/bin/activate ; pip install -r ../../requirements-server-debian.txt -t ./builddir/opt/wapt/lib/site-packages',shell=True))
rsync('./pylibs/lib/','./builddir/opt/wapt/lib/')
print >> sys.stderr, 'copying the waptserver files'
rsync(source_dir,'./builddir/opt/wapt/',excludes=['postconf','mongod.exe','bin','include'])
for lib in ('requests','iniparse','dns','pefile.py','rocket','flask','werkzeug','jinja2','itsdangerous.py','markupsafe', 'dialog.py', 'babel', 'flask_babel', 'huey', 'wakeonlan'):
    rsync(makepath(wapt_source_dir,'lib','site-packages',lib),'./builddir/opt/wapt/lib/site-packages/')

print >> sys.stderr, "copying the startup script /etc/init.d/waptserver"
try:
    mkdir_p('./builddir/etc/init.d/')
    if platform.dist()[0] in ('debian','ubuntu'):
        copyfile('../scripts/waptserver-init','./builddir/etc/init.d/waptserver')
    elif platform.dist()[0] in ('centos','redhat','fedora'):
        copyfile('../scripts/waptserver-init-centos','./builddir/etc/init.d/waptserver')
    else:
        print "unsupported distrib"
        sys.exit(1)

    subprocess.check_output('chmod 755 ./builddir/etc/init.d/waptserver',shell=True)
    subprocess.check_output('chown root:root ./builddir/etc/init.d/waptserver',shell=True)
except Exception as e:
    print >> sys.stderr, 'error: \n%s'%e
    exit(1)

print >> sys.stderr, "copying logrotate script /etc/logrotate.d/waptserver"
try:
    mkdir_p('./builddir/etc/logrotate.d/')
    shutil.copyfile('../scripts/waptserver-logrotate','./builddir/etc/logrotate.d/waptserver')
    subprocess.check_output('chown root:root ./builddir/etc/logrotate.d/waptserver',shell=True)
except Exception as e:
    print >> sys.stderr, 'error: \n%s'%e
    exit(1)

print >> sys.stderr, "copying logrotate script /etc/rsyslog.d/waptserver.conf"
try:
    mkdir_p('./builddir/etc/rsyslog.d/')
    shutil.copyfile('../scripts/waptserver-rsyslog','./builddir/etc/rsyslog.d/waptserver.conf')
    subprocess.check_output('chown root:root ./builddir/etc/rsyslog.d/waptserver.conf',shell=True)
except Exception as e:
    print >> sys.stderr, 'error: \n%s'%e
    exit(1)

print >> sys.stderr, "adding symlink for wapt-serverpostconf"
mkdir_p('builddir/usr/bin')
os.symlink('/opt/wapt/waptserver/scripts/postconf.py', 'builddir/usr/bin/wapt-serverpostconf')

print >> sys.stderr, "copying apache-related goo"
try:
    apache_dir = './builddir/opt/wapt/waptserver/apache/'
    mkdir_p(apache_dir + '/ssl')
    subprocess.check_output(['chmod', '0700', apache_dir + '/ssl'])
    copyfile('../apache-win32/conf/httpd.conf.j2', apache_dir + 'httpd.conf.j2')
except Exception as e:
    print >> sys.stderr, 'error: \n%s'%e
    exit(1)

