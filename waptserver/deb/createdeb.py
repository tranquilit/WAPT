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

def rsync(src,dst):
    rsync_option = " --exclude '*.pyc' --exclude '.svn' --exclude 'apache-win32' --exclude 'deb' --exclude '.git' --exclude '.gitignore' -aP"
    rsync_source = src
    rsync_destination = dst
    rsync_command = '/usr/bin/rsync %s "%s" "%s"'%(rsync_option,rsync_source,rsync_destination)
    os.system(rsync_command)

makepath = os.path.join
from shutil import copyfile

# wapt
wapt_source_dir = os.path.abspath('../..')

# waptrepo
source_dir = os.path.abspath('..')

if platform.system()!='Linux':
    print "this script should be used on debian linux"
    sys.exit(1)

for line in open('%s/waptserver.py'% source_dir):
    if line.strip().startswith('__version__'):
        wapt_version = line.split('=')[1].strip().replace('"','').replace("'","")

if not wapt_version:
    print 'version non trouvée dans %s/waptserver.py, la version est mise a 0.0.0 par défault.'%os.path.abspath('..')
    wapt_version = '0.0.0'

control_file = './builddir/DEBIAN/control'

for filename in glob.glob("tis-waptserver*.deb"):
    print "destruction de %s"%filename
    os.remove(filename)

if os.path.exists("builddir"):
    shutil.rmtree("builddir")

print 'création de l\'arborescence'
os.makedirs("builddir")
os.makedirs("builddir/DEBIAN")
os.makedirs("builddir/opt")
os.makedirs("builddir/opt/wapt")
os.makedirs("builddir/opt/wapt/lib")
os.makedirs("builddir/opt/wapt/lib/site-packages")
os.makedirs("builddir/opt/wapt/waptserver")

#adding version info in VERSION file
rev=''
output = subprocess.check_output('env LC_ALL=C /usr/bin/svn info',shell=True)
for line in output.split('\n'):
    if 'Revision:' in line:
        rev = 'rev%s' % line.split(':')[1].strip()

version_file = open(os.path.join('./builddir/opt/wapt/waptserver','VERSION'),'w')
version_file.write(rev)
version_file.close()

print 'copy waptserver files'
rsync(source_dir,'./builddir/opt/wapt/')
for lib in ('requests','iniparse','dns','pefile.py','rocket','pymongo','bson','flask','werkzeug','jinja2','itsdangerous.py','markupsafe', 'dialog.py'):
    rsync(makepath(wapt_source_dir,'lib','site-packages',lib),'./builddir/opt/wapt/lib/site-packages/')

print 'copie des fichiers control et postinst'
copyfile('./DEBIAN/control','./builddir/DEBIAN/control')
copyfile('./DEBIAN/postinst','./builddir/DEBIAN/postinst')
copyfile('./DEBIAN/preinst','./builddir/DEBIAN/preinst')

print "copy startup script /etc/init.d/waptserver"
try:
    mkdir_p('./builddir/etc/init.d/')
    copyfile('../scripts/waptserver-init','./builddir/etc/init.d/waptserver')
    subprocess.check_output('chmod 755 ./builddir/etc/init.d/waptserver',shell=True)
    subprocess.check_output('chown root:root ./builddir/etc/init.d/waptserver',shell=True)
except Exception as e:
    print 'erreur: \n%s'%e
    exit(1)

print "copy logrotate script /etc/logrotate.d/waptserver"
try:
    mkdir_p('./builddir/etc/logrotate.d/')
    shutil.copyfile('../scripts/waptserver-logrotate','./builddir/etc/logrotate.d/waptserver')
    subprocess.check_output('chown root:root ./builddir/etc/logrotate.d/waptserver',shell=True)
except Exception as e:
    print 'erreur: \n%s'%e
    exit(1)

print "copying apache-related goo"
try:
    apache_dir = './builddir/opt/wapt/waptserver/apache/'
    mkdir_p(apache_dir + '/ssl')
    subprocess.check_output(['chmod', '0700', apache_dir + '/ssl'])
    copyfile('../apache-win32/conf/httpd.conf.j2', apache_dir + 'httpd.conf.j2')
except Exception as e:
    print 'erreur: \n%s'%e
    exit(1)

print 'inscription de la version dans le fichier de control'
replaceAll(control_file,'0.0.7',wapt_version + '-' + rev)

os.chmod('./builddir/DEBIAN/postinst',stat.S_IRWXU| stat.S_IXGRP | stat.S_IRGRP | stat.S_IROTH | stat.S_IXOTH)
os.chmod('./builddir/DEBIAN/preinst',stat.S_IRWXU| stat.S_IXGRP | stat.S_IRGRP | stat.S_IROTH | stat.S_IXOTH)

print 'création du paquet Deb'
dpkg_command = 'dpkg-deb --build builddir tis-waptserver-%s-rev%s.deb'% (wapt_version ,rev)
os.system(dpkg_command)
shutil.rmtree("builddir")

