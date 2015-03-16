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

import fileinput
import glob
import os
import shutil
import stat
import subprocess
import sys


def replaceAll(file,searchExp,replaceExp):
    for line in fileinput.input(file, inplace=1):
        if searchExp in line:
            line = line.replace(searchExp,replaceExp)
        sys.stdout.write(line)


def rsync(src,dst):
    rsync_option = ' '.join([
        "--exclude '.svn'",
        "--exclude 'deb'",
        "--exclude '.git'",
        "--exclude '.gitignore'",
        "-aP",
    ])
    rsync_source = src
    rsync_destination = dst
    rsync_command = '/usr/bin/rsync %s "%s" "%s"' % (
        rsync_option,rsync_source,rsync_destination)
    os.system(rsync_command)

makepath = os.path.join
from shutil import copyfile

# wapt
wapt_source_dir = os.path.abspath('../..')

# waptrepo
source_dir = os.path.abspath('..')

sys.path.insert(0, wapt_source_dir)
from waptpackage import __version__ as wapt_version

if not wapt_version:
    print 'version "%s" incorrecte dans waptpackage.py' % (wapt_version,)
    sys.exit(1)

control_file = './builddir/DEBIAN/control'

new_umask = 022
old_umask = os.umask(new_umask)
if new_umask != old_umask:
    print >> sys.stderr, 'umask fixed (previous %03o, current %03o)' % (old_umask, new_umask)
 
# remove old debs
for filename in glob.glob("tis-waptrepo*.deb"):
    print "destruction de %s" % filename
    os.remove(filename)
if os.path.exists("builddir"):
    shutil.rmtree("builddir")

print u'creation de l\'arborescence'
os.makedirs("builddir")
os.makedirs("builddir/DEBIAN")
os.makedirs("builddir/opt")
os.makedirs("builddir/opt/wapt")
os.makedirs("builddir/opt/wapt/waptrepo/")

version_file = open(os.path.join('./builddir/opt/wapt/waptrepo','VERSION'),'w')
version_file.write(wapt_version)
version_file.close()

print 'copie des fichiers waptrepo'
rsync(source_dir,'./builddir/opt/wapt/')
copyfile(makepath(wapt_source_dir,'waptpackage.py'),
         './builddir/opt/wapt/waptpackage.py')
copyfile(makepath(wapt_source_dir,'wapt-scanpackages.py'),
         './builddir/opt/wapt/wapt-scanpackages.py')

print 'copie des fichiers control et postinst'
copyfile('./DEBIAN/control','./builddir/DEBIAN/control')
copyfile('./DEBIAN/postinst','./builddir/DEBIAN/postinst')

print u'inscription de la version dans le fichier de control. new version: ' + wapt_version
replaceAll(control_file,'0.0.7',wapt_version)

print u'creation du paquet Deb'
os.chmod('./builddir/DEBIAN/postinst',
         stat.S_IRWXU
         | stat.S_IXGRP | stat.S_IRGRP
         | stat.S_IROTH | stat.S_IXOTH
         )
dpkg_command = 'dpkg-deb --build builddir tis-waptrepo.deb'
os.system(dpkg_command)
shutil.rmtree("builddir")
