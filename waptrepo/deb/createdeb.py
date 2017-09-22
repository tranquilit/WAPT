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
import errno

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def replaceAll(file,searchExp,replaceExp):
    for line in fileinput.input(file, inplace=1):
        if searchExp in line:
            line = line.replace(searchExp,replaceExp)
        sys.stdout.write(line)

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise



def rsync(src,dst):
    rsync_option = ' '.join([
        "--exclude '.svn'",
        "--exclude 'deb'",
        "--exclude '.git'",
        "--exclude '.gitignore'",
        "--exclude 'rpm'",
        "-aP"
    ])
    rsync_source = src
    rsync_destination = dst
    rsync_command = '/usr/bin/rsync %s "%s" "%s" 1>&2' % (
        rsync_option,rsync_source,rsync_destination)
    os.system(rsync_command)

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

makepath = os.path.join
from shutil import copyfile

# wapt
wapt_source_dir = os.path.abspath('../..')

# waptrepo
source_dir = os.path.abspath('..')

wapt_version = None
for line in file('../../waptpackage.py', 'r').readlines():
    if line.strip().startswith('__version__'):
        wapt_version = line.split('=')[1].strip().replace('"','').replace("'","")

if wapt_version is None:
    eprint('version "%s" incorrecte/non trouvee dans waptpackage.py' % str(wapt_version))
    sys.exit(1)

control_file = './builddir/DEBIAN/control'

new_umask = 022
old_umask = os.umask(new_umask)
if new_umask != old_umask:
    eprint('umask fixed (previous %03o, current %03o)' % (old_umask, new_umask))

# remove old debs
for filename in glob.glob("tis-waptrepo*.deb"):
    eprint("destruction de %s" % filename)
    os.remove(filename)
if os.path.exists("builddir"):
    shutil.rmtree("builddir")

eprint(u'creation de l\'arborescence')
os.makedirs("builddir")
os.makedirs("builddir/DEBIAN")
os.makedirs("builddir/opt")
os.makedirs("builddir/opt/wapt")
os.makedirs("builddir/opt/wapt/waptrepo/")
os.makedirs("builddir/opt/wapt/lib")
os.makedirs("builddir/opt/wapt/lib/site-packages")

# for some reason the virtualenv does not build itself right if we don't
# have pip systemwide...
eprint(subprocess.check_output(
    r'sudo apt-get install -y python-virtualenv python-setuptools python-pip python-dev libpq-dev libffi-dev', shell=True))

eprint('Create a build environment virtualenv. May need to download a few libraries, it may take some time')
subprocess.check_output(r'virtualenv ./builddir/opt/wapt --system-site-packages', shell=True)

eprint('Install additional libraries in build environment virtualenv')
subprocess.check_output(r'./builddir/opt/wapt/bin/pip install -r ../../requirements-repo.txt -t ./builddir/opt/wapt/lib/site-packages', shell=True)

version_file = open(os.path.join('./builddir/opt/wapt/waptrepo','VERSION'),'w')
version_file.write(wapt_version)
version_file.close()

eprint('copie des fichiers waptrepo')
copyfile(makepath(wapt_source_dir,'waptcrypto.py'),
         './builddir/opt/wapt/waptcrypto.py')
copyfile(makepath(wapt_source_dir,'waptutils.py'),
         './builddir/opt/wapt/waptutils.py')
copyfile(makepath(wapt_source_dir,'custom_zip.py'),
         './builddir/opt/wapt/custom_zip.py')
copyfile(makepath(wapt_source_dir,'waptpackage.py'),
         './builddir/opt/wapt/waptpackage.py')
copyfile(makepath(wapt_source_dir,'wapt-scanpackages.py'),
         './builddir/opt/wapt/wapt-scanpackages.py')
copyfile(makepath(wapt_source_dir,'wapt-signpackages.py'),
         './builddir/opt/wapt/wapt-signpackages.py')

eprint('cryptography patches')
copyfile(makepath(wapt_source_dir,'utils','patch-cryptography','__init__.py'),
         './builddir/opt/wapt/lib/site-packages/cryptography/x509/__init__.py')
copyfile(makepath(wapt_source_dir,'utils','patch-cryptography','verification.py'),
         './builddir/opt/wapt/lib/site-packages/cryptography/x509/verification.py')


add_symlink('./opt/wapt/wapt-signpackages.py','./usr/bin/wapt-signpackages')
add_symlink('./opt/wapt/wapt-scanpackages.py','./usr/bin/wapt-scanpackages')

os.chmod('./builddir/opt/wapt/wapt-scanpackages.py',0o755)
os.chmod('./builddir/opt/wapt/wapt-signpackages.py',0o755)

eprint('copie des fichiers control et postinst')
copyfile('./DEBIAN/control','./builddir/DEBIAN/control')
copyfile('./DEBIAN/postinst','./builddir/DEBIAN/postinst')

def git_hash():
    from git import Repo
    r = Repo('.',search_parent_directories = True)
    return r.active_branch.object.name_rev[:8]

deb_revision = None
if len(sys.argv) >= 2:
    deb_revision = sys.argv[1]
else:
    deb_revision = 'git-'+git_hash()

if deb_revision:
    wapt_version += '-'+deb_revision

eprint(u'inscription de la version dans le fichier de control. new version: ' + wapt_version)
replaceAll(control_file,'0.0.7',wapt_version)

eprint(u'creation du paquet Deb')
os.chmod('./builddir/DEBIAN/postinst',
         stat.S_IRWXU
         | stat.S_IXGRP | stat.S_IRGRP
         | stat.S_IROTH | stat.S_IXOTH
         )

final_deb = 'tis-waptrepo-{}.deb'.format(wapt_version)
dpkg_command = 'dpkg-deb --build builddir %s 1>&2' % final_deb
os.system(dpkg_command)
shutil.rmtree("builddir")
print(final_deb)
