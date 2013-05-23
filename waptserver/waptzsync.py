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
import os
import zipfile
import codecs
import re
import urllib
import tempfile
import shutil
import sys 
import logging
import ConfigParser
from optparse import OptionParser


logger = logging.getLogger()
hdlr = logging.StreamHandler(sys.stdout)
hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logger.addHandler(hdlr)
logger.setLevel(logging.CRITICAL)

parser = OptionParser()
parser.add_option('-c', help='pass config file')
(options, args) = parser.parse_args()

if options.c:
    config_file = options.c
else:
    config_file = '/etc/tis/config-waptzsync.ini'


if not os.path.exists(config_file):
    raise Exception("No config file found")


config = ConfigParser.ConfigParser()
config.read(config_file)

section = config.sections()[0]

if config.has_option(section, 'main_repo'):
    main_repo = config.get(section, 'main_repo')
else:
    main_repo = "http://srvinstallation.tranquil.it/wapt/" 
    
if config.has_option(section, 'wapt_dir'):
    wapt_dir = config.get(section, 'wapt_dir')
else:
    wapt_dir = "/var/www/wapt/"
    
if config.has_option(section, 'donwload_new_packages'):
    donwload_new_packages = config.get(section, 'donwload_new_packages')
else:
    donwload_new_packages = True 
    


os.chdir(wapt_dir)
os.system('cd '+wapt_dir)

urllib.urlretrieve(main_repo+"wapt-scanpackages.py", wapt_dir+'wapt-scanpackages.py')
urllib.urlretrieve(main_repo+"waptpackage.py", wapt_dir+'waptpackage.py')
os.system("/usr/bin/zsync  %s.zsync -o %s" % (main_repo+"waptsetup.exe", wapt_dir+"waptsetup.exe"))

os.system('cd '+wapt_dir+'&& python wapt-scanpackages.py .')

sys.path.append(wapt_dir)
from waptpackage import PackageEntry

packagesToUpgrade = []
newPackages = []
multipleVersionPackages = []


def match_version(package1, package2):
    if package1 > package2:
        packagesToUpgrade.append(package1)

def packagesFileToList(pathTofile):
    listPackages = codecs.decode(zipfile.ZipFile(pathTofile).read(name='Packages'),'utf-8')
    packages = []

    def add_package(lines):
        package = PackageEntry()
        package.load_control_from_wapt(lines)
        package.filename = package.make_package_filename()
        packages.append(package)


    lines = []
    for line in listPackages.splitlines():
        # new package
        if line.strip()=='':
            add_package(lines)
            lines = []
            # add ettribute to current package
        else:
            lines.append(line)

    if lines:
        add_package(lines)
        lines = []

    return packages



def downloadRepoPackages(mainRepo):
    tempDir  =  tempfile.mkdtemp()
    packagesTemp = tempDir+"/Packages"
    urllib.urlretrieve(mainRepo+"Packages", packagesTemp)
    packages =  packagesFileToList(packagesTemp)
    if os.path.exists(tempDir):
        shutil.rmtree(tempDir)
    return packages 


def downloadPackages(packages):
    for package in packages:
        print "Downloading : %s version => %s" % ( package.package, package.version )
        os.system("/usr/bin/zsync  %s.zsync -o %s" % (main_repo+package.filename, wapt_dir+package.filename))



repoPackages = downloadRepoPackages(main_repo)
localPackages = packagesFileToList(wapt_dir+'Packages') 

for repoPackage in repoPackages:
    if not repoPackage.section != "host":
        continue
        
    matchPackage = [ package for package in localPackages if repoPackage.package == package.package ]

    if len(matchPackage) == 1:
        if repoPackage > matchPackage[0]:
            packagesToUpgrade.append(repoPackage)
    elif len(matchPackage) > 1: 
        if not [ x for x in matchPackage if repoPackage.version in x.version ]:
            packagesToUpgrade.append(repoPackage)
    elif donwload_new_packages:
        newPackages.append(repoPackage)
    else:
        print "New package: "+repoPackage.package


if packagesToUpgrade:
    downloadPackages( packagesToUpgrade)
else :
    print "The system is already up to date"
if newPackages:
    downloadPackages(newPackages)

if packagesToUpgrade or newPackages:
    os.system('cd '+wapt_dir+'&& python wapt-scanpackages.py .')
    
    

os.system('chmod 644 %s*'%wapt_dir)