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


logger = logging.getLogger()
hdlr = logging.StreamHandler(sys.stdout)
hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logger.addHandler(hdlr)
logger.setLevel(logging.CRITICAL)


#Remote WAPT Repository 
#mainRepo = "http://wapt/wapt/"
mainRepo = "http://srvinstallation.tranquil.it/wapt/"

#Local WAPT Repository
waptDir = "/var/www/wapt/"


# download new packages if present
donwloadNewPackages = True


urllib.urlretrieve(mainRepo+"wapt-scanpackages.py", waptDir+'wapt-scanpackages.py')
urllib.urlretrieve(mainRepo+"waptpackage.py", waptDir+'waptpackage.py')
os.system("/usr/bin/zsync  %s.zsync -o %s" % (mainRepo+"waptsetup.exe", waptDir+"waptsetup.exe"))

if not os.path.exists(waptDir+"Packages"):
    os.system('cd '+waptDir+'&& python wapt-scanpackages.py .')

sys.path.append(waptDir)
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
    os.system("/usr/bin/zsync  %s.zsync -o %s" % (mainRepo+package.filename, waptDir+package.filename))
   


repoPackages = downloadRepoPackages(mainRepo)
localPackages = packagesFileToList(waptDir+'Packages') 

for repoPackage in repoPackages:
    matchPackage = [ package for package in localPackages if repoPackage.package == package.package ]
    if len(matchPackage) == 1:
        if repoPackage > matchPackage[0]:
        	packagesToUpgrade.append(repoPackage)
    elif len(matchPackage) > 1: 
	if not [ x for x in matchPackage if repoPackage.version in x.version ]:
	  packagesToUpgrade.append(repoPackage)
    elif donwloadNewPackages :
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
  os.system('cd '+waptDir+'&& python wapt-scanpackages.py .')
