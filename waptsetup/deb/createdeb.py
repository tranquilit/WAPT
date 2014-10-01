#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013-2014  Tranquil IT Systems http://www.tranquil.it
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

import HTMLParser
import argparse
import errno
import fileinput
import glob
import httplib
import logging
import os
import pefile
import platform
import re
import shutil
import stat
import subprocess
import sys

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


makepath = os.path.join
run = subprocess.check_output

BDIR = './builddir/'
EXE = 'waptsetup.exe'
SRV = 'srvinstallation.tranquil.it'
BASEPATH = '/wapt/nightly/'

class MyHTMLParser(HTMLParser.HTMLParser):

    def __init__(self, *args, **kwargs):
        HTMLParser.HTMLParser.__init__(self, *args, **kwargs)
        self.wapt_waptsetup_exes = []

    def handle_starttag(self, tag, attrs):
        if tag != 'a':
            return
        for (attr, value) in attrs:
            if attr == 'href' and value.startswith('waptsetup_'):
                self.wapt_waptsetup_exes.append(value)

def setloglevel(logger,loglevel):
    """set loglevel as string"""
    if loglevel in ('debug','warning','info','error','critical'):
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % loglevel)
        logger.setLevel(numeric_level)


parser = argparse.ArgumentParser(u'Crée un paquet .deb contenant le dernier waptsetup.exe publié')
parser.add_argument('-l', '--loglevel', help='Change log level (error, warning, info, debug...)')
options = parser.parse_args()

logger = logging.getLogger()
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
if options.loglevel is not None:
    setloglevel(logger,options.loglevel)


if platform.system() != 'Linux':
    logger.error("this script should be used on debian linux")
    sys.exit(1)

try:
    shutil.rmtree(BDIR)
except Exception as e:
    logger.info('Error while deleting %s: %s', BDIR, e)
    pass
try:
    os.unlink(EXE)
except Exception as e:
    logger.info('Error while unlinking %s: %s', EXE, e)
    pass

logger.info('Fetching executable')
logger.debug('Connecting to server %s', SRV)
conn = httplib.HTTPConnection(SRV, '80')
conn.request('GET', BASEPATH)
response = conn.getresponse()
if response.status != 200:
    logger.error('Unexpected response from server (%s)', response.status)
    sys.exit(1)

logger.debug('Parsing response from server')
parser = MyHTMLParser()
parser.feed(response.read())
parser.close()

logger.debug('Filtering results')
regexp = re.compile('waptsetup_rev([0-9]+)\.exe')
revision = 0
latest_exe = None

for cur_exe in parser.wapt_waptsetup_exes:
    match = regexp.search(cur_exe)
    if match:
        cur_rev = match.group(1)
        if cur_rev > revision:
            revision = cur_rev
            latest_exe = cur_exe

if latest_exe is None:
    logger.error('No matching files on server')
    sys.exit(1)

logger.debug('Starting download of %s', BASEPATH + latest_exe)
conn.request('GET', BASEPATH + latest_exe)
response = conn.getresponse()
if response.status != 200:
    logger.error('Unexpected response from server (%s)', response.status)
    sys.exit(1)

out = file(EXE, 'wb')
while True:
    buffer = response.read(2**15)
    if len(buffer) == 0:
        break
    out.write(buffer)
out.close()

logger.info('Correctly fetched %s', EXE)

logger.debug('Getting version from executable')
pe = pefile.PE(EXE)
version = pe.FileInfo[0].StringTable[0].entries['ProductVersion'].strip()
logger.debug('%s version: %s', EXE, version)

logger.info('Creating .deb')
ignore_svn = lambda dir, files: ".svn"
shutil.copytree('./debian/', BDIR + 'DEBIAN/', ignore=ignore_svn)
mkdir_p(BDIR + 'var/www/wapt/')
shutil.copy(EXE, BDIR + 'var/www/wapt/')

output = 'tis-waptsetup-%s-%s.deb' % (version, revision)
dpkg_command = ['dpkg-deb', '--build', BDIR, output]
run(dpkg_command)

logger.info('All done')

shutil.rmtree(BDIR)
os.unlink(EXE)
