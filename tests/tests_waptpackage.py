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
__version__ = "1.5.0.5"
import logging
import sys

logger = logging.getLogger()
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')

def setloglevel(logger,loglevel):
    """set loglevel as string"""
    if loglevel in ('debug','warning','info','error','critical'):
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(_('Invalid log level: {}').format(loglevel))
        logger.setLevel(numeric_level)

setloglevel(logger,'debug')

from waptutils import *
from waptcrypto import *
from waptpackage import *
from common import *

w = Wapt(config_filename= r"C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini")
w.dbpath=':memory:'

print w.update()
print w.list_upgrade()
print w.repositories
print w.waptserver

certificates = SSLCAChain()
certificates.add_pems('c:/wapt/ssl/*.crt')
print certificates.certificates()

p = PackageEntry().load_control_from_wapt('c:/tranquilit/tis-wapttest-wapt')
print ensure_unicode(p)
p.inc_build()
print p.build_package()

def pwd_callback(*args):
    #print('password callback called with %' % (args,))
    return str('test')

key = SSLPrivateKey('c:/private/150.pem',callback = pwd_callback)
codeur = SSLCertificate(r'c:\wapt\ssl\150.crt')
print("codeur : %s" %codeur)
assert(codeur.is_code_signing)

gest = SSLCertificate(r'c:\wapt\ssl\150-20170529-000000.crt')
print("gestionnaire : %s" %gest)
assert(not gest.is_code_signing)

try:
    print p.sign_package(key,gest)
    raise Exception('Should fail')
except EWaptBadCertificate as e:
    print(u"%s" % e)

print p.sign_package(key,codeur)
print('OK, codeur')

p2= PackageEntry().load_control_from_wapt(p.localpath)
print ensure_unicode(p2)

print p2.check_control_signature(certificates.certificates())
destdir = p2.unzip_package(check_with_certs = certificates.certificates())
print destdir

logger.debug('Test avec sertificat simple')
try:
    p2.check_package_signature(gest)
    raise Exception('Should fail')
except EWaptBadSignature as e:
    logger.debug('OK : %s' % e)

logger.debug('Test avec certificat codeur')
cert = p2.check_package_signature(codeur)
logger.debug('OK : %s' % cert)

logger.debug('Test avec un ensemble de certificats, le codeur le plus recent doit venir')
cert = p2.check_package_signature(certificates.certificates())
logger.debug('OK : %s' % cert)

logger.debug('Corruption setup')
try:
    with open(os.path.join(destdir,'setup.py'),'a') as setup_py:
        setup_py.write('\n')
    cert = p2.check_package_signature(certificates.certificates())
    raise Exception('Should fail corrupted file')
except EWaptCorruptedFiles as e:
    logger.debug('OK : %s' % e)

p2.build_package()
p2.sign_package(key,codeur)
p2.unzip_package()
cert = p2.check_package_signature(certificates.certificates())
p2.remove_localsources()

logger.debug('Corruption control')
try:
    destdir = p2.unzip_package()
    with open(os.path.join(destdir,'WAPT/control'),'a') as control:
        control.write('\n')
    cert = p2.check_package_signature(certificates.certificates())
    raise Exception('Should fail corrupted file')
except EWaptCorruptedFiles as e:
    assert('WAPT/control' in str(e))
    logger.debug('OK : %s' % e)

p2.build_package()
p2.sign_package(key,codeur)
p2.unzip_package()
cert = p2.check_package_signature(certificates.certificates())
p2.remove_localsources()

logger.debug('Corruption attribut control')
try:
    destdir = p2.unzip_package()
    p2.inc_build()
    p2.build_package()
    cert = p2.check_control_signature(certificates.certificates())
    raise Exception('Should fail corrupted file')
except SSLVerifyException as e:
    logger.debug('OK : %s' % e)

logger.debug('OK !')

p2.remove_localsources()
