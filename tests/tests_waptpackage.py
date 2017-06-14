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
import tempfile
import codecs

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
from waptdevutils import *

import urllib3

# global parameters
key = None
cabundle = None
gest = None
codeur = None

# for private key decrypt
def pwd_callback(*args):
    return str('test')

def setup_test():
    global cabundle
    cabundle = SSLCABundle()
    cabundle.add_pems('c:/wapt/ssl/*.crt')
    print cabundle.certificates()

    global key
    key = SSLPrivateKey('c:/private/150.pem',callback = pwd_callback)

    global codeur
    codeur = SSLCertificate(r'c:/private/150-codeur.crt')
    print("codeur : %s" %codeur)
    assert(codeur.is_code_signing)

    global gest
    gest = SSLCertificate(r'c:/private/150-gest.crt')
    print("gestionnaire : %s" %gest)
    assert(not gest.is_code_signing)

def test_build_sign_verify_package():
    print('creation paquet test')
    p = PackageEntry(waptfile= 'c:/tranquilit/tis-wapttest-wapt')
    print ensure_unicode(p)
    p.inc_build()
    print p.build_package()

    try:
        print(u'Signature paquet test avec clé gestionnaire')
        print p.sign_package(gest,key)
        raise Exception('Should fail, package has a setup.py')
    except EWaptBadCertificate as e:
        print(u"%s" % e)

    print(u'Signature paquet test avec clé codeur')
    print p.sign_package(codeur,key)
    print('OK, codeur')

    p2= PackageEntry(waptfile = p.localpath)
    print u"Paquet testé:\n%s" % ensure_unicode(p2)

    print p2.check_control_signature(cabundle)
    destdir = p2.unzip_package(cabundle = cabundle)
    print destdir

    logger.debug('Test avec certificat simple gestionnaire')
    try:
        p2.check_package_signature(gest)
        raise Exception('Should fail')
    except EWaptBadSignature as e:
        logger.debug('OK : %s' % e)

    logger.debug('Test avec certificat codeur')
    cert = p2.check_package_signature(codeur)
    logger.debug('OK : %s' % cert)

    print('Test avec un ensemble de certificats, le codeur le plus recent doit venir')
    cert = p2.check_package_signature(cabundle)
    assert(cert.is_code_signing)
    print('OK : %s' % cert)

    print('Corruption setup')
    try:
        with open(os.path.join(destdir,'setup.py'),'a') as setup_py:
            setup_py.write('\n')
        cert = p2.check_package_signature(cabundle)
        raise Exception('Should fail corrupted file')
    except EWaptCorruptedFiles as e:
        print('OK : %s' % e)

    p2.delete_localsources()

    destdir = p2.unzip_package()
    print('Corruption ajout fichier au paquet')
    try:
        with open(os.path.join(destdir,'virus'),'w') as afile:
            afile.write('Un virus\n')
        cert = p2.check_package_signature(cabundle)
        raise Exception('Should fail corrupted file')
    except EWaptCorruptedFiles as e:
        print('OK : %s' % e)

    p2.delete_localsources()

    print('Corruption suppression fichier du paquet')
    try:
        destdir = p2.unzip_package()
        os.remove(os.path.join(destdir,'setup.py'))
        cert = p2.check_package_signature(cabundle)
        raise Exception('Should fail corrupted file')
    except (EWaptCorruptedFiles,IOError) as e:
        print('OK : %s' % e)



    p2.build_package()
    p2.sign_package(codeur,key)
    p2.unzip_package(cabundle = cabundle)
    cert = p2.check_package_signature(cabundle)
    p2.delete_localsources()

    logger.debug('Corruption control')
    try:
        destdir = p2.unzip_package()
        with open(os.path.join(destdir,'WAPT/control'),'a') as control:
            control.write('\n')
        cert = p2.check_package_signature(cabundle)
        raise Exception('Should fail corrupted file')
    except EWaptCorruptedFiles as e:
        assert('WAPT/control' in str(e))
        logger.debug('OK : %s' % e)

    p2.build_package()
    p2.sign_package(codeur,key)
    p2.unzip_package()
    cert = p2.check_package_signature(cabundle)
    p2.delete_localsources()

    logger.debug('Corruption attribut control')
    try:
        destdir = p2.unzip_package()
        p2.inc_build()
        p2.build_package()
        cert = p2.check_control_signature(cabundle)
        raise Exception('Should fail corrupted file')
    except SSLVerifyException as e:
        logger.debug('OK : %s' % e)

    logger.debug('OK !')

    p2.delete_localsources()


def test_sign_action():
    action = dict(action='install',package='tis-7zip')
    action_signed = key.sign_claim(action,certificate=gest)
    t1 = time.time()
    for i in range(0,100):
        action_signed = key.sign_claim(action,certificate=gest)
    print('Signature 100 fois...: %s' % (time.time()-t1,))


    print('test verification')
    print gest.verify_claim(action_signed)

    print('test corruption')
    action_signed = key.sign_claim(action,certificate=gest)
    action_signed['package']='garb'
    try:
        print gest.verify_claim(action_signed)
        raise Exception('erreur... devrait fail')
    except SSLVerifyException as e:
        print(u'OK: erreur %s'%e)

    print('test replay')
    action_signed = key.sign_claim(action,certificate=gest)
    try:
        time.sleep(2)
        print gest.verify_claim(action_signed,max_age_secs=1)
        raise Exception('erreur... devrait fail')
    except SSLVerifyException as e:
        print(u'OK: erreur %s'%e)

    print gest.verify_claim(action_signed)
    print('test fake replay')
    action_signed['signature_date']=(datetime.datetime.now()+datetime.timedelta(seconds=10)).isoformat()
    try:
        print gest.verify_claim(action_signed,max_age_secs=50)
        raise Exception('erreur... devrait fail')
    except SSLVerifyException as e:
        print(u'OK: erreur %s'%e)


def test_sign_verify_file():
    print('Tests sign / verify / vitesse sha256')
    t1 = time.time()
    s = key.sign_content(sha256_for_file(r'C:\tranquilit\tis-lazarus-wapt\lazarus-1.6.0-fpc-3.0.0-win32.exe'))
    codeur.verify_content(sha256_for_file(r'C:\tranquilit\tis-lazarus-wapt\lazarus-1.6.0-fpc-3.0.0-win32.exe'),s)
    print time.time()-t1

    t1 = time.time()
    s = key.sign_content(sha256_for_file(r'C:\tranquilit\tis-lazarus-wapt\lazarus-1.6.0-fpc-3.0.0-win32.exe'))
    codeur.verify_content(sha256_for_file(r'C:\tranquilit\tis-lazarus-wapt\lazarus-1.6.0-fpc-3.0.0-win32.exe'),s)
    print time.time()-t1

    t1 = time.time()
    s = key.sign_content(open(r'C:\tranquilit\tis-lazarus-wapt\lazarus-1.6.0-fpc-3.0.0-win32.exe','rb'))
    codeur.verify_content(open(r'C:\tranquilit\tis-lazarus-wapt\lazarus-1.6.0-fpc-3.0.0-win32.exe','rb'),s)
    print time.time()-t1

    t1 = time.time()
    s = key.sign_content(open(r'C:\tranquilit\tis-lazarus-wapt\lazarus-1.6.0-fpc-3.0.0-win32.exe','rb'))
    codeur.verify_content(open(r'C:\tranquilit\tis-lazarus-wapt\lazarus-1.6.0-fpc-3.0.0-win32.exe','rb'),s)
    print time.time()-t1



def test_paquet_host():
    pe = PackageEntry('htlaptop.tranquilit.local',section='host')
    pe.depends = 'tis-7zip'
    old_pe = pe.save_control_to_wapt(fname = tempfile.mkdtemp('wapt'))
    assert(old_pe is None)
    package_filename = pe.build_package()
    assert(os.path.isfile(package_filename))
    signature = pe.sign_package(gest,key)
    assert(isinstance(signature,str))

    pe = PackageEntry(waptfile = package_filename)
    pe.inc_build()
    old_pe = pe.save_control_to_wapt()
    signature = pe.sign_package(gest,key)
    pe.unzip_package()
    print('Les deux certificats sont OK car pas de setup.py')
    print pe.sourcespath
    print pe.check_package_signature(gest)
    print pe.check_package_signature(SSLCABundle(certificates=[codeur,gest]))

    # Ajout d'un setup.py
    codecs.open(os.path.join(pe.sourcespath,'setup.py'),'w',encoding='utf8').write(u"""\
#!/usr/bin/python
# -*- coding: utf-8 -*-
from setuphelpers import *

def install():
    pass

""")
    package_filename = pe.build_package()
    assert(os.path.isfile(package_filename))
    try:
        signature = pe.sign_package(gest,key)
        raise Exception('Doit failer, pas un certificat codeur et setup.py')
    except EWaptBadCertificate as e:
        print(u'OK: %s'%e)

    signature = pe.sign_package(codeur,key)
    print(u'OK: certificat codeur')
    pe.delete_localsources()
    assert('tis-7zip' in ensure_list(pe.depends))
    os.remove(pe.localpath)

def test_oldsignature():
    w = Wapt(config_filename= r"C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini")
    w.dbpath=':memory:'
    pe = PackageEntry(waptfile=r'C:\tranquilit\wapt\cache\tis-ms-pstools_1-5_all.wapt')
    pe.check_control_signature(cabundle)

def test_waptrepo():
    r = WaptRemoteRepo('https://wapt142.tranquilit.local/wapt',cabundle=cabundle,verify_cert=False)
    print r.packages_matching('tis-longtask')
    r = WaptRemoteRepo('https://wapt142.tranquilit.local/wapt',cabundle=cabundle,verify_cert=True)
    try:
        print r.packages
        raise('certificate autosigné, doit failer')
    except requests.exceptions.SSLError as e:
        print('OK: %s' % e)

    # get cert from server
    cert_pem = get_pem_server_certificate('https://wapt142.tranquilit.local')
    assert(SSLCertificate(crt_string=cert_pem).cn == 'wapt142.tranquilit.local')
    with tempfile.NamedTemporaryFile(delete=False) as crtfile:
        crtfile.file.write(cert_pem)
        crtfile.file.close()
        r = WaptRemoteRepo('https://wapt142.tranquilit.local/wapt',cabundle=cabundle,verify_cert=crtfile.name)
        print(r.packages)
        print('OK: certtificate pinning ok')

def test_wapt_engine():
    #w = Wapt(config_filename= r"C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini")
    w = Wapt(config_filename= r"C:\tranquilit\wapt\wapt-get.ini")
    w.dbpath=':memory:'
    w.use_hostpackages = True
    w._set_fake_hostname('testwaptcomputer.tranquilit.local')
    print w.update()
    print w.search()
    print w.list_upgrade()
    for r in w.repositories:
        print r.cabundle
    print w.waptserver
    res = w.update()
    print('OK: %s'%res)


def test_edithost():
    w = Wapt(config_filename= r"C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini")
    w.dbpath=':memory:'
    w.use_hostpackages = False
    w._set_fake_hostname('testwaptcomputer.tranquilit.local')
    pe = w.edit_host('testwaptcomputer.tranquilit.local')
    print pe
    print w.is_available(setuphelpers.get_hostname())

def test_dnsrepos():
    w = Wapt(config_filename= r"C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini")
    w.dbpath=':memory:'
    w.use_hostpackages = False
    w._set_fake_hostname('testwaptcomputer.tranquilit.local')
    w.repositories[0].repo_url = ''
    w.repositories[0].dnsdomain = 'tranquilit.local'
    w.repositories[1].repo_url = ''
    w.repositories[1].dnsdomain = 'tranquilit.local'
    w.update()

def test_reload_config():
    cfn = r"C:\tranquilit\wapt\wapt-get.ini"
    ini = open(cfn,'r').read()
    open(cfn,'wb').write(ini.replace('dnsdomain=tranquilit.local',';dnsdomain=tranquilit.local'))
    w = Wapt(config_filename=cfn )
    w.dbpath=':memory:'
    print w.repositories[1].dnsdomain
    ini = open(cfn,'r').read()
    open(cfn,'wb').write(ini.replace(';dnsdomain=tranquilit.local','dnsdomain=tranquilit.local'))
    print w.reload_config_if_updated()
    print w.repositories[1].dnsdomain


def test_editpackage():
    w = Wapt(config_filename= r"C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini")
    w.dbpath=':memory:'
    w.use_hostpackages = False
    w._set_fake_hostname('testwaptcomputer.tranquilit.local')
    w.update()
    pe = w.edit_package(w.repositories[-1].packages[-1])
    assert(os.path.isdir(pe.sourcespath))
    wapt_sources_edit(pe.sourcespath)

def test_keypassword():
    print get_private_key_encrypted('c:/private/150-codeur.crt','test')
    print SSLPrivateKey('c:/private/150.pem').modulus
    c = SSLCertificate('c:/private/150-codeur.crt')
    try:
        k = c.matching_key_in_dirs()
    except RSAError as e:
        print e
        raise

def test_waptdevutils():
    cfn = r"C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini"
    results = get_packages_filenames(cfn,'tis-7zip',repo_name='wapt-templates')
    (fn,md5) = results[0]
    w = Wapt(config_filename=cfn)
    templates = WaptRemoteRepo(url='https://store.wapt.fr/wapt',name='wapt-templates',config = w.config)
    localfn = wget('%s/%s'% (templates.repo_url,fn))
    res = duplicate_from_file(cfn,localfn)
    print res



if __name__ == '__main__':
    setup_test()
    test_keypassword()

    test_wapt_engine()
    test_waptdevutils()

    test_paquet_host()
    test_editpackage()
    test_reload_config()
    test_edithost()

    test_waptrepo()
    test_oldsignature()
    test_build_sign_verify_package()
    test_sign_action()
