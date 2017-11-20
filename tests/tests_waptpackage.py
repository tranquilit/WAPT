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
__version__ = "1.5.1.3"
import logging
import sys
import tempfile
import codecs
import certifi

from OpenSSL import crypto
from OpenSSL import SSL

logger = logging.getLogger()
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')

def setloglevel(logger,loglevel):
    """set loglevel as string"""
    if loglevel in ('debug','warning','info','error','critical'):
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(_('Invalid log level: {}').format(loglevel))
        logger.setLevel(numeric_level)

setloglevel(logger,'warning')


from waptutils import *
from waptcrypto import *
from waptpackage import *
from common import *
from waptdevutils import *

import urllib3

# global parameters
key = None
cacert = None
cabundle = None
gest = None
codeur = None

# for private key decrypt
def pwd_callback(*args):
    return str('test')

def setup_test():
    global cabundle
    cabundle = SSLCABundle()
    #cabundle.add_pems('c:/wapt/ssl/*.crt')
    print cabundle.certificates()

    global cacert
    cacert = SSLCertificate(r'c:/private/tranquilit-ca-test.crt')
    cabundle.add_certificates(cacert)

    global key
    key = SSLPrivateKey('c:/private/150.pem',callback = pwd_callback)

    global codeur
    codeur = SSLCertificate(r'c:/private/150-codeur2.crt')
    print("codeur : %s" %codeur)
    assert(codeur.is_code_signing)

    global gest
    gest = SSLCertificate(r'c:/private/150-gest2.crt')
    print("gestionnaire : %s" %gest)
    assert(not gest.is_code_signing)


def test_build_sign_verify_package():
    print('creation paquet test')
    p = PackageEntry(waptfile= 'c:/tranquilit/tis-putty-wapt')
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
        p2.check_package_signature(SSLCABundle(certificates = [gest]))
        raise Exception('Should fail')
    except EWaptCertificateUnknownIssuer as e:
        logger.debug('OK : %s' % e)

    logger.debug('Test avec certificat codeur')
    cert = p2.check_package_signature(SSLCABundle(certificates = [cacert,gest,codeur]))
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



def test_sign_action2():
    action = dict(action='install',package='tis-7zip')
    action_signed = key.sign_claim(action,certificate=gest)
    t1 = time.time()
    for i in range(0,100):
        action_signed = key.sign_claim(action,certificate=gest,attributes=['action'])
    print('Signature 100 fois...: %s' % (time.time()-t1,))

    print('test verification attribut requis')
    try:
        print gest.verify_claim(action_signed,required_attributes=['package'])
        raise Exception('erreur... devrait fail')
    except SSLVerifyException as e:
        print(u'OK: erreur %s'%e)

    print('test verification partielle')
    print gest.verify_claim(action_signed,required_attributes=['action'])

    print('test corruption')
    action_signed = key.sign_claim(action,certificate=gest)
    action_signed['package']='garb'
    try:
        print gest.verify_claim(action_signed,required_attributes=['action'])
        raise Exception('erreur... devrait fail')
    except SSLVerifyException as e:
        print(u'OK: erreur %s'%e)

    print('test replay')
    action_signed = key.sign_claim(action,certificate=gest,attributes=[])
    try:
        time.sleep(2)
        print gest.verify_claim(action_signed,max_age_secs=1,required_attributes=[])
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
    bu = SSLCABundle('c:/wapt/ssl')
    pe = PackageEntry(waptfile=r'C:\Users\htouvet\Downloads\150-putty_0.68-3_all.wapt')
    pe.check_control_signature(bu)



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
    w = Wapt(config_filename= r"C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini")
    #w = Wapt(config_filename= r"C:\tranquilit\wapt\wapt-get.ini")
    w.dbpath=':memory:'
    w._set_fake_hostname('testwaptcomputer.tranquilit.local')

    w.update()
    print w.search()

    w.use_hostpackages = True
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
    print get_private_key_encrypted('c:/private/150-codeur.crt','')
    print get_private_key_encrypted('c:/private/150-codeur.crt','test')
    print SSLPrivateKey('c:/private/150.pem',password='test').modulus
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
    templates = WaptRemoteRepo(url='https://store.wapt.fr/wapt',name='wapt-templates',config = w.config,verify_cert=True)
    localfn = wget('%s/%s'% (templates.repo_url,fn),verify_cert=True)
    res = duplicate_from_file(localfn,'test')
    print res

def test_localrepo_cert():
    r = WaptLocalRepo('c:/wapt/cache')
    r.update_packages_index()

    #list files
    import custom_zip as zipfile
    import StringIO

    with zipfile.ZipFile(open(r.packages_path,'rb'),allowZip64=True) as zip:
        packages_lines = codecs.decode(zip.read(name='Packages'),'UTF-8').splitlines()
        names = zip.namelist()
        #print packages_lines
        for fn in names:
            if fn.startswith('ssl/'):
                cert = SSLCertificate(crt_string=zip.read(name=fn))
                print cert.cn


    print('Done')

def test_editzip():
    r = WaptRemoteRepo('https://wapt142.tranquilit.local/wapt',cabundle=SSLCABundle('c:/tranquilit/wapt/ssl'),verify_cert=False)
    r.update()
    res = r.download_packages('tistest-7zip')
    if res:
        pe = res['packages'][0]
        print pe
        os.startfile(pe.unzip_package( cabundle = r.cabundle))
    print('Done')


def test_editcommon():
    w = Wapt(config_filename= r"C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini")
    w.dbpath=':memory:'
    w.use_hostpackages = False
    w.update()
    pe = w.edit_package('tistest-firefox-esr')
    wapt_sources_edit(pe.sourcespath)

def test_edit_host():
    w = Wapt(config_filename= r"C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini")
    w.dbpath=':memory:'
    w.use_hostpackages = False
    pe = w.edit_host('htlaptop.tranquilit.local')
    assert(pe.version>Version('0'))

def test_findsnsrepourl():
    r = WaptRepo(dnsdomain='tranquilit.local')
    print r.repo_url

def test_installemove_host():
    w = Wapt()
    w.update()
    w.install('htlaptop.tranquilit.local')
    w.remove('htlaptop.tranquilit.local')
    res = w.list_upgrade()
    print res


def test_buildupload():
    w = Wapt(config_filename= r"C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini")
    w.dbpath=':memory:'
    w.use_hostpackages = False
    w.personal_certificate_path='c:/private/150-codeur2.crt'
    w.build_upload('c:/tranquilit/tis-7zip2-wapt',private_key_passwd='test')


def test_matching_certs():
    c = SSLPrivateKey('c:/private/150.pem',password='test')
    certs = c.matching_certs()
    print(certs)
    assert(isinstance(certs,list))
    assert(len(certs)>0)

def test_conflicts():
    w = Wapt(config_filename= r"C:\tranquilit\wapt\wapt-get.ini")
    w.dbpath=':memory:'
    w.install('zip')
    w.use_hostpackages = True
    w.update()
    r = w.check_depends('htlaptop.tranquilit.local')
    print r

def test_certifi_cacert():
    import certifi
    cabundle = SSLCABundle()
    cabundle.add_pems(certifi.where())
    print len(cabundle.certificates())

def test_newcrypto():
    #
    assert(check_key_password('c:/private/150.pem','test'))
    assert(not check_key_password('c:/private/150.pem','badpassword'))
    assert(not check_key_password('c:/private/150.pem'))

    crt = SSLCertificate('c:/private/150-codeur2.crt')
    print crt.fingerprint

    key = SSLPrivateKey('c:/private/150.pem',password='test')
    sign = key.sign_content('test')


    print crt.verify_content('test',sign)
    cabundle = SSLCABundle(certifi.where())
    chain = get_peer_cert_chain_from_server('https://www.google.fr')
    cecert = chain[0]
    print cecert.issuer

    cabundle.check_certificates_chain(chain)
    pass

def test_saveservercert():
    w = Wapt()
    w.waptserver.save_server_certificate(server_ssl_dir='c:/tranquilit/wapt/ssl/server')

def test_get_peer_chain():
    print SSLCABundle(certificates = get_peer_cert_chain_from_server('https://www.google.fr')).as_pem()

    certs = get_peer_cert_chain_from_server('https://www.google.fr')

    bundle = SSLCABundle()
    bundle.add_pems('c:/tranquilit/wapt/tests/ssl/waptrpm-dca.ad.tranquil.it.crt')
    certs = bundle._certificates
    ca = SSLCABundle(certifi.where())

    ca.check_certificates_chain(bundle)


def test_subject_hash():
    crt = SSLCertificate('c:/private/150-codeur2.crt')
    print crt.subject_hash
    print crt.issuer_subject_hash

def test_openssl():
    codeur_bundle = SSLCABundle('c:/private/tranquilit-codeur.crt')
    codeur = codeur_bundle.certificates()[0]
    trusted_ca = SSLCABundle(certifi.where())
    print codeur_bundle.certificate_chain(codeur)

    codeur.verify_signature_with(codeur_bundle)

    print trusted_ca.certificate_chain(codeur)

    for ca in codeur_bundle.certificate_chain(codeur):
        print ca.crl_urls()

    for ca in trusted_ca.certificates():
        print ca.crl_urls()

    store = crypto.X509Store()
    store.set_flags( (
        crypto.X509StoreFlags.CRL_CHECK |
        crypto.X509StoreFlags.CB_ISSUER_CHECK
        ))
    for cert in trusted_ca.certificates():
        store.add_cert(cert.as_X509())

    # load all the crl...
    issuer = trusted_ca.is_known_issuer(codeur)
    crl = requests.get('http://crl.usertrust.com/UTN-USERFirst-Object.crl').content
    crlcert = crypto.load_crl(crypto.FILETYPE_ASN1,crl)
    store.add_crl(crlcert)

    store_ctx = crypto.X509StoreContext(store,cert.as_X509())
    try:
        print store_ctx.verify_certificate()
    except Exception as e:
        print e

def test_crl():
    w = Wapt(config_filename='c:/wapt/wapt-get.ini')
    for crl in w.update_crls(force=True):
        print crl.crl
        print crl.revoked_certs()


def test_self_signed():
    cakey = SSLPrivateKey('c:/tmp/catest.pem')
    cakey.create()
    cakey.save_as_pem()

    cacert = cakey.build_sign_certificate(None,None,
        'Tranquil IT Systems ROOT CA',
        is_code_signing = False,
        )
    cacert.save_as_pem('c:/tranquilit/wapt/cache/catest.crt')

    k = SSLPrivateKey('c:/tmp/test.pem')
    k.create()
    k.save_as_pem()

    c = k.build_sign_certificate(cakey,cacert,cn='HT Codeur',
        organization='Tranquil IT',country='FR',
        crl_url = 'http://127.0.0.1:8088/wapt/test.crl',
        issuer_cert_url = 'http://127.0.0.1:8088/wapt/catest.crt')
    c.save_as_pem('c:/tmp/test.crt')

    assert(c.authority_key_identifier == cacert.subject_key_identifier)
    print c.subject
    print c.key_usage

    print c.verify_signature_with(cacert)

def test_hostcert():
    w = Wapt()
    w.dbpath=':memory:'
    w._set_fake_hostname('testwaptcomputer.tranquilit.local')
    w.create_or_update_host_certificate(force_recreate=True)

def test_hook_action():
    w = Wapt(config_filename= r"C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini")
    w.dbpath=':memory:'
    w.use_hostpackages = False
    w.update()
    d = w.download_packages('tis-seafile')
    pe = d['packages'][0]
    src = pe.unzip_package()
    w.call_setup_hook(src,'update_package')
    print('Done')

def test_update_crl():
    cabundle = SSLCABundle('c:/private')
    cabundle.update_crl(force=True)
    print cabundle.crls
    crl = cabundle.crls[0]
    print crl.verify_signature_with(cabundle)
    cabundle.is_known_issuer(crl)

def test_github():
    gh_server_bundle = get_peer_cert_chain_from_server('https://github.com/')
    cabundle = SSLCABundle()
    cabundle.add_pems(certifi.where())
    print cabundle.check_certificates_chain(gh_server_bundle)
    try:
        print cabundle.check_certificates_chain(SSLCABundle('c:/private/tranquilit-codeur.crt').certificates())
        raise Exception('should fail, expired...')
    except EWaptCertificateExpired:
        print('ok')

    google = get_peer_cert_chain_from_server('https://google.com/')
    print cabundle.check_certificates_chain(google)

def test_update_packages():
    r = WaptLocalRepo('c:/tranquilit/wapt/cache')
    r.update_packages_index()
    cabundle = r.get_certificates()
    print cabundle._certificates
    print cabundle.crls

def test_fernet_encrypt():
    data = open(__file__,'rb').read()
    cert = SSLCertificate('c:/private/htouvet.crt')
    enc_data = cert.encrypt_fernet(data)
    print(len(data),len(enc_data))

    key = SSLPrivateKey('c:/private/htouvet.pem',password='test')
    data2 = key.decrypt_fernet(enc_data)
    print(len(data2))
    assert(data == data2)


def test_is_valid_certificate():
    ca = SSLCABundle()
    ca.add_pems('c:/private/tranquilit-ca-test.crt')
    cert = SSLCertificate('c:/private/htouvet.crt')
    ca.is_valid_certificate(cert)

    ca.clear()
    ca.add_pems(certifi.where())
    #ca.add_pems('c:/private/comodo-ca.crt')
    #caev = SSLCertificate('c:/private/COMODORSAExtendedValidationCodeSigningCA.crt')
    #ca.add_certificates(caev)
    cert = SSLCertificate('c:/private/tranquilit-comodo-ev.crt')
    print cert.issuer_cert_urls()
    print ca.download_issuer_certs(for_certificates = cert)

    ca.update_crl(for_certificates = ca.certificate_chain(cert))
    ca.is_valid_certificate(cert)

    try:
        crt2 = SSLCertificate('c:/private/tranquilit-gest.crt')
        ca.is_valid_certificate(crt2)
        raise Exception('Not trusted..')
    except Exception as e:
        print('OK: %s' % e)


def test_check_certificates_chain():
    ca = SSLCABundle()
    ca.add_pems('c:/private/tranquilit-ca-test.crt')
    cert = SSLCertificate('c:/private/htouvet.crt')
    print ca.check_certificates_chain([cert])

    cert = SSLCertificate('c:/private/tranquilit-comodo-ev.crt')
    print cert.issuer_cert_urls()
    print ca.download_issuer_certs(for_certificates = cert)

    ca.update_crl(for_certificates = ca.certificate_chain(cert))
    print ca.check_certificates_chain([cert])

    open('c:/tmp/myca.pem','wb').write(ca.as_pem())

    crt2 = SSLCertificate('c:/private/tranquilit-gest.crt')
    try:
        print ca.check_certificates_chain([crt2])
        raise Exception('not trusted Self signed')
    except EWaptBadCertificate:
        print('OK : self signed')

    ca.add_certificates(crt2)
    print ca.check_certificates_chain([crt2])
    print('OK')

def test_whole_ca():
    ca = SSLCABundle()
    ca.add_pems('c:/private/crts/ca.crt')
    ca.add_pems('c:/private/crts/crl2.pem')
    ca.add_pems('c:/private/crts/crl.pem')

    certs = SSLCABundle('c:/private/crts/')
    for cert in certs.certificates():
        print cert.subject,cert.serial_number
        try:
            ca.check_if_revoked(cert)
        except (EWaptCertificateRevoked,EWaptCertificateRevoked) as e:
            print e
    print('ok')

def test_partial_chain():
    # test when we don't have root issuer
    ca = SSLCABundle()
    ca.add_pems('c:/private/htouvet.crt')
    #ca.add_pems('c:/private/crts/crl2.pem')
    #ca.add_pems('c:/private/crts/crl.pem')
    certs = SSLCABundle('c:/private/htouvet.crt')
    res = ca.check_certificates_chain(certs)
    print res

def test_update():
    w = Wapt()
    w.dbpath = ':memory:'
    w.use_hostpackages = False
    t1 = time.time()
    w.update(force=True)
    print('update: %ss' % (time.time() - t1,))

def test_download_packages():
    w = Wapt()
    w.dbpath = ':memory:'
    w.use_hostpackages = False
    t1 = time.time()
    w.update()
    res = w.download_packages('tis-firefox-esr')
    print res
    print('download: %ss' % (time.time() - t1,))

def test_hostkey():
    w = Wapt()
    w.dbpath=':memory:'
    w.use_hostpackages = False
    w.update()

def test_encryption_algo():
    k = SSLPrivateKey()
    k.create()
    print k.as_pem('mypassword')


def test_uploadpackages():
    s = WaptServer('http://192.168.100.114:8080')
    s.verify_cert = False
    import uuid
    hosts = []
    for n in range(0,10):
        host = PackageEntry(package=str(uuid.uuid4()),section='host')
        host.depends='test3'
        t = host.build_management_package()
        host.sign_package(gest,key)
        hosts.append(host)
    prog = PackageEntry(waptfile='c:/waptdev/test-mercurial_4.2.1-0_all.wapt')

    result = s.upload_packages(hosts,auth=('admin','password'))
    print result
    if not result['ok'] or result['errors']:
        raise Exception('not uploaded properly')

def test_edit_hosts_depends():
    edit_hosts_depends(r'C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini',
        ['C5921400-3476-11E2-9D6F-F806DF88E3E5','54313B54-F9E3-DC41-9EE5-EBBE7A9BB584'],
        append_depends='socle',key_password='test',wapt_server_user='admin',wapt_server_passwd='password')
    edit_hosts_depends(r'C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini',
        ['C5921400-3476-11E2-9D6F-F806DF88E3E5','54313B54-F9E3-DC41-9EE5-EBBE7A9BB584'],
        remove_depends='socle',key_password='test',wapt_server_user='admin',wapt_server_passwd='password')

def edit_host_raw():
    w = Wapt(config_filename= r'C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini')
    host_id = 'TEST-4C4C4544-004E-3510-8051-C7C04F325131'
    r = WaptHostRepo(name ='wapt-host', host_id=[host_id])
    r.load_config_from_file(w.config_filename)
    host = r.get(host_id)
    if host is None:
        host = PackageEntry(package=host_id,description = 'test host',section='host')
        d = host.build_management_package()
    else:
        host.inc_build()
        host.build_package()
    host.sign_package(gest,key)
    s = WaptServer()
    s.load_config_from_file(w.config_filename)
    res = s.upload_packages([host],auth=('admin','...'))
    print res


if __name__ == '__main__':
    setup_test()
    edit_host_raw()
    test_buildupload()

    test_build_sign_verify_package()
    test_edit_hosts_depends()
    #test_uploadpackages()

    test_waptdevutils()
    test_download_packages()
    test_sign_action2()
    test_sign_action()
    test_encryption_algo()

    test_hostkey()
    test_download_packages()

    test_update()
    test_partial_chain()

    test_whole_ca()
    test_self_signed()
    test_check_certificates_chain()
    test_is_valid_certificate()
    test_fernet_encrypt()
    test_update_packages()
    test_github()
    test_update_crl()
    #test_hook_action()
    test_hostcert()
    test_wapt_engine()
    test_crl()
    #test_openssl()
    test_subject_hash()
    test_get_peer_chain()
    test_saveservercert()
    test_newcrypto()
    #test_oldsignature()
    test_certifi_cacert()
    test_conflicts()
    test_keypassword()
    test_paquet_host()
    #test_buildupload()
    #test_installemove_host()
    test_matching_certs()
    test_findsnsrepourl()
    #test_edit_host()
    test_editcommon()
    test_editzip()
    test_localrepo_cert()

    test_wapt_engine()
    #test_waptdevutils()

    #test_editpackage()
    test_reload_config()
    test_waptrepo()

