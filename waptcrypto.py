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
__version__ = "1.5.0.6"

import os,sys
import codecs
import base64
import hashlib
import glob
import subprocess
import logging

from M2Crypto import EVP, X509, SSL, BIO, ASN1
from M2Crypto.EVP import EVPError
from M2Crypto import BIO,RSA
from M2Crypto.RSA import RSAError

from waptutils import *

import datetime

logger = logging.getLogger()

class EWaptCryptoException(Exception):
    pass

class SSLVerifyException(EWaptCryptoException):
    pass

class EWaptEmptyPassword(EWaptCryptoException):
    pass

class EWaptMissingPrivateKey(EWaptCryptoException):
    pass

class EWaptMissingCertificate(EWaptCryptoException):
    pass

class EWaptBadCertificate(EWaptCryptoException):
    pass

class EWaptCertificateUnknowIssuer(EWaptBadCertificate):
    pass

class EWaptCertificateExpired(EWaptBadCertificate):
    pass

class EWaptBadKeyPassword(EWaptCryptoException):
    pass

def check_key_password(key_filename,password=""):
    """Check if provided password is valid to read the PEM private key
    >>> if not os.path.isfile('c:/private/test.pem'):
    ...     create_self_signed_key('test',organization='Tranquil IT',locality=u'St Sebastien sur Loire',commonname='wapt.tranquil.it',email='...@tranquil.it')
    >>> check_key_password('c:/private/test.pem','')
    True
    >>> check_key_password('c:/private/ko.pem','')
    False
    """
    def callback(*args):
        return password
    try:
        EVP.load_key(key_filename, callback)
    except EVPError:
        return False
    return True


def read_in_chunks(f, chunk_size=1024*128):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 128k."""
    while True:
        data = f.read(chunk_size)
        if not data:
            break
        yield data


def hexdigest_for_file(fname, block_size=2**20,md='sha256'):
    digest = hashlib.new(md)
    with open(fname,'rb') as f:
        while True:
            data = f.read(block_size)
            if not data:
                break
            digest.update(data)
        return digest.hexdigest()

def sha1_for_file(fname, block_size=2**20):
    return hexdigest_for_file(fname, block_size=2**20,md='sha1')

def sha256_for_file(fname, block_size=2**20):
    return hexdigest_for_file(fname, block_size=2**20,md='sha256')

def hexdigest_for_data(data,md='sha256'):
    digest = hashlib.new(md)
    assert(isinstance(data,str))
    digest.update(data)
    return digest.hexdigest()

def sha256_for_data(data):
    return hexdigest_for_data(data,md='sha256')

def sha1_for_data(data):
    return hexdigest_for_data(data,md='sha1')

def default_pwd_callback(*args):
    """Default password callback for opening private keys.
    """
    import getpass
    i = 3
    while i>0:
        i -= 1
        pwd = getpass.getpass().encode('ascii')
        if pwd:
            return pwd
    raise EWaptEmptyPassword('A non empty password is required')

def NOPASSWORD_CALLBACK(*args):
    pass

class SSLCABundle(object):
    BEGIN_KEY = '-----BEGIN ENCRYPTED PRIVATE KEY-----'
    END_KEY = '-----END ENCRYPTED PRIVATE KEY-----'
    BEGIN_CERTIFICATE = '-----BEGIN CERTIFICATE-----'
    END_CERTIFICATE = '-----END CERTIFICATE-----'

    md = 'sha256'

    def __init__(self,cert_pattern_or_dir=None,callback=None,certificates=None):
        self._keys = {}
        self._certificates = {}
        if callback is None:
            callback = default_pwd_callback
        self.callback = callback
        if cert_pattern_or_dir is not None:
            self.add_pems(cert_pattern_or_dir,load_keys=True)
        if certificates is not None:
            self.add_certificates(certificates)

    def clear(self):
        self._keys.clear()
        self._certificates.clear()

    def add_pems(self,cert_pattern_or_dir='*.crt',load_keys=False):
        if os.path.isdir(cert_pattern_or_dir):
            # load pems from provided directory
            for fn in glob.glob(os.path.join(cert_pattern_or_dir,'*.crt'))+glob.glob(os.path.join(cert_pattern_or_dir,'*.pem')):
                with open(fn,'r') as pem_data:
                    self.add_pem(pem_data.read(),load_keys=load_keys)
        else:
            # load pems based on file wildcards
            for fn in glob.glob(cert_pattern_or_dir):
                with open(fn,'r') as pem_data:
                    self.add_pem(pem_data.read(),load_keys=load_keys)
        return self

    def add_certificates(self,certificates):
        if not isinstance(certificates,list):
            certificates = [certificates]
        for cert in certificates:
            self._certificates[cert.get_fingerprint(md=self.md)] = cert
        return self

    def add_pem(self,pem_data,load_keys=False):
        # parse a bundle PEM with multiple key / certificates
        lines = pem_data.splitlines()
        inkey = False
        incert = False
        tmplines = []
        for line in lines:
            if line == self.BEGIN_CERTIFICATE:
                tmplines = [line]
                incert = True
            elif line == self.END_CERTIFICATE:
                tmplines.append(line)
                crt =  X509.load_cert_string(str('\n'.join(tmplines)))
                cert = SSLCertificate(crt=crt)
                if not cert.is_valid():
                    logger.warning('Certificate %s is not valid' % cert.cn)
                self._certificates[crt.get_fingerprint(md=self.md)] =cert
                incert = False
                tmplines = []
            elif line == self.BEGIN_KEY:
                tmplines = [line]
                inkey = True
            elif line == self.END_KEY:
                tmplines.append(line)
                if load_keys:
                    key = EVP.load_key_string(str('\n'.join(tmplines)),callback=self.callback)
                    self._keys[key.get_modulus()] = SSLPrivateKey(filename,key=key,callback=self.callback)
                inkey = False
                tmplines = []
            else:
                if inkey or incert:
                    tmplines.append(line)
        return self

    def key(self,modulus):
        return self._keys.get(modulus,None)

    def certificate(self,fingerprint=None,subject_hash=None):
        if subject_hash:
            certs = [crt for crt in self.certificates() if crt.subject_hash == subject_hash]
            if certs:
                return certs[0]
            else:
                return None
        else:
            return self._certificates.get(fingerprint,None)

    def certificate_for_cn(self,cn):
        certs = [crt for crt in self.certificates() if crt.cn == cn or glob.fnmatch.fnmatch(cn,crt.cn)]
        if certs:
            return certs[0]
        else:
            return None

    def keys(self):
        return self._keys.values()

    def certificates(self,valid_only=False):
        return [crt for crt in self._certificates.values() if not valid_only or crt.is_valid()]

    def matching_certs(self,key,ca=None,code_signing=None,valid=True):
        return [
            crt for crt in self.certificates() if
                (valid is None or crt.is_valid() == valid) and
                (code_signing is None or crt.is_code_signing == code_signing) and
                (ca is None or crt.is_ca == ca) and
                crt.match_key(key)
                ]

    def certificate_chain(self,crt):
        # bad implementation
        result = [crt]
        issuer = self.certificate(subject_hash=crt.crt.get_issuer().as_hash())
        while issuer and issuer != result[-1] and issuer.is_ca:
            result.append(issuer)
            issuer_subject_hash = issuer.crt.get_issuer().as_hash()
            new_issuer = self.certificate(subject_hash=issuer_subject_hash)
            if new_issuer == issuer:
                break
            else:
                issuer = new_issuer
        return result

    def is_issued_by(self,cacertificate):
        # to be done
        if cacertificate == self:
            return True
        else:
            return False

    def is_known_issuer(self,certificate):
        """Check if certificate is issued by one of this certificate bundle CA

        Return:
            SSLCertificate: issuer certificate or None
        """
        if certificate in self.certificates():
            return certificate
        else:
            for ca in self.certificates():
                if self.is_issued_by(ca):
                    return ca

_tmp_passwd = None

class SSLPrivateKey(object):
    def __init__(self,filename=None,key=None,callback=None,password=None):
        """Args:
            private_key (str) : Filename Path to PEM encoded Private Key
            key (PKey) : Public/[private]  PKey structure
            callback (func) : Called to provide password for the key if needed.
                              If password is set (not None), this parameter is ignored
                              else if None, default is default_pwd_callback.
            password (str) : passpharse to decrypt private key.
                             If '', no decryption and no password is asked. RSA key loadind will fail.

        """
        self.private_key_filename = filename
        if key:
            self.key = key
        if password == '':
            callback = NOPASSWORD_CALLBACK
        else:
            if password is None and callback is None:
                callback = default_pwd_callback
        self.pwd_callback = callback
        self.password = password
        self._rsa = None
        self._key = None

    def create(self,bits=2048):
        """Create RSA"""
        self._rsa = RSA.gen_key(bits, 65537, lambda: None)

    def as_pem(self):
        return self.key.as_pem()

    @property
    def rsa(self):
        """access to RSA keys"""
        if not self._rsa:
            global _tmp_passwd
            _tmp_passwd = self.password
            try:
                def local_password_callback(*args):
                    global _tmp_passwd
                    if isinstance(_tmp_passwd,unicode):
                        _tmp_passwd = _tmp_passwd.encode('utf8')
                    if _tmp_passwd is not None:
                        return str(_tmp_passwd)
                    else:
                        return None
                # direct feed of password
                if self.password is not None:
                    self._rsa = RSA.load_key(self.private_key_filename,callback=local_password_callback)
                # password fed using callback
                elif self.pwd_callback != NOPASSWORD_CALLBACK:
                    retry_count = 3
                    while retry_count>0:
                        try:
                            self._rsa = RSA.load_key(self.private_key_filename,callback=self.pwd_callback)
                            break
                        except Exception as e:
                            if 'bad decrypt' in e:
                                if retry_count>0:
                                    retry_count -=1
                                else:
                                    raise EWaptBadKeyPassword(u'Unable to decrypt %s with supplied password'%self.private_key_filename)
                            else:
                                raise
                # no password
                else:
                    self._rsa = RSA.load_key(self.private_key_filename,callback=NOPASSWORD_CALLBACK)
            finally:
                _tmp_passwd = None
        return self._rsa

    @property
    def key(self):
        if not self._key:
            print(u'Key %s'%self.private_key_filename)
            self._key = EVP.PKey()
            self._key.assign_rsa(self.rsa)
        return self._key

    def sign_content(self,content,md='sha256',block_size=2**20):
        """ Sign content with the private_key, return the signature"""
        self.key.reset_context(md=md)
        self.key.sign_init()
        if isinstance(content,unicode):
            content = content.encode('utf8')
        elif isinstance(content,(list,dict)):
            content = jsondump(content)
        if isinstance(content,str):
            self.key.sign_update(content)
        elif hasattr(content,'read'):
            # file like objetc
            while True:
                data = content.read(block_size)
                if not data:
                    break
                self.key.sign_update(data)
        else:
            raise Exception('Bad content type for sign_content, should be either str or file like')
        signature = self.key.sign_final()
        return signature

    def match_cert(self,crt):
        """Check if provided public certificate matches the current private key"""
        if not isinstance(crt,SSLCertificate):
            crt = SSLCertificate(crt)
        return crt.crt.get_pubkey().get_modulus() == self.key.get_modulus()


    def matching_certs(self,cert_dir=None,ca=None,code_signing=None,valid=None):
        if cert_dir is None and self.private_key_filename:
            cert_dir = os.path.dirname(self.private_key_filename)
        result = []
        for fn in glob.glob(os.path.join(cert_dir,'*.crt')):
            try:
                crt = SSLCertificate(fn)
                if (valid is None or crt.is_valid() == valid) and\
                   (code_signing is None or crt.is_code_signing == code_signing) and\
                   (ca is None or crt.is_ca == ca) and\
                   crt.match_key(self):
                        result.append(crt)
            except ValueError as e:
                logger.critical('Certificate %s can not be read. Skipping. Error was:%s' % (fn,repr(e)))
        return result

    def encrypt(self,content):
        """Encrypt a message will can be decrypted with the public key"""
        return self.rsa.private_encrypt(content,RSA.pkcs1_padding)

    def decrypt(self,content):
        """Decrypt a message encrypted with the public key"""
        return self.rsa.private_decrypt(content,RSA.pkcs1_oaep_padding)

    @property
    def modulus(self):
        return self.key.get_modulus()

    def __cmp__(self,key):
        return cmp(self.modulus,key.modulus)

    def __repr__(self):
        return '<SSLPrivateKey %s>' % repr(self.private_key_filename)

    def sign_claim(self,claim,attributes=None,certificate=None):
        assert(isinstance(claim,dict))
        if attributes is None:
            attributes = claim.keys()
        if certificate is None:
            certificates = sorted(self.matching_certs(valid=True))
            if certificates:
                certificate = certificates[-1]
            else:
                raise EWaptBadCertificate('Missing certificate for %s' % self.private_key_filename)

        signature_attributes = ['signed_attributes','signer','signature_date','signer_fingerprint']
        for att in signature_attributes:
            if att in attributes:
                attributes.remove(att)

        reclaim = {att:claim.get(att,None) for att in attributes}
        reclaim['signed_attributes'] = attributes+signature_attributes
        reclaim['signer'] = certificate.cn
        reclaim['signature_date'] = datetime.datetime.now().isoformat()
        reclaim['signer_fingerprint'] = certificate.fingerprint
        signature = base64.b64encode(self.sign_content(reclaim))
        reclaim['signature'] = signature
        return reclaim


class SSLCertificate(object):
    """Hold a X509 public certificate"""
    def __init__(self,crt_filename=None,crt=None,crt_string=None,ignore_validity_checks=False):
        """
        Args:
            public_cert (str): File Path to X509 encoded certificate
            crt (: X509 SSL Object
            crt_string (str): X09 PEM encoded string
        """
        self._public_cert_filename = None
        self._crt = None
        self._rsa = None
        self._key = None
        self.public_cert_filename = crt_filename
        if crt:
            self._crt = crt
        elif crt_string:
            self._crt = X509.load_cert_string(str(crt_string))
        self.ignore_validity_checks = ignore_validity_checks

    def as_pem(self):
        return self.crt.as_pem()

    @property
    def public_cert_filename(self):
        return self._public_cert_filename

    @public_cert_filename.setter
    def public_cert_filename(self,value):
        if value != self._public_cert_filename:
            self._public_cert_filename = value
            self._crt = None
            self._rsa = None
            self._key = None
            self._crt = None
            if not os.path.isfile(value):
                raise EWaptMissingCertificate('Public certificate %s not found' % value)

    @property
    def crt(self):
        if self._crt is None:
            self._crt = X509.load_cert(self._public_cert_filename)
        return self._crt

    @property
    def rsa(self):
        """Return public RSA keys"""
        if not self._rsa:
            self._rsa = self.crt.get_pubkey().get_rsa()
        return self._rsa

    @property
    def key(self):
        """Return public key"""
        if not self._key:
            self._key = EVP.PKey()
            self._key.assign_rsa(self.rsa)
        return self._key

    @property
    def modulus(self):
        return self.crt.get_pubkey().get_modulus()

    @property
    def organisation(self):
        return self.crt.get_subject().O

    @property
    def cn(self):
        return self.crt.get_subject().CN

    @property
    def subject(self):
        subject = self.crt.get_subject()
        result = {}
        for key in subject.nid.keys():
            result[key] = getattr(subject,key)
        return result

    @property
    def subject_hash(self):
        return self.crt.get_subject().as_hash()

    @property
    def subject_dn(self):
        return self.crt.get_subject().as_text()

    def get_fingerprint(self,md='sha256'):
        return self.crt.get_fingerprint(md=md)

    @property
    def fingerprint(self):
        return self.crt.get_fingerprint(md='sha256')

    @property
    def issuer(self):
        data = self.crt.get_issuer()
        result = {}
        for key in data.nid.keys():
            result[key] = getattr(data,key)
        return result

    @property
    def issuer_dn(self):
        return self.crt.get_issuer().as_text()

    def verify_content(self,content,signature,md='sha256',block_size=2**20):
        u"""Check that the signature matches the content

        Args:
            content (str) : content to check. if not str, the structure will be converted to json first
            signature (str) : ssl signature of the content

        Return
            str: subject (CN) of current certificate or raise an exception if no match

        Raise SSLVerifyException
        """
        self.key.reset_context(md=md)
        self.key.verify_init()
        if isinstance(content,unicode):
            content = content.encode('utf8')
        elif isinstance(content,(list,dict)):
            content = jsondump(content)

        if isinstance(content,str):
            self.key.verify_update(content)
        elif hasattr(content,'read'):
            # file like objetc
            while True:
                data = content.read(block_size)
                if not data:
                    break
                self.key.verify_update(data)
        else:
            raise Exception('Bad content type for verify_content, should be either str or file like')

        if self.key.verify_final(signature):
            return self.subject_dn
        raise SSLVerifyException('SSL signature verification failed for certificate %s'%self.subject_dn)

    def match_key(self,key):
        """Check if certificate matches the given private key"""
        if not isinstance(key,SSLPrivateKey):
            key = SSLPrivateKey(key)
        return self.crt.get_pubkey().get_modulus() == key.key.get_modulus()

    def matching_key_in_dirs(self,directories=None,password_callback=None,private_key_password=None):
        """Return the first SSLPrivateKey matching this certificate

        Args:
            directories (list): list of directories to look for pem encoded private key files
                                if None, look in the same directory as certificate file.

        Returns:
            SSLPrivateKey : or None if nothing found.

        >>> crt = SSL
        """
        if directories is None:
            directories = os.path.abspath(os.path.dirname(self.public_cert_filename))
        directories = ensure_list(directories)

        for adir in directories:
            for akeyfile in glob.glob(os.path.join(adir,'*.pem')):
                try:
                    key = SSLPrivateKey(os.path.abspath(akeyfile),callback = password_callback,password = private_key_password)
                    if key.match_cert(self):
                        return key
                    else:
                        break
                except RSAError as e:
                    if (e.message == 'padding check failed') or ('decrypt' in e.message):
                        pwd_try_count -= 1
                    else:
                        break
                except Exception as e:
                    print('Error for %s: %s'%(akeyfile,e))
                    break
        return None

    @property
    def not_before(self):
        result = self.crt.get_not_before().get_datetime()
        return result

    @property
    def not_after(self):
        result = self.crt.get_not_after().get_datetime()
        return result

    def is_revoked(self):
        ca_info = self.extensions
        return False

    def is_valid(self,ca_bundle=None):
        """Check validity of certificate
                not before / not after
            if ca_bundle is provided, check that the certificate is issued by a known ca
            if issuer_cert is provided, check that the certificate is issued by this issuer
        """
        if self.ignore_validity_checks:
            return True
        nb,na = self.not_before,self.not_after
        now = datetime.datetime.now(nb.tzinfo)
        return \
            now >= nb and now <= na and \
            (ca_bundle is None or ca_bundle.check_is_known_issuer(self))

    def __iter__(self):
        for k in ['issuer_dn','fingerprint','subject_dn','cn','is_code_signing','is_ca']:
            yield k,getattr(self,k)

    def __str__(self):
        return u'SSLCertificate cn=%s'%self.cn

    def __repr__(self):
        return '<SSLCertificate cn=%s issuer=%s validity=%s - %s Code-Signing=%s CA=%s>'%\
            (repr(self.cn),repr(self.issuer.get('CN','?')),
            self.not_before.strftime('%Y-%m-%d'),
            self.not_after.strftime('%Y-%m-%d'),
            self.is_code_signing,self.is_ca)

    def __cmp__(self,crt):
        if isinstance(crt,SSLCertificate):
            return cmp((self.is_valid(),self.is_code_signing,self.not_before,self.not_after,self.fingerprint),
                            (crt.is_valid(),crt.is_code_signing,crt.not_before,crt.not_after,crt.fingerprint))
        elif isinstance(crt,dict):
            return cmp(self.subject,crt)
        else:
            raise ValueError('Can not compare SSLCertificate with %s'%(type(crt)))

    def encrypt(self,content):
        """Encrypt a message will can be decrypted with the private key"""
        rsa = self.crt.get_pubkey().get_rsa()
        return rsa.public_encrypt(content, RSA.pkcs1_oaep_padding)

    def decrypt(self,content):
        """Decrypt a message encrypted with the private key"""
        rsa = self.crt.get_pubkey().get_rsa()
        return rsa.public_decrypt(content, RSA.pkcs1_padding)

    def extensions(self):
        result = {}
        for i in range(0,self.crt.get_ext_count()):
            e =  self.crt.get_ext_at(i)
            prop = e.get_name()
            if prop in result:
                # convert to list as several items in the property
                result[prop] = [result[prop]].append(e.get_value())
            else:
                result[prop] = e.get_value()
        return result

    @property
    def is_ca(self):
        """Return Tue if certificate has CA:TRUE baisc contraints"""
        return 'CA:TRUE' in ensure_list(self.extensions().get('basicConstraints',''))

    @property
    def is_code_signing(self):
        """Return True id certificate has 'Code Signing' in its extenedKeyUsage"""
        return 'Code Signing' in ensure_list(self.extensions().get('extendedKeyUsage',''))

    def verify(self,CAfile,check_errors=True):
        """Check validity of certificate against list of CA and validity
        Raise error if not OK
        """
        wapt_basedir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
        openssl_bin = os.path.join(wapt_basedir,'lib','site-packages','M2Crypto','openssl.exe')
        certfile = self.public_cert_filename
        print '"%(openssl_bin)s" verify -CAfile "%(CAfile)s" "%(certfile)s"' % locals()
        p = subprocess.Popen('"%(openssl_bin)s" verify -CAfile "%(CAfile)s" "%(certfile)s"' % locals(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        check_output = p.communicate()[0]

        errors = []
        result = False
        for output in check_output.splitlines():
            if output.startswith('error'):
                error = output.rsplit(':',1)[1]
                if check_errors and 'certificate has expired' in error:
                    raise EWaptCertificateExpired('Certificate %s error: %s'%(self.public_cert_filename,error))
                elif check_errors and 'unable to get local issuer certificate' in error:
                    raise EWaptCertificateUnknowIssuer('Certificate %s error: %s'%(self.public_cert_filename,error))
                else:
                    raise EWaptBadCertificate('Certificate %s error: %s'%(self.public_cert_filename,error))
                errors.append(errors)
            if output=='OK':
                result = True
        logger.debug(check_output)
        if not result:
            raise EWaptCertificateUnknowIssuer('Unknown issuer for %s' % (self.public_cert_filename))
        return result

    def verify_claim(self,claim,max_age_secs=None):
        """Verify a simple dict signed with SSLPrivateKey.sign_claim
        Args:
            claim (dict) : with keys signature,signed_attributes,signer,signature_date
        Returns:
            dict: signature_date,signer,verified_by(cn)

        >>> key = SSLPrivateKey('c:/private/150.pem')
        >>> crt = SSLCertificate('c:/private/150.crt')
        >>> action = dict(action='install',package='tis-7zip')
        >>> action_signed
            {'action': None,
             'package': None,
             'signature': 'jSJbX3sPmiEBRxN3Sue4fTSlJ2Q6llUSOIkleCm4NyFQlSc0KvLKbtlmHxvYV7mPW3TDYjfhkuQSG0ZfQQmo0r+zcA9ZL075P/vNLkxwElOYacMtBBObsxhPU7DKc4AdQMorgSfSEpW4a/Zq5VPJy9q6vBJxSzZjnHGmuPYlfQKuedP1dY6ifCrcAelKEZOKZl5LJl6e0NHeiXy3+3e4bm8V2VtDPCbvVKtIMRgA5qtDDrif3IauwzUyzEpnC0d229ynz6LAj5WdZR32HtV0g5aJ5ye5rQ+IAcGJSbxQ3EJZQhZy1wZ6WUVsF9/mXLbR/d1xRl9M0CqI+8eUvQWD2g==',
             'signature_date': '20170606-163401',
             'signed_attributes': ['action', 'package'],
             'signer': '150',
             'signer_fingerprint': '88654A5A946B8BFFFAC7F61A2E21B7F02168D5E4'}
        >>> action_signed = key.sign_claim(action,certificate=crt)
        >>> print crt.verify_claim(action_signed)
        {'signer': '150', 'verified_by': '150', 'signature_date': '20170606-163401'}
        """
        assert(isinstance(claim,dict))
        attributes = claim['signed_attributes']
        reclaim = {att:claim.get(att,None) for att in attributes}
        signature = claim['signature'].decode('base64')

        if max_age_secs is not None:
            signature_date = isodate2datetime(claim['signature_date'])
            delta = abs(datetime.datetime.now() - signature_date)
            if delta > datetime.timedelta(seconds=max_age_secs):
                raise SSLVerifyException('Data too old or in the futur age : %ss...' % delta.seconds)
        self.verify_content(reclaim,signature)
        return dict(
            signature_date=claim['signature_date'],
            signer=claim['signer'],
            verified_by=self.cn,
            )


def private_key_has_password(key):
    r"""Return True if key can not be loaded without password

    Args;

    >>> private_key_has_password(r'c:/tranquilit/wapt/tests/ssl/test.pem')
    False
    >>> private_key_has_password(r'c:/tmp/ko.pem')
    True
    """
    def callback(*args):
        return ""
    try:
        EVP.load_key(key, callback)
    except Exception as e:
        if "bad password" in str(e):
            return True
        else:
            print(str(e))
            return True
    return False


if __name__ == '__main__':
    import doctest
    import sys
    reload(sys)
    sys.setdefaultencoding("UTF-8")
    import doctest
    doctest.ELLIPSIS_MARKER = '???'
    doctest.testmod(optionflags=doctest.ELLIPSIS)
    sys.exit(0)
