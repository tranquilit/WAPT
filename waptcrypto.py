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
__version__ = "1.5.0.8"

import os,sys
import codecs
import base64
import hashlib
import glob
import subprocess
import logging

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding,utils,rsa,AsymmetricVerificationContext,AsymmetricVerificationContext
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.verification import CertificateVerificationContext, InvalidCertificate, InvalidSigningCertificate

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

def check_key_password(key_filename,password=None):
    """Check if provided password is valid to read the PEM private key

    Args:
        password (str): or None if key is not encrypted.

    >>> if not os.path.isfile('c:/private/test.pem'):
    ...     create_self_signed_key('test',organization='Tranquil IT',locality=u'St Sebastien sur Loire',commonname='wapt.tranquil.it',email='...@tranquil.it')
    >>> check_key_password('c:/private/test.pem','')
    True
    >>> check_key_password('c:/private/ko.pem','')
    False
    """
    try:
        with open(key_filename,'rb') as key_pem:
            serialization.load_pem_private_key(key_pem.read(),password or None,default_backend())
    except (TypeError,ValueError) as e:
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

def hash_for_file(fname, block_size=2**20,md='sha256'):
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
    print(args)
    pwd = getpass.getpass().encode('ascii')
    if pwd:
        return pwd
    else:
        return None

def NOPASSWORD_CALLBACK(*args):
    pass


def get_hash_algo(md='sha256'):
    return  {'sha1':hashes.SHA1(),
             'sha256':hashes.SHA256(),
            }.get(md,hashes.SHA256())

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
                cert = SSLCertificate(crt_string =str('\n'.join(tmplines)))
                #if not cert.is_valid():
                #    logger.warning('Certificate %s is not valid' % cert.cn)
                self._certificates[cert.fingerprint] = cert
                incert = False
                tmplines = []
            elif line == self.BEGIN_KEY:
                tmplines = [line]
                inkey = True
            elif line == self.END_KEY:
                tmplines.append(line)
                if load_keys:
                    pem_data = str('\n'.join(tmplines))
                    key = SSLPrivateKey(pem_data = pem_data,callback=self.callback)
                    self._keys[key.modulus] = key
                inkey = False
                tmplines = []
            else:
                if inkey or incert:
                    tmplines.append(line)
        return self

    def key(self,modulus):
        return self._keys.get(modulus,None)

    def certificate(self,fingerprint):
        return self._certificates.get(fingerprint,None)

    def certificate_for_cn(self,cn):
        certs = [crt for crt in self.certificates() if (crt.cn == cn) or (cn and crt.cn and glob.fnmatch.fnmatch(cn,crt.cn))]
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
        issuer_cert = self.certificate(crt.issuer)
        while issuer_cert and issuer_cert != result[-1] and issuer_cert.is_ca:
            result.append(issuer_cert)
            issuer_fingerprint = issuer_cert.fingerprint
            new_issuer = self.certificate(issuer_fingerprint)
            if not new_issuer or new_issuer == issuer_cert:
                if not new_issuer:
                    logger.warning(u'Issuer of %s not found' % issuer_cert.subject)
                break
            else:
                issuer_cert = new_issuer
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
    def __init__(self,filename=None,pem_data=None,callback=None,password = None):
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
        if password == '':
            callback = NOPASSWORD_CALLBACK
        else:
            if password is None and callback is None:
                callback = default_pwd_callback
        self.password_callback = callback
        self.password = password
        self._rsa = None
        if pem_data:
            self.load_key_data(pem_data)

    def create(self,bits=2048):
        """Create RSA"""
        self._rsa = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend())


    def as_pem(self,password=None):
        password = str(password)
        if password is not None:
            enc = serialization.BestAvailableEncryption(password)
        else:
            enc = None
        pem = self._rsa.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=enc,
        )
        return pem

    def save_as_pem(self,filename=None,password=None):
        if filename is None:
            filename = self.private_key_filename
        self.password = password
        self.private_key_filename = filename
        with open(self.private_key_filename,'wb') as f:
            f.write(self.as_pem(password=password))

    def load_key_data(self,pem_data):
        retry_cnt=3
        password = self.password
        while retry_cnt>0:
            try:
                self._rsa = serialization.load_pem_private_key(
                    pem_data,
                    password = password,
                    backend = default_backend())
                self.password = password
                break
            except (TypeError,ValueError) as e:
                if "Password was not given but private key is encrypted" in e.message or\
                        "Bad decrypt. Incorrect password?" in e.message:
                    retry_cnt -= 1
                    password = self.password_callback(self.private_key_filename)
                    if password == '':
                        password = None
                else:
                    raise

    @property
    def rsa(self):
        """access to RSA keys"""
        if not self._rsa:
            with open(self.private_key_filename,'rb') as pem_file:
                self.load_key_data(pem_file.read())
        if not self._rsa:
            raise EWaptEmptyPassword('Unable to load key %s'%self.private_key_filename)
        return self._rsa

    def sign_content(self,content,md='sha256',block_size=2**20):
        """ Sign content with the private_key, return the signature"""
        #apadding = padding.PSS(
        #                mgf=padding.MGF1(hashes.SHA256()),
        #                salt_length=padding.PSS.MAX_LENGTH)
        apadding = padding.PKCS1v15()
        algo = get_hash_algo(md)

        signer = self.rsa.signer(apadding,algo)
        if isinstance(content,unicode):
            content = content.encode('utf8')
        elif isinstance(content,(list,dict)):
            content = jsondump(content)
        if isinstance(content,str):
            signer.update(content)
        elif hasattr(content,'read'):
            # file like objetc
            while True:
                data = content.read(block_size)
                if not data:
                    break
                signer.update(data)
        else:
            raise Exception('Bad content type for sign_content, should be either str or file like')
        signature = signer.finalize()
        return signature

    def match_cert(self,crt):
        """Check if provided public certificate matches the current private key"""
        if not isinstance(crt,SSLCertificate):
            crt = SSLCertificate(crt)
        return crt.modulus == self.modulus


    def matching_certs(self,cert_dir=None,ca=None,code_signing=None,valid=None):
        if cert_dir is None and self.private_key_filename:
            cert_dir = os.path.dirname(self.private_key_filename)
        result = []
        for fn in glob.glob(os.path.join(cert_dir,'*.crt'))+glob.glob(os.path.join(cert_dir,'*.cer'))+glob.glob(os.path.join(cert_dir,'*.pem')):
            try:
                crt = SSLCertificate(fn)
                if (valid is None or crt.is_valid() == valid) and\
                   (code_signing is None or crt.is_code_signing == code_signing) and\
                   (ca is None or crt.is_ca == ca) and\
                   crt.match_key(self):
                        result.append(crt)
            except (TypeError,ValueError) as e:
                logger.debug('Certificate %s can not be read. Skipping. Error was:%s' % (fn,repr(e)))
        return result

    def decrypt(self,content):
        """Decrypt a message encrypted with the public key"""
        apadding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
        return self.rsa.decrypt(content,apadding)

    @property
    def modulus(self):
        return format(self.rsa.private_numbers().public_numbers.n, "x")

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
            crt : cryptography.x509.Certificate
            crt_string (str): X09 PEM encoded string
        """
        self._public_cert_filename = crt_filename
        self._crt = None
        self._rsa = None
        self._key = None
        if crt:
            self._crt = crt
        elif crt_string:
            self._load_cert_data(crt_string)
        self.ignore_validity_checks = ignore_validity_checks

    def _load_cert_data(self,pem_data):
        self._crt = x509.load_pem_x509_certificate(pem_data,default_backend())

    def _load_cert_file(self,filename):
        with open(filename,'rb') as crt_file:
            self._load_cert_data(crt_file.read())

    def as_pem(self):
        return self.crt.public_bytes(serialization.Encoding.PEM)

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

    @property
    def crt(self):
        if self._crt is None:
            if not os.path.isfile(self._public_cert_filename):
                raise EWaptMissingCertificate('Public certificate %s not found' % self._public_cert_filename)
            self._load_cert_file(self._public_cert_filename)
        return self._crt

    @crt.setter
    def crt(self,value):
        if value != self._crt:
            self._public_cert_filename = None
            self._crt = value
            self._rsa = None
            self._key = None

    @property
    def rsa(self):
        """Return public RSA keys"""
        if not self._rsa:
            self._rsa = self.crt.public_key()
        return self._rsa

    def _build_certificate(self,subject, issuer, not_valid_before, not_valid_after,
                          signing_key, public_key, extensions):
        builder = x509.CertificateBuilder().serial_number(
            x509.random_serial_number()
        ).issuer_name(
            issuer
        ).subject_name(
            subject
        ).public_key(
            public_key
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        for ext in extensions:
            builder = builder.add_extension(
                ext.get('extension'), ext.get('critical')
            )
        self.crt = builder.sign(signing_key.key, hash_alg=hashes.SHA256(), backend=default_backend())

    @property
    def modulus(self):
        return format(self.rsa.public_numbers().n, "x")

    def _subject_attribute(self,oid):
        att = self.crt.subject.get_attributes_for_oid(oid)
        if att:
            return att[0].value
        else:
            return None

    @property
    def subject_dn(self):
        return self._subject_attribute(x509.NameOID.DN_QUALIFIER)

    @property
    def organisation(self):
        return self._subject_attribute(x509.NameOID.ORGANIZATION_NAME)

    @property
    def cn(self):
        return self._subject_attribute(x509.NameOID.COMMON_NAME)

    @property
    def subject(self):
        """Returns subject of the certificate as a Dict"""
        subject = self.crt.subject
        result = {}
        for attribute in subject:
            result[attribute.oid._name]= attribute.value
        return result

    def get_fingerprint(self,md='sha256'):
        """Get raw bytes fingerprint"""
        return self.crt.fingerprint(get_hash_algo(md))

    @property
    def fingerprint(self):
        """Get base64 endoded sha256 fingerprint"""
        return base64.b64encode(self.get_fingerprint(md='sha256'))

    @property
    def issuer(self):
        data = self.crt.issuer
        result = {}
        for attribute in data:
            result[attribute.oid._name] = attribute.value
        return result

    @property
    def issuer_dn(self):
        return u','.join([u"%s=%s"%(attribute.oid._name,attribute.value) for attribute in self.crt.issuer])

    def verify_content(self,content,signature,md='sha256',block_size=2**20):
        u"""Check that the signature matches the content

        Args:
            content (str) : content to check. if not str, the structure will be converted to json first
            signature (str) : ssl signature of the content

        Return
            str: subject (CN) of current certificate or raise an exception if no match

        Raise SSLVerifyException
        """
        if isinstance(content,unicode):
            content = content.encode('utf8')
        elif isinstance(content,(list,dict)):
            content = jsondump(content)

        if hasattr(content,'read'):
            # file like object
            # TODO : use prehash
            sha1_for_data
            #while True:
            #    data = content.read(block_size)
            #    if not data:
            #        break
            #    self.key.verify_update(data)
        elif not isinstance(content,str):
            raise Exception('Bad content type for verify_content, should be either str or file like')

        #apadding = padding.PSS(
        #    mgf=padding.MGF1(get_hash_algo(md)),
        #    salt_length=padding.PSS.MAX_LENGTH)

        apadding = padding.PKCS1v15()

        try:
            logger.debug(self.rsa.verify(signature,content,apadding,get_hash_algo(md)))
            return self.cn
        except InvalidSignature as e:
            raise SSLVerifyException('SSL signature verification failed for certificate %s'%self.subject_dn)

    def match_key(self,key):
        """Check if certificate matches the given private key"""
        if not isinstance(key,SSLPrivateKey):
            key = SSLPrivateKey(key)
        return self.modulus == key.modulus

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
                    logger.debug('Testing if key %s match certificate...'% akeyfile)
                    key = SSLPrivateKey(os.path.abspath(akeyfile),callback = password_callback,password = private_key_password)
                    if key.match_cert(self):
                        return key
                except Exception as e:
                    logger.debug('Error for %s: %s'%(akeyfile,e))
        return None

    @property
    def not_before(self):
        result = self.crt.not_valid_before
        return result

    @property
    def not_after(self):
        result = self.crt.not_valid_after
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
        """Encrypt a message will can be decrypted with the public key"""
        apadding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
        return self.rsa.encrypt(content,apadding)

    @property
    def extensions(self):
        return dict([(e.oid._name,e.value) for e in self.crt.extensions])

    @property
    def is_ca(self):
        """Return Tue if certificate has CA:TRUE baisc contraints"""
        return 'basicConstraints' in self.extensions and self.extensions['basicConstraints'].ca

    @property
    def is_code_signing(self):
        """Return True id certificate has 'Code Signing' in its extenedKeyUsage"""
        ext_key_usages = 'extendedKeyUsage' in self.extensions and self.extensions['extendedKeyUsage']
        if ext_key_usages:
            return len([usage for usage in ext_key_usages if usage._name == 'codeSigning'])>0
        else:
            return False

    def verify_old(self,CAfile,check_errors=True):
        """Check validity of certificate against list of CA and validity
        Raise error if not OK
        """
        wapt_basedir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
        openssl_bin = os.path.join(wapt_basedir,'openssl.exe')
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

    def verify_cert(self,cabundle,check_errors=True):
        """Check validity of certificate against list of CA and validity
        Raise error if not OK
        """
        certs = cabundle.certificates()
        verifier = CertificateVerificationContext( )
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



if __name__ == '__main__':
    import doctest
    import sys
    reload(sys)
    sys.setdefaultencoding("UTF-8")
    import doctest
    doctest.ELLIPSIS_MARKER = '???'
    doctest.testmod(optionflags=doctest.ELLIPSIS)
    sys.exit(0)
