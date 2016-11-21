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
__version__ = "1.3.9"

import os,sys
import codecs
import hashlib
import glob

from M2Crypto import EVP, X509, SSL
from M2Crypto.EVP import EVPError
from M2Crypto import BIO,RSA

from waptutils import *

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


def sha1_for_file(fname, block_size=2**20):
    f = open(fname,'rb')
    sha1 = hashlib.sha1()
    while True:
        data = f.read(block_size)
        if not data:
            break
        sha1.update(data)
    return sha1.hexdigest()


def sha1_for_data(data):
    assert(isinstance(data,str))
    sha1 = hashlib.sha1()
    sha1.update(data)
    return sha1.hexdigest()


def sha256_for_file(fname, block_size=2**20):
    f = open(fname,'rb')
    sha256 = hashlib.sha256()
    while True:
        data = f.read(block_size)
        if not data:
            break
        sha256.update(data)
    return sha256.hexdigest()


def sha256_for_data(data):
    assert(isinstance(data,str))
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()


def pwd_callback(*args):
    """Default password callback for opening private keys.
    """
    import getpass
    return getpass.getpass().encode('ascii')


class SSLPrivateKey(object):
    def __init__(self,private_key,callback=pwd_callback):
        if not os.path.isfile(private_key):
            raise Exception('Private key %s not found' % private_key)
        self.private_key_filename = private_key
        self.pwd_callback = callback
        self._rsa = None
        self._key = None

    @property
    def rsa(self):
        if not self._rsa:
            self._rsa = RSA.load_key(self.private_key_filename,callback=self.pwd_callback)
        return self._rsa

    @property
    def key(self):
        if not self._key:
            self._key = EVP.PKey()
            self._key.assign_rsa(self.rsa)
        return self._key

    def sign_content(self,content):
        """ Sign content with the private_key, return the signature"""
        if isinstance(content,unicode):
            content = content.encode('utf8')
        if not isinstance(content,str):
            content = jsondump(content)
        self.key.sign_init()
        self.key.sign_update(content)
        signature = self.key.sign_final()
        return signature

    def match_cert(self,crt):
        """Check if provided public certificate matches the current private key"""
        if not isinstance(crt,SSLCertificate):
            crt = SSLCertificate(crt)
        return crt.get_pubkey().get_modulus() == self.key.get_modulus()

    def matching_certs(self,cert_dir):
        result = []
        for fn in glob.glob(os.path.join(cert_dir,'*.crt')):
            crt = SSLCertificate(fn)
            if crt.match_key(self):
                result.append(crt)
        return result

    def encrypt(self,content):
        """Encrypt a message will can be decrypted with the public key"""
        return self.rsa.private_encrypt(content,RSA.pkcs1_padding)

    def decrypt(self,content):
        """Decrypt a message encrypted with the public key"""
        return self.rsa.private_decrypt(content,RSA.pkcs1_oaep_padding)


class SSLCertificate(object):
    def __init__(self,public_cert):
        self._public_cert_filename = None
        self._crt = None
        self._rsa = None
        self._key = None
        self.public_cert_filename = public_cert

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
                raise Exception('Public certificate %s not found' % value)

    @property
    def crt(self):
        if self._crt is None:
            self._crt = X509.load_cert(self._public_cert_filename)
        return self._crt

    @property
    def rsa(self):
        if not self._rsa:
            self._rsa = self.crt.get_pubkey().get_rsa()
        return self._rsa

    @property
    def key(self):
        if not self._key:
            self._key = EVP.PKey()
            self._key.assign_rsa(self.rsa)
        return self._key

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
    def subject_dn(self):
        return self.crt.get_subject().as_text()

    @property
    def fingerprint(self):
        return self.crt.get_fingerprint()

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

    def verify_content(self,content,signature):
        u"""Check that the signature matches the content

        Args:
            content (str) : content to check. if not str, the structure will be converted to json first
            signature (str) : ssl signature of the content

        Return
            str: subject (CN) of current certificate or raise an exception if no match
        """
        if isinstance(content,unicode):
            content = content.encode('utf8')
        if not isinstance(content,str):
            content = jsondump(content)
        self.key.verify_init()
        self.key.verify_update(content)
        if self.key.verify_final(signature):
            return self.subject_dn
        raise Exception('SSL signature verification failed for certificate %s'%self.subject_dn)

    def match_key(self,key):
        """Check if certificate matches the given private key"""
        if not isinstance(key,SSLPrivateKey):
            key = SSLPrivateKey(key)
        return self.crt.get_pubkey().get_modulus() == key.key.get_modulus()

    def __iter__(self):
        for k in ['issuer_dn','fingerprint','subject_dn','cn']:
            yield k,getattr(self,k)

    def encrypt(self,content):
        """Encrypt a message will can be decrypted with the private key"""
        rsa = self.crt.get_pubkey().get_rsa()
        return rsa.public_encrypt(content, RSA.pkcs1_oaep_padding)

    def decrypt(self,content):
        """Decrypt a message encrypted with the private key"""
        rsa = self.crt.get_pubkey().get_rsa()
        return rsa.public_decrypt(content, RSA.pkcs1_padding)


def ssl_verify_content(content,signature,public_certs):
    u"""Check that the signature matches the content, using the provided list of public keys
        Content, signature are String
        public_certs is either a filename or a list of filenames
    >>> if not os.path.isfile('c:/private/test.pem'):
    ...     key = create_self_signed_key('test',organization='Tranquil IT',locality=u'St Sebastien sur Loire',commonname='wapt.tranquil.it',email='...@tranquil.it')
    >>> my_content = 'Un test de contenu'
    >>> my_signature = SSLPrivateKey('c:/private/test.pem').sign_content(my_content)
    >>> SSLCertificate('c:/private/test.crt').verify_content(my_content,my_signature)
    'C=FR, L=St Sebastien sur Loire, O=Tranquil IT, CN=wapt.tranquil.it/emailAddress=...@tranquil.it'
    """
    assert isinstance(signature,str)
    assert isinstance(public_certs,str) or isinstance(public_certs,unicode) or isinstance(public_certs,list)
    if not isinstance(public_certs,list):
        public_certs = [public_certs]
    for public_cert in public_certs:
        try:
            crt = SSLCertificate(public_cert)
            return crt.verify_content(content,signature)
        except:
            pass
    raise Exception('SSL signature verification failed, either none public certificates match signature or signed content has been changed')


def private_key_has_password(key):
    r"""Return True if key can not be loaded without password
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
            print str(e)
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
