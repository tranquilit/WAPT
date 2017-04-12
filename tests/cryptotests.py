#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      htouvet
#
# Created:     14/03/2017
# Copyright:   (c) htouvet 2017
# Licence:     <your licence>
#-------------------------------------------------------------------------------
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.verification import CertificateVerificationContext

##
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID,ExtendedKeyUsageOID,CRLEntryExtensionOID
from cryptography.hazmat.primitives import hashes

ca = x509.load_pem_x509_certificate(open('c:/private/comodo-ca.crt','rb').read(),default_backend())
crt = x509.load_pem_x509_certificate(open('c:/private/tranquilit.crt','rb').read(),default_backend())

ctx = CertificateVerificationContext(ca)
ctx.update(crt)
ctx.verify()



sys.exit(1)
# Generate our key
key = rsa.generate_private_key(
     public_exponent=65537,
     key_size=2048,
     backend=default_backend()
 )

# Write our key to disk for safe keeping
with open("c:/private/mykey.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm= serialization.NoEncryption(),
        #encryption_algorithm= serialization.BestAvailableEncryption(b"passphrase"),
  ))


from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
     # Provide various details about who we are.
     x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
     x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
     x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
 ])).add_extension(
     x509.SubjectAlternativeName([
         # Describe what sites we want this certificate for.
         x509.DNSName(u"mysite.com"),
         x509.DNSName(u"www.mysite.com"),
         x509.DNSName(u"subdomain.mysite.com"),
    ]),
     critical=False,
 # Sign the CSR with our private key.
 ).sign(key, hashes.SHA256(), default_backend())
# Write our CSR out to disk.
with open("path/to/csr.pem", "wb") as f:
     f.write(csr.public_bytes(serialization.Encoding.PEM))


