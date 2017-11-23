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
__version__ = "1.5.1.5"

import os
import sys
import glob

try:
    wapt_root_dir = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0,os.path.join(wapt_root_dir))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib'))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib','site-packages'))

from waptutils import *
from waptcrypto import *
from waptpackage import *

from optparse import OptionParser
import logging

logger = logging.getLogger()

__doc__ = """\
wapt-signpackages -c crtfile package1 package2

Resign a list of packages
"""

def setloglevel(loglevel):
    """set loglevel as string"""
    if loglevel in ('debug','warning','info','error','critical'):
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % loglevel)
        logger.setLevel(numeric_level)



def main():
    parser=OptionParser(usage=__doc__,prog = 'wapt-signpackage')
    parser.add_option("-c","--certificate", dest="public_key", default='', help="Path to the PEM RSA certificate to embed identitiy in control. (default: %default)")
    parser.add_option("-k","--private-key", dest="private_key", default='', help="Path to the PEM RSA private key to sign packages.  (default: %default)")
    #parser.add_option("-w","--private-key-passwd", dest="private_key_passwd", default='', help="Path to the password of the private key. (default: %default)")
    parser.add_option("-l","--loglevel", dest="loglevel", default=None, type='choice',  choices=['debug','warning','info','error','critical'], metavar='LOGLEVEL',help="Loglevel (default: warning)")
    parser.add_option("-i","--if-needed", dest="if_needed", default=False, action='store_true',help="Re-sign package only if needed (default: warning)")
    parser.add_option("-m","--message-digest", dest="md", default='sha256', help="Message digest type for signatures.  (default: %default)")
    parser.add_option("-s","--scan-packages", dest="doscan", default=False, action='store_true', help="Rescan packages and update local Packages index after signing.  (default: %default)")
    parser.add_option("-r","--remove-setup", dest="removesetup", default=False, action='store_true', help="Remove setup.py.  (default: %default)")
    (options,args) = parser.parse_args()

    loglevel = options.loglevel

    if len(logger.handlers) < 1:
        hdlr = logging.StreamHandler(sys.stderr)
        hdlr.setFormatter(logging.Formatter(
            u'%(asctime)s %(levelname)s %(message)s'))
        logger.addHandler(hdlr)

    if loglevel:
        setloglevel(loglevel)
    else:
        setloglevel('warning')

    if len(args) < 1:
        print(parser.usage)
        sys.exit(1)

    if not options.public_key and not options.private_key:
        print('ERROR: No certificate found or specified')
        sys.exit(1)

    cert = SSLCertificate(options.public_key or options.private_key)
    if options.private_key and os.path.isfile(options.private_key):
        key = SSLPrivateKey(options.private_key)
    else:
        key = cert.matching_key_in_dirs()

    if not key:
        print('ERROR: No private key found or specified')
        sys.exit(1)

    args = ensure_list(args)

    ca_bundle = SSLCABundle()
    signers_bundle = SSLCABundle()
    signers_bundle.add_certificates([cert])

    waptpackages = []
    for arg in args:
        waptpackages.extend(glob.glob(arg))

    errors = []
    package_dirs = []
    for waptpackage in waptpackages:
        package_dir = os.path.abspath(os.path.dirname(waptpackage))
        if not package_dir in package_dirs:
            package_dirs.append(package_dir)

        print('Processing %s'%waptpackage)
        try:
            sign_needed=False
            pe = PackageEntry(waptfile = waptpackage)
            if options.removesetup:
                if pe.has_file('setup.py'):
                    with pe.as_zipfile(mode='a') as waptfile:
                        waptfile.remove('setup.py')
                    sign_needed=True

            if options.if_needed:
                try:
                    pe.check_control_signature(cabundle=signers_bundle,signers_bundle=signers_bundle)
                    for md in ensure_list(options.md):
                        if not pe.has_file(pe.get_signature_filename(md)):
                            raise Exception('Missing signature for md %s' % md)
                    logger.info('Skipping %s, already signed properly' % pe.asrequirement())
                    sign_needed = False
                except Exception as e:
                    logger.info('Sign is needed for %s because %s' % (pe.asrequirement(),e))
                    sign_needed = True

            if not options.if_needed or sign_needed:
                pe.sign_package(private_key=key,certificate = cert,mds = ensure_list(options.md))
            print('Done')
        except Exception as e:
            print(u'Error: %s'%ensure_unicode(e.message))
            errors.append([waptpackage,repr(e)])

    if options.doscan:
        for package_dir in package_dirs:
            if os.path.isfile(os.path.join(package_dir,'Packages')):
                print(u'Launching the update of Packages index in %s ...'% ensure_unicode(package_dir))
                repo = WaptLocalRepo(package_dir)
                repo.update_packages_index()
                print('Done')
    else:
        print("Don't forget to rescan your repository with wapt-scanpackages %s" % os.path.dirname(waptpackages[0]))

    if errors:
        print('Package not processed properly: ')
        for fn,error in errors:
            print(u'%s : %s' % (fn,error))

        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
