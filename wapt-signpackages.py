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

import os
import sys
from waptutils import *
from waptcrypto import *
from waptpackage import *
import glob

try:
    wapt_root_dir = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0,os.path.join(wapt_root_dir))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib'))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib','site-packages'))

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
    parser.add_option("-m","--message-digest", dest="md", default='sha256', type='choice',  choices=['sha1','sha256'], help="Message digest type for signatures.  (default: %default)")
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


    waptpackages = []
    for arg in args:
        waptpackages.extend(glob.glob(arg))

    errors = []
    for waptpackage in waptpackages:
        print('Processing %s'%waptpackage)
        try:
            pe = PackageEntry(waptfile = waptpackage)
            # force md
            pe._md = options.md
            pe.sign_package(private_key=key,certificate = cert)
            print('Done')
        except Exception as e:
            errors.append([waptpackage,repr(e)])

    if errors:
        print('Package not processes properly: ')
        for fn,error in errors:
            print(u'%s : %s' % (fn,error))
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
