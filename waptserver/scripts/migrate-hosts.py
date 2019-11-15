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
from __future__ import absolute_import

import sys
import os

import os,sys
try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),'../..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

from waptutils import __version__

import requests
import json
import ujson
import shutil

from waptpackage import *
from waptcrypto import *
import waptserver.config
from optparse import OptionParser
import getpass

if __name__ == '__main__':
    usage = """\
    %prog [-c configfile] [action]

    Renames host packages from fqdn to UUID.

    """
    parser = OptionParser(usage=usage, version=__version__)
    parser.add_option(
        '-c',
        '--config',
        dest='configfile',
        default=waptserver.config.DEFAULT_CONFIG_FILE,
        help='Config file full path (default: %default)')
    parser.add_option('-d','--devel',dest='devel',default=False,action='store_true',
            help='Enable debug mode (for development only)')
    parser.add_option("-C","--certificate", dest="public_key", default='', help="Path to the PEM RSA certificate to embed identitiy in control. (default: %default)")
    parser.add_option("-K","--private-key", dest="private_key", default='', help="Path to the PEM RSA private key to sign packages.  (default: %default)")


    (options, args) = parser.parse_args()
    conf = waptserver.config.load_config(options.configfile)

    instance = conf.get('application_root','')
    wapt_host_dir =  conf.get('wapt_folder')+'-host'

    cert = SSLCertificate(options.public_key or options.private_key)
    if options.private_key and os.path.isfile(options.private_key):
        key = SSLPrivateKey(options.private_key)
    else:
        key = cert.matching_key_in_dirs()

    server_pwd = getpass.getpass('Admin wapt server password:')

    hosts = ujson.loads(requests.get('http://127.0.0.1:%s/api/v1/hosts?columns=uuid,computer_fqdn' % conf['waptserver_port'],
        auth=('admin',server_pwd),
        proxies={'http':None,'https':None}).content)

    host_map = {}

    for host in hosts['result']:
        host_map[host['computer_fqdn']] = host['uuid']

    import glob
    for host_fn in glob.glob(os.path.join(wapt_host_dir,'*.wapt')):
        host_pe = PackageEntry(waptfile=host_fn)
        if host_pe.package != host_map.get(host_pe.package,host_pe.package):
            print('Renaming %s into %s' % (host_pe.package,host_map.get(host_pe.package,host_pe.package)))
            tmp_dir = host_pe.unzip_package()
            host_pe.package = host_map.get(host_pe.package,host_pe.package)
            host_pe.build_package(target_directory=wapt_host_dir)
            host_pe.sign_package(private_key=key,certificate = cert)
            print(host_pe.localpath)
            os.unlink(host_fn)
            if os.path.isdir(tmp_dir):
                shutil.rmtree(tmp_dir)
        else:
            print('Skip %s' % host_pe.package)
