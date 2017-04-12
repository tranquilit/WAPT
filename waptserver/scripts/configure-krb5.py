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
__version__ = "1.4.0"

import subprocess
import socket
import getpass
import platform
import sys
import os
from optparse import OptionParser

usage="""config-krb5.py <option>"""
          

parser=OptionParser(usage=usage,version="1.4.0")
parser.add_option("-d","--dc-name", dest="dc_name", default=None, help="DC to join to (default: %default)")

(options,args) = parser.parse_args()


def type_debian():
    return platform.dist()[0].lower() in ('debian','ubuntu')

def type_redhat():
    return platform.dist()[0].lower() in ('redhat','centos','fedora')


def main(dc_name):
    fqdn = socket.getfqdn()

    # check if specified dc is pingable
    if dc_name:
        response = os.system("ping -c 1 %s " % dc_name)
        #and then check the response...
        if response != 0:
             print ("couldn't not ping dc %s , please check network configuration"  % dc_name)
             sys.exit(1)

    # TODO : should try to ping dc_name

    cmd = """ msktutil --precreate --host %s -b cn=computers --service HTTP --description "Host account for WaptServer" --enctypes 24  """ % (fqdn,)
    if dc_name !='' :
        cmd = "%s --server %s" % (cmd,dc_name)

    print "Excuting shell command : %s " % cmd
    print subprocess.check_output(cmd,shell=True)

    # --server needed only if default dc not suitable for RW operation (rodc, etc.)
    # we support only 0x8=aes128-cts-hmac-sha1 and  0x10=aes256-cts-hmac-sha1 (no DES / RC4)

    # create keytab

    cmd = """msktutil --server dc-nantes --auto-update --keytab /etc/apache2/http-krb5.keytab --host %s""" % (fqdn,)

    if dc_name !='' :
        cmd = "%s --server %s" % (cmd,dc_name)

    print ("Executing shell command : %s " % cmd)
    print (subprocess.check_output(cmd,shell=True))

    print ("Fixing right and ownership")
    print (subprocess.check_output("chown www-data:root /etc/apache2/http-krb5.keytab",shell=True))
    print (subprocess.check_output("chmod 600 /etc/apache2/http-krb5.keytab",shell=True))

if __name__ == "__main__":

    if not type_debian() and not type_redhat():
        print "unsupported distrib"
        sys.exit(1)

    if getpass.getuser()!='root':
        print "Command should be run as root"
        sys.exit(1)

    main(options.dc_name)

