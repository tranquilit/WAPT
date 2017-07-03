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
__version__ = "1.5.0"
usage = """
This script if aimed at triggering package upgrade through direct http call
for client waptagent <=1.4. It is usefull for triggering upgrades from earlier
waptagent version to wapt 1.5 which uses websockets.

Note :
client version<=1.4 are polled from the server using http requests.
client version >=1.5 use websockets from clients.

trigger_install_all.py [-c configfile] [-l loglevel] [-t timeout] package
"""

import os
import sys

try:
    wapt_root_dir = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            '..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0, os.path.join(wapt_root_dir))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib'))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib', 'site-packages'))

import glob
import requests

import logging
import ConfigParser
from optparse import OptionParser

from playhouse.migrate import *
from waptserver_model import *
from waptserver_utils import *
from waptutils import *

DEFAULT_CONFIG_FILE = os.path.join(wapt_root_dir, 'conf', 'waptserver.ini')
config_file = DEFAULT_CONFIG_FILE

# setup logging
logger = logging.getLogger()
logging.basicConfig()

if __name__ == '__main__':
    parser = OptionParser(usage=usage, version='waptserver.py ' + __version__)
    parser.add_option(
        "-c",
        "--config",
        dest="configfile",
        default=DEFAULT_CONFIG_FILE,
        help="Config file full path (default: %default)")
    parser.add_option(
        "-a",
        "--action",
        dest="action",
        default="update",
        help="Initial action  (default: %default)")
    parser.add_option(
        "-l",
        "--loglevel",
        dest="loglevel",
        default='info',
        type='choice',
        choices=[
            'debug',
            'warning',
            'info',
            'error',
            'critical'],
        metavar='LOGLEVEL',
        help="Loglevel (default: warning)")
    parser.add_option(
        "-t",
        "--timeout",
        dest="timeout",
        default=0.5,
        type='float',
        help="Timeout (default: %default)")

    (options, args) = parser.parse_args()

    timeout = 0.5
    packages = args[0:]
    result_ok = []

    hosts = Hosts.select(Hosts.uuid,Hosts.computer_fqdn,
        Hosts.listening_address,Hosts.listening_port,Hosts.connected_ips,Hosts.wapt_status).where(~Hosts.listening_protocol.is_null() and ~Hosts.connected_ips.is_null())
    try:
            for host in hosts:
                if Version(host.wapt_status['wapt-exe-version']) < Version('1.5.0'):
                    print('processing %s %s' %( host.computer_fqdn,host.connected_ips))
                    params= {}
                    params['uuid'] = host.uuid
                    params['protocol'] = host.listening_protocol
                    params['port'] = host.listening_port
                    params['package'] = ','.join(packages)
                    params['action'] = options.action
                    for address in ensure_list(host.connected_ips):
                        try:
                            params['address'] = address
                            client_result = requests.get("http://%(address)s:8088/%(action)s.json?uuid=%(uuid)s&force=1&notify_server=1" % params,
                                proxies={'http':None,'https':None},verify=False, timeout=options.timeout).text
                            try:
                                client_result = json.loads(client_result)
                                result_ok.append(host.computer_fqdn)
                            except ValueError:
                                if 'Restricted access' in client_result:
                                    print('Forbidden %s' % host.computer_fqdn)
                                else:
                                    print('Error %s : %s' % repr(e))

                            if packages:
                                    print ("sending install command")
                                    client_result = requests.get("http://%(address)s:8088/install.json?uuid=%(uuid)s&package=%(package)s&force=1" % params,
                                        proxies={'http':None,'https':None},verify=False, timeout=options.timeout).text
                                    try:
                                        client_result = json.loads(client_result)
                                        print json.dumps(client_result,indent=True)
                                        print 'OK'
                                        break
                                    except ValueError:
                                        if 'Restricted access' in client_result:
                                            print('Forbidden %s' % host.computer_fqdn)
                                        else:
                                            print('Error %s : %s' % repr(e))
                        except (requests.ConnectTimeout,requests.ConnectionError,requests.ReadTimeout):
                            print('No answer %s' % address)

    finally:
        print('\nresult: \n\n%s'%'\n'.join(result_ok))
