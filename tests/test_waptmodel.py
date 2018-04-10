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

usage = """\
%prog [-c configfile] [-l loglevel] action

Action:
    upgrade2postgres: import data from mongodb (wapt <1.4)
    upgrade_structure : update the table structure to most current one.
    reset_database : empty the db and recreate tables.
    import_data : import json files
"""

import os
import sys
import glob
import uuid as _uuid

try:
    wapt_root_dir = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            '..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

import site
site.addsitedir(wapt_root_dir)

from waptserver.config import __version__
from waptserver.model import load_db_config
import platform

import logging
import ConfigParser
from optparse import OptionParser

from waptserver.model import *
from waptserver.utils import *

from waptpackage import PackageEntry,WaptLocalRepo

DEFAULT_CONFIG_FILE = os.path.join(r'c:\wapt', 'conf', 'waptserver.ini')
config_file = DEFAULT_CONFIG_FILE

# setup logging
logger = logging.getLogger()
logging.basicConfig()

def test_tableprovider():
    q = TableProvider(query = Hosts.select(
                    Hosts.computer_ad_ou,
                    fn.COUNT(Hosts.uuid).alias('host_count'))
                .where(
                ~Hosts.computer_ad_ou.is_null())
                .group_by(Hosts.computer_ad_ou),
                model = Hosts)
    print q.get_data()
    q = Hosts.select(Hosts.computer_fqdn,fn.COUNT(HostPackagesStatus.package).alias('cnt')).join(HostPackagesStatus).group_by(Hosts.computer_fqdn)
    p = TableProvider(q)
    print(p.get_data())

def test_beforesave():
    h = Hosts(uuid=str(_uuid.uuid4()),computer_fqdn='Test')
    print h.created_on
    h.save()
    print h.created_on

def test_packages():
    repo = WaptLocalRepo('c:/wapt/cache')
    new_packages = Packages.update_from_repo(repo)
    print new_packages

if __name__ == '__main__':
    parser = OptionParser(usage=usage, version=__version__)
    parser.add_option(
        '-c',
        '--config',
        dest='configfile',
        default=DEFAULT_CONFIG_FILE,
        help='Config file full path (default: %default)')

    parser.add_option('-l', '--loglevel', dest='loglevel', default='info', type='choice',
        choices=['debug', 'warning', 'info', 'error', 'critical'],
        metavar='LOGLEVEL', help='Loglevel (default: warning)')

    (options, args) = parser.parse_args()
    setloglevel(logger,options.loglevel)
    conf = waptserver.config.load_config(options.configfile)
    load_db_config(conf)
    test_packages()
    test_beforesave()
    test_tableprovider()
