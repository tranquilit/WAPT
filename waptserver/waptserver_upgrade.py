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
__version__ = "1.4.4"
usage = """\
%prog [-c configfile] [-l loglevel]

  upgrade database
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

import logging
import ConfigParser
from optparse import OptionParser

from playhouse.migrate import *
from waptserver_model import *
from waptserver_utils import *

DEFAULT_CONFIG_FILE = os.path.join(wapt_root_dir, 'conf', 'waptserver.ini')
config_file = DEFAULT_CONFIG_FILE

# setup logging
logger = logging.getLogger()

logging.basicConfig()

parser = OptionParser(usage=usage, version='waptserver.py ' + __version__)
parser.add_option(
    "-c",
    "--config",
    dest="configfile",
    default=DEFAULT_CONFIG_FILE,
    help="Config file full path (default: %default)")
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
    "-d",
    "--devel",
    dest="devel",
    default=False,
    action='store_true',
    help="Enable debug mode (for development only)")

(options, args) = parser.parse_args()

migrator = PostgresqlMigrator(wapt_db)

utils_set_devel_mode(options.devel)

if options.loglevel is not None:
    setloglevel(logger, options.loglevel)

logging.info('Current DB: %s version: %s' % (wapt_db.connect_kwargs,get_db_version()))

# from 1.4.1 to 1.4.2
if get_db_version() < '1.4.2':
    with wapt_db.transaction():
        logging.info('Migrating from %s to %s' % (get_db_version(),'1.4.2'))
        migrate(
            migrator.rename_column(Hosts._meta.name,'host','host_info'),
            migrator.rename_column(Hosts._meta.name,'wapt','wapt_status'),
            migrator.rename_column(Hosts._meta.name,'update_status','last_update_status'),

            migrator.rename_column(Hosts._meta.name,'softwares','installed_softwares'),
            migrator.rename_column(Hosts._meta.name,'packages','installed_packages'),
        )
        HostGroups.create_table(fail_silently=True)
        HostJsonRaw.create_table(fail_silently=True)
        HostWsus.create_table(fail_silently=True)

        (v,created) = ServerAttribs.get_or_create(key='db_version')
        v.value = '1.4.2'
        v.save()

# from 1.4.2 to 1.4.3
if get_db_version() < '1.4.3':
    with wapt_db.transaction():
        logging.info('Migrating from %s to %s' % (get_db_version(),'1.4.3'))
        if not [c.name for c in wapt_db.get_columns('hosts') if c.name == 'host_certificate']:
            migrate(
                migrator.add_column(Hosts._meta.name,'host_certificate',Hosts.host_certificate),
                )

        (v,created) = ServerAttribs.get_or_create(key='db_version')
        v.value = '1.4.3'
        v.save()

# from 1.4.3 to 1.4.4
if get_db_version() < '1.4.3.1':
    with wapt_db.transaction():
        logging.info('Migrating from %s to %s' % (get_db_version(),'1.4.3.1'))
        columns = [c.name for c in wapt_db.get_columns('hosts')]
        opes = []
        if not 'last_logged_on_user' in columns:
            opes.append(migrator.add_column(Hosts._meta.name,'last_logged_on_user',Hosts.last_logged_on_user))
        if 'installed_sofwares' in columns:
            opes.append(migrator.drop_column(Hosts._meta.name,'installed_sofwares'))
        if 'installed_sofwares' in columns:
            opes.append(migrator.drop_column(Hosts._meta.name,'installed_packages'))
        migrate(*opes)

        (v,created) = ServerAttribs.get_or_create(key='db_version')
        v.value = '1.4.3.1'
        v.save()

