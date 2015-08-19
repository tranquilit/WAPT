#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013-2015  Tranquil IT Systems http://www.tranquil.it
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
__version__="1.3.1"

import os,sys
try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0,os.path.join(wapt_root_dir))
sys.path.insert(1,os.path.join(wapt_root_dir,'lib'))
sys.path.insert(2,os.path.join(wapt_root_dir,'lib','site-packages'))

from huey import Huey
from huey.backends.sqlite_backend import SqliteQueue
import ConfigParser


_defaults = {
    'client_tasks_timeout': 0.5,
    'clients_connect_timeout': 5,
    'clients_read_timeout': 5,
    'loglevel': 'warning',
    'mongodb_ip': "127.0.0.1",
    'mongodb_port': "38999",
    'secret_key': 'NOT DEFINED',
    'server_uuid': '',
    'wapt_folder': os.path.join(wapt_root_dir, 'waptserver','repository','wapt'),
    'wapt_huey_db': '/tmp/wapthuey.db',
    'wapt_password': '',
    'wapt_user': 'admin',
    'waptserver_port': 8080,
    'waptservice_port': 8088,
    'waptwua_folder': '', # default: wapt_wolder + 'wua'
}

_default_config_file = os.path.join(wapt_root_dir, 'waptserver', 'waptserver.ini')

def load_config(cfgfile=_default_config_file):

    conf = _defaults.copy()

    # read configuration from waptserver.ini
    _config = ConfigParser.RawConfigParser()
    if os.path.exists(cfgfile):
        _config.read(cfgfile)
    else:
        raise Exception(_("FATAL : couldn't open configuration file : {}.".format(options.configfile)))

    if not _config.has_section('options'):
        raise Exception (_("FATAL, configuration file {} has no section [options]. Please check the waptserver documentation.").format(options.configfile))

    if _config.has_option('options', 'client_tasks_timeout'):
        conf['client_tasks_timeout'] = int(_config.get('options', 'client_tasks_timeout'))

    if _config.has_option('options', 'clients_connect_timeout'):
        conf['clients_connect_timeout'] = int(_config.get('options', 'clients_connect_timeout'))

    if _config.has_option('options', 'clients_read_timeout'):
        conf['clients_read_timeout'] = int(_config.get('options', 'clients_read_timeout'))

    if _config.has_option('options', 'loglevel'):
        conf['loglevel'] = _config.get('options', 'loglevel')

    if _config.has_option('options', 'mongodb_ip'):
        conf['mongodb_ip'] = _config.get('options', 'mongodb_ip')

    if _config.has_option('options', 'mongodb_port'):
        conf['mongodb_port'] = _config.get('options', 'mongodb_port')

    if _config.has_option('options', 'secret_key'):
        config['secret_key'] = _config.get('options','secret_key')

    if _config.has_option('options', 'server_uuid'):
        conf['server_uuid'] = _config.get('options', 'server_uuid')

    if _config.has_option('options', 'wapt_folder'):
        conf['wapt_folder'] = _config.get('options', 'wapt_folder').rstrip('/')

    if _config.has_option('options', 'wapt_huey_db'):
        conf['wapt_huey_db'] = _config.get('options', 'wapt_huey_db')

    if _config.has_option('options', 'wapt_password'):
        conf['wapt_password'] = _config.get('options', 'wapt_password')
    if not conf['wapt_password']:
        raise Exception('wapt_password not defined in config file, Please check the waptserver documentation.')

    if _config.has_option('options', 'wapt_user'):
        conf['wapt_user'] = _config.get('options', 'wapt_user')

    if _config.has_option('options', 'waptserver_port'):
        conf['waptserver_port'] = _config.get('options', 'waptserver_port')

    if _config.has_option('options', 'waptservice_port'):
        conf['waptservice_port'] = _config.get('options', 'waptservice_port')

    # XXX must be processed after conf['wapt_folder']
    if _config.has_option('options', 'waptwua_folder'):
        conf['waptwua_folder'] = _config.get('options', 'waptwua_folder').rstrip('/')
    if not conf['waptwua_folder']:
        conf['waptwua_folder'] = conf['wapt_folder'] + 'wua'

    return conf


conf = load_config()
_queue = SqliteQueue('wapt', conf['wapt_huey_db'])
huey = Huey(_queue)
