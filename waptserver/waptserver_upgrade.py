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
    upgrade2postgres: import data from running mongodb (wapt <1.4)
    upgrade_structure : update the table structure to most current one.
    reset_database : empty the db and recreate tables.
    import_data : import json files
"""

import os
import sys
import glob

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

from waptserver_config import __version__
from waptserver_model import load_db_config
import platform

import logging
import ConfigParser
from optparse import OptionParser

from waptserver_model import *
from waptserver_utils import *



DEFAULT_CONFIG_FILE = os.path.join(wapt_root_dir, 'conf', 'waptserver.ini')
config_file = DEFAULT_CONFIG_FILE

# setup logging
logger = logging.getLogger()
logging.basicConfig()

# TODO : move to waptserver_upgrade with plain mongo connection.


def create_import_data():
    """Connect to a mongo instance and write all wapt.hosts collection as json into a file"""
    if platform.system()=='Linux':
        mongo_datadir = '/var/lib/mongodb/'
        data = subprocess.check_output('mongoexport -d wapt -c hosts --jsonArray --dbpath=%s' % mongo_datadir,shell=True)
        data = data.replace('\u0000', ' ')
        jsondata = json.load()
    elif platform.system()=='Windows':
        win_mongo_dir ="c:\\wapt\\waptserver\\mongodb"
        cmd  = '%s -d wapt -c hosts --jsonArray --dbpath=%s' % (os.path.join(win_mongo_dir,'mongoexport.exe'),os.path.join(win_mongo_dir,'data'))
        print ('executing mongodb dump using command line : %s' % cmd)
        data = subprocess.check_output(cmd,shell=True)
        data = data.replace('\u0000', ' ')
        jsondata = json.loads(data)
    else:
        print "unsupported platform"
        sys.exit(1)
    return jsondata


def load_json(json_data):
    """Read a json host collection exported from wapt mongo and creates
            Wapt PG Host DB instances"""
    for rec in json_data:
        try:
            uuid = rec['uuid']
            if not uuid:
                uuid = rec['wmi']['Win32_ComputerSystemProduct']['UUID']
            if not 'uuid' in rec:
                rec['uuid'] = uuid
            computer_fqdn = rec.get('host_info', rec.get('host'))['computer_fqdn']
            print update_host_data(rec)
            wapt_db.commit()
        except Exception as e:
            print(u'Error for %s : %s' % (ensure_unicode(computer_fqdn), ensure_unicode(e)))
            wapt_db.rollback()


def comment_mongodb_lines(conf_filename=DEFAULT_CONFIG_FILE):
    if not os.path.exists(conf_filename):
        print ('file %s does not exists!! Exiting ' % conf_filename)
        sys.exit(1)
    data = open(conf_filename)
    new_conf_file_data = ''
    modified = False
    for line in data.readlines():
        line = line.strip()
        if 'mongodb_port' in line:
            line = '#%s' % line
            modified = True
        elif 'mongodb_ip' in line:
            line = '#%s' % line
            modified = True
        new_conf_file_data = new_conf_file_data + line + '\n'
    print new_conf_file_data
    if modified == True:
        os.rename(conf_filename, '%s.%s' % (conf_filename, datetime.datetime.today().strftime('%Y%m%d-%H:%M:%S')))
        with open(conf_filename, 'w') as text_file:
            text_file.write(new_conf_file_data)


def upgrade2postgres():
    """Dump current mongo wapt.hosts collection and feed it to PG DB"""
    # check if mongo is runnina
    print 'upgrading data from mongodb to postgresql'
    mongo_running = False
    if platform.system()=='Linux':
        mongo_procname = 'mongod'
        psql_path = 'psql'

        mongoclient_path = 'mongoexport'
    elif platform.system()=='Windows':
        mongo_procname = 'mongod.exe'
        psql_path = r'c:\wapt\waptserver\pgsql\bin\psql.exe'
    else:
        print('unsupported OS %s' % str(platform.system()))
        sys.exit(1)

    for proc in psutil.process_iter():
        if proc.name() == mongo_procname:
            mongo_running = True

    if not mongo_running:
        print ('mongodb process not running, please check your configuration. Perhaps migration of data has already been done...')
        sys.exit(1)
    cmd ="""  "%s" -U wapt -c " SELECT datname FROM pg_database WHERE datname='wapt';   " """ % psql_path
    val = subprocess.check_output(cmd, shell=True)
    if 'wapt' not in val:
        print ('missing wapt database, please create database first')
        sys.exit(1)


    print ('dumping mongodb data ')
    jsondata = create_import_data()
    try:
        load_json(jsondata)

    except Exception as e:
        traceback.print_exc(file=sys.stdout)
        print ('Exception while loading data, please check current configuration')
        sys.exit(1)


if __name__ == '__main__':
    parser = OptionParser(usage=usage, version='waptserver.py ' + __version__)
    parser.add_option(
        '-c',
        '--config',
        dest='configfile',
        default=DEFAULT_CONFIG_FILE,
        help='Config file full path (default: %default)')

    parser.add_option('-l', '--loglevel', dest='loglevel', default='info', type='choice',
        choices=['debug', 'warning', 'info', 'error', 'critical'],
        metavar='LOGLEVEL', help='Loglevel (default: warning)')

    parser.add_option('-d', '--devel', dest='devel', default=False, action='store_true',
        help='Enable debug mode (for development only)')

    parser.add_option('-p', '--test-prefix', dest='test_prefix', default=None,
        help='test prefix for fqdn and uuid for load testing (for development only)')

    (options, args) = parser.parse_args()
    conf = waptserver_config.load_config(options.configfile)
    load_db_config(conf)

    utils_set_devel_mode(options.devel)
    if options.loglevel is not None:
        setloglevel(logger, options.loglevel)

    action = args and args[0] or 'upgrade_structure'

    if action == 'upgrade2postgres':
        print('Upgrading from mongodb to postgres')
        comment_mongodb_lines(conf_filename=options.configfile)
        upgrade2postgres()
    elif action == 'upgrade_structure':
        print('Updating current PostgreSQL DB Structure')
        init_db(False)
        upgrade_db_structure()
    elif action == 'reset_database':
        print('Reset current PostgreSQL DB Structure')
        init_db(True)
    elif action == 'import_data':
        print('import json data from files %s' % (' '.join(args[1:])))
        for f in args[1:]:
            load_json(f, add_test_prefix=options.test_prefix)
