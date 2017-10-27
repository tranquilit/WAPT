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
__version__ = '1.5.1.0'

import os
import sys

try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0, os.path.join(wapt_root_dir))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib'))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib', 'site-packages'))

import psutil
import datetime
import subprocess
import getpass
import traceback
import platform

from peewee import *
from playhouse.postgres_ext import *
from playhouse.pool import PooledPostgresqlExtDatabase

from playhouse.shortcuts import dict_to_model, model_to_dict
from playhouse.signals import Model as SignaledModel, pre_save, post_save

from waptutils import ensure_unicode, Version
from waptserver_utils import setloglevel

import json
import codecs
import datetime
import os

import waptserver_config

# You must be sure your database is an instance of PostgresqlExtDatabase in order to use the JSONField.
server_config = waptserver_config.load_config()

import logging
logger = logging.getLogger()

logger.debug('DB connection pool : %s' % server_config['db_max_connections'])
wapt_db = PooledPostgresqlExtDatabase(
    database=server_config['db_name'],
    host=server_config['db_host'],
    user=server_config['db_user'],
    password=server_config['db_password'],
    max_connections=server_config['db_max_connections'],
    stale_timeout=server_config['db_stale_timeout'])


class BaseModel(SignaledModel):

    """A base model that will use our Postgresql database"""
    class Meta:
        database = wapt_db


class ServerAttribs(BaseModel):

    """key/value registry"""
    key = CharField(primary_key=True, null=False, index=True)
    value = BinaryJSONField(null=True)

    @classmethod
    def dump(cls):
        for key, value in cls.select(cls.key, cls.value).tuples():
            print(u'%s: %s' % (key, repr(value)))

    @classmethod
    def get_value(cls, key):
        v = cls.select(cls.value).where(cls.key == key).dicts().first()
        if v:
            return v['value']
        else:
            return None

    @classmethod
    def set_value(cls, key, value):
        with cls._meta.database.atomic():
            try:
                cls.create(key=key, value=value)
            except IntegrityError:
                cls.update(value=value).where(cls.key == key).execute()


class Hosts(BaseModel):

    """
    Inventory informations of a host
    """
    # from bios
    uuid = CharField(primary_key=True, index=True)

    # inventory type data (updated on register)
    computer_fqdn = CharField(null=True, index=True)
    description = CharField(null=True, index=True)
    computer_name = CharField(null=True)
    computer_type = CharField(null=True)  # tower, laptop,etc..
    computer_architecture = CharField(null=True)  # tower, laptop,etc..
    manufacturer = CharField(null=True)
    productname = CharField(null=True)
    serialnr = CharField(null=True)

    host_certificate = TextField(null=True, help_text='Host public X509 certificate bundle')

    #authorized_certificates = ArrayField(CharField, null=True, help_text='authorized packages signers certificates sha1 fingerprint')

    os_name = CharField(null=True)
    os_version = CharField(null=True)
    os_architecture = CharField(null=True)

    # frequently updated data from host update_status
    connected_users = ArrayField(CharField, null=True)
    connected_ips = ArrayField(CharField, null=True)
    mac_addresses = ArrayField(CharField, null=True)
    gateways = ArrayField(CharField, null=True)
    networks = ArrayField(CharField, null=True)
    dnsdomain = CharField(null=True)

    # calculated by server when update_status
    reachable = CharField(20, null=True)

    # for websockets
    server_uuid = CharField(null=True)
    listening_protocol = CharField(10, null=True)
    # in case of websockets, this stores the sid
    listening_address = CharField(null=True)
    listening_port = IntegerField(null=True)
    listening_timestamp = CharField(null=True)

    host_status = CharField(null=True)
    last_seen_on = CharField(null=True)
    last_logged_on_user = CharField(null=True)

    # raw json data
    wapt_status = BinaryJSONField(null=True)
    # running, pending, errors, finished , upgradable, errors,
    last_update_status = BinaryJSONField(null=True)
    host_info = BinaryJSONField(null=True)

    # variable structures... so keep them as json
    dmi = BinaryJSONField(null=True)
    wmi = BinaryJSONField(null=True)

    # audit data
    created_on = DateTimeField(null=True, default=datetime.datetime.now)
    created_by = DateTimeField(null=True)
    updated_on = DateTimeField(null=True, default=datetime.datetime.now)
    updated_by = DateTimeField(null=True)

    def __repr__(self):
        return '<Host fqdn=%s / uuid=%s>' % (self.computer_fqdn, self.uuid)

    @classmethod
    def fieldbyname(cls, fieldname):
        return cls._meta.fields[fieldname]


class HostPackagesStatus(BaseModel):

    """
    Stores the status of packages installed on a host
    """
    host = ForeignKeyField(Hosts, on_delete='CASCADE', on_update='CASCADE')
    package = CharField(null=True, index=True)
    version = CharField(null=True)
    architecture = CharField(null=True)
    locale = CharField(null=True)
    maturity = CharField(null=True)
    section = CharField(null=True)
    priority = CharField(null=True)
    signer = CharField(null=True)
    signer_fingerprint = CharField(null=True)
    description = TextField(null=True)
    install_status = CharField(null=True)
    install_date = CharField(null=True)
    install_output = TextField(null=True)
    install_params = CharField(null=True)
    explicit_by = CharField(null=True)
    repo_url = CharField(max_length=600, null=True)

    # audit data
    created_on = DateTimeField(null=True, default=datetime.datetime.now)
    created_by = DateTimeField(null=True)
    updated_on = DateTimeField(null=True, default=datetime.datetime.now)
    updated_by = DateTimeField(null=True)

    def __repr__(self):
        return '<HostPackageStatus uuid=%s packages=%s (%s) install_status=%s>' % (self.id, self.package, self.version, self.install_status)


class HostSoftwares(BaseModel):
    host = ForeignKeyField(Hosts, on_delete='CASCADE', on_update='CASCADE')
    name = CharField(max_length=2000, null=True, index=True)
    version = CharField(max_length=1000, null=True)
    publisher = CharField(max_length=2000, null=True)
    key = CharField(max_length=600, null=True)
    system_component = CharField(null=True)
    uninstall_string = CharField(max_length=2000, null=True)
    install_date = CharField(null=True)
    install_location = CharField(max_length=2000, null=True)

    # audit data
    created_on = DateTimeField(null=True, default=datetime.datetime.now)
    created_by = DateTimeField(null=True)
    updated_on = DateTimeField(null=True, default=datetime.datetime.now)
    updated_by = DateTimeField(null=True)

    def __repr__(self):
        return '<HostSoftwares uuid=%s name=%s (%s) key=%s>' % (self.uuid, self.name, self.version, self.key)


class HostGroups(BaseModel):
    host = ForeignKeyField(Hosts, on_delete='CASCADE', on_update='CASCADE')
    group_name = CharField(null=False, index=True)

    # audit data
    created_on = DateTimeField(null=True, default=datetime.datetime.now)
    created_by = DateTimeField(null=True)
    updated_on = DateTimeField(null=True, default=datetime.datetime.now)
    updated_by = DateTimeField(null=True)

    def __repr__(self):
        return '<HostGroups uuid=%s group_name=%s>' % (self.uuid, self.group_name)


class HostJsonRaw(BaseModel):
    host = ForeignKeyField(Hosts, on_delete='CASCADE', on_update='CASCADE')

    # audit data
    created_on = DateTimeField(null=True, default=datetime.datetime.now)
    created_by = DateTimeField(null=True)
    updated_on = DateTimeField(null=True, default=datetime.datetime.now)
    updated_by = DateTimeField(null=True)


class HostWsus(BaseModel):
    host = ForeignKeyField(Hosts, on_delete='CASCADE', on_update='CASCADE')
    # windows updates
    wsus = BinaryJSONField(null=True)

    # audit data
    created_on = DateTimeField(null=True, default=datetime.datetime.now)
    created_by = DateTimeField(null=True)
    updated_on = DateTimeField(null=True, default=datetime.datetime.now)
    updated_by = DateTimeField(null=True)


def dictgetpath(adict, pathstr):
    """Iterates a list of path pathstr of the form 'key.subkey.sskey' and returns
        the first occurence in adict which returns not None
    """
    if not isinstance(pathstr, (list, tuple)):
        pathstr = [pathstr]
    for path in pathstr:
        result = adict
        for k in path.split('.'):
            if isinstance(k, (str, unicode)) and isinstance(result, dict):
                # assume this level is an object and returns the specified key
                result = result.get(k)
            elif isinstance(k, int) and isinstance(result, list) and k < len(result):
                # assume this levele is a list and return the n'th item
                result = result[k]
            elif k == '*' and isinstance(result, list):
                # assume this level is an array, and iterates all items
                continue
            elif isinstance(k, (str, unicode)) and isinstance(result, list):
                # iterate through a list returning only a key
                result = [item.get(k) for item in result if item.get(k)]
            else:
                # key not found, we have to retry with next path
                result = None
                break
        if result:
            break
    return result


def set_host_field(host, fieldname, data):
    # these attributes can be transfered as dict
    if fieldname in ['installed_softwares', 'installed_packages']:
        # in case data is transfered as list of tuples instead of list of dict (more compact)
        if data and isinstance(data[0], list):
            rec_data = []
            fieldnames = data[0]
            for rec in data[1:]:
                r = zip(fieldnames, rec)
                rec_data.append(r)
            setattr(host, fieldname, rec_data)
        else:
            setattr(host, fieldname, data)
    else:
        # awfull hack for data containing null char, not accepted by postgresql.
        if fieldname in ('host_info', 'wmi', 'dmi'):
            jsonrepr = json.dumps(data)
            if '\u0000' in jsonrepr:
                logger.warning('Workaround \\u0000 not handled by postgresql json for host %s field %s' % (getattr(host, 'uuid', '???'), fieldname))
                data = json.loads(jsonrepr.replace('\u0000', ' '))

        setattr(host, fieldname, data)
    return host


def update_installed_packages(uuid, installed_packages):
    """Stores packages json data into separate HostPackagesStatus

    Args:
        uuid (str) : unique ID of host
        installed_packages (list): data from host
    Returns:

    """
    # TODO : be smarter : insert / update / delete instead of delete all / insert all ?
    # is it faster ?
    HostPackagesStatus.delete().where(HostPackagesStatus.host == uuid).execute()
    packages = []
    for package in installed_packages:
        package['host'] = uuid
        # filter out all unknown fields from json data for the SQL insert
        packages.append(dict([(k, v) for k, v in package.iteritems() if k in HostPackagesStatus._meta.fields]))
    if packages:
        return HostPackagesStatus.insert_many(packages).execute()
    else:
        return True


def update_installed_softwares(uuid, installed_softwares):
    """Stores softwares json data into separate HostSoftwares table

    Args:
        uuid (str) : unique ID of host
        installed_packages (list): data from host
    Returns:

    """
    # TODO : be smarter : insert / update / delete instead of delete all / insert all ?
    HostSoftwares.delete().where(HostSoftwares.host == uuid).execute()
    softwares = []
    for software in installed_softwares:
        software['host'] = uuid
        # filter out all unknown fields from json data for the SQL insert
        softwares.append(dict([(k, v) for k, v in software.iteritems() if k in HostSoftwares._meta.fields]))
    if softwares:
        return HostSoftwares.insert_many(softwares).execute()
    else:
        return True


def update_host_data(data):
    """Helper function to insert or update host data in db

    Args :
        data (dict) : data to push in DB with at least 'uuid' key
                        if uuid key already exists, update the data
                        eld insert
                      only keys in data are pushed to DB.
                        Other data (fields) are left untouched
    Returns:
        dict : with uuid,computer_fqdn,host_info from db after update
    """
    migrate_map_13_14 = {
        'packages': None,
        'installed_packages': None,
        'softwares': None,
        'installed_softwares': None,

        'update_status': 'last_update_status',
        'host': 'host_info',
        'wapt': 'wapt_status',
        'update_status': 'last_update_status',
    }

    uuid = data['uuid']
    try:
        existing = Hosts.select(Hosts.uuid, Hosts.computer_fqdn).where(Hosts.uuid == uuid).first()
        if not existing:
            logger.debug('Inserting new host %s with fields %s' % (uuid, data.keys()))
            # wapt update_status packages softwares host
            newhost = Hosts()
            for k in data.keys():
                # manage field renaming between 1.3 and >= 1.4
                target_key = migrate_map_13_14.get(k, k)
                if target_key and hasattr(newhost, target_key):
                    set_host_field(newhost, target_key, data[k])

            newhost.save(force_insert=True)
        else:
            logger.debug('Updating %s for fields %s' % (uuid, data.keys()))

            updhost = Hosts.get(uuid=uuid)
            for k in data.keys():
                # manage field renaming between 1.3 and >= 1.4
                target_key = migrate_map_13_14.get(k, k)
                if target_key and hasattr(updhost, target_key):
                    set_host_field(updhost, target_key, data[k])
            updhost.save()

        # separate tables
        # we are tolerant on errors here a we don't know exactly if client send good encoded data
        # but we still want to get host in table
        try:
            if ('installed_softwares' in data) or ('softwares' in data):
                installed_softwares = data.get('installed_softwares', data.get('softwares', None))
                if not update_installed_softwares(uuid, installed_softwares):
                    logger.critical('Unable to update installed_softwares for %s' % uuid)
        except Exception as e:
            logger.critical(u'Unable to update installed_softwares for %s: %s' % (uuid,traceback.format_exc()))

        try:
            if ('installed_packages' in data) or ('packages' in data):
                installed_packages = data.get('installed_packages', data.get('packages', None))
                if not update_installed_packages(uuid, installed_packages):
                    logger.critical('Unable to update installed_packages for %s' % uuid)
        except Exception as e:
            logger.critical(u'Unable to update installed_packages for %s: %s' % (uuid,traceback.format_exc()))

        result_query = Hosts.select(Hosts.uuid, Hosts.computer_fqdn)
        return result_query.where(Hosts.uuid == uuid).dicts().dicts().first(1)

    except Exception as e:
        logger.warning(traceback.format_exc())
        logger.critical(u'Error updating data for %s : %s' % (uuid, ensure_unicode(e)))
        wapt_db.rollback()
        raise e


@pre_save(sender=Hosts)
def wapthosts_pre_save(model_class, instance, created):
    if created:
        instance.created_on = datetime.datetime.now()
    instance.updated_on = datetime.datetime.now()


@pre_save(sender=HostSoftwares)
def hostsoftwares_pre_save(model_class, instance, created):
    if created:
        instance.created_on = datetime.datetime.now()
    instance.updated_on = datetime.datetime.now()


@pre_save(sender=HostPackagesStatus)
def installstatus_pre_save(model_class, instance, created):
    if created:
        instance.created_on = datetime.datetime.now()
    instance.updated_on = datetime.datetime.now()


@pre_save(sender=Hosts)
def wapthosts_json(model_class, instance, created):
    """Stores in plain table fields data from json"""
    # extract data from json into plain table fields
    if (created or Hosts.host_info in instance.dirty_fields) and instance.host_info:
        extractmap = [
            ['computer_fqdn', 'computer_fqdn'],
            ['computer_name', 'computer_name'],
            ['description', 'description'],
            ['manufacturer', 'system_manufacturer'],
            ['productname', 'system_productname'],
            ['os_name', 'windows_product_infos.version'],
            ['os_version', ('windows_version', 'windows_product_infos.windows_version')],
            ['connected_ips', 'connected_ips'],
            ['connected_users', ('connected_users', 'current_user')],
            ['last_loggged_on_user', 'last_loggged_on_user'],
            ['mac_addresses', 'mac'],
            ['dnsdomain', ('dnsdomain', 'dns_domain')],
            ['gateways', 'gateways'],
        ]

        for field, attribute in extractmap:
            setattr(instance, field, dictgetpath(instance.host_info, attribute))

        instance.os_architecture = 'x64' and instance.host_info.get('win64', '?') or 'x86'

    if (created or Hosts.dmi in instance.dirty_fields) and instance.dmi:
        extractmap = [
            ['serialnr', 'Chassis_Information.Serial_Number'],
            ['computer_type', 'Chassis_Information.Type'],
        ]
        for field, attribute in extractmap:
            setattr(instance, field, dictgetpath(instance.dmi, attribute))

    if not instance.connected_ips:
        instance.connected_ips = dictgetpath(instance.host_info, 'networking.*.addr')

    # update host update status based on update_status json data or packages collection
    if not instance.host_status or created or Hosts.last_update_status in instance.dirty_fields:
        instance.host_status = None
        if instance.last_update_status:
            if instance.last_update_status.get('errors', []):
                instance.host_status = 'ERROR'
            elif instance.last_update_status.get('upgrades', []):
                instance.host_status = 'TO-UPGRADE'
        if not instance.host_status:
            instance.host_status = 'OK'


def get_db_version():
    try:
        return Version(ServerAttribs.get(key='db_version').value, 4)
    except:
        return None


def init_db(drop=False):
    wapt_db.get_conn()
    try:
        wapt_db.execute_sql('CREATE EXTENSION hstore;')
    except:
        wapt_db.rollback()
    if drop:
        for table in reversed([ServerAttribs, Hosts, HostPackagesStatus, HostSoftwares, HostJsonRaw, HostWsus,HostGroups]):
            table.drop_table(fail_silently=True)
    wapt_db.create_tables([ServerAttribs, Hosts, HostPackagesStatus, HostSoftwares, HostJsonRaw, HostWsus,HostGroups], safe=True)

    if get_db_version() == None:
        # new database install, we setup the db_version key
        (v, created) = ServerAttribs.get_or_create(key='db_version')
        v.value = __version__
        v.save()

    if get_db_version() != __version__:
        with wapt_db.atomic():
            upgrade_db_structure()
            (v, created) = ServerAttribs.get_or_create(key='db_version')
            v.value = __version__
            v.save()
    return get_db_version()


def upgrade_db_structure():
    """Upgrade the tables version by version"""
    from playhouse.migrate import PostgresqlMigrator, migrate
    migrator = PostgresqlMigrator(wapt_db)
    logger.info('Current DB: %s version: %s' % (wapt_db.connect_kwargs, get_db_version()))

    # from 1.4.1 to 1.4.2
    if get_db_version() < '1.4.2':
        with wapt_db.atomic():
            logger.info('Migrating from %s to %s' % (get_db_version(), '1.4.2'))
            migrate(
                migrator.rename_column(Hosts._meta.name, 'host', 'host_info'),
                migrator.rename_column(Hosts._meta.name, 'wapt', 'wapt_status'),
                migrator.rename_column(Hosts._meta.name, 'update_status', 'last_update_status'),

                migrator.rename_column(Hosts._meta.name, 'softwares', 'installed_softwares'),
                migrator.rename_column(Hosts._meta.name, 'packages', 'installed_packages'),
            )
            HostGroups.create_table(fail_silently=True)
            HostJsonRaw.create_table(fail_silently=True)
            HostWsus.create_table(fail_silently=True)

            (v, created) = ServerAttribs.get_or_create(key='db_version')
            v.value = '1.4.2'
            v.save()

    next_version = '1.4.3'
    if get_db_version() < next_version:
        with wapt_db.atomic():
            logger.info('Migrating from %s to %s' % (get_db_version(), next_version))
            if not [c.name for c in wapt_db.get_columns('hosts') if c.name == 'host_certificate']:
                migrate(
                    migrator.add_column(Hosts._meta.name, 'host_certificate', Hosts.host_certificate),
                )

            (v, created) = ServerAttribs.get_or_create(key='db_version')
            v.value = next_version
            v.save()

    next_version = '1.4.3.1'
    if get_db_version() < next_version:
        with wapt_db.atomic():
            logger.info('Migrating from %s to %s' % (get_db_version(), next_version))
            columns = [c.name for c in wapt_db.get_columns('hosts')]
            opes = []
            if not 'last_logged_on_user' in columns:
                opes.append(migrator.add_column(Hosts._meta.name, 'last_logged_on_user', Hosts.last_logged_on_user))
            if 'installed_sofwares' in columns:
                opes.append(migrator.drop_column(Hosts._meta.name, 'installed_sofwares'))
            if 'installed_sofwares' in columns:
                opes.append(migrator.drop_column(Hosts._meta.name, 'installed_packages'))
            migrate(*opes)

            (v, created) = ServerAttribs.get_or_create(key='db_version')
            v.value = next_version
            v.save()

    next_version = '1.4.3.2'
    if get_db_version() < next_version:
        with wapt_db.atomic():
            logger.info('Migrating from %s to %s' % (get_db_version(), next_version))
            wapt_db.execute_sql('''\
                ALTER TABLE hostsoftwares
                    ALTER COLUMN publisher TYPE character varying(2000),
                    ALTER COLUMN version TYPE character varying(1000);''')
            (v, created) = ServerAttribs.get_or_create(key='db_version')
            v.value = next_version
            v.save()

    next_version = '1.5.0.4'
    if get_db_version() < next_version:
        with wapt_db.atomic():
            logger.info('Migrating from %s to %s' % (get_db_version(), next_version))
            columns = [c.name for c in wapt_db.get_columns('hosts')]
            opes = []
            if not 'server_uuid' in columns:
                opes.append(migrator.add_column(Hosts._meta.name, 'server_uuid', Hosts.server_uuid))
            migrate(*opes)
            (v, created) = ServerAttribs.get_or_create(key='db_version')
            v.value = next_version
            v.save()

    next_version = '1.5.0.11'
    if get_db_version() < next_version:
        with wapt_db.atomic():
            logger.info('Migrating from %s to %s' % (get_db_version(), next_version))
            HostGroups.create_table(fail_silently=True)
            (v, created) = ServerAttribs.get_or_create(key='db_version')
            v.value = next_version
            v.save()

if __name__ == '__main__':
    if platform.system() != 'Windows' and getpass.getuser() != 'wapt':
        print """you should run this program as wapt:
                     sudo -u wapt python /opt/wapt/waptserver/waptserver_model.py  <action>
                 actions : init_db
                           upgrade2postgres"""
        sys.exit(1)

    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
    setloglevel(logger, server_config['loglevel'])

    if len(sys.argv) > 1:
        print sys.argv[1]
        if sys.argv[1] == 'init_db':
            print ('initializing missing wapt tables without dropping data.')
            init_db(False)
            sys.exit(0)
        if sys.argv[1] == 'reset_db':
            print ('Drop existing tables and recreate wapt tables.')
            init_db(True)
            sys.exit(0)
    else:
        print ("""usage :
                python waptserver_model.py init_db
                python waptserver_model.py reset_db
                """)
