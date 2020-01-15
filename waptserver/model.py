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

import os
import sys
import uuid as _uuid

import psutil
import datetime
import subprocess
import getpass
import traceback
import platform
import hashlib
import re

from peewee import *
from peewee import Function
from waptserver.config import __version__

from playhouse.postgres_ext import *
from playhouse.pool import PooledPostgresqlExtDatabase

from playhouse.shortcuts import dict_to_model, model_to_dict
from playhouse.signals import Model as SignaledModel, pre_save, post_save

from waptutils import Version
from waptutils import ensure_unicode,ensure_list,datetime2isodate,jsondump

from waptcrypto import SSLCABundle,SSLCertificate,SSLPrivateKey,serialize_content_for_signature,EWaptCryptoException

from waptserver.utils import setloglevel

import json
import ujson
import codecs
import datetime
import os

from optparse import OptionParser

import waptserver.config

# You must be sure your database is an instance of PostgresqlExtDatabase in order to use the JSONField.

import logging
logger = logging.getLogger()

wapt_db = Proxy()

def load_db_config(server_config=None):
    """Initialise db proxy with parameters from inifile

    Args:
        serverconfig (dict): dict of server parameters as returned by waptserver.config.load_config(ainifilename)

    Returns
        configured db : db which has been put in wapt_db proxy
    """
    global wapt_db
    if server_config is None:
        server_config = waptserver.config.load_config()

    logger.info('Initializing a DB connection pool for db host %s:%s db_name:%s. Size:%s' %
        (server_config['db_host'],server_config['db_port'],server_config['db_name'],server_config['db_max_connections']))
    pgdb = PooledPostgresqlExtDatabase(
        database=server_config['db_name'],
        host=server_config['db_host'],
        port=server_config['db_port'],
        user=server_config['db_user'],
        password=server_config['db_password'],
        max_connections=server_config['db_max_connections'],
        stale_timeout=server_config['db_stale_timeout'],
        timeout=server_config['db_connect_timeout'],
        autoconnect=False)
    wapt_db.initialize(pgdb)
    return pgdb

class WaptBaseModel(SignaledModel):
    """A base model that will use our Postgresql database"""
    class Meta(object):
        database = wapt_db

    # audit data
    created_on = DateTimeField(null=True)
    created_by = CharField(null=True)
    updated_on = DateTimeField(null=True)
    updated_by = CharField(null=True)

    def __unicode__(self):
        return u'%s' % (self.__data__,)

    def __str__(self):
        return self.__unicode__().encode('utf8')


@pre_save(sender=WaptBaseModel)
def waptbasemodel_pre_save(model_class, instance, created):
    if created:
        instance.created_on = datetime.datetime.utcnow()
    instance.updated_on = datetime.datetime.utcnow()


class ServerAttribs(SignaledModel):
    """key/value registry"""
    class Meta(object):
        database = wapt_db

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
                wapt_db.rollback()
                cls.update(value=value).where(cls.key == key).execute()

    def __unicode__(self):
        return u'%s' % (self.__data__,)

    def __str__(self):
        return self.__unicode__().encode('utf8')

class Hosts(WaptBaseModel):
    """Inventory informations of a host
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
    registration_auth_user = CharField(null=True)

    #authorized_certificates = ArrayField(CharField, null=True, help_text='authorized packages signers certificates sha1 fingerprint')
    authorized_certificates_sha256 = ArrayField(CharField, null=True, help_text='authorized packages signers certificates sha256 fingerprint')

    os_name = CharField(null=True)
    os_version = CharField(null=True)
    os_architecture = CharField(null=True)
    platform = CharField(null=True)

    # frequently updated data from host update_status
    connected_users = ArrayField(CharField, null=True)
    connected_ips = ArrayField(CharField, null=True)
    mac_addresses = ArrayField(CharField, null=True)
    gateways = ArrayField(CharField, null=True)
    networks = ArrayField(CharField, null=True)
    dnsdomain = CharField(null=True)

    computer_ad_site = CharField(null=True,index=True)
    computer_ad_ou = CharField(null=True,index=True)
    computer_ad_groups = ArrayField(CharField, null=True)

    # calculated by server when update_status
    reachable = CharField(20, null=True)

    # for websockets
    server_uuid = CharField(null=True)
    listening_protocol = CharField(10, null=True)
    # in case of websockets, this stores the sid
    listening_address = CharField(null=True)
    listening_port = IntegerField(null=True)
    listening_timestamp = CharField(null=True)

    # for repo sync

    repositories = CharField(null=True)

    # OK, TO-UPGRADE, ERROR, RUNNING
    host_status = CharField(null=True)
    last_seen_on = CharField(null=True)
    last_logged_on_user = CharField(null=True)

    # OK, WARNING, ERROR
    audit_status = CharField(null=True)

    #
    wapt_version = CharField(null=True)

    # raw json data
    wapt_status = BinaryJSONField(null=True)

    # running, pending, errors, finished , upgradable, errors,
    last_update_status = BinaryJSONField(null=True,index=False)
    host_info = BinaryJSONField(null=True)
    host_capabilities = BinaryJSONField(null=True)
    host_metrics = BinaryJSONField(null=True)

    # variable structures... so keep them as json
    dmi = BinaryJSONField(null=True,index=False)
    wmi = BinaryJSONField(null=True)

    wuauserv_status = BinaryJSONField(null=True,index=False)
    waptwua_status = BinaryJSONField(null=True,index=False)
    waptwua_rules = BinaryJSONField(null=True,index=False)

    #
    status_hashes = BinaryJSONField(null=True,index=False)

    """
    def save(self,*args,**argvs):
        if 'uuid' in self._dirty:
            argvs['force_insert'] = True
        return super(Hosts,self).save(*args,**argvs)
    """

    def __repr__(self):
        return '<Host fqdn=%s / uuid=%s>' % (self.computer_fqdn, self.uuid)

    @classmethod
    def fieldbyname(cls, fieldname):
        return cls._meta.fields[fieldname]

class HostPackagesStatus(WaptBaseModel):
    """Stores the status of packages installed on a host
    """
    id = PrimaryKeyField(primary_key=True)
    host = ForeignKeyField(Hosts, on_delete='CASCADE', on_update='CASCADE')
    package_uuid = CharField(null=True)
    package = CharField(null=True, index=True)
    version = CharField(null=True)
    architecture = CharField(null=True)
    locale = CharField(null=True)
    maturity = CharField(null=True)
    section = CharField(null=True)
    priority = CharField(null=True)
    signer = CharField(null=True)
    signer_fingerprint = CharField(null=True)
    signature_date = CharField(null=True)
    description = TextField(null=True)
    install_status = CharField(null=True)
    install_date = CharField(null=True)
    install_output = TextField(null=True)
    install_params = CharField(null=True)
    uninstall_key = ArrayField(CharField,null=True)
    explicit_by = CharField(null=True)
    repo_url = CharField(max_length=600, null=True)
    depends = ArrayField(CharField,null=True)
    conflicts = ArrayField(CharField,null=True)
    last_audit_status = CharField(null=True)
    last_audit_on = CharField(null=True)
    last_audit_output = TextField(null=True)
    next_audit_on = CharField(null=True)

    def __repr__(self):
        return '<HostPackageStatus uuid=%s packages=%s (%s) install_status=%s>' % (self.id, self.package, self.version, self.install_status)


class WaptUsers(WaptBaseModel):
    """Users
    """
    id = PrimaryKeyField(primary_key=True)
    name = CharField(null=True, index=True, help_text='Username to authenticate with password')
    auth_method = CharField(null=True, index=False, help_text='Authorized authentication method')
    description = CharField(null=True, index=False)
    user_certificate = TextField(null=True, help_text='User public X509 certificates chain. Root certificate must be approved on server')
    user_fingerprint_sha1 = CharField(null=True, index=True, help_text='Calculated from user_certificate')
    user_fingerprint_sha256 = CharField(null=True, index=True, help_text='Calculated from user_certificate')

    def __repr__(self):
        return '<WaptUsers id=%s name=%s>' % (self.id, self.name)


class WaptUserAcls(WaptBaseModel):
    """Users
    """
    id = PrimaryKeyField(primary_key=True)
    user_fingerprint_sha1 = CharField(null=False, index=True, help_text='sha1 fingerprint of user certificate')
    perimeter_fingerprint = CharField(null=False, index=True, help_text='sha256 fingerprint of CA root for perimeter')
    acls = ArrayField(CharField,null=True, help_text='List of authorized actions on the perimeter defined by the perimeter_sha256')
    expiration_date = CharField(null=True, help_text='End of ACL date')
    signer = CharField(null=True, help_text='ACL signer')
    signature_date = CharField(null=True, help_text='ACL date')
    signer_fingerprint = CharField(null=True, help_text='SHA256 signer fingerprint')
    signature = CharField(null=True, help_text='ACL signature (serialize as as json dict with sorted keys)')

    def _signed_attributes(self):
        return ['acls','user_fingerprint_sha1',
            'perimeter_fingerprint','expiration_date',
            'signer','signature_date','signer_fingerprint']

    def __repr__(self):
        return '<WaptUserAcls id=%s>' % (self.id,)

    def to_dict(self):
        _dict = {k: getattr(self,k) for k in self._signed_attributes()}
        return _dict

    def sign(self,key,cert):
        self.signer = cert.cn
        self.signer_fingerprint = cert.fingerprint
        self.signature_date = datetime2isodate()
        self.signature = key.sign_content(self.to_dict(),pre_py3=False)
        self.save()

    def verify(self,cabundle):
        """Check that the ACL is properly signed and signed by a trusted user
        """
        # get signer certificate
        signer_cert = cabundle.certificate(self.signer_fingerprint)
        if not signer_cert:
            raise EWaptCryptoException('ACL signer is not known')
        user_dict = self.to_dict()
        # verify signature
        signer_cert.verify_content(user_dict,self.signature)

        # verify signer is trusted
        cert_chain = cabundle.check_certificates_chain(signer_cert,check_is_trusted=True)
        logger.debug('ACL is trusted by %s' % cert_chain[-1])
        return cert_chain



class Packages(WaptBaseModel):
    """Stores the content of packages of repositories
    """
    id = PrimaryKeyField(primary_key=True)
    package_uuid = CharField(null=True)
    package = CharField(null=False, index=True)
    version = CharField(null=False)
    description = CharField(max_length=1200,null=True)
    architecture = CharField(null=True)
    locale = CharField(null=True)
    maturity = CharField(null=True)
    section = CharField(null=True)
    priority = CharField(null=True)
    signer = CharField(null=True)
    signer_fingerprint = CharField(null=True)
    signature_date = CharField(null=True)
    description = TextField(null=True)
    depends = ArrayField(CharField,null=True)
    conflicts = ArrayField(CharField,null=True)
    audit_schedule = CharField(null=True)
    valid_from = CharField(null=True)
    valid_until = CharField(null=True)
    forced_install_on = CharField(null=True)
    installed_size = BigIntegerField(null=True)
    target_os = CharField(null=True)
    min_os_version = CharField(null=True)
    max_os_version = CharField(null=True)
    min_wapt_version = CharField(null=True)
    impacted_process = ArrayField(CharField,null=True)
    keywords = ArrayField(CharField,null=True)
    name = CharField(null=True)
    categories = ArrayField(CharField,null=True)
    licence = CharField(null=True)
    editor = CharField(null=True)
    homepage = CharField(null=True)
    filename = CharField(null=True,index=True)

    @classmethod
    def _as_attribute(cls,k,v):
        if k in ['depends','conflicts','impacted_process','keywords','categories']:
            return ensure_list(v or None)
        else:
            return v or None

    @classmethod
    def from_control(cls,entry):
        package = cls(** dict((a,cls._as_attribute(a,v)) for (a,v) in entry.as_dict().iteritems() if a in cls._meta.columns))


    @classmethod
    def update_from_control(cls,entry):
        """Create or update a single package entry in database given a PackageEntry

        """
        key = {'package_uuid':entry.package_uuid,
                'package':entry.package,'version':entry.version}
        (rec,_isnew) = Packages.get_or_create(**key)
        for (a,v) in entry.as_dict().iteritems():
            if a in cls._meta.columns and not a in key:
                new_value = cls._as_attribute(a,v)
                if new_value != getattr(rec,a):
                    setattr(rec,a,cls._as_attribute(a,v))
        # rec.available = True
        if not rec.package_uuid:
            rec.package_uuid = entry.make_fallback_uuid()
        if rec.is_dirty():
            rec.save()
        return (rec,_isnew)

    @classmethod
    def update_from_repo(cls,repo):
        """Update Packages table with all the Packages entries from repo WaptRepo

        Args:
            repo (WaptRepo):
        Returns:
            list of PackagEntry added to the table
        """
        result = []
        with cls._meta.database.atomic() as trans:
            try:
                for pe in repo.packages():
                    (rec,_isnew) = cls.update_from_control(pe)
                    if _isnew:
                        result.append(pe)
                trans.commit()
            except:
                trans.rollback()
                raise
        return result


class HostSoftwares(WaptBaseModel):
    """Content of Host's softwares uninstall registry
    """
    id = PrimaryKeyField(primary_key=True)
    host = ForeignKeyField(Hosts, on_delete='CASCADE', on_update='CASCADE')
    name = CharField(max_length=2000, null=True, index=True)
    version = CharField(max_length=1000, null=True)
    publisher = CharField(max_length=2000, null=True)
    key = CharField(max_length=600, null=True)
    system_component = CharField(null=True)
    uninstall_string = CharField(max_length=2000, null=True)
    install_date = CharField(null=True)
    install_location = CharField(max_length=2000, null=True)

    def __repr__(self):
        return '<HostSoftwares uuid=%s name=%s (%s) key=%s>' % (self.uuid, self.name, self.version, self.key)


class HostGroups(WaptBaseModel):
    """Mirror of the depends attribut of Hots's packages

    Updated when a host package is uploaded to the server
    Helps to speed up filtering Hosts list on groups.
    """
    id = PrimaryKeyField(primary_key=True)
    host = ForeignKeyField(Hosts, on_delete='CASCADE', on_update='CASCADE')
    group_name = CharField(null=False, index=True)

    def __repr__(self):
        return '<HostGroups id=%s group_name=%s>' % (self.id, self.group_name)

    @classmethod
    def sync_from_host_package(cls,entry):
        """Update HostGroups table from Host Package depends.
        Add / Remove host <-> group link based on entry.depends csv attribute

        Args:
            entry (PackageEntry): Host package entry

        Returns
            tuple: (added depends, removed depends)
        """
        with cls._meta.database.atomic() as trans:
            try:
                host_id = entry.package

                # insert /delete depends as groups
                if entry.depends:
                    depends = [s.strip() for s in entry.depends.split(',')]
                else:
                    depends = []
                old_groups = [h['group_name'] for h in HostGroups.select(HostGroups.group_name).where(HostGroups.host == host_id).dicts()]
                to_delete = [g for g in old_groups if not g in depends]
                to_add = [g for g in depends if not g in old_groups]
                if to_delete:
                    HostGroups.delete().where((HostGroups.host == host_id) & (HostGroups.group_name.in_(to_delete))).execute()
                if to_add:
                    HostGroups.insert_many([dict(host=host_id, group_name=group) for group in to_add]).execute() #pylint: disable=no-value-for-parameter
                return (to_add,to_delete)
            except IntegrityError as e:
                trans.rollback()
                return (0,0)

class ReportingQueries(WaptBaseModel):
    """Reporting queries"""
    id = PrimaryKeyField(primary_key=True)
    name = CharField(null=False, index=True )
    query = CharField( null=True, max_length=2000 )
    settings = BinaryJSONField(null=True,index=False)
    snapshot_period = IntegerField( null=True )  # period in seconds
    snapshot_name = CharField( null=True )
    last_snapshot_date = TimestampField(null=True)
    snapshot_ttl = IntegerField( null=True )     # period in seconds

    def __repr__(self):
        return '<ReportingQueries id=%s name=%s>' % (self.id, self.name)

    def snapshot(self):
        if self.snapshot_name:
            with wapt_db.atomic() as trans:
                report_date = datetime.datetime.now()
                data = ReportingQueries.raw(self.query)
                jsondata = list(data.dicts())
                s = ReportingSnapshots.create(
                    report_id = self.id,
                    report_name = self.snapshot_name,
                    report_date = report_date,
                    data = jsondata
                    )
                s.save()

                self.last_snapshot_date = report_date
                self.save()

                if not self.snapshot_ttl.is_null():
                    ReportingSnapshots.delete().where(
                        ReportingSnapshots.report_id == self.id,
                        ReportingSnapshots.report_id <= report_date - datetime.timedelta(seconds=self.snapshot_ttl)
                        ).execute()

                trans.commit()


class ReportingSnapshots(WaptBaseModel):
    """Reporting queries"""
    id = PrimaryKeyField(primary_key=True)
    report_id = ForeignKeyField(ReportingQueries, on_delete='CASCADE', on_update='CASCADE')
    report_name = CharField()
    report_date = TimestampField(null=True)
    data = BinaryJSONField(null=True)

    def __repr__(self):
        return '<ReportingSnapsphots id=%s name=%s date=%s>' % (self.id, self.report_name,self.report_date)

class Normalization(WaptBaseModel):
    """Normalization table"""
    original_name = CharField(   max_length=2000 )
    key = CharField(             max_length=600 )
    normalized_name = CharField( max_length=2000, null=True,  index=True )
    banned = BooleanField( null=True )
    windows_update = BooleanField( null=True  )
    class Meta(object):
        primary_key = CompositeKey('original_name', 'key' )
    def __repr__(self):
        return '<Normalization uuid=%s name=%s>' % (self.uuid, self.name)


class WsusUpdates(WaptBaseModel):
    update_id = CharField(primary_key=True, index=True)
    title = CharField()
    update_type = CharField()
    kbids = ArrayField(CharField, index=True,null=True)
    severity = CharField(null=True)
    changetime = CharField(null=True)
    product = CharField(null=True, index=True)
    classification = CharField(null=True)
    download_urls = ArrayField(CharField,null=True)
    min_download_size = BigIntegerField(null=True)
    max_download_size = BigIntegerField(null=True)
    superseded_update_ids = ArrayField(CharField,null=True)
    security_bulletin_ids = ArrayField(CharField,null=True)
    is_mandatory = BooleanField(null=True)
    reboot_behaviour = CharField(null=True)
    can_request_user_input = CharField(null=True)
    requires_network_connectivity = BooleanField(null=True)
    is_beta = BooleanField(null=True)
    is_uninstallable = BooleanField(null=True)
    installation_impact = CharField(null=True)
    uninstallation_impact = CharField(null=True)
    support_url = CharField(null=True)
    release_notes = TextField(null=True)
    uninstallation_notes = TextField(null=True)
    languages = ArrayField(CharField,null=True)
    downloaded_on = CharField(null=True)

class HostWsus(WaptBaseModel):
    """List of Windows Update discovered by waptwua for a Host with install status
    """
    id = PrimaryKeyField(primary_key=True)
    host = ForeignKeyField(Hosts, on_delete='CASCADE', on_update='CASCADE')
    update_id = ForeignKeyField(WsusUpdates, on_delete='CASCADE', on_update='CASCADE')
    status = CharField(null=True)
    allowed = BooleanField(null=True)
    installed = BooleanField(null=True)
    present = BooleanField(null=True)
    hidden = BooleanField(null=True)
    delayed = BooleanField(null=True)
    downloaded = BooleanField(null=True)
    install_date = CharField(null=True)
    history = BinaryJSONField(null=True,index=False)


class SignedModel(WaptBaseModel):
    uuid = CharField(primary_key=True,null=False,default=str(_uuid.uuid4()))

    def save(self,*args,**argvs):
        if 'uuid' in self._dirty:
            argvs['force_insert'] = True
        return super(SignedModel,self).save(*args,**argvs)


class WsusDownloadTasks(WaptBaseModel):
    id = PrimaryKeyField(primary_key=True)
    task_id = CharField(null=True,index=True)
    kind = CharField(null=True,index=True)
    url = CharField(null=True)
    target_size = BigIntegerField(null=True)
    local_filename = CharField(null=True)
    file_date = DateTimeField(null=True)
    file_size = BigIntegerField(null=True)
    status = CharField(null=True)
    started_on = DateTimeField(null=True,index=True)
    finished_on = DateTimeField(null=True,index=True)
    msg = CharField(null=True)
    forced = BooleanField(null=True)
    skipped = BooleanField(null=True)
    error = CharField(max_length=1200,null=True)

class StoreDownload(WaptBaseModel):
    id = PrimaryKeyField(primary_key=True)
    download_number = BigIntegerField(null=True)
    last_download = DateTimeField(null=True)
    package_name = CharField(null=True)
    package_version = CharField(null=True)

class StoreMember(WaptBaseModel):
    id = PrimaryKeyField(primary_key=True)
    email = CharField(null=True)
    password = CharField(null=True)
    surname = CharField(null=True)
    firstname = CharField(null=True)
    organization = CharField(null=True)
    lastconnection = DateTimeField(null=True)
    gdpr = BooleanField(null=True)
    tos = BooleanField(null=True)
    token = CharField(null=True)
    validat_account = BooleanField(null=True)

class StoreUsage(SignaledModel):
    class Meta(object):
        database = wapt_db

    id = PrimaryKeyField(primary_key=True)
    architecture = CharField(null=True)
    date = DateTimeField(null=True)
    host_count = IntegerField(null=True)
    ip = CharField(null=True)
    netname = CharField(null=True)
    platform = CharField(null=True)
    ptr = CharField(null=True)
    uuid = CharField(null=True)
    version = CharField(null=True)
    oldest_query = DateTimeField(null=True)
    newest_query = DateTimeField(null=True)
    first_seen = DateTimeField(null=True)
    packages_count_avg = FloatField(null=True)
    packages_count_ok = IntegerField(null=True)
    packages_count_max = IntegerField(null=True)
    hosts_count_need_upgrade = IntegerField(null=True)
    hosts_count_has_error = IntegerField(null=True)

class SiteRules(WaptBaseModel):
    id = PrimaryKeyField(primary_key=True)
    sequence = IntegerField(null=True)
    name = CharField(null=True)
    repositories = JSONField(null=True)
    condition = CharField(null=True)
    value = CharField(null=True)
    repo_url = CharField(null=True)
    signature_date = CharField(null=True)
    signed_attributes = JSONField(null=True)
    signer = CharField(null=True)
    signature = TextField(null=True)
    signer_certificate = TextField(null=True)

class SyncStatus(WaptBaseModel):
    id = PrimaryKeyField(primary_key=True)
    version = IntegerField(null=True)
    changelog = JSONField(null=True)


def dictgetpath(adict, pathstr):
    """Iterates a list of path pathstr of the form 'key.subkey.sskey' and returns
    the first occurence in adict which returns not None.

    A path component can contain a wildcard '*' to match an array.

    """
    if not isinstance(pathstr, (list, tuple)):
        pathstr = [pathstr]
    for path in pathstr:
        result = adict
        for k in path.split('.'):
            if isinstance(result, dict):
                # assume this level is an object and returns the specified key
                result = result.get(k)
            elif isinstance(result, list) and k.isdigit() and int(k) < len(result):
                # assume this level is a list and return the n'th item
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
    # awfull hack for data containing null char, not accepted by postgresql.
    if fieldname in ('host_info', 'wmi', 'dmi'):
        jsonrepr = ujson.dumps(data)
        if '\u0000' in jsonrepr:
            logger.warning('Workaround \\u0000 not handled by postgresql json for host %s field %s' % (getattr(host, 'uuid', '???'), fieldname))
            data = ujson.loads(jsonrepr.replace('\u0000', ' '))

    setattr(host, fieldname, data)
    return host

def package_version_from_prequest(prequest):
    """Split package and version from  "package(=version)"

    Returns:
        tuple (str,str): (package,version)
    """
    package_version_re = re.compile('([^()]+)\s*(\(\s*([<=>]*)\s*(\S+)\s*\))?.*')
    match = package_version_re.match(prequest)
    if match and len(match.groups())==4:
        result = match.groups()
        return (result[0],result[3])
    else:
        return None

def update_installed_packages(uuid, data, applied_status_hashes):
    """Stores packages json data into separate HostPackagesStatus

    Merge

    Args:
        uuid (str) : unique ID of host
        data (dict): data from host
        applied_status_hashes (dict): add the supplied hash into 'installed_packages' key

    Returns:
        None

    """
    # TODO : be smarter : insert / update / delete instead of delete all / insert all ?
    # is it faster ?
    key = ['package','version','version','architecture','locale','maturity']
    def get_key(rec):
        return {k:rec[k] for k in rec}
    #old_installed = HostPackagesStatus.select().where(HostPackagesStatus.host == uuid).dicts()

    def encode_value(value):
        if isinstance(value,unicode):
            value = value.replace(u'\x00', ' ')
        return value

    def _get_uninstallkeylist(uninstall_key_str):
        """Decode uninstallkey list from db field
        For historical reasons, this field is encoded as str(pythonlist)
        or sometimes simple repr of a str

        Returns:
            list
        """
        if uninstall_key_str:
            if uninstall_key_str.startswith("['") or uninstall_key_str.startswith("[u'"):
                # python encoded repr of a list
                try:
                    # transform to a json like array.
                    guids = json.loads(uninstall_key_str.replace("[u'","['").replace(", u'",',"').replace("'",'"'))
                except:
                    logger.warning(u'Bad uninstallkey list format : %s' % uninstall_key_str)
                    guids = uninstall_key_str
            elif uninstall_key_str[0] in ["'",'"']:
                # simple python string, removes quotes
                guids = uninstall_key_str[1:-1]
            else:
                try:
                    # normal json encoded list
                    guids = ujson.loads(uninstall_key_str)
                except:
                    guids = uninstall_key_str

            if isinstance(guids,(unicode,str)):
                guids = [guids]
            return guids
        else:
            return []

    installed_packages = data.get('installed_packages', data.get('packages', None))

    last_update_status = data.get('last_update_status',None)
    if last_update_status is None:
        last_update_status = Hosts.select(Hosts.last_update_status).where(Hosts.uuid == uuid).dicts().first()
    pending = last_update_status.get('pending',{})

    missing = [ package_version_from_prequest(pr) for pr in ((pending.get('install',[]) or []) + (pending.get('additional',[]) or []))]
    upgrades = [ package_version_from_prequest(pr) for pr in pending.get('upgrade',[])]  or []
    removes = [ package_version_from_prequest(pr)[0] for pr in pending.get('remove',[])]  or []
    errors = [ package_version_from_prequest(pr) for pr in last_update_status.get('errors',[])]  or []

    if installed_packages is not None:
        HostPackagesStatus.delete().where(HostPackagesStatus.host == uuid).execute()
        packages = []
        for package in installed_packages:
            package['host'] = uuid
            # csv str on the client, Array on the server
            package['depends'] = ensure_list(package.get('depends'))
            package['conflicts'] = ensure_list(package.get('conflicts'))
            package['uninstall_key'] = _get_uninstallkeylist(package.get('uninstall_key'))
            package['created_on'] = datetime.datetime.utcnow()
            if not package.get('package_uuid'):
                package['package_uuid'] = 'fb-%s' % (hashlib.sha256('-'.join([
                    (package.get('package') or '').encode('utf8'),
                     str(package.get('version') or ''),
                     str(package.get('architecture') or ''),
                     str(package.get('locale') or ''),
                     str(package.get('maturity') or '')])).hexdigest(),)

            # merge update status from Hosts.last_update_status
            pv = (package['package'],package['version'])
            if pv in errors:
                package['install_status'] = 'ERROR'
            elif package['package'] in [p[0] for p in upgrades]:
                p = [p for p in upgrades if p[0] == package['package']][0]
                if Version(p[1]) > Version(package['version']):
                    package['install_status'] = 'NEED-UPGRADE'
                elif Version(p[1]) < Version(package['version']):
                    package['install_status'] = 'NEED-DOWNGRADE'
            elif package['package'] in removes:
                package['install_status'] = 'NEED-REMOVE'

            # filter out all unknown fields from json data for the SQL insert
            packages.append(dict([(k, encode_value(v)) for k, v in package.iteritems() if k in HostPackagesStatus._meta.fields]))


        if packages:
            HostPackagesStatus.insert_many(packages).execute() # pylint: disable=no-value-for-parameter

        for pv in missing+upgrades:
            HostPackagesStatus(
                    host = uuid,
                    package=pv[0],
                    version=pv[1],
                    created_on=datetime.datetime.utcnow(),
                    install_status='NEED-INSTALL',
                    package_uuid='fb-%s' % (hashlib.sha256(package['package'].encode('utf8')+'-'+package['version']).hexdigest()),
                    ).save()

        applied_status_hashes['installed_packages'] = data.get('status_hashes',{}).get('installed_packages')


def update_installed_softwares(uuid, data,applied_status_hashes):
    """Stores softwares json data into separate HostSoftwares table

    Args:
        uuid (str) : unique ID of host
        data (dict): data from host

    Returns:
        None
    """
    installed_softwares = data.get('installed_softwares', data.get('softwares', None))
    if installed_softwares is not None:
        # TODO : be smarter : insert / update / delete instead of delete all / insert all ?
        HostSoftwares.delete().where(HostSoftwares.host == uuid).execute()
        softwares = []

        def encode_value(value):
            if isinstance(value,unicode):
                value = value.replace(u'\x00', ' ')
            return value

        for software in installed_softwares:
            software['host'] = uuid
            software['created_on'] = datetime.datetime.utcnow()
            # filter out all unknown fields from json data for the SQL insert
            softwares.append(dict([(k,encode_value(v)) for k, v in software.iteritems() if k in HostSoftwares._meta.fields]))

        if softwares:
            HostSoftwares.insert_many(softwares).execute() # pylint: disable=no-value-for-parameter

        applied_status_hashes['installed_softwares'] = data.get('status_hashes',{}).get('installed_softwares')

def update_waptwua(uuid,data,applied_status_hashes):
    """Stores discovered windows update into WindowsUpdates table and
    links between host and updates into HostWsus

    Args:
        uuid (str) : unique ID of host
        data (dict): data from host

    Returns:
        None
    """
    def encode_value(value):
        if isinstance(value,unicode):
            value = value.replace(u'\x00', ' ')
        return value

    if 'waptwua_updates' in data:
        windows_updates = []
        for w in data['waptwua_updates']:
            u = dict([(k,encode_value(v)) for k, v in w.iteritems() if k in WsusUpdates._meta.fields])
            u['created_on'] = datetime.datetime.utcnow()
            windows_updates.append(u)
        if windows_updates:
            # if win update has already been registered, we don't update it, but simply ignore the insert
            # we should append missing URLS... to do in a dedicated PG sql proc will be better.
            for update in windows_updates:
                download_urls = WsusUpdates.select(WsusUpdates.update_id,WsusUpdates.download_urls).where(WsusUpdates.update_id==update['update_id']).first()
                if not download_urls:
                    WsusUpdates.insert(update).on_conflict('IGNORE').execute()
                #elif download_urls.download_urls != update['download_urls']:
                #    new_urls = list(set(download_urls.download_urls + update['download_urls']))
                #    WsusUpdates.update(download_urls=new_urls).where(WsusUpdates.update_id == update['update_id']).execute()
                else:
                    # append new urls when different locales for example
                    if download_urls.download_urls != update['download_urls']:
                        new_urls = list(set(download_urls.download_urls + update['download_urls']))
                        update['download_urls'] = new_urls
                        update['downloaded_on'] = None
                    WsusUpdates.update(**update).where(WsusUpdates.update_id == update['update_id']).execute()
            #WsusUpdates.insert_many(windows_updates).on_conflict('IGNORE').execute()

        applied_status_hashes['waptwua_updates'] = data.get('status_hashes',{}).get('waptwua_updates')

    if 'waptwua_updates_localstatus' in data:
        HostWsus.delete().where(HostWsus.host == uuid).execute()
        host_wsus = []
        for h in data['waptwua_updates_localstatus']:
            # default if not supplied
            new_rec = dict([(k,encode_value(v)) for k, v in h.iteritems() if k in HostWsus._meta.fields])
            new_rec['host'] = uuid
            new_rec['created_on'] = datetime.datetime.utcnow()
            if not 'install_date' in new_rec:
                new_rec['install_date'] = None
            host_wsus.append(new_rec)
        if host_wsus:
            HostWsus.insert_many(host_wsus).execute() # pylint: disable=no-value-for-parameter
        applied_status_hashes['waptwua_updates_localstatus'] = data.get('status_hashes',{}).get('waptwua_updates_localstatus')

def update_known_ssl_certificates(data,server_conf):
    """Append supplied sertificates_pems to the local ssl known certificates directory
    (<waptrepodir>/wapt/ssl/<sha256 of cert>.crt)

    Args:
        server_conf (dict)
        certificates (list of X509 pem encoded certificates)

    Returns:
        None
    """
    if server_conf is None:
        return False

    certificates = data.get('authorized_certificates',None)
    fingerprints = data.get('wapt_status',{}).get('authorized_certificates_sha256',None)
    if not certificates:
        return False

    ssl_dir = os.path.join(server_conf['wapt_folder'],'ssl')
    if not os.path.isdir(ssl_dir):
        os.makedirs(ssl_dir)

    # optimization... if all fingerprints are already in ssl dir, skip whole proc
    if fingerprints is not None:
        skip = True
        for fg in fingerprints:
            cert_fn = os.path.join(ssl_dir,'%s.crt' % fg)
            if not os.path.isfile(cert_fn):
                skip = False
                break

        if skip:
            return True

    for pem in certificates:
        certs = SSLCABundle()
        certs.add_certificates_from_pem(pem)
        for cert in certs.certificates():
            cert_fn = os.path.join(ssl_dir,'%s.crt'%cert.fingerprint)
            if not os.path.isfile(cert_fn):
                open(cert_fn,'w').write(cert.as_pem())

    return True

def update_host_data(data,server_conf=None):
    """Helper function to insert or update host data in db

    Args :
        data (dict) : data to push in DB with at least 'uuid' key
                      if uuid key already exists, update the data
                      else insert
                      only keys in data are pushed to DB.
                      Other data (fields) are left untouched

        server_conf(dict) : server configuraation dict (to get wapt_folder)

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
    }

    uuid = data['uuid']
    with wapt_db.atomic() as trans:
        try:
            supplied_hashes = data.get('status_hashes',{})
            applied_status_hashes = {}
            existing = Hosts.select(Hosts.uuid, Hosts.computer_fqdn,Hosts.status_hashes).where(Hosts.uuid == uuid).first()
            if not existing:
                logger.debug('Inserting new host %s with fields %s' % (uuid, list(data.keys())))
                # wapt update_status packages softwares host
                updhost = Hosts()

                for k in data.keys():
                    # manage field renaming between 1.3 and >= 1.4
                    target_key = migrate_map_13_14.get(k, k)
                    if target_key and hasattr(updhost, target_key):
                        set_host_field(updhost, target_key, data[k])
                        if k in supplied_hashes:
                            applied_status_hashes[k] = supplied_hashes[k]
                updhost.status_hashes = applied_status_hashes
                updhost.save(force_insert=True)
            else:
                logger.debug('Updating %s for fields %s' % (uuid, list(data.keys())))

                updhost = Hosts.get(uuid=uuid)
                if not updhost.status_hashes:
                    updhost.status_hashes = {}

                for k in data.keys():
                    # supplied status_hashes is a subset of known hashes
                    if k != 'status_hashes':
                        # manage field renaming between 1.3 and >= 1.4
                        target_key = migrate_map_13_14.get(k, k)
                        if target_key and hasattr(updhost, target_key):
                            set_host_field(updhost, target_key, data[k])
                            if k in supplied_hashes:
                                # logger.info('set data: %s , size: %s' % (target_key,len(jsondump(data[k]))))
                                applied_status_hashes[k] = supplied_hashes[k]
                # merge already known data with new set
                updhost.status_hashes.update(applied_status_hashes)
                updhost.save()

            # separate tables
            # we are tolerant on errors here as we don't know exactly if client send good encoded data
            # but we still want to get host in table
            with wapt_db.atomic() as translocal:
                try:
                    update_installed_softwares(uuid, data,applied_status_hashes)
                except Exception as e:
                    # be tolerant
                    translocal.rollback()
                    logger.critical(u'Unable to update installed_softwares for %s: %s' % (uuid,ensure_unicode(e)))

            with wapt_db.atomic() as translocal:
                try:
                    update_installed_packages(uuid, data,applied_status_hashes)
                except Exception as e:
                    # be tolerant
                    translocal.rollback()
                    logger.critical(u'Unable to update installed_packages for %s: %s' % (uuid,ensure_unicode(e)))

            with wapt_db.atomic() as translocal:
                try:
                    # update waptwua state tables
                    update_waptwua(uuid,data,applied_status_hashes)
                except Exception as e:
                    # be tolerant
                    translocal.rollback()
                    logger.critical(u'Unable to update wuauserv_status or waptwua_status for %s: %s' % (uuid,ensure_unicode(e)))

            # extract X509 certificates PEM and store them in repo wapt/ssl
            if update_known_ssl_certificates(data,server_conf):
                if 'authorized_certificates' in supplied_hashes:
                    updhost.status_hashes['authorized_certificates'] = supplied_hashes['authorized_certificates']

            if server_conf['diff_repo']:
                try:
                    from waptenterprise.waptserver.repositories import update_file_tree_of_files
                    update_file_tree_of_files()
                except:
                    logger.critical(u"Something went wrong with diff repo : can't launch")

            # merge new known hashes for properly applied data, for next round
            updhost.status_hashes.update(applied_status_hashes)
            updhost.save()
            logger.info('Applied data for host %s: %s' % (uuid,list(applied_status_hashes.keys())))
            # returns actual registered fqdn and status hashes so that host can omit to send some data next time if they have not changed
            result_query = Hosts.select(Hosts.uuid, Hosts.computer_fqdn,Hosts.status_hashes)
            return result_query.where(Hosts.uuid == uuid).dicts().first()

        except Exception as e:
            logger.critical(u'Error updating data for %s : %s' % (uuid, ensure_unicode(e)))
            trans.rollback()
            raise e



@pre_save(sender=Hosts)
def wapthosts_json(model_class, instance, created):
    """Stores in plain table fields data from json"""
    # extract data from json into plain table fields
    if (created or Hosts.host_info in instance.dirty_fields) and instance.host_info:
        def extract_ou(host_info):
            dn =  host_info.get('computer_ad_dn',None)
            if dn:
                parts = dn.split(',',1)
                if len(parts)>=2:
                    return parts[1]
                else:
                    return ''
            else:
                return None

        extractmap = [
            ['computer_fqdn', 'computer_fqdn'],
            ['computer_name', 'computer_name'],
            ['description', 'description'],
            ['manufacturer', 'system_manufacturer'],
            ['productname', 'system_productname'],
            ['os_name', 'os_name'],
            ['platform','platform'],
            ['repositories','repositories'],
            ['os_version', ('os_version', 'os_name')],
            ['connected_ips', 'connected_ips'],
            ['connected_users', ('connected_users', 'current_user')],
            ['last_logged_on_user', 'last_logged_on_user'],
            ['mac_addresses', 'mac'],
            ['dnsdomain', ('dnsdomain', 'dns_domain')],
            ['gateways', ['gateways','default_gateways']],
            ['computer_ad_site', 'computer_ad_site'],
            ['computer_ad_ou', extract_ou],
            ['computer_ad_groups', 'computer_ad_groups'],
        ]

        for field, attribute in extractmap:
            if callable(attribute):
                setattr(instance, field, attribute(instance.host_info))
            else:
                setattr(instance, field, dictgetpath(instance.host_info, attribute))

        instance.os_architecture = 'x64' and instance.host_info.get('win64', '?') or 'x86'

    if (created or Hosts.dmi in instance.dirty_fields) and instance.dmi:
        extractmap = [
            ['serialnr', 'Chassis_Information.Serial_Number'],
            ['computer_type', 'Chassis_Information.Type'],
        ]
        for field, attribute in extractmap:
            if callable(attribute):
                setattr(instance, field, attribute(instance.dmi))
            else:
                setattr(instance, field, dictgetpath(instance.dmi, attribute))

    if (created or Hosts.host_metrics in instance.dirty_fields) and instance.host_metrics:
        extractmap = [
            ['connected_users',('logged_in_users','connected_users')],
            ['last_logged_on_user', 'last_logged_on_user'],
        ]
        for field, attribute in extractmap:
            if callable(attribute):
                setattr(instance, field, attribute(instance.host_metrics))
            else:
                setattr(instance, field, dictgetpath(instance.host_metrics, attribute))


    # extract list for fast query.
    if (created or Hosts.host_capabilities in instance.dirty_fields) and instance.host_capabilities:
        instance.authorized_certificates_sha256 = dictgetpath(instance.host_capabilities, 'packages_trusted_ca_fingerprints')
        instance.wapt_version = dictgetpath(instance.host_capabilities, 'wapt_version')

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


class ColumnDef(object):
    """Holds definitin of column for updatable remote GUI table
    """

    def __init__(self,field,in_update=None,in_where=None,in_key=None,calc_field_name=None):
        self.field = field
        if in_update is not None:
            self.in_update = in_update
        else:
            self.in_update = not isinstance(field,ForeignKeyField) and not isinstance(field,Function)

        self.in_where = None
        if in_where is not None:
            self.in_where = in_where

        if in_where is None:
            self.in_where = not isinstance(field,ForeignKeyField) and not isinstance(field,Function)

        self.in_key = field and field.primary_key
        self.visible = False
        self.default_width = None
        self.calc_field_name = calc_field_name
        if self.calc_field_name is None and self.field is not None:
            self.calc_field_name = getattr(self.field,'_alias',self.field.name)

    def as_metadata(self):
        result = dict()
        if isinstance(self.field,Function):
            result = {'name':getattr(self.field,'_alias',self.field.name),'org_name':self.field.name,'type':self.field._node_type}
        else:
            if self.field:
                result = {'name':getattr(self.field,'_alias',self.field.name),
                    'field_name':self.field.name,
                    'type':self.field.field_type,
                    'table_name':self.field.model._meta.table_name,
                    }
                attlist = ('primary_key','description','help_text','choice',
                            'default','sequence','max_length')
                for att in attlist:
                    if hasattr(self.field,att):
                        value = getattr(self.field,att)
                        if value is not None and not isinstance(value,Function):
                            if callable(value):
                                result[att] = value()
                            else:
                                result[att] = value

            elif self.calc_field_name:
                result = {'name':self.calc_field_name,
                    'field_name':self.calc_field_name,
                    'type':'calc',
                    'table_name':None,
                    }

        for att in ('visible','default_width'):
            value = getattr(self,att)
            if value is not None:
                if callable(value):
                    result[att] = value()
                else:
                    result[att] = value

        result['required'] = self.field and not self.field.is_null()
        return result

    def to_client(self,data):
        """Return a serialization of data, suitable for client application"""
        if isinstance(data,list):
            return json.dumps(data)
        else:
            return data

    def from_client(self,data):
        """Return db suitable value from a serialization from client application"""
        if isinstance(self.field,ArrayField):
            return json.loads(data)
        else:
            return data

class TableProvider(object):
    """Updatable dataset provider based on a list of column defs and
    a where clause.

    >>>
    """
    def __init__(self,query=None,model=None,columns=None,where=None):
        self.query = query
        self.model = model
        self._columns = columns
        self.where = where
        self._columns_idx = None

    @property
    def columns(self):
        if not self._columns:
            self._columns = []
            if self.model is not None:
                for field in self.model._meta.sorted_fields:
                    column = ColumnDef(field)
                    self._columns.append(column)
            elif self.query is not None:
                cursor = self.query.execute()
                cursor._initialize_columns()
                col = 0
                for field in cursor.fields:
                    column = ColumnDef(field,calc_field_name=cursor.columns[col])
                    col +=1
                    self._columns.append(column)
        return self._columns


    def get_data(self,start=0,count=None):
        """Build query, retrieve rows"""

        fields_list = []
        query = self.query
        if query is None and self.model is not None:
            query = self.model.select(* [f.field for f in self.columns])
            if self.where:
                query = query.where(self.where)

        rows = []
        for row in query.dicts():
            rows.append([column.to_client(row[column.calc_field_name]) for column in self.columns])

        return dict(
            metadata = [c.as_metadata() for c in self.columns],
            rows = rows
        )

    def column_by_name(self,name):
        """Return ColumnDef for field name"""
        if self._columns_idx is None:
            self._columns_idx = dict([(c.field.column_name,c) for c in self.columns])
        return self._columns_idx.get(name,None)

    def _where_from_values(self,old_values={}):
        """Return a where clause from old and new dict for update and delete"""
        result = None
        for (column_name,column_value) in old_values.iteritems():
            column = self.column_by_name(column_name)
            if column:
                if column.in_key or column.in_where:
                    if result is None:
                        result = column.field == column_value
                    else:
                        result = result & column.field == column_value
        return result

    def _record_values_from_values(self,new_values={}):
        """Return a dict for the insert/update into database from supplied dict
        filtering out non updateable values.
        """
        result = {}
        for (column_name,column_value) in new_values.iteritems():
            column = self.column_by_name(column_name)
            if column:
                if column.in_update:
                    result[column_name] = column.from_client(column_value)
        return result

    def _values_from_record_values(self,values):
        """Return a dict
        """
        result = {}
        for (column_name,column_value) in values.iteritems():
            column = self.column_by_name(column_name)
            if column:
                result[column_name] = column.to_client(column_value)
        return result

    def _update_set_from_values(self,new_values={}):
        """Return a dict for the insert/update into database from supplkied dict
        filtering out non updateable values.
        """
        result = {}
        for (column_name,column_value) in new_values.iteritems():
            column = self.column_by_name(column_name)
            if column:
                if column.in_update:
                    result[column.field] = column.from_client(column_value)
        return result

    def apply_updates(self,delta):
        """Build update queries from delta

        Args:
            delta (list): list of (update_type,old_data,new_data)
                update_type (str) = ('insert','update','delete')
                old_data (dict)  = empty dict for insert, list of old values for update / delete.
                           must include in_key, in_where, and updated fields with in_update flag
                new_data (dict) = dict for updated / inserted data, empty for delete

        """
        result = []
        with self.model._meta.database.atomic():
            for (update_type,old,new) in delta:
                # translates old / new value to
                if update_type == 'insert':
                    query = self.model.insert(self._update_set_from_values(new))
                elif update_type == 'update':
                    old_db_values = self._record_values_from_values(old)
                    query = self.model.update(self._update_set_from_values(new)).where(self._where_from_values(old_db_values))
                elif update_type == 'delete':
                    old_db_values = self._record_values_from_values(old)
                    query = self.model.delete().where(self._where_from_values(old_db_values))
                query.execute()
        return result


def get_db_version():
    try:
        return Version(ServerAttribs.get(key='db_version').value, 4)
    except:
        wapt_db.rollback()
        return None


def init_db(drop=False):
    try:
        wapt_db.connect()
        try:
            wapt_db.execute_sql('CREATE EXTENSION hstore;')
        except:
            wapt_db.rollback()

        list_tables = [ServerAttribs, Hosts, HostPackagesStatus, HostSoftwares, HostGroups,WsusUpdates,
                HostWsus,WsusDownloadTasks,Packages, ReportingQueries, Normalization, StoreDownload,ReportingQueries,
                ReportingSnapshots,WaptUsers,WaptUserAcls,SyncStatus,SiteRules]
        if drop:
            for table in reversed(list_tables):
                table.drop_table(fail_silently=True)

        try:
            wapt_db.create_tables(list_tables, safe=True)
        except Exception as e:
            wapt_db.rollback()
            print(u'Unable to create tables, will try to upgrade step by step instead... : %s' % (repr(e),))

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
    finally:
        if not wapt_db.is_closed():
            wapt_db.close()


def upgrade_db_structure():
    """Upgrade the tables version by version"""
    from playhouse.migrate import PostgresqlMigrator, migrate
    try:
        migrator = PostgresqlMigrator(wapt_db)
        logger.info('Current DB: %s version: %s' % (wapt_db.connect_params, get_db_version()))
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

        next_version = '1.5.1.1'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info('Migrating from %s to %s' % (get_db_version(), next_version))
                columns = [c.name for c in wapt_db.get_columns('hosts')]
                opes = []
                if not 'computer_ad_site' in columns:
                    opes.append(migrator.add_column(Hosts._meta.name, 'computer_ad_site', Hosts.computer_ad_site))
                if not 'computer_ad_ou' in columns:
                    opes.append(migrator.add_column(Hosts._meta.name, 'computer_ad_ou', Hosts.computer_ad_ou))
                if not 'computer_ad_groups' in columns:
                    opes.append(migrator.add_column(Hosts._meta.name, 'computer_ad_groups', Hosts.computer_ad_groups))
                migrate(*opes)

                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.5.1.3'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info('Migrating from %s to %s' % (get_db_version(), next_version))
                columns = [c.name for c in wapt_db.get_columns('hosts')]
                opes = []
                if not 'registration_auth_user' in columns:
                    opes.append(migrator.add_column(Hosts._meta.name, 'registration_auth_user', Hosts.registration_auth_user))
                migrate(*opes)

                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.5.1.14'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info('Migrating from %s to %s' % (get_db_version(), next_version))
                columns = [c.name for c in wapt_db.get_columns('hostpackagesstatus')]
                opes = []
                if not 'depends' in columns:
                    opes.append(migrator.add_column(HostPackagesStatus._meta.name, 'depends', HostPackagesStatus.depends))
                if not 'conflicts' in columns:
                    opes.append(migrator.add_column(HostPackagesStatus._meta.name, 'conflicts', HostPackagesStatus.conflicts))
                migrate(*opes)

                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.5.1.17'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info('Migrating from %s to %s' % (get_db_version(), next_version))
                opes = []
                ##
                migrate(*opes)

                #WsusScan2History.create_table(fail_silently=True)

                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.5.1.22'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info('Migrating from %s to %s' % (get_db_version(), next_version))
                opes = []
                opes.append(migrator.drop_column(HostPackagesStatus._meta.name, 'depends'))
                opes.append(migrator.add_column(HostPackagesStatus._meta.name, 'depends', HostPackagesStatus.depends))
                opes.append(migrator.drop_column(HostPackagesStatus._meta.name, 'conflicts'))
                opes.append(migrator.add_column(HostPackagesStatus._meta.name, 'conflicts', HostPackagesStatus.conflicts))
                migrate(*opes)

                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.6.0.0'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info('Migrating from %s to %s' % (get_db_version(), next_version))
                opes = []
                opes.append(migrator.add_column(Hosts._meta.name, 'audit_status', Hosts.audit_status))

                opes.append(migrator.add_column(HostPackagesStatus._meta.name, 'last_audit_status', HostPackagesStatus.last_audit_status))
                opes.append(migrator.add_column(HostPackagesStatus._meta.name, 'last_audit_on', HostPackagesStatus.last_audit_on))
                opes.append(migrator.add_column(HostPackagesStatus._meta.name, 'last_audit_output', HostPackagesStatus.last_audit_output))
                opes.append(migrator.add_column(HostPackagesStatus._meta.name, 'next_audit_on', HostPackagesStatus.next_audit_on))
                migrate(*opes)

                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.6.0.1'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info('Migrating from %s to %s' % (get_db_version(), next_version))
                opes = []
                opes.append(migrator.add_column(HostPackagesStatus._meta.name, 'uninstall_key', HostPackagesStatus.uninstall_key))
                migrate(*opes)

                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.6.2.0'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info('Migrating from %s to %s' % (get_db_version(), next_version))
                opes = []
                opes.append(migrator.add_column(Hosts._meta.name, 'authorized_certificates_sha256', Hosts.authorized_certificates_sha256))
                migrate(*opes)

                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.6.2.1'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info('Migrating from %s to %s' % (get_db_version(), next_version))

                HostWsus.drop_table()
                WsusUpdates.drop_table()

                wapt_db.create_tables([WsusUpdates,HostWsus],safe=True)

                opes = []
                #opes.append(migrator.add_column(Hosts._meta.name, 'waptwua', Hosts.waptwua))
                migrate(*opes)

                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.6.2.2'
        if get_db_version() <= next_version:
            with wapt_db.atomic():
                logger.info('Migrating from %s to %s' % (get_db_version(), next_version))

                WsusDownloadTasks.create_table(fail_silently=True)
                Packages.create_table(fail_silently=True)

                opes = []
                columns = [c.name for c in wapt_db.get_columns('hosts')]
                if not 'status_hashes' in columns:
                    opes.append(migrator.add_column(Hosts._meta.name, 'status_hashes',Hosts.status_hashes))
                if not 'waptwua_status' in columns:
                    opes.append(migrator.add_column(Hosts._meta.name, 'waptwua_status',Hosts.waptwua_status))
                if not 'wuauserv_status' in columns:
                    opes.append(migrator.add_column(Hosts._meta.name, 'wuauserv_status',Hosts.wuauserv_status))

                columns = [c.name for c in wapt_db.get_columns('wsusupdates')]
                if not 'downloaded_on' in columns:
                    opes.append(migrator.add_column(WsusUpdates._meta.name, 'downloaded_on',WsusUpdates.downloaded_on))
                migrate(*opes)

                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.6.2.3'
        if get_db_version() <= next_version:
            with wapt_db.atomic():
                logger.info('Migrating from %s to %s' % (get_db_version(), next_version))

                opes = []
                columns = [c.name for c in wapt_db.get_columns('wsusupdates')]
                if 'cve_ids' in columns:
                    opes.append(migrator.drop_column(WsusUpdates._meta.name, 'cve_ids'))
                migrate(*opes)

                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.6.2.4'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info('Migrating from %s to %s' % (get_db_version(), next_version))

                opes = []
                columns = [c.name for c in wapt_db.get_columns('packages')]
                for c in ['impacted_process','editor','keywords','licence','homepage']:
                    if not c in columns:
                        opes.append(migrator.add_column(Packages._meta.name, c, getattr(Packages,c)))

                columns = [c.name for c in wapt_db.get_columns('hostwsus')]
                for c in ['install_date']:
                    if not c in columns:
                        opes.append(migrator.add_column(HostWsus._meta.name, c, getattr(HostWsus,c)))

                migrate(*opes)

                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.6.2.8'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info('Migrating from %s to %s' % (get_db_version(), next_version))

                opes = []

                columns = [c.name for c in wapt_db.get_columns('packages')]
                for c in ['package_uuid']:
                    if not c in columns:
                        opes.append(migrator.add_column(Packages._meta.name, c, getattr(Packages,c)))

                columns = [c.name for c in wapt_db.get_columns('hostpackagesstatus')]
                for c in ['package_uuid']:
                    if not c in columns:
                        opes.append(migrator.add_column(HostPackagesStatus._meta.name, c, getattr(HostPackagesStatus,c)))

                columns = [c.name for c in wapt_db.get_columns('hostwsus')]
                for c in ['history']:
                    if not c in columns:
                        opes.append(migrator.add_column(HostWsus._meta.name, c, getattr(HostWsus,c)))

                # change type to Array
                opes.append(migrator.drop_column(HostPackagesStatus._meta.name, 'uninstall_key'))
                opes.append(migrator.add_column(HostPackagesStatus._meta.name, 'uninstall_key', HostPackagesStatus.uninstall_key))

                migrate(*opes)

                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.7.0.0'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info("Migrating from %s to %s" % (get_db_version(), next_version))

                opes = []

                ReportingQueries.create_table(fail_silently=True);
                Normalization.create_table(fail_silently=True);

                columns = [c.name for c in wapt_db.get_columns('packages')]
                for c in ['audit_schedule','installed_size','target_os','min_os_version','max_os_version','min_wapt_version']:
                    if not c in columns:
                        opes.append(migrator.add_column(Packages._meta.name, c, getattr(Packages,c)))

                migrate(*opes)
                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.7.2.1'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info("Migrating from %s to %s" % (get_db_version(), next_version))

                opes = []

                columns = [c.name for c in wapt_db.get_columns('hostwsus')]
                for c in ['delayed',]:
                    if not c in columns:
                        opes.append(migrator.add_column(HostWsus._meta.name, c, getattr(HostWsus,c)))

                migrate(*opes)
                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.7.3.0'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info("Migrating from %s to %s" % (get_db_version(), next_version))

                opes = []

                columns = [c.name for c in wapt_db.get_columns('hosts')]
                if not 'host_capabilities' in columns:
                    opes.append(migrator.add_column(Hosts._meta.name, 'host_capabilities',Hosts.host_capabilities))

                migrate(*opes)
                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.7.3.1'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info("Migrating from %s to %s" % (get_db_version(), next_version))
                StoreDownload.create_table(fail_silently=True)
                StoreMember.create_table(fail_silently=True)
                StoreUsage.create_table(fail_silently=True)

                opes = []

                columns = [c.name for c in wapt_db.get_columns('hosts')]
                if not 'waptwua_rules' in columns:
                    opes.append(migrator.add_column(Hosts._meta.name, 'waptwua_rules',Hosts.waptwua_rules))
                if not 'host_metrics' in columns:
                    opes.append(migrator.add_column(Hosts._meta.name, 'host_metrics',Hosts.host_metrics))
                if not 'wapt_version' in columns:
                    opes.append(migrator.add_column(Hosts._meta.name, 'wapt_version',Hosts.wapt_version))

                migrate(*opes)
                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.7.3.2'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info("Migrating from %s to %s" % (get_db_version(), next_version))
                opes = []

                columns = [c.name for c in wapt_db.get_columns('hostpackagesstatus')]
                if not 'signature_date' in columns:
                    opes.append(migrator.add_column(HostPackagesStatus._meta.name, 'signature_date',HostPackagesStatus.signature_date))
                columns = [c.name for c in wapt_db.get_columns('packages')]
                if not 'signature_date' in columns:
                    opes.append(migrator.add_column(Packages._meta.name, 'signature_date',Packages.signature_date))

                migrate(*opes)
                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.7.3.6'
        if get_db_version() < next_version:
            with wapt_db.atomic():
                logger.info("Migrating from %s to %s" % (get_db_version(), next_version))
                opes = []

                columns = [c.name for c in wapt_db.get_columns('packages')]
                if not 'filename' in columns:
                    opes.append(migrator.add_column(Packages._meta.name, 'filename',Packages.filename))

                columns = [c.name for c in wapt_db.get_columns('wsusupdates')]
                for col in ['is_beta','is_uninstallable','uninstallation_impact','installation_impact','support_url','release_notes','uninstallation_notes','languages']:
                    if not col in columns:
                        opes.append(migrator.add_column(WsusUpdates._meta.name, col,getattr(WsusUpdates,col)))

                migrate(*opes)
                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.7.4'
        if get_db_version() <= next_version:
            with wapt_db.atomic():
                logger.info("Migrating from %s to %s" % (get_db_version(), next_version))
                opes = []

                columns = [c.name for c in wapt_db.get_columns('packages')]
                if not 'name' in columns:
                    opes.append(migrator.add_column(Packages._meta.name, 'name',Packages.name))
                if not 'valid_from' in columns:
                    opes.append(migrator.add_column(Packages._meta.name, 'valid_from',Packages.valid_from))
                if not 'valid_until' in columns:
                    opes.append(migrator.add_column(Packages._meta.name, 'valid_until',Packages.valid_until))
                if not 'forced_install_on' in columns:
                    opes.append(migrator.add_column(Packages._meta.name, 'forced_install_on',Packages.forced_install_on))
                if not 'categories' in columns:
                    opes.append(migrator.add_column(Packages._meta.name, 'categories',Packages.categories))
                if not 'hosts_server_uuid_listening' in [i.name for i in wapt_db.get_indexes('hosts')]:
                    wapt_db.execute_sql('create index hosts_server_uuid_listening on hosts(server_uuid,listening_address)')

                migrate(*opes)
                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.7.5'
        if get_db_version() <= next_version:
            with wapt_db.atomic():
                logger.info("Migrating from %s to %s" % (get_db_version(), next_version))
                opes = []

                ReportingSnapshots.create_table(fail_silently=True);

                columns = [c.name for c in wapt_db.get_columns('reportingqueries')]
                if not 'snapshot_period' in columns:
                    opes.append(migrator.add_column(ReportingQueries._meta.name, 'snapshot_period',ReportingQueries.snapshot_period))
                if not 'snapshot_name' in columns:
                    opes.append(migrator.add_column(ReportingQueries._meta.name, 'snapshot_name',ReportingQueries.snapshot_name))
                if not 'last_snapshot_date' in columns:
                    opes.append(migrator.add_column(ReportingQueries._meta.name, 'last_snapshot_date',ReportingQueries.last_snapshot_date))
                if not 'snapshot_ttl' in columns:
                    opes.append(migrator.add_column(ReportingQueries._meta.name, 'snapshot_ttl',ReportingQueries.snapshot_ttl))

                migrate(*opes)
                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.7.6'
        if get_db_version() <= next_version:
            with wapt_db.atomic():
                logger.info("Migrating from %s to %s" % (get_db_version(), next_version))
                opes = []

                SyncStatus.create_table(fail_silently=True);

                columns = [c.name for c in wapt_db.get_columns('syncstatus')]
                if not 'version' in columns:
                    opes.append(migrator.add_column(SyncStatus._meta.name, 'version',SyncStatus.version))
                if not 'changelog' in columns:
                    opes.append(migrator.add_column(SyncStatus._meta.name, 'changelog',SyncStatus.changelog))

                SiteRules.create_table(fail_silently=True);

                columns = [c.name for c in wapt_db.get_columns('siterules')]
                if not 'sequence' in columns:
                    opes.append(migrator.add_column(SiteRules._meta.name, 'sequence',SiteRules.sequence))
                if not 'name' in columns:
                    opes.append(migrator.add_column(SiteRules._meta.name, 'name',SiteRules.name))
                if not 'condition' in columns:
                    opes.append(migrator.add_column(SiteRules._meta.name, 'condition',SiteRules.condition))
                if not 'value' in columns:
                    opes.append(migrator.add_column(SiteRules._meta.name, 'value',SiteRules.value))
                if not 'repo_url' in columns:
                    opes.append(migrator.add_column(SiteRules._meta.name, 'repo_url',SiteRules.repo_url))
                if not 'repositories' in columns:
                    opes.append(migrator.add_column(SiteRules._meta.name, 'repositories',SiteRules.repositories))
                columns = [c.name for c in wapt_db.get_columns('hosts')]
                if not 'platform' in columns:
                    opes.append(migrator.add_column(Hosts._meta.name, 'platform',Hosts.platform))
                if not 'repositories' in columns:
                    opes.append(migrator.add_column(Hosts._meta.name, 'repositories',Hosts.repositories))

                migrate(*opes)
                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.7.6.5'
        if get_db_version() <= next_version:
            with wapt_db.atomic():
                logger.info("Migrating from %s to %s" % (get_db_version(), next_version))
                opes = []

                columns = [c.name for c in wapt_db.get_columns('siterules')]
                if not 'repositories' in columns:
                    opes.append(migrator.add_column(SiteRules._meta.name, 'repositories',SiteRules.repositories))

                migrate(*opes)
                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

        next_version = '1.7.6.6'
        if get_db_version() <= next_version:
            with wapt_db.atomic():
                logger.info("Migrating from %s to %s" % (get_db_version(), next_version))
                opes = []
                WaptUsers.create_table()
                WaptUserAcls.create_table()

                (admin,_) = WaptUsers.get_or_create(name='admin',user_fingerprint_sha1='admin')
                admin.save()

                (user,_) = WaptUsers.get_or_create(name='user',user_fingerprint_sha1='user')
                user.save()

                (acl,_) = WaptUserAcls.get_or_create(user_fingerprint_sha1='admin',acls=['admin'],perimeter_fingerprint='')
                acl.save()
                (acl,_) = WaptUserAcls.get_or_create(user_fingerprint_sha1='user',acls=['view'],perimeter_fingerprint='')
                acl.save()

                migrate(*opes)
                (v, created) = ServerAttribs.get_or_create(key='db_version')
                v.value = next_version
                v.save()

    finally:
        pass


if __name__ == '__main__':
    if platform.system() != 'Windows' and getpass.getuser() != 'wapt':
        print("""you should run this program as wapt:
                     sudo -u wapt python /opt/wapt/waptserver/model.py  <action>
                 actions : init_db
                           upgrade2postgres""")
        sys.exit(1)

    usage = """\
    %prog [-c configfile] [action]

    WAPT Server database reset / init / upgrade.

    action is either :
       init_db: initialize or upgrade an existing DB without dropping data
       reset_db: initiliaze or recreate an empty database dropping the data.
    """
    parser = OptionParser(usage=usage, version=__version__)
    parser.add_option(
        '-c',
        '--config',
        dest='configfile',
        default=waptserver.config.DEFAULT_CONFIG_FILE,
        help='Config file full path (default: %default)')
    parser.add_option('-l','--loglevel',dest='loglevel',default=None,type='choice',
            choices=['debug',   'warning','info','error','critical'],
            metavar='LOGLEVEL',help='Loglevel (default: warning)')
    parser.add_option('-d','--devel',dest='devel',default=False,action='store_true',
            help='Enable debug mode (for development only)')


    (options, args) = parser.parse_args()
    conf = waptserver.config.load_config(options.configfile)
    load_db_config(conf)

    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')


    if options.loglevel is not None:
        setloglevel(logger, options.loglevel)
    else:
        setloglevel(logger, conf['loglevel'])

    if len(args) == 1:
        action = args[0]
        if action == 'init_db':
            print ('initializing missing wapt tables without dropping data.')
            init_db(False)
            sys.exit(0)
        elif action == 'reset_db':
            print ('Drop existing tables and recreate wapt tables.')
            init_db(True)
            sys.exit(0)
    else:
        parser.print_usage()
