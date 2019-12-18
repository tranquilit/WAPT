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
from waptutils import __version__

import os
import re
import logging
import datetime
import time
import sys
import tempfile
import hashlib
import glob
import codecs
import base64
import zlib
import sqlite3
import json
import ujson
import StringIO
import requests
import cPickle
try:
    # pylint: disable=no-member
    # no error
    import requests.packages.urllib3
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    pass

import fnmatch
import ipaddress
import whichcraft
import subprocess
import platform
import socket
import ssl
import copy
import getpass
import psutil
import threading
import traceback
import uuid
import gc
import random
import string
import locale
import shlex
from iniparse import RawConfigParser,INIConfig
from optparse import OptionParser

from operator import itemgetter
from collections import namedtuple
from collections import OrderedDict
from collections import defaultdict
from types import ModuleType

import shutil
import urlparse
import zipfile

# conditionnal imports for windows or linux
if sys.platform=='win32':
    import windnsquery
    import win32api
    import ntsecuritycon
    import win32security
    import win32net
    import pywintypes
    import pythoncom
    from ntsecuritycon import DOMAIN_GROUP_RID_ADMINS,DOMAIN_GROUP_RID_USERS
    from ctypes import wintypes
    from winreg import HKEY_LOCAL_MACHINE,EnumKey,OpenKey,QueryValueEx,\
    EnableReflectionKey,DisableReflectionKey,QueryReflectionKey,\
    QueryInfoKey,DeleteValue,DeleteKey,\
    KEY_READ,KEY_WOW64_32KEY,KEY_WOW64_64KEY,KEY_ALL_ACCESS
    try:
        import requests_kerberos
        has_kerberos = True
    except:
        has_kerberos = False
elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
    has_kerberos=False
    pass

logger = logging.getLogger()

from waptutils import BaseObjectClass,ensure_list,ensure_unicode,default_http_headers,get_time_delta
from waptutils import httpdatetime2isodate,datetime2isodate,FileChunks,jsondump,ZipFile,LogOutput,isodate2datetime
from waptutils import import_code,import_setup,force_utf8_no_bom,format_bytes,wget,merge_dict,remove_encoding_declaration,list_intersection
from waptutils import _disable_file_system_redirection
from waptutils import get_requests_client_cert_session,get_main_ip

from waptcrypto import SSLCABundle,SSLCertificate,SSLPrivateKey,SSLCRL,SSLVerifyException,SSLCertificateSigningRequest
from waptcrypto import get_peer_cert_chain_from_server,default_pwd_callback,hexdigest_for_data,get_cert_chain_as_pem
from waptcrypto import sha256_for_data,EWaptMissingPrivateKey,EWaptMissingCertificate
from waptcrypto import is_pem_key_encrypted

from waptpackage import EWaptException,EWaptMissingLocalWaptFile,EWaptNotAPackage,EWaptNotSigned
from waptpackage import EWaptBadTargetOS,EWaptNeedsNewerAgent,EWaptDiskSpace
from waptpackage import EWaptUnavailablePackage,EWaptConflictingPackage
from waptpackage import EWaptDownloadError,EWaptMissingPackageHook

from waptpackage import REGEX_PACKAGE_CONDITION,WaptRemoteRepo,PackageEntry,PackageRequest,HostCapabilities,PackageKey
from waptpackage import make_valid_package_name

from itsdangerous import TimedJSONWebSignatureSerializer

import setuphelpers
import netifaces

try:
    from waptenterprise import enterprise_common
except ImportError:
    enterprise_common = None


class EWaptBadServerAuthentication(EWaptException):
    pass

def is_system_user():
    return setuphelpers.get_current_user().lower() == 'system'


###########################"
##################
def ipv4_to_int(ipaddr):
    (a,b,c,d) = ipaddr.split('.')
    return (int(a) << 24) + (int(b) << 16) + (int(c) << 8) + int(d)


def same_net(ip1,ip2,netmask):
    """Given 2 ipv4 address and mask, return True if in same subnet"""
    return (ipv4_to_int(ip1) & ipv4_to_int(netmask)) == (ipv4_to_int(ip2) & ipv4_to_int(netmask))


def host_ipv4():
    """return a list of (iface,mac,{addr,broadcast,netmask})"""
    ifaces = netifaces.interfaces()
    res = []
    for i in ifaces:
        params = netifaces.ifaddresses(i)
        if netifaces.AF_LINK in params and params[netifaces.AF_LINK][0]['addr'] and not params[netifaces.AF_LINK][0]['addr'].startswith('00:00:00'):
            iface = {'iface':i,'mac':params[netifaces.AF_LINK][0]['addr']}
            if netifaces.AF_INET in params:
                iface.update(params[netifaces.AF_INET][0])
            res.append( iface )
    return res


def tryurl(url,proxies=None,timeout=5.0,auth=None,verify_cert=False,cert=None):
    # try to get header for the supplied URL, returns None if no answer within the specified timeout
    # else return time to get he answer.
    with get_requests_client_cert_session(url=url,cert=cert,verify=verify_cert,proxies=proxies) as session:
        try:
            logger.debug(u'  trying %s' % url)
            starttime = time.time()
            headers = session.head(url=url,
                timeout=timeout,
                auth=auth,
                allow_redirects=True)
            if headers.ok:
                logger.debug(u'  OK')
                return time.time() - starttime
            else:
                headers.raise_for_status()
        except Exception as e:
            logger.debug(u'  Not available : %s' % ensure_unicode(e))
            return None

class EWaptCancelled(Exception):
    pass


class WaptBaseDB(BaseObjectClass):
    _dbpath = ''
    _db_version = None
    db = None
    curr_db_version = None

    def __init__(self,dbpath):
        self.transaction_depth = 0
        self._db_version = None
        self.dbpath = dbpath
        self.threadid = None

    @property
    def dbpath(self):
        return self._dbpath

    @dbpath.setter
    def dbpath(self,value):
        if not self._dbpath or (self._dbpath and self._dbpath != value):
            self._dbpath = value
            self.connect()

    def begin(self):
        # recreate a connection if not in same thread (reuse of object...)
        if self.threadid is not None and self.threadid != threading.current_thread().ident:
            logger.warning('Reset of DB connection, reusing wapt db object in a new thread')
            self.connect()
        elif self.threadid is None:
            self.connect()
        if self.transaction_depth == 0:
            logger.debug(u'DB Start transaction')
            self.db.execute('begin')
        self.transaction_depth += 1

    def commit(self):
        if self.transaction_depth > 0:
            self.transaction_depth -= 1
        else:
            logger.critical('Unexpected commit of an already committed transaction...')
            if logger.level == logging.DEBUG:
                raise Exception('Unexpected commit of an already committed transaction...')
        if self.transaction_depth == 0:
            logger.debug(u'DB commit')
            try:
                self.db.execute('commit')
            except:
                self.db.execute('rollback')
                raise

    def rollback(self):
        if self.transaction_depth > 0:
            self.transaction_depth -= 1
        if self.transaction_depth == 0:
            logger.debug(u'DB rollback')
            self.db.execute('rollback')

    def connect(self):
        if not self.dbpath:
            return
        logger.debug('Thread %s is connecting to wapt db' % threading.current_thread().ident)
        self.threadid = threading.current_thread().ident
        if not self.dbpath == ':memory:' and not os.path.isfile(self.dbpath):
            dirname = os.path.dirname(self.dbpath)
            if os.path.isdir (dirname)==False:
                os.makedirs(dirname)
            os.path.dirname(self.dbpath)
            self.db=sqlite3.connect(self.dbpath,detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
            self.db.isolation_level = None
            self.transaction_depth = 0
            self.initdb()
        elif self.dbpath == ':memory:':
            self.db=sqlite3.connect(self.dbpath,detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
            self.db.isolation_level = None
            self.transaction_depth = 0
            self.initdb()
        else:
            self.db=sqlite3.connect(self.dbpath,detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
            self.db.isolation_level = None
            self.transaction_depth = 0
            if self.curr_db_version != self.db_version:
                self.upgradedb()

    def __enter__(self):
        self.start_timestamp = time.time()
        self.begin()
        #logger.debug(u'DB enter %i' % self.transaction_depth)
        return self

    def __exit__(self, type, value, tb):
        if time.time()-self.start_timestamp>1.0:
            logger.debug('Transaction took too much time : %s' % (time.time()-self.start_timestamp,))
        if not value:
            #logger.debug(u'DB exit %i' % self.transaction_depth)
            self.commit()
        else:
            self.rollback()
            logger.debug(u'Error at DB exit %s, rollbacking\n%s' % (value,ensure_unicode(traceback.format_tb(tb))))

    @property
    def db_version(self):
        if not self._db_version:
            val = self.db.execute('select value from wapt_params where name="db_version"').fetchone()
            if val:
                self._db_version = val[0]
            else:
                raise Exception('Unknown DB Version')
        return self._db_version

    @db_version.setter
    def db_version(self,value):
        with self:
            self.db.execute('insert or replace into wapt_params(name,value,create_date) values (?,?,?)',('db_version',value,datetime2isodate()))
            self._db_version = value

    @db_version.deleter
    def db_version(self):
        with self:
            self.db.execute("delete from wapt_params where name = 'db_version'")
            self._db_version = None

    def initdb(self):
        pass

    def set_package_attribute(self,install_id,key,value):
        """Store permanently a (key/value) pair in database for a given package, replace existing one"""
        with self:
            self.db.execute('insert or replace into wapt_package_attributes(install_id,key,value,create_date) values (?,?,?,?)',(install_id,key,value,datetime2isodate()))

    def set_param(self,name,value,ptype=None):
        """Store permanently a (name/value) pair in database, replace existing one"""
        with self:
            if not value is None:
                if ptype is None:
                    if isinstance(value,(str,unicode)):
                        ptype = 'str'
                    # bool before int !
                    elif isinstance(value,bool):
                        ptype = 'bool'
                    elif isinstance(value,int):
                        ptype = 'int'
                    elif isinstance(value,float):
                        ptype = 'float'
                    elif isinstance(value,datetime.datetime):
                        ptype = 'datetime'
                    else:
                        ptype = 'json'

                if ptype in ('int','float'):
                    value = str(value)
                elif ptype in ('json','bool'):
                    value = jsondump(value)
                elif ptype == 'datetime':
                    value = datetime2isodate(value)
            self.db.execute('insert or replace into wapt_params(name,value,create_date,ptype) values (?,?,?,?)',(name,value,datetime2isodate(),ptype))

    def get_param(self,name,default=None,ptype=None):
        """Retrieve the value associated with name from database"""
        q = self.db.execute('select value,ptype from wapt_params where name=? order by create_date desc limit 1',(name,)).fetchone()
        if q:
            (value,sptype) = q
            if ptype is None:
                ptype = sptype
            if not value is None:
                if ptype == 'int':
                    value = long(value)
                elif ptype == 'float':
                    value = float(value)
                elif ptype in ('json','bool'):
                    value = ujson.loads(value)
                elif ptype == 'datetime':
                    value = isodate2datetime(value)
            return value
        else:
            return default

    def delete_param(self,name):
        with self:
            row =  self.db.execute('select value from wapt_params where name=? limit 1',(name,)).fetchone()
            if row:
                self.db.execute('delete from wapt_params where name=?',(name,))

    def query(self,query, args=(), one=False,as_dict=True):
        """
        execute la requete query sur la db et renvoie un tableau de dictionnaires
        """
        cur = self.db.execute(query, args)
        if as_dict:
            rv = [dict((cur.description[idx][0], value)
                   for idx, value in enumerate(row)) for row in cur.fetchall()]
        else:
            rv = cur.fetchall()
        return (rv[0] if rv else None) if one else rv


    def upgradedb(self,force=False):
        """Update local database structure to current version if rules are described in db_upgrades

        Args:
            force (bool): force upgrade even if structure version is greater than requested.

        Returns:
            tuple: (old_structure_version,new_structure_version)

        """
        with self:
            try:
                backupfn = ''
                # use cached value to avoid infinite loop
                old_structure_version = self._db_version
                if old_structure_version >= self.curr_db_version and not force:
                    logger.warning(u'upgrade db aborted : current structure version %s is newer or equal to requested structure version %s' % (old_structure_version,self.curr_db_version))
                    return (old_structure_version,old_structure_version)

                logger.info(u'Upgrade database schema')
                if self.dbpath != ':memory:':
                    # we will backup old data in a file so that we can rollback
                    backupfn = tempfile.mktemp('.sqlite')
                    logger.debug(u' copy old data to %s' % backupfn)
                    shutil.copy(self.dbpath,backupfn)
                else:
                    backupfn = None

                # we will backup old data in dictionaries to convert them to new structure
                logger.debug(u' backup data in memory')
                old_datas = {}
                tables = [ c[0] for c in self.db.execute('SELECT name FROM sqlite_master WHERE type = "table" and name like "wapt_%"').fetchall()]
                for tablename in tables:
                    old_datas[tablename] = self.query('select * from %s' % tablename)
                    logger.debug(u' %s table : %i records' % (tablename,len(old_datas[tablename])))

                logger.debug(u' drop tables')
                for tablename in tables:
                    self.db.execute('drop table if exists %s' % tablename)

                # create new empty structure
                logger.debug(u' recreates new tables ')
                new_structure_version = self.initdb()
                del(self.db_version)
                # append old data in new tables
                logger.debug(u' fill with old data')
                for tablename in tables:
                    if old_datas[tablename]:
                        logger.debug(u' process table %s' % tablename)
                        allnewcolumns = [ c[0] for c in self.db.execute('select * from %s limit 0' % tablename).description]
                        # take only old columns which match a new column in new structure
                        oldcolumns = [ k for k in old_datas[tablename][0] if k in allnewcolumns ]

                        insquery = "insert into %s (%s) values (%s)" % (tablename,",".join(oldcolumns),",".join("?" * len(oldcolumns)))
                        for rec in old_datas[tablename]:
                            logger.debug(u' %s' %[ rec[oldcolumns[i]] for i in range(0,len(oldcolumns))])
                            self.db.execute(insquery,[ rec[oldcolumns[i]] for i in range(0,len(oldcolumns))] )

                # be sure to put back new version in table as db upgrade has put the old value in table
                self.db_version = new_structure_version
                return (old_structure_version,new_structure_version)
            except Exception as e:
                if backupfn:
                    logger.critical(u"UpgradeDB ERROR : %s, copy back backup database %s" % (e,backupfn))
                    shutil.copy(backupfn,self.dbpath)
                raise

class WaptSessionDB(WaptBaseDB):
    curr_db_version = '20181004'

    def __init__(self,username=''):
        super(WaptSessionDB,self).__init__(None)
        if not username:
            username = setuphelpers.get_current_user()
        self.username = username
        self.dbpath = os.path.join(setuphelpers.application_data(),'wapt','waptsession.sqlite')

    def initdb(self):
        """Initialize current sqlite db with empty table and return structure version"""
        assert(isinstance(self.db,sqlite3.Connection))
        logger.debug(u'Initialize Wapt session database')

        self.db.execute("""
        create table if not exists wapt_sessionsetup (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username varchar(255),
          package_uuid varchar(255),
          package varchar(255),
          version varchar(255),
          architecture varchar(255),
          install_date varchar(255),
          install_status varchar(255),
          install_output TEXT,
          process_id integer
          )"""
                        )
        self.db.execute("""
            create index if not exists idx_sessionsetup_username on wapt_sessionsetup(username,package);""")

        self.db.execute("""
            create index if not exists idx_sessionsetup_package on wapt_sessionsetup(package);""")

        self.db.execute("""
            create index if not exists idx_sessionsetup_package_uuid on wapt_sessionsetup(package_uuid);""")

        self.db.execute("""
        create table if not exists wapt_params (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name  varchar(64),
          value text,
          ptype varchar(10),
          create_date varchar(255)
          ) """)

        self.db.execute("""
          create unique index if not exists idx_params_name on wapt_params(name);
          """)

        self.db_version = self.curr_db_version
        return self.curr_db_version

    def add_start_install(self,package_entry):
        """Register the start of installation in local db

        Returns:
            int : rowid of the inserted record
        """
        with self:
            cur = self.db.execute("""delete from wapt_sessionsetup where package=?""" ,(package_entry.package,))
            cur = self.db.execute("""\
                  insert into wapt_sessionsetup (
                    username,
                    package_uuid,
                    package,
                    version,
                    architecture,
                    install_date,
                    install_status,
                    install_output,
                    process_id
                    ) values (?,?,?,?,?,?,?,?,?)
                """,(
                     self.username,
                     package_entry.package_uuid,
                     package_entry.package,
                     package_entry.version,
                     package_entry.architecture,
                     datetime2isodate(),
                     'INIT',
                     '',
                     os.getpid()
                   ))
            return cur.lastrowid

    def update_install_status(self,rowid,set_status=None,append_output=None):
        """Update status of package installation on localdb"""
        with self:
            if set_status in ('OK','WARNING','ERROR'):
                pid = None
            else:
                pid = os.getpid()
            cur = self.db.execute("""\
                  update wapt_sessionsetup
                    set install_status=coalesce(?,install_status),install_output = coalesce(install_output,'') || ?,process_id=?
                    where rowid = ?
                """,(
                     set_status,
                     ensure_unicode(append_output) if append_output is not None else '',
                     pid,
                     rowid,
                     )
                   )
            return cur.lastrowid

    def update_install_status_pid(self,pid,set_status='ERROR'):
        """Update status of package installation on localdb"""
        with self:
            cur = self.db.execute("""\
                  update wapt_sessionsetup
                    set install_status=coalesce(?,install_status) where process_id = ?
                """,(
                     set_status,
                     pid,
                     )
                   )
            return cur.lastrowid

    def remove_install_status(self,package):
        """Remove status of package installation from localdb

        >>> wapt = Wapt()
        >>> wapt.forget_packages('tis-7zip')
        ???
        """
        with self:
            cur = self.db.execute("""delete from wapt_sessionsetup where package=?""" ,(package,))
            return cur.rowcount

    def remove_obsolete_install_status(self,installed_packages):
        """Remove local user status of packages no more installed"""
        with self:
            cur = self.db.execute("""delete from wapt_sessionsetup where package not in (%s)"""%\
                ','.join('?' for i in installed_packages), installed_packages)
            return cur.rowcount

    def is_installed(self,package,version):
        p = self.query('select * from  wapt_sessionsetup where package=? and version=? and install_status="OK"',(package,version))
        if p:
            return p[0]
        else:
            return None


class WaptDB(WaptBaseDB):
    """Class to manage SQLite database with local installation status"""

    curr_db_version = '20190606'

    def initdb(self):
        """Initialize current sqlite db with empty table and return structure version"""
        assert(isinstance(self.db,sqlite3.Connection))
        logger.debug(u'Initialize Wapt database')
        self.db.execute("""
        create table if not exists wapt_package (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          package_uuid varchar(255),
          package varchar(255),
          categories varchar(255),
          version varchar(255),
          architecture varchar(255),
          section varchar(255),
          priority varchar(255),
          maintainer varchar(255),
          description varchar(255),
          filename varchar(255),
          size integer,
          md5sum varchar(255),
          depends varchar(800),
          conflicts varchar(800),
          sources varchar(255),
          repo_url varchar(255),
          repo varchar(255),
          signer varchar(255),
          signer_fingerprint varchar(255),
          signature varchar(255),
          signature_date varchar(255),
          signed_attributes varchar(800),
          min_wapt_version varchar(255),
          maturity varchar(255),
          locale varchar(255),
          installed_size integer,
          target_os varchar(255),
          max_os_version varchar(255),
          min_os_version varchar(255),
          impacted_process varchar(255),
          audit_schedule varchar(255),
          name varchar(255),
          editor varchar(255),
          keywords varchar(255),
          licence varchar(255),
          homepage varchar(255),
          valid_from varchar(255),
          valid_until varchar(255),
          forced_install_on varchar(255)
        )"""
                        )
        self.db.execute("""
        create index if not exists idx_package_name on wapt_package(package);""")
        self.db.execute("""
        create index if not exists idx_package_uuid on wapt_package(package_uuid);""")

        self.db.execute("""
        create table if not exists wapt_localstatus (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          package_uuid varchar(255),
          package varchar(255),
          version varchar(255),
          version_pinning varchar(255),
          explicit_by varchar(255),
          architecture varchar(255),
          section varchar(255),
          priority varchar(255),
          maturity varchar(255),
          locale varchar(255),
          install_date varchar(255),
          install_status varchar(255),
          install_output TEXT,
          install_params VARCHAR(800),
          uninstall_key varchar(255),
          setuppy TEXT,
          process_id integer,
          depends varchar(800),
          conflicts varchar(800),
          last_audit_on varchar(255),
          last_audit_status varchar(255),
          last_audit_output TEXT,
          next_audit_on varchar(255),
          impacted_process varchar(255),
          audit_schedule varchar(255),
          persistent_dir varchar(255)
          )
          """)

          # in a separate table :
          # upgrade_action -> 'INSTALL, UPGRADE, REMOVE'
          # related_package_uuid  -> package which will replace
          # upgrade_planned_on
          # upgrade_deadline
          # upgrade_allowed_schedules
          # retry_count
          # max_retry_count


        self.db.execute("""
        create index if not exists idx_localstatus_name on wapt_localstatus(package);
        """)
        self.db.execute("""
        create index if not exists idx_localstatus_status on wapt_localstatus(install_status);
        """)
        self.db.execute("""
        create index if not exists idx_localstatus_next_audit_on on wapt_localstatus(next_audit_on);
        """)
        self.db.execute("""
        create index if not exists idx_localstatus_package_uuid on wapt_localstatus(package_uuid);
        """)

        self.db.execute("""
        create table if not exists wapt_params (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name  varchar(64),
          value text,
          ptype varchar(10),
          create_date varchar(255)
          ) """)

        self.db.execute("""
          create unique index if not exists idx_params_name on wapt_params(name);
          """)

        self.db.execute("""CREATE TRIGGER IF NOT EXISTS inc_rev_ins_status
            AFTER INSERT ON wapt_params
            WHEN NEW.name not in ('status_revision','last_update_server_hashes')
            BEGIN
                update wapt_params set value=cast(value as integer)+1
                where name='status_revision';
            END
            """)

        self.db.execute("""CREATE TRIGGER IF NOT EXISTS inc_rev_upd_status
            AFTER UPDATE ON wapt_params
            WHEN NEW.name <> 'status_revision'
            BEGIN
                update wapt_params set value=cast(value as integer)+1
                where name='status_revision';
            END
            """)

        self.db.execute("""CREATE TRIGGER IF NOT EXISTS inc_rev_del_status
            AFTER DELETE ON wapt_params
            WHEN OLD.name <> 'status_revision'
            BEGIN
                update wapt_params set value=cast(value as integer)+1
                where name='status_revision';
            END
            """)

        # action : install, remove, check, session_setup, update, upgrade
        # state : draft, planned, postponed, running, done, error, canceled
        self.db.execute("""
            CREATE TABLE if not exists wapt_task (
                id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
                action varchar(16),
                state varchar(16),
                current_step varchar(255),
                process_id integer,
                start_date varchar(255),
                finish_date varchar(255),
                package_name varchar(255),
                username varchar(255),
                package_version_min varchar(255),
                package_version_max varchar(255),
                rundate_min varchar(255),
                rundate_max varchar(255),
                rundate_nexttry varchar(255),
                runduration_max integer,
                created_date varchar(255),
                run_params VARCHAR(800),
                run_output TEXT
            );
                """)

        self.db.execute("""
          create index if not exists idx_task_state on wapt_task(state);
          """)

        self.db.execute("""
          create index if not exists idx_task_package_name on wapt_task(package_name);
          """)

        self.db.execute("""
        create table if not exists wapt_sessionsetup (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username varchar(255),
          package varchar(255),
          version varchar(255),
          architecture varchar(255),
          maturity varchar(255),
          locale varchar(255),
          install_date varchar(255),
          install_status varchar(255),
          install_output TEXT
          )"""
                        )
        self.db.execute("""
        create index idx_sessionsetup_username on wapt_sessionsetup(username,package);""")

        self.db_version = self.curr_db_version
        return self.curr_db_version


    def add_package_entry(self,package_entry,locale_code=None):
        with self:
            # for backward compatibility with packages signed without package_uuid attribute
            if not package_entry.package_uuid:
                package_entry.package_uuid = package_entry.make_fallback_uuid()
            cur = self.db.execute("""delete from wapt_package where package=? and version=? and architecture=? and maturity=? and locale=?""" ,
                (package_entry.package,package_entry.version,package_entry.architecture,package_entry.maturity,package_entry.locale))
            cur = self.db.execute("""\
                  insert into wapt_package (
                    package_uuid,
                    package,
                    categories,
                    name,
                    version,
                    section,
                    priority,
                    architecture,
                    maintainer,
                    description,
                    filename,
                    size,
                    md5sum,
                    depends,
                    conflicts,
                    sources,
                    repo_url,
                    repo,
                    signer,
                    signer_fingerprint,
                    maturity,
                    locale,
                    signature,
                    signature_date,
                    signed_attributes,
                    min_wapt_version,
                    installed_size,
                    max_os_version,
                    min_os_version,
                    target_os,
                    impacted_process,
                    audit_schedule,
                    editor,
                    keywords,
                    licence,
                    homepage,
                    valid_from,
                    valid_until,
                    forced_install_on
                    ) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,(
                    package_entry.package_uuid,
                    package_entry.package,
                    package_entry.categories,
                    package_entry.name,
                    package_entry.version,
                    package_entry.section,
                    package_entry.priority,
                    package_entry.architecture,
                    package_entry.maintainer,
                    package_entry.get_localized_description(locale_code),
                    package_entry.filename,
                    package_entry.size,
                    package_entry.md5sum,
                    package_entry.depends,
                    package_entry.conflicts,
                    package_entry.sources,
                    package_entry.repo_url,
                    package_entry.repo,
                    package_entry.signer,
                    package_entry.signer_fingerprint,
                    package_entry.maturity,
                    package_entry.locale,
                    package_entry.signature,
                    package_entry.signature_date,
                    package_entry.signed_attributes,
                    package_entry.min_wapt_version,
                    package_entry.installed_size,
                    package_entry.max_os_version,
                    package_entry.min_os_version,
                    package_entry.target_os,
                    package_entry.impacted_process,
                    package_entry.audit_schedule,
                    package_entry.editor,
                    package_entry.keywords,
                    package_entry.licence,
                    package_entry.homepage,
                    package_entry.valid_from,
                    package_entry.valid_until,
                    package_entry.forced_install_on,
                    )
                )
            return cur.lastrowid

    def add_start_install(self,package_entry,params_dict={},explicit_by=None):
        """Register the start of installation in local db

        Args:
            params_dict (dict) : dictionary of parameters provided on command line with --param or by the server
            explicit_by (str) : username of initiator of the install.
                          if not None, install is not a dependencie but an explicit manual install
            setuppy (str) : python source code used for install, uninstall or session_setup
                            code used for uninstall or session_setup must use only wapt self library as
                            package content is no longer available at this step.

        Returns:
            int : rowid of the inserted install status row
        """
        with self:
            if package_entry.package_uuid:
                # keep old entry for reference until install is completed.
                cur = self.db.execute("""update wapt_localstatus set install_status='UPGRADING' where package=? and package_uuid <> ?""" ,(package_entry.package,package_entry.package_uuid))
                cur = self.db.execute("""delete from wapt_localstatus where package_uuid=?""" ,(package_entry.package_uuid,))
            else:
                cur = self.db.execute("""delete from wapt_localstatus where package_uuid=?""" ,(package_entry.package,))

            cur = self.db.execute("""\
                  insert into wapt_localstatus (
                    package_uuid,
                    package,
                    version,
                    section,
                    priority,
                    architecture,
                    install_date,
                    install_status,
                    install_output,
                    install_params,
                    explicit_by,
                    process_id,
                    maturity,
                    locale,
                    depends,
                    conflicts,
                    impacted_process,
                    audit_schedule
                    ) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,(
                    package_entry.package_uuid,
                    package_entry.package,
                    package_entry.version,
                    package_entry.section,
                    package_entry.priority,
                    package_entry.architecture,
                    datetime2isodate(),
                    'INIT',
                    '',
                    jsondump(params_dict),
                    explicit_by,
                    os.getpid(),
                    package_entry.maturity,
                    package_entry.locale,
                    package_entry.depends,
                    package_entry.conflicts,
                    package_entry.impacted_process,
                    package_entry.audit_schedule,
                   ))
            return cur.lastrowid

    def update_install_status(self,rowid,set_status=None,append_output=None,uninstall_key=None,persistent_dir=None):
        """Update status of package installation on localdb"""
        with self:
            if set_status in ('OK','WARNING','ERROR'):
                pid = None
            else:
                pid = os.getpid()

            cur = self.db.execute("""\
                  update wapt_localstatus
                    set install_status=coalesce(?,install_status),
                        install_output = coalesce(install_output,'') || ?,
                        uninstall_key=coalesce(?,uninstall_key),
                        process_id=?,
                        persistent_dir = coalesce(?,persistent_dir)
                    where rowid = ?
                """,(
                     set_status,
                     ensure_unicode(append_output) if append_output is not None else u'',
                     uninstall_key,
                     pid,
                     persistent_dir,
                     rowid,
                     )
                   )

            # removed repviously installed package entry
            install_rec = self.query('select package_uuid,package from wapt_localstatus where rowid = ?',(rowid,),one=True)
            if install_rec and set_status in ('OK','WARNING','ERROR'):
                cur = self.db.execute("""delete from wapt_localstatus where package=? and rowid <> ?""" ,(install_rec['package'],rowid))
            return cur.lastrowid

    def update_audit_status(self,rowid,set_status=None,set_output=None,append_output=None,set_last_audit_on=None,set_next_audit_on=None):
        """Update status of package installation on localdb"""
        with self:
            if set_status in ('OK','WARNING','ERROR'):
                pid = None
            else:
                pid = os.getpid()

            # retrieve last status
            #cur = self.db.execute("""select last_audit_status,last_audit_on,next_audit_on from wapt_localstatus where rowid = ?""",(rowid,))
            #(last_audit_status,last_audit_on,next_audit_on) = cur.fetchone()
            #if last_audit_on is None:
            #    last_audit_on = datetime2isodate()
            #
            #if set_status is None:
            #    set_status = last_audit_status

            #if set_status is None:
            #    set_status = 'RUNNING'

            cur = self.db.execute("""\
                  update wapt_localstatus set
                    last_audit_status=coalesce(?,last_audit_status,'RUNNING'),
                    last_audit_on=coalesce(?,last_audit_on),
                    last_audit_output = coalesce(?,last_audit_output,'') || ?,
                    process_id=?,next_audit_on=coalesce(?,next_audit_on)
                    where rowid = ?
                """,(
                     set_status,
                     set_last_audit_on,
                     set_output,
                     append_output if append_output is not None else '',
                     pid,
                     set_next_audit_on,
                     rowid
                     )
                   )
            return cur.lastrowid

    def update_install_status_pid(self,pid,set_status='ERROR'):
        """Update status of package installation on localdb"""
        with self:
            cur = self.db.execute("""\
                  update wapt_localstatus
                    set install_status=coalesce(?,install_status) where process_id = ?
                """,(
                     set_status,
                     pid,
                     )
                   )
            return cur.lastrowid

    def switch_to_explicit_mode(self,package,user_id):
        """Set package install mode to manual
        so that package is not removed
        when meta packages don't require it anymore
        """
        with self:
            cur = self.db.execute("""\
                  update wapt_localstatus
                    set explicit_by=? where package = ?
                """,(
                     user_id,
                     package,
                     )
                   )
            return cur.lastrowid

    def store_setuppy(self,rowid,setuppy=None,install_params={}):
        """Update status of package installation on localdb"""
        with self:
            cur = self.db.execute("""\
                  update wapt_localstatus
                    set setuppy=?,install_params=? where rowid = ?
                """,(
                     remove_encoding_declaration(setuppy),
                     jsondump(install_params),
                     rowid,
                     )
                   )
            return cur.lastrowid

    def remove_install_status(self,package=None,package_uuid=None):
        """Remove status of package installation from localdb"""
        with self:
            if package_uuid is not None:
                cur = self.db.execute("""delete from wapt_localstatus where package_uuid=?""" ,(package_uuid,))
            else:
                cur = self.db.execute("""delete from wapt_localstatus where package=?""" ,(package,))
            return cur.rowcount

    def known_packages(self):
        """Return a dict of all known packages PackageKey(s) indexed by package_uuid

        Returns:
            dict  {'package_uuid':PackageKey(package)}
        """
        q = self.db.execute("""\
              select distinct wapt_package.package_uuid,wapt_package.package,wapt_package.version,architecture,locale,maturity from wapt_package
           """)
        return {e[0] : PackageKey(e[0],e[1],Version(e[2]),*e[3:]) for e in q.fetchall()}

    def packages_matching(self,package_cond):
        """Return an ordered list of available packages entries which match
        the condition "packagename[([=<>]version)]?"
        version ascending

        Args:
            package_cond (PackageRequest or str): filter packages and determine the ordering

        Returns:
            list of PakcageEntry

        """
        if isinstance(package_cond,(unicode,str)):
            package_cond = PackageRequest(request=package_cond)

        q = self.query_package_entry("""\
              select * from wapt_package where package = ?
           """, (package_cond.package,))
        result = [ p for p in q if package_cond.is_matched_by(p) ]
        result.sort(cmp=lambda p1,p2: package_cond.compare_packages(p1,p2))
        return result

    def packages_search(self,searchwords=[],exclude_host_repo=True,section_filter=None,packages_filter=None):
        """Return a list of package entries matching the search words

        Args:
            searchwords (list): list of words which must be in package name or description
            exclude_host (bool): don't take in account packages comming from a repo named 'wapt-host"
            section_filter (list): list of packages sections to take in account
            packages_filter (PackageRequest): additional filters (arch, locale, maturities etc...)
                                              to take in account for filter and sort

        Returns:
            list of PackageEntry

        """
        if not isinstance(searchwords,list) and not isinstance(searchwords,tuple):
            searchwords = [searchwords]
        if not searchwords:
            words = []
            search = [u'1=1']
        else:
            words = [ u"%"+w.lower()+"%" for w in searchwords ]
            search = [u"lower(description || package) like ?"] *  len(words)
        if exclude_host_repo:
            search.append(u'repo <> "wapt-host"')
        if section_filter:
            section_filter = ensure_list(section_filter)
            search.append(u'section in ( %s )' %  u",".join(['"%s"' % x for x in  section_filter]))

        if isinstance(packages_filter,(unicode,str)):
            packages_filter = PackageRequest(request=packages_filter)

        result = self.query_package_entry(u"select * from wapt_package where %s" % " and ".join(search),words)
        if packages_filter is not None:
            result = [p for p in result if packages_filter.is_matched_by(packages_filter)]
            result.sort(cmp=lambda p1,p2: packages_filter.compare_packages(p1,p2))
        else:
            result.sort()
        return result

    def installed_package_names(self,include_errors=False):
        """
        """
        sql = ["select l.package from wapt_localstatus l"]
        if not include_errors:
            sql.append('where l.install_status in ("OK","UNKNOWN")')
        return [p['package'] for p in self.query('\n'.join(sql))]


    def installed(self,include_errors=False,include_setup=True):
        """Return a list of installed packages on this host (status 'OK' or 'UNKNWON')

        Args:
            include_errors (bool) : if False, only packages with status 'OK' and 'UNKNOWN' are returned
                                    if True, all packages are installed.
            include_setup (bool) : if True, setup.py files content is in the result rows

        Returns:
            list: of installed PackageEntry
        """
        sql = ["""\
              select l.package,l.version,l.architecture,l.install_date,l.install_status,l.install_output,l.install_params,%s
                l.uninstall_key,l.explicit_by,
                coalesce(l.depends,r.depends) as depends,coalesce(l.conflicts,r.conflicts) as conflicts,coalesce(l.section,r.section) as section,coalesce(l.priority,r.priority) as priority,
                r.maintainer,r.description,r.sources,r.filename,r.size,
                r.repo_url,r.md5sum,r.repo,r.signer,r.signature_date,r.signer_fingerprint,
                l.maturity,l.locale,
                l.last_audit_status,l.last_audit_on,l.last_audit_output,l.next_audit_on,l.package_uuid,
                l.persistent_dir
                from wapt_localstatus l
                left join wapt_package r on r.package=l.package and l.version=r.version and
                    (l.architecture is null or l.architecture=r.architecture) and
                    (l.maturity is null or l.maturity=r.maturity) and
                    (l.locale is null or l.locale=r.locale)
            """ % ( ('l.setuppy,' if include_setup else ''),) ]
        if not include_errors:
            sql.append('where l.install_status in ("OK","UNKNOWN")')

        q = self.query_package_entry('\n'.join(sql))
        result = []
        for p in q:
            result.append(p)
        return result

    def install_status(self,id):
        """Return the local install status for id

        Args:
            id: sql rowid

        Returns:
            dict : merge of package local install, audit and package attributes.

        """
        sql = ["""\
              select l.package,l.version,l.architecture,l.install_date,l.install_status,l.install_output,l.install_params,l.explicit_by,
                    l.depends,l.conflicts,l.uninstall_key,
                    l.last_audit_status,l.last_audit_on,l.last_audit_output,l.next_audit_on,l.audit_schedule,l.package_uuid,
                    r.section,r.priority,r.maintainer,r.description,r.sources,r.filename,r.size,r.signer,r.signature_date,r.signer_fingerprint,
                    r.repo_url,r.md5sum,r.repo,l.maturity,l.locale,l.persistent_dir
                from wapt_localstatus l
                left join wapt_package r on
                    r.package=l.package and l.version=r.version and
                    (l.architecture is null or l.architecture=r.architecture) and
                    (l.maturity is null or l.maturity=r.maturity) and
                    (l.locale is null or l.locale=r.locale)
                where l.id = ?
           """]

        q = self.query_package_entry('\n'.join(sql),args = [id])
        if q:
            return q[0]
        else:
            return None

    def installed_search(self,searchwords=[],include_errors=False):
        """Return a list of installed package entries based on search keywords


        Returns:
            list of PackageEntry merge with localstatus attributes without setuppy

        """
        if not isinstance(searchwords,list) and not isinstance(searchwords,tuple):
            searchwords = [searchwords]
        if not searchwords:
            words = []
            search = ['1=1']
        else:
            words = [ u"%"+w.lower()+"%" for w in searchwords ]
            search = [u"lower(l.package || (case when r.description is NULL then '' else r.description end) ) like ?"] *  len(words)
        if not include_errors:
            search.append(u'l.install_status in ("OK","UNKNOWN")')
        q = self.query_package_entry(u"""\
              select l.package,l.version,l.architecture,l.install_date,l.install_status,l.install_output,l.install_params,
                l.uninstall_key,l.explicit_by,
                coalesce(l.depends,r.depends) as depends,coalesce(l.conflicts,r.conflicts) as conflicts,coalesce(l.section,r.section) as section,coalesce(l.priority,r.priority) as priority,
                l.last_audit_status,l.last_audit_on,l.last_audit_output,l.next_audit_on,l.audit_schedule,l.package_uuid,
                r.maintainer,r.description,r.sources,r.filename,r.size,r.signer,r.signature_date,r.signer_fingerprint,
                r.repo_url,r.md5sum,r.repo,l.persistent_dir
              from wapt_localstatus l
                left join wapt_package r on r.package=l.package and l.version=r.version and (l.architecture is null or l.architecture=r.architecture)
              where %s
           """ % " and ".join(search),words)
        return q

    def installed_matching(self,package_cond,include_errors=False,include_setup=True):
        """Return a list of PackageEntry
        if one properly installed (if include_errors=False) package match the package condition 'tis-package (>=version)'

        Args:
            package_cond (str): package requirement to lookup
            include_errors

        Returns:
            list of PackageEntry merge with localstatus attributes WITH setuppy

        """
        if isinstance(package_cond,(str,unicode)):
            requ = package_cond
            package_cond = PackageRequest(request=requ)
        elif not isinstance(package_cond,PackageRequest):
            raise Exception('installed_matching: package_cond must be either str ot PackageRequest')

        package = package_cond.package

        if include_errors:
            status = '"OK","UNKNOWN","ERROR"'
        else:
            status = '"OK","UNKNOWN"'

        q = self.query_package_entry(u"""\
              select l.rowid,l.package_uuid,
                l.package,l.version,l.architecture,
                coalesce(l.locale,r.locale) as locale,
                coalesce(l.maturity,r.maturity) as maturity,
                l.install_date,l.install_status,l.install_output,l.install_params,%s
                l.persistent_dir,
                l.uninstall_key,l.explicit_by,
                l.last_audit_status,l.last_audit_on,l.last_audit_output,l.next_audit_on,
                coalesce(l.depends,r.depends) as depends,
                coalesce(l.conflicts,r.conflicts) as conflicts,
                coalesce(l.section,r.section) as section,
                coalesce(l.priority,r.priority) as priority,
                r.maintainer,r.description,r.sources,r.filename,r.size,r.signer,r.signature_date,r.signer_fingerprint,
                r.repo_url,r.md5sum,r.repo
                from wapt_localstatus l
                left join wapt_package r on r.package=l.package and l.version=r.version and (l.architecture is null or l.architecture=r.architecture)
              where l.package=? and l.install_status in (%s)
           """ % (('l.setuppy,' if include_setup else ''),status),(package,))
        return q[0] if q and package_cond.is_matched_by(q[0]) else None

    def upgradeable(self,include_errors=True):
        """Return a dictionary of upgradable Package entries"""
        result = {}
        allinstalled = self.installed(include_errors=True)
        for p in allinstalled:
            available = self.query_package_entry("""select * from wapt_package where package=?""",(p.package,))
            available.sort()
            available.reverse()
            if available and (available[0] > p) or (include_errors and (p.install_status == 'ERROR')):
                result[p.package] = available
        return result

    def audit_status(self):
        """Return WORST audit status among properly installed packages"""
        errors = self.query("""select count(*) from wapt_localstatus where install_status="OK" and last_audit_status="ERROR"  """,one=True,as_dict=False)[0]
        if errors>0:
            return 'ERROR'
        warnings = self.query("""select count(*) from wapt_localstatus where install_status="OK" and (last_audit_status is NULL or last_audit_status in ("WARNING","UNKNOWN")) """,one=True,as_dict=False)[0]
        if warnings and warnings>0:
            return 'WARNING'
        return 'OK'

    def build_depends(self,packages,packages_filter=None):
        """Given a list of packages conditions (packagename (optionalcondition))
        return a list of dependencies (packages conditions) to install


        Args:
            packages (list of str): list of packages requirements ( package_name(=version) )

        Returns:
            (list depends,list conflicts,list missing) : tuple of (all_depends,missing_depends)

        TODO : choose available dependencies in order to reduce the number of new packages to install

        >>> waptdb = WaptDB(':memory:')
        >>> office = PackageEntry('office','0')
        >>> firefox22 = PackageEntry('firefox','22')
        >>> firefox22.depends = 'mymissing,flash'
        >>> firefox24 = PackageEntry('firefox','24')
        >>> thunderbird = PackageEntry('thunderbird','23')
        >>> flash10 = PackageEntry('flash','10')
        >>> flash12 = PackageEntry('flash','12')
        >>> office.depends='firefox(<24),thunderbird,mymissing'
        >>> firefox22.depends='flash(>=10)'
        >>> firefox24.depends='flash(>=12)'
        >>> waptdb.add_package_entry(office)
        >>> waptdb.add_package_entry(firefox22)
        >>> waptdb.add_package_entry(firefox24)
        >>> waptdb.add_package_entry(flash10)
        >>> waptdb.add_package_entry(flash12)
        >>> waptdb.add_package_entry(thunderbird)
        >>> waptdb.build_depends('office')
        ([u'flash(>=10)', u'firefox(<24)', u'thunderbird'], [u'mymissing'])
        """
        if not isinstance(packages,list) and not isinstance(packages,tuple):
            packages = [packages]

        MAXDEPTH = 30
        # roots : list of initial packages to avoid infinite loops

        alldepends = []
        allconflicts = []
        missing = []
        explored = []

        def dodepends(packages,depth):
            if depth>MAXDEPTH:
                raise Exception('Max depth in build dependencies reached, aborting')
            package_request = PackageRequest(request=None,copy_from=packages_filter)
            # loop over all package names
            for package in packages:
                if not package in explored:
                    if isinstance(package,(str,unicode)):
                        package_request.request = package
                        entries = self.packages_matching(package_request)
                    else:
                        entries = self.packages_matching(package)

                    if not entries and package not in missing:
                        missing.append(package)
                    else:
                        # get depends of the most recent matching entry
                        # TODO : use another older if this can limit the number of packages to install !
                        depends = ensure_list(entries[-1].depends)
                        available_depends = []
                        for d in depends:
                            package_request.request = d
                            if self.packages_matching(package_request):
                                available_depends.append(d)
                            elif d not in missing:
                                missing.append(d)

                        newdepends = dodepends(available_depends,depth+1)
                        for d in newdepends:
                            if not d in alldepends:
                                alldepends.append(d)

                        for d in available_depends:
                            if not d in alldepends:
                                alldepends.append(d)

                        conflicts = ensure_list(entries[-1].conflicts)
                        for d in conflicts:
                            if not d in allconflicts:
                                allconflicts.append(d)

                    explored.append(package)
            return alldepends

        depth = 0
        alldepends = dodepends(packages,depth)
        return (alldepends,allconflicts,missing)

    def package_entry_from_db(self,package,version_min='',version_max=''):
        """Return the most recent package entry given its packagename and minimum and maximum version

        >>> waptdb = WaptDB(':memory:')
        >>> waptdb.add_package_entry(PackageEntry('dummy','1'))
        >>> waptdb.add_package_entry(PackageEntry('dummy','2'))
        >>> waptdb.add_package_entry(PackageEntry('dummy','3'))
        >>> waptdb.package_entry_from_db('dummy')
        PackageEntry('dummy','3')
        >>> waptdb.package_entry_from_db('dummy',version_min=2)
        PackageEntry('dummy','3')
        >>> waptdb.package_entry_from_db('dummy',version_max=1)
        PackageEntry('dummy','1')
        """
        result = PackageEntry()
        filter = ""
        if version_min is None:
            version_min=""
        if version_max is None:
            version_max=""

        if not version_min and not version_max:
            entries = self.query("""select * from wapt_package where package = ? order by version desc limit 1""",(package,))
        else:
            entries = self.query("""select * from wapt_package where package = ? and (version>=? or ?="") and (version<=? or ?="") order by version desc limit 1""",
                (package,version_min,version_min,version_max,version_max))
        if not entries:
            raise Exception('Package %s (min : %s, max %s) not found in local DB, please update' % (package,version_min,version_max))
        for k,v in entries[0].iteritems():
            setattr(result,k,v)
        return result

    def query_package_entry(self,query, args=(), one=False, package_request=None):
        """Execute the query on the db try to map result on PackageEntry attributes
        Fields which don't match attributes are added as attributes (and listed in _calc_attributes list)

        >>> waptdb = WaptDB(':memory:')
        >>> waptdb.add_package_entry(PackageEntry('toto','0',repo='main'))
        >>> waptdb.add_package_entry(PackageEntry('dummy','2',repo='main'))
        >>> waptdb.add_package_entry(PackageEntry('dummy','1',repo='main'))
        >>> waptdb.query_package_entry("select * from wapt_package where package=?",["dummy"])
        [PackageEntry('dummy','2'), PackageEntry('dummy','1')]
        >>> waptdb.query_package_entry("select * from wapt_package where package=?",["dummy"],one=True)
        PackageEntry('dummy','2')
        """
        result = []

        cur = self.db.execute(query, args)
        for row in cur.fetchall():
            pe = PackageEntry()
            rec_dict = dict((cur.description[idx][0], value) for idx, value in enumerate(row))
            for k in rec_dict:
                setattr(pe,k,rec_dict[k])
                # add joined field to calculated attributes list
                if not k in pe.all_attributes:
                    pe._calculated_attributes.append(k)
            if package_request is None or package_request.is_matched_by(pe):
                result.append(pe)

        if one and result:
            if not package_request:
                result = sorted(result)[-1]
            else:
                result = sorted(result,cmp=lambda p1,p2:package_request.compare_packages(p1,p2))[-1]

        return result

    def purge_repo(self,repo_name):
        """remove references to repo repo_name

        >>> waptdb = WaptDB('c:/wapt/db/waptdb.sqlite')
        >>> waptdb.purge_repo('main')
        """
        with self:
            self.db.execute('delete from wapt_package where repo=?',(repo_name,))

    def params(self,packagename):
        """Return install parameters associated with a package"""
        with self:
            cur = self.db.execute("""select install_params from wapt_localstatus where package=?""" ,(packagename,))
            rows = cur.fetchall()
            if rows:
                return ujson.loads(rows[0][0])

class WaptServer(BaseObjectClass):
    """Manage connection to waptserver"""

    def __init__(self,url=None,proxies={'http':None,'https':None},timeout = 5.0,dnsdomain=None,name='waptserver'):
        if url and url[-1]=='/':
            url = url.rstrip('/')
        self._server_url = url
        self._cached_dns_server_url = None

        self.name = name

        self.proxies=proxies
        self.timeout = timeout
        self.use_kerberos = False
        self.verify_cert = True

        self.client_certificate = None
        self.client_private_key = None

        self.interactive_session = False
        self.ask_user_password_hook = None

        self.private_key_password_callback=None

        self.capture_external_ip_callback = None
        if dnsdomain:
            self.dnsdomain = dnsdomain
        else:
            self.dnsdomain = setuphelpers.get_domain()

    def get_computer_principal(self):
        try:
            dnsdomain = setuphelpers.get_domain_fromregistry()
            if not dnsdomain:
                dnsdomain = self.dnsdomain

            return '%s@%s' % (setuphelpers.get_computername().upper(),dnsdomain.upper())
        except Exception as e:
            logger.critical('Unable to build computer_principal %s' % repr(e))
            raise

    def auth(self,action=None):
        if self._server_url:
            if action in ('add_host_kerberos','add_host'):
                scheme = urlparse.urlparse(self._server_url).scheme
                if scheme == 'https' and has_kerberos and self.use_kerberos:
                    return requests_kerberos.HTTPKerberosAuth(mutual_authentication=requests_kerberos.DISABLED)

                    # TODO : simple auth if kerberos is not available...
                else:
                    return self.ask_user_password(action)
            else:
                return self.ask_user_password(action)
        else:
            return None

    def get_private_key_password(self,location,identity):
        if self.private_key_password_callback is not None:
            return self.private_key_password_callback(location,identity)
        else:
            return None

    def get_requests_session(self,url=None,use_ssl_auth=True):
        if url is None:
            url = self.server_url
        if use_ssl_auth:
            if self.client_private_key and is_pem_key_encrypted(self.client_private_key):
                password = self.get_private_key_password(url,self.client_private_key)
            else:
                password = None
            cert = (self.client_certificate,self.client_private_key,password)
        else:
            cert = None
        session = get_requests_client_cert_session(url=url,cert=cert,verify=self.verify_cert,proxies=self.proxies)
        return session


    def save_server_certificate(self,server_ssl_dir=None,overwrite=False):
        """Retrieve certificate of https server for further checks

        Args:
            server_ssl_dir (str): Directory where to save x509 certificate file

        Returns:
            str : full path to x509 certificate file.

        """
        certs = get_peer_cert_chain_from_server(self.server_url)
        if certs:
            new_cert = certs[0]
            url = urlparse.urlparse(self.server_url)
            pem_fn = os.path.join(server_ssl_dir,new_cert.cn+'.crt')

            if new_cert.cn != url.hostname:
                logger.warning('Warning, certificate CN %s sent by server does not match URL host %s' % (new_cert.cn,url.hostname))

            if not os.path.isdir(server_ssl_dir):
                os.makedirs(server_ssl_dir)
            if os.path.isfile(pem_fn):
                try:
                    # compare current and new cert
                    old_cert = SSLCertificate(pem_fn)
                    if old_cert.modulus != new_cert.modulus:
                        if not overwrite:
                            raise Exception('Can not save server certificate, a file with same name but from diffrent key already exists in %s' % pem_fn)
                        else:
                            logger.info('Overwriting old server certificate %s with new one %s'%(old_cert.fingerprint,new_cert.fingerprint))
                    return pem_fn
                except Exception as e:
                    logger.critical('save_server_certificate : %s'% repr(e))
                    raise
            # write full chain
            open(pem_fn,'wb').write(get_cert_chain_as_pem(certs))
            logger.info('New certificate %s with fingerprint %s saved to %s'%(new_cert,new_cert.fingerprint,pem_fn))
            return pem_fn
        else:
            return None

    def reset_network(self):
        """called by wapt when network configuration has changed"""
        self._cached_dns_server_url = None

    @property
    def server_url(self):
        """Return fixed url if any, else request DNS

        >>> server = WaptServer(timeout=4)
        >>> print server.dnsdomain
        tranquilit.local
        >>> server = WaptServer(timeout=4)
        >>> print server.dnsdomain
        tranquilit.local
        >>> print server.server_url
        https://wapt.tranquil.it
        """
        if self._server_url is not None:
            return self._server_url
        else:
            if not self._cached_dns_server_url:
                try:
                    self._cached_dns_server_url = self.find_wapt_server_url()
                except Exception:
                    logger.debug('DNS server is not available to get waptserver URL')
            return self._cached_dns_server_url

    def find_wapt_server_url(self):
        """Search the WAPT server with dns SRV query

        preference for SRV is :
           same priority asc -> weight desc

        >>> WaptServer(dnsdomain='tranquilit.local',timeout=4,url=None).server_url
        'https://wapt.tranquilit.local'
        >>> WaptServer(url='http://srvwapt:8080',timeout=4).server_url
        'http://srvwapt:8080'
        """

        try:
            if self.dnsdomain and self.dnsdomain != '.':
                # find by dns SRV _waptserver._tcp
                try:
                    logger.debug(u'Trying _waptserver._tcp.%s SRV records' % self.dnsdomain)
                    answers = windnsquery.dnsquery_srv('_waptserver._tcp.%s' % self.dnsdomain)
                    servers = []
                    for (priority,weight,wapthost,port) in answers:
                        # get first numerical ipv4 from SRV name record
                        try:
                            if port == 443:
                                url = 'https://%s' % (wapthost)
                                servers.append((priority,-weight,url))
                            else:
                                url = 'http://%s:%i' % (wapthost,port)
                                servers.append((priority,-weight,url))
                        except Exception as e:
                            logging.debug('Unable to resolve : error %s' % (ensure_unicode(e),))

                    if servers:
                        servers.sort()
                        logger.debug(u'  Defined servers : %s' % (servers,))
                        return servers[0][2]

                    if not answers:
                        logger.debug(u'  No _waptserver._tcp.%s SRV record found' % self.dnsdomain)
                except Exception as e:
                    logger.debug(u'  DNS resolver exception _SRV records: %s' % (ensure_unicode(e),))
                    raise

            else:
                logger.warning(u'Local DNS domain not found, skipping SRV _waptserver._tcp search ')

            return None
        except Exception as e:
            logger.debug(u'WaptServer.find_wapt_server_url: DNS resolver exception: %s' % (e,))
            raise

    @server_url.setter
    def server_url(self,value):
        """Wapt main repository URL
        """
        # remove / at the end
        if value:
            value = value.rstrip('/')
        self._server_url = value

    def load_config(self,config,section='global'):
        """Load waptserver configuration from inifile
        """
        if not section:
            section = 'global'
        if config.has_section(section):
            self.name = section
            if config.has_option(section,'wapt_server'):
                # if defined but empty, look in dns srv
                url = config.get(section,'wapt_server')
                if url:
                    self._server_url = url
                else:
                    self._server_url = None
            else:
                # no server at all
                self._server_url = ''

            if  config.has_option(section,'use_kerberos'):
                self.use_kerberos =  config.getboolean(section,'use_kerberos')

            if config.has_option(section,'use_http_proxy_for_server') and config.getboolean(section,'use_http_proxy_for_server'):
                if config.has_option(section,'http_proxy'):
                    self.proxies = {'http':config.get(section,'http_proxy'),'https':config.get(section,'http_proxy')}
                else:
                    self.proxies = None
            else:
                self.proxies = {'http':None,'https':None}

            if config.has_option(section,'wapt_server_timeout'):
                self.timeout = config.getfloat(section,'wapt_server_timeout')

            if config.has_option(section,'dnsdomain'):
                self.dnsdomain = config.get(section,'dnsdomain')

            if config.has_option(section,'verify_cert'):
                try:
                    self.verify_cert = config.getboolean(section,'verify_cert')
                except:
                    self.verify_cert = config.get(section,'verify_cert')
                    if self.verify_cert == '':
                        self.verify_cert = '0'
                    elif not os.path.isfile(self.verify_cert):
                        logger.warning(u'waptserver certificate %s declared in configuration file can not be found. Waptserver communication will fail' % self.verify_cert)

            if config.has_option(section,'client_certificate'):
                self.client_certificate = config.get(section,'client_certificate')

            if config.has_option(section,'client_private_key'):
                self.client_private_key = config.get(section,'client_private_key')

        return self

    def load_config_from_file(self,config_filename,section='global'):
        """Load waptserver configuration from an inifile located at config_filename

        Args:
            config_filename (str) : path to wapt inifile
            section (str): ini section from which to get parameters. default to 'global'

        Returns:
            WaptServer: self

        """
        ini = RawConfigParser()
        ini.read(config_filename)
        self.load_config(ini,section)
        return self

    def get(self,action,auth=None,timeout=None,use_ssl_auth=True):
        """ """
        surl = self.server_url
        if surl:
            with self.get_requests_session(surl,use_ssl_auth=use_ssl_auth) as session:
                req = session.get("%s/%s" % (surl,action),
                    timeout=timeout or self.timeout,
                    auth=auth,
                    allow_redirects=True)
                if req.status_code == 401:
                    req = session.get("%s/%s" % (surl,action),
                        timeout=timeout or self.timeout,
                        auth=self.auth(action=action),
                        allow_redirects=True)

                req.raise_for_status()
                if req.headers.get('X-Remote-IP') and self.capture_external_ip_callback:
                    self.capture_external_ip_callback(req.headers['X-Remote-IP'])
                return ujson.loads(req.content)
        else:
            raise Exception(u'Wapt server url not defined or not found in DNS')

    def head(self,action,auth=None,timeout=None,use_ssl_auth=True):
        """ """
        surl = self.server_url
        if surl:
            with self.get_requests_session(surl,use_ssl_auth=use_ssl_auth) as session:
                req = session.head("%s/%s" % (surl,action),
                    timeout=timeout or self.timeout,
                    auth=auth,
                    allow_redirects=True)
                if req.status_code == 401:
                    req = session.head("%s/%s" % (surl,action),
                        timeout=timeout or self.timeout,
                        auth=self.auth(action=action),
                        allow_redirects=True)

                req.raise_for_status()
                if req.headers.get('X-Remote-IP') and self.capture_external_ip_callback:
                    self.capture_external_ip_callback(req.headers['X-Remote-IP'])
                return req.headers
        else:
            raise Exception(u'Wapt server url not defined or not found in DNS')

    def post(self,action,data=None,files=None,auth=None,timeout=None,signature=None,signer=None,content_length=None,use_ssl_auth=True):
        """Post data to waptserver using http POST method

        Add a signature to the posted data using host certificate.

        Posted Body is gzipped

        Args:
            action (str): doc part of the url
            data (str) : posted data body
            files (list or dict) : list of filenames

        """
        surl = self.server_url
        if surl:
            with self.get_requests_session(surl,use_ssl_auth=use_ssl_auth) as session:
                if data:
                    session.headers.update({
                        'Content-type': 'binary/octet-stream',
                        'Content-transfer-encoding': 'binary',
                        })
                    if isinstance(data,str):
                        session.headers['Content-Encoding'] = 'gzip'
                        data = zlib.compress(data)

                if signature:
                    session.headers.update({
                        'X-Signature': base64.b64encode(signature),
                        })
                if signer:
                    session.headers.update({
                        'X-Signer': signer,
                        })

                if content_length is not None:
                    session.headers['Content-Length'] = "%s" % content_length

                if isinstance(files,list):
                    files_dict = {}
                    for fn in files:
                        with open(fn,'rb') as f:
                            files_dict[os.path.basename(fn)] = f.read()
                elif isinstance(files,dict):
                    files_dict = files
                else:
                    files_dict = None

                # check if auth is required before sending data in chunk
                retry_count=0
                if files_dict:
                    while True:
                        req = session.head("%s/%s" % (surl,action),
                                timeout=timeout or self.timeout,
                                auth=auth,
                                allow_redirects=True)
                        if req.status_code == 401:
                            retry_count += 1
                            if retry_count >= 3:
                                raise EWaptBadServerAuthentication('Authentication failed on server %s for action %s' % (self.server_url,action))
                            auth = self.auth(action=action)
                        else:
                            break

                while True:
                    req = session.post("%s/%s" % (surl,action),
                        data=data,
                        files=files_dict,
                        timeout=timeout or self.timeout,
                        auth=auth,
                        allow_redirects=True)

                    if (req.status_code == 401) and (retry_count < 3):
                        retry_count += 1
                        if retry_count >= 3:
                            raise EWaptBadServerAuthentication('Authentication failed on server %s for action %s' % (self.server_url,action))
                        auth = self.auth(action=action)
                    else:
                        break
                req.raise_for_status()
                if req.headers.get('X-Remote-IP') and self.capture_external_ip_callback:
                    self.capture_external_ip_callback(req.headers['X-Remote-IP'])
                return ujson.loads(req.content)
        else:
            raise Exception(u'Wapt server url not defined or not found in DNS')

    def client_auth(self):
        """Return SSL pair (cert,key) filenames for client side SSL auth

        Returns:
            tuple: (cert path,key path,strkeypassword)
        """
        if self.client_certificate and os.path.isfile(self.client_certificate):
            if self.client_private_key is None:
                cert = SSLCertificate(self.client_certificate)
                key = cert.matching_key_in_dirs(password_callback=self.get_private_key_password)
                self.client_private_key = key.private_key_filename
            return (self.client_certificate,self.client_private_key,self.get_private_key_password(self.server_url,self.client_certificate))
        else:
            return None


    def available(self):
        if self.server_url:
            with self.get_requests_session() as session:
                try:
                    req = session.head("%s/ping" % (self.server_url),
                        timeout=self.timeout,
                        auth=None,
                        allow_redirects=True)
                    if req.status_code == 401:
                        req = session.head("%s/ping" % (self.server_url),
                            timeout=self.timeout,
                            auth=self.auth(action='ping'),
                            allow_redirects=True)
                    req.raise_for_status()
                    return True
                except Exception as e:
                    logger.debug(u'Wapt server %s unavailable because %s'%(self._server_url,ensure_unicode(e)))
                    return False
        else:
            logger.debug(u'Wapt server is unavailable because no URL is defined')
            return False

    def as_dict(self):
        result = {}
        attributes = ['server_url','proxies','dnsdomain']
        for att in attributes:
            result[att] = getattr(self,att)
        return result

    def upload_packages(self,packages,auth=None,timeout=None,progress_hook=None):
        """Upload a list of PackageEntry with local wapt build/signed files

        Returns:
            dict: {'ok','errors'} list of http post upload results
        """
        if not isinstance(packages,list):
            packages = [packages]

        files = {}

        ok = []
        errors = []

        for package in packages:
            if not isinstance(package,PackageEntry):
                pe = PackageEntry().load_control_from_wapt(package)
                package_filename = package
            else:
                pe = package
                package_filename = pe.localpath

            # TODO : issue if more hosts to upload than allowed open file handles.
            if pe.localpath and os.path.isfile(pe.localpath):
                if pe.section in ['host','group','unit','profile']:
                    # small local files, don't stream, we will upload many at once with form encoded files
                    files[os.path.basename(package_filename)] = open(pe.localpath,'rb').read()
                else:
                    # stream it immediately
                    logger.debug('Uploading %s to server %s' % (pe.localpath,self.server_url))
                    res = self.post('api/v3/upload_packages',data = FileChunks(pe.localpath,progress_hook=progress_hook).get(),auth=auth,timeout=300)
                    if not res['success']:
                        errors.append(res)
                        logger.critical('Error when uploading package %s: %s'% (pe.localpath, res['msg']))
                    else:
                        ok.append(res)
            elif pe._package_content is not None:
                # cached package content for hosts
                files[os.path.basename(package_filename)] = pe._package_content
            else:
                raise EWaptMissingLocalWaptFile('No content to upload for %s' % pe.asrequirement())

        if files:
            try:
                logger.debug('Uploading %s files to server %s'% (len(files),self.server_url))
                res = self.post('api/v3/upload_packages',files=files,auth=auth,timeout=300)
                if not res['success']:
                    errors.append(res)
                    logger.critical('Error when uploading packages: %s'% (res['msg']))
                else:
                    ok.append(res)
            finally:
                pass
        return dict(ok=ok,errors=errors)


    def ask_user_password(self,action=None):
        """Ask for basic auth if server requires it"""
        if self.ask_user_password_hook is not None:
            return self.ask_user_password_hook(action) # pylint: disable=not-callable
        elif self.interactive_session:
            user = raw_input(u'Please provide username for action "%s" on server %s: ' % (action,self.server_url))
            if user:
                password = getpass.getpass('Password: ')
                if user and password:
                    return (ensure_unicode(user).encode('utf8'),ensure_unicode(password).encode('utf8'))
                else:
                    return None
        else:
            return None

    def __repr__(self):
        try:
            return '<WaptServer %s>' % self.server_url
        except:
            return '<WaptServer %s>' % 'unknown'


class WaptRepo(WaptRemoteRepo):
    """Gives access to a remote http repository, with a zipped Packages packages index
    Find its repo_url based on
    * repo_url explicit setting in ini config section [<name>]
    * if there is some rules use rules
    >>> repo = WaptRepo(name='main',url='http://wapt/wapt',timeout=4)
    >>> packages = repo.packages()
    >>> len(packages)
    """

    def __init__(self,url=None,name='wapt',verify_cert=None,http_proxy=None,timeout=None,cabundle=None,config=None,WAPT=None):
        """Initialize a repo at url "url".

        Args:
            name (str): internal local name of this repository
            url  (str): http URL to the repository.
                 If url is None, the url is requested at the server.
            http_proxy (str): URL to http proxy or None if no proxy.
            timeout (float): timeout in seconds for the connection to the rmeote repository
            wapt_server (str): WAPT Server URL to use for autodiscovery if url is not supplied.

        .. versionchanged:: 1.4.0
           authorized_certs (list):  list of trusted SSL certificates to filter out untrusted entries.
                                 if None, no check is performed. All antries are accepted.
        .. versionchanged:: 1.5.0
           cabundle (SSLCABundle):  list of trusted SSL ca certificates to filter out untrusted entries.
                                     if None, no check is performed. All antries are accepted.

        """
        self._WAPT = None
        self.WAPT = WAPT
        # create additional properties
        self._cached_wapt_repo_url = None
        self._rules = None
        self._rulesdb = None
        self.iswaptwua = True if name=='waptwua' else False
        WaptRemoteRepo.__init__(self,url=url,name=name,verify_cert=verify_cert,http_proxy=http_proxy,timeout=timeout,cabundle=cabundle,config=config)


    def reset_network(self):
        """called by wapt when network configuration has changed"""
        self.cached_wapt_repo_url = None
        self._packages = None
        self._packages_date = None

    @property
    def WAPT(self):
        return self._WAPT

    @WAPT.setter
    def WAPT(self,value):
        if value!=self.WAPT:
            self._WAPT=value

    @property
    def rulesdb(self):
        """
        Get rules from DB (or from _rulesdb if they were set in this instance)
        """
        if self._rulesdb is None:
            self._rulesdb = self.WAPT.waptdb.get_param('rules-%s' %(self.name)) if self.WAPT is not None else None
        return self._rulesdb

    @rulesdb.setter
    def rulesdb(self,value):
        if value!=self._rulesdb:
            self.reset_network()
            self._rulesdb=value

    @property
    def cached_wapt_repo_url(self):
        if self._cached_wapt_repo_url is not None:
            return self._cached_wapt_repo_url
        else:
            return self.find_wapt_repo_url() if self.rulesdb else None

    @cached_wapt_repo_url.setter
    def cached_wapt_repo_url(self,value):
        if value!=self._cached_wapt_repo_url:
            if value:
                value = value.rstrip('/')
            self._cached_wapt_repo_url=value

    @property
    def repo_url(self):
        """Repository URL

        Fixed url if none is set in wapt-get.ini by querying the server.

        The URL is queried once and then cached into a local property.

        Returns:
            str: url to the repository

        >>> repo = WaptRepo(name='wapt',timeout=4)
        >>> print repo.wapt_server
        http://wapt.wapt.fr/
        >>> repo = WaptRepo(name='wapt',timeout=4)
        >>> print repo.wapt_server
        http://wapt.wapt.fr/
        >>> print repo.repo_url
        http://srvwapt.tranquilit.local/wapt
        """
        calculated_repo = self.cached_wapt_repo_url
        return calculated_repo if (calculated_repo is not None and calculated_repo!='') else self._repo_url

    @repo_url.setter
    def repo_url(self,value):
        if value:
            value = value.rstrip('/')

        if value != self._repo_url:
            self.reset_network()
            self._repo_url = value

    def rules(self):
        """
        Return the list of rules in Packages/Rules
        """
        def check_instance_of_repo(value):
            return (self.iswaptwua and 'waptwua' in value) or (isinstance(self,WaptHostRepo) and 'wapt-host' in value) or (isinstance(self,WaptRepo) and 'wapt' in value)

        if not self.repo_url:
            raise EWaptException('Repository URL for %s is empty. Add a %s section in ini' % (self.name,self.name))

        if self._rules is None:
            self._rules = []

        if isinstance(self,WaptHostRepo) and self.repo_url.endswith('-host'):
            url=self.repo_url[:-5]
        else:
            url=None

        if not self._rules:
            (_packages_index_str,_packages_index_date) = self._get_packages_index_data(url)
            with zipfile.ZipFile(StringIO.StringIO(_packages_index_str)) as waptzip:
                if 'Rules' in waptzip.namelist():
                    json_rules = json.loads(codecs.decode(waptzip.read(name='Rules'),'utf-8'))
                    for rule in json_rules:
                        try:
                            if check_instance_of_repo(rule['repositories']):
                                signer_cert_ca = SSLCABundle()
                                signer_cert_ca.add_certificates_from_pem(rule['signer_certificate'])
                                chain = self.cabundle.check_certificates_chain(signer_cert_ca.certificates())
                                rule['verified_by'] = chain[0].verify_claim(rule,required_attributes=rule['signed_attributes'])
                                self._rules.append(rule)
                                rule['active_rule'] = False
                        except:
                            logger.debug('Cert not recognize or bad signature for : \n%s' % (rule))
                    self._rulesdb=self._rules
                    self.reset_network()
        return self._rules

    def find_wapt_repo_url(self):
        """Find a wapt_repo_url from rules
        Returns:
            str: URL to the repo.
        """
        def rule_agent_ip(value):
            return ipaddress.ip_address(get_main_ip().decode('utf-8')) in ipaddress.ip_network(value.decode('utf-8'))

        def rule_domain(value):
            return setuphelpers.get_domain() == value

        def rule_hostname(value):
            return fnmatch.fnmatch(setuphelpers.get_hostname(),value)

        def rule_public_ip(value):
            ip=self.WAPT.waptdb.get_param('last_external_ip')
            return ip and (ipaddress.ip_address(ip.decode('utf-8')) in ipaddress.ip_network(value.decode('utf-8')))

        def rule_site(value):
            return self.WAPT.get_host_site() == value

        def check_rule(rule,value):
            return {
                    'AGENT IP':rule_agent_ip,
                    'DOMAIN':rule_domain,
                    'HOSTNAME':rule_hostname,
                    'PUBLIC IP':rule_public_ip,
                    'SITE':rule_site
                    }[rule](value)

        for rule in sorted(self.rulesdb,key=itemgetter('sequence')):
            try:
                if check_rule(rule['condition'],rule['value']) and (super(WaptRepo,self).is_available(url=rule['repo_url']) is not None):
                    self.cached_wapt_repo_url=rule['repo_url']+'-host' if isinstance(self,WaptHostRepo) else rule['repo_url']
                    rule['active_rule']=True
                    return self.cached_wapt_repo_url
            except Exception as e:
                logger.warning("Warning a rule failed %s\n, exception :%s" % (rule,str(e)))
                rule['exception']=str(e)
        self.cached_wapt_repo_url=''
        return None

    def load_config(self,config,section=None):
        """Load waptrepo configuration from inifile section.

        Use name of repo as section name if section is not provided.
        Use 'global' if no section named section in ini file
        """
        if not section:
             section = self.name

        # creates a default parser with a default section if None provided to get defaults
        if config is None:
            config = RawConfigParser(self._default_config)
            config.add_section(section)

        if not config.has_section(section):
            section = 'global'

        if config.has_option(section,'repo_url'):
            self._repo_url = config.get(section,'repo_url')

        WaptRemoteRepo.load_config(self,config,section)
        return self

    def as_dict(self):
        result = super(WaptRepo,self).as_dict()
        rules={}
        result.update(
            {
            'repo_url':self.repo_url,
            'rules':self._rules,
            })
        return result

    def __repr__(self):
        return '<WaptRepo %s>' % (self.repo_url,)

class WaptHostRepo(WaptRepo):
    """Dummy http repository for host packages

    >>> host_repo = WaptHostRepo(name='wapt-host',host_id=['0D2972AC-0993-0C61-9633-529FB1A177E3','4C4C4544-004E-3510-8051-C7C04F325131'])
    >>> host_repo.load_config_from_file(r'C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini')
    >>> host_repo.packages()
    [PackageEntry('0D2972AC-0993-0C61-9633-529FB1A177E3','10') ,
     PackageEntry('4C4C4544-004E-3510-8051-C7C04F325131','30') ]
    """

    def __init__(self,url=None,name='wapt-host',verify_cert=None,http_proxy=None,timeout = None,host_id=None,cabundle=None,config=None,host_key=None,WAPT=None):
        self._host_id = None
        self.host_key = None
        WaptRepo.__init__(self,url=url,name=name,verify_cert=verify_cert,http_proxy=http_proxy,timeout = timeout,cabundle=cabundle,config=config,WAPT=WAPT)
        self.host_id = host_id

        if host_key:
            self.host_key = host_key

    def host_package_url(self,host_id=None):
        if host_id is None:
            if self.host_id and isinstance(self.host_id,list):
                host_id = self.host_id[0]
            else:
                host_id = self.host_id
        return  "%s/%s.wapt" % (self.repo_url,host_id)

    def is_available(self):
        logger.debug(u'Checking availability of %s' % (self.name))
        try:
            host_package_url = self.host_package_url()
            with self.get_requests_session() as session:
                logger.debug(u'Trying to get  host package for %s at %s' % (self.host_id,host_package_url))
                req = session.head(host_package_url,
                    timeout=self.timeout,
                    allow_redirects=True)
                req.raise_for_status()
                packages_last_modified = req.headers.get('last-modified')

                return httpdatetime2isodate(packages_last_modified)
        except requests.HTTPError as e:
            logger.info(u'No host package available at this time for %s on %s' % (self.host_id,self.name))
            return None

    def load_config(self,config,section=None):
        """Load waptrepo configuration from inifile section.

        Use name of repo as section name if section is not provided.
        Use 'global' if no section named section in ini file
        """
        if not section:
             section = self.name

        # creates a default parser with a default section if None provided to get defaults
        if config is None:
            config = RawConfigParser(self._default_config)
            config.add_section(section)

        if not config.has_section(section):
            if config.has_section('wapt-main'):
                section = 'wapt-main'
            else:
                section = 'global'
        self._section = section

        WaptRepo.load_config(self,config,section)
        return self

    @property
    def repo_url(self):
        # hack to get implicit repo_url from main repo_url
        repo_url = super(WaptHostRepo,self).repo_url
        if repo_url and self._section in ['wapt-main','global'] and not repo_url.endswith('-host'):
            return repo_url+'-host'
        else:
            return repo_url

    @repo_url.setter
    def repo_url(self,value):
        if value:
            value = value.rstrip('/')

        if value != self._repo_url:
            self.reset_network()
            self._repo_url = value

    @property
    def host_id(self):
        return self._host_id

    @host_id.setter
    def host_id(self,value):
        if value != self._host_id:
            self._packages = None
            self._packages_date = None
            self._index = {}
        self._host_id = value

    def _load_packages_index(self):
        self._packages = []
        self._index = {}
        self.discarded = []
        if not self.repo_url:
            raise EWaptException(u'URL for WaptHostRepo repository %s is empty. Either add a wapt-host section in ini, or add a correct wapt_server and rules' % (self.name))
        if self.host_id and not isinstance(self.host_id,list):
            host_ids = [self.host_id]
        else:
            host_ids = self.host_id

        with self.get_requests_session() as session:
            for host_id in host_ids:
                host_package_url = self.host_package_url(host_id)
                logger.debug(u'Trying to get  host package for %s at %s' % (host_id,host_package_url))
                host_package = session.get(host_package_url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    )

                # prepare a package entry for further check
                package = PackageEntry()
                package.package = host_id
                package.repo = self.name
                package.repo_url = self.repo_url

                if host_package.status_code == 404:
                    # host package not found
                    logger.info('No host package found for %s' % host_id)
                else:
                    # for other than not found error, add to the discarded list.
                    # this can be consulted for mass changes to not recreate host packages because of temporary failures
                    try:
                        host_package.raise_for_status()
                    except requests.HTTPError as e:
                        logger.info(u'Discarding package for %s: error %s' % (package.package,e))
                        self.discarded.append(package)
                        continue

                    content = host_package.content

                    if not content.startswith(zipfile.stringFileHeader):
                        # try to decrypt package data
                        if self.host_key:
                            _host_package_content = self.host_key.decrypt_fernet(content)
                        else:
                            raise EWaptNotAPackage(u'Package for %s does not look like a Zip file and no key is available to try to decrypt it'% host_id)
                    else:
                        _host_package_content = content

                    # Packages file is a zipfile with one Packages file inside
                    with ZipFile(StringIO.StringIO(_host_package_content)) as zip:
                        control_data = codecs.decode(zip.read(name='WAPT/control'),'UTF-8')
                        package._load_control(control_data)
                        package.filename = package.make_package_filename()

                        try:
                            cert_data = zip.read(name='WAPT/certificate.crt')
                            signers_bundle = SSLCABundle()
                            signers_bundle.add_certificates_from_pem(cert_data)
                        except Exception as e:
                            logger.warning('Error reading host package certificate: %s'%repr(e))
                            signers_bundle = None

                    if self.is_locally_allowed_package(package):
                        try:
                            if self.cabundle is not None:
                                package.check_control_signature(self.cabundle,signers_bundle = signers_bundle)
                            self._packages.append(package)
                            if package.package not in self._index or self._index[package.package] < package:
                                self._index[package.package] = package

                            # keep content with index as it should be small
                            package._package_content = _host_package_content
                            package._packages_date = httpdatetime2isodate(host_package.headers.get('last-modified',None))

                            # TODO better
                            self._packages_date = package._packages_date

                        except (SSLVerifyException,EWaptNotSigned) as e:
                            logger.critical("Control data of package %s on repository %s is either corrupted or doesn't match any of the expected certificates %s" % (package.asrequirement(),self.name,self.cabundle))
                            self.discarded.append(package)
                    else:
                        logger.info('Discarding %s on repo "%s" because of local whitelist/blacklist rules' % (package.asrequirement(),self.name))
                        self.discarded.append(package)


    def download_packages(self,package_requests,target_dir=None,usecache=True,printhook=None):
        """Download a list of packages from repo

        Args:
            package_request (list,PackateEntry): a list of PackageEntry to download
            target_dir (str): where to store downloaded Wapt Package files
            usecache (bool): wether to try to use cached Wapt files if checksum is ok
            printhook (callable): to show progress of download

        Returns:
            dict: {"downloaded":[local filenames],"skipped":[filenames in cache],"errors":[],"packages":self.packages()}
        """
        if not isinstance(package_requests,(list,tuple)):
            package_requests = [ package_requests ]
        if not target_dir:
            target_dir = tempfile.mkdtemp()
        downloaded = []
        errors = []

        self._load_packages_index()

        # if multithread... we don't have host package in memory cache from last self._load_packages_index
        for pr in package_requests:
            for pe in self.packages():
                if ((isinstance(pr,PackageEntry) and (pe == pr)) or
                   (isinstance(pr,(str,unicode)) and pe.match(pr))):
                    if not pe.filename:
                        # fallback
                        pfn = os.path.join(target_dir,pe.make_package_filename())
                    else:
                        pfn = os.path.join(target_dir,pe.filename)

                    if pe._package_content is not None:
                        with open(pfn,'wb') as package_zip:
                            package_zip.write(pe._package_content)
                        pe.localpath = pfn
                        # for further reference
                        if isinstance(pr,PackageEntry):
                            pr.localpath = pfn
                        downloaded.append(pfn)
                        if not os.path.isfile(pfn):
                            logger.warning('Unable to write host package %s into %s' % (pr.asrequirement(),pfn))
                            errors.append(pfn)
                    else:
                        logger.warning('No host package content for %s' % (pr.asrequirement(),))
                    break

        return {"downloaded":downloaded,"skipped":[],"errors":[],"packages":self.packages()}

    def __repr__(self):
        return '<WaptHostRepo %s for host_id %s >' % (self.repo_url,self.host_id)

class WaptPackageInstallLogger(LogOutput):
    """Context handler to log all print messages to a wapt package install log

    Args:
        wapt_context (Wapt): Wapt instance
        package_name (str): name of running or installed package local status where to log status and output
    >>>
    """
    def __init__(self,console,wapt_context=None,install_id=None,user=None,running_status='RUNNING',exit_status='OK',error_status='ERROR'):
        self.wapt_context = wapt_context
        self.install_id = install_id

        self.user = user
        if self.user is None:
            self.user = setuphelpers.get_current_user()

        def update_install_status(append_output=None,set_status=None,context=None):
            if self.wapt_context:
                self.wapt_context.update_package_install_status(
                    rowid=context.install_id,
                    set_status=set_status,
                    append_output=append_output)

                if hasattr(self.wapt_context,'events') and self.wapt_context.events:
                    self.wapt_context.events.post_event('PRINT',ensure_unicode(append_output))

        LogOutput.__init__(self,console=console,
            update_status_hook=update_install_status,
            context=self,
            running_status=running_status,
            exit_status=exit_status,
            error_status=error_status)

class WaptPackageSessionSetupLogger(LogOutput):
    """Context handler to log all print messages to a wapt package install log

    Args:
        wapt_context (Wapt): Wapt instance
        package_name (str): name of running or installed package local status where to log status and output
    >>>
    """
    def __init__(self,console,waptsessiondb,install_id,running_status='RUNNING',exit_status=None,error_status='ERROR'):
        self.waptsessiondb = waptsessiondb
        self.install_id = install_id

        def update_install_status(append_output=None,set_status=None,context=None):
            self.waptsessiondb.update_install_status(
                rowid=context.install_id,
                set_status=set_status,
                append_output=append_output)

        LogOutput.__init__(self,console=console,
            update_status_hook=update_install_status,
            context=self,
            running_status=running_status,
            exit_status=exit_status,
            error_status=error_status)

class WaptPackageAuditLogger(LogOutput):
    """Context handler to log all print messages to a wapt package audit log

    Args:
        console (file) : sys.stderr
        wapt_context (Wapt): Wapt instance
        install_id (int): name of running or installed package local status where to log status and output
    >>>
    """
    def __init__(self,console,wapt_context=None,install_id=None,user=None,running_status='RUNNING',exit_status=None,error_status='ERROR'):
        self.wapt_context = wapt_context
        self.install_id = install_id

        self.user = user
        if self.user is None:
            self.user = setuphelpers.get_current_user()

        def update_audit_status(append_output=None,set_status=None,context=None):
            self.wapt_context.waptdb.update_audit_status(
                rowid=context.install_id,
                set_status=set_status,
                append_output=append_output)

        LogOutput.__init__(self,console=console,
            update_status_hook=update_audit_status,
            context=self,
            running_status=running_status,
            exit_status=exit_status,
            error_status=error_status)

######################

class Wapt(BaseObjectClass):
    """Global WAPT engine"""
    global_attributes = ['wapt_base_dir','waptserver','config_filename','proxies','repositories','personal_certificate_path','public_certs_dir','package_cache_dir','dbpath']

    def __init__(self,config=None,config_filename=None,defaults=None,disable_update_server_status=True):
        """Initialize engine with a configParser instance (inifile) and other defaults in a dictionary
        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> updates = wapt.update()
        >>> 'count' in updates and 'added' in updates and 'upgrades' in updates and 'date' in updates and 'removed' in updates
        True
        """
        # used to signal to cancel current operations ASAP
        self.task_is_cancelled = threading.Event()

        assert not config or isinstance(config,RawConfigParser)
        self._waptdb = None
        self._waptsessiondb = None
        self._dbpath = None
        # cached runstatus to avoid setting in db if not changed.
        self._runstatus = None
        self.use_hostpackages = False
        self.use_ad_groups = False

        self._repositories = None

        self.dry_run = False

        self.upload_cmd = None
        self.upload_cmd_host = self.upload_cmd
        self.after_upload = None
        self.proxies = None
        self.language = setuphelpers.get_language()
        self.locales = [setuphelpers.get_language()]
        self.maturities = ['PROD','']
        # default maturity when importing or creating new package
        self.default_maturity = ''

        self.filter_on_host_cap=True

        self.use_http_proxy_for_repo = False
        self.use_http_proxy_for_server = False

        self.public_certs_dir = None

        self.forced_uuid = None
        self.use_fqdn_as_uuid = False

        try:
            self.wapt_base_dir = os.path.abspath(os.path.dirname(__file__))
        except NameError:
            self.wapt_base_dir = os.getcwdu()

        self.private_dir = os.path.join(self.wapt_base_dir,'private')
        self.persistent_root_dir = os.path.join(self.wapt_base_dir,'private','persistent')
        self.token_lifetime = 24*60*60


        self.disable_update_server_status = disable_update_server_status

        self.config = config
        self.config_filename = config_filename
        if not self.config_filename:
            self.config_filename = os.path.join(self.wapt_base_dir,'wapt-get.ini')

        self.package_cache_dir = os.path.join(os.path.dirname(self.config_filename),u'cache')
        if not os.path.exists(self.package_cache_dir):
            os.makedirs(self.package_cache_dir)

        # to allow/restrict installation, supplied to packages
        self.user = setuphelpers.get_current_user()
        self.usergroups = None

        self.sign_digests = ['sha256']

        # host key cache
        self._host_key = None

        self._host_certificate = None
        self._host_certificate_timestamp = None

        # for private key password dialog tales (location,indentity) parameters
        self._private_key_password_callback = None

        # keep private key in cache
        self._private_key_cache = None

        self.cabundle = SSLCABundle()
        self.check_certificates_validity = False

        self.waptserver = None
        self.config_filedate = None

        self.packages_whitelist = None
        self.packages_blacklist = None
        self._host_profiles = None

        self.load_config(config_filename = self.config_filename)

        self.options = OptionParser()
        self.options.force = False

        # list of process pids launched by run command
        self.pidlist = []

        # events handler
        self.events = None

        self.progress_hook = None

        if sys.platform=='win32':
            pythoncom.CoInitialize()


    @property
    def private_key_password_callback(self):
        return self._private_key_password_callback

    @private_key_password_callback.setter
    def private_key_password_callback(self,value):
        self._private_key_password_callback = value
        if self.waptserver:
            self.waptserver.private_key_password_callback = value
        for repo in self.repositories:
            repo.private_key_password_callback = value

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        pass

    def as_dict(self):
        result = {}
        for att in self.global_attributes:
            result[att] = getattr(self,att)
        return result

    @property
    def dbdir(self):
        if self._waptdb:
            if self._dbpath != ':memory:':
                return os.path.dirname(self._dbpath)
            else:
                return None
        else:
            return None

    @property
    def dbpath(self):
        if self._waptdb:
            return self._waptdb.dbpath
        elif self._dbpath:
            return self._dbpath
        else:
            return None

    @dbpath.setter
    def dbpath(self,value):
        # check if not changed
        if self._waptdb and self._waptdb.dbpath == value:
            exit
        # updated : reset db
        self._waptdb = None
        self._dbpath = value


    @property
    def host_profiles(self):
        result = []
        if self._host_profiles is not None:
            result.extend(self._host_profiles)

        if self.use_ad_groups:
            host_ad_groups_ttl = self.read_param('host_ad_groups_ttl',0.0,'float')
            host_ad_groups     = self.read_param('host_ad_groups',None)

            if host_ad_groups_ttl<=0 or time.time() > host_ad_groups_ttl:
                with self.waptdb:
                    try:
                        ad_groups = setuphelpers.get_computer_groups()
                        self.write_param('host_ad_groups',ad_groups)
                        self.write_param('host_ad_groups_ttl',time.time() + (110.0 + 20.0 * random.random()) * 60.0) # random ttl
                    except:
                        ad_groups = host_ad_groups
            else:
                ad_groups = host_ad_groups
            result.extend(ad_groups)
        return result

    def set_client_cert_auth(self,connection):
        """Set client side ssl authentication for a waptserver or a waptrepo using
        host_certificate if client_certificate is not yet set in config and host certificate is able to do client_auth

        Args:
            connection: object with client_certificate, client_private_key and client_auth

        """
        try:
            # use implicit host client certificate if not already set by config
            if connection.client_certificate is None:
                if os.path.isfile(self.get_host_certificate_filename()) and os.path.isfile(self.get_host_key_filename()):
                    crt = self.get_host_certificate()
                    if crt.is_client_auth:
                        logger.debug('Using host certificate %s for repo %s auth' % (self.get_host_key_filename(),connection.name))
                        connection.client_certificate = self.get_host_certificate_filename()
                        connection.client_private_key = self.get_host_key_filename()
                else:
                    logger.debug('Warning : Host certificate %s not found, not using it for auth on repo %s' % (self.get_host_key_filename(),connection.name))
            connection.private_key_password_callback = self.private_key_password_callback
        except Exception as e:
            logger.debug(u'Unable to use client certificate auth: %s' % ensure_unicode(e))

    def save_external_ip(self,ip):
        self.waptdb.set_param('last_external_ip',ip)

    def load_config(self,config_filename=None):
        """Load configuration parameters from supplied inifilename
        """
        # default config file
        defaults = {
            'loglevel':'warning',
            'log_to_windows_events':'0',
            'use_http_proxy_for_repo':'0',
            'use_http_proxy_for_server':'0',
            'tray_check_interval':2,
            'service_interval':2,
            'use_hostpackages':'0',
            'use_ad_groups':'0',
            'timeout':10.0,
            'wapt_server_timeout':30.0,
            'maturities':'PROD',
            'default_maturity':'',
            'http_proxy':'',
            'public_certs_dir':os.path.join(self.wapt_base_dir,'ssl'),
            'private_dir': os.path.join(self.wapt_base_dir,'private'),
            'persistent_root_dir':os.path.join(self.wapt_base_dir,'private','persistent'),
            'token_lifetime': 24*60*60,  # 24 hours

            # optional...
            'default_sources_root': 'c:\\waptdev' if (os.name == 'nt') else os.path.join(os.path.expanduser('~'),'waptdev'),
            'default_package_prefix':'tis',
            'default_sources_suffix':'wapt',
            'default_sources_url':'',
            'upload_cmd':'',
            'upload_cmd_host':'',
            'after_upload':'',
            'personal_certificate_path':'',
            'check_certificates_validity':'1',
            'sign_digests':'sha256',

            'uuid':'',
            'use_fqdn_as_uuid':'0',
            }

        if not self.config:
            self.config = RawConfigParser(defaults = defaults)

        if config_filename:
            self.config_filename = config_filename

        self.config.read(self.config_filename)

        # lazzy loading
        self._repositories = None

        # keep the timestamp of last read config file to reload it if it is changed
        if os.path.isfile(self.config_filename):
            self.config_filedate = os.stat(self.config_filename).st_mtime
        else:
            self.config_filedate = None

        if self.config.has_option('global','dbpath'):
            self.dbpath =  self.config.get('global','dbpath').decode('utf8')
        else:
            self.dbpath = os.path.join(self.wapt_base_dir,'db','waptdb.sqlite')

        if self.config.has_option('global','private_dir'):
            self.private_dir = self.config.get('global','private_dir').decode('utf8')

        if self.config.has_option('global','persistent_root_dir'):
            self.persistent_root_dir = self.config.get('global','persistent_root_dir').decode('utf8')

        if self.config.has_option('global','uuid'):
            self.forced_uuid = self.config.get('global','uuid')
        else:
            # force reset to None if config file is changed at runtime
            self.forced_uuid = None

        if self.config.has_option('global','use_fqdn_as_uuid'):
            self.use_fqdn_as_uuid = self.config.getboolean('global','use_fqdn_as_uuid')

        # must have a matching key either in same file or in same directory
        # see self.private_key()
        if self.config.has_option('global','personal_certificate_path'):
            self.personal_certificate_path = self.config.get('global','personal_certificate_path').decode('utf8')

        # be smart with old config
        if not self.personal_certificate_path and self.config.has_option('global','private_key'):
            pk = self.config.get('global','private_key').decode('utf8')
            if pk and os.path.isfile(pk):
                (root,ext) = os.path.splitext(pk)
                if os.path.isfile(root+'.crt'):
                    self.personal_certificate_path = root+'.crt'

        if self.config.has_option('global','public_certs_dir'):
            self.public_certs_dir = self.config.get('global','public_certs_dir').decode('utf8')
        else:
            self.public_certs_dir = os.path.join(self.wapt_base_dir,'ssl')

        self.cabundle.clear()
        self.cabundle.add_pems(self.public_certs_dir)

        if self.config.has_option('global','check_certificates_validity'):
            self.check_certificates_validity = self.config.getboolean('global','check_certificates_validity')

        if self.config.has_option('global','upload_cmd'):
            self.upload_cmd = self.config.get('global','upload_cmd')

        if self.config.has_option('global','upload_cmd_host'):
            self.upload_cmd_host = self.config.get('global','upload_cmd_host')

        if self.config.has_option('global','after_upload'):
            self.after_upload = self.config.get('global','after_upload')

        self.use_http_proxy_for_repo = self.config.getboolean('global','use_http_proxy_for_repo')
        self.use_http_proxy_for_server = self.config.getboolean('global','use_http_proxy_for_server')

        if self.config.has_option('global','http_proxy'):
            self.proxies = {'http':self.config.get('global','http_proxy'),'https':self.config.get('global','http_proxy')}
        else:
            self.proxies = None

        if self.config.has_option('global','wapt_server'):
            self.waptserver = WaptServer().load_config(self.config)
            self.waptserver.capture_external_ip_callback=self.save_external_ip
            self.set_client_cert_auth(self.waptserver)
        else:
            # force reset to None if config file is changed at runtime
            self.waptserver = None

        if self.config.has_option('global','language'):
            self.language = self.config.get('global','language')

        if self.config.has_option('global','sign_digests'):
            self.sign_digests = ensure_list(self.config.get('global','sign_digests'))

        # for testing
        if self.config.has_option('global','fake_hostname'):
            self._set_fake_hostname(self.config.get('global','fake_hostname'))

        # allow to fake a host Oragnaizational Unit when the computer is not part of an AD, but we want to put host in a OU.
        if self.config.has_option('global','host_organizational_unit_dn'):
            forced_host_organizational_unit_dn = self.config.get('global','host_organizational_unit_dn')
            if forced_host_organizational_unit_dn != self.host_organizational_unit_dn:
                logger.info('Forced forced_host_organizational_unit_dn DB %s' % forced_host_organizational_unit_dn)
                self.host_organizational_unit_dn = forced_host_organizational_unit_dn
        else:
            # force reset to None if config file is changed at runtime
            try:
                del(self.host_organizational_unit_dn)
            except:
                # error writing to db because of write access ?
                logger.warning('forced OU DN in local wapt db is not matching wapt-get.ini value')

        if self.config.has_option('global','packages_whitelist'):
            self.packages_whitelist = ensure_list(self.config.get('global','packages_whitelist'),allow_none=True)

        if self.config.has_option('global','packages_blacklist'):
            self.packages_blacklist = ensure_list(self.config.get('global','packages_blacklist'),allow_none=True)

        if self.config.has_option('global','host_profiles'):
            self._host_profiles = ensure_list(self.config.get('global','host_profiles'),allow_none=True)

        if self.config.has_option('global','locales'):
            self.locales = ensure_list(self.config.get('global','locales'),allow_none=True)

        if self.config.has_option('global','maturities'):
            self.maturities = ensure_list(self.config.get('global','maturities'),allow_none=True)
            if not self.maturities:
                self.maturities=['PROD']

        if self.config.has_option('global','default_maturity'):
            self.default_maturity = self.config.get('global','default_maturity')

        if self.config.has_option('global','token_lifetime'):
            self.token_lifetime = self.config.getint('global','token_lifetime')

        if self.config.has_option('global','use_hostpackages'):
            self.use_hostpackages = self.config.getboolean('global','use_hostpackages')

        if self.config.has_option('global','use_ad_groups'):
            self.use_ad_groups = self.config.getboolean('global','use_ad_groups')

        self.waptwua_enabled = None
        if self.config.has_section('waptwua'):
            if self.config.has_option('waptwua','enabled'):
                self.waptwua_enabled = self.config.getboolean('waptwua','enabled')

        # clear host key cache
        self._host_key = None

        # clear host filter for packages
        self._packages_filter_for_host = None


        return self

    @property
    def repositories(self):
        if self._repositories is None:
            # Get the configuration of all repositories (url, ...)
            # TODO : make this lazzy...
            self._repositories = []
            # secondary
            if self.config.has_option('global','repositories'):
                repository_names = ensure_list(self.config.get('global','repositories'))
                logger.info(u'Other repositories : %s' % (repository_names,))
                for name in repository_names:
                    if name:
                        w = WaptRepo(name=name,WAPT=self,config=self.config,section=name)
                        if w.cabundle is None:
                            w.cabundle = self.cabundle
                        self.set_client_cert_auth(w)

                        self._repositories.append(w)
                        logger.debug(u'    %s:%s' % (w.name,w._repo_url))
            else:
                repository_names = []

            # last is main repository so it overrides the secondary repositories
            if self.config.has_option('global','repo_url') and not 'wapt' in repository_names:
                w = WaptRepo(name='wapt',WAPT=self,config=self.config)
                self._repositories.append(w)
                if w.cabundle is None:
                    w.cabundle = self.cabundle
                self.set_client_cert_auth(w)

            if self.use_hostpackages:
                self.add_hosts_repo()

        return self._repositories

    def write_config(self,config_filename=None):
        """Update configuration parameters to supplied inifilename
        """
        def _encode_ini_value(value,key=None):
            if isinstance(value,list):
                return ','.join(value)
            elif value is None:
                return ''
            else:
                return value

        for key in self.config.defaults():
            if hasattr(self,key) and getattr(self,key) != self.config.defaults()[key]:
                logger.debug('update config global.%s : %s' % (key,getattr(self,key)))
                self.config.set('global',key,_encode_ini_value(getattr(self,key),key))
        repositories_names = ','.join([ r.name for r in self.repositories if r.name not in ('global','wapt-host')])
        if self.config.has_option('global','repositories') and repositories_names != '':
            self.config.set('global','repositories',_encode_ini_value(repositories_names))

        if config_filename is None:
            config_filename = self.config_filename

        if config_filename is not None:
            self.config.write(open(config_filename,'wb'))
            self.config_filedate = os.stat(config_filename).st_mtime

    def _set_fake_hostname(self,fqdn):
        setuphelpers._fake_hostname = fqdn
        logger.warning('Using test fake hostname and uuid: %s'%fqdn)
        self.use_fqdn_as_uuid = fqdn
        logger.debug('Host uuid is now: %s'%self.host_uuid)
        logger.debug('Host computer_name is now: %s'%setuphelpers.get_computername())

    def get_token_secret_key(self):
        kfn = os.path.join(self.private_dir,'secret_key')
        if not os.path.isfile(kfn):
            if not os.path.isdir(self.private_dir):
                os.makedirs(self.private_dir)
            result = ''.join(random.SystemRandom().choice(string.letters + string.digits) for _ in range(64))
            open(kfn,'w').write(result)
            return result
        else:
            return open(kfn,'r').read()


    def add_hosts_repo(self):
        """Add an automatic host repository, remove existing WaptHostRepo last one before"""
        while self.repositories and isinstance(self.repositories[-1],WaptHostRepo):
            del self.repositories[-1]

        if self.config.has_section('wapt-host'):
            section = 'wapt-host'
        else:
            section = 'global'

        if self.waptserver or section:
            try:
                # don't create key if not exist at this step
                host_key = self.get_host_key(False)
            except Exception as e:
                # unable to access or create host key
                host_key = None

            host_repo = WaptHostRepo(name='wapt-host',config=self.config,host_id=self.host_packagename(),host_key=host_key,WAPT=self)
            self.repositories.append(host_repo)
            if host_repo.cabundle is None:
                host_repo.cabundle = self.cabundle

            # in case host repo is calculated from server url (no specific section) and main repor_url is set
            if section is None and self.waptserver:
                # host_repo.repo_url=self.waptserver.server_url+'/wapt-host'
                host_repo._section = 'global'
            else:
                host_repo._section = section

            self.set_client_cert_auth(host_repo)

        else:
            host_repo = None

        return host_repo

    def reload_config_if_updated(self):
        """Check if config file has been updated,
        Return None if config has not changed or date of new config file if reloaded

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> wapt.reload_config_if_updated()

        """
        if os.path.exists(self.config_filename):
            new_config_filedate = os.stat(self.config_filename).st_mtime
            if new_config_filedate!=self.config_filedate:
                self.load_config()
                return new_config_filedate
            else:
                return None
        else:
            return None

    @property
    def waptdb(self):
        """Wapt database"""
        if not self._waptdb:
            self._waptdb = WaptDB(dbpath=self.dbpath)
            if self._waptdb.db_version < self._waptdb.curr_db_version:
                logger.info(u'Upgrading db structure from %s to %s' % (self._waptdb.db_version,self._waptdb.curr_db_version))
                self._waptdb.upgradedb()
        return self._waptdb

    @property
    def waptsessiondb(self):
        """Wapt user session database"""
        if not self._waptsessiondb:
            self._waptsessiondb = WaptSessionDB(username=setuphelpers.get_current_user())
            if self._waptsessiondb.db_version < self._waptsessiondb.curr_db_version:
                logger.info(u'Upgrading db structure from %s to %s' % (self._waptsessiondb.db_version,self._waptsessiondb.curr_db_version))
                self._waptsessiondb.upgradedb()
        return self._waptsessiondb

    @property
    def runstatus(self):
        """returns the current run status for tray display"""
        return self.read_param('runstatus','')

    @runstatus.setter
    def runstatus(self,waptstatus):
        """Stores in local db the current run status for tray display"""
        #if self._runstatus is None or self._runstatus != waptstatus:
        logger.info(u'Status : %s' % ensure_unicode(waptstatus))
        self.write_param('runstatus',waptstatus)
        #self._runstatus = waptstatus
        #if not self.disable_update_server_status and self.waptserver_available():
        #    try:
        #        self.update_server_status()
        #    except Exception as e:
        #        logger.warning(u'Unable to contact server to register current status')
        #        logger.debug(u'Unable to update server with current status : %s' % ensure_unicode(e))

    @property
    def host_uuid(self):
        previous_uuid = self.read_param('uuid') or None
        new_uuid = None

        registered_hostname = self.read_param('hostname')
        current_hostname = setuphelpers.get_hostname()

        if self.forced_uuid:
            new_uuid = self.forced_uuid
        elif self.use_fqdn_as_uuid:
            new_uuid = current_hostname
        else:
            try:
                if os.name=='nt':
                    inv = setuphelpers.wmi_info_basic()
                else:
                    inv = setuphelpers.dmi_info()
                new_uuid = inv['System_Information']['UUID']
            except:
                if previous_uuid is None or registered_hostname != current_hostname:
                    # random uuid if wmi is not working
                    self.forced_uuid = str(uuid.uuid4())
                    new_uuid = self.forced_uuid
                    self.config.set('global','uuid',new_uuid)
                    if self.config_filename is not None:
                        try:
                            self.config.write(open(self.config_filename,'wb'))
                        except:
                            pass
                else:
                    new_uuid = previous_uuid

        if previous_uuid is None or previous_uuid != new_uuid or registered_hostname != current_hostname:
            try:
                self.write_param('uuid',new_uuid)
                self.write_param('hostname',current_hostname)
            except:
                # no write access
                pass
        return new_uuid


    @host_uuid.setter
    def host_uuid(self,value):
        self.forced_uuid = value

    @host_uuid.deleter
    def host_uuid(self):
        self.forced_uuid = None
        self.delete_param('uuid')

    def generate_host_uuid(self,forced_uuid=None):
        """Regenerate a random UUID for this host or force with supplied one.

        Normally, the UUID is taken from BIOS through wmi.

        In case bios returns some duplicates or garbage, it can be useful to
        force a random uuid. This is stored as uuid key in wapt-get.ini.

        In case we want to link th host with a an existing record on server, we
        can force a old UUID.

        Args;
            forced_uuid (str): uuid to force for this host. If None, generate a random one

        """
        auuid = forced_uuid or 'rnd-%s' % str(uuid.uuid4())
        self.host_uuid = auuid
        ini = RawConfigParser()
        ini.read(self.config_filename)
        ini.set('global','uuid',auuid)
        ini.write(open(self.config_filename,'w'))
        return auuid

    def reset_host_uuid(self):
        """Reset host uuid to bios provided UUID.
        If it was forced in ini file, remove setting from ini file.
        """
        del(self.host_uuid)
        ini = RawConfigParser()
        ini.read(self.config_filename)
        if ini.has_option('global','uuid'):
            ini.remove_option('global','uuid')
            ini.write(open(self.config_filename,'w'))
        return self.host_uuid

    @property
    def host_organizational_unit_dn(self):
        """Get host org unit DN from wapt-get.ini [global] host_organizational_unit_dn if defined
        or from registry as supplied by AD / GPO process
        """
        if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
            return None

        host_organizational_unit_dn = self.read_param('host_organizational_unit_dn',None)
        if host_organizational_unit_dn:
            return host_organizational_unit_dn

        gpo_host_dn = setuphelpers.registry_readstring(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine','Distinguished-Name')
        if gpo_host_dn:
            try:
                default_organizational_unit_dn = ','.join(gpo_host_dn.split(',')[1:])
            except:
                default_organizational_unit_dn = None
        else:
            default_organizational_unit_dn = None

        return default_organizational_unit_dn

    @host_organizational_unit_dn.setter
    def host_organizational_unit_dn(self,value):
        self.write_param('host_organizational_unit_dn',value)

    @host_organizational_unit_dn.deleter
    def host_organizational_unit_dn(self):
        self.delete_param('host_organizational_unit_dn')

    def reset_host_organizational_unit_dn(self):
        """Reset forced host_organizational_unit_dn to AD / GPO registry defaults.
        If it was forced in ini file, remove setting from ini file.
        """
        del(self.host_organizational_unit_dn)
        ini = RawConfigParser()
        ini.read(self.config_filename)
        if ini.has_option('global','host_organizational_unit_dn'):
            ini.remove_option('global','host_organizational_unit_dn')
            with open(self.config_filename,'w') as f:
                ini.write(f)
                f.close()

        return self.host_dn

    @property
    def host_dn(self):
        result = u'CN=%s' % setuphelpers.get_computername().upper()
        org_unit = self.host_organizational_unit_dn
        if org_unit:
            result = result + ',' + org_unit
        return result

    def http_upload_package(self,packages,wapt_server_user=None,wapt_server_passwd=None,progress_hook=None):
        r"""Upload a package or host package to the waptserver.

        Args:
            packages (str or list): list of filepaths or PackageEntry to wapt packages to upload
            wapt_server_user (str)   : user for basic auth on waptserver
            wapt_server_passwd (str) : password for basic auth on waptserver

        Returns:


        >>> from common import *
        >>> wapt = Wapt(config_filename = r'C:\tranquilit\wapt\tests\wapt-get.ini')
        >>> r = wapt.update()
        >>> d = wapt.duplicate_package('tis-wapttest','toto')
        >>> print d
        {'target': u'c:\\users\\htouvet\\appdata\\local\\temp\\toto.wapt', 'package': PackageEntry('toto','119')}
        >>> wapt.http_upload_package(d['package'],wapt_server_user='admin',wapt_server_passwd='password')
        """
        if not isinstance(packages,list):
            packages = [packages]

        # force auth before trying to upload to avoid uncessary upload buffering server side before it send a 401.
        auth = None
        if wapt_server_user:
            auth = (wapt_server_user, wapt_server_passwd)
        else:
            auth = self.waptserver.ask_user_password('%s/%s' % (self.waptserver.server_url,'api/v3/upload_xxx'))

        files = {}
        is_hosts = None

        def upload_progress_hook(filename,amount_seen,file_size):
            if progress_hook:
                return progress_hook(True,amount_seen,file_size,u'Uploading package %s' % filename)
            else:
                return False

        if not progress_hook:
            upload_progress_hook = None


        for package in packages:
            if not isinstance(package,PackageEntry):
                pe = PackageEntry(waptfile = package)
                package_filename = package
            else:
                pe = package
                package_filename = pe.localpath

            if is_hosts is None and pe.section == 'host':
                is_hosts = True

            if is_hosts:
                # small files
                with open(package_filename,'rb') as f:
                    files[os.path.basename(package_filename)] = f.read()
            else:
                # stream
                #files[os.path.basename(package_filename)] = open(package_filename,'rb')
                files[os.path.basename(package_filename)] = FileChunks(package_filename,progress_hook=upload_progress_hook)


        if files:
            try:
                if is_hosts:
                    logger.info('Uploading %s host packages' % len(files))
                    # single shot
                    res = self.waptserver.post('api/v3/upload_hosts',files=files,auth=auth,timeout=300)
                    if not res['success']:
                        raise Exception('Error when uploading host packages: %s'% (res['msg']))
                else:
                    ok = []
                    errors = []
                    for (fn,f) in files.iteritems():
                        res_partiel = self.waptserver.post('api/v3/upload_packages',data=f.get(),auth=auth,timeout=300)
                        if not res_partiel['success']:
                            errors.append(res_partiel)
                        else:
                            ok.append(res_partiel)
                    res = {'success':len(errors)==0,'result':{'ok':ok,'errors':errors},'msg':'%s Packages uploaded, %s errors' % (len(ok),len(errors))}
            finally:
                for f in files.values():
                    if isinstance(f,file):
                        f.close()
            return res
        else:
            raise Exception('No package to upload')

    def upload_package(self,filenames,wapt_server_user=None,wapt_server_passwd=None):
        """Method to upload a package using Shell command (like scp) instead of http upload
            You must define first a command in inifile with the form :
                upload_cmd="c:\Program Files"\putty\pscp -v -l waptserver %(waptfile)s srvwapt:/var/www/%(waptdir)s/
            or
                upload_cmd="C:\Program Files\WinSCP\WinSCP.exe" root@wapt.tranquilit.local /upload %(waptfile)s
            You can define a "after_upload" shell command. Typical use is to update the Packages index
                after_upload="c:\Program Files"\putty\plink -v -l waptserver srvwapt.tranquilit.local "python /opt/wapt/wapt-scanpackages.py /var/www/%(waptdir)s/"
        """
        if self.upload_cmd:
            args = dict(filenames = " ".join('"%s"' % fn for fn in filenames),)
            return dict(status='OK',message=ensure_unicode(self.run(self.upload_cmd % args )))
        else:
            return self.http_upload_package(filenames,wapt_server_user=wapt_server_user,wapt_server_passwd=wapt_server_passwd)

    def check_install_running(self,max_ttl=60):
        """ Check if an install is in progress, return list of pids of install in progress
            Kill old stucked wapt-get processes/children and update db status
            max_ttl is maximum age of wapt-get in minutes
        """

        logger.debug(u'Checking if old install in progress')
        # kill old wapt-get
        mindate = time.time() - max_ttl*60

        killed=[]
        for p in psutil.process_iter():
            try:
                if p.pid != os.getpid() and (p.create_time() < mindate) and p.name() in ('wapt-get','wapt-get.exe'):
                    logger.debug(u'Killing process tree of pid %i' % p.pid)
                    setuphelpers.killtree(p.pid)
                    logger.debug(u'Killing pid %i' % p.pid)
                    killed.append(p.pid)
            except (psutil.NoSuchProcess,psutil.AccessDenied):
                pass

        # reset install_status
        logger.debug(u'reset stalled install_status in database')
        init_run_pids = self.waptdb.query("""\
           select process_id from wapt_localstatus
              where install_status in ('INIT','RUNNING')
           """ )

        all_pids = psutil.pids()
        reset_error = []
        result = []
        for rec in init_run_pids:
            # check if process is no more running
            if not rec['process_id'] in all_pids or rec['process_id'] in killed:
                reset_error.append(rec['process_id'])
            else:
                # install in progress
                result.append(rec['process_id'])

        if reset_error:
            with self.waptdb:
                cur = self.waptdb.db.execute("""\
                      update wapt_localstatus
                        set install_status=coalesce('ERROR',install_status) where process_id in (?)
                    """,( ','.join([str(p) for p in reset_error]),))

            self.runstatus = ''

        # return pids of install in progress
        return result

    @property
    def pre_shutdown_timeout(self):
        """get / set the pre shutdown timeout shutdown tasks.
        """
        if setuphelpers.reg_key_exists(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\services\gpsvc'):
            with setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\services\gpsvc') as key:
                ms = setuphelpers.reg_getvalue(key,'PreshutdownTimeout',None)
                if ms:
                    return ms / (60*1000)
                else:
                    return None
        else:
            return None

    @pre_shutdown_timeout.setter
    def pre_shutdown_timeout(self,minutes):
        """Set PreshutdownTimeout"""
        if setuphelpers.reg_key_exists(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\services\gpsvc'):
            key = setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\services\gpsvc',sam=setuphelpers.KEY_WRITE)
            if not key:
                raise Exception('The PreshutdownTimeout can only be changed with System Account rights')
            setuphelpers.reg_setvalue(key,'PreshutdownTimeout',minutes*60*1000,setuphelpers.REG_DWORD)

    @property
    def max_gpo_script_wait(self):
        """get / set the MaxGPOScriptWait.
        """
        with setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') as key:
            ms = setuphelpers.reg_getvalue(key,'MaxGPOScriptWait',None)
            if ms:
                return ms / (60*1000)
            else:
                return None

    @max_gpo_script_wait.setter
    def max_gpo_script_wait(self,minutes):
        """Set MaxGPOScriptWait"""
        key = setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',sam=setuphelpers.KEY_WRITE)
        if not key:
            raise Exception('The MaxGPOScriptWait can only be changed with System Account rights')
        setuphelpers.reg_setvalue(key,'MaxGPOScriptWait',minutes*60*1000,setuphelpers.REG_DWORD)


    @property
    def hiberboot_enabled(self):
        """get HiberbootEnabled.
        """
        key = setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Session Manager\Power')
        return key and setuphelpers.reg_getvalue(key,'HiberbootEnabled',None)

    @hiberboot_enabled.setter
    def hiberboot_enabled(self,enabled):
        """Set HiberbootEnabled (0/1)"""
        key = setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\Session Manager\Power',sam=setuphelpers.KEY_WRITE)
        if key:
            setuphelpers.reg_setvalue(key,'HiberbootEnabled',enabled,setuphelpers.REG_DWORD)


    def registry_uninstall_snapshot(self):
        """Return list of uninstall ID from registry
             launched before and after an installation to capture uninstallkey
        """
        result = []
        with setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall") as key:
            try:
                i = 0
                while True:
                    subkey = EnumKey(key, i)
                    result.append(subkey)
                    i += 1
            except WindowsError as e:
                # WindowsError: [Errno 259] No more data is available
                if e.winerror == 259:
                    pass
                else:
                    raise

        if platform.machine() == 'AMD64':
            with setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE,"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall") as key:
                try:
                    i = 0
                    while True:
                        subkey = EnumKey(key, i)
                        result.append(subkey)
                        i += 1
                except WindowsError as e:
                    # WindowsError: [Errno 259] No more data is available
                    if e.winerror == 259:
                        pass
                    else:
                        raise
        return result

    def uninstall_cmd(self,guid):
        """return the (quiet) command stored in registry to uninstall a software given its registry key"""
        return setuphelpers.uninstall_cmd(guid)

    def set_local_password(self,user='admin',pwd='password'):
        """Set admin/password local auth for waptservice in ini file as a sha256 hex hash"""
        conf = RawConfigParser()
        conf.read(self.config_filename)
        conf.set('global','waptservice_user',user)
        conf.set('global','waptservice_password',hashlib.sha256(pwd).hexdigest())
        conf.write(open(self.config_filename,'wb'))

    def reset_local_password(self):
        """Remove the local waptservice auth from ini file"""
        conf = RawConfigParser()
        conf.read(self.config_filename)
        if conf.has_option('global','waptservice_user'):
            conf.remove_option('global','waptservice_user')
        if conf.has_option('global','waptservice_password'):
            conf.remove_option('global','waptservice_password')
        conf.write(open(self.config_filename,'wb'))

    def check_cancelled(self,msg='Task cancelled'):
        if self.task_is_cancelled.is_set():
            raise EWaptCancelled(msg)

    def run(self,*arg,**args):
        return ensure_unicode(setuphelpers.run(*arg,**args))

    def run_notfatal(self,*cmd,**args):
        """Runs the command and wait for it termination
        returns output, don't raise exception if exitcode is not null but return '' """
        try:
            return self.run(*cmd,accept_returncodes=None,**args)
        except Exception as e:
            return ensure_unicode(e)


    def install_wapt(self,fname,params_dict={},explicit_by=None,force=None):
        """Install a single wapt package given its WAPT filename.
        return install status

        Args:
            fname (str): Path to wapt Zip file or unzipped development directory
            params (dict): custom parmaters for the install function
            explicit_by (str): identify who has initiated the install

        Returns:
            str:  'OK','ERROR'

        Raises:

            EWaptMissingCertificate
            EWaptNeedsNewerAgent
            EWaptUnavailablePackage
            EWaptConflictingPackage
            EWaptBadTargetOS
            EWaptException
            various Exception depending on setup script
        """
        install_id = None
        # we  record old sys.path as we will include current setup.py
        oldpath = sys.path

        self.check_cancelled(u'Install of %s cancelled before starting up'%ensure_unicode(fname))
        logger.info(u"Register start of install %s as user %s to local DB with params %s" % (ensure_unicode(fname), setuphelpers.get_current_user(), params_dict))
        logger.info(u"Interactive user:%s, usergroups %s" % (self.user,self.usergroups))

        if sys.platform == 'win32':
            previous_uninstall = self.registry_uninstall_snapshot()

        try:
            if not self.cabundle:
                raise EWaptMissingCertificate(u'install_wapt %s: No public Key provided for package signature checking.'%(fname,))

            entry = PackageEntry(waptfile=fname)
            if not entry.package_uuid:
                entry.make_uuid()
                logger.info('No uuid, generating package uuid on the fly: %s' % entry.package_uuid)
            self.runstatus=u"Installing package %s version %s ..." % (entry.package,entry.version)

            params = self.get_previous_package_params(entry)
            params.update(params_dict)

            install_id = self.waptdb.add_start_install(
                entry ,
                params_dict=params,
                explicit_by=explicit_by,
                )

            # we setup a redirection of stdout to catch print output from install scripts
            with WaptPackageInstallLogger(sys.stderr,wapt_context=self,install_id=install_id,user=self.user,exit_status=None) as dblogger:
                if entry.min_wapt_version and Version(entry.min_wapt_version)>Version(setuphelpers.__version__):
                    raise EWaptNeedsNewerAgent('This package requires a newer Wapt agent. Minimum version: %s' % entry.min_wapt_version)

                depends = ensure_list(entry.depends)
                conflicts = ensure_list(entry.conflicts)

                missing_depends = [ p for p in depends if not self.is_installed(p)]
                installed_conflicts = [ p for p in conflicts if self.is_installed(p)]

                if missing_depends:
                    raise EWaptUnavailablePackage('Missing dependencies: %s' % (','.join(missing_depends,)))

                if installed_conflicts:
                    raise EWaptConflictingPackage('Conflicting packages installed: %s' % (','.join(installed_conflicts,)))

                # check if there is enough space for final install
                # TODO : space for the temporary unzip ?

                #LINUXTODO
                ###################################################################
                if sys.platform == 'win32':
                    free_disk_space = setuphelpers.get_disk_free_space(setuphelpers.programfiles)
                    if entry.installed_size and free_disk_space < entry.installed_size:
                        raise EWaptDiskSpace('This package requires at least %s free space. The "Program File"s drive has only %s free space' %
                            (format_bytes(entry.installed_size),format_bytes(free_disk_space)))

                    if entry.target_os and entry.target_os != 'windows':
                        raise EWaptBadTargetOS('This package is designed for OS %s' % entry.target_os)

                    os_version = setuphelpers.windows_version()
                    if entry.min_os_version and os_version < Version(entry.min_os_version):
                        raise EWaptBadTargetOS('This package requires that OS be at least %s' % entry.min_os_version)
                    if entry.max_os_version and os_version > Version(entry.max_os_version):
                        raise EWaptBadTargetOS('This package requires that OS be at most %s' % entry.min_os_version)
                ###################################################################

                # don't check in developper mode
                if os.path.isfile(fname):
                    cert = entry.check_control_signature(self.cabundle)
                    logger.info(u'Control data for package %s verified by certificate %s' % (setuphelpers.ensure_unicode(fname),cert))
                else:
                    logger.info(u'Developper mode, don''t check control signature for %s' % setuphelpers.ensure_unicode(fname))

                self.check_cancelled()

                logger.info(u"Installing package %s"%(ensure_unicode(fname),))
                # case where fname is a wapt zipped file, else directory (during developement)
                istemporary = False

                if os.path.isfile(fname):
                    # check signature and files when unzipping
                    packagetempdir = entry.unzip_package(cabundle=self.cabundle)
                    istemporary = True
                elif os.path.isdir(fname):
                    packagetempdir = fname
                else:
                    raise EWaptNotAPackage(u'%s is not a file nor a directory, aborting.' % ensure_unicode(fname))

                try:
                    previous_cwd = os.getcwdu()
                    self.check_cancelled()

                    exitstatus = None
                    new_uninstall_key = None
                    uninstallstring = None

                    if entry.package_uuid:
                        persistent_source_dir = os.path.join(packagetempdir,'WAPT','persistent')
                        persistent_dir = os.path.join(self.persistent_root_dir,entry.package_uuid)

                        if os.path.isdir(persistent_dir):
                            logger.debug(u'Removing existing persistent dir %s' % persistent_dir)
                            shutil.rmtree(persistent_dir,ignore_errors=False)

                        # install persistent files
                        if os.path.isdir(persistent_source_dir):
                            logger.info(u'Copy persistent package data to %s' % persistent_dir)
                            shutil.copytree(persistent_source_dir,persistent_dir)
                        else:
                            # create always
                            os.makedirs(persistent_dir)

                    else:
                        persistent_source_dir = None
                        persistent_dir = None

                    setup_filename = os.path.join( packagetempdir,'setup.py')

                    # take in account the case we have no setup.py
                    if os.path.isfile(setup_filename):
                        os.chdir(os.path.dirname(setup_filename))
                        if not os.getcwdu() in sys.path:
                            sys.path.append(os.getcwdu())

                        # import the setup module from package file
                        logger.info(u"  sourcing install file %s " % ensure_unicode(setup_filename) )
                        setup = import_setup(setup_filename)
                        required_params = []

                        # be sure some minimal functions are available in setup module at install step
                        setattr(setup,'basedir',os.path.dirname(setup_filename))
                        # redefine run to add reference to wapt.pidlist
                        setattr(setup,'run',self.run)
                        setattr(setup,'run_notfatal',self.run_notfatal)

                        if not hasattr(setup,'uninstallkey'):
                            setup.uninstallkey = []

                        # to set some contextual default arguments
                        def with_install_context(func,impacted_process=None,uninstallkeylist=None,force=None,pidlist=None):
                            def new_func(*args,**kwargs):
                                if impacted_process and not 'killbefore' in kwargs:
                                    kwargs['killbefore'] = impacted_process
                                if uninstallkeylist is not None and not 'uninstallkeylist' in kwargs:
                                    kwargs['uninstallkeylist'] = uninstallkeylist
                                if force is not None and not 'force' in kwargs:
                                    kwargs['force'] = force
                                if pidlist is not None and not 'pidlist' in kwargs:
                                    kwargs['pidlist'] = pidlist
                                return func(*args,**kwargs)
                            return new_func

                        if sys.platform == 'win32':
                            setattr(setup,'install_msi_if_needed',with_install_context(setuphelpers.install_msi_if_needed,entry.impacted_process,setup.uninstallkey,force,self.pidlist))
                            setattr(setup,'install_exe_if_needed',with_install_context(setuphelpers.install_exe_if_needed,entry.impacted_process,setup.uninstallkey,force,self.pidlist))

                        setattr(setup,'WAPT',self)
                        setattr(setup,'control',entry)
                        setattr(setup,'language',self.language)
                        setattr(setup,'force',force)

                        setattr(setup,'user',self.user)
                        setattr(setup,'usergroups',self.usergroups)

                        setattr(setup,'persistent_source_dir',persistent_source_dir)
                        setattr(setup,'persistent_dir',persistent_dir)

                        # get definitions of required parameters from setup module
                        if hasattr(setup,'required_params'):
                            required_params = setup.required_params

                        # get value of required parameters if not already supplied
                        for p in required_params:
                            if not p in params:
                                if not is_system_user():
                                    params[p] = raw_input(u"%s: " % p)
                                else:
                                    raise EWaptException(u'Required parameters %s is not supplied' % p)
                        logger.info(u'Install parameters : %s' % (params,))

                        # set params dictionary
                        if not hasattr(setup,'params'):
                            # create a params variable for the setup module
                            setattr(setup,'params',params)
                        else:
                            # update the already created params with additional params from command line
                            setup.params.update(params)

                        # store source of install and params in DB for future use (upgrade, session_setup, uninstall)
                        self.waptdb.store_setuppy(install_id, setuppy = codecs.open(setup_filename,'r',encoding='utf-8').read(),install_params=params)

                        if not self.dry_run:
                            with _disable_file_system_redirection():
                                try:
                                    logger.info(u"  executing install script")
                                    exitstatus = setup.install()
                                except Exception as e:
                                    logger.critical(u'Fatal error in install script: %s:\n%s' % (ensure_unicode(e),ensure_unicode(traceback.format_exc())))
                                    raise
                        else:
                            logger.warning(u'Dry run, not actually running setup.install()')
                            exitstatus = None

                        if exitstatus is None or exitstatus == 0:
                            dblogger.exit_status = 'OK'
                        else:
                            dblogger.exit_status = exitstatus


                        if sys.platform == 'win32':
                            # get uninstallkey from setup module (string or array of strings)
                            if hasattr(setup,'uninstallkey'):
                                new_uninstall_key = ensure_list(setup.uninstallkey)[:]
                                # check that uninstallkey(s) are in registry
                                if not self.dry_run:
                                    key_errors = []
                                    for key in new_uninstall_key:
                                        if not setuphelpers.uninstall_key_exists(uninstallkey=key):
                                            key_errors.append(key)
                                    if key_errors:
                                        if len(key_errors)>1:
                                            raise EWaptException(u'The uninstall keys: \n%s\n have not been found in system registry after softwares installation.' % ('\n'.join(key_errors),))
                                        else:
                                            raise EWaptException(u'The uninstall key: %s has not been found in system registry after software installation.' % (' '.join(key_errors),))

                        else:
                            if sys.platform == 'win32':
                                new_uninstall = self.registry_uninstall_snapshot()
                                new_uninstall_key = [ k for k in new_uninstall if not k in previous_uninstall]
                            else:
                                new_uninstall_key = []

                        # get uninstallstring from setup module (string or array of strings)
                        if hasattr(setup,'uninstallstring'):
                            uninstallstring = setup.uninstallstring[:]
                        else:
                            uninstallstring = None

                        logger.info(u'  uninstall keys : %s' % (new_uninstall_key,))
                        logger.info(u'  uninstall strings : %s' % (uninstallstring,))

                        logger.info(u"Install script finished with status %s" % dblogger.exit_status )
                    else:
                        logger.info(u'No setup.py')
                        dblogger.exit_status = 'OK'

                    if entry.package_uuid:
                        for row in self.waptdb.query('select persistent_dir from wapt_localstatus l where l.package=? and l.package_uuid<>?',(entry.package, entry.package_uuid)):
                            if row['persistent_dir'] and os.path.isdir(os.path.abspath(row['persistent_dir'])):
                                logger.info('Cleanup of previous versions of %s  persistent dir: %s' % (entry.package,row['persistent_dir']))
                                shutil.rmtree(os.path.abspath(row['persistent_dir']))

                    self.waptdb.update_install_status(install_id,
                        uninstall_key = jsondump(new_uninstall_key),persistent_dir=persistent_dir)

                finally:
                    if istemporary:
                        os.chdir(previous_cwd)
                        logger.debug(u"Cleaning package tmp dir")
                        # trying 3 times to remove
                        cnt = 3
                        while cnt>0:
                            try:
                                shutil.rmtree(packagetempdir)
                                break
                            except Exception as e:
                                cnt -= 1
                                time.sleep(2)
                                print(e)
                        else:
                            logger.warning(u"Unable to clean tmp dir")

            # end
            return self.waptdb.install_status(install_id)

        except Exception as e:
            if install_id:
                try:
                    self.waptdb.update_install_status(install_id,set_status='ERROR',append_output=ensure_unicode(e))
                except Exception as e2:
                    logger.critical(ensure_unicode(e2))
            else:
                logger.critical(ensure_unicode(e))
            raise e

        finally:
            gc.collect()
            if 'setup' in dir() and setup is not None:
                setup_name = setup.__name__[:]
                logger.debug('Removing module: %s, refcnt: %s'%(setup_name,sys.getrefcount(setup)))
                del setup
                if setup_name in sys.modules:
                    del sys.modules[setup_name]

            sys.path = oldpath
            self.store_upgrade_status()
            self.runstatus=''


    def running_tasks(self):
        """return current install tasks"""
        running = self.waptdb.query_package_entry("""\
           select * from wapt_localstatus
              where install_status in ('INIT','DOWNLOAD','RUNNING')
           """ )
        return running

    def error_packages(self):
        """return install tasks with error status"""
        q = self.waptdb.query_package_entry("""\
           select * from wapt_localstatus
              where install_status in ('ERROR')
           """ )
        return q

    def store_upgrade_status(self,upgrades=None):
        """Stores in DB the current pending upgrades and running installs for
          query by waptservice"""
        try:
            status={
                "running_tasks": [ "%s : %s" % (p.asrequirement(),p.install_status) for p in self.running_tasks()],
                "errors": [ "%s" % p.asrequirement() for p in self.error_packages()],
                "date":datetime2isodate(),
                }
            if upgrades is None:
                upgrades = self.list_upgrade()

            status["upgrades"] = upgrades['upgrade']+upgrades['install']+upgrades['additional']
            status["pending"] = upgrades
            logger.debug(u"store status in DB")
            self.write_param('last_update_status',status)
            return status
        except Exception as e:
            logger.critical(u'Unable to store status of update in DB : %s'% ensure_unicode(e))
            if logger.level == logging.DEBUG:
                raise


    def read_upgrade_status(self):
        """Return last stored pending updates status

        Returns:
            dict: {running_tasks errors pending (dict) upgrades (list)}

        """
        return self.read_param('last_update_status',ptype='json')

    def get_sources(self,package):
        """Download sources of package (if referenced in package as a https svn)
        in the current directory

        Args:
            package (str or PackageRequest): package to get sources for

        Returns:
            str : checkout directory path

        """
        sources_url = None
        entry = None
        entries = self.waptdb.packages_matching(package)
        if entries:
            entry = entries[-1]
            if entry.sources:
                sources_url = entry.sources
        if not sources_url:
            if self.config.has_option('global','default_sources_url'):
                sources_url = self.config.get('global','default_sources_url') % {'packagename':package}

        if not sources_url:
            raise Exception('No sources defined in package control file and no default_sources_url in config file')
        if "PROGRAMW6432" in os.environ:
            svncmd = os.path.join(os.environ['PROGRAMW6432'],'TortoiseSVN','bin','svn.exe')
        else:
            svncmd = os.path.join(os.environ['PROGRAMFILES'],'TortoiseSVN','bin','svn.exe')
        logger.debug(u'svn command : %s'% svncmd)
        if not os.path.isfile(svncmd):
            raise Exception(u'svn.exe command not available, please install TortoiseSVN with commandline tools')

        # checkout directory
        if entry:
            co_dir = self.get_default_development_dir(entry.package, section = entry.section)
        else:
            co_dir = self.get_default_development_dir(package)

        logger.info(u'sources : %s'% sources_url)
        logger.info(u'checkout dir : %s'% co_dir)
        # if already checked out...
        if os.path.isdir(os.path.join(co_dir,'.svn')):
            print(self.run(u'"%s" up "%s"' % (svncmd,co_dir)))
        else:
            print(self.run(u'"%s" co "%s" "%s"' % (svncmd,sources_url,co_dir)))
        return co_dir

    def last_install_log(self,packagename):
        r"""Get the printed output of the last install of package named packagename

        Args:
            packagename (str): name of package to query
        Returns:
            dict: {status,log} of the last install of a package

        >>> w = Wapt()
        >>> w.last_install_log('tis-7zip')
        ???
        {'install_status': u'OK', 'install_output': u'Installing 7-Zip 9.38.0-1\n7-Zip already installed, skipping msi install\n',install_params: ''}

        """
        q = self.waptdb.query("""\
           select   rowid,package,version,architecture,maturity,locale,install_status,
                    install_output,install_params,explicit_by,uninstall_key,install_date,
                    last_audit_status,last_audit_on,last_audit_output,next_audit_on,package_uuid
           from wapt_localstatus
           where package=? order by install_date desc limit 1
           """ , (packagename,) )
        if not q:
            raise Exception("Package %s not found in local DB status" % packagename)
        return q[0]

    def cleanup(self,obsolete_only=False):
        """Remove cached WAPT files from local disk

        Args:
           obsolete_only (boolean):  If True, remove packages which are either no more available,
                                     or installed at a equal or newer version

        Returns:
            list: list of filenames of removed packages

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> l = wapt.download_packages(wapt.check_downloads())
        >>> res = wapt.cleanup(True)
        """
        result = []
        logger.info(u'Cleaning up WAPT cache directory')
        cachepath = self.package_cache_dir

        upgrade_actions = self.list_upgrade()
        futures =   upgrade_actions['install']+\
                    upgrade_actions['upgrade']+\
                    upgrade_actions['additional']
        def in_futures(pe):
            for p in futures:
                if pe.match(p):
                    return True
            return False

        for f in glob.glob(os.path.join(cachepath,u'*.wapt')):
            if os.path.isfile(f):
                can_remove = True
                if obsolete_only:
                    try:
                        # check if cached package could be installed at next ugrade
                        pe = PackageEntry().load_control_from_wapt(f)
                        pe_installed = self.is_installed(pe.package)
                        can_remove = not in_futures(pe) and ((pe_installed and pe <= pe_installed) or not self.is_available(pe.asrequirement()))
                    except:
                        # if error... control file in wapt file is corrupted.
                        continue
                if can_remove:
                    logger.debug(u'Removing %s' % f)
                    try:
                        os.remove(f)
                        result.append(f)
                    except Exception as e:
                        logger.warning(u'Unable to remove %s : %s' % (f,ensure_unicode(e)))
        return result

    def _update_db(self,repo,force=False):
        """Get Packages from http repo and update local package database
        return last-update header

        The local status DB is updated. Date of index is stored in params table
        for further checks.

        Args:
            force (bool): get index from remote repo even if creation date is not newer
                          than the datetime stored in local status database
            waptdb (WaptDB): instance of Wapt status database.

        Returns:
            isodatetime: date of Packages index

        >>> import common
        >>> repo = common.WaptRepo('wapt','http://wapt/wapt')
        >>> localdb = common.WaptDB('c:/wapt/db/waptdb.sqlite')
        >>> last_update = repo.is_available()
        >>> repo.update_db(waptdb=localdb) == last_update
        True
        """

        result = None
        last_modified = self.waptdb.get_param('last-%s'%(repo.repo_url[:59]))
        last_url = self.waptdb.get_param('last-url-%s' % repo.name)

        # Check if updated
        if force or repo.repo_url != last_url or repo.need_update(last_modified):
            #TODOLINUX
            if sys.platform == 'win32':
                os_version = setuphelpers.windows_version()
            old_status = repo.invalidate_packages_cache()
            discarded = []

            self._packages_filter_for_host = None

            if self.filter_on_host_cap:
                host_capabilities = self.host_capabilities()
            else:
                host_capabilities = None

            with self.waptdb:
                try:
                    logger.debug(u'Read remote Packages index file %s' % repo.packages_url())
                    last_modified = repo.packages_date()

                    self.waptdb.purge_repo(repo.name)
                    repo_packages =  repo.packages()
                    discarded.extend(repo.discarded)

                    next_update_on = '9999-12-31'

                    for package in repo_packages:
                        # if there are time related restriction, we should check again at that time in the future.
                        if package.valid_from:
                            next_update_on = min(next_update_on,package.valid_from)
                        if package.valid_until:
                            next_update_on = min(next_update_on,package.valid_until)
                        if package.forced_install_on:
                            next_update_on = min(next_update_on,package.forced_install_on)

                        if self.filter_on_host_cap:
                            if not host_capabilities.is_matching_package(package,datetime2isodate()):
                                discarded.append(package)
                                continue
                        try:
                            self.waptdb.add_package_entry(package,self.language)
                        except Exception as e:
                            logger.critical(u'Error adding entry %s to local DB for repo %s : discarding : %s' % (package.asrequirement(),repo.name,e) )
                            discarded.append(package)

                    logger.debug(u'Storing last-modified header for repo_url %s : %s' % (repo.repo_url,repo.packages_date()))
                    self.waptdb.set_param('last-%s' % repo.repo_url[:59],repo.packages_date())
                    self.waptdb.set_param('last-url-%s' % repo.name, repo.repo_url)
                    self.waptdb.set_param('last-discarded-%s' % repo.name, [p.as_key() for p in discarded])
                    self.waptdb.set_param('next-update-%s' % repo.name,next_update_on)

                    # get rules to put them into DB
                    rules = repo.rules()
                    if rules:
                        self.waptdb.set_param('rules-%s' % repo.name,repo.rules())
                    else:
                        self.waptdb.delete_param('rules-%s' % repo.name)

                    return (last_modified,next_update_on)
                except Exception as e:
                    logger.info(u'Unable to update repository status of %s, error %s'%(repo._repo_url,e))
                    # put back cached status data
                    for (k,v) in old_status.iteritems():
                        setattr(repo,k,v)
                    raise
        else:
            return (self.waptdb.get_param('last-%s' % repo.repo_url[:59]),self.waptdb.get_param('next-update-%s' % repo.name,'9999-12-31'))

    def get_host_architecture(self):
        if setuphelpers.is64():
            return 'x64'
        else:
            return 'x86'

    def get_host_locales(self):
        return ensure_list(self.locales)

    def get_host_site(self):
        if sys.platform == 'win32':
            return setuphelpers.registry_readstring(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine','Site-Name')
        else:
            return 'TODO'

    def get_host_certificate_fingerprint(self):
        result = self.read_param('host_certificate_fingerprint')
        if result is None:
            result = self.get_host_certificate().fingerprint
            self.write_param('host_certificate_fingerprint',result)
        return result

    def get_host_certificate_authority_key_identifier(self):
        result = self.read_param('host_certificate_authority_key_identifier')
        if result is None:
            result = (self.get_host_certificate().authority_key_identifier or '').encode('hex')
            self.write_param('host_certificate_authority_key_identifier',result)
        return result

    def host_capabilities(self):
        """Return the current capabilities of host taken in account to determine packages list and whether update should be forced (when filter criteria are updated)
        This includes host certificate,architecture,locale,authorized certificates

        Returns:
            dict
        """
        waptos = sys.platform

        if waptos == "win32":
            waptos = "windows"

        if waptos.startswith('linux') :
            waptos = "linux"

        if waptos.startswith('darwin') :
            waptos = "mac"

        host_capa = HostCapabilities(
            uuid=self.host_uuid,
            language=self.language,
            os=waptos,
            os_version=setuphelpers.get_os_version(),
            architecture=self.get_host_architecture(),
            dn=self.host_dn,
            fqdn=setuphelpers.get_hostname(),
            site=self.get_host_site(),
            wapt_version=Version(setuphelpers.__version__,3),
            wapt_edition=self.get_wapt_edition(),
            packages_trusted_ca_fingerprints=[c.fingerprint for c in self.authorized_certificates()],
            packages_blacklist=self.packages_blacklist,
            packages_whitelist=self.packages_whitelist,
            packages_locales=self.locales,
            packages_maturities=self.maturities,
            use_host_packages=self.use_hostpackages,
            host_profiles=self.host_profiles,
            host_certificate_fingerprint=self.get_host_certificate_fingerprint(),
            host_certificate_authority_key_identifier = self.get_host_certificate_authority_key_identifier(),
            host_packages_names=self.get_host_packages_names(),
            #authorized_maturities=self.get_host_maturities(),
        )
        return host_capa

    def packages_filter_for_host(self):
        """Returns a PackageRequest object based on host capabilities to filter applicable packages from a repo

        Returns:
            PackageRequest
        """
        if self._packages_filter_for_host is None:
            self._packages_filter_for_host = self.host_capabilities().get_package_request_filter()
        return self._packages_filter_for_host

    def get_wapt_edition(self):
        return 'enterprise' if os.path.isfile(os.path.join(self.wapt_base_dir,'waptenterprise','licencing.py')) else 'community'

    def host_capabilities_fingerprint(self):
        """Return a fingerprint representing the current capabilities of host
        This includes host certificate,architecture,locale,authorized certificates

        Returns:
            str

        """
        return self.host_capabilities().fingerprint()

    def is_locally_allowed_package(self,package):
        """Return True if package is not in blacklist and is in whitelist if whitelist is not None
        packages_whitelist and packages_blacklist are list of package name wildcards (file style wildcards)
        blacklist is taken in account first if defined.
        whitelist is taken in acoount if not None, else all not blacklisted package names are allowed.
        """
        if self.packages_blacklist is not None:
            for bl in self.packages_blacklist:
                if glob.fnmatch.fnmatch(package.package,bl):
                    return False
        if self.packages_whitelist is None:
            return True
        else:
            for wl in self.packages_whitelist:
                if glob.fnmatch.fnmatch(package.package,wl):
                    return True
        return False

    def _update_repos_list(self,force=False):
        """update the packages database with Packages files from the Wapt repos list
        removes obsolete records for repositories which are no more referenced

        Args:
            force : update repository even if date of packages index is same as
                    last retrieved date

        Returns:
            dict:   update_db results for each repository name
                    which has been accessed.

        >>> wapt = Wapt(config_filename = 'c:/tranquilit/wapt/tests/wapt-get.ini' )
        >>> res = wapt._update_repos_list()
        {'wapt': '2018-02-13T11:22:00', 'wapt-host': u'2018-02-09T10:55:04'}
        """
        if self.filter_on_host_cap:
            # force update if host capabilities have changed and requires a new filering of packages
            new_capa = self.host_capabilities_fingerprint()
            old_capa = self.read_param('host_capabilities_fingerprint')
            if not force and old_capa != new_capa:
                logger.info('Host capabilities have changed since last update, forcing update')
                force = True

        with self.waptdb:
            result = {}
            logger.debug(u'Remove unknown repositories from packages table and params (%s)' %(','.join('"%s"'% r.name for r in self.repositories),)  )
            self.waptdb.db.execute('delete from wapt_package where repo not in (%s)' % (','.join('"%s"'% r.name for r in self.repositories)))
            self.waptdb.db.execute('delete from wapt_params where name like "last-http%%" and name not in (%s)' % (','.join('"last-%s"'% r.repo_url for r in self.repositories)))
            self.waptdb.db.execute('delete from wapt_params where name like "last-url-%%" and name not in (%s)' % (','.join('"last-url-%s"'% r.name for r in self.repositories)))
            self.waptdb.db.execute('delete from wapt_params where name like "last-discarded-%%-" and name not in (%s)' % (','.join('"last-discarded-%s"'% r.name for r in self.repositories)))

            # to check the next time we should update the local repositories
            next_update_on='9999-12-31'

            for repo in self.repositories:
                # if auto discover, repo_url can be None if no network.
                if repo.repo_url:
                    try:
                        (result[repo.name],repo_next_update_on) = self._update_db(repo,force=force)
                        next_update_on = min(next_update_on,repo_next_update_on)
                    except Exception as e:
                        logger.critical(u'Error merging Packages from %s into db: %s' % (repo.repo_url,ensure_unicode(e)))
                else:
                    logger.info('No location found for repository %s, skipping' % (repo.name))
            if self.filter_on_host_cap:
                self.write_param('host_capabilities_fingerprint',new_capa)
            self.write_param('next_update_on',next_update_on)
        return result


    def update(self,force=False,register=True):
        """Update local database with packages definition from repositories

        Args:
            force (boolean):    update even if Packages index on repository has not been
                                updated since last update (based on http headers)
            register (boolean): Send informations about status of local packages to waptserver
        .. versionadded 1.3.10::
            filter_on_host_cap (boolean) : restrict list of retrieved packages to those matching current os / architecture

        Returns;
            list of (host package entry,entry date on server)

        Returns:
            dict: {"added","removed","count","repos","upgrades","date"}

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> updates = wapt.update()
        >>> 'count' in updates and 'added' in updates and 'upgrades' in updates and 'date' in updates and 'removed' in updates
        True

        """
        # be sure to get up to date host groups if possible
        self.write_param('host_ad_groups_ttl',0.0)
        previous = self.waptdb.known_packages()
        # (main repo is at the end so that it will used in priority)
        next_update_on = self._update_repos_list(force=force)

        current = self.waptdb.known_packages()
        result = {
            "added":   [ current[package_uuid] for package_uuid in current if not package_uuid in previous],
            "removed": [ previous[package_uuid] for package_uuid in previous if not package_uuid in current],
            "discarded_count": len(self.read_param('last-discarded-wapt',[],'json')),
            "count" : len(current),
            "repos" : [r.repo_url for r in self.repositories],
            "upgrades": self.list_upgrade(),
            "date":datetime2isodate(),
            "next_update_on": next_update_on,
            }

        self.store_upgrade_status(result['upgrades'])

        if self.waptserver and not self.disable_update_server_status and register:
            try:
                self.update_server_status()
            except Exception as e:
                logger.info(u'Unable to contact server to register current packages status')
                logger.debug(u'Unable to update server with current status : %s' % ensure_unicode(e))
                if logger.level == logging.DEBUG:
                    raise
        return result

    def update_crls(self,force=False):
        # retrieve CRL
        # TODO : to be moved to an abstracted wapt https client
        crl_dir = setuphelpers.makepath(self.wapt_base_dir,'ssl','crl')
        result = []
        for cert in self.cabundle.certificates():
            crl_urls = cert.crl_urls()
            for url in crl_urls:
                crl_filename = setuphelpers.makepath(crl_dir,sha256_for_data(str(url))+'.crl')
                if os.path.isfile(crl_filename):
                    ssl_crl = SSLCRL(crl_filename)
                else:
                    ssl_crl = None

                if force or not ssl_crl or ssl_crl.next_update > datetime.datetime.utcnow():
                    try:
                        # need update
                        if not os.path.isdir(crl_dir):
                            os.makedirs(crl_dir)
                        logger.debug('Download CRL %s' % (url,))
                        wget(url,target=crl_filename)
                        ssl_crl = SSLCRL(crl_filename)
                        result.append(ssl_crl)
                    except Exception as e:
                        logger.warning('Unable to download CRL from %s: %s' % (url,repr(e)))
                        if ssl_crl:
                            result.append(ssl_crl)
                        pass
                elif ssl_crl:
                    # not changed
                    result.append(ssl_crl)
        return result

    def check_all_depends_conflicts(self):
        """Check the whole dependencies/conflicts tree for installed packages


        """
        installed_packages = self.installed(True)

        all_depends = defaultdict(list)
        all_conflicts = defaultdict(list)
        all_missing = defaultdict(list)

        conflictings = []
        orphans = []

        # host_depends = host_packages ^
        # host_conflicts = blacklist

        if self.use_hostpackages:
            for p in self.get_host_packages():
                all_depends[p.asrequirement()].append(None)
                (depends,conflicts,missing) = self.waptdb.build_depends(p.asrequirement())
                for d in depends:
                    if not p in all_depends[d]:
                        all_depends[d].append(p.asrequirement())
                for c in conflicts:
                    if not p in all_conflicts[c]:
                        all_conflicts[c].append(p.asrequirement())
                for m in missing:
                    if not m in all_missing:
                        all_missing[m].append(p.asrequirement())


        for p in installed_packages:
            if self.is_locally_allowed_package(p):
                if not p.asrequirement() in all_depends:
                    all_depends[p.asrequirement()] = []
            else:
                if not p.asrequirement() in all_conflicts:
                    all_conflicts[p.asrequirement()] = []

            (depends,conflicts,missing) = self.waptdb.build_depends(p.asrequirement())
            for d in depends:
                if not p in all_depends[d]:
                    all_depends[d].append(p.asrequirement())
            for c in conflicts:
                if not p in all_conflicts[c]:
                    all_conflicts[c].append(p.asrequirement())
            for m in missing:
                if not m in all_missing:
                    all_missing[m].append(p.asrequirement())

        return (all_depends,all_conflicts,all_missing)


    def check_depends(self,apackages,forceupgrade=False,force=False,assume_removed=[],package_request_filter=None):
        """Given a list of packagename or requirement "name (=version)",
        return a dictionnary of {'additional' 'upgrade' 'install' 'skipped' 'unavailable','remove'} of
        [packagerequest,matching PackageEntry]

        Args:
            apackages (str or list): list of packages for which to check missing dependencies.
            forceupgrade (boolean): if True, check if the current installed packages is the latest available
            force (boolean): if True, install the latest version even if the package is already there and match the requirement
            assume_removed (list): list of packagename which are assumed to be absent even if they are actually installed to check the
                                    consequences of removal of packages, implies force=True
            package_request_filter (PackageRequest): additional filter to apply to packages to sort by locales/arch/mat preferences
                                                       if None, get active host filter
        Returns:
            dict : {'additional' 'upgrade' 'install' 'skipped' 'unavailable', 'remove'} with list of [packagerequest,matching PackageEntry]

        """
        if apackages is None:
            apackages = []

        if package_request_filter is None:
            package_request_filter = self.packages_filter_for_host()

        package_requests = self._ensure_package_requests_list(apackages,package_request_filter=package_request_filter)

        if not isinstance(assume_removed,list):
            assume_removed = [assume_removed]
        if assume_removed:
            force=True
        # packages to install after skipping already installed ones
        skipped = []
        unavailable = []
        additional_install = []
        to_upgrade = []
        to_remove = []
        packages = []

        # search for most recent matching package to install
        for package_request in package_requests:
            # get the current installed package matching the request
            old_matches = self.waptdb.installed_matching(package_request)

            # removes "assumed removed" packages
            if old_matches:
                for packagename in assume_removed:
                    if old_matches.match(packagename):
                        old_matches = None
                        break

            # current installed matches
            if not force and old_matches and not forceupgrade:
                skipped.append((package_request,old_matches))
            else:
                new_availables = self.waptdb.packages_matching(package_request)
                if new_availables:
                    if force or not old_matches or (forceupgrade and old_matches < new_availables[-1]):
                        if not (package_request,new_availables[-1]) in packages:
                            packages.append((package_request,new_availables[-1]))
                    else:
                        skipped.append((package_request,old_matches))
                else:
                    if (package_request,None) not in unavailable:
                        unavailable.append((package_request,None))

        # get dependencies of not installed top packages
        if forceupgrade:
            (depends,conflicts,missing) = self.waptdb.build_depends(package_requests)
        else:
            (depends,conflicts,missing) = self.waptdb.build_depends([p[0] for p in packages])

        for p in missing:
            if (p,None) not in unavailable:
                unavailable.append((p,None))

        # search for most recent matching package to install
        for request in depends:
            package_request= PackageRequest(request=request,copy_from=package_request_filter)
            # get the current installed package matching the request
            old_matches = self.waptdb.installed_matching(package_request)

            # removes "assumed removed" packages
            if old_matches:
                for packagename in assume_removed:
                    if old_matches.match(packagename):
                        old_matches = None
                        break

            # current installed matches
            if not force and old_matches:
                skipped.append((package_request,old_matches))
            else:
                # check if installable or upgradable ?
                new_availables = self.waptdb.packages_matching(package_request)
                if new_availables:
                    if not old_matches or (forceupgrade and old_matches < new_availables[-1]):
                        additional_install.append((package_request,new_availables[-1]))
                    else:
                        skipped.append((package_request,old_matches))
                else:
                    unavailable.append((package_request,None))

        # check new conflicts which should force removal
        all_new = additional_install+to_upgrade+packages

        def remove_matching(package,req_pe_list):
            todel = []
            for req,pe in req_pe_list:
                if pe.match(package):
                    todel.append((req,pe))
            for e in todel:
                req_pe_list.remove(e)

        for (request,pe) in all_new:
            conflicts = ensure_list(pe.conflicts)
            for conflict in conflicts:
                installed_conflict = self.waptdb.installed_matching(conflict)
                if installed_conflict and not ((conflict,installed_conflict)) in to_remove:
                    to_remove.append((conflict,installed_conflict))
                remove_matching(conflict,to_upgrade)
                remove_matching(conflict,additional_install)
                remove_matching(conflict,skipped)


        result =  {'additional':additional_install,'upgrade':to_upgrade,'install':packages,'skipped':skipped,'unavailable':unavailable,'remove':to_remove}
        return result

    def check_remove(self,apackages):
        """Return a list of additional package to remove if apackages are removed

        Args:
            apackages (str or list of req or PackageRequest): list of packages for which parent dependencies will be checked.

        Returns:
            list: list of PackageRequest with broken dependencies

        """
        if not isinstance(apackages,list):
            apackages = [apackages]
        result = []

        package_requests = self._ensure_package_requests_list(apackages,PackageRequest())

        installed = []
        for p in self.installed():
            for req in package_requests:
                if req.is_matched_by(p):
                    continue

            installed.append(p)

        for pe in installed:
            # test for each installed package if the removal would imply a reinstall
            test = self.check_depends(pe,assume_removed=apackages,package_request_filter=PackageRequest())
            # get package names only
            reinstall = [ p[0] for p in (test['upgrade'] + test['additional'])]
            for pr in reinstall:
                if pr in package_requests and not pe in result:
                    result.append(pe)
        return result

    def check_install(self,apackages=None,force=True,forceupgrade=True):
        """Return a list of actions required for install of apackages list of packages
        if apackages is None, check for all pending updates.

        Args:
            apackages (str or list): list of packages or None to check pending install/upgrades
            force (boolean): if True, already installed package listed in apackages
                                will be considered to be reinstalled
            forceupgrade: if True, all dependencies are upgraded to latest version,
                          even if current version comply with depends requirements
        Returns:
            dict: with keys ['skipped', 'additional', 'remove', 'upgrade', 'install', 'unavailable'] and list of
                        (package requirements, PackageEntry)

        """
        result = []
        if apackages is None:
            actions = self.list_upgrade()
            apackages = actions['install']+actions['additional']+actions['upgrade']

        actions = self.check_depends(apackages,force=force,forceupgrade=forceupgrade)
        return  actions

    def packages_matching(self,package_request=None,query=None,args=()):
        """Returns the list of known packages Entries matching a PackageRequest

        Args:
            package_request (PackageRequest): request

        Returns:
            list (of PackageEntry)
        """
        if isinstance(package_request,(unicode,str)):
            package_request = PackageRequest(request=package_request)

        if query is None:
            if package_request is not None and package_request.package:
                query = 'select * from wapt_package where package=?'
                args = (package_request.package,)
            else:
                query = u'select * from wapt_package'
                args = ()

        return self.waptdb.query_package_entry(query=query,args=args,package_request=package_request)

    def _ensure_package_requests_list(self,package_requests_or_str,package_request_filter=None,keep_package_entries=False):
        """Takes a list of packages request as string, or PackageRequest or PackageEntry
        and return a list of PackageRequest

        Args:
            package_requests ( (list of) str,PackageEntry,PackageRequest)
            package_request_filter ( PackageRequest) : additional filter. If None, takes the host filter.

        Returns:
            list of PackageEntry
        """
        if package_request_filter is None and self.filter_on_host_cap:
            package_request_filter = self.packages_filter_for_host()

        package_requests = []
        if not isinstance(package_requests_or_str,list):
            package_requests_or_str = [package_requests_or_str]

        for req in package_requests_or_str:
            if isinstance(req,PackageEntry):
                if keep_package_entries:
                    package_requests.append(req)
                else:
                    package_requests.append(PackageRequest(request=req.asrequirement(),copy_from=package_request_filter))
            elif isinstance(req,(str,unicode)):
                package_requests.append(PackageRequest(request=req,copy_from=package_request_filter))
            elif isinstance(req,PackageRequest):
                package_requests.append(req)
            else:
                raise Exception('Unsupported request %s for check_depends' % req)
        return package_requests



    def install(self,apackages,
            force=False,
            params_dict = {},
            download_only=False,
            usecache=True,
            printhook=None,
            installed_by=None,
            only_priorities=None,
            only_if_not_process_running=False,
            process_dependencies=True):

        """Install a list of packages and its dependencies
        removes first packages which are in conflicts package attribute

        Returns a dictionary of (package requirement,package) with 'install','skipped','additional'

        Args:
            apackages (list or str): list of packages requirements "packagename(=version)" or list of PackageEntry.
            force (bool) : reinstalls the packages even if it is already installed
            params_dict (dict) : parameters passed to the install() procedure in the packages setup.py of all packages
                          as params variables and as "setup module" attributes
            download_only (bool) : don't install package, but only download them
            usecache (bool) : use the already downloaded packages if available in cache directory
            printhook (func) : hook for progress print

        Returns:
            dict: with keys ['skipped', 'additional', 'remove', 'upgrade', 'install', 'unavailable'] and list of
                        (package requirements, PackageEntry)

        >>> wapt = Wapt(config_filename='c:/tranquilit/wapt/tests/wapt-get.ini')
        >>> def nullhook(*args):
        ...     pass
        >>> res = wapt.install(['tis-wapttest'],usecache=False,printhook=nullhook,params_dict=dict(company='toto'))
        >>> isinstance(res['upgrade'],list) and isinstance(res['errors'],list) and isinstance(res['additional'],list) and isinstance(res['install'],list) and isinstance(res['unavailable'],list)
        True
        >>> res = wapt.remove('tis-wapttest')
        >>> res == {'removed': ['tis-wapttest'], 'errors': []}
        True
        """

        apackages = self._ensure_package_requests_list(apackages,keep_package_entries=True)

        # ensure that apackages is a list of package requirements (strings)

        actions = self.check_depends(apackages,force=force or download_only,forceupgrade=True)
        actions['errors']=[]

        packages = actions['install']
        skipped = actions['skipped']
        missing = actions['unavailable']

        if process_dependencies:
            to_upgrade = actions['upgrade']
            additional_install = actions['additional']
        else:
            to_upgrade = []
            additional_install = []

        # removal from conflicts
        to_remove = actions['remove']
        for (request,pe) in to_remove:
            logger.info('Removing conflicting package %s'%request)
            try:
                res = self.remove(request,force=True)
                actions['errors'].extend(res['errors'])
                if res['errors']:
                    logger.warning(u'Error removing %s:%s'%(request,ensure_unicode(res['errors'])))
            except Exception as e:
                logger.critical(u'Error removing %s:%s'%(request,ensure_unicode(e)))

        to_install = []

        def is_process_running(processes):
            processes = ensure_list(processes)
            for p in processes:
                if setuphelpers.isrunning(p):
                    return True
            return False

        def is_allowed(package):
            return ((only_priorities is None or package.priority in only_priorities) and
                   (not only_if_not_process_running or not package.impacted_process or not is_process_running(package.impacted_process))
                   )

        to_install.extend([p for p in additional_install if is_allowed(p[1])])
        to_install.extend([p for p in to_upgrade if is_allowed(p[1])])
        to_install.extend([p for p in packages if is_allowed(p[1])] )

        # get package entries to install to_install is a list of (request,package)
        packages = [ p[1] for p in to_install ]

        downloaded = self.download_packages(packages,usecache=usecache,printhook=printhook)
        if downloaded.get('errors',[]):
            logger.critical(u'Error downloading some files : %s'%(downloaded['errors'],))
            for request in downloaded.get('errors',[]):
                actions['errors'].append([request,None])

        # check downloaded packages signatures and merge control data in local database
        for fname in downloaded['downloaded'] + downloaded['skipped']:
            pe = PackageEntry(waptfile = fname)
            pe.check_control_signature(self.cabundle)

        actions['downloads'] = downloaded
        logger.debug(u'Downloaded : %s' % (downloaded,))

        def full_fname(packagefilename):
            return os.path.join(self.package_cache_dir,packagefilename)

        if not download_only:
            # switch to manual mode
            for (request,p) in skipped:
                if request in apackages and not p.explicit_by:
                    logger.info(u'switch to manual mode for %s' % (request,))
                    self.waptdb.switch_to_explicit_mode(p.package,installed_by or self.user)

            for (request,p) in to_install:
                try:
                    if not os.path.isfile(full_fname(p.filename)):
                        raise EWaptDownloadError('Package file %s not downloaded properly.' % p.filename)
                    print(u"Installing %s" % (p.asrequirement(),))
                    result = self.install_wapt(full_fname(p.filename),
                        params_dict = params_dict,
                        explicit_by=(installed_by or self.user) if request in apackages else None,
                        force=force
                        )
                    if result:
                        for k in result.as_dict():
                            p[k] = result[k]

                    if not result or result['install_status'] != 'OK':
                        actions['errors'].append([request,p])
                        logger.critical(u'Package %s not installed due to errors' %(request,))
                except Exception as e:
                    actions['errors'].append([request,p,ensure_unicode(traceback.format_exc())])
                    logger.critical(u'Package %s not installed due to errors : %s' %(request,ensure_unicode(e)))
                    if logger.level == logging.DEBUG:
                        raise
            return actions
        else:
            logger.info(u'Download only, no install performed')
            return actions

    def download_packages(self,package_requests,usecache=True,printhook=None):
        r"""Download a list of packages (requests are of the form packagename (>version) )
        returns a dict of {"downloaded,"skipped","errors"}

        Args:
            package_requests (str or list): list of packages to prefetch
            usecache (boolean) : if True, don't download package if already in cache
            printhook (func) : callback with signature report(received,total,speed,url) to display progress

        Returns:
            dict: with keys {"downloaded,"skipped","errors","packages"} and list of PackageEntry.

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> def nullhook(*args):
        ...     pass
        >>> wapt.download_packages(['tis-firefox','tis-waptdev'],usecache=False,printhook=nullhook)
        {'downloaded': [u'c:/wapt\\cache\\tis-firefox_37.0.2-9_all.wapt', u'c:/wapt\\cache\\tis-waptdev.wapt'], 'skipped': [], 'errors': []}
        """

        package_requests = self._ensure_package_requests_list(package_requests,keep_package_entries=True)

        downloaded = []
        skipped = []
        errors = []
        packages = []

        for p in package_requests:
            if isinstance(p,PackageRequest):
                mp = self.waptdb.packages_matching(p)
                if mp:
                    packages.append(mp[-1])
                else:
                    errors.append((p,u'Unavailable package %s' % (p,)))
                    logger.critical(u'Unavailable package %s' % (p,))
            elif isinstance(p,PackageEntry):
                packages.append(p)
            elif isinstance(p,list) or isinstance(p,tuple):
                packages.append(self.waptdb.package_entry_from_db(p[0],version_min=p[1],version_max=p[1]))
            else:
                raise Exception('Invalid package request %s' % p)

        for entry in packages:
            self.check_cancelled()

            def report(received,total,speed,url):
                self.check_cancelled()
                try:
                    if total>1:
                        stat = u'%s : %i / %i (%.0f%%) (%.0f KB/s)\r' % (url,received,total,100.0*received/total, speed)
                        print(stat)
                    else:
                        stat = u''
                    self.runstatus = u'Downloading %s : %s' % (entry.package,stat)
                except:
                    self.runstatus = u'Downloading %s' % (entry.package,)
            """
            if not printhook:
                printhook = report
            """
            res = self.get_repo(entry.repo).download_packages(entry,
                target_dir=self.package_cache_dir,
                usecache=usecache,
                printhook=printhook)

            downloaded.extend(res['downloaded'])
            skipped.extend(res['skipped'])
            errors.extend(res['errors'])

        return {"downloaded":downloaded,"skipped":skipped,"errors":errors,"packages":packages}

    def get_repo(self,repo_name):
        for r in self.repositories:
            if r.name == repo_name:
                return r
        return None

    def _get_uninstallkeylist(self,uninstall_key_str):
        """Decode uninstallkey list from db field
        For historical reasons, this field is encoded as str(pythonlist)
        or sometimes simple repr of a str

        ..Changed 1.6.2.8:: uninstallkeylist is a json representation of list.

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

    def remove(self,packages_list,force=False):
        """Removes a package giving its package name, unregister from local status DB

        Args:
            packages_list (str or list or path): packages to remove (package name,
                            list of package requirement, package entry or development directory)
            force : if True, unregister package from local status database, even if uninstall has failed

        Returns:
            dict: {'errors': [], 'removed': []}

        """
        result = {'removed':[],'errors':[]}
        if not isinstance(packages_list,list):
            packages_list = [packages_list]

        for package in packages_list:
            try:
                self.check_cancelled()
                # development mode, remove a package by its directory
                if isinstance(package,(str,unicode)) and os.path.isfile(os.path.join(package,'WAPT','control')):
                    package = PackageEntry().load_control_from_wapt(package).package
                elif isinstance(package,PackageEntry):
                    package = package.package
                else:
                    pe = self.is_installed(package)
                    if pe:
                        package = pe.package

                q = self.waptdb.query(u"""\
                   select * from wapt_localstatus
                    where package=?
                   """ , (package,))
                if not q:
                    logger.debug(u"Package %s not installed, removal aborted" % package)
                    return result

                # several versions installed of the same package... ?
                for mydict in q:
                    self.runstatus = u"Removing package %s version %s from computer..." % (mydict['package'],mydict['version'])

                    # removes recursively meta packages which are not satisfied anymore
                    additional_removes = self.check_remove(package)

                    if mydict.get('impacted_process',None):
                        setuphelpers.killalltasks(ensure_list(mydict['impacted_process']))


                    if mydict['uninstall_key']:
                        # cook the uninstall_key because could be either repr of python list or string
                        # should be now json list in DB
                        uninstall_keys = self._get_uninstallkeylist(mydict['uninstall_key'])
                        if uninstall_keys:
                            for uninstall_key in uninstall_keys:
                                if uninstall_key:
                                    try:
                                        uninstall_cmd = self.uninstall_cmd(uninstall_key)
                                        if uninstall_cmd:
                                            logger.info(u'Launch uninstall cmd %s' % (uninstall_cmd,))
                                            # if running porcesses, kill them before launching uninstaller
                                            print(self.run(uninstall_cmd))
                                    except Exception as e:
                                        logger.critical(u"Critical error during uninstall: %s" % (ensure_unicode(e)))
                                        result['errors'].append(package)
                                        if not force:
                                            raise

                    else:
                        logger.debug(u'uninstall key not registered in local DB status.')

                    if mydict['install_status'] != 'ERROR':
                        try:
                            self.uninstall(package)
                        except Exception as e:
                            logger.critical(u'Error running uninstall script: %s'%e)
                            result['errors'].append(package)

                    if mydict['persistent_dir'] and os.path.isdir(os.path.abspath(mydict['persistent_dir'])):
                        shutil.rmtree(os.path.abspath(mydict['persistent_dir']))

                    logger.info(u'Remove status record from local DB for %s' % package)
                    if mydict['package_uuid']:
                        self.waptdb.remove_install_status(package_uuid=mydict['package_uuid'])
                    else:
                        # backard
                        self.waptdb.remove_install_status(package=package)

                    result['removed'].append(package)

                    if reversed(additional_removes):
                        logger.info(u'Additional packages to remove : %s' % additional_removes)
                        for apackage in additional_removes:
                            res = self.remove(apackage,force=True)
                            result['removed'].extend(res['removed'])
                            result['errors'].extend(res['errors'])

                return result
            finally:
                self.store_upgrade_status()
                self.runstatus=''

    def host_packagename(self):
        """Return package name for current computer"""
        #return "%s" % (setuphelpers.get_hostname().lower())
        return u"%s" % (self.host_uuid,)

    def get_host_packages_names(self):
        """Return list of implicit host package names based on computer UUID and AD Org Units

        Returns:
            list: list of str package names.
        """
        """Return list of implicit available host packages based on computer UUID and AD Org Units

        Returns:
            list: list of PackageEntry.
        """
        result = []
        host_package = self.host_packagename()
        result.append(host_package)

        # ini configured profiles
        if self.host_profiles:
            result.extend([make_valid_package_name(p) for p in self.host_profiles])

        previous_dn_part_type = ''
        host_dn = self.host_dn
        if host_dn:
            dn_parts = host_dn.split(',')
            for i in range(1,len(dn_parts)):
                dn_part = dn_parts[i]
                dn_part_type,value = dn_part.split('=',1)
                if dn_part_type.lower() == 'dc' and  dn_part_type == previous_dn_part_type:
                    break
                level_dn = ','.join(dn_parts[i:])
                # spaces and
                result.append(make_valid_package_name(level_dn))
                previous_dn_part_type = dn_part_type
        return result

    def get_host_packages(self):
        """Return list of implicit available host packages based on computer UUID and AD Org Units

        Returns:
            list: list of PackageEntry.
        """
        result = []
        package_names = self.get_host_packages_names()
        for pn in package_names:
            packages = self.is_available(pn)
            if packages and packages[-1].section in ('host','unit','profile'):
                result.append(packages[-1])
        return result

    def get_outdated_host_packages(self):
        """Check and return the available host packages available and not installed"""

        result = []
        host_packages = self.get_host_packages()
        logger.debug(u'Checking availability of host packages "%s"' % (host_packages, ))
        for package in host_packages:
            if self.is_locally_allowed_package(package):
                logger.debug(u'Checking if %s is installed/outdated' % package.asrequirement())
                installed_package = self.is_installed(package.asrequirement())
                if not installed_package or installed_package < package:
                    result.append(package)
        return result

    def get_installed_host_packages(self):
        """Get the implicit package names (host and unit packages) which are installed but no longer relevant

        Returns:
            list: of installed package names
        """
        return [p.package for p in self.installed(True) if p.section in ('host','unit','profile')]

    def get_unrelevant_host_packages(self):
        """Get the implicit package names (host and unit packages) which are installed but no longer relevant

        Returns:
            list: of installed package names
        """
        installed_host_packages = self.get_installed_host_packages()
        expected_host_packages = self.get_host_packages_names()
        return [pn for pn in installed_host_packages if pn not in expected_host_packages]

    def upgrade(self,only_priorities=None,only_if_not_process_running=False):
        """Install "well known" host package from main repository if not already installed
        then query localstatus database for packages with a version older than repository
        and install all newest packages

        Args:
            priorities (list of str): If not None, upgrade only packages with these priorities.

        Returns:
            dict: {'upgrade': [], 'additional': [], 'downloads':
                        {'downloaded': [], 'skipped': [], 'errors': []},
                     'remove': [], 'skipped': [], 'install': [], 'errors': [], 'unavailable': []}
        """
        try:
            self.runstatus='Upgrade system'
            upgrades = self.list_upgrade()
            logger.debug(u'upgrades : %s' % upgrades)

            result = dict(
                install=[],
                upgrade=[],
                additional=[],
                remove=[],
                errors=[])

            if upgrades['remove']:
                self.runstatus = 'Removes outdated / conflicted packages'
                result = merge_dict(result,self.remove(upgrades['remove'],force=True))

            for key in ['additional','upgrade','install']:
                self.runstatus='Install %s packages' % key
                if upgrades[key]:
                    result = merge_dict(result,self.install(upgrades[key],process_dependencies=True))

            result = merge_dict(result,self.install(list(upgrades.keys()),force=True,only_priorities=only_priorities,only_if_not_process_running=only_if_not_process_running))
            self.store_upgrade_status()

            # merge results
            return result
        finally:
            self.runstatus=''

    def list_upgrade(self):
        """Returns a list of packages requirement which can be upgraded

        Returns:
           dict: {'additional': [], 'install': [], 'remove': [], 'upgrade': []}
        """
        result = dict(
            install=[],
            upgrade=[],
            additional=[],
            remove=[])
        # only most up to date (first one in list)
        # put 'host' package at the end.
        result['upgrade'].extend([p[0].asrequirement() for p in self.waptdb.upgradeable().values() if p and not p[0].section in ('host','unit','profile')])

        to_remove = self.get_unrelevant_host_packages()
        result['remove'].extend(to_remove)
        if self.use_hostpackages:
            host_packages = self.get_outdated_host_packages()
            if host_packages:
                for p in host_packages:
                    if self.is_locally_allowed_package(p):
                        req = p.asrequirement()
                        if not req in result['install']+result['upgrade']+result['additional']:
                            result['install'].append(req)

        # get additional packages to install/upgrade based on new upgrades
        depends = self.check_depends(result['install']+result['upgrade']+result['additional'])
        for l in ('upgrade','additional','install'):
            for (r,candidate) in depends[l]:
                req = candidate.asrequirement()
                if not req in result['install']+result['upgrade']+result['additional']:
                    result[l].append(req)
        result['remove'].extend([p[1].asrequirement() for p in depends['remove'] if p[1].package not in result['remove']])
        return result

    def search(self,searchwords=[],exclude_host_repo=True,section_filter=None,newest_only=False):
        """Returns a list of packages which have the searchwords in their description

        Args:
            searchwords (str or list): words to search in packages name or description
            exclude_host_repo (boolean): if True, don't search in host repoisitories.
            section_filter (str or list): restrict search to the specified package sections/categories

        Returns:
            list: list of PackageEntry

        """
        available = self.waptdb.packages_search(searchwords=searchwords,exclude_host_repo=exclude_host_repo,section_filter=section_filter)
        installed = {p.package_uuid:p for p in self.waptdb.installed(include_errors=True)}
        upgradable =  self.waptdb.upgradeable()
        for p in available:
            if p.package_uuid in installed:
                current = installed[p.package_uuid]
                if p == current:
                    p['installed'] = current
                    if p.package in upgradable:
                        p['status'] = 'U'
                    else:
                        p['status'] = 'I'
                else:
                    p['installed'] = None
                    p['status'] = '-'
            else:
                p['installed'] = None
                p['status'] = '-'
        if newest_only:
            filtered = []
            last_package_name = None
            for package in sorted(available,reverse=True,cmp=lambda p1,p2: self.packages_filter_for_host().compare_packages(p1,p2)):
                if package.package != last_package_name:
                    filtered.append(package)
                last_package_name = package.package
            return list(reversed(filtered))
        else:
            return available

    def list(self,searchwords=[]):
        """Returns a list of installed packages which have the searchwords
        in their description

        Args:
            searchwords (list): list of words to llokup in package name and description
                                only entries which have words in the proper order are returned.

        Returns:
            list: list of PackageEntry matching the search words

        >>> w = Wapt()
        >>> w.list('zip')
        [PackageEntry('tis-7zip','16.4-8') ]
        """
        return self.waptdb.installed_search(searchwords=searchwords,)

    def check_downloads(self,apackages=None,usecache=True):
        """Return list of available package entries
        to match supplied packages requirements

        Args:
            apackages (list or str): list of packages
            usecache (bool) : returns only PackageEntry not yet in cache

        Returns:
            list: list of PackageEntry to download
        """
        result = []
        if apackages is None:
            actions = self.list_upgrade()
            apackages = actions['install']+actions['additional']+actions['upgrade']
        elif isinstance(apackages,(str,unicode)):
            apackages = ensure_list(apackages)
        elif isinstance(apackages,list):
            # ensure that apackages is a list of package requirements (strings)
            new_apackages = []
            for p in apackages:
                if isinstance(p,PackageEntry):
                    new_apackages.append(p.asrequirement())
                else:
                    new_apackages.append(p)
            apackages = new_apackages

        for p in apackages:
            entries = self.is_available(p)
            if entries:
                # download most recent
                entry = entries[-1]
                fullpackagepath = os.path.join(self.package_cache_dir,entry.filename)
                if usecache and (os.path.isfile(fullpackagepath) and os.path.getsize(fullpackagepath) == entry.size):
                    # check version
                    try:
                        cached = PackageEntry()
                        cached.load_control_from_wapt(fullpackagepath,calc_md5=False)
                        if entry != cached:
                            result.append(entry)
                    except Exception as e:
                        logger.warning(u'Unable to get version of cached package %s: %s'%(fullpackagepath,ensure_unicode(e),))
                        result.append(entry)
                else:
                    result.append(entry)
            else:
                logger.debug(u'check_downloads : Package %s is not available'%p)
        return result

    def download_upgrades(self):
        """Download packages that can be upgraded"""
        self.runstatus='Download upgrades'
        try:
            to_download = self.check_downloads()
            return self.download_packages(to_download)
        finally:
            self.runstatus=''

    def authorized_certificates(self):
        """return a list of autorized package certificate issuers for this host
            check_certificates_validity enable date checking.
        """
        return self.cabundle.certificates(valid_only = self.check_certificates_validity)

    def register_computer(self,description=None):
        """Send computer informations to WAPT Server
            if description is provided, updates local registry with new description

        Returns:
            dict: response from server.

        >>> wapt = Wapt()
        >>> s = wapt.register_computer()
        >>>

        """
        if description:
            try:
                setuphelpers.set_computer_description(description)
            except Exception as e:
                logger.critical(u'Unable to change computer description to %s: %s' % (description,e))

        # force regenerating uuid
        self.delete_param('uuid')


        new_hashes = {}
        old_hashes = {}

        inv = self._get_host_status_data(old_hashes, new_hashes, force=True, include_dmi=True, include_wmi=True)
        inv['status_hashes'] = new_hashes

        #inv = self.inventory()
        inv['uuid'] = self.host_uuid
        inv['host_certificate'] = self.create_or_update_host_certificate()
        inv['host_certificate_signing_request'] = self.get_host_certificate_signing_request().as_pem()

        data = jsondump(inv)
        if self.waptserver:
            if not self.waptserver.use_kerberos:
                urladdhost = 'add_host'
            else:
                urladdhost = 'add_host_kerberos'
            try:
                result = self.waptserver.post(urladdhost,
                    data = data ,
                    signature = self.sign_host_content(data),
                    signer = self.get_host_certificate().cn
                    )
            except requests.HTTPError as e:
                if e.response.status_code == 400: # could be a bad certificate error, so retry without client side cert
                    # retry without ssl client auth
                    result = self.waptserver.post(urladdhost,
                        data = data ,
                        signature = self.sign_host_content(data),
                        signer = self.get_host_certificate().cn ,
                        use_ssl_auth = False
                        )
                else:
                    raise


            if result and result['success']:
                # stores for next round.
                self.write_param('last_update_server_status_timestamp',datetime.datetime.utcnow())
                result_data = result.get('result',{})
                if 'status_hashes' in result_data:
                    # invalidate unmatching hashes for next round.
                    self.write_param('last_update_server_hashes',result_data['status_hashes'])
                if 'host_certificate' in result_data:
                    # server has signed the certificate, we replace our self signed one.
                    new_host_cert = SSLCertificate(crt_string=result_data['host_certificate'])
                    logger.info('Got signed certificate from server. Issuer: %s. CN: %s' % (new_host_cert.issuer_cn,new_host_cert.cn))
                    if new_host_cert.cn == self.host_uuid and new_host_cert.match_key(self.get_host_key()):
                        new_host_cert.save_as_pem(self.get_host_certificate_filename())
                        self._host_certificate = None
                        self._host_certificate_timestamp = None
                        self.write_param('host_certificate_fingerprint',new_host_cert.fingerprint)
                        self.write_param('host_certificate_authority_key_identifier',(new_host_cert.authority_key_identifier or '').encode('hex'))


            return result

        else:
            return dict(
                success = False,
                msg = u'No WAPT server defined',
                data = data,
                )

    def unregister_computer(self):
        """Remove computer informations from WAPT Server

        Returns:
            dict: response from server.

        >>> wapt = Wapt()
        >>> s = wapt.unregister_computer()
        >>>

        """
        if self.waptserver:
            data = jsondump({'uuids': [self.host_uuid], 'delete_packages':1,'delete_inventory':1})
            result = self.waptserver.post('api/v3/hosts_delete',
                data = data,
                signature = self.sign_host_content(data),
                signer = self.get_host_certificate().cn
                )

            if result and result['success']:
                self.delete_param('last_update_server_hashes')
                if os.path.isfile(self.get_host_certificate_filename()):
                    os.unlink(self.get_host_certificate_filename())
            return result

        else:
            return dict(
                success = False,
                msg = u'No WAPT server defined',
                data = {},
                )

    def get_host_key_filename(self):
        return os.path.join(self.private_dir,self.host_uuid+'.pem')


    def get_host_certificate_filename(self):
        return os.path.join(self.private_dir,self.host_uuid+'.crt')


    def get_host_certificate(self):
        """Return the current host certificate.

        Returns:
            SSLCertificate: host public certificate.
        """
        cert_fn = self.get_host_certificate_filename()
        if not self._host_certificate or not os.path.isfile(cert_fn) or self._host_certificate_timestamp != os.stat(cert_fn).st_mtime:
            if not os.path.isfile(cert_fn):
                self.create_or_update_host_certificate()
            self._host_certificate = SSLCertificate(cert_fn)
            self._host_certificate_timestamp = os.stat(cert_fn).st_mtime
        return self._host_certificate

    def get_host_certificate_signing_request(self):
        """Return a CSR for the host.

        Returns:
            SSLCertificateSigningRequest: host public certificate sigbinbg request.
        """
        host_key = self.get_host_key()
        if sys.platform == 'win32':
            csr = host_key.build_csr(
                    cn = self.host_uuid,
                    dnsname = setuphelpers.get_hostname(),
                    organization = setuphelpers.registered_organization() or None,
                    is_ca=False,
                    is_code_signing=False,
                    is_client_auth=True,
                    key_usages=['digital_signature','content_commitment','data_encipherment','key_encipherment'])
        else:
            csr = host_key.build_csr(
                    cn = self.host_uuid,
                    dnsname = setuphelpers.get_hostname(),
                    is_ca=False,
                    is_code_signing=False,
                    is_client_auth=True,
                    key_usages=['digital_signature','content_commitment','data_encipherment','key_encipherment'])
        return csr

    def create_or_update_host_certificate(self,force_recreate=False):
        """Create a rsa key pair for the host and a x509 certiticate.
            Location of key is <wapt_root>\private
            Should be kept secret
            restricted access to system account and administrators only.

        Args:
            force_recreate (bool): recreate key pair even if already exists for this FQDN.

        Returns:
            str: x509 certificate of this host.

        """
        key_filename = self.get_host_key_filename()
        crt_filename = self.get_host_certificate_filename()

        if force_recreate or not os.path.isfile(crt_filename):
            logger.info(u'Creates host keys pair and x509 certificate %s' % crt_filename)
            self._host_key = self.get_host_key()
            if not os.path.isdir(self.private_dir):
                os.makedirs(self.private_dir)
            if sys.platform =='win32':
                crt = self._host_key.build_sign_certificate(
                    ca_signing_key=None,
                    ca_signing_cert=None,
                    cn = self.host_uuid,
                    dnsname = setuphelpers.get_hostname(),
                    organization = setuphelpers.registered_organization() or None,
                    is_ca=True,
                    is_code_signing=False,
                    is_client_auth=True)
            else:
                crt = self._host_key.build_sign_certificate(
                    ca_signing_key=None,
                    ca_signing_cert=None,
                    cn = self.host_uuid,
                    dnsname = setuphelpers.get_hostname(),
                    organization = None,
                    is_ca=True,
                    is_code_signing=False,
                    is_client_auth=True)
            crt.save_as_pem(crt_filename)
            self.write_param('host_certificate_fingerprint',crt.fingerprint)
            self.write_param('host_certificate_authority_key_identifier',(crt.authority_key_identifier or '').encode('hex'))
        # check validity
        return open(crt_filename,'rb').read()

    def get_host_key(self,create=True):
        """Return private key used to sign uploaded data from host
        Create key if it does not exists yet.

        Returns:
            SSLPrivateKey: Private key used to sign data posted by host.
        """
        if self._host_key is None:
            # create keys pair / certificate if not yet initialised
            key_filename = self.get_host_key_filename()
            if create and not os.path.isfile(key_filename):
                self._host_key = SSLPrivateKey(key_filename)
                self._host_key.create()
                if not os.path.isdir(os.path.dirname(key_filename)):
                    os.makedirs(os.path.dirname(key_filename))
                self._host_key.save_as_pem()
            elif os.path.isfile(key_filename):
                self._host_key = SSLPrivateKey(key_filename)

        return self._host_key

    def sign_host_content(self,data,md='sha256'):
        """Sign data str with host private key with sha256 + RSA
        Args:
            data (bytes) : data to sign
        Returns
            bytes: signature of sha256 hash of data.
        """
        key = self.get_host_key()
        return key.sign_content(hexdigest_for_data(str(data),md = md))

    def get_last_update_status(self):
        """Get update status of host as stored at the end of last operation.

        Returns:
            dict:
                'date': timestamp of last operation
                'runstatus': last printed message of wapt core
                'running_tasks': list of tasks
                'errors': list of packages not installed properly
                'upgrades': list of packages which need to be upgraded
        """
        status = self.read_param('last_update_status',{"date": "", "running_tasks": [], "errors": [], "upgrades": []},ptype='json')
        status['runstatus'] = self.read_param('runstatus','')
        return status


    def _get_package_status_rowid(self,package_entry=None,package_name=None):
        """Return ID of package_status record for package_name

        Args:
            package_entry (PackageEntry): package
            # todo: should be a PackageRequest

        Returns:
            int: rowid in local wapt_localstatus table
        """
        with self.waptdb as waptdb:
            cur = waptdb.db.execute("""select rowid from wapt_localstatus where package=?""" ,(package_entry.package if package_entry is not None else package_name,))
            pe = cur.fetchone()
            if not pe:
                return None
            else:
                return pe[0]

    def update_package_install_status(self,**kwargs):
        """Update the install status
        """

        return self.waptdb.update_install_status(**kwargs)


    def _get_host_status_data(self,old_hashes,new_hashes,force=False,include_wmi=False,include_dmi=False):
        """Build the data to send to server where update_server_status required

        Returns:
            dict
        """

        def _add_data_if_updated(inv,key,data,old_hashes,new_hashes):
            """Add the data to inv as key if modified since last update_server_status"""
            newhash = hashlib.sha1(cPickle.dumps(data)).hexdigest()
            oldhash = old_hashes.get(key,None)
            if force or oldhash != newhash:
                inv[key] = data
                new_hashes[key] = newhash

        inv = {'uuid': self.host_uuid}
        inv['status_revision'] = self.read_param('status_revision',0,'int')

        host_info = setuphelpers.host_info()
        host_info['repositories'] = ";".join([r.as_dict()['repo_url'] for r in self.repositories if not(r.as_dict()['repo_url'].endswith('-host'))])

        # optionally forced dn
        host_info['computer_ad_dn'] = self.host_dn

        self.write_param('host_ad_groups_ttl',0.0)
        _add_data_if_updated(inv,'wapt_status',self.wapt_status(),old_hashes,new_hashes)
        _add_data_if_updated(inv,'host_capabilities',self.host_capabilities(),old_hashes,new_hashes)
        _add_data_if_updated(inv,'host_info',host_info,old_hashes,new_hashes)
        _add_data_if_updated(inv,'host_metrics',setuphelpers.host_metrics(),old_hashes,new_hashes)
        _add_data_if_updated(inv,'audit_status',self.get_audit_status(),old_hashes,new_hashes)
        _add_data_if_updated(inv,'installed_softwares',setuphelpers.installed_softwares(''),old_hashes,new_hashes)
        _add_data_if_updated(inv,'installed_packages',[p.as_dict() for p in self.waptdb.installed(include_errors=True,include_setup=False)],old_hashes,new_hashes)
        _add_data_if_updated(inv,'last_update_status', self.get_last_update_status(),old_hashes,new_hashes)

        authorized_certificates_pem = [c.as_pem() for c in self.authorized_certificates()]
        _add_data_if_updated(inv,'authorized_certificates',authorized_certificates_pem,old_hashes,new_hashes)

        if include_dmi:
            try:
                _add_data_if_updated(inv,'dmi',setuphelpers.dmi_info(),old_hashes,new_hashes)
            except:
                logger.warning(u'DMI not working')

        if os.name=='nt':
            if include_wmi:
                try:
                    _add_data_if_updated(inv,'wmi',setuphelpers.wmi_info(),old_hashes,new_hashes)
                except:
                    logger.warning('WMI not working')

            if self.get_wapt_edition() == 'enterprise':
                try:
                    import waptenterprise.waptwua.client
                    wua_client = waptenterprise.waptwua.client.WaptWUA(self)
                    try:
                        waptwua_status = wua_client.stored_waptwua_status()
                        waptwua_rules_packages = wua_client.stored_waptwua_rules()
                        waptwua_updates = wua_client.stored_updates()
                        waptwua_updates_localstatus = wua_client.stored_updates_localstatus()

                        _add_data_if_updated(inv,'wuauserv_status', wua_client.get_wuauserv_status(),old_hashes,new_hashes)
                        _add_data_if_updated(inv,'waptwua_status', waptwua_status,old_hashes,new_hashes)
                        # not useful
                        _add_data_if_updated(inv,'waptwua_rules_packages', waptwua_rules_packages,old_hashes,new_hashes)
                        _add_data_if_updated(inv,'waptwua_updates', waptwua_updates,old_hashes,new_hashes)
                        _add_data_if_updated(inv,'waptwua_updates_localstatus', waptwua_updates_localstatus,old_hashes,new_hashes)

                    finally:
                        wua_client = None

                except ImportError as e:
                    logger.warning(u'waptwua module not installed')

        return inv

    def get_auth_token(self,purpose='websocket'):
        """Get an auth token from server providing signed uuid by provite host key.

        Returns:
            dict
        """
        # avoid sending data to the server if it has not been updated.
        data = jsondump({'uuid':self.host_uuid,'purpose':purpose,'computer_fqdn':setuphelpers.get_hostname()})
        signature = self.sign_host_content(data)

        result = self.waptserver.post('get_websocket_auth_token',
            data = data,
            signature = signature,
            signer = self.get_host_certificate().fingerprint
            )

        if result and result['success']:
            return result['result']['authorization_token']
        else:
            raise EWaptException(u'Unable to get auth token: %s' % result['msg'])

    def update_server_status(self,force=False):
        """Send host_info, installed packages and installed softwares,
            and last update status informations to WAPT Server,
            but don't send register info like dmi or wmi.

        .. versionchanged:: 1.4.3
            if last status has been properly sent to server and data has not changed,
                don't push data again to server.
            the hash is stored in memory, so is not pass across threads or processes.

        >>> wapt = Wapt()
        >>> s = wapt.update_server_status()
        >>>
        """
        result = None
        sys.stdout.flush()
        if self.waptserver_available():
            # avoid sending data to the server if it has not been updated.
            try:
                new_hashes = {}
                old_hashes = self.read_param('last_update_server_hashes',{},ptype='json')

                inv = self._get_host_status_data(old_hashes, new_hashes, force=force)
                inv['status_hashes'] = new_hashes
                logger.info('Updated data keys : %s' % [k for k in new_hashes if k != new_hashes.get(k)])
                logger.info('Supplied data keys : %s' % list(inv.keys()))
                data = jsondump(inv)
                signature = self.sign_host_content(data,)

                result = self.waptserver.post('update_host',
                    data = data,
                    signature = signature,
                    signer = self.get_host_certificate().cn
                    )

                if result and result['success']:
                    # stores for next round.
                    self.write_param('last_update_server_status_timestamp',datetime.datetime.utcnow())
                    if 'status_hashes' in result.get('result',{}):
                        # known server hashes for next round.
                        self.write_param('last_update_server_hashes',result['result']['status_hashes'])

                    logger.info(u'Status on server %s updated properly' % self.waptserver.server_url)
                else:
                    logger.info(u'Error updating Status on server %s: %s' % (self.waptserver.server_url,result and result['msg'] or 'No message'))

            except Exception as e:
                logger.warning(u'Unable to update server status : %s' % ensure_unicode(e))
                logger.debug(traceback.format_exc())

            # force register if computer has not been registered or hostname has changed
            # this should work only if computer can authenticate on wapt server using
            # kerberos (if enabled...)
            if result and not result['success']:
                db_data = result.get('result',None)
                if not db_data or db_data.get('computer_fqdn',None) != setuphelpers.get_hostname():
                    logger.warning(u'Host on the server is not known or not known under this FQDN name (known as %s). Trying to register the computer...'%(db_data and db_data.get('computer_fqdn',None) or None))
                    result = self.register_computer()
                    if result and result['success']:
                        logger.info(u'New registration successful')
                    else:
                        logger.critical(u'Unable to register: %s' % result and result['msg'])
            elif not result:
                logger.info(u'update_server_status failed, no result. Check server version.')
            else:
                logger.debug(u'update_server_status successful %s' % (result,))
        else:
            logger.info('WAPT Server is not available to store current host status')
        return result

    def waptserver_available(self):
        """Test reachability of waptserver.

        If waptserver is defined and available, return True, else False

        Returns:
            boolean: True if server is defined and actually reachable
        """
        return self.waptserver and self.waptserver.available()

    def inc_status_revision(self,inc=1):
        rev = self.read_param('status_revision',0,ptype='int')+inc
        self.write_param('status_revision',rev)
        return rev


    def wapt_status(self):
        """Wapt configuration and version informations

        Returns:
            dict: versions of main main files, waptservice config,
                  repos and waptserver config

        >>> w = Wapt()
        >>> w.wapt_status()
        {
        	'setuphelpers-version': '1.1.1',
        	'waptserver': {
        		'wapt_server': u'tranquilit.local',
        		'proxies': {
        			'http': None,
        			'https': None
        		},
        		'server_url': 'https: //wapt.tranquilit.local'
        	},
        	'waptservice_protocol': 'http',
        	'repositories': [{
        		'wapt_server': u'tranquilit.local',
        		'proxies': {
        			'http': None,
        			'https': None
        		},
        		'name': 'global',
        		'repo_url': 'http: //wapt.tranquilit.local/wapt'
        	},
        	{
        		'wapt_server': u'tranquilit.local',
        		'proxies': {
        			'http': None,
        			'https': None
        		},
        		'name': 'wapt-host',
        		'repo_url': 'http: //srvwapt.tranquilit.local/wapt-host'
        	}],
        	'common-version': '1.1.1',
        	'wapt-exe-version': u'1.1.1.0',
        	'waptservice_port': 8088,
        	'wapt-py-version': '1.1.1'
        }
        """
        result = {}
        waptexe = os.path.join(self.wapt_base_dir,'wapt-get.exe')
        if os.path.isfile(waptexe):
            result['wapt-exe-version'] = setuphelpers.get_file_properties(waptexe)['FileVersion']
        waptservice =  os.path.join( os.path.dirname(sys.argv[0]),'waptservice.exe')
        if os.path.isfile(waptservice):
            result['waptservice-version'] = setuphelpers.get_file_properties(waptservice)['FileVersion']
        result['setuphelpers-version'] = setuphelpers.__version__
        result['wapt-py-version'] = __version__
        result['common-version'] = __version__

        trusted_certs_sha256 = []
        trusted_certs_cn = []
        invalid_certs_sha256 = []

        for c in self.authorized_certificates():
            try:
                for c2 in self.cabundle.check_certificates_chain(c):
                    if not c2.fingerprint in trusted_certs_sha256:
                        trusted_certs_sha256.append(c2.fingerprint)
                        trusted_certs_cn.append(c2.cn)
            except Exception as e:
                logger.warning('Certificate %s invalid (fingerprint %s expiration %s): %s' % (c.cn,c.fingerprint,c.not_after,e))
                invalid_certs_sha256.append(c.fingerprint)

        result['authorized_certificates_sha256'] = trusted_certs_sha256
        result['invalid_certificates_sha256'] = invalid_certs_sha256
        result['authorized_certificates_cn'] = trusted_certs_cn
        result['maturities'] = self.maturities
        result['locales'] = self.locales
        result['is_remote_repo']=self.config.getboolean('repo-sync','enable_remote_repo') if (self.config.has_section('repo-sync') and self.config.has_option('repo-sync','enable_remote_repo')) else False
        if sys.platform == 'win32':
            result['pending_reboot_reasons']= setuphelpers.pending_reboot_reasons()

        # read from config
        if self.config.has_option('global','waptservice_sslport'):
            port = self.config.get('global','waptservice_sslport')
            if port:
                result['waptservice_protocol'] = 'https'
                result['waptservice_port'] = int(port)
            else:
                result['waptservice_protocol'] = None
                result['waptservice_port'] = None
        elif self.config.has_option('global','waptservice_port'):
            port = self.config.get('global','waptservice_port')
            if port:
                result['waptservice_protocol'] = 'http'
                result['waptservice_port'] = int(port)
            else:
            # could be better
                result['waptservice_protocol'] = None
                result['waptservice_port'] = None
        else:
            # could be better
            result['waptservice_protocol'] = 'http'
            result['waptservice_port'] = 8088

        result['repositories'] = [ r.as_dict() for r in self.repositories]
        if self.waptserver:
            result['waptserver'] = self.waptserver.as_dict()

        result['packages_whitelist'] = self.packages_whitelist
        result['packages_blacklist'] = self.packages_blacklist

        if enterprise_common:
            result['self_service_rules'] = enterprise_common.self_service_rules(self)

        return result

    def reachable_ip(self):
        """Return the local IP which is most probably reachable by wapt server

        In case there are several network connections, returns the local IP
          which Windows choose for sending packets to WaptServer.

        This can be the most probable IP which would get packets from WaptServer.

        Returns:
            str: Local IP
        """
        try:
            if self.waptserver and self.waptserver.server_url:
                host = urlparse.urlparse(self.waptserver.server_url).hostname
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1)
                s.connect((host, 0))
                local_ip = s.getsockname()[0]
                s.close()
                return local_ip
            else:
                return None
        except:
            return None

    def inventory(self):
        """Return full inventory of the computer as a dictionary.

        Returns:
            dict: {'host_info','wapt_status','dmi','installed_softwares','installed_packages'}

        ...changed:
            1.4.1: renamed keys
            1.6.2.4: removed setup.py from packages inventory.
        """
        inv = {}
        inv['host_info'] = setuphelpers.host_info()
        inv['host_info']['repositories'] = ";".join([r.as_dict()['repo_url'] for r in self.repositories if not(r.as_dict()['repo_url'].endswith('-host'))])
        # optionally forced dn
        inv['computer_ad_dn'] = self.host_dn

        try:
            inv['dmi'] = setuphelpers.dmi_info()
        except:
            inv['dmi'] = None
            logger.warning('DMI not working')

        try:
            inv['wmi'] = setuphelpers.wmi_info()
        except:
            inv['wmi'] = None
            logger.warning('WMI unavailable')

        inv['wapt_status'] = self.wapt_status()

        inv['installed_softwares'] = setuphelpers.installed_softwares('')
        inv['installed_packages'] = [p.as_dict() for p in self.waptdb.installed(include_errors=True,include_setup=False)]
        return inv

    def personal_certificate(self):
        """Returns the personal certificates chain

        Returns:
            list (of SSLCertificate). The first one is the personal certificate. The other are useful if intermediate CA are used.
        """
        cert_chain = SSLCABundle()
        cert_chain.add_certificates_from_pem(pem_filename = self.personal_certificate_path)
        return cert_chain.certificates()

    def private_key(self,private_key_password = None):
        """SSLPrivateKey matching the personal_certificate
        When key has been found, it is kept in memory for later use.

        Args:
            private_key_password : password to use to decrypt key. If None, passwd_callback is called.

        Returns:
            SSLPrivateKey

        Raises:
            EWaptMissingPrivateKey if ket can not be decrypted or found.
        """
        if private_key_password is None:
            password_callback = self.private_key_password_callback
        else:
            password_callback = None

        certs = self.personal_certificate()
        cert = certs[0]
        if not self._private_key_cache or not cert.match_key(self._private_key_cache):
            self._private_key_cache = cert.matching_key_in_dirs(password_callback=password_callback,private_key_password=private_key_password)
        if self._private_key_cache is None:
            raise EWaptMissingPrivateKey(u'The key matching the certificate %s can not be found or decrypted' % (cert.public_cert_filename or cert.subject))
        return self._private_key_cache

    def sign_package(self,zip_or_directoryname,certificate=None,private_key_password=None,private_key = None,
        set_maturity=None,inc_package_release=False,keep_signature_date=False,excludes = []):
        """Calc the signature of the WAPT/manifest.sha256 file and put/replace it in ZIP or directory.
            if directory, creates WAPT/manifest.sha256 and add it to the content of package
            create a WAPT/signature file and it to directory or zip file.

            known issue : if zip file already contains a manifest.sha256 file, it is not removed, so there will be
                          2 manifest files in zip / wapt package.

        Args:
            zip_or_directoryname: filename or path for the wapt package's content
            certificate (list): certificates chain of signer.
            private_key (SSLPrivateKey): the private key to use
            private_key_password (str) : passphrase to decrypt the private key. If None provided, use self.private_key_password_callback

        Returns:
            str: base64 encoded signature of manifest.sha256 file (content
        """
        if not isinstance(zip_or_directoryname,unicode):
            zip_or_directoryname = unicode(zip_or_directoryname)

        if certificate is None:
            certificate = self.personal_certificate()

        if isinstance(certificate,list):
            signer_cert = certificate[0]
        else:
            signer_cert = certificate

        if private_key_password is None:
            password_callback = self.private_key_password_callback
        else:
            password_callback = None

        if private_key is None:
            private_key = signer_cert.matching_key_in_dirs(password_callback=password_callback,private_key_password=private_key_password)

        logger.info(u'Using identity : %s' % signer_cert.cn)
        pe =  PackageEntry().load_control_from_wapt(zip_or_directoryname)
        if set_maturity is not None and pe.maturity != set_maturity:
            pe.maturity = set_maturity
        if inc_package_release:
            pe.inc_build()
        pe.save_control_to_wapt()
        return pe.sign_package(private_key=private_key,
                certificate = certificate,password_callback=password_callback,
                private_key_password=private_key_password,
                mds = self.sign_digests,
                keep_signature_date=keep_signature_date,
                excludes = excludes,
                excludes_full = ['.svn','.git','.gitignore','setup.pyc'] )

    def build_package(self,directoryname,target_directory=None,excludes=[]):
        """Build the WAPT package from a directory

        Args:
            directoryname (str): source root directory of package to build
            inc_package_release (boolean): increment the version of package in control file.
            set_maturity (str): if not None, change package maturity to this. Can be something like DEV, PROD etc..

        Returns:
            str: Filename of built WAPT package
        """
        if not isinstance(directoryname,unicode):
            directoryname = unicode(directoryname)
        result_filename = u''
        # some checks
        if not os.path.isdir(os.path.join(directoryname,'WAPT')):
            raise EWaptNotAPackage('Error building package : There is no WAPT directory in %s' % directoryname)
        if not os.path.isfile(os.path.join(directoryname,'WAPT','control')):
            raise EWaptNotAPackage('Error building package : There is no control file in WAPT directory')

        control_filename = os.path.join(directoryname,'WAPT','control')

        logger.info(u'Load control informations from control file')
        entry = PackageEntry(waptfile = directoryname)
        result_filename = entry.build_package(excludes=excludes,excludes_full = ['.svn','.git','.gitignore','setup.pyc'],target_directory = target_directory)
        return result_filename


    def build_upload(self,sources_directories,private_key_passwd=None,wapt_server_user=None,wapt_server_passwd=None,inc_package_release=False,
        target_directory=None,set_maturity=None):
        """Build a list of packages and upload the resulting packages to the main repository.
        if section of package is group or host, user specific wapt-host or wapt-group

        Returns
            list: list of filenames of built WAPT package
        """
        sources_directories = ensure_list(sources_directories)
        buildresults = []

        if not self.personal_certificate_path or not os.path.isfile(self.personal_certificate_path):
            raise EWaptMissingPrivateKey('Unable to build %s, personal certificate path %s not provided or not present'%(sources_directories,self.personal_certificate_path))

        for source_dir in [os.path.abspath(p) for p in sources_directories]:
            if os.path.isdir(source_dir):
                logger.info('Signing %s with certificate %s' % (source_dir,self.personal_certificate() ))
                signature = self.sign_package(
                        source_dir,private_key_password = private_key_passwd,
                        inc_package_release=inc_package_release,
                        set_maturity=set_maturity
                        )
                logger.debug(u"Package %s signed : signature :\n%s" % (source_dir,signature))
                logger.info(u'Building  %s' % source_dir)
                package_fn = self.build_package(source_dir,target_directory=target_directory)
                if package_fn:
                    logger.info(u'...done. Package filename %s' % (package_fn,))
                    buildresults.append(package_fn)
                else:
                    logger.critical(u'package %s not created' % package_fn)
            else:
                logger.critical(u'Directory %s not found' % source_dir)

        logger.info(u'Uploading %s files...' % len(buildresults))
        auth = None
        if wapt_server_user and wapt_server_passwd:
            auth = (wapt_server_user,wapt_server_passwd)
        upload_res = self.waptserver.upload_packages(buildresults,auth=auth)
        if buildresults and not upload_res:
            raise Exception(u'Packages built but no package were uploaded')
        return buildresults

    def cleanup_session_setup(self):
        """Remove all current user session_setup informations for removed packages
        """
        installed = self.waptdb.installed_package_names(False)
        self.waptsessiondb.remove_obsolete_install_status(installed)

    def session_setup(self,package,force=False):
        """Setup the user session for a specific system wide installed package"
           Source setup.py from database or filename
        """
        install_id = None
        oldpath = sys.path
        try:
            is_dev_mode = False
            if isinstance(package,PackageEntry):
                package_entry = package
            elif os.path.isdir(package):
                package_entry = PackageEntry().load_control_from_wapt(package)
                is_dev_mode = True
            else:
                package_entry = self.is_installed(package)

            if not package_entry:
                raise Exception(u'Package %s is not installed' % package)

            if package_entry.has_setup_py() and (is_dev_mode or 'def session_setup():' in package_entry.setuppy):
                # initialize a session db for the user
                session_db = WaptSessionDB(self.user)  # WaptSessionDB()
                with session_db:
                    if force or is_dev_mode or not session_db.is_installed(package_entry.package,package_entry.version):
                        print(u"Running session_setup for package %s and user %s" % (package_entry.asrequirement(),self.user))
                        install_id = session_db.add_start_install(package_entry)
                        with WaptPackageSessionSetupLogger(console=sys.stderr,waptsessiondb=session_db,install_id=install_id) as dblog:
                            try:
                                # get value of required parameters from system wide install
                                params = self.get_previous_package_params(package_entry)
                                try:
                                    result = package_entry.call_setup_hook('session_setup',self,params)
                                except EWaptMissingPackageHook:
                                    result = None

                                if result:
                                    dblog.exit_status = 'RETRY'
                                    session_db.update_install_status(install_id,append_output = u'session_setup() done\n')
                                else:
                                    dblog.exit_status = 'OK'
                                    session_db.update_install_status(install_id,append_output = u'session_setup() done\n')
                                return result
                            except Exception as e:
                                logger.critical(u"session_setup failed for package %s and user %s" % (package,self.user))
                                session_db.update_install_status(install_id,append_output = traceback.format_exc())
                                dblog.exit_status = 'ERROR'

                    else:
                        logger.info(u"session_setup for package %s and user %s already installed" % (package,self.user))
            else:
                logger.debug('No setup.py, skipping session-setup')
        finally:
            sys.path = oldpath


    def get_audit_status(self):
        return self.waptdb.audit_status()


    def audit(self,package,force=False):
        """Run the audit hook for the installed package"
        Source setup.py from database, filename, or packageEntry
        """

        def worst(r1,r2):
            states = ['OK','WARNING','ERROR','UNKNOWN']
            try:
                idxr1 = states.index(r1)
            except ValueError:
                idxr1 = states.index('UNKNOWN')
            try:
                idxr2 = states.index(r2)
            except ValueError:
                idxr2 = states.index('UNKNOWN')
            if idxr1 > idxr2:
                return states[idxr1]
            else:
                return states[idxr2]


        install_id = None
        now = datetime2isodate()

        oldpath = sys.path
        try:
            is_dev_mode = False
            if isinstance(package,PackageEntry):
                package_entry = package
            elif os.path.isdir(package):
                package_entry = PackageEntry().load_control_from_wapt(package)
                is_dev_mode = True
            else:
                package_entry = self.is_installed(package)

            if not package_entry:
                raise Exception('Package %s is not installed' % package)

            if hasattr(package_entry,'install_status') and hasattr(package_entry,'rowid'):
                install_id = package_entry.rowid
                package_install = package_entry
            else:
                install_id =  self._get_package_status_rowid(package_entry)
                if install_id is None:
                    raise Exception('Package %s is not installed' % package)
                package_install = self.waptdb.install_status(install_id)

            if force or not package_install.next_audit_on or now >= package_install.next_audit_on:
                next_audit = None

                if package_install.audit_schedule:
                    audit_period = package_install.audit_schedule
                elif self.config.has_option('global','waptaudit_task_period'):
                    audit_period = self.config.get('global','waptaudit_task_period')
                else:
                    audit_period = None

                if audit_period is not None:
                    timedelta = get_time_delta(audit_period,'m')
                    next_audit = datetime.datetime.now()+timedelta

                # skip audit entirely if no uninstall_key and no audit hook
                if not package_install['uninstall_key']  and (not package_entry.has_setup_py() or not 'def audit():' in package_entry.setuppy):
                    self.waptdb.update_audit_status(install_id,set_status='OK',set_last_audit_on=datetime2isodate(),set_next_audit_on=datetime2isodate(next_audit))
                    return 'OK'

                logger.info(u"Audit run for package %s and user %s" % (package,self.user))
                self.waptdb.update_audit_status(install_id,set_status='RUNNING',set_output='',
                    set_last_audit_on=datetime2isodate(),
                    set_next_audit_on=datetime2isodate(next_audit))

                with WaptPackageAuditLogger(console=sys.stderr,wapt_context=self,install_id=install_id,user=self.user) as dblog:
                    try:
                        # check if registered uninstalley are still there
                        uninstallkeys = self._get_uninstallkeylist(package_install['uninstall_key'])
                        dblog.exit_status = 'OK'

                        if uninstallkeys is not None:
                            for key in uninstallkeys:
                                uninstallkey_exists = setuphelpers.installed_softwares(uninstallkey=key)
                                if not uninstallkey_exists:
                                    print(u'ERROR: Uninstall Key %s is not in Windows Registry.' % key)
                                    dblog.exit_status = worst(dblog.exit_status,'ERROR')
                                else:
                                    print(u'OK: Uninstall Key %s in Windows Registry.' % key)
                                    dblog.exit_status = worst(dblog.exit_status,'OK')

                        if package_entry.has_setup_py():
                            # get value of required parameters from system wide install
                            params = self.get_previous_package_params(package_entry)
                            # this call return None if not audit hook or if hook has no return value.
                            try:
                                result = package_entry.call_setup_hook('audit',self,params)
                            except EWaptMissingPackageHook:
                                result = 'OK'
                            dblog.exit_status = worst(dblog.exit_status,result)
                        else:
                            logger.debug(u'No setup.py, skipping session-setup')
                            print(u'OK: No setup.py')
                            dblog.exit_status = worst(dblog.exit_status,'OK')

                        return dblog.exit_status

                    except Exception as e:
                        print(u'Audit aborted due to exception: %s' % e)
                        dblog.exit_status = 'ERROR'
                        return dblog.exit_status
            else:
                return package_install.last_audit_status

        finally:
            sys.path = oldpath

    def get_previous_package_params(self,package_entry):
        """Return the params used when previous install of package_entry.package
        If no previous install, return {}
        The params are stored as json string in local package status table.

        Args:
            package_entry (PackageEntry): package request to lookup.

        Returns:
            dict
        """
        # get old install params if the package has been already installed
        old_install = self.is_installed(package_entry.package)
        if old_install:
            return ujson.loads(old_install['install_params'])
        else:
            return {}

    def uninstall(self,packagename,params_dict={}):
        """Launch the uninstall script of an installed package"
        Source setup.py from database or filename
        """
        try:
            previous_cwd = os.getcwdu()
            if os.path.isdir(packagename):
                entry = PackageEntry().load_control_from_wapt(packagename)
            else:
                logger.debug(u'Sourcing setup from DB')
                entry = self.is_installed(packagename)

            params = self.get_previous_package_params(entry)
            params.update(params_dict)

            if entry.has_setup_py():
                try:
                    result = entry.call_setup_hook('uninstall',self,params=params)
                except EWaptMissingPackageHook:
                    pass
            else:
                logger.info(u'Uninstall: no setup.py source in database.')

        finally:
            logger.debug(u'  Change current directory to %s' % previous_cwd)
            os.chdir(previous_cwd)

    def make_package_template(self,installer_path='',packagename='',directoryname='',
        section='base',description=None,depends='',version=None,silentflags=None,uninstallkey=None,
        maturity=None,architecture='all'):
        r"""Build a skeleton of WAPT package based on the properties of the supplied installer
           Return the path of the skeleton
        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> wapt.dbpath = ':memory:'
        >>> files = 'c:/tmp/files'
        >>> if not os.path.isdir(files):
        ...    os.makedirs(files)
        >>> tmpdir = 'c:/tmp/dummy'
        >>> devdir = wapt.make_package_template(files,packagename='mydummy',directoryname=tmpdir,depends='tis-firefox')
        >>> os.path.isfile(os.path.join(devdir,'WAPT','control'))
        True
        >>> p = wapt.build_package(devdir)
        >>> 'filename' in p and isinstance(p['files'],list) and isinstance(p['package'],PackageEntry)
        True
        >>> import shutil
        >>> shutil.rmtree(tmpdir)
        """
        if installer_path:
            installer_path = os.path.abspath(installer_path)
        if directoryname:
             directoryname = os.path.abspath(directoryname)

        if not installer_path and not packagename:
            raise EWaptException(u'You must provide at least installer_path or packagename to be able to prepare a package template')

        if installer_path:
            installer = os.path.basename(installer_path)
        else:
            installer = ''

        uninstallkey = uninstallkey or  ''

        if os.path.isfile(installer_path):
            # case of an installer
            props = setuphelpers.getproductprops(installer_path)
            silentflags = silentflags or setuphelpers.getsilentflags(installer_path)
            # for MSI, uninstallkey is in properties
            if not uninstallkey and 'ProductCode' in props:
                uninstallkey = u'"%s"' % props['ProductCode']
        elif os.path.isdir(installer_path):
            # case of a directory
            props = {
                'product':installer,
                'description':installer,
                'version': '0',
                'publisher':ensure_unicode(setuphelpers.get_current_user())
                }
            silentflags = silentflags or ''
        else:
            # case of a nothing
            props = {
                'product':packagename,
                'description':packagename,
                'version': '0',
                'publisher':ensure_unicode(setuphelpers.get_current_user())
                }
            silentflags = ''

        if not packagename:
            simplename = re.sub(r'[\s\(\)\|\,\.\%]+','_',props['product'].lower())
            packagename = u'%s-%s' %  (self.config.get('global','default_package_prefix'),simplename)

        description = description or u'Package for %s ' % props['description']
        version = version or props['version']

        if not directoryname:
            directoryname = self.get_default_development_dir(packagename,section=section)

        if not os.path.isdir(os.path.join(directoryname,'WAPT')):
            os.makedirs(os.path.join(directoryname,'WAPT'))

        if installer_path:
            (installer_name,installer_ext) = os.path.splitext(installer)
            installer_ext = installer_ext.lower()
            if installer_ext == '.msi':
                setup_template = os.path.join(self.wapt_base_dir,'templates','setup_package_template_msi.py')
            elif installer_ext == '.msu':
                setup_template = os.path.join(self.wapt_base_dir,'templates','setup_package_template_msu.py')
            elif installer_ext == '.exe':
                setup_template = os.path.join(self.wapt_base_dir,'templates','setup_package_template_exe.py')
            elif os.path.isdir(installer_path):
                setup_template = os.path.join(self.wapt_base_dir,'templates','setup_package_template_dir.py')
            else:
                setup_template = os.path.join(self.wapt_base_dir,'templates','setup_package_template.py')
        else:
            setup_template = os.path.join(self.wapt_base_dir,'templates','setup_package_skel.py')

        template = codecs.open(setup_template,encoding='utf8').read()%dict(
            packagename=packagename,
            uninstallkey=uninstallkey,
            silentflags=silentflags,
            installer = installer,
            product=props['product'],
            description=description,
            version=version,
            )
        setuppy_filename = os.path.join(directoryname,'setup.py')
        if not os.path.isfile(setuppy_filename):
            codecs.open(setuppy_filename,'w',encoding='utf8').write(template)
        else:
            logger.info(u'setup.py file already exists, skip create')
        logger.debug(u'Copy installer %s to target' % installer)
        if os.path.isfile(installer_path):
            shutil.copyfile(installer_path,os.path.join(directoryname,installer))
        elif os.path.isdir(installer_path):
            setuphelpers.copytree2(installer_path,os.path.join(directoryname,installer))

        control_filename = os.path.join(directoryname,'WAPT','control')
        if not os.path.isfile(control_filename):
            entry = PackageEntry()
            entry.package = packagename
            entry.architecture=architecture
            if maturity is None:
                entry.maturity=self.default_maturity
            else:
                entry.maturity=maturity

            entry.description = description
            try:
                entry.maintainer = ensure_unicode(win32api.GetUserNameEx(3))
            except:
                try:
                    entry.maintainer = ensure_unicode(setuphelpers.get_current_user())
                except:
                    entry.maintainer = os.environ['USERNAME']

            entry.priority = 'optional'
            entry.section = section or 'base'
            entry.version = version+'-0'
            entry.depends = depends
            if self.config.has_option('global','default_sources_url'):
                entry.sources = self.config.get('global','default_sources_url') % entry.as_dict()
            codecs.open(control_filename,'w',encoding='utf8').write(entry.ascontrol())
        else:
            logger.info(u'control file already exists, skip create')

        self.add_pyscripter_project(directoryname)

        return directoryname

    def make_host_template(self,packagename='',depends=None,conflicts=None,directoryname=None,description=None):
        if not packagename:
            packagename = self.host_packagename()
        return self.make_group_template(packagename=packagename,depends=depends,conflicts=conflicts,directoryname=directoryname,section='host',description=description)

    def make_group_template(self,packagename='',maturity=None,depends=None,conflicts=None,directoryname=None,section='group',description=None):
        r"""Creates or updates on disk a skeleton of a WAPT group package.
        If the a package skeleton already exists in directoryname, it is updated.

        sourcespath attribute of returned PackageEntry is populated with the developement directory of group package.

        Args:
            packagename (str): group name
            depends :
            conflicts
            directoryname
            section
            description

        Returns:
            PackageEntry

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> tmpdir = 'c:/tmp/dummy'
        >>> if os.path.isdir(tmpdir):
        ...    import shutil
        ...    shutil.rmtree(tmpdir)
        >>> p = wapt.make_group_template(packagename='testgroupe',directoryname=tmpdir,depends='tis-firefox',description=u'Test de groupe')
        >>> print p
        >>> print p['package'].depends
        tis-firefox
        >>> import shutil
        >>> shutil.rmtree(tmpdir)
        """
        if directoryname:
             directoryname = os.path.abspath(directoryname)

        if not packagename:
            packagename = self.host_packagename()

        if not directoryname:
            directoryname = self.get_default_development_dir(packagename,section=section)

        if not directoryname:
            directoryname = tempfile.mkdtemp('wapt')

        if not os.path.isdir(os.path.join(directoryname,'WAPT')):
            os.makedirs(os.path.join(directoryname,'WAPT'))

        template_fn = os.path.join(self.wapt_base_dir,'templates','setup_%s_template.py' % section)
        if os.path.isfile(template_fn):
            # replacing %(var)s by local values in template
            # so setup template must use other string formating system than % like '{}'.format()
            template = codecs.open(template_fn,encoding='utf8').read() % locals()
            setuppy_filename = os.path.join(directoryname,'setup.py')
            if not os.path.isfile(setuppy_filename):
                codecs.open(setuppy_filename,'w',encoding='utf8').write(template)
            else:
                logger.info(u'setup.py file already exists, skip create')
        else:
            logger.info(u'No %s template. Package wil lhave no setup.py' % template_fn)

        control_filename = os.path.join(directoryname,'WAPT','control')
        entry = PackageEntry()
        if not os.path.isfile(control_filename):
            entry.priority = 'standard'
            entry.section = section
            entry.version = '0'
            entry.architecture='all'
            if maturity is None:
                entry.maturity = maturity
            else:
                entry.maturity = self.default_maturity
            entry.description = description or u'%s package for %s ' % (section,packagename)
            try:
                entry.maintainer = ensure_unicode(win32api.GetUserNameEx(3))
            except:
                try:
                    entry.maintainer = ensure_unicode(setuphelpers.get_current_user())
                except:
                    entry.maintainer = os.environ['USERNAME']
        else:
            entry.load_control_from_wapt(directoryname)

        entry.package = packagename

        # Check existing versions and increment it
        older_packages = self.is_available(entry.package)
        if older_packages and entry<=older_packages[-1]:
            entry.version = older_packages[-1].version
            entry.inc_build()

        entry.filename = entry.make_package_filename()

        if self.config.has_option('global','default_sources_url'):
            entry.sources = self.config.get('global','default_sources_url') % {'packagename':packagename}

        # check if depends should be appended to existing depends
        if (isinstance(depends,str) or isinstance(depends,unicode)) and depends.startswith('+'):
            append_depends = True
            depends = ensure_list(depends[1:])
            current = ensure_list(entry.depends)
            for d in depends:
                if not d in current:
                    current.append(d)
            depends = current
        else:
            append_depends = False

        depends = ensure_list(depends)
        if depends:
            # use supplied list of packages
            entry.depends = u','.join([u'%s' % p for p in depends if p and p != packagename ])


        # check if conflicts should be appended to existing conflicts
        if (isinstance(conflicts,str) or isinstance(conflicts,unicode)) and conflicts.startswith('+'):
            append_conflicts = True
            conflicts = ensure_list(conflicts[1:])
            current = ensure_list(entry.conflicts)
            for d in conflicts:
                if not d in current:
                    current.append(d)
            conflicts = current
        else:
            append_conflicts = False

        conflicts = ensure_list(conflicts)
        if conflicts:
            # use supplied list of packages
            entry.conflicts = u','.join([u'%s' % p for p in conflicts if p and p != packagename ])

        entry.save_control_to_wapt(directoryname)
        if entry.section != 'host':
            self.add_pyscripter_project(directoryname)
        return entry

    def is_installed(self,packagename,include_errors=False):
        """Checks if a package is installed.
        Return package entry and additional local status or None

        Args:
            packagename (str): name / package request to query

        Returns:
            PackageEntry: None en PackageEntry merged with local install_xxx fields
                          * install_date
                          * install_output
                          * install_params
                          * install_status
        """
        if isinstance(packagename,PackageEntry):
            packagename = packagename.asrequirement()
        return self.waptdb.installed_matching(packagename,include_errors=include_errors)

    def installed(self,include_errors=False):
        """Returns all installed packages with their status

        Args:
            include_errors (boolean): include packages wnot installed successfully

        Returns:
            list: list of PackageEntry merged with local install status.
        """
        return self.waptdb.installed(include_errors=include_errors)

    def is_available(self,packagename):
        r"""Check if a package (with optional version condition) is available
        in repositories.

        Args:
            packagename (str) : package name to lookup or package requirement ( packagename(=version) )

        Returns:
            list : of PackageEntry sorted by package version ascending

        >>> wapt = Wapt(config_filename='c:/tranquilit/wapt/tests/wapt-get.ini')
        >>> l = wapt.is_available('tis-wapttest')
        >>> l and isinstance(l[0],PackageEntry)
        True
        """
        return self.waptdb.packages_matching(packagename)

    def get_default_development_dir(self,packagecond,section='base'):
        """Returns the default development directory for package named <packagecond>
        based on default_sources_root ini parameter if provided

        Args:
            packagecond (PackageEntry or str): either PackageEntry or a "name(=version)" string

        Returns:
            unicode: path to local proposed development directory
        """
        if not isinstance(packagecond,PackageEntry):
            # assume something like "package(=version)"
            package_and_version = REGEX_PACKAGE_CONDITION.match(packagecond).groupdict()
            pe = PackageEntry(package_and_version['package'],package_and_version['version'] or '0')
        else:
            pe = packagecond

        root = ensure_unicode(self.config.get('global','default_sources_root'))
        if not root:
            root = ensure_unicode(tempfile.gettempdir())
        return os.path.join(root, pe.make_package_edit_directory())

    def add_pyscripter_project(self,target_directory):
        """Add a pyscripter project file to package development directory.

        Args:
            target_directory (str): path to location where to create the wa^t.psproj file.

        Returns:
            None
        """
        psproj_filename = os.path.join(target_directory,'WAPT','wapt.psproj')
        #if not os.path.isfile(psproj_filename):
        # supply some variables to psproj template
        datas = self.as_dict()
        datas['target_directory'] = target_directory
        proj_template = codecs.open(os.path.join(self.wapt_base_dir,'templates','wapt.psproj'),encoding='utf8').read()%datas
        codecs.open(psproj_filename,'w',encoding='utf8').write(proj_template)

    def edit_package(self,packagerequest,
            target_directory='',
            use_local_sources=True,
            append_depends=None,
            remove_depends=None,
            append_conflicts=None,
            remove_conflicts=None,
            auto_inc_version=True,
            cabundle=None,
            ):
        r"""Download an existing package from repositories into target_directory for modification
        if use_local_sources is True and no newer package exists on repos, updates current local edited data
        else if target_directory exists and is not empty, raise an exception

        Args:
            packagerequest (str) : path to existing wapt file, or package request
            use_local_sources (boolean) : don't raise an exception if target exist and match package version
            append_depends (list of str) : package requirements to add to depends
            remove_depends (list or str) : package requirements to remove from depends
            auto_inc_version (bool) :
            cabundle  (SSLCABundle) : list of authorized certificate filenames. If None, use default from current wapt.

        Returns:
            PackageEntry : edit local package with sourcespath attribute populated

        >>> wapt = Wapt(config_filename='c:/tranquilit/wapt/tests/wapt-get.ini')
        >>> wapt.dbpath = ':memory:'
        >>> r= wapt.update()
        >>> tmpdir = tempfile.mkdtemp('wapt')
        >>> res = wapt.edit_package('tis-wapttest',target_directory=tmpdir,append_depends='tis-firefox',remove_depends='tis-7zip')
        >>> res['target'] == tmpdir and res['package'].package == 'tis-wapttest' and 'tis-firefox' in res['package'].depends
        True
        >>> import shutil
        >>> shutil.rmtree(tmpdir)

        """
        if cabundle is None:
            cabundle = self.cabundle

        # check if available in repos
        entries = self.is_available(packagerequest)
        if entries:
            entry = entries[-1]
            self.download_packages(entry)
        elif os.path.isfile(packagerequest):
            # argument is a wapt package filename, replace packagerequest with entry
            entry = PackageEntry(waptfile=packagerequest)
        else:
            raise EWaptException(u'Package %s does not exist. Either update local status or check filepath.' % (packagerequest))

        packagerequest = entry.asrequirement()

        if target_directory is None:
            target_directory = tempfile.mkdtemp(prefix="wapt")
        elif not target_directory:
            target_directory = self.get_default_development_dir(entry.package,section=entry.section)

        if entry.localpath:
            local_dev_entry = self.is_wapt_package_development_dir(target_directory)
            if local_dev_entry:
                if use_local_sources and not local_dev_entry.match(packagerequest):
                    raise Exception(u'Target directory %s contains a different package version %s' % (target_directory,entry.asrequirement()))
                elif not use_local_sources:
                    raise Exception(u'Target directory %s contains already a developement package %s' % (target_directory,entry.asrequirement()))
                else:
                    logger.info(u'Using existing development sources %s' % target_directory)
            elif not local_dev_entry:
                entry.unzip_package(target_dir=target_directory, cabundle = cabundle)
                entry.invalidate_signature()
                local_dev_entry = entry

            append_depends = ensure_list(append_depends)
            remove_depends = ensure_list(remove_depends)
            append_conflicts = ensure_list(append_conflicts)
            remove_conflicts = ensure_list(remove_conflicts)

            if append_depends or remove_depends or append_conflicts or remove_conflicts:
                prev_depends = ensure_list(local_dev_entry.depends)
                for d in append_depends:
                    if not d in prev_depends:
                        prev_depends.append(d)

                for d in remove_depends:
                    if d in prev_depends:
                        prev_depends.remove(d)

                prev_conflicts = ensure_list(local_dev_entry.conflicts)
                for d in append_conflicts:
                    if not d in prev_conflicts:
                        prev_conflicts.append(d)

                if remove_conflicts:
                    for d in remove_conflicts:
                        if d in prev_conflicts:
                            prev_conflicts.remove(d)


                local_dev_entry.depends = ','.join(prev_depends)
                local_dev_entry.conflicts = ','.join(prev_conflicts)
                local_dev_entry.save_control_to_wapt(target_directory)

            if entry.section != 'host':
                self.add_pyscripter_project(target_directory)
            return local_dev_entry
        else:
            raise Exception(u'Unable to unzip package in %s' % target_directory)

    def is_wapt_package_development_dir(self,directory):
        """Return PackageEntry if directory is a wapt developement directory (a WAPT/control file exists) or False"""
        return os.path.isfile(os.path.join(directory,'WAPT','control')) and PackageEntry().load_control_from_wapt(directory,calc_md5=False)

    def is_wapt_package_file(self,filename):
        """Return PackageEntry if filename is a wapt package or False
        True if file ends with .wapt and control file can be loaded and decoded from zip file

        Args:
            filename (str): path to a file

        Returns:
            False or PackageEntry

        """
        (root,ext)=os.path.splitext(filename)
        if ext != '.wapt' or not os.path.isfile(filename):
            return False
        try:
            entry = PackageEntry().load_control_from_wapt(filename,calc_md5=False)
            return entry
        except:
            return False

    def edit_host(self,
            hostname,
            target_directory=None,
            append_depends=None,
            remove_depends=None,
            append_conflicts=None,
            remove_conflicts=None,
            printhook=None,
            description=None,
            cabundle=None,
            ):
        """Download and extract a host package from host repositories into target_directory for modification

        Args:
            hostname       (str)   : fqdn of the host to edit
            target_directory (str)  : where to place the developments files. if empty, use default one from wapt-get.ini configuration
            append_depends (str or list) : list or comma separated list of package requirements
            remove_depends (str or list) : list or comma separated list of package requirements to remove
            cabundle (SSLCA Bundle) : authorized ca certificates. If None, use default from current wapt.

        Returns:
            PackageEntry

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> tmpdir = 'c:/tmp/dummy'
        >>> wapt.edit_host('dummy.tranquilit.local',target_directory=tmpdir,append_depends='tis-firefox')
        >>> import shutil
        >>> shutil.rmtree(tmpdir)
        >>> host = wapt.edit_host('htlaptop.tranquilit.local',target_directory=tmpdir,append_depends='tis-firefox')
        >>> 'package' in host
        True
        >>> shutil.rmtree(tmpdir)
        """
        if target_directory is None:
            target_directory = tempfile.mkdtemp('wapt')
        elif not target_directory:
            target_directory = self.get_default_development_dir(hostname,section='host')

        if os.path.isdir(target_directory) and os.listdir(target_directory):
            raise Exception(u'directory %s is not empty, aborting.' % target_directory)

        #self.use_hostpackages = True

        if cabundle is None:
            cabundle = self.cabundle

        append_depends = ensure_list(append_depends)
        remove_depends = ensure_list(remove_depends)
        append_conflicts = ensure_list(append_conflicts)
        remove_conflicts = ensure_list(remove_conflicts)

        for d in append_depends:
            if not d in remove_conflicts:
                remove_conflicts.append(d)

        for d in append_conflicts:
            if not d in remove_depends:
                remove_depends.append(d)

        # create a temporary repo for this host
        host_repo = WaptHostRepo(name='wapt-host',host_id=hostname,config = self.config,host_key = self._host_key,WAPT=self)
        entry = host_repo.get(hostname)
        if entry:
            host_repo.download_packages(entry)
            entry.unzip_package(target_dir=target_directory,cabundle=cabundle)
            entry.invalidate_signature()

            # update depends list
            prev_depends = ensure_list(entry.depends)
            for d in append_depends:
                if not d in prev_depends:
                    prev_depends.append(d)
            for d in remove_depends:
                if d in prev_depends:
                    prev_depends.remove(d)
            entry.depends = u','.join(prev_depends)

            # update conflicts list
            prev_conflicts = ensure_list(entry.conflicts)
            for d in append_conflicts:
                if not d in prev_conflicts:
                    prev_conflicts.append(d)
            if remove_conflicts:
                for d in remove_conflicts:
                    if d in prev_conflicts:
                        prev_conflicts.remove(d)
            entry.conflicts = u','.join(prev_conflicts)
            if description is not None:
                entry.description = description

            entry.save_control_to_wapt(target_directory)
            return entry
        else:
            # create a new version of the existing package in repository
            return self.make_host_template(packagename=hostname,directoryname=target_directory,depends=append_depends,description=description)

    def forget_packages(self,packages_list):
        """Remove install status for packages from local database
        without actually uninstalling the packages

        Args:
            packages_list (list): list of installed package names to forget

        Returns:
            list: list of package names actually forgotten

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> res = wapt.install('tis-test')
        ???
        >>> res = wapt.is_installed('tis-test')
        >>> isinstance(res,PackageEntry)
        True
        >>> wapt.forget_packages('tis-test')
        ['tis-test']
        >>> wapt.is_installed('tis-test')
        >>> print wapt.is_installed('tis-test')
        None
        """
        result = []
        packages_list = ensure_list(packages_list)
        for package in packages_list:
            rowid = self.waptdb.remove_install_status(package)
            if rowid:
                result.append(package)
        return result

    def duplicate_package(self,
            packagename,
            newname=None,
            newversion=None,
            newmaturity=None,
            target_directory=None,
            append_depends=None,
            remove_depends=None,
            append_conflicts=None,
            remove_conflicts=None,
            auto_inc_version=True,
            usecache=True,
            printhook=None,
            cabundle = None,
            ):
        """Duplicate an existing package.
        Duplicate an existing package from declared repostory or file into targetdirectory with
          optional newname and version.

        Args:
            packagename (str) :      packagename to duplicate, or filepath to a local package or package development directory.
            newname (str):           name of target package
            newversion (str):        version of target package. if None, use source package version
            target_directory (str):  path where to put development files. If None, use temporary. If empty, use default development dir
            append_depends (list):   comma str or list of depends to append.
            remove_depends (list):   comma str or list of depends to remove.
            auto_inc_version (bool): if version is less than existing package in repo, set version to repo version+1
            usecache (bool):         If True, allow to use cached package in local repo instead of downloading it.
            printhook (func):        hook for download progress
            cabundle (SSLCABundle):         list of authorized ca certificate (SSLPublicCertificate) to check authenticity of source packages. If None, no check is performed.

        Returns:
            PackageEntry : new packageEntry with sourcespath = target_directory

        >>> wapt = Wapt(config_filename='c:/tranquilit/wapt/tests/wapt-get.ini')
        >>> wapt.dbpath = ':memory:'
        >>> r= wapt.update()
        >>> def nullhook(*args):
        ...     pass
        >>> tmpdir = 'c:/tmp/testdup-wapt'
        >>> if os.path.isdir(tmpdir):
        ...     import shutil
        ...     shutil.rmtree(tmpdir)
        >>> p = wapt.duplicate_package('tis-wapttest',
        ...     newname='testdup',
        ...     newversion='20.0-0',
        ...     target_directory=tmpdir,
        ...     excludes=['.svn','.git','.gitignore','*.pyc','src'],
        ...     append_depends=None,
        ...     auto_inc_version=True,
        ...     usecache=False,
        ...     printhook=nullhook)
        >>> print repr(p['package'])
        PackageEntry('testdup','20.0-0')
        >>> if os.path.isdir(tmpdir):
        ...     import shutil
        ...     shutil.rmtree(tmpdir)
        >>> p = wapt.duplicate_package('tis-wapttest',
        ...    target_directory=tempfile.mkdtemp('wapt'),
        ...    auto_inc_version=True,
        ...    append_depends=['tis-firefox','tis-irfanview'],
        ...    remove_depends=['tis-wapttestsub'],
        ...    )
        >>> print repr(p['package'])
        PackageEntry('tis-wapttest','120')
        """
        if target_directory:
             target_directory = os.path.abspath(target_directory)

        if newname:
            while newname.endswith('.wapt'):
                dot_wapt = newname.rfind('.wapt')
                newname = newname[0:dot_wapt]
                logger.warning(u"Target ends with '.wapt', stripping.  New name: %s", newname)

        # default empty result
        result = {}

        append_depends = ensure_list(append_depends)
        remove_depends = ensure_list(remove_depends)
        append_conflicts = ensure_list(append_conflicts)
        remove_conflicts = ensure_list(remove_conflicts)

        def check_target_directory(target_directory,source_control):
            if os.path.isdir(target_directory) and os.listdir(target_directory):
                pe = PackageEntry().load_control_from_wapt(target_directory)
                if  pe.package != source_control.package or pe > source_control:
                    raise Exception(u'Target directory "%s" is not empty and contains either another package or a newer version, aborting.' % target_directory)

        # duplicate a development directory tree
        if os.path.isdir(packagename):
            source_control = PackageEntry().load_control_from_wapt(packagename)
            if not newname:
                newname = source_control.package
            if target_directory == '':
                target_directory = self.get_default_development_dir(newname,section=source_control.section)
            if target_directory is None:
                target_directory = tempfile.mkdtemp('wapt')
            # check if we will not overwrite newer package or different package
            check_target_directory(target_directory,source_control)
            if packagename != target_directory:
                shutil.copytree(packagename,target_directory)
        # duplicate a wapt file
        elif os.path.isfile(packagename):
            source_filename = packagename
            source_control = PackageEntry().load_control_from_wapt(source_filename)
            if not newname:
                newname = source_control.package
            if target_directory == '':
                target_directory = self.get_default_development_dir(newname,section=source_control.section)
            if target_directory is None:
                target_directory = tempfile.mkdtemp('wapt')
            # check if we will not overwrite newer package or different package
            check_target_directory(target_directory,source_control)
            source_control.unzip_package(target_dir=target_directory,cabundle=cabundle)

        else:
            source_package = self.is_available(packagename)
            if not source_package:
                raise Exception(u'Package %s is not available is current repositories.'%(packagename,))
            # duplicate package from a repository
            filenames = self.download_packages([packagename],usecache=usecache,printhook=printhook)
            package_paths = filenames['downloaded'] or filenames['skipped']
            if not package_paths:
                raise Exception(u'Unable to download package %s'%(packagename,))
            source_filename = package_paths[0]
            source_control = PackageEntry().load_control_from_wapt(source_filename)
            if not newname:
                newname = source_control.package
            if target_directory == '':
                target_directory = self.get_default_development_dir(newname,section=source_control.section)
            if target_directory is None:
                target_directory = tempfile.mkdtemp('wapt')
            # check if we will not overwrite newer package or different package
            check_target_directory(target_directory,source_control)
            source_control.unzip_package(target_dir=target_directory,cabundle=cabundle)

        # duplicate package informations
        dest_control = PackageEntry()
        for a in source_control.required_attributes + source_control.optional_attributes:
            dest_control[a] = source_control[a]

        if newmaturity is not None:
            dest_control.maturity = newmaturity
        else:
            dest_control.maturity = self.default_maturity

        # add / remove dependencies from copy
        prev_depends = ensure_list(dest_control.depends)
        for d in append_depends:
            if not d in prev_depends:
                prev_depends.append(d)
        for d in remove_depends:
            if d in prev_depends:
                prev_depends.remove(d)
        dest_control.depends = u','.join(prev_depends)

        # add / remove conflicts from copy
        prev_conflicts = ensure_list(dest_control.conflicts)
        for d in append_conflicts:
            if not d in prev_conflicts:
                prev_conflicts.append(d)

        for d in remove_conflicts:
            if d in prev_conflicts:
                prev_conflicts.remove(d)
        dest_control.conflicts = u','.join(prev_conflicts)

        # change package name
        dest_control.package = newname
        if newversion:
            dest_control.version = newversion

        # Check existing versions of newname and increment it
        if auto_inc_version:
            older_packages = self.is_available(newname)
            if older_packages and dest_control<=older_packages[-1]:
                dest_control.version = older_packages[-1].version
                dest_control.inc_build()

        dest_control.filename = dest_control.make_package_filename()
        dest_control.save_control_to_wapt(target_directory)

        if dest_control.section != 'host':
            self.add_pyscripter_project(target_directory)
        dest_control.invalidate_signature()
        return dest_control

    def write_param(self,name,value):
        """Store in local db a key/value pair for later use"""
        self.waptdb.set_param(name,value)

    def set_package_attribute(self,package,key,value):
        """Store in local db a key/value pair for later use"""
        self.waptdb.set_param(package+'.'+key,value)

    def get_package_attribute(self,package,key,default_value=None):
        """Store in local db a key/value pair for later use"""
        return self.waptdb.get_param(package+'.'+key,default_value)

    def read_param(self,name,default=None,ptype=None):
        """read a param value from local db
        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> wapt.read_param('db_version')
        u'20140410'
        """
        return self.waptdb.get_param(name,default,ptype)

    def delete_param(self,name):
        """Remove a key from local db"""
        self.waptdb.delete_param(name)

    def dependencies(self,packagename,expand=False):
        """Return all dependecies of a given package
        >>> w = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> dep = w.dependencies('tis-waptdev')
        >>> isinstance(dep,list) and isinstance(dep[0],PackageEntry)
        True
        """
        packages = self.is_available(packagename)
        result = []
        errors = []
        if packages:
            depends = ensure_list(packages[-1].depends)
            for dep in depends:
                subpackages = self.is_available(dep)
                if subpackages:
                    if expand:
                        result.extend(self.dependencies(dep))
                    if not subpackages[-1] in result:
                        result.append(subpackages[-1])
                else:
                    errors.append(dep)

        return result

    def get_package_entries(self,packages_names):
        r"""Return most up to date packages entries for packages_names
        packages_names is either a list or a string.

        'missing' key lists the package requirements which are not available in the
        package index.

        Args;
            packages_names (list or str): list of package requirements

        Returns:
            dict : {'packages':[PackageEntries,],'missing':[str,]}

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> res = wapt.get_package_entries(['tis-firefox','tis-putty'])
        >>> isinstance(res['missing'],list) and isinstance(res['packages'][0],PackageEntry)
        True
        """
        result = {'packages':[],'missing':[]}
        if isinstance(packages_names,str) or isinstance(packages_names,unicode):
            packages_names=[ p.strip() for p in packages_names.split(",")]
        for package_name in packages_names:
            matches = self.waptdb.packages_matching(package_name)
            if matches:
                result['packages'].append(matches[-1])
            else:
                result['missing'].append(package_name)
        return result


    def network_reconfigure(self):
        """Called whenever the network configuration has changed
        """
        try:
            for repo in self.repositories:
                repo.reset_network()
            if not self.disable_update_server_status and self.waptserver_available():
                self.update_server_status()
        except Exception as e:
            logger.warning(u'WAPT was unable to reconfigure properly after network changes : %s'%ensure_unicode(e))

    def add_upgrade_shutdown_policy(self):
        """Add a local shitdown policy to upgrade system"""
        waptexit_path = setuphelpers.makepath(self.wapt_base_dir,'waptexit.exe')
        if not os.path.isfile(waptexit_path):
            raise Exception('Can not find %s'%waptexit_path)
        setuphelpers.shutdown_scripts_ui_visible(state=True)
        return setuphelpers.add_shutdown_script(waptexit_path,'')

    def remove_upgrade_shutdown_policy(self):
        """Add a local shitdown policy to upgrade system"""
        waptexit_path = setuphelpers.makepath(self.wapt_base_dir,'waptexit.exe')
        if not os.path.isfile(waptexit_path):
            raise Exception('Can not find %s'%waptexit_path)
        return setuphelpers.remove_shutdown_script(waptexit_path,'')


    def show_progress(self,show_box=False,msg='Loading...',progress = None,progress_max = None):
        """Global hook to report progress feedback to the user

        Args:
            show_box (bool): indicate to display or hide the notification
            msg (str): A status message to display. If None, nothing is changed.
            progress (float): Completion
            progress_max (float): Target of completion.

        """
        if self.progress_hook:
            return self.progress_hook(show_box,msg,progress,progress_max)  # pylint: disable=not-callable
        else:
            print(u'%s : %s / %s' % (msg,progress,progress_max))
            return False

    def get_secured_token_generator(self):
        return TimedJSONWebSignatureSerializer(self.get_token_secret_key(),expires_in=self.token_lifetime)

    def is_authorized_package_action(self,action,package,user_groups=[],rules=None):
        package_request = PackageRequest(package=package)
        if package_request.package in self.waptdb.installed_package_names() and action in ('install','upgrade'):
            return True

        upgrades_and_pending = [PackageRequest(pr).package for pr in self.get_last_update_status().get('upgrades',[])]
        if package_request.package in upgrades_and_pending and action in ('install','upgrade'):
            return True

        if not user_groups:
            return False

        if enterprise_common:
            if rules is None:
                rules = enterprise_common.self_service_rules(self)

            for group in user_groups:
                if package_request.package in rules.get(group,[]):
                    return True

        if 'waptselfservice' in user_groups:
            return True
            # return package_request.section not in ('restricted','wsus','unit','profile')

        return False

    def available_categories(self):
        return list(set([k.get('keywords').capitalize().split(',')[0] for k in self.waptdb.query('select distinct keywords from wapt_package where keywords is not null')]))


def check_user_authorisation_for_self_service(rules,packagename,user_groups):
    """Returns True if the user is allowed to install software based on their group and selfservice rules

    Args:
        rules (dict): dict rules with allowed groups for a package name
        packagename(str): name of the package the user wants to install
        listgroupuser(list): selfservice group list of the user

    Returns:
        boolean: True
    """
    if 'waptselfservice' in user_groups :
        return True
    if not packagename in rules:
        return False
    else:
        for group in user_groups :
            if group in rules[packagename]:
                return True
    return False

def wapt_sources_edit(wapt_sources_dir):
    """Utility to open Pyscripter with package source if it is installed
        else open the development directory in Shell Explorer.

    Args
        wapt_sources_dir (str): directory path of  teh wapt package sources

    Returns:
        str: sources path
    """
    wapt_sources_dir = ensure_unicode(wapt_sources_dir)
    psproj_filename = os.path.join(wapt_sources_dir,u'WAPT',u'wapt.psproj')
    control_filename = os.path.join(wapt_sources_dir,u'WAPT',u'control')
    setup_filename = os.path.join(wapt_sources_dir,u'setup.py')
    if os.name == 'nt':
        pyscripter_filename = os.path.join(setuphelpers.programfiles32,
                                           'PyScripter', 'PyScripter.exe')
        wapt_base_dir = os.path.dirname(__file__)
        env = os.environ
        env.update(dict(
            PYTHONHOME=wapt_base_dir,
            PYTHONPATH=wapt_base_dir,
            VIRTUAL_ENV=wapt_base_dir
            ))

        if os.path.isfile(pyscripter_filename) and os.path.isfile(psproj_filename):
            p = psutil.Popen((u'"%s" --PYTHONDLLPATH "%s" --python27 -N --project "%s" "%s" "%s"' % (
                            pyscripter_filename,
                            wapt_base_dir,
                            psproj_filename,
                            setup_filename,
                            control_filename)).encode(sys.getfilesystemencoding()),
                            cwd=wapt_sources_dir.encode(sys.getfilesystemencoding()),
                            env=env)
        else:
            os.startfile(wapt_sources_dir)
    else:
        if whichcraft.which('nano'):
            command = ['nano', setup_filename]
            subprocess.call(command)
        elif whichcraft.which('vim'):
            command = ['vim', setup_filename]
            subprocess.call(command)
    return wapt_sources_dir


def sid_from_rid(domain_controller, rid):
    """Return SID structure based on supplied domain controller's domain and supplied rid
    rid can be for example DOMAIN_GROUP_RID_ADMINS, DOMAIN_GROUP_RID_USERS
    """
    umi2 = win32net.NetUserModalsGet(domain_controller, 2)
    domain_sid = umi2['domain_id']

    sub_authority_count = domain_sid.GetSubAuthorityCount()

    # create and init new sid with acct domain Sid + acct rid
    sid = pywintypes.SID()
    sid.Initialize(domain_sid.GetSidIdentifierAuthority(),
                   sub_authority_count+1)

    # copy existing subauthorities from account domain Sid into
    # new Sid
    for i in range(sub_authority_count):
        sid.SetSubAuthority(i, domain_sid.GetSubAuthority(i))

    # append Rid to new Sid
    sid.SetSubAuthority(sub_authority_count, rid)
    return sid


def lookup_name_from_rid(domain_controller, rid):
    """ return username or group name from RID (with localization if applicable)
        from https://mail.python.org/pipermail/python-win32/2006-May/004655.html
        domain_controller : should be a DC
        rid : integer number (512 for domain admins, 513 for domain users, etc.)
    >>> lookup_name_from_rid('srvads', DOMAIN_GROUP_RID_ADMINS)
    u'Domain Admins'

    """
    sid = sid_from_rid(domain_controller,rid)
    name, domain, typ = win32security.LookupAccountSid(domain_controller, sid)
    return name


def get_domain_admins_group_name():
    r"""Return localized version of domain admin group (ie "domain admins" or
                 "administrateurs du domaine" with RID -512)

    >>> get_domain_admins_group_name()
    u'Domain Admins'
    """
    try:
        target_computer = win32net.NetGetAnyDCName ()
        name = lookup_name_from_rid(target_computer, DOMAIN_GROUP_RID_ADMINS)
        return name
    except Exception as e:
        logger.debug('Error getting Domain Admins group name : %s'%e)
        return 'Domain Admins'


def get_local_admins_group_name():
    sid = win32security.GetBinarySid('S-1-5-32-544')
    name, domain, typ = win32security.LookupAccountSid(setuphelpers.wincomputername(), sid)
    return name


def check_is_member_of(huser,group_name):
    """Check if a user is a member of a group

    Args:
        huser (handle) : pywin32
        group_name (str) : group

    >>> from win32security import LogonUser
    >>> hUser = win32security.LogonUser ('technique','tranquilit','xxxxxxx',win32security.LOGON32_LOGON_NETWORK,win32security.LOGON32_PROVIDER_DEFAULT)
    >>> check_is_member_of(hUser,'domain admins')
    False
    """
    try:
        sid, system, type = win32security.LookupAccountName(None,group_name)
    except:
        logger.debug('"%s" is not a valid group name'%group_name)
        return False
    return win32security.CheckTokenMembership(huser, sid)


def check_user_membership(user_name,password,domain_name,group_name):
    """Check if a user is a member of a group

    Args:
        user_name (str): user
        password (str):
        domain_name (str) : If empty, check local then domain
        group_name (str): group

    >>> from win32security import LogonUser
    >>> hUser = win32security.LogonUser ('technique','tranquilit','xxxxxxx',win32security.LOGON32_LOGON_NETWORK,win32security.LOGON32_PROVIDER_DEFAULT)
    >>> check_is_member_of(hUser,'domain admins')
    False
    """
    try:
        sid, system, type = win32security.LookupAccountName(None,group_name)
    except pywintypes.error as e:
        if e.args[0] == 1332:
            logger.warning(u'"%s" is not a valid group name' % group_name)
            return False
        else:
            raise
    huser = win32security.LogonUser(user_name,domain_name,password,win32security.LOGON32_LOGON_NETWORK,win32security.LOGON32_PROVIDER_DEFAULT)
    return win32security.CheckTokenMembership(huser, sid)

def is_between_two_times(time1,time2):
    time_now = datetime.datetime.now()
    time_nowHHMM = '%s:%s' % (time_now.hour,time_now.minute)
    if time2<time1:
        return time_nowHHMM>=time1 or time_nowHHMM<=time2
    else:
        return time1<=time_nowHHMM<=time2

# for backward compatibility
Version = setuphelpers.Version  # obsolete

if __name__ == '__main__':
    import doctest
    import sys
    reload(sys)
    sys.setdefaultencoding("UTF-8")
    import doctest
    doctest.ELLIPSIS_MARKER = '???'
    doctest.testmod(optionflags=doctest.ELLIPSIS)
    sys.exit(0)
