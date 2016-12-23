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
__version__ = "1.3.9"

import os
import re
import logging
import datetime
import time
import sys
import zipfile
from zipfile import ZipFile
import tempfile
import hashlib
import glob
import codecs
import sqlite3
import json
import StringIO
import requests

try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass

import fnmatch
import platform
import imp
import socket
import windnsquery
import copy
import getpass
import psutil
import threading
import traceback
import uuid

import random
import string

from waptpackage import *
import locale

import shlex
from iniparse import RawConfigParser
from optparse import OptionParser

from collections import namedtuple
from types import ModuleType

import shutil
import win32api
import ntsecuritycon
import win32security
import win32net
import pywintypes
from ntsecuritycon import SECURITY_NT_AUTHORITY,SECURITY_BUILTIN_DOMAIN_RID
from ntsecuritycon import DOMAIN_GROUP_RID_ADMINS,DOMAIN_GROUP_RID_USERS

import ctypes
from ctypes import wintypes

from urlparse import urlparse
try:
    from requests_kerberos import HTTPKerberosAuth,OPTIONAL
    has_kerberos = True
except:
    has_kerberos = False

from _winreg import HKEY_LOCAL_MACHINE,EnumKey,OpenKey,QueryValueEx,\
    EnableReflectionKey,DisableReflectionKey,QueryReflectionKey,\
    QueryInfoKey,DeleteValue,DeleteKey,\
    KEY_READ,KEY_WOW64_32KEY,KEY_WOW64_64KEY,KEY_ALL_ACCESS

import re
import struct
import types
import gc


from waptutils import *
from waptcrypto import *
import setuphelpers

logger = logging.getLogger()

ArchitecturesList = ('all','x86','x64')

def create_self_signed_key(orgname,
        wapt_base_dir=None,
        destdir='c:\\private',
        country='FR',
        locality=u'',
        organization=u'',
        unit='',
        commonname='',
        email='',
    ):
    ur"""Creates a self signed key/certificate without password using openssl.exe
    return a dict {'crt_filename': 'c:\\private\\test.crt', 'pem_filename': 'c:\\private\\test.pem'}
    >>> if os.path.isfile('c:/private/test.pem'):
    ...     os.unlink('c:/private/test.pem')
    >>> create_self_signed_key('test',organization='Tranquil IT',locality=u'St Sebastien sur Loire',commonname='wapt.tranquil.it',email='...@tranquil.it')
    {'crt_filename': 'c:\\private\\test.crt', 'pem_filename': 'c:\\private\\test.pem'}
    """
    if not wapt_base_dir:
        wapt_base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__)))

    destpem = os.path.join(destdir,'%s.pem' % orgname)
    destcrt = os.path.join(destdir,'%s.crt' % orgname)
    if os.path.isfile(destpem):
        raise Exception('Destination SSL key %s already exist' % destpem)
    if not os.path.isdir(destdir):
        os.makedirs(destdir)
    params = {
        'country':country,
        'locality':locality,
        'organization':organization,
        'unit':unit,
        'commonname':commonname,
        'email':email,
    }
    opensslbin = os.path.join(wapt_base_dir,'lib','site-packages','M2Crypto','openssl.exe')
    opensslcfg = codecs.open(os.path.join(wapt_base_dir,'templates','openssl_template.cfg'),'r',encoding='utf8').read() % params
    opensslcfg_fn = os.path.join(destdir,'openssl.cfg')
    codecs.open(opensslcfg_fn,'w',encoding='utf8').write(opensslcfg)
    os.environ['OPENSSL_CONF'] =  opensslcfg_fn
    out = setuphelpers.run(u'%(opensslbin)s req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout "%(destpem)s" -out "%(destcrt)s"' %
        {'opensslbin':opensslbin,'orgname':orgname,'destcrt':destcrt,'destpem':destpem})
    os.unlink(opensslcfg_fn)
    return {'pem_filename':destpem,'crt_filename':destcrt}



def create_recursive_zip(zipfn, source_root, target_root = u"",excludes = [u'.svn',u'.git',u'.gitignore',u'*.pyc',u'*.dbg',u'src']):
    """Create a zip file with filename zipf from source_root directory with target_root as new root.
       Don't include file which match excludes file pattern
    """
    result = []
    if not isinstance(source_root,unicode):
        source_root = unicode(source_root)
    if not isinstance(source_root,unicode):
        source_root = unicode(source_root)

    if isinstance(zipfn,str) or isinstance(zipfn,unicode):
        if logger: logger.debug(u'Create zip file %s' % zipfn)
        zipf = ZipFile(zipfn,'w',allowZip64=True,compression=zipfile.ZIP_DEFLATED)
    elif isinstance(zipfn,ZipFile):
        zipf = zipfn
    else:
        raise Exception('zipfn must be either a filename (string) or an ZipFile')
    for item in os.listdir(source_root):
        excluded = False
        for x in excludes:
            excluded = fnmatch.fnmatch(item,x)
            if excluded:
                break
        if excluded:
            continue
        source_item_fn = os.path.join(source_root, item)
        zip_item_fn = os.path.join(target_root,item)
        # exclude manifest and signature which are added afterward
        if zip_item_fn in ('WAPT\\manifest.sha1','WAPT\\signature'):
            continue
        if os.path.isfile(source_item_fn):
            if logger: logger.debug(u' adding file %s' % source_item_fn)
            zipf.write(source_item_fn, zip_item_fn)
            result.append(zip_item_fn)
        elif os.path.isdir(source_item_fn):
            if logger: logger.debug(u'Add directory %s' % source_item_fn)
            result.extend(create_recursive_zip(zipf, source_item_fn, zip_item_fn,excludes))
    if isinstance(zipfn,str) or isinstance(zipfn,unicode):
        if logger:
            logger.debug(u'  adding sha1 hash for all %i files' % len(result))
        zipf.close()
    return result


def import_code(code,name='',add_to_sys_modules=0):
    """
    Import dynamically generated code as a module. code is the
    object containing the code (a string, a file handle or an
    actual compiled code object, same types as accepted by an
    exec statement). The name is the name to give to the module,
    and the final argument says wheter to add it to sys.modules
    or not. If it is added, a subsequent import statement using
    name will return this module. If it is not added to sys.modules
    import will try to load it in the normal fashion.

    import foo

    is equivalent to

    foofile = open("/path/to/foo.py")
    foo = import_code(foofile,"foo",1)

    Returns a newly generated module.
    From : http://code.activestate.com/recipes/82234-importing-a-dynamically-generated-module/
    """
    import sys,imp

    if not name:
        name = '__waptsetup_%s__'%generate_unique_string()
        #name = '__waptsetup__'

    logger.debug('Import source code as %s'%(name))
    module = imp.new_module(name)

    exec(code, module.__dict__)
    if add_to_sys_modules:
        sys.modules[name] = module

    return module


def import_setup(setupfilename,modulename=''):
    """Import setupfilename as modulename, return the module object"""
    try:
        mod_name,file_ext = os.path.splitext(os.path.split(setupfilename)[-1])
        if not modulename:
            #modulename=mod_name
            modulename = '__waptsetup_%s__'%generate_unique_string()
        # can debug but keep module in memory
        logger.debug('Import source %s as %s'%(setupfilename,modulename))
        py_mod = imp.load_source(modulename, setupfilename)
        # can not debug but memory is not cumbered with setup.py modules
        #py_mod = import_code(codecs.open(setupfilename,'r').read(), modulename)
        return py_mod
    except Exception as e:
        logger.critical(u'Error importing %s :\n%s'%(setupfilename,ensure_unicode(traceback.format_exc())))
        raise

def remove_encoding_declaration(source):
    headers = source.split('\n',3)
    result = []
    for h in headers[0:3]:
        result.append(h.replace('coding:','coding is').replace('coding=','coding is'))
    result.extend(headers[3:])
    return "\n".join(result)


def is_system_user():
    return setuphelpers.get_current_user() == 'system'


def adjust_privileges():
    flags = ntsecuritycon.TOKEN_ADJUST_PRIVILEGES | ntsecuritycon.TOKEN_QUERY
    htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(),flags)

    privileges = [
        (win32security.LookupPrivilegeValue(None, 'SeSystemProfilePrivilege'), ntsecuritycon.SE_PRIVILEGE_ENABLED),
        (win32security.LookupPrivilegeValue(None, 'SeSecurityPrivilege'), ntsecuritycon.SE_PRIVILEGE_ENABLED),
        (win32security.LookupPrivilegeValue(None, 'SeRestorePrivilege'), ntsecuritycon.SE_PRIVILEGE_ENABLED),
        (win32security.LookupPrivilegeValue(None, 'SeBackupPrivilege'), ntsecuritycon.SE_PRIVILEGE_ENABLED),
        ]

    return win32security.AdjustTokenPrivileges(htoken, 0, privileges)


class SYSTEM_POWER_STATUS(ctypes.Structure):
    _fields_ = [
        ('ACLineStatus', wintypes.BYTE),
        ('BatteryFlag', wintypes.BYTE),
        ('BatteryLifePercent', wintypes.BYTE),
        ('Reserved1', wintypes.BYTE),
        ('BatteryLifeTime', wintypes.DWORD),
        ('BatteryFullLifeTime', wintypes.DWORD),
    ]

SYSTEM_POWER_STATUS_P = ctypes.POINTER(SYSTEM_POWER_STATUS)
GetSystemPowerStatus = ctypes.windll.kernel32.GetSystemPowerStatus
GetSystemPowerStatus.argtypes = [SYSTEM_POWER_STATUS_P]
GetSystemPowerStatus.restype = wintypes.BOOL

def running_on_ac():
    """Return True if computer is connected to AC power supply
    """
    status = SYSTEM_POWER_STATUS()
    if not GetSystemPowerStatus(ctypes.pointer(status)):
        raise ctypes.WinError()
    return status.ACLineStatus == 1


def uac_enabled():
    """Return True if UAC is enabled"""
    with setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') as k:
        return QueryValueEx(k,'EnableLUA')[1] == 0

###########################"
class LogInstallOutput(object):
    """file like to log print output to db installstatus"""
    def __init__(self,console,waptdb,rowid):
        self.output = []
        self.console = console
        self.waptdb = waptdb
        self.rowid = rowid
        self.threadid = threading.current_thread()
        self.lock = threading.RLock()

    def write(self,txt):
        with self.lock:
            txt = ensure_unicode(txt)
            try:
                self.console.write(txt)
            except:
                self.console.write(repr(txt))
            if txt != '\n':
                self.output.append(txt)
                if txt and txt[-1] != u'\n':
                    txtdb = txt+u'\n'
                else:
                    txtdb = txt
                if threading.current_thread() == self.threadid:
                    self.waptdb.update_install_status(self.rowid,'RUNNING',txtdb if not txtdb == None else None)

    def __getattrib__(self, name):
        if hasattr(self.console,'__getattrib__'):
            return self.console.__getattrib__(name)
        else:
            return self.console.__getattribute__(name)


##################
def ipv4_to_int(ipaddr):
    (a,b,c,d) = ipaddr.split('.')
    return (int(a) << 24) + (int(b) << 16) + (int(c) << 8) + int(d)


def same_net(ip1,ip2,netmask):
    """Given 2 ipv4 address and mask, return True if in same subnet"""
    return (ipv4_to_int(ip1) & ipv4_to_int(netmask)) == (ipv4_to_int(ip2) & ipv4_to_int(netmask))


def host_ipv4():
    """return a list of (iface,mac,{addr,broadcast,netmask})"""
    import netifaces
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


def tryurl(url,proxies=None,timeout=2,auth=None,verify_cert=False):
    try:
        logger.debug(u'  trying %s' % url)
        headers = requests.head(url,proxies=proxies,timeout=timeout,auth=auth,verify=verify_cert,headers=default_http_headers())
        if headers.ok:
            logger.debug(u'  OK')
            return True
        else:
            headers.raise_for_status()
    except Exception as e:
        logger.debug(u'  Not available : %s' % ensure_unicode(e))
        return False


def force_utf8_no_bom(filename):
    """Check if the file is encoded in utf8 readable encoding without BOM
         rewrite the file in place if not compliant.
    """
    BUFSIZE = 4096
    BOMLEN = len(codecs.BOM_UTF8)

    content = open(filename, mode='rb').read(BOMLEN)
    if content.startswith(codecs.BOM_UTF8):
        content = open(filename,'rb').read()
        open(filename, mode='wb').write(content[BOMLEN:])
    else:
        try:
            content = codecs.open(filename, encoding='utf8').read()
        except:
            content = codecs.open(filename, encoding='iso8859-15').read()
            codecs.open(filename, mode='wb', encoding='utf8').write(content)


class EWaptCancelled(Exception):
    pass


class WaptBaseDB(object):
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
        self.begin()
        #logger.debug(u'DB enter %i' % self.transaction_depth)
        return self

    def __exit__(self, type, value, tb):
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

    def set_param(self,name,value):
        """Store permanently a (name/value) pair in database, replace existing one"""
        with self:
            self.db.execute('insert or replace into wapt_params(name,value,create_date) values (?,?,?)',(name,value,datetime2isodate()))

    def get_param(self,name,default=None):
        """Retrieve the value associated with name from database"""
        q = self.db.execute('select value from wapt_params where name=? order by create_date desc limit 1',(name,)).fetchone()
        if q:
            return q[0]
        else:
            return default

    def delete_param(self,name):
        with self:
            self.db.execute('delete from wapt_params where name=?',(name,))

    def query(self,query, args=(), one=False):
        """
        execute la requete query sur la db et renvoie un tableau de dictionnaires
        """
        cur = self.db.execute(query, args)
        rv = [dict((cur.description[idx][0], value)
                   for idx, value in enumerate(row)) for row in cur.fetchall()]
        return (rv[0] if rv else None) if one else rv


    def upgradedb(self,force=False):
        """Update local database structure to current version if rules are described in db_upgrades"""
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
    curr_db_version = '20161103'

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
        create table if not exists wapt_params (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name  varchar(64),
          value text,
          create_date varchar(255)
          ) """)

        self.db.execute("""
          create unique index if not exists idx_params_name on wapt_params(name);
          """)
        self.db_version = self.curr_db_version
        return self.curr_db_version

    def add_start_install(self,package,version,architecture):
        """Register the start of installation in local db
        """
        with self:
            cur = self.db.execute("""delete from wapt_sessionsetup where package=?""" ,(package,))
            cur = self.db.execute("""\
                  insert into wapt_sessionsetup (
                    username,
                    package,
                    version,
                    architecture,
                    install_date,
                    install_status,
                    install_output,
                    process_id
                    ) values (?,?,?,?,?,?,?,?)
                """,(
                     self.username,
                     package,
                     version,
                     architecture,
                     datetime2isodate(),
                     'INIT',
                     '',
                     os.getpid()
                   ))
            return cur.lastrowid

    def update_install_status(self,rowid,install_status,install_output):
        """Update status of package installation on localdb"""
        with self:
            if install_status in ('OK','ERROR'):
                pid = None
            else:
                pid = os.getpid()
            cur = self.db.execute("""\
                  update wapt_sessionsetup
                    set install_status=?,install_output = install_output || ?,process_id=?
                    where rowid = ?
                """,(
                     install_status,
                     install_output,
                     pid,
                     rowid,
                     )
                   )
            return cur.lastrowid

    def update_install_status_pid(self,pid,install_status='ERROR'):
        """Update status of package installation on localdb"""
        with self:
            cur = self.db.execute("""\
                  update wapt_sessionsetup
                    set install_status=? where process_id = ?
                """,(
                     install_status,
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


PackageKey = namedtuple('package',('packagename','version'))

class WaptDB(WaptBaseDB):
    """Class to manage SQLite database with local installation status"""

    curr_db_version = '20161109'

    def initdb(self):
        """Initialize current sqlite db with empty table and return structure version"""
        assert(isinstance(self.db,sqlite3.Connection))
        logger.debug(u'Initialize Wapt database')
        self.db.execute("""
        create table if not exists wapt_package (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          package varchar(255),
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
          min_wapt_version varchar(255),
          maturity varchar(255),
          locale varchar(255)
        )"""
                        )
        self.db.execute("""
        create index if not exists idx_package_name on wapt_package(package);""")

        self.db.execute("""
        create table if not exists wapt_localstatus (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          package varchar(255),
          version varchar(255),
          version_pinning varchar(255),
          explicit_by varchar(255),
          architecture varchar(255),
          maturity varchar(255),
          locale varchar(255),
          install_date varchar(255),
          install_status varchar(255),
          install_output TEXT,
          install_params VARCHAR(800),
          uninstall_string varchar(255),
          uninstall_key varchar(255),
          setuppy TEXT,
          process_id integer
          )"""
                        )
        self.db.execute("""
        create index if not exists idx_localstatus_name on wapt_localstatus(package);""")

        self.db.execute("""
        create table if not exists wapt_params (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name  varchar(64),
          value text,
          create_date varchar(255)
          ) """)

        self.db.execute("""
          create unique index if not exists idx_params_name on wapt_params(name);
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

    def add_package(self,
                    package='',
                    version='',
                    section='',
                    priority='',
                    architecture='',
                    maintainer='',
                    description='',
                    filename='',
                    size='',
                    md5sum='',
                    depends='',
                    conflicts='',
                    sources='',
                    repo_url='',
                    repo='',
                    signer='',
                    signer_fingerprint='',
                    maturity='',
                    locale='',
                    signature='',
                    signature_date='',
                    min_wapt_version=''
                    ):

        with self:
            cur = self.db.execute("""\
                  insert into wapt_package (
                    package,
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
                    min_wapt_version
                    ) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,(
                     package,
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
                     min_wapt_version,
                     )
                   )
            return cur.lastrowid

    def add_package_entry(self,package_entry):
        cur = self.db.execute("""delete from wapt_package where package=? and version=? and architecture=? and maturity=? and locale=?""" ,
            (package_entry.package,package_entry.version,package_entry.architecture,package_entry.maturity,package_entry.locale))

        with self:
            self.add_package(package=package_entry.package,
                             version=package_entry.version,
                             section=package_entry.section,
                             priority=package_entry.priority,
                             architecture=package_entry.architecture,
                             maintainer=package_entry.maintainer,
                             description=package_entry.description,
                             filename=package_entry.filename,
                             size=package_entry.size,
                             md5sum=package_entry.md5sum,
                             depends=package_entry.depends,
                             conflicts=package_entry.conflicts,
                             sources=package_entry.sources,
                             repo_url=package_entry.repo_url,
                             repo=package_entry.repo,
                             signer=package_entry.signer,
                             signer_fingerprint=package_entry.signer_fingerprint,
                             maturity=package_entry.maturity,
                             locale=package_entry.locale,
                             signature=package_entry.signature,
                             signature_date=package_entry.signature_date,
                             min_wapt_version=package_entry.min_wapt_version,
                             )

    def add_start_install(self,package,version,architecture,params_dict={},explicit_by=None,maturity='',locale=''):
        """Register the start of installation in local db
            params_dict is the dictionary pf parameters provided on command line with --params
              or by the server
            explicit_by : username of initiator of the install.
                          if not None, install is not a dependencie but an explicit manual install
            setuppy is the python source code used for install, uninstall or session_setup
              code used for uninstall or session_setup must use only wapt self library as
              package content is not longer available at this step.
        """
        with self:
            cur = self.db.execute("""delete from wapt_localstatus where package=?""" ,(package,))
            cur = self.db.execute("""\
                  insert into wapt_localstatus (
                    package,
                    version,
                    architecture,
                    install_date,
                    install_status,
                    install_output,
                    install_params,
                    explicit_by,
                    process_id,
                    maturity,
                    locale
                    ) values (?,?,?,?,?,?,?,?,?,?,?)
                """,(
                     package,
                     version,
                     architecture,
                     datetime2isodate(),
                     'INIT',
                     '',
                     json.dumps(params_dict),
                     explicit_by,
                     os.getpid(),
                     maturity,
                     locale
                   ))
            return cur.lastrowid

    def update_install_status(self,rowid,install_status,install_output,uninstall_key=None,uninstall_string=None):
        """Update status of package installation on localdb"""
        with self:
            if install_status in ('OK','ERROR'):
                pid = None
            else:
                pid = os.getpid()
            cur = self.db.execute("""\
                  update wapt_localstatus
                    set install_status=?,install_output = install_output || ?,uninstall_key=?,uninstall_string=?,process_id=?
                    where rowid = ?
                """,(
                     install_status,
                     install_output,
                     uninstall_key,
                     uninstall_string,
                     pid,
                     rowid,
                     )
                   )
            return cur.lastrowid

    def update_install_status_pid(self,pid,install_status='ERROR'):
        """Update status of package installation on localdb"""
        with self:
            cur = self.db.execute("""\
                  update wapt_localstatus
                    set install_status=? where process_id = ?
                """,(
                     install_status,
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
                     json.dumps(install_params),
                     rowid,
                     )
                   )
            return cur.lastrowid

    def remove_install_status(self,package):
        """Remove status of package installation from localdb"""
        with self:
            cur = self.db.execute("""delete from wapt_localstatus where package=?""" ,(package,))
            return cur.rowcount

    def known_packages(self):
        """return a list of all (package,version)"""
        q = self.db.execute("""\
              select distinct wapt_package.package,wapt_package.version from wapt_package
           """)
        return [PackageKey(*e) for e in q.fetchall()]

    def packages_matching(self,package_cond):
        """Return an ordered list of available packages entries which match
            the condition "packagename[([=<>]version)]?"
            version ascending
        """
        pcv_match = REGEX_PACKAGE_CONDITION.match(package_cond)
        if pcv_match:
            pcv = pcv_match.groupdict()
            q = self.query_package_entry("""\
                  select * from wapt_package where package = ?
               """, (pcv['package'],))
            result = [ p for p in q if p.match(package_cond)]
            result.sort()
            return result
        else:
            return []

    def packages_search(self,searchwords=[],exclude_host_repo=True,section_filter=None):
        """Return a list of package entries matching the search words"""
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

        result = self.query_package_entry(u"select * from wapt_package where %s" % " and ".join(search),words)
        result.sort()
        return result

    def installed(self,include_errors=False):
        """Return a dictionary of installed packages : keys=package, values = PackageEntry """
        sql = ["""\
              select l.package,l.version,l.architecture,l.install_date,l.install_status,l.install_output,l.install_params,l.explicit_by,
                r.section,r.priority,r.maintainer,r.description,r.depends,r.conflicts,r.sources,r.filename,r.size,
                r.repo_url,r.md5sum,r.repo,l.maturity,l.locale
                from wapt_localstatus l
                left join wapt_package r on r.package=l.package and l.version=r.version and
                    (l.architecture is null or l.architecture=r.architecture) and
                    (l.maturity is null or l.maturity=r.maturity) and
                    (l.locale is null or l.locale=r.locale)
           """]
        if not include_errors:
            sql.append('where l.install_status in ("OK","UNKNOWN")')

        q = self.query_package_entry('\n'.join(sql))
        result = {}
        for p in q:
            result[p.package]= p
        return result

    def install_status(self,id):
        """Return a PackageEntry of the local install status for id"""
        sql = ["""\
              select l.package,l.version,l.architecture,l.install_date,l.install_status,l.install_output,l.install_params,l.explicit_by,l.setuppy,
                r.section,r.priority,r.maintainer,r.description,r.depends,r.conflicts,r.sources,r.filename,r.size,
                r.repo_url,r.md5sum,r.repo,l.maturity,l.locale
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
        """Return a list of installed package entries based on search keywords"""
        if not isinstance(searchwords,list) and not isinstance(searchwords,tuple):
            searchwords = [searchwords]
        if not searchwords:
            words = []
            search = ['1=1']
        else:
            words = [ "%"+w.lower()+"%" for w in searchwords ]
            search = ["lower(l.package || (case when r.description is NULL then '' else r.description end) ) like ?"] *  len(words)
        if not include_errors:
            search.append('l.install_status in ("OK","UNKNOWN")')
        q = self.query_package_entry("""\
              select l.package,l.version,l.architecture,l.install_date,l.install_status,l.install_output,l.install_params,l.explicit_by,
                r.section,r.priority,r.maintainer,r.description,r.depends,r.conflicts,r.sources,r.filename,r.size,
                r.repo_url,r.md5sum,r.repo
                 from wapt_localstatus l
                left join wapt_package r on r.package=l.package and l.version=r.version and (l.architecture is null or l.architecture=r.architecture)
              where %s
           """ % " and ".join(search),words)
        return q

    def installed_matching(self,package_cond,include_errors=False):
        """Return True if one properly installed (if include_errors=False) package match the package condition 'tis-package (>=version)' """
        package = REGEX_PACKAGE_CONDITION.match(package_cond).groupdict()['package']
        if include_errors:
            status = '"OK","UNKNOWN","ERROR"'
        else:
            status = '"OK","UNKNOWN"'

        q = self.query_package_entry("""\
              select l.package,l.version,l.architecture,l.install_date,l.install_status,l.install_output,l.install_params,l.setuppy,l.explicit_by,
                r.section,r.priority,r.maintainer,r.description,r.depends,r.conflicts,r.sources,r.filename,r.size,
                r.repo_url,r.md5sum,r.repo
                from wapt_localstatus l
                left join wapt_package r on r.package=l.package and l.version=r.version and (l.architecture is null or l.architecture=r.architecture)
              where l.package=? and l.install_status in (%s)
           """ % status,(package,))
        return q[0] if q and q[0].match(package_cond) else None

    def upgradeable(self,include_errors=True):
        """Return a dictionary of upgradable Package entries"""
        result = {}
        allinstalled = self.installed(include_errors=True).values()
        for p in allinstalled:
            available = self.query_package_entry("""select * from wapt_package where package=?""",(p.package,))
            available.sort()
            available.reverse()
            if available and (available[0] > p) or (include_errors and (p.install_status == 'ERROR')):
                result[p.package] = available
        return result

    def update_repos_list(self,repos_list,proxies=None,force=False,public_certs=[],filter_on_host_cap=True):
        """update the packages database with Packages files from the url repos_list
            removes obsolete records for repositories which are no more referenced
            repos_list : list of all the repositories objects referenced by the system
                          as returned by Wapt.repositories
            force : update repository even if date of packages index is same as
                    last retrieved date
            public_certs :
        return a dictionary of update_db results for each repository name
            which has been accessed.
        >>> wapt = Wapt(config_filename = 'c:/tranquilit/wapt/tests/wapt-get.ini' )
        >>> res = wapt.waptdb.update_repos_list(wapt.repositories)
        """
        with self:
            result = {}
            logger.debug(u'Remove unknown repositories from packages table and params (%s)' %(','.join('"%s"'% r.name for r in repos_list),)  )
            self.db.execute('delete from wapt_package where repo not in (%s)' % (','.join('"%s"'% r.name for r in repos_list)))
            self.db.execute('delete from wapt_params where name like "last-http%%" and name not in (%s)' % (','.join('"last-%s"'% r.repo_url for r in repos_list)))
            self.db.execute('delete from wapt_params where name like "last-url-%%" and name not in (%s)' % (','.join('"last-url-%s"'% r.name for r in repos_list)))
            for repo in repos_list:
                logger.info(u'Getting packages from %s' % repo.repo_url)
                try:
                    result[repo.name] = repo.update_db(waptdb=self,force=force,public_certs=public_certs,filter_on_host_cap=filter_on_host_cap)
                except Exception as e:
                    logger.warning(u'Error getting Packages index from %s : %s' % (repo.repo_url,ensure_unicode(e)))
        return result

    def build_depends(self,packages):
        """Given a list of packages conditions (packagename (optionalcondition))
            return a list of dependencies (packages conditions) to install
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

        def dodepends(explored,packages,depth,missing):
            if depth>MAXDEPTH:
                raise Exception.create('Max depth in build dependencies reached, aborting')
            alldepends = []
            # loop over all package names
            for package in packages:
                if not package in explored:
                    entries = self.packages_matching(package)
                    if not entries:
                        missing.append(package)
                    else:
                        # get depends of the most recent matching entry
                        # TODO : use another older if this can limit the number of packages to install !
                        depends =  ensure_list(entries[-1].depends)
                        available_depends = []
                        for d in depends:
                            if self.packages_matching(d):
                                available_depends.append(d)
                            else:
                                missing.append(d)
                        alldepends.extend(dodepends(explored,available_depends,depth+1,missing))
                        for d in available_depends:
                            if not d in alldepends:
                                alldepends.append(d)
                    explored.append(package)
            return alldepends

        missing = []
        explored = []
        depth = 0
        alldepends = dodepends(explored,packages,depth,missing)
        return (alldepends,missing)

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

    def query_package_entry(self,query, args=(), one=False):
        """
        execute la requete query sur la db et renvoie un tableau de PackageEntry
        Le matching est fait sur le nom de champs.
            Les champs qui ne matchent pas un attribut de PackageEntry
                sont également mis en attributs !
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
                    pe.calculated_attributes.append(k)
            result.append(pe)
        if one and result:
            result = sorted(result)[-1]
        return result

    def purge_repo(self,repo_name):
        """remove references to repo repo_name
        >>> waptdb = WaptDB('c:/wapt/db/waptdb.sqlite')
        >>> waptdb.purge_repo('main')
        """
        with self:
            self.db.execute('delete from wapt_package where repo=?',(repo_name,))

def get_pem_server_certificate(url):
    """Retrieve certificate for further checks"""
    url = urlparse(url)
    if url.scheme == 'https':
        context = SSL.Context();
        context.set_allow_unknown_ca(True)
        context.set_verify(SSL.verify_none, True)
        conn = SSL.Connection(context)
        # try a connection to get server certificate
        conn.connect((url.hostname, url.port or 443))
        cert_chain = conn.get_peer_cert_chain()
        return "\n".join(
            ["""\
# Issuer: %s
# Subject: %s
%s
""" % (c.get_issuer().as_text(),c.get_subject().as_text(),c.as_pem() )for c in cert_chain])
    else:
        return None


class WaptServer(object):
    """Manage connection to waptserver"""

    def __init__(self,url=None,proxies={'http':None,'https':None},timeout = 2,dnsdomain=None):
        if url and url[-1]=='/':
            url = url.rstrip('/')
        self._server_url = url
        self._cached_dns_server_url = None

        self.proxies=proxies
        self.timeout = timeout
        self.use_kerberos = False
        self.verify_cert = False

        if dnsdomain:
            self.dnsdomain = dnsdomain
        else:
            self.dnsdomain = setuphelpers.get_domain_fromregistry()

    def auth(self):
        if self._server_url:
            scheme = urlparse(self._server_url).scheme
            if scheme == 'https' and has_kerberos and self.use_kerberos:
                return HTTPKerberosAuth(mutual_authentication=OPTIONAL)
                # TODO : simple auth if kerberos is not available...
            else:
                return None
        else:
            return None


    def save_server_certificate(self,server_dir=None):
        """Retrieve certificate of https server for further checks"""
        pem = get_pem_server_certificate(self.server_url)
        if pem:
            url = urlparse(self.server_url)
            if isinstance(self.verify_cert,str) or isinstance(self.verify_cert,unicode):
                pem_fn = self.verify_cert
            else:
                pem_fn = os.path.join(server_dir,url.hostname+'.crt')
            if not os.path.isdir(server_dir):
                os.makedirs(server_dir)
            open(pem_fn,'wb').write(pem)
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
                # find by dns SRV _wapt._tcp
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

            self.use_kerberos = config.has_option(section,'use_kerberos') and \
                            config.getboolean(section,'use_kerberos')

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
                    if not os.path.isfile(self.verify_cert):
                        logger.warning(u'waptserver certificate %s declared in configuration file can not be found. Waptserver communication will fail' % self.verify_cert)
            else:
                self.verify_cert = False


        return self

    def get(self,action,auth=None,timeout=None):
        """ """
        surl = self.server_url
        if surl:
            req = requests.get("%s/%s" % (surl,action),proxies=self.proxies,verify=self.verify_cert,timeout=timeout or self.timeout,auth=auth or self.auth(),headers=default_http_headers())
            req.raise_for_status()
            return json.loads(req.content)
        else:
            raise Exception(u'Wapt server url not defined or not found in DNS')

    def post(self,action,data=None,files=None,auth=None,timeout=None):
        """ """
        surl = self.server_url
        if surl:
            headers = default_http_headers()
            if data:
                headers.update({
                    'Content-type': 'binary/octet-stream',
                    'Content-transfer-encoding': 'binary',
                    })
            req = requests.post("%s/%s" % (surl,action),data=data,files=files,proxies=self.proxies,verify=self.verify_cert,timeout=timeout or self.timeout,auth=auth or self.auth(),headers=headers)
            req.raise_for_status()
            return json.loads(req.content)
        else:
            raise Exception(u'Wapt server url not defined or not found in DNS')

    def available(self):
        try:
            if self.server_url:
                req = requests.head("%s" % (self.server_url),proxies=self.proxies,verify=self.verify_cert,timeout=self.timeout,auth=self.auth(),headers=default_http_headers())
                req.raise_for_status()
                return True
            else:
                logger.debug(u'Wapt server is unavailable because no URL is defined')
                return False
        except Exception as e:
            logger.debug(u'Wapt server %s unavailable because %s'%(self._server_url,ensure_unicode(e)))
            return False

    def as_dict(self):
        result = {}
        attributes = ['server_url','proxies','dnsdomain']
        for att in attributes:
            result[att] = getattr(self,att)
        return result

    def upload_package(self,package,auth=None,timeout=None):
        """ """
        if not (isinstance(package,(str,unicode)) and os.path.isfile(package)) and not isinstance(package,PackageEntry):
            raise Exception('Package %s is not found.')

        if not isinstance(package,PackageEntry):
            pe = PackageEntry().load_control_from_wapt(package)
            package_filename = package
        else:
            pe = package
            package_filename = pe.wapt_fullpath()

        with open(package_filename,'rb') as afile:
            res = json.loads(self.post('api/v1/upload_package?filename=%s' % os.path.basename(package_filename),data=afile,auth=auth,timeout=timeout))
        if not res['success']:
            raise Exception(u'Unable to upload package: %s'%ensure_unicode(res['msg']))

    def __repr__(self):
        try:
            return '<WaptServer %s>' % self.server_url
        except:
            return '<WaptServer %s>' % 'unknown'


class WaptRepo(WaptRemoteRepo):
    """Gives access to a remote http repository, with a zipped Packages packages index

    >>> repo = WaptRepo(name='main',url='http://wapt/wapt',timeout=4)
    >>> packages = repo.packages()
    >>> len(packages)
    """

    def __init__(self,url=None,name='',proxies={'http':None,'https':None},timeout = 2,dnsdomain=None):
        """Initialize a repo at url "url".

        Args:
            name (str): internal local name of this repository
            url  (str): http URL to the repository.
                 If url is None, the url is requested from DNS by a SRV query
            proxies (dict): configuration of http proxies as defined for requests
            timeout (float): timeout in seconds for the connection to the rmeote repository
            dnsdomain (str): DNS domain to use for autodiscovery of URL if url is not supplied.
        """

        WaptRemoteRepo.__init__(self,url=url,name=name,proxies=proxies,timeout=timeout)
        self._cached_dns_repo_url = None
        self._dnsdomain = dnsdomain

    def reset_network(self):
        """called by wapt when network configuration has changed"""
        self._cached_dns_repo_url = None
        self._packages = None
        self._packages_date = None

    @property
    def dnsdomain(self):
        return self._dnsdomain

    @dnsdomain.setter
    def dnsdomain(self,value):
        if value != self._dnsdomain:
            self._dnsdomain = value
            self._cached_dns_repo_url = None

    @property
    def repo_url(self):
        """Repository URL

        Fixed url if any, else request DNS with a SRV _wapt._tcp.domain query
         or a CNAME by the find_wapt_repo_url method.

        The URL is queried once and then cached into a local property.

        Returns:
            str: url to the repository

        >>> repo = WaptRepo(name='main',timeout=4)
        >>> print repo.dnsdomain
        tranquilit.local
        >>> repo = WaptRepo(name='main',timeout=4)
        >>> print repo.dnsdomain
        tranquilit.local
        >>> print repo.repo_url
        http://srvwapt.tranquilit.local/wapt
        """
        if self._repo_url:
            return self._repo_url
        else:
            if not self._cached_dns_repo_url and self.dnsdomain:
                self._cached_dns_repo_url = self.find_wapt_repo_url()
            elif not self.dnsdomain:
                raise Exception('No dnsdomain defined for repo %s'%self.name)
            return self._cached_dns_repo_url

    @repo_url.setter
    def repo_url(self,value):
        if value:
            value = value.rstrip('/')

        if value != self._repo_url:
            self._repo_url = value
            self._packages = None
            self._packages_date = None
            self._cached_dns_repo_url = None


    def find_wapt_repo_url(self):
        """Search the nearest working main WAPT repository given the following priority
           - URL defined in ini file
           - first SRV record in the same network as one of the connected network interface
           - first SRV record with the highest weight
           - wapt CNAME in the local dns domain (https first then http)

        preference for SRV records is :
           same subnet -> priority asc -> weight desc


        >>> repo = WaptRepo(name='main',dnsdomain='tranquil.it',timeout=4,url=None)
        >>> repo.repo_url
        'http://wapt.tranquil.it./wapt'
        >>> repo = WaptRepo(name='main',url='http://wapt/wapt',timeout=4)
        >>> repo.repo_url
        'http://wapt/wapt'
        """

        try:
            local_ips = socket.gethostbyname_ex(socket.gethostname())[2]
            logger.debug(u'All interfaces : %s' % [ "%s/%s" % (i['addr'],i['netmask']) for i in host_ipv4() if 'addr' in i and 'netmask' in i])
            connected_interfaces = [ i for i in host_ipv4() if 'addr' in i and 'netmask' in i and i['addr'] in local_ips ]
            logger.debug(u'Local connected IPs: %s' % [ "%s/%s" % (i['addr'],i['netmask']) for i in connected_interfaces])

            def is_inmysubnets(ip):
                """Return True if IP is in one of my connected subnets

                Returns:
                    boolean: True if ip is in one of my local connected interfaces subnets
                """
                for i in connected_interfaces:
                    if same_net(i['addr'],ip,i['netmask']):
                        logger.debug(u'  %s is in same subnet as %s/%s local connected interface' % (ip,i['addr'],i['netmask']))
                        return True
                return False

            if self.dnsdomain and self.dnsdomain != '.':
                # find by dns SRV _wapt._tcp
                try:
                    logger.debug(u'Trying _wapt._tcp.%s SRV records' % self.dnsdomain)
                    answers = windnsquery.dnsquery_srv('_wapt._tcp.%s' % self.dnsdomain)

                    # list of (outside,priority,weight,url)
                    servers = []
                    for (priority,weight,wapthost,port) in answers:
                        # get first numerical ipv4 from SRV name record
                        try:
                            ips = windnsquery.dnsquery_a(wapthost)
                            if not ips:
                                logger.debug('DNS Name %s is not resolvable' % wapthost)
                            else:
                                ip = ips[0]
                                if port == 80:
                                    url = 'http://%s/wapt' % (wapthost,)
                                    servers.append([not is_inmysubnets(ip),priority,-weight,url])
                                elif a.port == 443:
                                    url = 'https://%s/wapt' % (wapthost)
                                    servers.append([not is_inmysubnets(ip),priority,-weight,url])
                                else:
                                    url = 'http://%s:%i/wapt' % (wapthost,port)
                                    servers.append([not is_inmysubnets(ip),priority,-weight,url])
                        except Exception as e:
                            logging.debug('Unable to resolve %s : error %s' % (wapthost,ensure_unicode(e),))

                    servers.sort()
                    for (outside,priority,weight,url) in servers:
                        if tryurl(url+'/Packages',timeout=self.timeout,proxies=self.proxies):
                            return url

                    if not answers:
                        logger.debug(u'  No _wapt._tcp.%s SRV record found' % self.dnsdomain)

                except Exception as e:
                    logger.debug(u'  DNS resolver exception: %s' % (ensure_unicode(e),))
                    raise

                # find by dns CNAME
                try:
                    logger.debug(u'Trying wapt.%s CNAME records' % self.dnsdomain)
                    answers = windnsquery.dnsquery_cname('wapt.%s' % self.dnsdomain)
                    # list of (outside,priority,weight,url)
                    servers = []

                    for wapthost in answers:
                        url = 'https://%s/wapt' % (wapthost,)
                        if tryurl(url+'/Packages',timeout=self.timeout,proxies=self.proxies):
                            return url
                        url = 'http://%s/wapt' % (wapthost,)
                        if tryurl(url+'/Packages',timeout=self.timeout,proxies=self.proxies):
                            return url
                    if not answers:
                        logger.debug(u'  No working wapt.%s CNAME record found' % self.dnsdomain)

                except Exception as e:
                    logger.debug(u'  DNS error: %s' % (ensure_unicode(e),))
                    raise

                # find by dns A
                try:
                    wapthost = 'wapt.%s.' % self.dnsdomain
                    logger.debug(u'Trying %s A records' % wapthost)
                    answers = windnsquery.dnsquery_a(wapthost)
                    if answers:
                        url = 'https://%s/wapt' % (wapthost,)
                        if tryurl(url+'/Packages',timeout=self.timeout,proxies=self.proxies):
                            return url
                        url = 'http://%s/wapt' % (wapthost,)
                        if tryurl(url+'/Packages',timeout=self.timeout,proxies=self.proxies):
                            return url
                    if not answers:
                        logger.debug(u'  No %s A record found' % wapthost)

                except Exception as e:
                    logger.debug(u'  DNS resolver exception: %s' % (ensure_unicode(e),))
                    raise

            else:
                logger.warning(u'Local DNS domain not found, skipping SRV _wapt._tcp and CNAME search ')

            return None
        except Exception as e:
            logger.debug(u'Waptrepo.find_wapt_repo_url: exception: %s' % (e,))
            raise

    def update_db(self,force=False,waptdb=None,public_certs=[],filter_on_host_cap=True):
        """Get Packages from http repo and update local package database
            return last-update header

        The local status DB is updated. Date of index is stored in params table
          for further checks.

        Args:
            force (bool): get index from remote repo even if creation date is not newer
                          than the datetime stored in local status database
            waptdb (WaptDB): instance of Wapt status database.
            public_certs (list) :

        Returns:
            isodatetime: date of Packages index

        >>> import common
        >>> repo = common.WaptRepo('main','http://wapt/wapt')
        >>> localdb = common.WaptDB('c:/wapt/db/waptdb.sqlite')
        >>> last_update = repo.is_available()
        >>> repo.update_db(waptdb=localdb) == last_update
        True
        """

        result = None
        last_modified = waptdb.get_param('last-%s'%(self.repo_url[:59]))
        last_url = waptdb.get_param('last-url-%s' % self.name)

        # Check if updated
        if force or self.repo_url != last_url or self.need_update(last_modified):
            old_packages = self._packages
            old_packages_date = self._packages_date
            os_version = setuphelpers.windows_version()

            with waptdb:
                try:
                    logger.debug(u'Read remote Packages index file %s' % self.packages_url)
                    last_modified = self.packages_date

                    self._packages = None
                    self._packages_date = None

                    waptdb.purge_repo(self.name)
                    for package in self.packages:
                        if filter_on_host_cap:
                            if package.min_wapt_version and Version(package.min_wapt_version)>Version(setuphelpers.__version__):
                                logger.debug('Skipping package %s, requires a newer Wapt agent. Minimum version: %s' % (package.asrequirement(),package.min_wapt_version))
                                continue
                            if package.min_os_version and os_version < Version(package.min_os_version):
                                logger.debug('Discarding package %s, requires OS version > %s' % (package.asrequirement(),package.min_os_version))
                                continue
                            if package.max_os_version and os_version > Version(package.max_os_version):
                                logger.debug('Discarding package %s, requires OS version < %s' % (package.asrequirement(),package.max_os_version))
                                continue
                            if package.architecture == 'x64' and not setuphelpers.iswin64():
                                logger.debug('Discarding package %s, requires OS with x64 architecture' % (package.asrequirement(),))
                                continue

                        try:
                            package.check_control_signature(public_certs)
                            waptdb.add_package_entry(package)
                        except:
                            logger.critical('Invalid signature for package control entry %s on repo %s : discarding' % (package.asrequirement(),self.name) )

                    logger.debug(u'Storing last-modified header for repo_url %s : %s' % (self.repo_url,self.packages_date))
                    waptdb.set_param('last-%s' % self.repo_url[:59],self.packages_date)
                    waptdb.set_param('last-url-%s' % self.name, self.repo_url)
                    return last_modified
                except Exception as e:
                    logger.info(u'Unable to update repository status of %s, error %s'%(self._repo_url,e))
                    self._packages = old_packages
                    self._packages_date = old_packages_date
                    raise
        else:
            return waptdb.get_param('last-%s' % self.repo_url[:59])


    def load_config(self,config,section=None):
        """Load waptrepo configuration from inifile section.
                Use name of repo as section name if section is not provided.
                Use 'global' if no section named section in ini file
        """
        if not section:
             section = self.name
        if not config.has_section(section):
            section = 'global'
        WaptRemoteRepo.load_config(self,config,section)
        if config.has_section(section) and config.has_option(section,'dnsdomain'):
            self.dnsdomain = config.get(section,'dnsdomain')
        return self

    def as_dict(self):
        result = {
            'name':self.name,
            'repo_url':self._repo_url or self._cached_dns_repo_url,
            'proxies':self.proxies,
            'dnsdomain':self.dnsdomain,
            'timeout':self.timeout,
            }
        return result

    def __repr__(self):
        try:
            return '<WaptRepo %s for domain %s>' % (self.repo_url,self.dnsdomain)
        except:
            return '<WaptRepo %s for domain %s>' % ('unknown',self.dnsdomain)

class WaptHostRepo(WaptRepo):
    """Dummy http repository for host packages"""

    def __init__(self,url=None,name='',proxies={'http':None,'https':None},timeout = 2,dnsdomain=None,hosts=[]):
        WaptRepo.__init__(self,url=url,name=name,proxies=proxies,timeout = timeout,dnsdomain=dnsdomain)
        self.hosts_list = hosts

    def _load_packages_index(self):
        self._packages = []

    def update_db(self,force=False,waptdb=None,public_certs=[],filter_on_host_cap=True):
        """get a list of host packages from remote repo"""
        current_host = setuphelpers.get_hostname()
        if not current_host in self.hosts_list:
            self.hosts_list.append(current_host)
        result = ''
        for host in self.hosts_list:
            (entry,result) = self.update_host(host,waptdb,force=force,public_certs=public_certs)
            if not entry in self.packages:
                self.packages.append(entry)
        return result

    def update_host(self,host,waptdb,force=False,public_certs=[]):
        """Update host package from repo.
           Stores last-http-date in database/

        Args:
            host (str): fqdn of host for which to retrieve host package
            waptdb (WaptDB) : to check/store last modified date of host package
            force (bool) : force wget even if http date of remote file has not changed
            public_certs (list of paths or SSLCertificates) : Certificates against which to check control signature

        Returns;
            list of (host package entry,entry date on server)


        >>> repo = WaptHostRepo(name='wapt-host',timeout=4)
        >>> print repo.dnsdomain
        tranquilit.local
        >>> print repo.repo_url
        http://wapt.tranquilit.local/wapt-host
        >>> waptdb = WaptDB(':memory:')
        >>> repo.update_host('test-dummy',waptdb)
        (None, None)
        """
        try:
            host_package_url = "%s/%s.wapt" % (self.repo_url,host)
            host_cachedate = 'date-%s' % (host,)
            host_request = requests.head(host_package_url,proxies=self.proxies,verify=self.verify_cert,timeout=self.timeout,headers=default_http_headers())
            try:
                host_request.raise_for_status()
                host_package_date = httpdatetime2isodate(host_request.headers.get('last-modified',None))
                package = None
                if host_package_date:
                    if force or host_package_date != waptdb.get_param(host_cachedate) or not waptdb.packages_matching(host):
                        host_package = requests.get(host_package_url,proxies=self.proxies,verify=self.verify_cert,timeout=self.timeout,headers=default_http_headers())
                        host_package.raise_for_status()

                        # Packages file is a zipfile with one Packages file inside
                        control = codecs.decode(ZipFile(
                              StringIO.StringIO(host_package.content)
                            ).read(name='WAPT/control'),'UTF-8').splitlines()

                        with waptdb:
                            logger.debug(u'Purge packages table')
                            waptdb.db.execute('delete from wapt_package where package=?',(host,))

                            package = PackageEntry()
                            package.load_control_from_wapt(control)
                            logger.debug(u"%s (%s)" % (package.package,package.version))
                            package.repo_url = self.repo_url
                            package.repo = self.name
                            try:
                                package.check_control_signature(public_certs)
                                waptdb.add_package_entry(package)
                            except:
                                logger.critical('Invalid signature for package control entry %s : discarding' % package.asrequirement())

                            logger.debug(u'Commit wapt_package updates')
                            waptdb.set_param(host_cachedate,host_package_date)
                    else:
                        logger.debug(u'No change on host package at %s (%s)' % (host_package_url,host_package_date))
                        packages = waptdb.packages_matching(host)
                        if packages:
                            package=packages[-1]
                        else:
                            package=None

            except requests.HTTPError as e:
                # no host package
                with waptdb:
                    package,host_package_date=(None,None)
                    logger.info(u'No host package available at %s' % host_package_url)
                    waptdb.db.execute('delete from wapt_package where package=?',(host,))
                    waptdb.delete_param(host_cachedate)

            return (package,host_package_date)
        except:
            self._cached_dns_repo_url = None
            raise

    @property
    def repo_url(self):
        if self._repo_url:
            return self._repo_url
        else:
            if not self._cached_dns_repo_url and self.dnsdomain:
                main = self.find_wapt_repo_url()
                if main:
                    self._cached_dns_repo_url = main +'-host'
                else:
                    self._cached_dns_repo_url = None
            return self._cached_dns_repo_url

    @repo_url.setter
    def repo_url(self,value):
        if value:
            value = value.rstrip('/')

        if value != self._repo_url:
            self._repo_url = value
            self._packages = None
            self._packages_date = None
            self._cached_dns_repo_url = None

    def load_config(self,config,section=None):
        """Load waptrepo configuration from inifile section.
                Use name of repo as section name if section is not provided.
                Use 'global' if no section named section in ini file
        """
        WaptRepo.load_config(self,config,section)
        # well known url guessed from main repo : url+"-host"
        if section is None or section == 'global':
            self._repo_url = None
        return self

    def __repr__(self):
        try:
            return '<WaptHostRepo %s for domain %s>' % (self.repo_url,self.dnsdomain)
        except:
            return '<WaptHostRepo %s for domain %s>' % ('unknown',self.dnsdomain)


######################"""

key_passwd = None


class Wapt(object):
    """Global WAPT engine"""
    global_attributes = ['wapt_base_dir','waptserver','config_filename','proxies','repositories','private_key','public_certs','package_cache_dir','dbpath']

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
        self._use_hostpackages = None

        self.repositories = []

        self.dry_run = False

        self.upload_cmd = None
        self.upload_cmd_host = self.upload_cmd
        self.after_upload = None
        self.proxies = None
        self.language = None

        self.use_http_proxy_for_repo = False
        self.use_http_proxy_for_server = False
        self.use_http_proxy_for_templates = False

        try:
            self.wapt_base_dir = os.path.dirname(__file__)
        except NameError:
            self.wapt_base_dir = os.getcwd()

        self.disable_update_server_status = disable_update_server_status

        self.config = config
        self.config_filename = config_filename
        if not self.config_filename:
            self.config_filename = os.path.join(self.wapt_base_dir,'wapt-get.ini')

        self.package_cache_dir = os.path.join(os.path.dirname(self.config_filename),'cache')
        if not os.path.exists(self.package_cache_dir):
            os.makedirs(self.package_cache_dir)

        # to allow/restrict installation, supplied to packages
        self.user = setuphelpers.get_current_user()
        self.usergroups = None

        # keep private key in cache
        self._private_key = ''
        self._private_key_cache = None

        self.waptserver = None
        self.config_filedate = None
        self.load_config(config_filename = self.config_filename)

        self.options = OptionParser()
        self.options.force = False

        # list of process pids launched by run command
        self.pidlist = []

        # events handler
        self.events = None


        self._key_passwd_cache = None

        def _cache_passwd_callback(*args):
            """Default password callback for opening private keys.
            """
            if not self._key_passwd_cache:
                import getpass
                self._key_passwd_cache = getpass.getpass()
            return self._key_passwd_cache.encode('ascii')

        self.key_passwd_callback = _cache_passwd_callback

        import pythoncom
        pythoncom.CoInitialize()

    @property
    def private_key(self):
        return self._private_key

    @private_key.setter
    def private_key(self,value):
        if value != self._private_key:
            self._private_key_cache = None
            self._private_key = value

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
    def use_hostpackages(self):
        return self._use_hostpackages

    @use_hostpackages.setter
    def use_hostpackages(self,value):
        if value and not self._use_hostpackages == True:
            self.add_hosts_repo()
        elif not value and self._use_hostpackages:
            if self.repositories and isinstance(self.repositories[-1],WaptHostRepo):
                del self.repositories[-1]
        self._use_hostpackages = value

    def load_config(self,config_filename=None):
        """Load configuration parameters from supplied inifilename
        """
        # default config file
        defaults = {
            'loglevel':'warning',
            'default_package_prefix':'tis',
            'default_sources_suffix':'wapt',
            'default_sources_root':'c:\\waptdev',
            'use_http_proxy_for_repo':'0',
            'use_http_proxy_for_server':'0',
            'use_http_proxy_for_templates':'0',
            'tray_check_interval':2,
            'service_interval':2,
            'use_hostpackages':'0',
            'timeout':5.0,
            'wapt_server_timeout':10.0,
            # optional...
            'templates_repo_url':'',
            'private_key':'',
            'default_sources_url':'',
            'upload_cmd':'',
            'upload_cmd_host':'',
            'after_upload':'',
            'http_proxy':'',
            'waptwua_enabled':'0',
            }

        if not self.config:
            self.config = RawConfigParser(defaults = defaults)

        if config_filename:
            self.config_filename = config_filename

        self.config.read(self.config_filename)
        # keep the timestamp of last read config file to reload it if it is changed
        if os.path.isfile(self.config_filename):
            self.config_filedate = os.stat(self.config_filename).st_mtime
        else:
            self.config_filedate = None

        if self.config.has_option('global','dbpath'):
            self.dbpath =  self.config.get('global','dbpath')
        else:
            self.dbpath = os.path.join(self.wapt_base_dir,'db','waptdb.sqlite')

        if self.config.has_option('global','private_key'):
            self.private_key = self.config.get('global','private_key')

        if self.config.has_option('global','public_certs_dir'):
            self.public_certs_dir = self.config.get('global','public_certs_dir')
        else:
            self.public_certs_dir = os.path.join(self.wapt_base_dir,'ssl')
        # get the list of certificates to use :
        self.public_certs = glob.glob(os.path.join(self.public_certs_dir,'*.crt')) + glob.glob(os.path.join(self.public_certs_dir,'*.cer'))

        if self.config.has_option('global','upload_cmd'):
            self.upload_cmd = self.config.get('global','upload_cmd')

        if self.config.has_option('global','upload_cmd_host'):
            self.upload_cmd_host = self.config.get('global','upload_cmd_host')

        if self.config.has_option('global','after_upload'):
            self.after_upload = self.config.get('global','after_upload')

        self.use_http_proxy_for_repo = self.config.getboolean('global','use_http_proxy_for_repo')
        self.use_http_proxy_for_server = self.config.getboolean('global','use_http_proxy_for_server')
        self.use_http_proxy_for_templates = self.config.getboolean('global','use_http_proxy_for_templates')

        if self.config.has_option('global','http_proxy'):
            self.proxies = {'http':self.config.get('global','http_proxy'),'https':self.config.get('global','http_proxy')}
        else:
            self.proxies = None

        if self.config.has_option('global','wapt_server'):
            self.waptserver = WaptServer().load_config(self.config)
        else:
            self.waptserver = None

        if self.config.has_option('global','language'):
            self.language = self.config.get('global','language')

        if self.config.has_option('global','uuid'):
            forced_uuid = self.config.get('global','uuid')
            if forced_uuid != self.host_uuid:
                logger.debug('Storing new uuid in DB %s' % forced_uuid)
                self.host_uuid = forced_uuid

        # Get the configuration of all repositories (url, ...)
        self.repositories = []
        # secondary
        if self.config.has_option('global','repositories'):
            names = ensure_list(self.config.get('global','repositories'))
            logger.info(u'Other repositories : %s' % (names,))
            for name in names:
                if name:
                    w = WaptRepo(name=name).load_config(self.config,section=name)
                    self.repositories.append(w)
                    logger.debug(u'    %s:%s' % (w.name,w._repo_url))

        # last is main repository so it overrides the secondary repositories
        if self.config.has_option('global','repo_url'):
            w = WaptRepo(name='global').load_config(self.config)
            self.repositories.append(w)

        # True if we want to use automatic host package based on host fqdn
        #   privacy problem as there is a request to wapt repo to get
        #   host package update at each update/upgrade
        self._use_hostpackages = None
        if self.config.has_option('global','use_hostpackages'):
            self.use_hostpackages = self.config.getboolean('global','use_hostpackages')

        self.waptwua_enabled = False
        if self.config.has_option('global','waptwua_enabled'):
            self.waptwua_enabled = self.config.getboolean('global','waptwua_enabled')

    def write_config(self,config_filename=None):
        """Update configuration parameters to supplied inifilename
        """
        for key in self.config.defaults():
            if hasattr(self,key) and getattr(self,key) != self.config.defaults()[key]:
                logger.debug('update config global.%s : %s' % (key,getattr(self,key)))
                self.config.set('global',key,getattr(self,key))
        repositories_names = ','.join([ r.name for r in self.repositories if r.name not in ('global','wapt-host')])
        if self.config.has_option('global','repositories') and repositories_names != '':
            self.config.set('global','repositories',repositories_names)
        self.config.write(open(self.config_filename,'wb'))
        self.config_filedate = os.stat(self.config_filename).st_mtime

    def add_hosts_repo(self):
        """Add an automatic host repository, remove existing WaptHostRepo last one before"""
        while self.repositories and isinstance(self.repositories[-1],WaptHostRepo):
            del self.repositories[-1]

        main = None
        if self.repositories:
            main = self.repositories[-1]

        if self.config.has_section('wapt-host'):
            section = 'wapt-host'
        else:
            section = None
        host_repo = WaptHostRepo(name='wapt-host').load_config(self.config,section)
        self.repositories.append(host_repo)

        # in case host repo is guessed from main repo (no specific section) ans main repor_url is set
        if section is None and main:
            if main._repo_url and not host_repo._repo_url:
                host_repo.repo_url = main._repo_url+'-host'


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
        if self._runstatus is None or self._runstatus != waptstatus:
            logger.info(u'Status : %s' % ensure_unicode(waptstatus))
            self.write_param('runstatus',waptstatus)
            self._runstatus = waptstatus
            if not self.disable_update_server_status and self.waptserver_available():
                try:
                    self.update_server_status()
                except Exception as e:
                    logger.warning(u'Unable to contact server to register current status')
                    logger.debug(u'Unable to update server with current status : %s' % ensure_unicode(e))

    @property
    def host_uuid(self):
        value = self.read_param('uuid')
        registered_hostname = self.read_param('hostname')
        current_hostname = setuphelpers.get_hostname()
        if not value or registered_hostname != current_hostname:
            if registered_hostname != current_hostname:
                # forget old host package if any as it is not relevant anymore
                self.forget_packages(registered_hostname)

            logger.info('Unknown UUID or hostname has changed: reading host UUID from wmi informations')
            inv = setuphelpers.wmi_info_basic()
            value = inv['System_Information']['UUID']
            self.write_param('uuid',value)
            self.write_param('hostname',current_hostname)
        return value


    @host_uuid.setter
    def host_uuid(self,value):
        self.write_param('uuid',value)


    @host_uuid.deleter
    def host_uuid(self):
        self.delete_param('uuid')

    def generate_host_uuid(self,forced_uuid=None):
        """Regenerate a random UUID for this host or force with supplied one.

        Args;
            forced_uuid (str): uuid to force for this host. If None, generate a random one

        Normally, the UUID is taken from BIOS through wmi.

        In case bios returns some duplicates or garbage, it can be useful to
          force a random uuid. This is stored as uuid key in wapt-get.ini.

        In case we want to link th host with a an existing record on server, we
            can force a old UUID.
        """
        auuid = forced_uuid or str(uuid.uuid4())
        self.host_uuid = auuid
        ini = RawConfigParser()
        ini.read(self.config_filename)
        ini.set('global','uuid',auuid)
        ini.write(open(self.config_filename,'w'))
        return auuid

    def reset_host_uuid(self):
        """Reset host uuid to bios provided UUID.
        """
        del(self.host_uuid)
        ini = RawConfigParser()
        ini.read(self.config_filename)
        if ini.has_option('global','uuid'):
            ini.remove_option('global','uuid')
            ini.write(open(self.config_filename,'w'))
        return self.host_uuid

    def host_keys(self,force=False):
        """Creates a set of private/public keys to identify the host on the waptserver
            keys are created in the same directory as DB
        """
        destdir = self.dbdir
        if not os.path.isdir(destdir):
            raise Exception(u'host_keys: directory %s does not exist'%destdir)

        hostname = setuphelpers.get_hostname()
        destpem = os.path.join(destdir,'%s.pem' % hostname)
        destcrt = os.path.join(destdir,'%s.crt' % hostname)
        if os.path.isfile(destcrt):
            cn = SSLCertificate(destcrt).cn
        else:
            cn = None
        # check if host
        if not cn or cn != self.host_uuid or force:
            if os.path.isfile(destpem):
                os.unlink(destpem)
            if os.path.isfile(destcrt):
                os.unlink(destcrt)
            create_self_signed_key(
                hostname,
                destdir = destdir,
                organization = setuphelpers.registered_organization,
                commonname = self.host_uuid,
                )
        return {'pem_filename':destpem,'crt_filename':destcrt}


    def http_upload_package(self,package,wapt_server_user=None,wapt_server_passwd=None):
        r"""Upload a package or host package to the waptserver.
                package : either the filename of a wapt package, or a PackageEntry
                wapt_server_user   :
                wapt_server_passwd :
            >>> from common import *
            >>> wapt = Wapt(config_filename = r'C:\tranquilit\wapt\tests\wapt-get.ini')
            >>> r = wapt.update()
            >>> d = wapt.duplicate_package('tis-wapttest','toto')
            >>> print d
            {'target': u'c:\\users\\htouvet\\appdata\\local\\temp\\toto.wapt', 'package': PackageEntry('toto','119')}
            >>> wapt.http_upload_package(d['package'],wapt_server_user='admin',wapt_server_passwd='password')
            """
        if not (isinstance(package,(str,unicode)) and os.path.isfile(package)) and not isinstance(package,PackageEntry):
            raise Exception('No package file to upload')

        auth = None
        if not wapt_server_user:
            if self.waptserver.auth():
                auth = self.waptserver.auth()

        if not auth:
            if not wapt_server_user:
                wapt_server_user = raw_input('WAPT Server user :')
            if not wapt_server_passwd:
                wapt_server_passwd = getpass.getpass('WAPT Server password :').encode('ascii')
            auth =  (wapt_server_user, wapt_server_passwd)

        if not isinstance(package,PackageEntry):
            pe = PackageEntry().load_control_from_wapt(package)
            package_filename = package
        else:
            pe = package
            package_filename = pe.wapt_fullpath()
        with open(package_filename,'rb') as afile:
            if pe.section == 'host':
                #res = self.waptserver.post('upload_host',files={'file':afile},auth=auth)
                res = self.waptserver.post('upload_host',files={'file':afile},auth=auth,timeout=300)
            else:
                res = self.waptserver.post('upload_package/%s'%os.path.basename(package_filename),data=afile,auth=auth,timeout=300)
            return res
        if res['status'] != 'OK':
            raise Exception(u'Unable to upload package: %s'%ensure_unicode(res['message']))

    def upload_package(self,cmd_dict,wapt_server_user=None,wapt_server_passwd=None):
        """Method to upload a package using Shell command (like scp) instead of http upload
            You must define first a command in inifile with the form :
                upload_cmd="c:\Program Files"\putty\pscp -v -l waptserver %(waptfile)s srvwapt:/var/www/%(waptdir)s/
            or
                upload_cmd="C:\Program Files\WinSCP\WinSCP.exe" root@wapt.tranquilit.local /upload %(waptfile)s
            You can define a "after_upload" shell command. Typical use is to update the Packages index
                after_upload="c:\Program Files"\putty\plink -v -l waptserver srvwapt.tranquilit.local "python /opt/wapt/wapt-scanpackages.py /var/www/%(waptdir)s/"
        """
        if not self.upload_cmd and not wapt_server_user:
            wapt_server_user = raw_input('WAPT Server user :')
            wapt_server_passwd = getpass.getpass('WAPT Server password :').encode('ascii')
        auth =  (wapt_server_user, wapt_server_passwd)

        if cmd_dict['waptdir'] == "wapt-host":
            if self.upload_cmd_host:
                cmd_dict['waptfile'] = ' '.join(cmd_dict['waptfile'])
                return dict(status='OK',message=self.run(self.upload_cmd_host % cmd_dict))
            else:
                #upload par http vers un serveur WAPT  (url POST upload_host)
                for file in cmd_dict['waptfile']:
                    file = file[1:-1]
                    with open(file,'rb') as afile:
                        res = self.waptserver.post('upload_host',files={'file':afile},auth=auth,timeout=300)
                    if res['status'] != 'OK':
                        raise Exception(u'Unable to upload package: %s'%ensure_unicode(res['message']))
                return res

        else:
            if self.upload_cmd:
                cmd_dict['waptfile'] = ' '.join(cmd_dict['waptfile'])
                return dict(status='OK',message=ensure_unicode(self.run(self.upload_cmd % cmd_dict)))
            else:
                for file in cmd_dict['waptfile']:
                    # file is surrounded by quotes for shell usage
                    file = file[1:-1]
                    #upload par http vers un serveur WAPT  (url POST upload_package)
                    with open(file,'rb') as afile:
                        res = self.waptserver.post('upload_package/%s'%os.path.basename(file),data=afile,auth=auth,timeout=300)
                    if res['status'] != 'OK':
                        raise Exception(u'Unable to upload package: %s'%ensure_unicode(res['message']))
                return res

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
        with self.waptdb:
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

            for pid in reset_error:
                self.waptdb.update_install_status_pid(pid,'ERROR')

            if reset_error or not init_run_pids:
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

    def corrupted_files_sha1(self,rootdir,manifest):
        """check hexdigest sha1 for the files in manifest
        returns a list of non matching files (corrupted files)"""
        assert os.path.isdir(rootdir)
        assert isinstance(manifest,list) or isinstance(manifest,tuple)
        errors = []
        expected = []
        for (filename,sha1) in manifest:
            fullpath = os.path.abspath(os.path.join(rootdir,filename))
            expected.append(fullpath)
            if sha1 != sha1_for_file(fullpath):
                errors.append(filename)
        files = setuphelpers.all_files(ensure_unicode(rootdir))
        # removes files which are not in manifest by design
        for fn in ('WAPT/signature','WAPT/manifest.sha1'):
            full_fn = os.path.abspath(os.path.join(rootdir,fn))
            if full_fn in files:
                files.remove(full_fn)
        # add in errors list files found but not expected...
        errors.extend([ fn for fn in files if fn not in expected])
        return errors

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
        return setuphelpers.run(*arg,pidlist=self.pidlist,**args)

    def run_notfatal(self,*cmd,**args):
        """Runs the command and wait for it termination
        returns output, don't raise exception if exitcode is not null but return '' """
        try:
            return self.run(*cmd,**args)
        except Exception as e:
            print(u'Warning : %s' % e)
            return ''

    def check_control_signature(self,package_entry):
        """ """
        if not package_entry.signature:
            logger.warning('Package control %s on repo %s is not signed... not checking' % (package_entry.asrequirement(),package_entry.repo))
            return None
        return package_entry.check_control_signature(self.authorized_certificates())

    def install_wapt(self,fname,params_dict={},explicit_by=None):
        """Install a single wapt package given its WAPT filename.
        return install status"""
        install_id = None
        old_hdlr = None
        old_stdout = None
        old_stderr = None

        self.check_cancelled(u'Install of %s cancelled before starting up'%ensure_unicode(fname))
        logger.info(u"Register start of install %s as user %s to local DB with params %s" % (ensure_unicode(fname), setuphelpers.get_current_user(), params_dict))
        logger.info(u"Interactive user:%s, usergroups %s" % (self.user,self.usergroups))
        status = 'INIT'
        if not self.public_certs:
            raise Exception(u'install_wapt %s: No public Key provided for package signature checking.'%(fname,))
        previous_uninstall = self.registry_uninstall_snapshot()
        entry = PackageEntry()
        entry.load_control_from_wapt(fname)

        if entry.min_wapt_version and Version(entry.min_wapt_version)>Version(setuphelpers.__version__):
            raise Exception('This package requires a newer Wapt agent. Minimum version: %s' % entry.min_wapt_version)

        # check if there is enough space for final install
        # TODO : space for the temporary unzip ?
        free_disk_space = setuphelpers.get_disk_free_space(setuphelpers.programfiles)
        if entry.installed_size and free_disk_space < entry.installed_size:
            raise Exception('This package requires at least %s free space. The "Program File"s drive has only %s free space' %
                (format_bytes(entry.installed_size),format_bytes(free_disk_space)))

        os_version = setuphelpers.windows_version()
        if entry.min_os_version and os_version < Version(entry.min_os_version):
            raise Exception('This package requires that OS be at least %s' % entry.min_os_version)
        if entry.max_os_version and os_version > Version(entry.max_os_version):
            raise Exception('This package requires that OS be at most %s' % entry.min_os_version)

        # don't check in developper mode
        if os.path.isfile(fname):
            entry.check_control_signature(self.authorized_certificates())

        self.runstatus=u"Installing package %s version %s ..." % (entry.package,entry.version)
        old_stdout = sys.stdout
        old_stderr = sys.stderr

        # we  record old sys.path as we will include current setup.py
        oldpath = sys.path

        # get old install params if the package has been already installed
        old_install = self.is_installed(entry.package)
        if old_install:
            old_install_params = json.loads(old_install['install_params'])
            for name in old_install_params:
                if not name in params_dict:
                    params_dict[name] = old_install_params[name]

        try:
            install_id = self.waptdb.add_start_install(entry.package ,entry.version,entry.architecture,params_dict=params_dict,explicit_by=explicit_by)
            # we setup a redirection of stdout to catch print output from install scripts
            sys.stderr = sys.stdout = install_output = LogInstallOutput(sys.stderr,self.waptdb,install_id)
            """
            hdlr = logging.StreamHandler(install_output)
            hdlr.setFormatter(logging.Formatter(u'%(asctime)s %(levelname)s %(message)s'))
            if logger.handlers:
                old_hdlr = logger.handlers[0]
                logger.handlers[0] = hdlr
            else:
                old_hdlr = None
                logger.addHandler(hdlr)
            """

            self.check_cancelled()
            logger.info(u"Installing package %s"%(ensure_unicode(fname),))
            # case where fname is a wapt zipped file, else directory (during development)
            istemporary = False

            if os.path.isfile(fname):
                packagetempdir = tempfile.mkdtemp(prefix="wapt")
                logger.info(u'  unzipping %s to temporary %s' % (ensure_unicode(fname),ensure_unicode(packagetempdir)))
                zip = ZipFile(fname)
                zip.extractall(path=packagetempdir)
                istemporary = True
            elif os.path.isdir(fname):
                packagetempdir = fname
            else:
                raise Exception(u'%s is not a file nor a directory, aborting.' % ensure_unicode(fname))

            try:
                previous_cwd = os.getcwd()
                # chech sha1
                self.check_cancelled()
                manifest_filename = os.path.join( packagetempdir,'WAPT','manifest.sha1')
                if os.path.isfile(manifest_filename):
                    manifest_data = open(manifest_filename,'r').read()
                    # check signature of manifest
                    signature_filename = os.path.join( packagetempdir,'WAPT','signature')
                    # if public key provided, and signature in wapt file, check it
                    if self.public_certs and os.path.isfile(signature_filename):
                        signature = open(signature_filename,'r').read().decode('base64')
                        try:
                            subject = ssl_verify_content(manifest_data,signature,self.public_certs)
                            logger.info(u'Package issued by %s' % (subject,))
                        except:
                            raise Exception(u'Package file %s signature is invalid' % fname)
                    else:
                        raise Exception(u'No certificate provided for %s or package does not contain a signature' % fname)

                    manifest = json.loads(manifest_data)
                    errors = self.corrupted_files_sha1(packagetempdir,manifest)
                    if errors:
                        raise Exception(u'Error in package %s, files corrupted, SHA1 not matching for %s' % (fname,errors,))
                else:
                    # we allow unsigned in development mode where fname is a directory
                    if istemporary:
                        raise Exception(u'Package %s does not contain a manifest.sha1 file, and unsigned packages install is not allowed' % fname)

                self.check_cancelled()
                setup_filename = os.path.join( packagetempdir,'setup.py')
                os.chdir(os.path.dirname(setup_filename))
                if not os.getcwd() in sys.path:
                    sys.path.append(os.getcwd())

                # import the setup module from package file
                logger.info(u"  sourcing install file %s " % ensure_unicode(setup_filename) )
                setup = import_setup(setup_filename)
                required_params = []

                # be sure some minimal functions are available in setup module at install step
                setattr(setup,'basedir',os.path.dirname(setup_filename))
                # redefine run to add reference to wapt.pidlist
                setattr(setup,'run',self.run)
                setattr(setup,'run_notfatal',self.run_notfatal)
                setattr(setup,'WAPT',self)
                setattr(setup,'control',entry)
                setattr(setup,'language',self.language or setuphelpers.get_language() )

                setattr(setup,'user',self.user)
                setattr(setup,'usergroups',self.usergroups)

                # get definitions of required parameters from setup module
                if hasattr(setup,'required_params'):
                    required_params = setup.required_params

                # get value of required parameters if not already supplied
                for p in required_params:
                    if not p in params_dict:
                        if not is_system_user():
                            params_dict[p] = raw_input(u"%s: " % p)
                        else:
                            raise Exception(u'Required parameters %s is not supplied' % p)
                logger.info(u'Install parameters : %s' % (params_dict,))

                # set params dictionary
                if not hasattr(setup,'params'):
                    # create a params variable for the setup module
                    setattr(setup,'params',params_dict)
                else:
                    # update the already created params with additional params from command line
                    setup.params.update(params_dict)

                # store source of install and params in DB for future use (upgrade, session_setup, uninstall)
                self.waptdb.store_setuppy(install_id, setuppy = codecs.open(setup_filename,'r',encoding='utf-8').read(),install_params=params_dict)

                if not self.dry_run:
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
                    status = 'OK'
                else:
                    status = 'ERROR'

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
                                raise Exception(u'The uninstall keys: \n%s\n have not been found in system registry after softwares installation.' % ('\n'.join(key_errors),))
                            else:
                                raise Exception(u'The uninstall key: %s has not been found in system registry after software installation.' % (' '.join(key_errors),))

                else:
                    new_uninstall = self.registry_uninstall_snapshot()
                    new_uninstall_key = [ k for k in new_uninstall if not k in previous_uninstall]

                # get uninstallstring from setup module (string or array of strings)
                if hasattr(setup,'uninstallstring'):
                    uninstallstring = setup.uninstallstring[:]
                else:
                    uninstallstring = None
                logger.info(u'  uninstall keys : %s' % (new_uninstall_key,))
                logger.info(u'  uninstall strings : %s' % (uninstallstring,))

                logger.info(u"Install script finished with status %s" % status)

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
                        except:
                            cnt -= 1
                            time.sleep(2)
                    else:
                        logger.warning(u"Unable to clean tmp dir")

            self.waptdb.update_install_status(install_id,status,'',str(new_uninstall_key) if new_uninstall_key else '',str(uninstallstring) if uninstallstring else '')
            return self.waptdb.install_status(install_id)

        except Exception as e:
            if install_id:
                try:
                    self.waptdb.update_install_status(install_id,'ERROR',ensure_unicode(e))
                except Exception as e2:
                    logger.critical(ensure_unicode(e2))
            else:
                logger.critical(ensure_unicode(e))
            raise e
        finally:
            gc.collect()
            if 'setup' in dir():
                setup_name = setup.__name__[:]
                logger.debug('Removing module: %s, refcnt: %s'%(setup_name,sys.getrefcount(setup)))
                del setup
                if setup_name in sys.modules:
                    del sys.modules[setup_name]

            sys.stdout = old_stdout
            sys.stderr = old_stderr
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
                "errors": [ "%s : %s" % (p.asrequirement(),p.install_status) for p in self.error_packages()],
                "date":datetime2isodate(),
                }
            if upgrades is None:
                upgrades = self.list_upgrade()

            status["upgrades"] = upgrades['upgrade']+upgrades['install']+upgrades['additional']
            status["pending"] = upgrades
            logger.debug(u"store status in DB")
            self.write_param('last_update_status',jsondump(status))
            return status
        except Exception as e:
            logger.critical(u'Unable to store status of update in DB : %s'% ensure_unicode(e))
            if logger.level == logging.DEBUG:
                raise

    def get_sources(self,package):
        """Download sources of package (if referenced in package as a https svn)
           in the current directory"""
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
            print(ensure_unicode(self.run(u'"%s" up "%s"' % (svncmd,co_dir))))
        else:
            print(ensure_unicode(self.run(u'"%s" co "%s" "%s"' % (svncmd,sources_url,co_dir))))
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
        {'status': u'OK', 'log': u'Installing 7-Zip 9.38.0-1\n7-Zip already installed, skipping msi install\n'}

        """
        q = self.waptdb.query("""\
           select install_status,install_output from wapt_localstatus
            where package=? order by install_date desc limit 1
           """ , (packagename,) )
        if not q:
            raise Exception("Package %s not found in local DB status" % packagename)
        return {"status" : q[0]['install_status'], "log":q[0]['install_output']}

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

        for f in glob.glob(os.path.join(cachepath,'*.wapt')):
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

    def update(self,force=False,register=True,filter_on_host_cap=True):
        """Update local database with packages definition from repositories

        Args:
            force (boolean):    update even if Packages index on repository has not been
                                updated since last update (based on http headers)
            register (boolean): Send informations about status of local packages to waptserver
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
        previous = self.waptdb.known_packages()
        # (main repo is at the end so that it will used in priority)
        self.waptdb.update_repos_list(self.repositories,proxies=self.proxies,force=force,public_certs=self.public_certs,filter_on_host_cap=filter_on_host_cap)

        current = self.waptdb.known_packages()
        result = {
            "added":   [ p for p in current if not p in previous ],
            "removed": [ p for p in previous if not p in current],
            "count" : len(current),
            "repos" : [r.repo_url for r in self.repositories],
            "upgrades": self.list_upgrade(),
            "date":datetime2isodate(),
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

    def check_depends(self,apackages,forceupgrade=False,force=False,assume_removed=[]):
        """Given a list of packagename or requirement "name (=version)",
        return a dictionnary of {'additional' 'upgrade' 'install' 'skipped' 'unavailable','remove'} of
        [packagerequest,matching PackageEntry]

        Args:
            apackages (str or list): list of packages for which to check missing dependencies.
            forceupgrade (boolean): if True, check if the current installed packages is the latest available
            force (boolean): if True, install the latest version even if the package is already there and match the requirement
            assume_removed (list): list of packagename which are assumed to be absent even if they are installed to check the
                                    consequences of removal of packages, implies force=True
        Returns:
            dict : {'additional' 'upgrade' 'install' 'skipped' 'unavailable', 'remove'} with list of [packagerequest,matching PackageEntry]

        """
        if apackages is None:
            apackages = []
        # for csv string list of dependencies
        apackages = ensure_list(apackages)

        # check if all members are strings packages requirements "package_name(=version)"
        apackages = [isinstance(p,PackageEntry) and p.asrequirement() or p for p in apackages]

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
        for request in apackages:
            # get the current installed package matching the request
            old_matches = self.waptdb.installed_matching(request)

            # removes "assumed removed" packages
            if old_matches:
                for packagename in assume_removed:
                    if old_matches.match(packagename):
                        old_matches = None
                        break

            # current installed matches
            if not force and old_matches and not forceupgrade:
                skipped.append((request,old_matches))
            else:
                new_availables = self.waptdb.packages_matching(request)
                if new_availables:
                    if force or not old_matches or (forceupgrade and old_matches < new_availables[-1]):
                        if not (request,new_availables[-1]) in packages:
                            packages.append((request,new_availables[-1]))
                    else:
                        skipped.append((request,old_matches))
                else:
                    if (request,None) not in unavailable:
                        unavailable.append((request,None))

        # get dependencies of not installed top packages
        if forceupgrade:
            (depends,missing) = self.waptdb.build_depends(apackages)
        else:
            (depends,missing) = self.waptdb.build_depends([p[0] for p in packages])

        for p in missing:
            if (p,None) not in unavailable:
                unavailable.append((p,None))

        # search for most recent matching package to install
        for request in depends:
            # get the current installed package matching the request
            old_matches = self.waptdb.installed_matching(request)

            # removes "assumed removed" packages
            if old_matches:
                for packagename in assume_removed:
                    if old_matches.match(packagename):
                        old_matches = None
                        break

            # current installed matches
            if not force and old_matches:
                skipped.append((request,old_matches))
            else:
                # check if installable or upgradable ?
                new_availables = self.waptdb.packages_matching(request)
                if new_availables:
                    if not old_matches or (forceupgrade and old_matches < new_availables[-1]):
                        additional_install.append((request,new_availables[-1]))
                    else:
                        skipped.append((request,old_matches))
                else:
                    unavailable.append((request,None))

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
            apackages (str or list): list of packages fr which parent dependencies will be checked.

        Returns:
            list: list of package requirements with broken dependencies

        """
        if not isinstance(apackages,list):
            apackages = [apackages]
        result = []
        installed = [ p.asrequirement() for p in self.installed().values() if p.asrequirement() not in apackages ]
        for packagename in installed:
            # test for each installed package if the removal would imply a reinstall
            test = self.check_depends(packagename,assume_removed=apackages)
            # get package names only
            reinstall = [ p[0] for p in (test['upgrade'] + test['additional'])]
            for p in reinstall:
                if p in apackages and not packagename in result:
                    result.append(packagename)
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
        actions = self.check_depends(apackages,force=force,forceupgrade=forceupgrade)
        return  actions

    def install(self,apackages,
            force=False,
            params_dict = {},
            download_only=False,
            usecache=True,
            printhook=None):
        """Install a list of packages and its dependencies
        removes first packages which are in conflicts package attribute
        Returns a dictionary of (package requirement,package) with 'install','skipped','additional'

        Args:
            apackages : list of packages requirements "packagename(=version)" or list of PackageEntry.
            force : reinstalls the packages even if it is already installed
            params_dict : dict of parameters passed to the install() procedure in the packages setup.py of all packages
                          as params variables and as "setup module" attributes
            download_only : don't install package, but only download them
            usecache : use the already downloaded packages if available in cache directory
            printhook: hook for progress print

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
        if not isinstance(apackages,list):
            apackages = [apackages]

        # ensure that apackages is a list of package requirements (strings)
        new_apackages = []
        for p in apackages:
            if isinstance(p,PackageEntry):
                new_apackages.append(p.asrequirement())
            else:
                new_apackages.append(p)
        apackages = new_apackages

        actions = self.check_depends(apackages,force=force or download_only,forceupgrade=True)
        actions['errors']=[]

        skipped = actions['skipped']
        additional_install = actions['additional']
        to_upgrade = actions['upgrade']
        packages = actions['install']

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
        to_install.extend(additional_install)
        to_install.extend(to_upgrade)
        to_install.extend(packages)

        # get package entries to install to_install is a list of (request,package)
        packages = [ p[1] for p in to_install ]

        downloaded = self.download_packages(packages,usecache=usecache,printhook=printhook)
        if downloaded.get('errors',[]):
            logger.critical(u'Error downloading some files : %s'%(downloaded['errors'],))
            for request in downloaded.get('errors',[]):
                actions['errors'].append([request,None])

        # check downloaded packages signatures and merge control data in local database
        for fname in downloaded['downloaded'] + downloaded['skipped']:
            waptfile = zipfile.ZipFile(fname,'r',allowZip64=True)
            control = waptfile.open(u'WAPT/control').read().decode('utf8')
            manifest_content = waptfile.open(u'WAPT/manifest.sha1').read()
            manifest = json.loads(manifest_content)
            signature = waptfile.open(u'WAPT/signature').read().decode('base64')
            try:
                subject = ssl_verify_content(manifest_content,signature,self.public_certs)
                logger.info(u'Package issued by %s' % (subject,))
            except:
                raise Exception(u'Package file %s signature is invalid' % ensure_unicode(fname))

            for (fn,sha1) in manifest:
                if fn == 'WAPT\\control':
                    if sha1 != sha1_for_data(control.encode('utf8')):
                        raise Exception("WAPT/control file of %s is corrupted, sha1 digests don't match" % ensure_unicode(fname))
                    break
            # Merge updated control data
            # TODO

        actions['downloads'] = downloaded
        logger.debug(u'Downloaded : %s' % (downloaded,))

        def fname(packagefilename):
            return os.path.join(self.package_cache_dir,packagefilename)
        if not download_only:
            # switch to manual mode
            for (request,p) in skipped:
                if request in apackages and not p.explicit_by:
                    logger.info(u'switch to manual mode for %s' % (request,))
                    self.waptdb.switch_to_explicit_mode(p.package,self.user)

            for (request,p) in to_install:
                try:
                    print(u"Installing %s" % (p.package,))
                    result = self.install_wapt(fname(p.filename),
                        params_dict = params_dict,
                        explicit_by=self.user if request in apackages else None
                        )
                    if result:
                        for k in result.as_dict():
                            p[k] = result[k]

                    if not result or result['install_status'] != 'OK':
                        actions['errors'].append([request,p])
                        logger.critical(u'Package %s not installed due to errors' %(request,))
                except Exception as e:
                    actions['errors'].append([request,p])
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
            dict: with keys {"downloaded,"skipped","errors"} and list of cached file paths.

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> def nullhook(*args):
        ...     pass
        >>> wapt.download_packages(['tis-firefox','tis-waptdev'],usecache=False,printhook=nullhook)
        {'downloaded': [u'c:/wapt\\cache\\tis-firefox_37.0.2-9_all.wapt', u'c:/wapt\\cache\\tis-waptdev.wapt'], 'skipped': [], 'errors': []}
        """
        if not isinstance(package_requests,(list,tuple)):
            package_requests = [ package_requests ]
        downloaded = []
        skipped = []
        errors = []
        packages = []
        for p in package_requests:
            if isinstance(p,str) or isinstance(p,unicode):
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

            packagefilename = entry.filename.strip('./')
            download_url = entry.repo_url+'/'+packagefilename
            fullpackagepath = os.path.join(self.package_cache_dir,packagefilename)
            skip = False
            if os.path.isfile(fullpackagepath) and os.path.getsize(fullpackagepath)>0 and usecache:
                # check version
                try:
                    cached = PackageEntry()
                    cached.load_control_from_wapt(fullpackagepath,calc_md5=True)
                    if entry == cached:
                        if entry.md5sum == cached.md5sum:
                            skipped.append(fullpackagepath)
                            logger.info(u"  Use cached package file from " + fullpackagepath)
                            skip = True
                        else:
                            logger.critical(u"Cached file MD5 doesn't match MD5 found in packages index. Discarding cached file")
                            os.remove(fullpackagepath)
                except Exception as e:
                    # error : reload
                    logger.debug(u'Cache file %s is corrupted, reloading it. Error : %s' % (fullpackagepath,e) )

            if not skip:
                logger.info(u"  Downloading package from %s" % download_url)
                try:
                    def report(received,total,speed,url):
                        self.check_cancelled()
                        try:
                            if total>1:
                                stat = u'%s : %i / %i (%.0f%%) (%.0f KB/s)\r' % (url,received,total,100.0*received/total, speed)
                                print(stat)
                            else:
                                stat = ''
                            self.runstatus='Downloading %s : %s' % (entry.package,stat)
                        except:
                            self.runstatus='Downloading %s' % (entry.package,)

                    if not printhook:
                        printhook = report

                    self.runstatus='Downloading %s' % download_url
                    if self.use_http_proxy_for_repo:
                        curr_proxies = self.proxies
                    else:
                        curr_proxies = {'http':None,'https':None}
                    setuphelpers.wget( download_url, self.package_cache_dir,proxies=curr_proxies,printhook = printhook)
                    downloaded.append(fullpackagepath)
                    self.runstatus=''
                except Exception as e:
                    self.runstatus=''
                    if os.path.isfile(fullpackagepath):
                        os.remove(fullpackagepath)
                    logger.critical(u"Error downloading package from http repository, please update... error : %s" % ensure_unicode(e))
                    errors.append((download_url,"%s" % ensure_unicode(e)))
        return {"downloaded":downloaded,"skipped":skipped,"errors":errors}

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
        packages_list = ensure_list(packages_list)
        for package in packages_list:
            try:
                self.check_cancelled()
                # development mode, remove a package by its directory
                if os.path.isfile(os.path.join(package,'WAPT','control')):
                    package = PackageEntry().load_control_from_wapt(package).package
                elif isinstance(package,PackageEntry):
                    package = package.package
                else:
                    pe = self.is_installed(package)
                    if pe:
                        package = pe.package

                q = self.waptdb.query("""\
                   select * from wapt_localstatus
                    where package=?
                   """ , (package,))
                if not q:
                    logger.debug(u"Package %s not installed, removal aborted" % package)
                    return result

                # several versions installed of the same package... ?
                for mydict in q:
                    self.runstatus="Removing package %s version %s from computer..." % (mydict['package'],mydict['version'])

                    # removes recursively meta packages which are not satisfied anymore
                    additional_removes = self.check_remove(package)

                    if mydict['uninstall_string']:
                        if mydict['uninstall_string'][0] not in ['[','"',"'"]:
                            guids = mydict['uninstall_string']
                        else:
                            try:
                                guids = eval(mydict['uninstall_string'])
                            except:
                                guids = mydict['uninstall_string']
                        if isinstance(guids,(unicode,str)):
                            guids = [guids]
                        for guid in guids:
                            if guid:
                                try:
                                    logger.info(u'Running %s' % guid)
                                    logger.info(self.run(guid))
                                except Exception as e:
                                    logger.warning(u"Warning : %s" % ensure_unicode(e))

                    elif mydict['uninstall_key']:
                        if mydict['uninstall_key'][0] not in ['[','"',"'"]:
                            guids = mydict['uninstall_key']
                        else:
                            try:
                                guids = eval(mydict['uninstall_key'])
                            except:
                                guids = mydict['uninstall_key']

                        if isinstance(guids,(unicode,str)):
                            guids = [guids]

                        for guid in guids:
                            if guid:
                                try:
                                    uninstall_cmd =''
                                    uninstall_cmd = self.uninstall_cmd(guid)
                                    if uninstall_cmd:
                                        logger.info(u'Launch uninstall cmd %s' % (uninstall_cmd,))
                                        print(ensure_unicode(self.run(uninstall_cmd)))
                                except Exception as e:
                                    logger.critical(u"Critical error during uninstall cmd %s: %s" % (uninstall_cmd,ensure_unicode(e)))
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

                    logger.info(u'Remove status record from local DB for %s' % package)
                    self.waptdb.remove_install_status(package)
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
        return "%s" % (setuphelpers.get_hostname().lower())

    def check_host_package_outdated(self):
        """Check and return the host package if available and not installed"""
        logger.debug(u'Check if host package "%s" is available' % (self.host_packagename(), ))
        host_packages = self.is_available(self.host_packagename())
        if host_packages and not self.is_installed(host_packages[-1].asrequirement()):
            return host_packages[-1]
        else:
            return None

    def upgrade(self):
        """Install "well known" host package from main repository if not already installed
        then query localstatus database for packages with a version older than repository
        and install all newest packages

        Returns:
            dict: {'upgrade': [], 'additional': [], 'downloads':
                        {'downloaded': [], 'skipped': [], 'errors': []},
                     'remove': [], 'skipped': [], 'install': [], 'errors': [], 'unavailable': []}
        """
        self.runstatus='Upgrade system'
        try:
            if self.use_hostpackages:
                host_package = self.check_host_package_outdated()
                if host_package:
                    logger.info(u'Host package %s is available and not installed, installing host package...' % (host_package.package,) )
                    hostresult = self.install(host_package,force=True)
                else:
                    hostresult = {}
            else:
                hostresult = {}


            upgrades = self.waptdb.upgradeable()
            logger.debug(u'upgrades : %s' % upgrades.keys())
            result = self.install(upgrades.keys(),force=True)
            self.store_upgrade_status()

            # merge results
            return merge_dict(result,hostresult)
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
        result['upgrade'].extend([p[0].asrequirement() for p in self.waptdb.upgradeable().values() if p])
        if self.use_hostpackages:
            host_package = self.check_host_package_outdated()
            if host_package:
                host_package_req = host_package.asrequirement()
                if not host_package_req in result['install']+result['upgrade']+result['additional']:
                    result['install'].append(host_package_req)

        # get additional packages to install/upgrade based on new upgrades
        depends = self.check_depends(result['install']+result['upgrade']+result['additional'])
        for l in ('install','additional','upgrade'):
            for (r,candidate) in depends[l]:
                req = candidate.asrequirement()
                if not req in result['install']+result['upgrade']+result['additional']:
                    result[l].append(req)
        result['remove'] = [p[1].asrequirement() for p in depends['remove']]
        return result

    def search(self,searchwords=[],exclude_host_repo=True,section_filter=None,newest_only=False):
        """Returns a list of packages which have the searchwords in their description

        Args:
            searchwords (str or list): words to search in packages name or description
            exclude_host_repo (boolean): if True, don't search in host repoisitories.
            section_filter (str or list): restrict search to the specified package sections/categories

        Returns:
            list: list of packageEntry

        """
        available = self.waptdb.packages_search(searchwords=searchwords,exclude_host_repo=exclude_host_repo,section_filter=section_filter)
        installed = self.waptdb.installed(include_errors=True)
        upgradable =  self.waptdb.upgradeable()
        for p in available:
            if p.package in installed:
                current = installed[p.package]
                if p.version == current.version:
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
            for package in sorted(available,reverse=True):
                if package.package != last_package_name:
                    filtered.append(package)
                last_package_name = package.package
            return list(reversed(filtered))
        else:
            return available

    def list(self,searchwords=[]):
        """Returns a list of installed packages which have the searchwords
           in their description
        """
        return self.waptdb.installed_search(searchwords=searchwords,)

    def check_downloads(self,apackages=None):
        """Return list of available package entries not yet in cache
            to match supplied packages requirements
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
                if os.path.isfile(fullpackagepath) and os.path.getsize(fullpackagepath)>0:
                    # check version
                    try:
                        cached = PackageEntry()
                        cached.load_control_from_wapt(fullpackagepath,calc_md5=False)
                        if entry != cached:
                            result.append(entry)
                    except Exception as e:
                        logger.warning('Unable to get version of cached package %s: %s'%(fullpackagepath,ensure_unicode(e),))
                        result.append(entry)
                else:
                    result.append(entry)
            else:
                logger.debug('check_downloads : Package %s is not available'%p)
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
        """return a list of autorized package signers for this host
        """
        result = []
        for fn in self.public_certs:
            crt = SSLCertificate(fn)
            result.append(crt)
        return result

    def register_computer(self,description=None):
        """Send computer informations to WAPT Server
            if description is provided, updates local registry with new description
        >>> wapt = Wapt()
        >>> s = wapt.register_computer()
        >>>

        """
        if description:
            out = self.run("echo "" | WMIC os set description='%s'" % description.encode(sys.getfilesystemencoding()))
            logger.info(out)

        self.delete_param('uuid')
        inv = self.inventory()
        inv['uuid'] = self.host_uuid
        if self.waptserver:
            return self.waptserver.post('add_host',data = json.dumps(inv))
        else:
            return json.dumps(inv,indent=True)

    def get_last_update_status(self):
        status = json.loads(self.read_param('last_update_status','{"date": "", "running_tasks": [], "errors": [], "upgrades": []}'))
        status['runstatus'] = self.read_param('runstatus','')
        return json.loads(json.dumps(status))

    def update_server_status(self):
        """Send packages and software informations to WAPT Server, don't send dmi

        >>> wapt = Wapt()
        >>> s = wapt.update_server_status()
        >>>
        """
        inv = {'uuid': self.host_uuid}
        inv['wapt'] = self.wapt_status()
        inv['host'] = setuphelpers.host_info()
        inv['softwares'] = setuphelpers.installed_softwares('')
        inv['packages'] = [p.as_dict() for p in self.waptdb.installed(include_errors=True).values()]
        inv['update_status'] = self.get_last_update_status()

        if self.waptserver_available():
            try:
                result = self.waptserver.post('update_host',data=json.dumps(inv))
                logger.info(u'Status on server %s updated properly'%self.waptserver.server_url)
            except Exception as e:
                result = None
                logger.warning(u'Unable to update server status : %s' % ensure_unicode(e))
            # force register if computer has not been registered or hostname has changed
            if not result or not 'host' in result or result['host']['computer_fqdn'] != setuphelpers.get_hostname():
                self.register_computer()
            return result
        else:
            logger.info('WAPT Server is not available to store current host status')
            return False

    def waptserver_available(self):
        """Test reachability of waptserver.

        If waptserver is defined and available, return True, else False

        Returns:
            boolean: True if server is defined and actually reachable
        """
        return self.waptserver and self.waptserver.available()

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
        		'dnsdomain': u'tranquilit.local',
        		'proxies': {
        			'http': None,
        			'https': None
        		},
        		'server_url': 'https: //wapt.tranquilit.local'
        	},
        	'waptservice_protocol': 'http',
        	'repositories': [{
        		'dnsdomain': u'tranquilit.local',
        		'proxies': {
        			'http': None,
        			'https': None
        		},
        		'name': 'global',
        		'repo_url': 'http: //wapt.tranquilit.local/wapt'
        	},
        	{
        		'dnsdomain': u'tranquilit.local',
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
        result['authorized-certificates'] = [dict(crt) for crt in self.authorized_certificates()]

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
        # memory usage
        current_process = psutil.Process()
        result['wapt-memory-usage'] = vars(current_process.memory_info())

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
                host = urlparse(w.waptserver.server_url).hostname
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
            dict: {'host','wapt','dmi','softwares','packages'}
        """
        inv = {}
        inv['host'] = setuphelpers.host_info()
        inv['dmi'] = setuphelpers.dmi_info()
        try:
            inv['wmi'] = setuphelpers.wmi_info()
        except:
            logger.warning('WMI unavailable')
        inv['wapt'] = self.wapt_status()
        inv['softwares'] = setuphelpers.installed_softwares('')
        inv['packages'] = [p.as_dict() for p in self.waptdb.installed(include_errors=True).values()]
        """
        try:
            inv['qfe'] = setuphelpers.installed_windows_updates()
        except:
            pass
        """
        return inv

    def get_repo(self,name):
        for r in self.repositories:
            if r.name == name:
                return r
        return None

    @property
    def private_key_cache(self):
        # lazzy loading of privatekey
        # TODO : check that private key file has not been updated since last loading...
        if not self._private_key_cache:
            self._private_key_cache = SSLPrivateKey(self.private_key,callback=self.key_passwd_callback)
        return self._private_key_cache

    def sign_package(self,zip_or_directoryname,excludes=['.svn','.git','.gitignore','*.pyc','src'],private_key=None,callback=None):
        """Calc the signature of the WAPT/manifest.sha1 file and put/replace it in ZIP or directory.
            if directory, creates WAPT/manifest.sha1 and add it to the content of package
            create a WAPT/signature file and it to directory or zip file.

            known issue : if zip file already contains a manifest.sha1 file, it is not removed, so there will be
                          2 manifest files in zip / wapt package.

        Args:
            zip_or_directoryname: filename or path for the wapt package's content
            excludes: list of patterns to exclude from
            private_key: path to the private key to use for SSL signing.
            callback: ref to the function to call if a password is required for opening the private key.

        Returns:
            str: base64 encoded signature of manifest.sha1 file (content
        """
        if not isinstance(zip_or_directoryname,unicode):
            zip_or_directoryname = unicode(zip_or_directoryname)
        if not callback:
            callback = self.key_passwd_callback
        if not private_key:
            # get the default one, perhaps already cached
            private_key = self.private_key
            if not private_key:
                raise Exception('Private key filename not set in private_key')
            key = self.private_key_cache
        else:
            # specific
            if not os.path.isfile(private_key):
                raise Exception('Private key file %s not found' % private_key)
            key = SSLPrivateKey(private_key,callback=callback)

        # get matching certificate
        try:
            cert = SSLCertificate(key.private_key_filename)
            # try loading x509
            logger.debug('Using identity : %s' % cert.cn)
        except:
            cert = key.matching_certs(os.path.dirname(key.private_key_filename))[-1]
        pe =  PackageEntry().load_control_from_wapt(zip_or_directoryname)
        return pe.sign_package(key,cert)

    def build_package(self,directoryname,inc_package_release=False,excludes=['.svn','.git','.gitignore','*.pyc','src'],
                target_directory=None,
                include_signer=True,
                private_key=None,
                callback=None):
        """Build the WAPT package from a directory

        Call update_control from setup.py if this function is defined.
        Then zip the content of directory. Add a manifest.sha1 file with sha1 hash of
          the content of each file.

        Args:
            directoryname (str): source root directory of package to build
            inc_package_release (boolean): increment the version of package in control file.

        Returns:
            dict: {'filename':waptfilename,'files':[list of files],'package':PackageEntry}
        """
        if not isinstance(directoryname,unicode):
            directoryname = unicode(directoryname)
        result_filename = u''
        if not os.path.isdir(os.path.join(directoryname,'WAPT')):
            raise Exception('Error building package : There is no WAPT directory in %s' % directoryname)
        if not os.path.isfile(os.path.join(directoryname,'WAPT','control')):
            raise Exception('Error building package : There is no control file in WAPT directory')
        if not os.path.isfile(os.path.join(directoryname,'setup.py')):
            raise Exception('Error building package : There is no setup.py file in %s' % directoryname)
        oldpath = sys.path
        try:
            previous_cwd = os.getcwd()
            logger.debug(u'  Change current directory to %s' % directoryname)
            os.chdir(directoryname)
            if not os.getcwd() in sys.path:
                sys.path = [os.getcwd()] + sys.path
                logger.debug(u'new sys.path %s' % sys.path)
            logger.debug(u'Sourcing %s' % os.path.join(directoryname,'setup.py'))
            setup = import_setup(os.path.join(directoryname,'setup.py'))
             # be sure some minimal functions are available in setup module at install step
            logger.debug(u'Source import OK')

            # check minimal requirements of setup.py
            # check encoding
            try:
                codecs.open(os.path.join(directoryname,'setup.py'),mode='r',encoding='utf8')
            except:
                raise Exception('Encoding of setup.py is not utf8')

            if hasattr(setup,'uninstallstring'):
                mandatory = [('install',types.FunctionType) ,('uninstallstring',list),]
            else:
                mandatory = [('install',types.FunctionType) ,('uninstallkey',list),]
            for (attname,atttype) in mandatory:
                if not hasattr(setup,attname):
                    raise Exception('setup.py has no %s (%s)' % (attname,atttype))

            control_filename = os.path.join(directoryname,'WAPT','control')
            force_utf8_no_bom(control_filename)

            entry = PackageEntry()
            logger.info(u'Load control informations from control file')
            entry.load_control_from_wapt(directoryname)

            # to avoid double increment when update_control is used.
            inc_done = False

            # optionally, setup.py can update some attributes of control files using
            # a procedure called update_control(package_entry)
            # this can help automates version maintenance
            # a check of version collision is operated automatically
            if hasattr(setup,'update_control'):
                logger.info(u'Update control informations with update_control function from setup.py file')
                setattr(setup,'run',self.run)
                setattr(setup,'run_notfatal',self.run_notfatal)
                setattr(setup,'user',self.user)
                setattr(setup,'usergroups',self.usergroups)
                setattr(setup,'WAPT',self)
                setattr(setup,'language',self.language or setuphelpers.get_language() )
                setup.update_control(entry)

                if inc_package_release:
                    logger.debug(u'Check existing versions and increment it')
                    older_packages = self.is_available(entry.package)
                    if (older_packages and entry<=older_packages[-1]):
                        entry.version = older_packages[-1].version
                        entry.inc_build()
                        inc_done = True
                        logger.warning(u'Older package with same name exists, incrementing packaging version to %s' % (entry.version,))

                # save control file
                entry.save_control_to_wapt(directoryname)

            # check version syntax
            parse_major_minor_patch_build(entry.version)

            # check architecture
            if not entry.architecture in ArchitecturesList:
                raise Exception(u'Architecture should one of %s' % (ArchitecturesList,))

            # increment inconditionally the package buuld nr.
            if not inc_done and inc_package_release:
                entry.inc_build()

            if include_signer:
                if not callback:
                    callback = self.key_passwd_callback
                else:
                    self.key_passwd_callback = callback

                # use cached key file if not provided
                # the password will be retrieved by the self.key_passwd_callback
                if not private_key:
                    private_key = self.private_key
                    key = self.private_key_cache
                else:
                    # use provided key filename, use provided callback.
                    key = SSLPrivateKey(private_key,callback)

                # find proper certificate
                for fn in self.public_certs:
                    crt = SSLCertificate(fn)
                    if crt.match_key(key):
                        break
                    else:
                        crt = None
                if not crt:
                    raise Exception('No matching certificate found for private key %s'%self.private_key)
                entry.sign_control(key,crt)
                logger.info('Signer: %s'%entry.signer)
                logger.info('Signer fingerprint: %s'%entry.signer_fingerprint)

            if inc_package_release or include_signer:
                entry.save_control_to_wapt(directoryname)

            entry.filename = entry.make_package_filename()
            logger.debug(u'Control data : \n%s' % entry.ascontrol())
            if target_directory is None:
                target_directory = os.path.abspath(os.path.join( directoryname,'..'))

            if not os.path.isdir(target_directory):
                raise Exception('Bad target directory %s for package build' % target_directory)

            result_filename = os.path.abspath(os.path.join(target_directory,entry.filename))
            if os.path.isfile(result_filename):
                logger.info('Target package already exists, removing %s' % result_filename)
                os.unlink(result_filename)

            entry.localpath = target_directory

            allfiles = create_recursive_zip(
                zipfn = result_filename,
                source_root = directoryname,
                target_root = '' ,
                excludes=excludes)
            return {'filename':result_filename,'files':allfiles,'package':entry}

        finally:
            if 'setup' in dir():
                setup_name = setup.__name__
                del setup
                if setup_name in sys.modules:
                    del sys.modules[setup_name]
            sys.path = oldpath
            logger.debug(u'  Change current directory to %s' % previous_cwd)
            os.chdir(previous_cwd)

    def build_upload(self,sources_directories,private_key_passwd=None,wapt_server_user=None,wapt_server_passwd=None,inc_package_release=False,target_directory=None):
        """Build a list of packages and upload the resulting packages to the main repository.
           if section of package is group or host, user specific wapt-host or wapt-group

        Returns
            list of build result dict: {'filename':waptfilename,'files':[list of files],'package':PackageEntry}
        """
        sources_directories = ensure_list(sources_directories)
        buildresults = []

        if not self.private_key or not os.path.isfile(self.private_key):
            raise Exception('Unable to build %s, private key %s not provided or not present'%(sources_directories,self.private_key))

        def pwd_callback(*args):
            """Default password callback for opening private keys"""
            if not isinstance(private_key_passwd,str):
                return private_key_passwd.encode('ascii')
            else:
                return private_key_passwd

        callback = None
        if private_key_passwd is not None:
            callback = pwd_callback

        for source_dir in [os.path.abspath(p) for p in sources_directories]:
            if os.path.isdir(source_dir):
                logger.info(u'Building  %s' % source_dir)
                buildresult = self.build_package(source_dir,inc_package_release=inc_package_release,target_directory=target_directory,callback=callback)
                package_fn = buildresult['filename']
                if package_fn:
                    buildresults.append(buildresult)
                    logger.info(u'...done. Package filename %s' % (package_fn,))
                    logger.info('Signing %s' % package_fn)
                    signature = self.sign_package(package_fn,callback=callback)
                    logger.debug(u"Package %s signed : signature :\n%s" % (package_fn,signature))
                else:
                    logger.critical(u'package %s not created' % package_fn)
            else:
                logger.critical(u'Directory %s not found' % source_dir)

        result = []
        logger.info(u'Uploading files...')
        for buildresult in buildresults:
            upload_res = self.http_upload_package(buildresult['package'],wapt_server_user=wapt_server_user,wapt_server_passwd=wapt_server_passwd)
            result.append(buildresult)
        return result

    def cleanup_session_setup(self):
        """Remove all current user session_setup informations for removed packages
        """
        installed = self.installed(False)
        self.waptsessiondb.remove_obsolete_install_status(installed.keys())

    def session_setup(self,packagename,force=False):
        """Setup the user session for a specific system wide installed package"
           Source setup.py from database or filename
        """
        install_id = None
        old_stdout = sys.stdout
        old_stderr = sys.stderr

        logger.info(u"Session setup for package %s and user %s" % (packagename,self.user))

        oldpath = sys.path

        if os.path.isdir(packagename):
            package_entry = PackageEntry().load_control_from_wapt(packagename)
        else:
            package_entry = self.is_installed(packagename)

        if not package_entry:
            raise Exception('Package %s is not installed' % packagename)

        # initialize a session db for the user
        session_db =  WaptSessionDB(self.user)  # WaptSessionDB()
        with session_db:
            if force or os.path.isdir(packagename) or not session_db.is_installed(package_entry.package,package_entry.version):
                try:
                    previous_cwd = os.getcwd()

                    # source setup.py to get session_setup func
                    if os.path.isdir(packagename):
                        package_fn = os.path.join(packagename,'setup.py')
                        setup = import_setup(package_fn)
                        logger.debug(u'Source import OK from %s' % package_fn)
                    else:
                        logger.debug(u'Sourcing setup from DB (only if session_setup found)')
                        setuppy = package_entry['setuppy']
                        if not setuppy:
                            raise Exception('Source setup.py of package %s not stored in local database' % packagename)
                        if 'session_setup()' in setuppy:
                            setup = import_code(setuppy)
                            logger.debug(u'Source setup.py import OK from database')
                        else:
                            setup = None

                    required_params = []

                     # be sure some minimal functions are available in setup module at install step
                    if setup and hasattr(setup,'session_setup'):
                        logger.info(u'Launch session_setup')
                        # initialize a session record for this package
                        install_id = session_db.add_start_install(package_entry.package,package_entry.version,package_entry.architecture)

                        # redirect output to get print into session db log
                        sys.stderr = sys.stdout = install_output = LogInstallOutput(sys.stderr,session_db,install_id)
                        try:
                            setattr(setup,'run',self.run)
                            setattr(setup,'run_notfatal',self.run_notfatal)
                            setattr(setup,'user',self.user)
                            setattr(setup,'usergroups',self.usergroups)
                            setattr(setup,'control',package_entry)
                            setattr(setup,'WAPT',self)
                            setattr(setup,'language',self.language or setuphelpers.get_language() )

                            # get definitions of required parameters from setup module
                            if hasattr(setup,'required_params'):
                                required_params = setup.required_params

                            # get value of required parameters from system wide install
                            try:
                                params_dict=json.loads(self.waptdb.query("select install_params from wapt_localstatus where package=?",[package_entry.package,])[0]['install_params'])
                            except:
                                logger.warning(u'Unable to get installation parameters from wapt database for package %s' % package_entry.package)
                                params_dict={}

                            # set params dictionary
                            if not hasattr(setup,'params'):
                                # create a params variable for the setup module
                                setattr(setup,'params',params_dict)
                            else:
                                # update the already created params with additional params from command line
                                setup.params.update(params_dict)

                            session_db.update_install_status(install_id,'RUNNING','Launch session_setup()\n')
                            result = setup.session_setup()
                            if result:
                                session_db.update_install_status(install_id,'RETRY','session_setup() done\n')
                            else:
                                session_db.update_install_status(install_id,'OK','session_setup() done\n')
                            return result

                        except Exception as e:
                            if install_id:
                                try:
                                    try:
                                        uerror = repr(e).decode(locale.getpreferredencoding())
                                    except:
                                        uerror = ensure_unicode(e)
                                    session_db.update_install_status(install_id,'ERROR',uerror)
                                except Exception as e2:
                                    logger.critical(ensure_unicode(e2))
                            else:
                                logger.critical(ensure_unicode(e))
                            raise e
                        finally:
                            # restore normal output
                            sys.stdout = old_stdout
                            sys.stderr = old_stderr
                            sys.path = oldpath

                    else:
                        print('No session-setup.')
                finally:
                    # cleanup
                    if 'setup' in dir() and setup is not None:
                        setup_name = setup.__name__
                        logger.debug('Removing module %s'%setup_name)
                        del setup
                        if setup_name in sys.modules:
                            del sys.modules[setup_name]
                    sys.path = oldpath
                    logger.debug(u'  Change current directory to %s.' % previous_cwd)
                    os.chdir(previous_cwd)
            else:
                print('Already installed.')

    def uninstall(self,packagename,params_dict={}):
        """Launch the uninstall script of an installed package"
           Source setup.py from database or filename
        """
        logger.info(u"setup.uninstall for package %s with params %s" % (packagename,params_dict))
        oldpath = sys.path
        try:
            previous_cwd = os.getcwd()
            if os.path.isdir(packagename):
                entry = PackageEntry().load_control_from_wapt(packagename)
                setup = import_setup(os.path.join(packagename,'setup.py'))
            else:
                logger.debug(u'Sourcing setup from DB')
                entry = self.is_installed(packagename)
                setup = import_code(entry['setuppy'])

            required_params = []
             # be sure some minimal functions are available in setup module at install step
            logger.debug(u'Source import OK')
            if hasattr(setup,'uninstall'):
                logger.info('Launch uninstall')
                setattr(setup,'run',self.run)
                setattr(setup,'run_notfatal',self.run_notfatal)
                setattr(setup,'user',self.user)
                setattr(setup,'usergroups',self.usergroups)
                setattr(setup,'control',entry)
                setattr(setup,'WAPT',self)
                setattr(setup,'language',self.language or setuphelpers.get_language() )

                # get value of required parameters if not already supplied
                for p in required_params:
                    if not p in params_dict:
                        if not is_system_user():
                            params_dict[p] = raw_input("%s: " % p)
                        else:
                            raise Exception(u'Required parameters %s is not supplied' % p)

                # set params dictionary
                if not hasattr(setup,'params'):
                    # create a params variable for the setup module
                    setattr(setup,'params',params_dict)
                else:
                    # update the already created params with additional params from command line
                    setup.params.update(params_dict)

                result = setup.uninstall()
                return result
            else:
                logger.debug(u'No uninstall() function in setup.py for package %s' % packagename)
                #raise Exception(u'No uninstall() function in setup.py for package %s' % packagename)
        finally:
            if 'setup' in dir():
                setup_name = setup.__name__
                del setup
                if setup_name in sys.modules:
                    del sys.modules[setup_name]

            sys.path = oldpath
            logger.debug(u'  Change current directory to %s' % previous_cwd)
            os.chdir(previous_cwd)

    def make_package_template(self,installer_path,packagename='',directoryname='',section='',description='',depends=''):
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
        packagename = packagename.lower()
        if installer_path:
            installer_path = os.path.abspath(installer_path)
        if directoryname:
             directoryname = os.path.abspath(directoryname)

        installer = os.path.basename(installer_path)
        uninstallkey = ''

        if not os.path.exists(installer_path):
            raise Exception('The parameter "%s" is neither a file or a directory, it must be the path to a directory, or an .exe or .msi installer' % installer_path)
        if os.path.isfile(installer_path):
            # case of an installer
            props = setuphelpers.getproductprops(installer_path)
            silentflags = setuphelpers.getsilentflags(installer_path)
            # for MSI, uninstallkey is in properties
            if 'ProductCode' in props:
                uninstallkey = '"%s"' % props['ProductCode']
        else:
            # case of a directory
            props = {
                'product':installer,
                'description':installer,
                'version':'0',
                'publisher':ensure_unicode(setuphelpers.get_current_user())
                }
            silentflags = ''

        if not packagename:
            simplename = re.sub(r'[\s\(\)]+','',props['product'].lower())
            packagename = '%s-%s' %  (self.config.get('global','default_package_prefix'),simplename)

        if not directoryname:
            directoryname = self.get_default_development_dir(packagename,section='base')

        if not os.path.isdir(os.path.join(directoryname,'WAPT')):
            os.makedirs(os.path.join(directoryname,'WAPT'))

        template = codecs.open(os.path.join(self.wapt_base_dir,'templates','setup_package_template.py'),encoding='utf8').read()%dict(
            packagename=packagename,
            uninstallkey=uninstallkey,
            silentflags=silentflags,
            installer = installer,
            product=props['product'],
            description=props['description'],
            )
        setuppy_filename = os.path.join(directoryname,'setup.py')
        if not os.path.isfile(setuppy_filename):
            codecs.open(setuppy_filename,'w',encoding='utf8').write(template)
        else:
            logger.info(u'setup.py file already exists, skip create')
        logger.debug(u'Copy installer %s to target' % installer)
        if os.path.isfile(installer_path):
            shutil.copyfile(installer_path,os.path.join(directoryname,installer))
        else:
            setuphelpers.copytree2(installer_path,os.path.join(directoryname,installer))

        control_filename = os.path.join(directoryname,'WAPT','control')
        if not os.path.isfile(control_filename):
            entry = PackageEntry()
            entry.package = packagename
            entry.architecture='all'
            entry.description = description or 'automatic package for %s ' % props['description']
            try:
                entry.maintainer = ensure_unicode(win32api.GetUserNameEx(3))
            except:
                try:
                    entry.maintainer = ensure_unicode(setuphelpers.get_current_user())
                except:
                    entry.maintainer = os.environ['USERNAME']

            entry.priority = 'optional'
            entry.section = section or 'base'
            entry.version = props['version']+'-0'
            entry.depends = depends
            if self.config.has_option('global','default_sources_url'):
                entry.sources = self.config.get('global','default_sources_url') % {'packagename':packagename}
            codecs.open(control_filename,'w',encoding='utf8').write(entry.ascontrol())
        else:
            logger.info(u'control file already exists, skip create')

        self.add_pyscripter_project(directoryname)
        return directoryname

    def make_host_template(self,packagename='',depends=None,directoryname=None,description=None):
        if not packagename:
            packagename = setuphelpers.get_hostname().lower()
        return self.make_group_template(packagename=packagename,depends=depends,directoryname=directoryname,section='host',description=description)

    def make_group_template(self,packagename='',depends=None,directoryname=None,section='group',description=None):
        r"""Build a skeleton of WAPT group package
            depends : list of package dependencies.
           Return the path of the skeleton
        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> tmpdir = 'c:/tmp/dummy'
        >>> if os.path.isdir(tmpdir):
        ...    import shutil
        ...    shutil.rmtree(tmpdir)
        >>> p = wapt.make_group_template(packagename='testgroupe',directoryname=tmpdir,depends='tis-firefox',description=u'Test de groupe')
        >>> print p
        {'target': 'c:\\tmp\\dummy', 'source_dir': 'c:\\tmp\\dummy', 'package': PackageEntry('testgroupe','0')}
        >>> print p['package'].depends
        tis-firefox
        >>> import shutil
        >>> shutil.rmtree(tmpdir)
        """
        packagename = packagename.lower()
        if directoryname:
             directoryname = os.path.abspath(directoryname)

        if not packagename:
            packagename = setuphelpers.get_hostname().lower()
        else:
            packagename = packagename.lower()

        if not directoryname:
            directoryname = self.get_default_development_dir(packagename,section=section)

        if not directoryname:
            directoryname = tempfile.mkdtemp('wapt')

        if not os.path.isdir(os.path.join(directoryname,'WAPT')):
            os.makedirs(os.path.join(directoryname,'WAPT'))
        template_fn = os.path.join(self.wapt_base_dir,'templates','setup_%s_template.py' % section)
        if not os.path.isfile(template_fn):
            raise Exception("setup.py template %s doesn't exist" % template_fn)
        # replacing %(var)s by local values in template
        # so setup template must use other string formating system than % like '{}'.format()
        template = codecs.open(template_fn,encoding='utf8').read() % locals()
        setuppy_filename = os.path.join(directoryname,'setup.py')
        if not os.path.isfile(setuppy_filename):
            codecs.open(setuppy_filename,'w',encoding='utf8').write(template)
        else:
            logger.info(u'setup.py file already exists, skip create')

        control_filename = os.path.join(directoryname,'WAPT','control')
        entry = PackageEntry()
        if not os.path.isfile(control_filename):
            entry.priority = 'standard'
            entry.section = section
            entry.version = '0'
            entry.architecture='all'
            entry.description = description or '%s package for %s ' % (section,packagename)
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
            entry.depends = ','.join([u'%s' % p for p in depends if p and p != packagename ])

        codecs.open(control_filename,'w',encoding='utf8').write(entry.ascontrol())

        self.add_pyscripter_project(directoryname)

        result = {}
        result['package'] = entry
        result['source_dir'] = directoryname
        result['target'] = directoryname
        return result

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
            Return list of matching package entries or empty list
        >>> wapt = Wapt(config_filename='c:/tranquilit/wapt/tests/wapt-get.ini')
        >>> l = wapt.is_available('tis-wapttest')
        >>> l and isinstance(l[0],PackageEntry)
        True
        """
        return self.waptdb.packages_matching(packagename)

    def get_default_development_dir(self,packagecond,section='base'):
        """Returns the default developement directory for package named <packagecond>
           based on default_sources_root and default_sources_suffix ini parameters

        Args:
            packagecond (str): packahe name or pacjage request "name (=version)"

        Returns:
            str: path to local development directory
        """
        packagename = REGEX_PACKAGE_CONDITION.match(packagecond).groupdict()['package']
        default_root = 'c:\\waptdev\\%(package)s-%(suffix)s'
        suffix = self.config.get('global','default_sources_suffix')
        root = self.config.get('global','default_sources_root')
        if not root:
            raise Exception('default_sources_root is empty or not defined')
        if section == 'host':
            if self.config.has_option('global','default_sources_root_host'):
                root = self.config.get('global','default_sources_root_host')

        if not '%(package)s' in root:
            root = os.path.join(root,'%(package)s-%(suffix)s')
        return root % {'package':packagename,'section':section,'suffix':suffix}

    def add_pyscripter_project(self,target_directory):
        """Add a pyscripter project file to package development directory.

        Args:
            target_directory (str): path to location where to create the wa^t.psproj file.

        Returns:
            None
        """
        psproj_filename = os.path.join(target_directory,'WAPT','wapt.psproj')
        if not os.path.isfile(psproj_filename):
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
            ):
        r"""Download an existing package from repositories into target_directory for modification
            if use_local_sources is True and no newer package exists on repos, updates current local edited data
              else if target_directory exists and is not empty, raise an exception
            Return {'target':target_directory,'source_dir':target_directory,'package':package_entry}

        Args:
            packagerequest (str)        : path to existing wapt file, or package request
            use_local_sources (boolean) : don't raise an exception if target exist and match package version

        Returns:
            dict : {'target':target_directory,'source_dir':target_directory,'package':package_entry}


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
        # check if available in repos
        entries = self.is_available(packagerequest)
        if entries:
            entry = entries[-1]
            # the package can be downloaded
            if not target_directory:
                target_directory = self.get_default_development_dir(entry.package,section=entry.section)
            packagename = entry.package
        else:
            # argument is a wapt package
            entry = self.is_wapt_package_file(packagerequest)
            if entry:
                if not target_directory:
                    target_directory = tempfile.mkdtemp(prefix="wapt")
                zip = ZipFile(packagerequest)
                zip.extractall(path=target_directory)
                packagename = entry.package
                packagerequest = entry.asrequirement()
            else:
                raise Exception('%s is neither a package name nor a package filename' % packagerequest)

        append_depends = ensure_list(append_depends)
        remove_depends = ensure_list(remove_depends)
        append_conflicts = ensure_list(append_conflicts)
        remove_conflicts = ensure_list(remove_conflicts)

        local_dev_entry = self.is_wapt_package_development_dir(target_directory)
        if local_dev_entry:
            if use_local_sources:
                if entry > local_dev_entry:
                    raise Exception('A newer package version %s is already in repository "%s", local source %s is %s aborting' % (entry.asrequirement(),entry.repo,target_directory,local_dev_entry.asrequirement()))
                if local_dev_entry.match(packagerequest):
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

                    self.add_pyscripter_project(target_directory)
                    return {'target':target_directory,'source_dir':target_directory,'package':local_dev_entry}
                else:
                    raise Exception('Local target %s directory is the sources of a different package %s than expected %s' % (target_directory,local_dev_entry.asrequirement(),packagerequest))
            else:
                raise Exception('%s wapt developement directory exists' % target_directory)
        if entry:
            # edit an existing package by using
            return self.duplicate_package(packagename=entry.asrequirement(),
                newname=entry.package,
                target_directory=target_directory,
                build=False,
                append_depends = append_depends,
                remove_depends = remove_depends,
                append_conflicts = append_conflicts,
                remove_conflicts = remove_conflicts,
                auto_inc_version = auto_inc_version,
                )
        else:
            # create a new one
            packagename = PackageRequest(packagerequest).package
            return self.duplicate_package(packagename=packagename,
                newname=packagename,
                target_directory=target_directory,
                build=False,
                append_depends = append_depends,
                remove_depends = remove_depends,
                append_conflicts = append_conflicts,
                remove_conflicts = remove_conflicts,
                )

    def is_wapt_package_development_dir(self,directory):
        """Return PackageEntry if directory is a wapt developement directory (a WAPT/control file exists) or False"""
        return os.path.isfile(os.path.join(directory,'WAPT','control')) and PackageEntry().load_control_from_wapt(directory,calc_md5=False)

    def is_wapt_package_file(self,filename):
        """Return PackageEntry if filename is a wapt package or False"""
        (root,ext)=os.path.splitext(filename)
        if ext != '.wapt' or not os.path.isfile(filename):
            return False
        try:
            entry = PackageEntry().load_control_from_wapt(filename,calc_md5=False)
            return entry
        except:
            return False

    def edit_host(self,hostname,target_directory='',use_local_sources=True,
            append_depends=None,
            remove_depends=None,
            append_conflicts=None,
            remove_conflicts=None,
            printhook=None,
            description=None):
        """Download and extract a host package from host repositories into target_directory for modification
                Return dict {'target': 'c:\\\\tmp\\\\dummy', 'source_dir': 'c:\\\\tmp\\\\dummy', 'package': "dummy.tranquilit.local (=0)"}

           hostname          : fqdn of the host to edit
           target_directory  : where to place the developments files. if empty, use default one from wapt-get.ini configuration
           use_local_sources : don't raise an exception if local sources are newer or same than repo version
           append_depends    : list or comma separated list of package requirements
           remove_depends    : list or comma separated list of package requirements to remove

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> tmpdir = 'c:/tmp/dummy'
        >>> wapt.edit_host('dummy.tranquilit.local',target_directory=tmpdir,append_depends='tis-firefox')
        {'target': 'c:\\\\tmp\\\\dummy', 'source_dir': 'c:\\\\tmp\\\\dummy', 'package': PackageEntry('dummy.tranquilit.local','0')}
        >>> import shutil
        >>> shutil.rmtree(tmpdir)
        >>> host = wapt.edit_host('htlaptop.tranquilit.local',target_directory=tmpdir,append_depends='tis-firefox')
        >>> 'package' in host
        True
        >>> shutil.rmtree(tmpdir)
        """
        if not target_directory:
            target_directory = self.get_default_development_dir(hostname,section='host')

        self.use_hostpackages = True

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

        # check if host package exists on repos
        if self.repositories and isinstance(self.repositories[-1],WaptHostRepo):
            (entry,entry_date) = self.repositories[-1].update_host(hostname,self.waptdb,public_certs=self.public_certs)
            if entry:
                # target is already an "in-progress" package developement
                local_dev_entry = self.is_wapt_package_development_dir(target_directory)
                if local_dev_entry:
                    # use the current local development
                    if use_local_sources:
                        if entry>local_dev_entry:
                            raise Exception('A newer package version %s is already in repository "%s", local sources %s is %s, aborting' % (entry.asrequirement(),entry.repo,target_directory, local_dev_entry.asrequirement()))
                        if local_dev_entry.match(hostname):
                            # update depends list
                            prev_depends = ensure_list(local_dev_entry.depends)
                            for d in append_depends:
                                if not d in prev_depends:
                                    prev_depends.append(d)
                            for d in remove_depends:
                                if d in prev_depends:
                                    prev_depends.remove(d)
                            local_dev_entry.depends = ','.join(prev_depends)

                            # update conflicts list
                            prev_conflicts = ensure_list(local_dev_entry.conflicts)
                            for d in append_conflicts:
                                if not d in prev_conflicts:
                                    prev_conflicts.append(d)
                            if remove_conflicts:
                                for d in remove_conflicts:
                                    if d in prev_conflicts:
                                        prev_conflicts.remove(d)
                            local_dev_entry.conflicts = ','.join(prev_conflicts)
                            if description is not None:
                                local_dev_entry.description = description

                            local_dev_entry.save_control_to_wapt(target_directory)
                            self.add_pyscripter_project(target_directory)
                            return {'target':target_directory,'source_dir':target_directory,'package':local_dev_entry}
                        else:
                            raise Exception('Local target %s directory is the sources of a different package %s than expected %s' % (target_directory,local_dev_entry.package,hostname))
                    else:
                        raise Exception('directory %s is already a package development directory, aborting.' % target_directory)
                elif os.path.isdir(target_directory) and os.listdir(target_directory):
                    raise Exception('directory %s is not empty, aborting.' % target_directory)
                # create a new version of the existing package in repository
                return self.duplicate_package(
                        packagename=hostname,
                        newname=hostname,
                        target_directory=target_directory,
                        build=False,
                        append_depends = append_depends,
                        remove_depends = remove_depends,
                        append_conflicts = append_conflicts,
                        remove_conflicts = remove_conflicts,
                        usecache=False,
                        printhook=printhook)
            elif os.path.isdir(target_directory) and os.listdir(target_directory):
                raise Exception('directory %s is not empty, aborting.' % target_directory)
            else:
                # create new host package from template
                return self.make_host_template(packagename=hostname,directoryname=target_directory,depends=append_depends,description=description)
        else:
            raise Exception('No Wapthost repository defined')

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
            target_directory=None,
            build=True,
            excludes=['.svn','.git','.gitignore','*.pyc','src'],
            private_key=None,
            callback=pwd_callback,
            append_depends=None,
            remove_depends=None,
            append_conflicts=None,
            remove_conflicts=None,
            auto_inc_version=True,
            usecache=True,
            printhook=None):
        """Duplicate an existing package.

        Duplicate an existing package from declared repostory or file into targetdirectory with
          optional newname and version.

        Args:
            newname (str):           name of target package
            newversion (str):        version of target package. if None, use source package version
            target_directory (str):  path where to put development files. If None, use temporary. If empty, use default development dir
            build (bool):            If True, build and sign the package. The filename of build package will be in 'target' key of result
            callback (func):         function to get rawbytes password of private key
            append_depends (list):   comma str or list of depends to append.
            remove_depends (list):   comma str or list of depends to remove.
            auto_inc_version (bool): if version is less than existing package in repo, set version to repo version+1
            usecache (bool):         If True, allow to use cached package in local repo instead of downloading it.
            printhook (func):        hook for download progress

        Returns:
            dict: {'target':new package if build, or 'source_dir':new source directory if not build ,'package':new PackageEntry}

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
        ...     build=False,
        ...     excludes=['.svn','.git','.gitignore','*.pyc','src'],
        ...     private_key=None,
        ...     callback=pwd_callback,
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
        ...    build=True,
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
            newname = newname.lower()
            while newname.endswith('.wapt'):
                dot_wapt = newname.rfind('.wapt')
                newname = newname[0:dot_wapt]
                logger.warning("Target ends with '.wapt', stripping.  New name: %s", newname)

        if not private_key:
            private_key = self.private_key

        if build:
            if not private_key or not os.path.isfile(private_key) :
                raise Exception('Would be unable to build %s after duplication, private key %s not provided or not present'%(packagename,private_key))

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
                    raise Exception('Target directory "%s" is not empty and contains either another package or a newer version, aborting.' % target_directory)

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
            logger.info(u'  unzipping %s to directory %s' % (source_filename,target_directory))
            zip = ZipFile(source_filename,allowZip64=True)
            zip.extractall(path=target_directory)
        else:
            source_package = self.is_available(packagename)
            if not source_package:
                raise Exception('Package %s is not available is current repositories.'%(packagename,))
            # duplicate package from a repository
            filenames = self.download_packages([packagename],usecache=usecache,printhook=printhook)
            package_paths = filenames['downloaded'] or filenames['skipped']
            if not package_paths:
                raise Exception('Unable to download package %s'%(packagename,))
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
            logger.info(u'  unzipping %s to directory %s' % (source_filename,target_directory))
            zip = ZipFile(source_filename,allowZip64=True)
            zip.extractall(path=target_directory)

        # duplicate package informations
        dest_control = PackageEntry()
        for a in source_control.required_attributes + source_control.optional_attributes:
            if not a in source_control.not_duplicated_attributes:
                dest_control[a] = source_control[a]

        # reset sources URL
        if newname and source_control.package != newname:
            dest_control['sources']= ''

        # add / remove dependencies from copy
        prev_depends = ensure_list(dest_control.depends)
        for d in append_depends:
            if not d in prev_depends:
                prev_depends.append(d)
        for d in remove_depends:
            if d in prev_depends:
                prev_depends.remove(d)
        dest_control.depends = ','.join(prev_depends)

        # add / remove conflicts from copy
        prev_conflicts = ensure_list(dest_control.conflicts)
        for d in append_conflicts:
            if not d in prev_conflicts:
                prev_conflicts.append(d)

        for d in remove_conflicts:
            if d in prev_conflicts:
                prev_conflicts.remove(d)
        dest_control.conflicts = ','.join(prev_conflicts)

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

        self.add_pyscripter_project(target_directory)

        # remove manifest and signature
        manifest_filename = os.path.join( target_directory,'WAPT','manifest.sha1')
        if os.path.isfile(manifest_filename):
            os.unlink(manifest_filename)

        # remove signature of manifest
        signature_filename = os.path.join( target_directory,'WAPT','signature')
        if os.path.isfile(signature_filename):
            os.unlink(signature_filename)

        # build package
        if build:
            build_res = self.build_package(target_directory,inc_package_release=False,excludes=excludes)
            result['target'] = build_res['filename']
            result['package'] = build_res['package']
            # sign package
            if private_key:
                self.sign_package(build_res['filename'],excludes=excludes,private_key=private_key,callback=callback)
                logger.debug(u'Package signed')
            else:
                logger.warning(u'No private key provided, package is not signed !')
            # cleanup
            if os.path.isdir(target_directory):
                shutil.rmtree(target_directory)
        else:
            result['source_dir'] = target_directory
            result['target'] = target_directory
            result['package'] = dest_control
        return result

    def check_waptupgrades(self):
        """Check if a new version of the Wapt client is available
            return url and version if newer
            return None if no update
        """
        if self.config.has_option('global','waptupgrade_url'):
            upgradeurl = self.config.get('global','waptupgrade_url')
        raise NotImplemented()

    def packages_add_depends(packages,append_depends):
        """ Add a list of dependencies to existing packages, inc version and build-upload
            packages : list of package names
            append_depends : list of dependencies packages
        """
        raise NotImplementedError()

    def setup_tasks(self):
        """Setup cron job on windows for update and download-upgrade"""
        result = []
        # update and download new packages
        if setuphelpers.task_exists('wapt-update'):
            setuphelpers.delete_task('wapt-update')
        if self.config.has_option('global','waptupdate_task_period'):
            task = setuphelpers.create_daily_task(
                'wapt-update',
                sys.argv[0],
                '--update-packages download-upgrade',
                max_runtime=int(self.config.get('global','waptupdate_task_maxruntime')),
                repeat_minutes=int(self.config.get('global','waptupdate_task_period')))
            result.append('%s : %s' % ('wapt-update',task.GetTriggerString(0)))

        # upgrade of packages
        if setuphelpers.task_exists('wapt-upgrade'):
            setuphelpers.delete_task('wapt-upgrade')
        if self.config.has_option('global','waptupgrade_task_period'):
            task = setuphelpers.create_daily_task(
                'wapt-upgrade',
                sys.argv[0],
                '--update-packages upgrade',
                max_runtime=int(self.config.get('global','waptupgrade_task_maxruntime')),
                repeat_minutes= int(self.config.get('global','waptupgrade_task_period')))
            result.append('%s : %s' % ('wapt-upgrade',task.GetTriggerString(0)))
        return '\n'.join(result)

    def enable_tasks(self):
        """Enable Wapt automatic update/upgrade scheduling through windows scheduler"""
        result = []
        if setuphelpers.task_exists('wapt-upgrade'):
            setuphelpers.enable_task('wapt-upgrade')
            result.append('wapt-upgrade')
        if setuphelpers.task_exists('wapt-update'):
            setuphelpers.enable_task('wapt-update')
            result.append('wapt-update')
        return result

    def disable_tasks(self):
        """Disable Wapt automatic update/upgrade scheduling through windows scheduler"""
        result = []
        if setuphelpers.task_exists('wapt-upgrade'):
            setuphelpers.disable_task('wapt-upgrade')
            result.append('wapt-upgrade')
        if setuphelpers.task_exists('wapt-update'):
            setuphelpers.disable_task('wapt-update')
            result.append('wapt-update')
        return result

    def write_param(self,name,value):
        """Store in local db a key/value pair for later use"""
        self.waptdb.set_param(name,value)

    def read_param(self,name,default=None):
        """read a param value from local db
        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> wapt.read_param('db_version')
        u'20140410'
        """
        return self.waptdb.get_param(name,default)

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
        packages_names is either a list or a string
        return a dictionnary with {'packages':[],'missing':[]}
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
        """Called whenever the network configuration has changed"""
        try:
            for repo in self.repositories:
                repo.reset_network()
            if not self.disable_update_server_status and self.waptserver_available():
                self.update_server_status()
        except Exception as e:
            logger.warning(u'Problème lors du changement de réseau : %s'%ensure_unicode(e))

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
    r""" return localized version of domain admin group (ie "domain admins" or
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
    """ check if a user is a member of a group
    huser : handle pywin32
    group_name : group as a string
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
    """ check if a user is a member of a group
    user_name: user as a string
    password: as a string
    domain_name : as a string. If empty, check local then domain
    group_name : group as a string
    >>> from win32security import LogonUser
    >>> hUser = win32security.LogonUser ('technique','tranquilit','xxxxxxx',win32security.LOGON32_LOGON_NETWORK,win32security.LOGON32_PROVIDER_DEFAULT)
    >>> check_is_member_of(hUser,'domain admins')
    False
    """
    try:
        sid, system, type = win32security.LookupAccountName(None,group_name)
    except pywintypes.error as e:
        if e.args[0] == 1332:
            logger.warning('"%s" is not a valid group name'%group_name)
            return False
        else:
            raise
    huser = win32security.LogonUser(user_name,domain_name,password,win32security.LOGON32_LOGON_NETWORK,win32security.LOGON32_PROVIDER_DEFAULT)
    return win32security.CheckTokenMembership(huser, sid)

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
