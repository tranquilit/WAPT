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

import os
import subprocess
import re
import logging
import datetime
import time
import sys
import pprint
import zipfile
import tempfile
import hashlib
import glob
import codecs
import sqlite3
import json
import StringIO
import urllib2
import fnmatch
import platform
import imp
import socket
import dns.resolver
from waptpackage import *

import shlex
from iniparse import RawConfigParser
from collections import namedtuple
from types import ModuleType

import shutil
import win32api
from _winreg import HKEY_LOCAL_MACHINE,EnumKey,OpenKey,QueryValueEx,EnableReflectionKey,DisableReflectionKey,QueryReflectionKey,QueryInfoKey,KEY_READ,KEY_WOW64_32KEY,KEY_WOW64_64KEY

import re
import setuphelpers

__version__ = "0.0.3"

logger = logging.getLogger()

def datetime2isodate(adatetime = datetime.datetime.now()):
    assert(isinstance(adatetime,datetime.datetime))
    return adatetime.isoformat()

def isodate2datetime(isodatestr):
    # we remove the microseconds part as it is not working for python2.5 strptime
    return datetime.datetime.strptime(isodatestr.split('.')[0] , "%Y-%m-%dT%H:%M:%S")

def time2display(adatetime):
    return adatetime.strftime("%Y-%m-%d %H:%M")

def hours_minutes(hours):
    if hours is None:
        return None
    else:
        return "%02i:%02i" % ( int(hours) , int((hours - int(hours)) * 60.0))

def fileisodate(filename):
    return datetime.datetime.fromtimestamp(os.stat(filename).st_mtime).isoformat()

def dateof(adatetime):
    return adatetime.replace(hour=0,minute=0,second=0,microsecond=0)

#####################################
# http://code.activestate.com/recipes/498181-add-thousands-separator-commas-to-formatted-number/
# Code from Michael Robellard's comment made 28 Feb 2010
# Modified for leading +, -, space on 1 Mar 2010 by Glenn Linderman
#
# Tail recursion removed and  leading garbage handled on March 12 2010, Alessandro Forghieri
def splitThousands( s, tSep=',', dSep='.'):
    '''Splits a general float on thousands. GIGO on general input'''
    if s == None:
        return 0
    if not isinstance( s, str ):
        s = str( s )

    cnt=0
    numChars=dSep+'0123456789'
    ls=len(s)
    while cnt < ls and s[cnt] not in numChars: cnt += 1

    lhs = s[ 0:cnt ]
    s = s[ cnt: ]
    if dSep == '':
        cnt = -1
    else:
        cnt = s.rfind( dSep )
    if cnt > 0:
        rhs = dSep + s[ cnt+1: ]
        s = s[ :cnt ]
    else:
        rhs = ''

    splt=''
    while s != '':
        splt= s[ -3: ] + tSep + splt
        s = s[ :-3 ]

    return lhs + splt[ :-1 ] + rhs

"""
def call_external_process(shell_string):
    p = subprocess.call(shell_string, shell=True)
    if (p != 0 ):
        raise Exception('shell program exited with error code ' + str(p), shell_string)

def check_string(test_string):
    pattern = r'[^\.A-Za-z0-9\-_]'
    if re.search(pattern, test_string):
        #Character other then . a-z 0-9 was found
        print 'Invalid : %r' % (test_string,)
"""

def convert_bytes(bytes):
    if bytes is None:
        return None
    else:
        bytes = float(bytes)
        if bytes >= 1099511627776:
            terabytes = bytes / 1099511627776
            size = '%.2fT' % terabytes
        elif bytes >= 1073741824:
            gigabytes = bytes / 1073741824
            size = '%.2fG' % gigabytes
        elif bytes >= 1048576:
            megabytes = bytes / 1048576
            size = '%.2fM' % megabytes
        elif bytes >= 1024:
            kilobytes = bytes / 1024
            size = '%.2fK' % kilobytes
        else:
            size = '%.2fb' % bytes
        return size

## {{{ http://code.activestate.com/recipes/81189/ (r2)
def pptable(cursor, data=None, rowlens=0, callback=None):
    """
    pretty print a query result as a table
    callback is a function called for each field (fieldname,value) to format the output
    """
    def defaultcb(fieldname,value):
        return value

    if not callback:
        callback = defaultcb

    d = cursor.description
    if not d:
        return "#### NO RESULTS ###"
    names = []
    lengths = []
    rules = []
    if not data:
        data = cursor.fetchall()
    for dd in d:    # iterate over description
        l = dd[1]
        if not l:
            l = 12             # or default arg ...
        l = max(l, len(dd[0])) # handle long names
        names.append(dd[0])
        lengths.append(l)
    for col in range(len(lengths)):
        if rowlens:
            rls = [len(row[col]) for row in data if row[col]]
        lengths[col] = max([lengths[col]]+rls)
        rules.append("-"*lengths[col])

    format = u" ".join(["%%-%ss" % l for l in lengths])
    result = [format % tuple(names)]
    result.append(format % tuple(rules))
    for row in data:
        row_cb=[]
        for col in range(len(d)):
            row_cb.append(callback(d[col][0],row[col]))
        result.append(format % tuple(row_cb))
    return u"\n".join(result)
## end of http://code.activestate.com/recipes/81189/ }}}

def ppdicttable(alist, columns = [], callback=None):
    """
    pretty print a list of dict as a table
    columns is an ordered list of (fieldname,width)
    callback is a function called for each field (fieldname,value) to format the output
    """
    def defaultcb(fieldname,value):
        return value

    if not callback:
        callback = defaultcb

    if not alist:
        return "#### NO RESULTS ###"

    lengths = [c[1] for c in columns]
    names = [c[0] for c in columns]
    rules = []
    for col in range(len(lengths)):
        rules.append("-"*lengths[col])

    format = u" ".join(["%%-%ss" % l for l in lengths])
    result = [format % tuple(names)]
    result.append(format % tuple(rules))
    for row in alist:
        row_cb=[]
        for (name,width)in columns:
            if isinstance(row,dict):
                row_cb.append(callback(name,row.get(name,None)))
            else:
                row_cb.append(callback(name,getattr(row,name,None)))
        result.append(format % tuple(row_cb))
    return u"\n".join(result)
## end of http://code.activestate.com/recipes/81189/ }}}

def html_table(cur,callback=None):
    """
        cur est un cursor issu d'une requete
        callback est une fonction qui prend (rowmap,fieldname,value)
        et renvoie une representation texte
    """
    def safe_unicode(iso):
        if iso is None:
            return None
        elif isinstance(iso, str):
            return iso.decode('iso8859')
        else:
            return iso

    def itermap(cur):
        for row in cur:
            yield dict((cur.description[idx][0], value)
                       for idx, value in enumerate(row))

    head=u"<tr>"+"".join(["<th>"+c[0]+"</th>" for c in cur.description])+"</tr>"
    lines=""
    if callback:
        for r in itermap(cur):
            lines=lines+"<tr>"+"".join(["<td>"+str(callback(r,c[0],safe_unicode(r[c[0]])))+"</td>" for c in cur.description])+"</tr>"
    else:
        for r in cur:
            lines=lines+"<tr>"+"".join(["<td>"+safe_unicode(c)+"</td>" for c in r])+"</tr>"

    return "<table border=1  cellpadding=2 cellspacing=0>%s%s</table>" % (head,lines)

def sha1_for_file(fname, block_size=2**20):
    f = open(fname,'rb')
    sha1 = hashlib.sha1()
    while True:
        data = f.read(block_size)
        if not data:
            break
        sha1.update(data)
    return sha1.hexdigest()

def pwd_callback(*args):
    """Default password callback for opening private keys"""
    import getpass
    return getpass.getpass('Private key password :').encode('ascii')

def ssl_sign_content(content,private_key,callback=pwd_callback):
    """ Sign content with the private_key, return the signature"""
    assert os.path.isfile(private_key)
    from M2Crypto import EVP
    key = EVP.load_key(private_key,callback=callback)
    key.sign_init()
    key.sign_update(content)
    signature = key.sign_final()
    return signature

def ssl_verify_content(content,signature,public_cert):
    """Check that the signature matches the content, using the provided publoc key
        toto : check that the public key is valid....
    """
    assert isinstance(signature,str)
    assert isinstance(public_cert,str) or isinstance(public_cert,unicode)
    if not os.path.isfile(public_cert):
        raise Exception('Public certificate %s not found' % public_cert)
    from M2Crypto import EVP, X509
    rsa = X509.load_cert(public_cert).get_pubkey().get_rsa()
    pubkey = EVP.PKey()
    pubkey.assign_rsa(rsa)
    pubkey.verify_init()
    pubkey.verify_update(content)
    return pubkey.verify_final(signature) == 1

def create_recursive_zip_signed(zipfn, source_root, target_root = u"",excludes = [u'.svn',u'.git*',u'*.pyc',u'*.dbg',u'src']):
    """Create a zip file with filename zipf from source_root directory with target_root as new root.
       Don't include file which match excludes file pattern
       add a file WAPT/manifest.sha1 with sha1 hash of all files
       add a file WAPT/signature with the bas64 encoded signature of WAPT/manifest.sha1
    """
    result = []
    if not isinstance(source_root,unicode):
        source_root = unicode(source_root)
    if not isinstance(source_root,unicode):
        source_root = unicode(source_root)

    if isinstance(zipfn,str) or isinstance(zipfn,unicode):
        if logger: logger.debug('Create zip file %s' % zipfn)
        zipf = zipfile.ZipFile(zipfn,'w')
    elif isinstance(zipfn,zipfile.ZipFile):
        zipf = zipfn
    else:
        raise Exception('zipfn must be either a filename (string) or an zipfile.ZipFile')
    for item in os.listdir(source_root):
        excluded = False
        for x in excludes:
            excluded = fnmatch.fnmatch(item,x)
            if excluded:
                break
        if excluded:
            continue
        if os.path.isfile(os.path.join(source_root, item)):
            if logger: logger.debug(' adding file %s' % os.path.join(source_root, item))
            zipf.write(os.path.join(source_root, item), os.path.join(target_root,item))
            result.append([os.path.join(target_root,item),sha1_for_file(os.path.join(source_root, item))])
        elif os.path.isdir(os.path.join(source_root, item)):
            if logger: logger.debug('Add directory %s' % os.path.join(source_root, item))
            result.extend(create_recursive_zip_signed(zipf, os.path.join(source_root, item), os.path.join(target_root,item),excludes))
    if isinstance(zipfn,str) or isinstance(zipfn,unicode):
        if logger:
            logger.debug('  adding sha1 hash for all %i files' % len(result))
        # Write a file with all sha1 hashes of all files
        manifest = [ r for r in result if r[0] not in ('WAPT\\manifest.sha1','WAPT\\signature') ]
        manifest_data = json.dumps(manifest,indent=True)
        zipf.writestr(os.path.join(target_root,'WAPT/manifest.sha1'), manifest_data)
        zipf.close()
    return result

def get_manifest_data(source_root, target_root=u'', excludes = [u'.svn',u'.git*',u'*.pyc',u'*.dbg',u'src']):
    """Return a list of [filenames,sha1 hash] from files from source_root directory with target_root as new root.
       Don't include file which match excludes file pattern
    """
    result = []
    for item in os.listdir(source_root):
        excluded = False
        for x in excludes:
            excluded = fnmatch.fnmatch(item,x)
            if excluded:
                break
        if target_root == 'WAPT' and item in ('manifest.sha1','signature'):
            excluded = True
        if excluded:
            continue
        if os.path.isfile(os.path.join(source_root, item)):
            result.append([os.path.join(target_root,item),sha1_for_file(os.path.join(source_root, item))])
        elif os.path.isdir(os.path.join(source_root, item)):
            result.extend(get_manifest_data(os.path.join(source_root, item), os.path.join(target_root,item),excludes))
    return result


def import_code(code,name,add_to_sys_modules=0):
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

    module = imp.new_module(name)

    exec code in module.__dict__
    if add_to_sys_modules:
        sys.modules[name] = module

    return module


def import_setup(setupfilename,modulename=''):
    """Import setupfilename as modulename, return the module object"""
    mod_name,file_ext = os.path.splitext(os.path.split(setupfilename)[-1])
    if not modulename:
        modulename=mod_name
    py_mod = imp.load_source(modulename, setupfilename)
    return py_mod

def remove_encoding_declaration(source):
    headers = source.split('\n',3)
    result = []
    for h in headers[0:3]:
        result.append(h.replace('coding:','coding is').replace('coding=','coding is'))
    result.extend(headers[3:])
    return "\n".join(result)


###########################"
class LogInstallOutput(object):
    """file like to log print output to db installstatus"""
    def __init__(self,console,waptdb,rowid):
        self.output = []
        self.console = console
        self.waptdb = waptdb
        self.rowid = rowid

    def write(self,txt):
        self.console.write(txt)
        if txt <> '\n':
            try:
                txt = txt.decode('utf8')
            except:
                try:
                    txt = txt.decode('iso8859')
                except:
                    pass
            self.output.append(txt)
            if txt and txt[-1]<>'\n':
                txtdb = txt+'\n'
            else:
                txtdb = txt
            self.waptdb.update_install_status(self.rowid,'RUNNING',txtdb if not txtdb == None else None)

    def __getattrib__(self, name):
        if hasattr(self.console,'__getattrib__'):
            return self.console.__getattrib__(name)
        else:
            return self.console.__getattribute__(name)

###########
def reg_openkey_noredir(key, sub_key, sam=KEY_READ):
    try:
        if platform.machine() == 'AMD64':
            return OpenKey(key,sub_key,0, sam | KEY_WOW64_64KEY)
        else:
            return OpenKey(key,sub_key,0,sam)
    except WindowsError,e:
        if e.errno == 2:
            raise WindowsError(e.errno,'The key %s can not be opened' % sub_key)

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

def get_domain_fromregistry():
    key = OpenKey(HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters")
    try:
        (domain,atype) = QueryValueEx(key,'DhcpDomain')
    except:
        (domain,atype) = QueryValueEx(key,'Domain')
    return domain

def tryurl(url):
    try:
        logger.debug('  trying %s' % url)
        urllib2.urlopen(url)
        logger.debug('  OK')
        return True
    except Exception,e:
        logger.debug('  Not available : %s' % e)
        return False

PackageKey = namedtuple('package',('packagename','version'))

# tables : old_table_name:[newtablename,{dict of changed field names}]
db_upgrades = {
 ('0000','20130327'):{
        'wapt_localstatus':['wapt_localstatus',{
            'Package':'package',
            'Version':'version',
            'Architecture':'architecture',
            'InstallDate':'install_date',
            'InstallStatus':'install_status',
            'InstallOutput':'install_output',
            'InstallParams':'install_params',
            'UninstallString':'uninstall_string',
            'UninstallKey':'uninstall_key',
            }],
        'wapt_repo':['wapt_package',{
            'Package':'package',
            'Version':'version',
            'Architecture':'architecture',
            'Section':'section',
            'Priority':'priority',
            'Maintainer':'maintainer',
            'Description':'description',
            'Filename':'filename',
            'Size':'size',
            'MD5sum':'md5sum',
            'Depends':'depends',
            'Sources':'sources',
            }],
        },
 ('0000','20130408'):{
        'wapt_localstatus':['wapt_localstatus',{
            'Package':'package',
            'Version':'version',
            'Architecture':'architecture',
            'InstallDate':'install_date',
            'InstallStatus':'install_status',
            'InstallOutput':'install_output',
            'InstallParams':'install_params',
            'UninstallString':'uninstall_string',
            'UninstallKey':'uninstall_key',
            }],
        'wapt_repo':['wapt_package',{
            'Package':'package',
            'Version':'version',
            'Architecture':'architecture',
            'Section':'section',
            'Priority':'priority',
            'Maintainer':'maintainer',
            'Description':'description',
            'Filename':'filename',
            'Size':'size',
            'MD5sum':'md5sum',
            'Depends':'depends',
            'Sources':'sources',
            }],
        },
 ('20130327','20130408'):{
        },
    }



class WaptDB(object):
    """Class to manage SQLite database with local installation status"""
    dbpath = ''
    db = None

    curr_db_version = '20130408'

    def __init__(self,dbpath):
        self._db_version = None
        self.dbpath = dbpath
        if not os.path.isfile(self.dbpath):
            dirname = os.path.dirname(self.dbpath)
            if os.path.isdir (dirname)==False:
                os.makedirs(dirname)
            os.path.dirname(self.dbpath)
            self.db=sqlite3.connect(self.dbpath,detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
            self.initdb()
            self.db.commit()
        else:
            self.db=sqlite3.connect(self.dbpath,detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if not value:
            self.db.commit()
            self.db.close()
            logger.debug('DB commit')
        else:
            self.db.rollback()
            self.db.close()
            logger.critical('DB error %s, rollbacking\n' % (value,))

    def upgradedb(self):
        """Update local database structure to current version if rules are described in db_upgrades"""
        try:
            backupfn = ''
            old_structure_version = self.db_version
            if old_structure_version >= self.curr_db_version:
                logger.critical('upgrade db aborted : current structure version %s is newer or equal to requested structure version %s' % (old_structure_version,self.curr_db_version))
                return (old_structure_version,old_structure_version)

            if not (old_structure_version,self.curr_db_version) in db_upgrades:
                raise Exception('Unable to upgrade DB from version %s to version %s, no rules' % (old_structure_version,self.curr_db_version))
            logger.info('Upgrade database schema')
            # we will backup old data in a file so that we can rollback
            backupfn = os.path.join(os.path.dirname(self.dbpath),time.strftime('%Y%m%d-%H%M%S')+'.sqlite')
            logger.debug(' copy old data to %s' % backupfn)
            shutil.copy(self.dbpath,backupfn)

            # we will backup old data in dictionaries to convert them to new structure
            logger.debug(' backup data in memory')
            old_datas = {}
            tables = [ c[0] for c in self.db.execute('SELECT name FROM sqlite_master WHERE type = "table" and name like "wapt_%"').fetchall()]
            for tablename in tables:
                old_datas[tablename] = self.query('select * from %s' % tablename)
                logger.debug(' %s table : %i records' % (tablename,len(old_datas[tablename])))

            logger.debug(' drop tables')
            for tablename in tables:
                self.db.execute('drop table if exists %s' % tablename)

            # create new empty structure
            logger.debug(' recreates new tables ')
            new_structure_version = self.initdb()

            # append old data in new tables
            logger.debug(' fill with old data')
            for tablename in tables:
                if old_datas[tablename]:
                    logger.debug(' process table %s' % tablename)
                    # get rules from db_upgrades dict
                    (newtablename,newfieldnames) = db_upgrades[(old_structure_version,new_structure_version)].get(tablename,[tablename,{}])

                    allnewcolumns = [ c[0] for c in self.db.execute('select * from %s limit 0' % newtablename).description]
                    # take only old columns which match a new column in new structure
                    oldcolumns = [ k for k in old_datas[tablename][0].keys() if newfieldnames.get(k,k) in allnewcolumns ]
                    logger.debug(' old columns %s' % (oldcolumns,))
                    newcolumns = [ newfieldnames.get(k,k) for k in oldcolumns ]
                    logger.debug(' new columns %s' % (newcolumns,))

                    insquery = "insert into %s (%s) values (%s)" % (newtablename,",".join(newcolumns),",".join("?" * len(newcolumns)))
                    for rec in old_datas[tablename]:
                        print rec
                        logger.debug(' %s' %[ rec[oldcolumns[i]] for i in range(0,len(oldcolumns))])
                        self.db.execute(insquery,[ rec[oldcolumns[i]] for i in range(0,len(oldcolumns))] )

            # be sure to put back new version in table as db upgrade has put the old value in table
            self.db_version = new_structure_version
            self.db.commit()
            return (old_structure_version,new_structure_version)
        except Exception,e:
            self.db.rollback()
            if backupfn:
                logger.critical("UpgradeDB ERROR : %s, copy back backup database %s" % (e,backupfn))
                shutil.copy(backupfn,self.dbpath)
            raise

    def initdb(self):
        """Initialize curretn sqlite db with empty table and return structure version"""
        assert(isinstance(self.db,sqlite3.Connection))
        logger.debug('Initialize Wapt database')
        self.db.execute("""
        create table wapt_package (
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
          sources varchar(255),
          repo_url varchar(255)
          )"""
                        )
        self.db.execute("""
        create index idx_package_name on wapt_package(package);""")

        self.db.execute("""
        create table wapt_localstatus (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          package varchar(255),
          version varchar(255),
          architecture varchar(255),
          install_date varchar(255),
          install_status varchar(255),
          install_output TEXT,
          install_params VARCHAR(800),
          uninstall_string varchar(255),
          uninstall_key varchar(255),
          setuppy TEXT
          )"""
                        )
        self.db.execute("""
        create index idx_localstatus_name on wapt_localstatus(package);""")

        self.db.execute("""
        create table if not exists wapt_params (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name  varchar(64),
          value varchar(255),
          create_date varchar(255)
          ) """)

        self.db.execute("""
          create unique index if not exists idx_params_name on wapt_params(name);
          """)

        # action : install, remove, check, session_setup, update, upgrade
        # state : draft, planned, postponed, running, done, error, canceled
        self.db.execute("""
            CREATE TABLE wapt_task (
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

        return self.curr_db_version

    @property
    def db_version(self):
        if not self._db_version:
            try:
                val = self.db.execute('select value from wapt_params where name="db_version"').fetchone()
                if val:
                    self._db_version = val[0]
                else:
                    self._db_version = '0000'
            except Exception,e:
                logger.critical('Unable to get DB version (%s), upgrading' % e)
                self.db.rollback()
                self.upgradedb()
                self.db.execute('insert into wapt_params(name,value,create_date) values (?,?,?)',('db_version','0000',datetime2isodate()))
                self.db.commit()
                self._db_version = '0000'
        return self._db_version

    @db_version.setter
    def db_version(self,value):
        try:
            self.db.execute('insert or ignore into wapt_params(name,value,create_date) values (?,?,?)',('db_version',value,datetime2isodate()))
            self.db.execute('update wapt_params set value=?,create_date=? where name=?',(value,datetime2isodate(),'db_version'))
            self.db.commit()
            self._db_version = value
        except:
            logger.critical('Unable to set version, upgrading')
            self.db.rollback()
            self.upgradedb()

    @db_version.deleter
    def db_version(self):
        try:
            self.db.execute("delete from wapt_params where name = 'db_version'")
            self.db.commit()
            self._db_version = None
        except:
            logger.critical('Unable to delete version, upgrading')
            self.db.rollback()
            self.upgradedb()


    def set_param(self,name,value):
        try:
            self.db.execute('insert or replace into wapt_params(name,value,create_date) values (?,?,?)',(name,value,datetime2isodate()))
            self.db.commit()
        except:
            logger.critical('Unable to set param %s : %s' % (name,value))
            self.db.rollback()

    def get_param(self,name,default=None):
        q = self.db.execute('select value from wapt_params where name=?',(name,)).fetchone()
        if q:
            return q[0]
        else:
            return default

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
                    sources='',
                    repo_url=''):

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
                sources,
                repo_url) values (?,?,?,?,?,?,?,?,?,?,?,?,?)
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
                 sources,
                 repo_url)
               )

        return cur.lastrowid

    def add_package_entry(self,package_entry):
        cur = self.db.execute("""delete from wapt_package where package=? and version=?""" ,(package_entry.package,package_entry.version))

        self.add_package(package_entry.package,
                         package_entry.version,
                         package_entry.section,
                         package_entry.priority,
                         package_entry.architecture,
                         package_entry.maintainer,
                         package_entry.description,
                         package_entry.filename,
                         package_entry.size,
                         package_entry.md5sum,
                         package_entry.depends,
                         package_entry.sources,
                         package_entry.repo_url)


    def add_start_install(self,package,version,architecture,params_dict={}):
        """Register the start of installation in local db
            params_dict is the dictionary pf parameters provided on command line with --params
              or by the server
            setuppy is the python source code used for install, uninstall or session_setup
              code used for uninstall or session_setup must use only wapt self library as
              package content is not longer available at this step.
        """
        try:
            cur = self.db.execute("""delete from wapt_localstatus where package=?""" ,(package,))
            cur = self.db.execute("""\
                  insert into wapt_localstatus (
                    package,
                    version,
                    architecture,
                    install_date,
                    install_status,
                    install_output,
                    install_params
                    ) values (?,?,?,?,?,?,?)
                """,(
                     package,
                     version,
                     architecture,
                     datetime2isodate(),
                     'INIT',
                     '',
                     json.dumps(params_dict),
                   ))
        finally:
            self.db.commit()
        return cur.lastrowid

    def update_install_status(self,rowid,install_status,install_output,uninstall_key=None,uninstall_string=None):
        """Update status of package installation on localdb"""
        try:
            cur = self.db.execute("""\
                  update wapt_localstatus
                    set install_status=?,install_output = install_output || ?,uninstall_key=?,uninstall_string=?
                    where rowid = ?
                """,(
                     install_status,
                     install_output,
                     uninstall_key,
                     uninstall_string,
                     rowid,
                     )
                   )
        finally:
            self.db.commit()
        return cur.lastrowid

    def store_setuppy(self,rowid,setuppy=None,install_params={}):
        """Update status of package installation on localdb"""
        try:
            cur = self.db.execute("""\
                  update wapt_localstatus
                    set setuppy=?,install_params=? where rowid = ?
                """,(
                     remove_encoding_declaration(setuppy),
                     json.dumps(install_params),
                     rowid,
                     )
                   )
        finally:
            self.db.commit()
        return cur.lastrowid

    def remove_install_status(self,package):
        """Remove status of package installation from localdb"""
        try:
            cur = self.db.execute("""delete from wapt_localstatus where package=?""" ,(package,))
        finally:
            self.db.commit()
        return cur.lastrowid

    def known_packages(self):
        """return a list of all (package,version)"""
        q = self.db.execute("""\
              select distinct wapt_package.package,wapt_package.version from wapt_package
           """)
        return [PackageKey(*e) for e in q.fetchall()]

    def packages_matching(self,package_cond):
        """Return an ordered list of available packages which match the condition"""
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

    def packages_search(self,searchwords=[]):
        """Return a list of package entries matching the search words"""
        if not isinstance(searchwords,list) and not isinstance(searchwords,tuple):
            searchwords = [searchwords]
        if not searchwords:
            words = []
            search = ['1=1']
        else:
            words = [ "%"+w.lower()+"%" for w in searchwords ]
            search = ["lower(description || package) like ?"] *  len(words)
        result = self.query_package_entry("select * from wapt_package where %s" % " and ".join(search),words)
        result.sort()
        return result

    def installed(self):
        """Return a dictionary of installed packages : keys=package,version, values = package dict """
        q = self.query_package_entry("""\
              select l.install_date,l.install_status,l.install_output,l.install_params,
                r.* from wapt_localstatus l
                left join wapt_package r on r.package=l.package and l.version=r.version and (l.architecture is null or l.architecture=r.architecture)
              where l.install_status in ("OK","UNKNOWN")
           """)
        result = {}
        for p in q:
            result[p.package]= p
        return result

    def installed_search(self,searchwords=[]):
        """Return a dictionary of installed packages : keys=package,version, values = package dict """
        if not isinstance(searchwords,list) and not isinstance(searchwords,tuple):
            searchwords = [searchwords]
        if not searchwords:
            words = []
            search = ['1=1']
        else:
            words = [ "%"+w.lower()+"%" for w in searchwords ]
            search = ["lower(r.description || r.package) like ?"] *  len(words)
        q = self.query_package_entry("""\
              select l.install_date,l.install_status,l.install_output,l.install_params,
                r.* from wapt_localstatus l
                left join wapt_package r on r.package=l.package and l.version=r.version and (l.architecture is null or l.architecture=r.architecture)
              where l.install_status in ("OK","UNKNOWN") and %s
           """ % " and ".join(search),words)
        result = {}
        for p in q:
            result[p.package]= p
        return result

    def installed_matching(self,package_cond):
        """Return True if one installed package match te package condition 'tis-package (>=version)' """
        package = REGEX_PACKAGE_CONDITION.match(package_cond).groupdict()['package']
        q = self.query_package_entry("""\
              select l.install_date,l.install_status,l.install_output,l.install_params,l.setuppy,
                r.* from wapt_localstatus l
                left join wapt_package r on r.package=l.package and l.version=r.version and (l.architecture is null or l.architecture=r.architecture)
              where l.package=? and l.install_status in ("OK","UNKNOWN")
           """,(package,))
        return q[0] if q and q[0].match(package_cond) else None

    def upgradeable(self):
        """Return a dictionary of upgradable Package entries"""
        result = {}
        allinstalled = self.installed().values()
        for p in allinstalled:
            available = self.query_package_entry("""select * from wapt_package where package=?""",(p.package,))
            available.sort()
            available.reverse()
            if available and available[0] > p:
                result[p.package] = available
        return result

    def update_repos_list(self,url_list):
        """Cleanup all"""
        try:
            logger.info('Purge packages table')
            self.db.execute('delete from wapt_package where repo_url not in (%s)' % (','.join('"%s"'% url for url in url_list,)))
            self.db.commit()
            for url in url_list:
                logger.info('Getting packages from %s' % url)
                try:
                    self.update_packages_list(url)
                except Exception,e:
                    logger.critical('Error getting packages from %s : %s' % (url,e))
            logger.debug('Commit wapt_package updates')
        except:
            logger.debug('rollback delete table')
            self.db.rollback()
            raise

    def update_packages_list(self,repourl):
        """Get Packages from http repo and update local package database"""
        try:
            result = []
            packagesfn = repourl + '/Packages'
            logger.debug('read remote Packages zip file %s' % packagesfn)
            packageListFile = codecs.decode(zipfile.ZipFile(
                  StringIO.StringIO( urllib2.urlopen(packagesfn).read())
                ).read(name='Packages'),'UTF-8').splitlines()

            logger.debug('Purge packages table')
            self.db.execute('delete from wapt_package where repo_url=?',(repourl,))
            startline = 0
            endline = 0
            def add(start,end):
                if start <> end:
                    package = PackageEntry()
                    package.load_control_from_wapt(packageListFile[start:end])
                    logger.info("%s (%s)" % (package.package,package.version))
                    logger.debug(package)
                    package.repo_url = repourl
                    self.add_package_entry(package)
                    result.append((package.package,package.version))

            for line in packageListFile:
                if line.strip()=='':
                    add(startline,endline)
                    endline += 1
                    startline = endline
                # add ettribute to current package
                else:
                    endline += 1
            # last one
            add(startline,endline)

            logger.debug('Commit wapt_package updates')
            self.db.commit()
            return result
        except:
            logger.debug('rollback delete package')
            self.db.rollback()
            raise

    def build_depends(self,packages):
        """Given a list of packages conditions (packagename (optionalcondition))
            return a list of dependencies (packages conditions) to install
              TODO : choose available dependencies in order to reduce the number of new packages to install
        """
        if not isinstance(packages,list) and not isinstance(packages,tuple):
            packages = [packages]
        MAXDEPTH = 30
        # roots : list of initial packages to avoid infinite loops
        def dodepends(explored,packages,depth):
            if depth[0]>MAXDEPTH:
                raise Exception.create('Max depth in build dependencies reached, aborting')
            depth[0] += 1
            alldepends = []
            # loop over all package names
            for package in packages:
                if not package in explored:
                    entries = self.packages_matching(package)
                    if not entries:
                        raise Exception('Package %s not available' % package)
                    # get depends of the most recent matching entry
                    # TODO : use another older if this can limit the number of packages to install !
                    depends = [s.strip() for s in entries[-1].depends.split(',') if s.strip()<>'']
                    for d in depends:
                        alldepends.extend(dodepends(explored,depends,depth))
                        if not d in alldepends:
                            alldepends.append(d)
                    explored.append(package)
            return alldepends

        explored = []
        depth =[0]
        return dodepends(explored,packages,depth)

    def package_entry_from_db(self,package,version_min='',version_max=''):
        """Return the most recent package entry given its packagename and minimum and maximum version"""
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

    def query(self,query, args=(), one=False):
        """
        execute la requete query sur la db et renvoie un tableau de dictionnaires
        """
        cur = self.db.execute(query, args)
        rv = [dict((cur.description[idx][0], value)
                   for idx, value in enumerate(row)) for row in cur.fetchall()]
        return (rv[0] if rv else None) if one else rv

    def query_package_entry(self,query, args=(), one=False):
        """
        execute la requete query sur la db et renvoie un tableau de PackageEntry
        Le matching est fait sur le nom de champs.
            Les champs qui ne matchent pas un attribut de PackageEntry
                sont également mis en attributs !
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
        return result



class WaptRepo(object):
    def __init__(self,name='',url='',certfilename=''):
        self.name = name
        self.repo_url = url
        self.public_cert = certfilename

    def from_inifile(self,config,section=''):
        if section:
            self.name = section
        self.repo_url = config.get(self.name,'repo_url')
        self.public_cert = config.get(self.name,'public_cert')
        return self

######################"""
class Wapt(object):
    """Global WAPT engine"""
    def __init__(self,config=None,defaults=None):
        """Initialize engine with a configParser instance (inifile) and other defaults in a dictionary
            Main properties are :
        """
        assert not config or isinstance(config,RawConfigParser)
        self.wapt_base_dir = os.path.dirname(sys.argv[0])
        self.config = config
        # default config file
        if not config:
            config = RawConfigParser(defaults = defaults)
            config.read(os.path.join(self.wapt_base_dir,'wapt-get.ini'))
        self._wapt_repourl = config.get('global','repo_url')
        self.packagecachedir = os.path.join(self.wapt_base_dir,'cache')
        if not os.path.exists(self.packagecachedir):
            os.makedirs(self.packagecachedir)
        self.dry_run = False
        # database init
        if config.has_option('global','dbdir'):
            self.dbdir =  config.get('global','dbdir')
        else:
            self.dbdir = os.path.join(self.wapt_base_dir,'db')

        if not os.path.exists(self.dbdir):
            os.makedirs(self.dbdir)
        self.dbpath = os.path.join(self.dbdir,'waptdb.sqlite')
        self._waptdb = None
        #
        if config.has_option('global','private_key'):
            self.private_key = config.get('global','private_key')
        else:
            self.private_key = ''

        if config.has_option('global','allow_unsigned'):
            self.allow_unsigned = config.getboolean('global','allow_unsigned')
        else:
            self.allow_unsigned = False

        if config.has_option('global','upload_cmd'):
            self.upload_cmd = config.get('global','upload_cmd')
        else:
            self.upload_cmd = False

        self.repositories = []
        if config.has_option('global','repositories'):
            names = [n.strip() for n in config.get('global','repositories').split(',')]
            logger.info('Other repositories : %s' % (names,))
            for name in names:
                if name:
                    w = WaptRepo(name).from_inifile(config)
                    self.repositories.append(w)
                    logger.debug('    %s:%s' % (w.name,w.repo_url))

    @property
    def waptdb(self):
        if not self._waptdb:
            self._waptdb = WaptDB(dbpath=self.dbpath)
            if self._waptdb.db_version < self._waptdb.curr_db_version:
                logger.info('Upgrading db structure from %s to %s' % (self._waptdb.db_version,self._waptdb.curr_db_version))
                self._waptdb.upgradedb()
        return self._waptdb

    @property
    def wapt_repourl(self):
        if not self._wapt_repourl:
            self._wapt_repourl = self.find_wapt_server()
        return self._wapt_repourl

    def find_wapt_server(self):
        """Search the nearest working WAPT repository given the following priority
           - URL defined in ini file
           - first SRV record in the same network as one of the connected network interface
           - first SRV record with the highest weight
           - wapt CNAME in the local dns domain (https first then http)
        """
        if self.config:
            url = self.config.get('global','repo_url')
            if url:
                if tryurl(url+'/Packages'):
                    return url
                else:
                    logger.warning('URL defined in ini file %s is not available' % url)
            if not url:
                logger.debug('No url defined in ini file')

        local_ips = socket.gethostbyname_ex(socket.gethostname())[2]
        logger.debug('All interfaces : %s' % [ "%s/%s" % (i['addr'],i['netmask']) for i in host_ipv4() if 'addr' in i and 'netmask' in i])
        connected_interfaces = [ i for i in host_ipv4() if 'addr' in i and 'netmask' in i and i['addr'] in local_ips ]
        logger.debug('Local connected IPs: %s' % [ "%s/%s" % (i['addr'],i['netmask']) for i in connected_interfaces])

        def is_inmysubnets(ip):
            """Return True if IP is in one of my connected subnets"""
            for i in connected_interfaces:
                if same_net(i['addr'],ip,i['netmask']):
                    logger.debug('  %s is in same subnet as %s/%s local connected interface' % (ip,i['addr'],i['netmask']))
                    return True
            return False

        #dnsdomain = dns.resolver.get_default_resolver().domain.to_text()
        dnsdomain = get_domain_fromregistry()
        logger.debug('Default DNS domain: %s' % dnsdomain)

        if dnsdomain and dnsdomain <> '.':
            # find by dns SRV _wapt._tcp
            try:
                resolv = dns.resolver.get_default_resolver()
                logger.debug('DNS server %s' % (resolv.nameservers,))
                logger.debug('Trying _wapt._tcp.%s SRV records' % dnsdomain)
                answers = dns.resolver.query('_wapt._tcp.%s.' % dnsdomain,'SRV')
                working_url = []
                for a in answers:
                    # get first numerical ipv4 from SRV name record
                    try:
                        wapthost = a.target.to_text()[0:-1]
                        ip = dns.resolver.query(a.target)[0].to_text()
                        if a.port == 80:
                            url = 'http://%s/wapt' % (wapthost,)
                            if tryurl(url+'/Packages'):
                                working_url.append((a.weight,url))
                                if is_inmysubnets(ip):
                                    return url
                        elif a.port == 443:
                            url = 'https://%s/wapt' % (wapthost,)
                            if tryurl(url+'/Packages'):
                                working_url.append((a.weight,url))
                                if is_inmysubnets(ip):
                                    return url
                        else:
                            url = 'http://%s:%i/wapt' % (wapthost,a.port)
                            if tryurl(url+'/Packages'):
                                working_url.append((a.weight,url))
                                if is_inmysubnets(ip):
                                    return url
                    except Exception,e:
                        logging.debug('Unable to resolve : error %s' % (e,))

                if working_url:
                    working_url.sort()
                    logger.debug('  Accessible servers : %s' % (working_url,))
                    return working_url[-1][1]

                if not answers:
                    logger.debug('  No _wapt._tcp.%s SRV record found' % dnsdomain)
            except dns.exception.DNSException,e:
                logger.debug('  DNS resolver failed looking for _SRV records: %s' % (e,))

            # find by dns CNAME
            try:
                logger.debug('Trying wapt.%s CNAME records' % dnsdomain)
                answers = dns.resolver.query('wapt.%s.' % dnsdomain,'CNAME')
                for a in answers:
                    wapthost = a.target.canonicalize().to_text()[0:-1]
                    url = 'https://%s/wapt' % (wapthost,)
                    if tryurl(url+'/Packages'):
                        return url
                    url = 'http://%s/wapt' % (wapthost,)
                    if tryurl(url+'/Packages'):
                        return url
                if not answers:
                    logger.debug('  No wapt.%s CNAME SRV record found' % dnsdomain)

            except dns.exception.DNSException,e:
                logger.warning('  DNS resolver error : %s' % (e,))

            # find by dns A
            try:
                wapthost = 'wapt.%s.' % dnsdomain
                logger.debug('Trying %s A records' % wapthost)
                answers = dns.resolver.query(wapthost,'A')
                if answers:
                    url = 'https://%s/wapt' % (wapthost,)
                    if tryurl(url+'/Packages'):
                        return url
                    url = 'http://%s/wapt' % (wapthost,)
                    if tryurl(url+'/Packages'):
                        return url
                if not answers:
                    logger.debug('  No %s A record found' % wapthost)

            except dns.exception.DNSException,e:
                logger.warning('  DNS resolver error : %s' % (e,))
        else:
            logger.warning('Local DNS domain not found, skipping SRV _wapt._tcp and CNAME search ')

        return None

    def registry_uninstall_snapshot(self):
        """Return list of uninstall ID from registry
             launched nefore and after an installation to capture uninstallkey
        """
        result = []
        key = reg_openkey_noredir(HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        try:
            i = 0
            while True:
                subkey = EnumKey(key, i)
                result.append(subkey)
                i += 1
        except WindowsError,e:
            # WindowsError: [Errno 259] No more data is available
            if e.winerror == 259:
                pass
            else:
                raise
        if platform.machine() == 'AMD64':
            key = reg_openkey_noredir(HKEY_LOCAL_MACHINE,"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
            try:
                i = 0
                while True:
                    subkey = EnumKey(key, i)
                    result.append(subkey)
                    i += 1
            except WindowsError,e:
                # WindowsError: [Errno 259] No more data is available
                if e.winerror == 259:
                    pass
                else:
                    raise
        return result

    def uninstall_cmd(self,guid):
        """return the command stored in registry to uninstall a package """
        def get_fromkey(uninstall):
            key = reg_openkey_noredir(HKEY_LOCAL_MACHINE,"%s\\%s" % (uninstall,guid))
            try:
                cmd = QueryValueEx(key,'QuietUninstallString')[0]
                return cmd
            except WindowsError:
                cmd = QueryValueEx(key,'UninstallString')[0]
                if 'msiexec' in cmd.lower():
                    cmd = cmd.replace('/I','/X').replace('/i','/X')
                    args = shlex.split(cmd,posix=False)
                    if not '/q' in cmd.lower():
                        args.append('/q')
                else:
                    # mozilla et autre
                    # si pas de "" et des espaces et pas d'option, alors encadrer avec des quotes
                    if not(' -' in cmd or ' /' in cmd) and ' ' in cmd:
                        args = [ cmd ]
                    else:
                    #sinon splitter sur les paramètres
                        args = shlex.split(cmd,posix=False)
                        # remove double quotes if any
                        if args[0].startswith('"') and args[0].endswith('"') and (not "/" in cmd or not "--" in cmd):
                            args[0] = args[0][1:-1]
                    if ('uninst' in cmd.lower() or 'helper.exe' in cmd.lower()) and not ' /s' in cmd.lower():
                        args.append('/S')
                    if ('unins000' in cmd.lower()) and not ' /silent' in cmd.lower():
                        args.append('/silent')
                return args
        try:
            return get_fromkey("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        except:
            if platform.machine() == 'AMD64':
                return get_fromkey("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
            else:
                raise

    def check_files_sha1(self,rootdir,manifest):
        """check hexdigest sha1 for the files in manifest, returns a list of non matching files (corrupted)"""
        assert os.path.isdir(rootdir)
        assert isinstance(manifest,list) or isinstance(manifest,tuple)
        errors = []
        for (filename,sha1) in manifest:
            fullpath = os.path.join(rootdir,filename)
            if sha1 <> sha1_for_file(fullpath):
                errors.append(filename)
        return errors

    def install_wapt(self,fname,params_dict={},public_cert=''):
        """Install a single wapt package given its WAPT filename."""
        logger.info("Register start of install %s to local DB with params %s" % (fname,params_dict))
        status = 'INIT'
        if not public_cert:
            public_cert = self.get_public_cert()
        if not public_cert and not self.allow_unsigned:
            raise Exception('No public Key provided for package signature checking, and unsigned packages install is not allowed.\
                    If you want to allow unsigned packages, add "allow_unsigned=1" in wapt-get.ini file')
        previous_uninstall = self.registry_uninstall_snapshot()
        entry = PackageEntry()
        entry.load_control_from_wapt(fname)
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

        install_id = None
        install_id = self.waptdb.add_start_install(entry.package ,entry.version,entry.architecture,params_dict=params_dict)
        # we setup a redirection of stdout to catch print output from install scripts
        sys.stderr = sys.stdout = install_output = LogInstallOutput(sys.stdout,self.waptdb,install_id)
        hdlr = logging.StreamHandler(install_output)
        hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        if logger.handlers:
            old_hdlr = logger.handlers[0]
            logger.handlers[0] = hdlr
        else:
            old_hdlr = None
            logger.addHandler(hdlr)

        try:
            logger.info("Installing package " + fname)
            # ... inutile ?
            #global packagetempdir
            # case wapt is a zipped file, else directory (during developement)
            istemporary = False
            if os.path.isfile(fname):
                packagetempdir = tempfile.mkdtemp(prefix="wapt")
                logger.info('  unzipping %s to temporary %s' % (fname,packagetempdir))
                zip = zipfile.ZipFile(fname)
                zip.extractall(path=packagetempdir)
                istemporary = True
            elif os.path.isdir(fname):
                packagetempdir = fname
            else:
                raise Exception('%s is not a file nor a directory, aborting.' % fname)

            # chech sha1
            manifest_filename = os.path.join( packagetempdir,'WAPT','manifest.sha1')
            if os.path.isfile(manifest_filename):
                manifest_data = open(manifest_filename,'r').read()
                # check signature of manifest
                signature_filename = os.path.join( packagetempdir,'WAPT','signature')
                # if public key provided, and signature in wapt file, check it
                if os.path.isfile(public_cert) and os.path.isfile(signature_filename):
                    signature = open(signature_filename,'r').read().decode('base64')
                    ssl_verify_content(manifest_data,signature,public_cert)
                else:
                    if not self.allow_unsigned:
                        raise Exception('Package does not contain a signature, and unsigned packages install is not allowed')

                manifest = json.loads(manifest_data)
                errors = self.check_files_sha1(packagetempdir,manifest)
                if errors:
                    raise Exception('Files corrupted, SHA1 not matching for %s' % (errors,))
            else:
                if not self.allow_unsigned:
                    raise Exception('Package does not contain a manifest.sha1 file, and unsigned packages install is not allowed')

            setup_filename = os.path.join( packagetempdir,'setup.py')
            previous_cwd = os.getcwd()
            os.chdir(os.path.dirname(setup_filename))
            if not os.getcwd() in sys.path:
                sys.path.append(os.getcwd())

            # import the setup module from package file
            logger.info("  sourcing install file %s " % setup_filename )
            setup = import_setup(setup_filename,'_waptsetup_')
            required_params = []

            # be sure some minimal functions are available in setup module at install step
            setattr(setup,'basedir',os.path.dirname(setup_filename))
            setattr(setup,'run',setuphelpers.run)
            setattr(setup,'run_notfatal',setuphelpers.run_notfatal)
            setattr(setup,'WAPT',self)

            # get definitions of required parameters from setup module
            if hasattr(setup,'required_params'):
                required_params = setup.required_params

            # get value of required parameters if not already supplied
            for p in required_params:
                if not p in params_dict:
                    params_dict[p] = raw_input("%s: " % p)

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
                    logger.info("  executing install script")
                    exitstatus = setup.install()
                except Exception,e:
                    logger.critical('Fatal error in install script: %s' % e)
                    raise
            else:
                logger.warning('Dry run, not actually running setup.install()')
                exitstatus = None

            if exitstatus is None or exitstatus == 0:
                status = 'OK'
            else:
                status = 'ERROR'

            # get uninstallkey from setup module (string or array of strings)
            if hasattr(setup,'uninstallkey'):
                new_uninstall_key = '%s' % (setup.uninstallkey,)
            else:
                new_uninstall = self.registry_uninstall_snapshot()
                new_uninstall_key = [ k for k in new_uninstall if not k in previous_uninstall]

            # get uninstallstring from setup module (string or array of strings)
            if hasattr(setup,'uninstallstring'):
                uninstallstring = setup.uninstallstring
            else:
                uninstallstring = None
            logger.info('  uninstall keys : %s' % (new_uninstall_key,))
            logger.info('  uninstall strings : %s' % (uninstallstring,))

            logger.info("Install script finished with status %s" % status)
            if istemporary:
                os.chdir(previous_cwd)
                logger.debug("Cleaning package tmp dir")
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
                    logger.warning("Unable to clean tmp dir")

            self.waptdb.update_install_status(install_id,status,'',str(new_uninstall_key) if new_uninstall_key else '',str(uninstallstring) if uninstallstring else '')
            # (entry.package,entry.version,status,json.dumps({'output':install_output.output,'exitstatus':exitstatus}))
            return status

        except Exception,e:
            if install_id:
                try:
                    try:
                        uerror = repr(e).decode('iso8859')
                    except:
                        try:
                            uerror = repr(e).decode('utf8')
                        except:
                            uerror = repr(e)
                    self.waptdb.update_install_status(install_id,'ERROR',uerror)
                except Exception,e2:
                    logger.critical(e2)
            else:
                logger.critical(e)
            raise e
        finally:
            if 'setup' in dir():
                del setup
            if old_hdlr:
                logger.handlers[0] = old_hdlr
            else:
                logger.removeHandler(hdlr)
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            sys.path = oldpath

    def get_sources(self,package):
        """Download sources of package (if referenced in package as a https svn
           in the current directory"""
        entry = self.waptdb.packages_matching(package)[-1]
        if not entry.Sources:
            raise Exception('No sources defined in package control file')
        if "PROGRAMW6432" in os.environ:
            svncmd = os.path.join(os.environ['PROGRAMW6432'],'TortoiseSVN','bin','svn.exe')
        else:
            svncmd = os.path.join(os.environ['PROGRAMFILES'],'TortoiseSVN','bin','svn.exe')
        logger.debug('svn command : %s'% svncmd)
        if not os.path.isfile(svncmd):
            raise Exception('svn.exe command not available, please install TortoiseSVN with commandline tools')
        if self.config.get('global','default_sources_suffix'):
            co_dir = os.path.join(self.config.get('global','default_sources_root'),"%s-%s" % (entry.package,self.config.get('global','default_sources_suffix')))
        else:
            co_dir = os.path.join(self.config.get('default_sources_root',entry.package))
        logger.info('sources : %s'% entry.sources)
        logger.info('checkout dir : %s'% co_dir)
        logger.info(subprocess.check_output('"%s" co "%s" "%s"' % (svncmd,entry.sources,co_dir)))
        return co_dir

    def last_install_log(self,packagename):
        """Return a dict {status,log} of the last install of a package"""
        q = self.waptdb.query("""\
           select install_status,install_output from wapt_localstatus
            where package=? order by install_date desc limit 1
           """ , (packagename,) )
        if not q:
            raise Exception("Package %s not found in local DB status" % packagename)
        return {"status" : q[0]['install_status'], "log":q[0]['install_output']}

    def cleanup(self):
        """Remove cached WAPT file from local disk"""
        result = []
        logger.info('Cleaning up WAPT cache directory')
        cachepath = self.packagecachedir
        for f in glob.glob(os.path.join(cachepath,'*.wapt')):
            if os.path.isfile(f):
                logger.debug('Removing %s' % f)
                os.remove(f)
                result.append(f)
        return result

    def update(self):
        """Update local database with packages definition from repositories
            returns a dict of deltas
                "removed" (Package,Version)
                "added"  (Package,Version)
        """
        previous = self.waptdb.known_packages()
        if not self.wapt_repourl:
            raise Exception('No main WAPT repository available or setup')
        repos = [self.wapt_repourl] + [r.repo_url for r in self.repositories]
        self.waptdb.update_repos_list(repos)

        current = self.waptdb.known_packages()
        result = {
            "added":   [ p for p in current if not p in previous ],
            "removed": [ p for p in previous if not p in current],
            "count" : len(current),
            "repos" : repos,
            }
        return result

    def checkinstall(self,apackages,forceupgrade=False,force=False):
        """Given a list of packagename (condition), check which packages to upgrade, to install
            forceupgrade : check if the current installed package is the latest available
        """
        if not isinstance(apackages,list):
            apackages = [apackages]

        allinstalled = self.waptdb.installed()
        # packages to install after skipping already installed ones
        skipped = []
        unavailable = []
        additional_install = []
        to_upgrade = []
        packages = []

        # search for most recent matching package to install
        for request in apackages:
            # get the current installed package matching the request
            old_matches = self.waptdb.installed_matching(request)
            # current installed matches
            if not force and old_matches and not forceupgrade:
                skipped.append([request,old_matches])
            else:
                new_availables = self.waptdb.packages_matching(request)
                if new_availables:
                    if force or not old_matches or (forceupgrade and old_matches < new_availables[-1]):
                        packages.append([request,new_availables[-1]])
                    else:
                        skipped.append([request,old_matches])
                else:
                    unavailable.append([request,None])

        # get dependencies of not installed top packages
        if forceupgrade:
            depends = self.waptdb.build_depends(apackages)
        else:
            depends = self.waptdb.build_depends([p[0] for p in packages])
        # search for most recent matching package to install
        for request in depends:
            # get the current installed package matching the request
            old_matches = self.waptdb.installed_matching(request)
            # current installed matches
            if not force and old_matches:
                skipped.append([request,old_matches])
            else:
                # check if installable or upgradable ?
                new_availables = self.waptdb.packages_matching(request)
                if new_availables:
                    if not old_matches or (forceupgrade and old_matches < new_availables[-1]):
                        packages.append([request,new_availables[-1]])
                    else:
                        skipped.append([request,old_matches])
                else:
                    unavailable.append([request,None])
        return {'additional':additional_install,'upgrade':to_upgrade,'install':packages,'skipped':skipped,'unavailable':unavailable}

    def install(self,apackages,
        force=False,
        params_dict = {},
        download_only=False,
        usecache=True):
        """Install a list of packages and its dependencies
            apackages is a list of packages names. A specific version can be specified
            force=True reinstalls the packafes even if it is already installed
            params_dict is passed to the install() procedure in the packages setup.py of all packages
                as params variables and as "setup module" attributes
        """
        if not isinstance(apackages,list):
            apackages = [apackages]

        actions = self.checkinstall(apackages,force=download_only or force,forceupgrade=True)
        actions['errors']=[]

        skipped = actions['skipped']
        additional_install = actions['additional']
        to_upgrade = actions['upgrade']
        packages = actions['install']

        to_install = []
        to_install.extend(additional_install)
        to_install.extend(to_upgrade)
        to_install.extend(packages)

        # get package entries to install to_install is a list of (request,package)
        packages = [ p[1] for p in to_install ]

        downloaded = self.download_packages(packages,usecache=not download_only and usecache)
        if downloaded.get('errors',[]):
            raise Exception('Error downloading some files : %s',(downloaded['errors'],))
        actions['downloads'] = downloaded
        logger.debug('Downloaded : %s' % (downloaded,))
        def fname(packagefilename):
            return os.path.join(self.packagecachedir,packagefilename)
        if not download_only:
            for (request,p) in to_install:
                result = self.install_wapt(fname(p.filename),params_dict = params_dict,public_cert=self.get_public_cert())
                if result<>'OK':
                    actions['errors'].append([request,p])
                    logger.critical('Package %s (%s) not installed due to errors' %(request,p))
            return actions
        else:
            logger.info('Download only, no install performed')
            return actions

    def download_packages(self,package_requests,usecache=True):
        """Download a list of packages (requests are of the form packagename (>version) )
           returns a dict of {"downloaded,"skipped","errors"}
        """
        downloaded = []
        skipped = []
        errors = []
        packages = []
        for p in package_requests:
            if isinstance(p,str):
                mp = self.waptdb.packages_matching(p)
                if mp:
                    packages.append(mp[0])
                else:
                    raise Exception('Unavailable package %s' % (p,))
            elif isinstance(p,PackageEntry):
                packages.append(p)
            elif isinstance(p,list) or isinstance(p,tuple):
                packages.append(self.waptdb.package_entry_from_db(p[0],version_min=p[1],version_max=p[1]))
            else:
                raise Exception('Invalid package request %s' % p)
        for entry in packages:
            packagefilename = entry.filename.strip('./')
            download_url = entry.repo_url+'/'+packagefilename
            fullpackagepath = os.path.join(self.packagecachedir,packagefilename)
            if os.path.isfile(fullpackagepath) and os.path.getsize(fullpackagepath)>0 and usecache:
                skipped.append(fullpackagepath)
                logger.info("  Use cached package file from " + fullpackagepath)
            else:
                logger.info("  Downloading package from %s" % download_url)
                try:
                    setuphelpers.wget( download_url, self.packagecachedir)
                    downloaded.append(fullpackagepath)
                except BaseException as e:
                    if os.path.isfile(fullpackagepath):
                        os.remove(fullpackagepath)
                    logger.critical("Error downloading package from http repository, please update... error : %s" % e)
                    errors.append((download_url,"%s" % e))
        return {"downloaded":downloaded,"skipped":skipped,"errors":errors}

    def remove(self,package,force=False):
        """Removes a package giving its package name, unregister from local status DB"""
        q = self.waptdb.query("""\
           select * from wapt_localstatus
            where package=?
           """ , (package,) )
        if not q:
            logger.warning("Package %s not installed, aborting" % package)
            return True

        # several versions installed of the same package... ?
        for mydict in q:
            logger.info("Removing package %s version %s from computer..." % (mydict['package'],mydict['version']))
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
                    try:
                        logger.info('Running %s' % guid)
                        logger.info(subprocess.check_output(guid))
                    except Exception,e:
                        logger.info("Warning : %s" % e)
                logger.info('Remove status record from local DB')
                self.waptdb.remove_install_status(package)
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
                    try:
                        uninstall_cmd = self.uninstall_cmd(guid)
                        logger.info('Launch uninstall cmd %s' % (uninstall_cmd,))
                        print subprocess.check_output(uninstall_cmd,shell=True)
                    except Exception,e:
                        logger.info("Warning : %s" % e)
                logger.info('Remove status record from local DB')
                self.waptdb.remove_install_status(package)
            else:
                if force:
                    logger.critical('uninstall key not registered in local DB status, unable to remove properly. Please remove manually. Forced removal of local status of package')
                    self.waptdb.remove_install_status(package)
                else:
                    raise Exception('  uninstall key not registered in local DB status, unable to remove properly. Please remove manually')

    def upgrade(self):
        """\
Query localstatus database for packages with a version older than repository
and install all newest packages"""
        upgrades = self.waptdb.upgradeable()
        logger.debug('upgrades : %s' % upgrades.keys())
        return self.install(upgrades.keys(),force=True)

    def list_upgrade(self):
        """Returns a list of packages which can be upgraded
           Package,Current Version,Available version
        """
        return self.waptdb.upgradeable().values()

    def download_upgrades(self):
        """Download packages that can be upgraded"""
        q = self.waptdb.upgradeable()
        # get most recent packages
        to_download = [p[0] for p in q.values()]
        return self.download_packages(to_download)

    def inventory(self):
        """Return software inventory of the computer as a dictionary"""
        inv = {}
        inv['softwares'] = setuphelpers.installed_softwares('')
        inv['packages'] = self.waptdb.installed()
        return inv

    def get_public_cert(self,repository='global'):
        if self.config.has_option(repository,'public_cert'):
            return self.config.get(repository,'public_cert')
        else:
            return ''

    def signpackage(self,zip_or_directoryname,excludes=['.svn','.git*','*.pyc','src'],private_key=None,callback=pwd_callback):
        """calc the signature of the WAPT/manifest.sha1 file and put/replace it in ZIP or directory.
            create manifest.sha1 a directory is supplied"""
        if not isinstance(zip_or_directoryname,unicode):
            zip_or_directoryname = unicode(zip_or_directoryname)
        if not private_key:
            private_key = self.private_key
        if not private_key:
            raise Exception('Private key filename not set in private_key')
        if not os.path.isfile(private_key):
            raise Exception('Private key file %s not found' % private_key)
        if os.path.isfile(zip_or_directoryname):
            waptzip = zipfile.ZipFile(zip_or_directoryname,'a')
            manifest = waptzip.open('WAPT/manifest.sha1').read()
        else:
            manifest_data = get_manifest_data(zip_or_directoryname,excludes=excludes)
            manifest = json.dumps(manifest_data,indent=True)
            open(os.path.join(zip_or_directoryname,'WAPT','manifest.sha1'),'w').write(manifest)

        signature = ssl_sign_content(manifest,private_key=private_key,callback=callback)
        if os.path.isfile(zip_or_directoryname):
            waptzip.writestr('WAPT/signature',signature.encode('base64'),compress_type=zipfile.ZIP_STORED)
        else:
            open(os.path.join(zip_or_directoryname,'WAPT','signature'),'w').write(signature.encode('base64'))

        return signature.encode('base64')

    def buildpackage(self,directoryname,inc_package_release=False,excludes=['.svn','.git*','*.pyc','src']):
        """Build the WAPT package from a directory, return the filename of the WAPT file"""
        if not isinstance(directoryname,unicode):
            directoryname = unicode(directoryname)
        result_filename = u''
        if not os.path.isdir(os.path.join(directoryname,'WAPT')):
            raise Exception('Error building package : There is no WAPT directory in %s' % directoryname)
        if not os.path.isfile(os.path.join(directoryname,'setup.py')):
            raise Exception('Error building package : There is no setup.py file in %s' % directoryname)
        oldpath = sys.path
        try:
            previous_cwd = os.getcwd()
            logger.debug('  Change current directory to %s' % directoryname)
            os.chdir(directoryname)
            if not os.getcwd() in sys.path:
                sys.path = [os.getcwd()] + sys.path
                logger.debug('new sys.path %s' % sys.path)
            logger.debug('Sourcing %s' % os.path.join(directoryname,'setup.py'))
            setup = import_setup(os.path.join(directoryname,'setup.py'),'_waptsetup_')
             # be sure some minimal functions are available in setup module at install step
            logger.debug('Source import OK')
            control_filename = os.path.join(directoryname,'WAPT','control')
            entry = PackageEntry()
            if hasattr(setup,'control'):
                logger.info('Use control informations from setup.py file')
                entry.load_control_from_dict(setup.control)
                # update control file
                codecs.open(control_filename,'w',encoding='utf8').write(entry.ascontrol())
            else:
                logger.info('Use control informations from control file')
                entry.load_control_from_wapt(directoryname)
            if inc_package_release:
                current_release = entry.version.split('-')[-1]
                new_release = "%02i" % (int(current_release) + 1,)
                new_version = "-".join(entry.version.split('-')[0:-1]+[new_release])
                logger.info('Increasing version of package from %s to %s' % (entry.version,new_version))
                entry.version = new_version
                entry.save_control_to_wapt(directoryname)
            package_filename =  entry.make_package_filename()
            logger.debug('Control data : \n%s' % entry.ascontrol())
            result_filename = os.path.abspath(os.path.join( directoryname,'..',package_filename))

            allfiles = create_recursive_zip_signed(
                zipfn = result_filename,
                source_root = directoryname,
                target_root = '' ,
                excludes=excludes)
            return {'filename':result_filename,'files':allfiles}
        finally:
            if 'setup' in dir():
                del setup
            else:
                logger.critical('Unable to read setup.py file')
            sys.path = oldpath
            logger.debug('  Change current directory to %s' % previous_cwd)
            os.chdir(previous_cwd)

    def session_setup(self,packagename,params_dict={}):
        """Setup the user session for a specific system wide installed package"
           Source setup.py from database or filename
        """
        logger.info("Session setup for package %s with params %s" % (packagename,params_dict))

        oldpath = sys.path
        try:
            previous_cwd = os.getcwd()
            if os.path.isdir(packagename):
                setup = import_setup(os.path.join(directoryname,'setup.py'),'__waptsetup__')
            else:
                logger.debug('Sourcing setup from DB')
                setup = import_code(self.is_installed(packagename)['setuppy'],'__waptsetup__')

            required_params = []
             # be sure some minimal functions are available in setup module at install step
            logger.debug('Source import OK')
            if hasattr(setup,'session_setup'):
                logger.info('Launch session_setup')
                setattr(setup,'run',setuphelpers.run)
                setattr(setup,'run_notfatal',setuphelpers.run_notfatal)
                setattr(setup,'WAPT',self)

                # get definitions of required parameters from setup module
                if hasattr(setup,'required_params'):
                    required_params = setup.required_params

                # get value of required parameters if not already supplied
                for p in required_params:
                    if not p in params_dict:
                        params_dict[p] = raw_input("%s: " % p)

                # set params dictionary
                if not hasattr(setup,'params'):
                    # create a params variable for the setup module
                    setattr(setup,'params',params_dict)
                else:
                    # update the already created params with additional params from command line
                    setup.params.update(params_dict)

                result = setup.session_setup()
                return result
            else:
                raise Exception('No session_setup function in setup.py for package %s' % packagename)
        finally:
            if 'setup' in dir():
                del setup
            else:
                logger.critical('Unable to read setup.py file')
            sys.path = oldpath
            logger.debug('  Change current directory to %s' % previous_cwd)
            os.chdir(previous_cwd)

    def checkinstalled(self):
        """Source setup.py and launch checkinstalled"""
        result = False
        oldpath = sys.path
        try:
            previous_cwd = os.getcwd()
            logger.debug('  Change current directory to %s' % directoryname)
            os.chdir(directoryname)
            if not os.getcwd() in sys.path:
                sys.path = [os.getcwd()] + sys.path
                logger.debug('new sys.path %s' % sys.path)
            logger.debug('Sourcing %s' % os.path.join(directoryname,'setup.py'))
            setup = import_setup(os.path.join(directoryname,'setup.py'),'_waptsetup_')
             # be sure some minimal functions are available in setup module at install step
            logger.debug('Source import OK')
            if hasattr(setup,'checkinstalled'):
                logger.info('Use control informations from setup.py file')
                result = setup.checkinstalled()
            else:
                logger.info('No checkinstalled function in setup.pyfile')
                result = False
        finally:
            if 'setup' in dir():
                del setup
            else:
                logger.critical('Unable to read setup.py file')
            sys.path = oldpath
            logger.debug('  Change current directory to %s' % previous_cwd)
            os.chdir(previous_cwd)
            return result

    def maketemplate(self,installer_path,packagename='',directoryname=''):
        """Build a skeleton of WAPT package based on the properties of the supplied installer
           Return the path of the skeleton
        """
        packagename = packagename.lower()
        if installer_path:
            installer_path = os.path.abspath(installer_path)
        if directoryname:
             directoryname = os.path.abspath(directoryname)

        installer = os.path.basename(installer_path)
        (product_name,ext) = os.path.splitext(installer)
        product_desc = product_name

        if ext=='.exe':
            props = setuphelpers.get_file_properties(installer_path)
            product_name = props['ProductName'] or props['FileDescription'] or product_desc
            if props['CompanyName']:
                product_desc = "%s (%s)" % (product_name,props['CompanyName'])
            silentflag = '/VERYSILENT'
        elif ext=='.msi':
            props = setuphelpers.get_msi_properties(installer_path)
            product_name = props['ProductName'] or product_desc
            if 'Manufacturer' in props and props['Manufacturer']:
                product_desc = "%s (%s)" % (product_name,props['Manufacturer'])
            silentflag = '/q'
        else:
            props = {}

        if not packagename:
            simplename = re.sub(r'[\s\(\)]+','',product_name.lower())
            packagename = '%s-%s' %  (self.config.get('global','default_package_prefix','tis'),simplename)
        if not directoryname:
            directoryname = os.path.join(self.config.get('global','default_sources_root'),packagename)+'-%s' % self.config.get('global','default_sources_suffix','wapt')
        if not os.path.isdir(os.path.join(directoryname,'WAPT')):
            os.makedirs(os.path.join(directoryname,'WAPT'))
        template = """\
# -*- coding: utf-8 -*-
from setuphelpers import *

# registry key(s) where WAPT will find how to remove the application(s)
uninstallkey = []

# command(s) to launch to remove the application(s)
uninstallstring = []

# list of required parameters names (string) which canb be used during install
required_params = []

def install():
    # if you want to modify the keys depending on environment (win32/win64... params..)
    global uninstallkey
    global uninstallstring

    print('installing %(packagename)s')
    run('%(installer)s %(silentflag)s')
""" % locals()
        setuppy_filename = os.path.join(directoryname,'setup.py')
        if not os.path.isfile(setuppy_filename):
            codecs.open(setuppy_filename,'w',encoding='utf8').write(template)
        else:
            logger.info('setup.py file already exists, skip create')
        logger.debug('Copy installer %s to target' % installer)
        shutil.copyfile(installer_path,os.path.join(directoryname,installer))

        control_filename = os.path.join(directoryname,'WAPT','control')
        if not os.path.isfile(control_filename):
            entry = PackageEntry()
            entry.package = packagename
            entry.architecture='all'
            entry.description = 'automatic package for %s ' % product_desc
            try:
                entry.maintainer = win32api.GetUserNameEx(3)
            except:
                try:
                    entry.maintainer = win32api.GetUserName()
                except:
                    entry.maintainer = os.environ['USERNAME']

            entry.priority = 'optional'
            entry.section = 'base'
            entry.version = props.get('FileVersion',props.get('ProductVersion','0.0.0'))+'-00'
            if self.config.has_option('global','default_sources_url'):
                entry.Sources = self.config.get('global','default_sources_url') % {'packagename':packagename}
            codecs.open(control_filename,'w',encoding='utf8').write(entry.ascontrol())
        else:
            logger.info('control file already exists, skip create')
        return (directoryname)

    def is_installed(self,packagename):
        """Checks if a package is installed.
            Return package entry and additional local status or None"""
        return self.waptdb.installed_matching(packagename)

    def is_available(self,packagename):
        """Checks if a package (with optional version condition) is available.
            Return package entry or None"""
        return self.waptdb.packages_matching(packagename)


REGEX_MODULE_VERSION = re.compile(
                    r'^(?P<major>[0-9]+)'
                     '\.(?P<minor>[0-9]+)'
                     '(\.(?P<patch>[0-9]+))')

class Version():
    """Version object of form 0.0.0
        can compare with respect to natural numbering and not alphabetical
        ie : 0.10.2 > 0.2.5
    """
    def __init__(self,versionstring):
        assert isinstance(versionstring,ModuleType) or isinstance(versionstring,str) or isinstance(versionstring,unicode)
        if isinstance(versionstring,ModuleType):
            versionstring = versionstring.__version__
        self.keys = REGEX_MODULE_VERSION.match(versionstring).groupdict()

    def __cmp__(self,aversion):
        def nat_cmp(a, b):
            a, b = a or '', b or ''
            convert = lambda text: text.isdigit() and int(text) or text.lower()
            alphanum_key = lambda key: [convert(c) for c in re.split('([0-9]+)', key)]
            return cmp(alphanum_key(a), alphanum_key(b))

        assert isinstance(aversion,Version)
        for key in ['major', 'minor', 'patch']:
            i1,i2  = self.keys[key], aversion.keys[key]
            v = nat_cmp(i1,i2)
            if v:
                return v
        return 0



if __name__ == '__main__':
    logger.logLevel = logging.DEBUG
    if len(logger.handlers)<1:
        hdlr = logging.StreamHandler(sys.stdout)
        hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        logger.addHandler(hdlr)

    cfg = RawConfigParser()
    cfg.read('c:\\tranquilit\\wapt\\wapt-get.ini')
    w = Wapt(config=cfg)
    print w.waptdb.get_param('toto')
    #w.waptdb.db_version='00'
    w.waptdb.upgradedb()
    print w.is_installed('tis-firebird')
    #print w.signpackage('c:\\tranquilit\\tis-wapttest-wapt')
    #print w.signpackage('c:\\tranquilit\\tis-wapttest_0.0.0-40_all.wapt')
    #pfn = w.buildpackage('c:\\tranquilit\\tis-wapttest-wapt',True)
    #if not os.path.isfile(pfn['filename']):
    #    raise Exception("""w.buildpackage('c:\\tranquilit\\tis-wapttest-wapt',True) failed""")
    #print w.signpackage(pfn['filename'])
    #print w.install_wapt(pfn['filename'],params_dict={'company':'TIS'},public_cert=w.get_public_cert())

    print w.waptdb.upgradeable()
    assert isinstance(w.waptdb,WaptDB)
    print w.waptdb.get_param('db_version')
    print w.remove('tis-waptdev',force=True)
    print w.install(['tis-waptdev'])
    print w.remove('tis-firefox',force=True)
    print w.install('tis-firefox',force=True)
    print w.checkinstall(['tis-waptdev'],force=False)
    print w.checkinstall(['tis-waptdev'],force=True)
    print w.update()
    print w.list_upgrade()

