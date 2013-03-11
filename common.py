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

from iniparse import ConfigParser
import shlex
from collections import namedtuple

import netifaces
import shutil
import win32api
from _winreg import HKEY_LOCAL_MACHINE,EnumKey,OpenKey,QueryValueEx,EnableReflectionKey,DisableReflectionKey,QueryReflectionKey,QueryInfoKey,KEY_READ,KEY_WOW64_32KEY,KEY_WOW64_64KEY


import setuphelpers

logger = logging.getLogger('wapt-get')

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

def md5_for_file(fname, block_size=2**20):
    f = open(fname,'rb')
    md5 = hashlib.md5()
    while True:
        data = f.read(block_size)
        if not data:
            break
        md5.update(data)
    return md5.hexdigest()

def create_recursive_zip_signed(zipfn, source_root, target_root = "",excludes = ['.svn','*.pyc']):
    """Create a zip file with filename zipf from source_root directory with target_root as new root.
       Don't include file which match excludes file pattern
    """
    result = []
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
            result.append([os.path.join(target_root,item),md5_for_file(os.path.join(source_root, item))])
        elif os.path.isdir(os.path.join(source_root, item)):
            if logger: logger.debug('Add directory %s' % os.path.join(source_root, item))
            result.extend(create_recursive_zip_signed(zipf, os.path.join(source_root, item), os.path.join(target_root,item),excludes))
    if isinstance(zipfn,str) or isinstance(zipfn,unicode):
        if logger:
            logger.debug('  adding md5 sums for all %i files' % len(result))
        # Write a file with all md5 of all files
        zipf.writestr(os.path.join(target_root,'files.md5sum'), "\n".join( ["%s:%s" % (md5[0],md5[1]) for md5 in result] ))
        zipf.close()
    return result


def import_setup(setupfilename,modulename=''):
    """Import setupfilename as modulename, return the module object"""
    mod_name,file_ext = os.path.splitext(os.path.split(setupfilename)[-1])
    if not modulename:
        modulename=mod_name
    py_mod = imp.load_source(modulename, setupfilename)
    return py_mod

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

def _tryurl(url):
    try:
        logger.debug('  trying %s' % url)
        urllib2.urlopen(url)
        logger.debug('  OK')
        return True
    except Exception,e:
        logger.debug('  Not available : %s' % e)
        return False

PackageKey = namedtuple('Package',('packagename','version'))

class WaptDB:
    """Class to manage SQLite database with local installation status"""
    dbpath = ''
    db = None

    def __init__(self,dbpath):
        self.dbpath = dbpath
        if not os.path.isfile(self.dbpath):
            dirname = os.path.dirname(self.dbpath)
            if os.path.isdir (dirname)==False:
                os.makedirs(dirname)
            os.path.dirname(self.dbpath)
            self.db=sqlite3.connect(self.dbpath,detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
            self.initdb()
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
        pass

    def initdb(self):
        assert(isinstance(self.db,sqlite3.Connection))
        logger.debug('Initialize stat database')
        self.db.execute("""
        create table wapt_repo (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          Package varchar(255),
          Version varchar(255),
          Section varchar(255),
          Priority varchar(255),
          Architecture varchar(255),
          Maintainer varchar(255),
          Description varchar(255),
          Filename varchar(255),
          Size integer,
          MD5sum varchar(255),
          Depends varchar(800),
          Sources varchar(255),
          repo_url varchar(255)
          )"""
                        )
        self.db.execute("""
        create index idx_package_name on wapt_repo(Package);""")

        self.db.execute("""
        create table wapt_localstatus (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          Package varchar(255),
          Version varchar(255),
          InstallDate varchar(255),
          InstallStatus varchar(255),
          InstallOutput TEXT,
          InstallParams VARCHAR(800),
          UninstallString varchar(255),
          UninstallKey varchar(255)
          )"""
                        )
        self.db.execute("""
        create index idx_localstatus_name on wapt_localstatus(Package);""")

        self.db.commit()

    def add_package(self,
                    Package='',
                    Version='',
                    Section='',
                    Priority='',
                    Architecture='',
                    Maintainer='',
                    Description='',
                    Filename='',
                    Size='',
                    MD5sum='',
                    Depends='',
                    Sources='',
                    repo_url=''):

        cur = self.db.execute("""\
              insert into wapt_repo (
                Package,
                Version,
                Section,
                Priority,
                Architecture,
                Maintainer,
                Description,
                Filename,
                Size,
                MD5sum,
                Depends,
                Sources,
                repo_url) values (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,(
                 Package,
                 Version,
                 Section,
                 Priority,
                 Architecture,
                 Maintainer,
                 Description,
                 Filename,
                 Size,
                 MD5sum,
                 Depends,
                 Sources,
                 repo_url)
               )

        return cur.lastrowid

    def list_repo(self,words=[]):
        words = [ "%"+w.lower()+"%" for w in words ]
        search = ["lower(Description || Package) like ?"] *  len(words)
        cur = self.db.execute("select Package,Version,Description from wapt_repo where %s" % " and ".join(search),words)
        return pptable(cur,None,1,None)

    def add_package_entry(self,package_entry):
        cur = self.db.execute("""delete from wapt_repo where Package=? and Version=?""" ,(package_entry.Package,package_entry.Version))

        self.add_package(package_entry.Package,
                         package_entry.Version,
                         package_entry.Section,
                         package_entry.Priority,
                         package_entry.Architecture,
                         package_entry.Maintainer,
                         package_entry.Description,
                         package_entry.Filename,
                         package_entry.Size,
                         package_entry.MD5sum,
                         package_entry.Depends,
                         package_entry.Sources,
                         package_entry.repo_url)


    def add_start_install(self,package,version,params_dict={}):
        """Register the start of installation in local db"""
        try:
            cur = self.db.execute("""delete from wapt_localstatus where Package=?""" ,(package,))
            cur = self.db.execute("""\
                  insert into wapt_localstatus (
                    Package,
                    Version,
                    InstallDate,
                    InstallStatus,
                    InstallOutput,
                    InstallParams
                    ) values (?,?,?,?,?,?)
                """,(
                     package,
                     version,
                     datetime2isodate(),
                     'INIT',
                     '',
                     json.dumps(params_dict),
                   ))
        finally:
            self.db.commit()
        return cur.lastrowid

    def update_install_status(self,rowid,installstatus,installoutput,uninstallkey=None,uninstallstring=None,):
        """Update status of package installation on localdb"""
        try:
            cur = self.db.execute("""\
                  update wapt_localstatus
                    set InstallStatus=?,InstallOutput = InstallOutput || ?,UninstallKey=?,UninstallString=?
                    where rowid = ?
                """,(
                     installstatus,
                     installoutput,
                     uninstallkey,
                     uninstallstring,
                     rowid,
                     )
                   )
        finally:
            self.db.commit()
        return cur.lastrowid

    def remove_install_status(self,package):
        """Remove status of package installation from localdb"""
        try:
            cur = self.db.execute("""delete from wapt_localstatus where Package=?""" ,(package,))
        finally:
            self.db.commit()
        return cur.lastrowid

    def list_installed_packages(self,words=[],okonly=False):
        """Returns a cursor (Status, Package,VersionInstallDate,InstallStatus,Description for installed packets having words in their package name"""
        words = [ "%"+w.lower()+"%" for w in words ]
        search = ["lower(l.Package) like ?"] *  len(words)
        if okonly:
            search.append('l.InstallStatus in ("OK","UNKNOWN")')
        cur = self.db.execute("""\
              select
                CASE l.Version WHEN l.Version<r.Version THEN 'U' ELSE 'I' END as "Status",
                l.Package,l.Version,l.InstallDate,l.InstallStatus,r.Description
              from wapt_localstatus l
                left join wapt_repo r on l.Package=r.Package and l.Version=r.Version
              where %s
              order by l.Package
            """ %  (" and ".join(search) or "l.Package is not null",), words )
        return cur

    def known_packages(self):
        """return a list of all (package,version)"""
        q = self.db.execute("""\
              select distinct wapt_repo.Package,wapt_repo.Version from wapt_repo
           """)
        return [PackageKey(*e) for e in q.fetchall()]

    def installed(self):
        """Return a dictionary of installed packages : keys=package names, values = package dict """
        q = self.query("""\
              select wapt_localstatus.*,wapt_repo.Filename from wapt_localstatus
                left join wapt_repo on wapt_repo.Package=wapt_localstatus.Package
              where wapt_localstatus.InstallStatus in ("OK","UNKNOWN")
              order by wapt_localstatus.Package
           """)
        result = {}
        for p in q:
            result[p['Package']]= p
        return result

    def upgradeable(self):
        """Return a dictionary of packages to upgrade : keys=package names, value = package dict"""
        q = self.query("""\
           select l.*,r.Version as NewVersion,r.Filename from wapt_localstatus l
            left join wapt_repo r on r.Package=l.Package
           """)
        #where wapt_localstatus.Version<wapt_repo.Version
        result = {}
        qsort = []
        for p in q:
             result[p['Package']]= p
        return result

    def update_repos_list(url_list):
        """Cleanup all"""
        try:
            logger.debug('Purge packages table')
            self.db.execute('delete from wapt_repo where repo_url no in ?',(url_list,))
            logger.debug('Commit wapt_repo updates')
            self.db.commit()
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
            self.db.execute('delete from wapt_repo where repo_url=?',(repourl,))
            startline = 0
            endline = 0
            def add(start,end):
                if start <> end:
                    package = Package_Entry()
                    package.load_control_from_wapt(packageListFile[start:end])
                    logger.info("%s (%s)" % (package.Package,package.Version))
                    logger.debug(package)
                    package.repo_url = repourl
                    self.add_package_entry(package)
                    result.append((package.Package,package.Version))

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

            logger.debug('Commit wapt_repo updates')
            self.db.commit()
            return result
        except:
            logger.debug('rollback delete repo')
            self.db.rollback()
            raise

    def build_depends(self,packages):
        """Given a list of packages names Return a list of dependencies packages names to install
            TODO : currently doesn't take care on versions...
        """
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
                    entry = self.package_entry_from_db(package)
                    # depends is a comma seperated list
                    depends = [s.strip() for s in entry.Depends.split(',') if s.strip()<>'']
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
        result = Package_Entry()
        filter = ""
        if version_min is None:
            version_min=""
        if version_max is None:
            version_max=""


        if not version_min and not version_max:
            entries = self.query("""select * from wapt_repo where Package = ? order by version desc limit 1""",(package,))
        else:
            entries = self.query("""select * from wapt_repo where Package = ? and (version>=? or ?="") and (version<=? or ?="") order by version desc limit 1""",
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
        execute la requete query sur la db et renvoie un tableau de Package_Entry
        Le matching est fait sur le nom de champs. Les champs qui ne matchent pas un attribut de Package_Entry
            sont accessibles par un attribut 'fields'
        """
        result = []
        cur = self.db.execute(query, args)
        for row in cur.fetchall():
            pe = Package_Entry()
            rec_dict = dict((cur.description[idx][0], value) for idx, value in enumerate(row))
            for k in rec_dict:
                if k in pe.all_attributes:
                    setattr(pe,k,rec_dict[k])
            setattr(pe,'fields',rec_dict)
            result.append(pe)
        return result



######################"""
class Wapt:
    """Global WAPT engine"""
    def __init__(self,config=None,defaults=None):
        """Initialize engine with a configParser instance (inifile) and other defaults in a dictionary
            Main properties are :
        """
        self.wapt_base_dir = os.path.dirname(sys.argv[0])
        self.config = config
        # default config file
        if not config:
            config = ConfigParser(defaults = defaults)
            config.read(os.path.join(self.wapt_base_dir,'wapt-get.ini'))
        self.wapt_repourl = ""
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
        self.upload_cmd = ''

    @property
    def waptdb(self):
        if not self._waptdb:
            self._waptdb = WaptDB(dbpath=self.dbpath)
        return self._waptdb

    def find_wapt_server(self):
        """Search the nearest working WAPT repository given the following priority
           - URL defined in ini file
           - first SRV record in the same network as one of the connected network interface
           - first SRV record with the heigher weight
           - wapt CNAME in the local dns domain (https first then http)
           - hardcoded http://wapt/wapt

        """
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

        if self.config:
            url = self.config.get('global','repo_url')
            if url:
                if _tryurl(url+'/Packages'):
                    return url
                else:
                    logger.warning('URL defined in ini file %s is not available' % url)
            if not url:
                logger.debug('No url defined in ini file')

        if dnsdomain and dnsdomain <> '.':
            # find by dns SRV _wapt._tcp
            try:
                logger.debug('Trying _wapt._tcp.%s SRV records' % dnsdomain)
                answers = dns.resolver.query('_wapt._tcp.%s' % dnsdomain,'SRV')
                working_url = []
                for a in answers:
                    # get first numerical ipv4 from SRV name record
                    try:
                        wapthost = a.target.to_text()[0:-1]
                        ip = dns.resolver.query(a.target)[0].to_text()
                        if a.port == 80:
                            url = 'http://%s/wapt' % (wapthost,)
                            if _tryurl(url+'/Packages'):
                                working_url.append((a.weight,url))
                                if is_inmysubnets(ip):
                                    return url
                        elif a.port == 443:
                            url = 'https://%s/wapt' % (wapthost,)
                            if _tryurl(url+'/Packages'):
                                working_url.append((a.weight,url))
                                if is_inmysubnets(ip):
                                    return url
                        else:
                            url = 'http://%s:%i/wapt' % (wapthost,a.port)
                            if _tryurl(url+'/Packages'):
                                working_url.append((a.weight,url))
                                if is_inmysubnets(ip):
                                    return url
                    except Exception,e:
                        logging.debug('Unable to resolve : error %s' % (e,))

                if working_url:
                    working_url.sort()
                    logger.debug('  Accessible servers : %s' % (working_url,))
                    return working_url[-1][0][1]

                if not answers:
                    logger.debug('  No _wapt._tcp.%s SRV record found' % dnsdomain)
            except dns.exception.DNSException,e:
                logger.warning('  DNS resolver error : %s' % (e,))

            # find by dns CNAME
            try:
                logger.debug('Trying wapt.%s CNAME records' % dnsdomain)
                answers = dns.resolver.query('wapt.%s' % dnsdomain,'CNAME')
                for a in answers:
                    wapthost = a.target.canonicalize().to_text()[0:-1]
                    url = 'https://%s/wapt' % (wapthost,)
                    if _tryurl(url+'/Packages'):
                        return url
                    url = 'http://%s/wapt' % (wapthost,)
                    if _tryurl(url+'/Packages'):
                        return url
                if not answers:
                    logger.debug('  No wapt.%s CNAME SRV record found' % dnsdomain)

            except dns.exception.DNSException,e:
                logger.warning('  DNS resolver error : %s' % (e,))
        else:
            logger.warning('Local DNS domain not found, skipping SRV _wapt._tcp and CNAME search ')

        # hardcoded wapt
        url = 'http://wapt/wapt'
        if _tryurl(url+'/Packages'):
            return url

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
        """return cmd to uninstall from registry"""
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

    def install_wapt(self,fname,params_dict={}):
        logger.info("Register start of install %s to local DB with params %s" % (fname,params_dict))
        status = 'INIT'
        previous_uninstall = self.registry_uninstall_snapshot()
        entry = Package_Entry()
        entry.load_control_from_wapt(fname)
        old_stdout = sys.stdout
        old_stderr = sys.stderr

        # we  record old sys.path as we will include current setup.py
        oldpath = sys.path

        install_id = None
        install_id = self.waptdb.add_start_install(entry.Package ,entry.Version)
        # we setup a redirection of stdout to catch print output from install scripts
        sys.stderr = sys.stdout = installoutput = LogInstallOutput(sys.stdout,self.waptdb,install_id)
        hdlr = logging.StreamHandler(installoutput)
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
                logger.info('  unzipping %s to temporary' % (fname))
                zip = zipfile.ZipFile(fname)
                zip.extractall(path=packagetempdir)
                istemporary = True
            elif os.path.isdir(fname):
                packagetempdir = fname
            else:
                raise Exception('%s is not a file nor a directory, aborting.' % fname)

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

            if not self.dry_run:
                try:
                    logger.info("  executing install script")
                    exitstatus = setup.install()
                except Exception,e:
                    logger.critical('Fatal error in install script: %s' % e)
                    raise

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
                shutil.rmtree(packagetempdir)

            self.waptdb.update_install_status(install_id,status,'',str(new_uninstall_key) if new_uninstall_key else '',str(uninstallstring) if uninstallstring else '')
            # (entry.Package,entry.Version,status,json.dumps({'output':installoutput.output,'exitstatus':exitstatus}))

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
            raise
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
        entry = self.waptdb.package_entry_from_db(package)
        if not entry.Sources:
            raise Exception('No sources defined in package control file')
        if "PROGRAMW6432" in os.environ:
            svncmd = os.path.join(environ['PROGRAMW6432'],'TortoiseSVN','svn.exe')
        else:
            svncmd = os.path.join(environ['PROGRAMFILES'],'TortoiseSVN','svn.exe')
        if not os.path.isfile(svncmd):
            raise Exception('svn.exe command not available, please install TortoiseSVN with commandline tools')
        co_dir = re.sub('(/trunk/?$)|(/tags/?$)|(/branch/?$)','',entry.source)
        logger.info(subprocess.check_output('svn co %s %s' % (svncmd,codir)))

    def last_install_log(self,packagename):
        """Return last install status and log for package"""
        q = self.waptdb.query("""\
           select InstallStatus,InstallOutput from wapt_localstatus
            where Package=? order by InstallDate desc limit 1
           """ , (packagename,) )
        if not q:
            raise Exception("Package %s not found in local DB status" % packagename)
        return {"status" : q[0]['InstallStatus'], "log":q[0]['InstallOutput']}

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
            raise Exception('No main WAPT repository setup')
        self.waptdb.update_packages_list(self.wapt_repourl)
        current = self.waptdb.known_packages()
        result = {
            "added":   [ p for p in current if not p in previous ],
            "removed": [ p for p in previous if not p in current],
            "count" : len(current),
            "repos" : [self.wapt_repourl],
            }
        return result

    def checkinstall(self,apackages,force=False):
        """Check which package to upgrade, to install"""
        if not isinstance(apackages,list):
            apackages = [apackages]
        allupgrades = self.waptdb.upgradeable()
        allinstalled = self.waptdb.installed()
        # packages to install after skipping already installed ones
        packages = []
        skipped = []
        # check already installed top packages
        if not force:
            for p in apackages:
                # package seul ou avec sa version
                # Version = None : derniere version
                if not p in allupgrades and p in allinstalled:
                    skipped.append((p,allinstalled[p]['Version']))
                else:
                    packages.append(p)
        else:
            packages = apackages

        # get dependencies of not installed top packages
        depends = self.waptdb.build_depends(packages)
        to_upgrade =  [ p for p in depends if p in allupgrades.keys() ]
        additional_install = [ p for p in depends if not p in allinstalled.keys() ]
        # other depencies skipped because they are already installed and at the latest version
        remaining = [ (p,allinstalled[p]['Version']) for p in depends if not p in to_upgrade and not p in additional_install]
        if remaining:
            skipped.extend( remaining )
        return {'additional':additional_install,'upgrade':to_upgrade,'install':packages,'skipped':skipped}

    def install(self,apackages,force=False,params_dict = {}):
        """Install a list of packages and its dependencies
            apackages is a list of packages names. A specific version can be specified
            force=True reinstalls the packafes even if it is already installed
            params_dict is passed to the install() procedure in the packages setup.py of all packages
                as params variables and as "setup module" attributes
        """
        if not isinstance(apackages,list):
            apackages = [apackages]

        actions = self.checkinstall(apackages,force)

        skipped = actions['skipped']
        additional_install = actions['additional']
        to_upgrade = actions['upgrade']
        packages = actions['install']

        to_install = []
        to_install.extend(additional_install)
        to_install.extend(to_upgrade)
        to_install.extend(packages)

        # [[package/version],]
        self.download_packages([(p,None) for p in to_install])
        def fname(packagefilename):
            return os.path.join(self.packagecachedir,packagefilename)

        for p in additional_install:
            self.install_wapt(fname(self.waptdb.package_entry_from_db(p).Filename),params_dict)
        for p in to_upgrade:
            self.install_wapt(fname(to_upgrade[p]['Filename']),params_dict)
        for p in packages:
            self.install_wapt(fname(self.waptdb.package_entry_from_db(p).Filename),params_dict)

        return actions


    def download_packages(self,packages,usecache=True):
        downloaded = []
        skipped = []
        errors = []
        packages_versioned = []
        for p in packages:
            if not isinstance(p,list) and not isinstance(p,tuple) :
                packages_versioned.append((p,None))
            else:
                packages_versioned.append(p)

        for (package,version) in packages_versioned:
            entry = self.waptdb.package_entry_from_db(package)
            packagefilename = entry.Filename.strip('./')
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
            where Package=?
           """ , (package,) )
        if not q:
            logger.warning("Package %s not installed, aborting" % package)
            return True

        # several versions installed of the same package... ?
        for mydict in q:
            logger.info("Removing package %s version %s from computer..." % (mydict['Package'],mydict['Version']))
            if mydict['UninstallString']:
                if mydict['UninstallString'][0] not in ['[','"',"'"]:
                    guids = mydict['UninstallString']
                else:
                    try:
                        guids = eval(mydict['UninstallString'])
                    except:
                        guids = mydict['UninstallString']
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
            elif mydict['UninstallKey']:
                if mydict['UninstallKey'][0] not in ['[','"',"'"]:
                    guids = mydict['UninstallKey']
                else:
                    try:
                        guids = eval(mydict['UninstallKey'])
                    except:
                        guids = mydict['UninstallKey']

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
        upgrades = self.list_upgrade().fetchall()
        logger.debug('upgrades : %s' % upgrades)
        self.install([p[0] for p in upgrades])
        return upgrades

    def list_upgrade(self):
        """Returns a list of packages which can be upgraded
           Package,Current Version,Available version
        """
        q = self.waptdb.db.execute("""\
           select wapt_repo.Package,max(wapt_repo.Version) as Available from wapt_localstatus
            left join wapt_repo on wapt_repo.Package=wapt_localstatus.Package
            where wapt_repo.Version > wapt_localstatus.Version
            group by wapt_repo.Package
           """)
        return q

    def download_upgrades(self):
        """Download packages that can be upgraded"""
        q = self.list_upgrade()
        to_download = [ (p[0],p[1]) for p in q ]
        return self.download_packages(to_download)

    def list_repo(self,search):
        print self.waptdb.list_repo(search)

    def list_installed_packages(self,search):
        """return a SQLIte cursor of status of installed packages"""
        return self.waptdb.list_installed_packages(search)

    def inventory(self):
        """Return software inventory of the computer as a dictionary"""
        inv = {}
        inv['softwares'] = setuphelpers.installed_softwares('')
        inv['packages'] = self.waptdb.installed()
        return inv

    def buildpackage(self,directoryname,inc_package_release=False):
        """Build the WAPT package from a directory, return the filename of the WAPT file"""
        result_filename =''
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
            entry = Package_Entry()
            if hasattr(setup,'control'):
                logger.info('Use control informations from setup.py file')
                entry.load_control_from_dict(setup.control)
                # update control file
                codecs.open(control_filename,'w',encoding='utf8').write(entry.ascontrol())
            else:
                logger.info('Use control informations from control file')
                entry.load_control_from_wapt(directoryname)
            logger.debug('Control data : \n%s' % entry.ascontrol())
            if inc_package_release:
                current_release = entry.Version.split('-')[-1]
                new_release = "%02i" % (int(current_release) + 1,)
                new_version = "-".join(entry.Version.split('-')[0:-1]+[new_release])
                logger.info('Increasing version of package from %s to %s' % (entry.Version,new_version))
                entry.Version = new_version
                entry.save_control_to_wapt(directoryname)
            package_filename =  entry.make_package_filename()
            result_filename = os.path.abspath(os.path.join( directoryname,'..',package_filename))

            create_recursive_zip_signed(
                zipfn = result_filename,
                source_root = directoryname,
                target_root = '' ,
                excludes=['.svn','.git*','*.pyc'])
        finally:
            if 'setup' in dir():
                del setup
            else:
                logger.critical('Unable to read setup.py file')
            sys.path = oldpath
            logger.debug('  Change current directory to %s' % previous_cwd)
            os.chdir(previous_cwd)
            return result_filename

    def maketemplate(self,installer_path,packagename='',directoryname=''):
        """Build a skeleton of WAPT package based on the properties of the supplied installer
           Return the path of the skeleton
        """
        packagename = packagename.lower()

        installer = os.path.basename(installer_path)
        props = setuphelpers.get_file_properties(installer_path)
        (product_name,ext) = os.path.splitext(installer)

        product_desc = product_name
        product_name = props['ProductName'] or props['FileDescription'] or product_desc
        if props['CompanyName']:
            product_desc = "%s (%s)" % (product_name,props['CompanyName'])
        if not packagename:
            simplename = re.sub(r'[\s\(\)]+','',product_name.lower())
            packagename = 'tis-%s' %  simplename
        if not directoryname:
            directoryname = os.path.join('c:\\','tranquilit',packagename)+'-wapt'
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
    run('%(installer)s /VERYSILENT')
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
            entry = Package_Entry()
            entry.Package = packagename
            entry.Architecture='all'
            entry.Description = 'automatic package for %s ' % product_desc
            entry.Maintainer = win32api.GetUserNameEx(3)
            entry.Priority = 'optional'
            entry.Section = 'base'
            entry.Version = props.get('FileVersion','0.0.0')+'-00'
            codecs.open(control_filename,'w',encoding='utf8').write(entry.ascontrol())
        else:
            logger.info('control file already exists, skip create')
        return (directoryname)

if __name__ == '__main__':
    cfg = ConfigParser()
    cfg.read('c:\\tranquilit\\wapt\\wapt-get.ini')
    w = Wapt(config=cfg)
    w.wapt_repourl = w.find_wapt_server()

    print w.remove('tis-waptdev',force=True)
    print w.remove('tis-firefox',force=True)
    print w.install('tis-firefox',force=True)
    print w.checkinstall(['tis-waptdev'],force=False)
    print w.checkinstall(['tis-waptdev'],force=True)
    print w.update()
    print w.list_upgrade().fetchall()
    pfn = w.buildpackage('c:\\tranquilit\\tis-wapttest-wapt',True)
    if not os.path.isfile(pfn):
        raise Exception("""w.buildpackage('c:\\tranquilit\\tis-wapttest-wapt',True) failed""")
    print w.install_wapt(pfn,params_dict={'company':'TIS'})
    print w.install(['tis-wapttest'],force=True)

