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

__version__ = "0.8.21"
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
import fnmatch
import platform
import imp
import socket
import dns.resolver
import copy
import getpass
import psutil
import threading
import email.utils

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

from _winreg import HKEY_LOCAL_MACHINE,EnumKey,OpenKey,QueryValueEx,EnableReflectionKey,DisableReflectionKey,QueryReflectionKey,QueryInfoKey,KEY_READ,KEY_WOW64_32KEY,KEY_WOW64_64KEY

import struct

import re
import setuphelpers
from setuphelpers import ensure_unicode

import types

logger = logging.getLogger()

def datetime2isodate(adatetime = None):
    if not adatetime:
        adatetime = datetime.datetime.now()
    assert(isinstance(adatetime,datetime.datetime))
    return adatetime.isoformat()

def httpdatetime2isodate(httpdate):
    """convert a date string as returned in http headers or mail headers to isodate
    >>> import requests
    >>> last_modified = requests.head('http://wapt/wapt/Packages',headers={'cache-control':'no-cache','pragma':'no-cache'}).headers['last-modified']
    >>> len(httpdatetime2isodate(last_modified)) == 19
    True
    """
    return datetime2isodate(datetime.datetime(*email.utils.parsedate(httpdate)[:6]))

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

ArchitecturesList = ('all','x86','x64')

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

# adapted from opsi

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
            return iso.decode(locale.getpreferredencoding())
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


def merge_dict(d1,d2):
    """merge similar dict"""
    result = copy.deepcopy(d1)
    for k in d2:
        if k in result:
            if isinstance(result[k],list):
                for item in d2[k]:
                    if not item in result[k]:
                        result[k].append(item)
            elif isinstance(result[k],dict):
                result[k]=merge_dict(result[k],d2[k])
            else:
                raise Exception('Unsupported merge')
        else:
            result[k] = d2[k]
    return result

def read_in_chunks(f, chunk_size=1024*128):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 128k."""
    while True:
        data = f.read(chunk_size)
        if not data:
            break
        yield data

def sha1_for_file(fname, block_size=2**20):
    f = open(fname,'rb')
    sha1 = hashlib.sha1()
    while True:
        data = f.read(block_size)
        if not data:
            break
        sha1.update(data)
    return sha1.hexdigest()

def sha1_for_data(data):
    assert(isinstance(data,str))
    sha1 = hashlib.sha1()
    sha1.update(data)
    return sha1.hexdigest()

def sha512_for_data(data):
    return hashlib.sha512(data).hexdigest()

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

def ssl_verify_content(content,signature,public_certs):
    u"""Check that the signature matches the content, using the provided list of public keys
        Content, signature are String
        public_certs is either a filename or a list of filenames
    >>> if not os.path.isfile('c:/private/test.pem'):
    ...     create_self_signed_key('test',organization='Tranquil IT',locality=u'St Sebastien sur Loire',commonname='wapt.tranquil.it',email='...@tranquil.it')
    >>> my_content = 'Un test de contenu'
    >>> my_signature = ssl_sign_content(my_content,'c:/private/test.pem')
    >>> ssl_verify_content(my_content,my_signature,'c:/private/test.crt')
    'C=FR, L=St Sebastien sur Loire, O=Tranquil IT, CN=wapt.tranquil.it/emailAddress=...@tranquil.it'
    """
    assert isinstance(signature,str)
    assert isinstance(public_certs,str) or isinstance(public_certs,unicode) or isinstance(public_certs,list)
    if not isinstance(public_certs,list):
        public_certs = [public_certs]
    for fn in public_certs:
        if not os.path.isfile(fn):
            raise Exception('Public certificate %s not found' % fn)
    from M2Crypto import EVP, X509
    for public_cert in public_certs:
        crt = X509.load_cert(public_cert)
        rsa = crt.get_pubkey().get_rsa()
        pubkey = EVP.PKey()
        pubkey.assign_rsa(rsa)
        pubkey.verify_init()
        pubkey.verify_update(content)
        if pubkey.verify_final(signature):
            return crt.get_subject().as_text()
    raise Exception('SSL signature verification failed, either none public certificates match signature or signed content has been changed')

def private_key_has_password(key):
    def callback(*args):
        return ""
    try:
        EVP.load_key(key, callback)
    except Exception as e:
        if "bad password" in str(e):
            return True
        else:
            print str(e)
            return True
    return False

def check_key_password(key_filename,password=""):
    """Check if provided password is valid to read the PEM private key
    >>> if not os.path.isfile('c:/private/test.pem'):
    ...     create_self_signed_key('test',organization='Tranquil IT',locality=u'St Sebastien sur Loire',commonname='wapt.tranquil.it',email='...@tranquil.it')
    >>> check_key_password('c:/private/test.pem','')
    True
    >>> check_key_password('c:/private/ko.pem','')
    False
    """
    def callback(*args):
        return password
    try:
        from M2Crypto import EVP
        from M2Crypto.EVP import EVPError
        EVP.load_key(key_filename, callback)
    except EVPError:
        return False
    return True

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
    u"""Creates a self signed key/certificate and returns the paths (keyfilename,crtfilename)
        without password
    >>> if os.path.isfile('c:/private/test.pem'):
    ...     os.unlink('c:/private/test.pem')
    >>> create_self_signed_key('test',organization='Tranquil IT',locality=u'St Sebastien sur Loire',commonname='wapt.tranquil.it',email='...@tranquil.it')
    {'crt_filename': 'c:\\\\private\\\\test.crt', 'pem_filename': 'c:\\\\private\\\\test.pem'}
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
    out = setuphelpers.run('%(opensslbin)s req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout %(destpem)s -out %(destcrt)s' %
        {'opensslbin':opensslbin,'orgname':orgname,'destcrt':destcrt,'destpem':destpem})
    return {'pem_filename':destpem,'crt_filename':destcrt}


def default_json(o):
    """callback to extend handling of json.dumps"""
    if hasattr(o,'as_dict'):
        return o.as_dict()
    elif hasattr(o,'as_json'):
        return o.as_json()
    elif isinstance(o,datetime.datetime):
        return o.isoformat()
    else:
        return u"%s" % (ensure_unicode(o),)

def jsondump(o,**kwargs):
    """Dump argument to json format, including datetime
    and customized classes with as_dict or as_json callables
    >>> class MyClass(object):
    ...    def as_dict(self):
    ...        return {'test':'a','adate2':datetime.date(2014,03,15)}
    >>> jsondump({'adate':datetime.date(2014,03,14),'an_object':MyClass()})
    '{"adate": "2014-03-14", "an_object": {"test": "a", "adate2": "2014-03-15"}}'
    """
    return json.dumps(o,default=default_json,**kwargs)

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
        if os.path.isfile(os.path.join(source_root, item)):
            if logger: logger.debug(u' adding file %s' % os.path.join(source_root, item))
            zipf.write(os.path.join(source_root, item), os.path.join(target_root,item))
            result.append([os.path.join(target_root,item),sha1_for_file(os.path.join(source_root, item))])
        elif os.path.isdir(os.path.join(source_root, item)):
            if logger: logger.debug(u'Add directory %s' % os.path.join(source_root, item))
            result.extend(create_recursive_zip_signed(zipf, os.path.join(source_root, item), os.path.join(target_root,item),excludes))
    if isinstance(zipfn,str) or isinstance(zipfn,unicode):
        if logger:
            logger.debug(u'  adding sha1 hash for all %i files' % len(result))
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
            self.console.write(txt)
            if txt <> '\n':
                self.output.append(txt)
                if txt and txt[-1]<>'\n':
                    txtdb = txt+'\n'
                else:
                    txtdb = txt
                if threading.current_thread() == self.threadid:
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


def tryurl(url,proxies=None):
    try:
        logger.debug(u'  trying %s' % url)
        headers = requests.head(url,proxies=proxies)
        if headers.ok:
            logger.debug(u'  OK')
            return True
        else:
            headers.raise_for_status()
    except Exception,e:
        logger.debug(u'  Not available : %s' % ensure_unicode(e))
        return False

def force_utf8_no_bom(filename):
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
    dbpath = ''
    db = None
    curr_db_version = '20130523'

    def __init__(self,dbpath):
        self._db_version = None
        self.dbpath = dbpath
        self.connect()

    def connect(self):
        if not self.dbpath == ':memory:' and not os.path.isfile(self.dbpath):
            dirname = os.path.dirname(self.dbpath)
            if os.path.isdir (dirname)==False:
                os.makedirs(dirname)
            os.path.dirname(self.dbpath)
            self.db=sqlite3.connect(self.dbpath,detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
            self.initdb()
            self.db.commit()
        elif self.dbpath == ':memory:':
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
            logger.debug(u'DB commit')
        else:
            self.db.rollback()
            self.db.close()
            logger.critical(u'DB error %s, rollbacking\n' % (value,))

    @property
    def db_version(self):
        if not self._db_version:
            try:
                val = self.db.execute('select value from wapt_params where name="db_version"').fetchone()
                if val:
                    self._db_version = val[0]
                else:
                    self._db_version = self.curr_db_version
            except Exception,e:
                logger.critical(u'Unable to get DB version (%s), upgrading' % ensure_unicode(e))
                self.db.rollback()
                # pre-params version
                self._db_version = self.curr_db_version
                self.upgradedb()
                self.db.execute('insert into wapt_params(name,value,create_date) values (?,?,?)',('db_version',self.curr_db_version,datetime2isodate()))
                self.db.commit()
        return self._db_version

    @db_version.setter
    def db_version(self,value):
        try:
            self.db.execute('insert or ignore into wapt_params(name,value,create_date) values (?,?,?)',('db_version',value,datetime2isodate()))
            self.db.execute('update wapt_params set value=?,create_date=? where name=?',(value,datetime2isodate(),'db_version'))
            self.db.commit()
            self._db_version = value
        except:
            logger.critical(u'Unable to set version, upgrading')
            self.db.rollback()
            self.upgradedb()


    @db_version.deleter
    def db_version(self):
        try:
            self.db.execute("delete from wapt_params where name = 'db_version'")
            self.db.commit()
            self._db_version = None
        except:
            logger.critical(u'Unable to delete version, upgrading')
            self.db.rollback()
            self.upgradedb()


    def initdb(self):
        pass

    def set_param(self,name,value):
        """Store permanently a (name/value) pair in database, replace existing one"""
        try:
            self.db.execute('insert or replace into wapt_params(name,value,create_date) values (?,?,?)',(name,value,datetime2isodate()))
            self.db.commit()
        except Exception,e:
            logger.critical('Unable to set param %s : %s : %s' % (name,value,ensure_unicode(e)))
            self.db.rollback()
            raise

    def get_param(self,name,default=None):
        """Retrieve the value associated with name from database"""
        q = self.db.execute('select value from wapt_params where name=? order by create_date desc limit 1',(name,)).fetchone()
        if q:
            return q[0]
        else:
            return default

    def delete_param(self,name):
        try:
            self.db.execute('delete from wapt_params where name=?',(name,))
            self.db.commit()
        except:
            logger.critical(u'Unable to delete param %s : %s' % (name,value))
            self.db.rollback()
            raise

    def query(self,query, args=(), one=False):
        """
        execute la requete query sur la db et renvoie un tableau de dictionnaires
        """
        cur = self.db.execute(query, args)
        rv = [dict((cur.description[idx][0], value)
                   for idx, value in enumerate(row)) for row in cur.fetchall()]
        return (rv[0] if rv else None) if one else rv

class WaptSessionDB(WaptBaseDB):
    def __init__(self,username=''):
        if not username:
            username = setuphelpers.get_current_user()
        self.username = username
        self.dbpath = os.path.join(setuphelpers.application_data(),'wapt','waptsession.sqlite')
        super(WaptSessionDB,self).__init__(self.dbpath)

    def upgradedb(self,force=False):
        """Update local database structure to current version if rules are described in db_upgrades"""
        self.db_version = curr_db_version

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

        return self.curr_db_version

    def add_start_install(self,package,version,architecture):
        """Register the start of installation in local db
        """
        try:
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
        finally:
            self.db.commit()
        return cur.lastrowid

    def update_install_status(self,rowid,install_status,install_output):
        """Update status of package installation on localdb"""
        try:
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
        finally:
            self.db.commit()
        return cur.lastrowid

    def update_install_status_pid(self,pid,install_status='ERROR'):
        """Update status of package installation on localdb"""
        try:
            cur = self.db.execute("""\
                  update wapt_sessionsetup
                    set install_status=? where process_id = ?
                """,(
                     install_status,
                     pid,
                     )
                   )
        finally:
            self.db.commit()
        return cur.lastrowid

    def remove_install_status(self,package):
        """Remove status of package installation from localdb"""
        try:
            cur = self.db.execute("""delete from wapt_sessionsetup where package=?""" ,(package,))
        finally:
            self.db.commit()
        return cur.lastrowid

    def is_installed(self,package,version):
        p = self.query('select * from  wapt_sessionsetup where package=? and version=? and install_status="OK"',(package,version))
        if p:
            return p[0]
        else:
            return None


PackageKey = namedtuple('package',('packagename','version'))

# tables : (oldversion:newversion) : old_table_name:[newtablename,{dict of changed field names}]
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
 ('0000','20130410'):{
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
 ('0000','20130423'):{
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
    }


class WaptDB(WaptBaseDB):
    """Class to manage SQLite database with local installation status"""
    dbpath = ''
    db = None

    curr_db_version = '20130523'

    def upgradedb(self,force=False):
        """Update local database structure to current version if rules are described in db_upgrades"""
        try:
            backupfn = ''
            # use cached value to avoid infinite loop
            old_structure_version = self._db_version
            if old_structure_version >= self.curr_db_version and not force:
                logger.critical(u'upgrade db aborted : current structure version %s is newer or equal to requested structure version %s' % (old_structure_version,self.curr_db_version))
                return (old_structure_version,old_structure_version)

            logger.info(u'Upgrade database schema')
            # we will backup old data in a file so that we can rollback
            backupfn = os.path.join(os.path.dirname(self.dbpath),time.strftime('%Y%m%d-%H%M%S')+'.sqlite')
            logger.debug(u' copy old data to %s' % backupfn)
            shutil.copy(self.dbpath,backupfn)

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

            # append old data in new tables
            logger.debug(u' fill with old data')
            for tablename in tables:
                if old_datas[tablename]:
                    logger.debug(u' process table %s' % tablename)
                    # get rules from db_upgrades dict
                    if new_structure_version>old_structure_version and (old_structure_version,new_structure_version) in db_upgrades:
                        (newtablename,newfieldnames) = db_upgrades[(old_structure_version,new_structure_version)].get(tablename,[tablename,{}])
                    else:
                        (newtablename,newfieldnames) = (tablename,{})

                    allnewcolumns = [ c[0] for c in self.db.execute('select * from %s limit 0' % newtablename).description]
                    # take only old columns which match a new column in new structure
                    oldcolumns = [ k for k in old_datas[tablename][0].keys() if newfieldnames.get(k,k) in allnewcolumns ]
                    logger.debug(u' old columns %s' % (oldcolumns,))
                    newcolumns = [ newfieldnames.get(k,k) for k in oldcolumns ]
                    logger.debug(u' new columns %s' % (newcolumns,))

                    insquery = "insert into %s (%s) values (%s)" % (newtablename,",".join(newcolumns),",".join("?" * len(newcolumns)))
                    for rec in old_datas[tablename]:
                        logger.debug(u' %s' %[ rec[oldcolumns[i]] for i in range(0,len(oldcolumns))])
                        self.db.execute(insquery,[ rec[oldcolumns[i]] for i in range(0,len(oldcolumns))] )

            # be sure to put back new version in table as db upgrade has put the old value in table
            self.db_version = new_structure_version
            self.db.commit()
            return (old_structure_version,new_structure_version)
        except Exception,e:
            self.db.rollback()
            if backupfn:
                logger.critical(u"UpgradeDB ERROR : %s, copy back backup database %s" % (e,backupfn))
                shutil.copy(backupfn,self.dbpath)
            raise

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
          sources varchar(255),
          repo_url varchar(255),
          repo varchar(255)
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
          install_date varchar(255),
          install_status varchar(255),
          install_output TEXT
          )"""
                        )
        self.db.execute("""
        create index idx_sessionsetup_username on wapt_sessionsetup(username,package);""")

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
                    sources='',
                    repo_url='',
                    repo='',):

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
                repo_url,
                repo) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
                 repo_url,
                 repo)
               )

        return cur.lastrowid

    def add_package_entry(self,package_entry):
        cur = self.db.execute("""delete from wapt_package where package=? and version=?""" ,(package_entry.package,package_entry.version))

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
                         sources=package_entry.sources,
                         repo_url=package_entry.repo_url,
                         repo=package_entry.repo)


    def add_start_install(self,package,version,architecture,params_dict={},explicit_by=None):
        """Register the start of installation in local db
            params_dict is the dictionary pf parameters provided on command line with --params
              or by the server
            explicit_by : username of initiator of the install.
                          if not None, install is not a dependencie but an explicit manual install
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
                    install_params,
                    explicit_by,
                    process_id
                    ) values (?,?,?,?,?,?,?,?,?)
                """,(
                     package,
                     version,
                     architecture,
                     datetime2isodate(),
                     'INIT',
                     '',
                     json.dumps(params_dict),
                     explicit_by,
                     os.getpid()
                   ))
        finally:
            self.db.commit()
        return cur.lastrowid

    def update_install_status(self,rowid,install_status,install_output,uninstall_key=None,uninstall_string=None):
        """Update status of package installation on localdb"""
        try:
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
        finally:
            self.db.commit()
        return cur.lastrowid

    def update_install_status_pid(self,pid,install_status='ERROR'):
        """Update status of package installation on localdb"""
        try:
            cur = self.db.execute("""\
                  update wapt_localstatus
                    set install_status=? where process_id = ?
                """,(
                     install_status,
                     pid,
                     )
                   )
        finally:
            self.db.commit()
        return cur.lastrowid

    def switch_to_explicit_mode(self,package,user_id):
        """Set package install mode to manual so that package is not removed when meta packages don't require it anymore"""
        try:
            cur = self.db.execute("""\
                  update wapt_localstatus
                    set explicit_by=? where package = ?
                """,(
                     user_id,
                     package,
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

    def packages_search(self,searchwords=[],exclude_host_repo=True,section_filter=None):
        """Return a list of package entries matching the search words"""
        if not isinstance(searchwords,list) and not isinstance(searchwords,tuple):
            searchwords = [searchwords]
        if not searchwords:
            words = []
            search = ['1=1']
        else:
            words = [ "%"+w.lower()+"%" for w in searchwords ]
            search = ["lower(description || package) like ?"] *  len(words)
        if exclude_host_repo:
            search.append('repo <> "wapt-host"')
        if section_filter:
            search.append('section in ( %s )' %  ",".join([ '"%s"' % x for x in  section_filter.split(',')]))

        result = self.query_package_entry("select * from wapt_package where %s" % " and ".join(search),words)
        result.sort()
        return result

    def installed(self,include_errors=False):
        """Return a dictionary of installed packages : keys=package, values = PackageEntry """
        sql = ["""\
              select l.package,l.version,l.architecture,l.install_date,l.install_status,l.install_output,l.install_params,l.explicit_by,
                r.section,r.priority,r.maintainer,r.description,r.depends,r.sources,r.filename,r.size,
                r.repo_url,r.md5sum,r.repo
                from wapt_localstatus l
                left join wapt_package r on r.package=l.package and l.version=r.version and (l.architecture is null or l.architecture=r.architecture)
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
                r.section,r.priority,r.maintainer,r.description,r.depends,r.sources,r.filename,r.size,
                r.repo_url,r.md5sum,r.repo
                from wapt_localstatus l
                left join wapt_package r on r.package=l.package and l.version=r.version and (l.architecture is null or l.architecture=r.architecture)
                where l.id = ?
           """]

        q = self.query_package_entry('\n'.join(sql),args = [id])
        if q:
            return q[0]
        else:
            return None

    def installed_search(self,searchwords=[]):
        """Return a list of installed package entries"""
        if not isinstance(searchwords,list) and not isinstance(searchwords,tuple):
            searchwords = [searchwords]
        if not searchwords:
            words = []
            search = ['1=1']
        else:
            words = [ "%"+w.lower()+"%" for w in searchwords ]
            search = ["lower(l.package || (case when r.description is NULL then '' else r.description end) ) like ?"] *  len(words)
        q = self.query_package_entry("""\
              select l.package,l.version,l.architecture,l.install_date,l.install_status,l.install_output,l.install_params,l.explicit_by,
                r.section,r.priority,r.maintainer,r.description,r.depends,r.sources,r.filename,r.size,
                r.repo_url,r.md5sum,r.repo
                 from wapt_localstatus l
                left join wapt_package r on r.package=l.package and l.version=r.version and (l.architecture is null or l.architecture=r.architecture)
              where %s
           """ % " and ".join(search),words)
        return q

    def installed_matching(self,package_cond):
        """Return True if one properly installed package match the package condition 'tis-package (>=version)' """
        package = REGEX_PACKAGE_CONDITION.match(package_cond).groupdict()['package']
        q = self.query_package_entry("""\
              select l.package,l.version,l.architecture,l.install_date,l.install_status,l.install_output,l.install_params,l.setuppy,l.explicit_by,
                r.section,r.priority,r.maintainer,r.description,r.depends,r.sources,r.filename,r.size,
                r.repo_url,r.md5sum,r.repo
                from wapt_localstatus l
                left join wapt_package r on r.package=l.package and l.version=r.version and (l.architecture is null or l.architecture=r.architecture)
              where l.package=? and l.install_status in ("OK","UNKNOWN")
           """,(package,))
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

    def update_repos_list(self,repos_list,proxies=None,force=False):
        """update the packages database with Packages files from the url repos_list"""
        try:
            logger.info(u'Remove unknown repositories from packages table and params (%s)' %(','.join('"%s"'% r.name for r in repos_list,),)  )
            self.db.execute('delete from wapt_package where repo not in (%s)' % (','.join('"%s"'% r.name for r in repos_list,)))
            self.db.execute('delete from wapt_params where name like "last-http%%" and name not in (%s)' % (','.join('"last-%s"'% r.repo_url for r in repos_list,)))
            self.db.commit()
            for repo in repos_list:
                logger.info(u'Getting packages from %s' % repo.repo_url)
                try:
                    repo.update_db(waptdb=self,force=force)
                except Exception,e:
                    logger.critical(u'Error getting Packages index from %s : %s' % (repo.repo_url,ensure_unicode(e)))
            logger.debug(u'Commit wapt_package updates')
        except:
            logger.debug(u'rollback delete table')
            self.db.rollback()
            raise


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
                        depends = [s.strip() for s in entries[-1].depends.split(',') if s.strip()<>'']
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
        "dummy (=3)"
        >>> waptdb.package_entry_from_db('dummy',version_min=2)
        "dummy (=3)"
        >>> waptdb.package_entry_from_db('dummy',version_max=1)
        "dummy (=1)"
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
        ["dummy (=2)", "dummy (=1)"]
        >>> waptdb.query_package_entry("select * from wapt_package where package=?",["dummy"],one=True)
        "dummy (=2)"
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
        try:
            self.db.execute('delete from wapt_package where repo=?',(repo_name,))
            self.db.commit()
        except:
            self.db.rollback()
            raise


class WaptRepo(object):
    """Gives access to a remote http repository, with a zipped Packages pckages index
    >>> repo = WaptRepo(name='main',url='http://wapt/wapt',timeout=4)
    >>> delta = repo.load_packages()
    >>> 'last-modified' in delta and 'added' in delta and 'removed' in delta
    True
    """
    def __init__(self,name='',url=None,proxies=None,timeout = 2,dnsdomain=None):
        """Initialize a repo at url "url". If
                 url is None, the url is requested from DNS"""
        self.name = name
        if url and url[-1]=='/':
            url = url.rstrip('/')
        self._repo_url = url
        self._cached_dns_repo_url = None

        self.proxies=proxies
        self.packages = []
        self.timeout = timeout
        if dnsdomain:
            self.dnsdomain = dnsdomain
        else:
            self.dnsdomain = setuphelpers.get_domain_fromregistry()

    def reset_network(self):
        """called by wapt when network configuration has changed"""
        self._cached_dns_repo_url = None

    @property
    def repo_url(self):
        """Return fixed url if any, else request DNS
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
            if not self._cached_dns_repo_url:
                self._cached_dns_repo_url = self.find_wapt_repo_url()
            return self._cached_dns_repo_url

    def find_wapt_repo_url(self):
        """Search the nearest working main WAPT repository given the following priority
           - URL defined in ini file
           - first SRV record in the same network as one of the connected network interface
           - first SRV record with the highest weight
           - wapt CNAME in the local dns domain (https first then http)
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
                """Return True if IP is in one of my connected subnets"""
                for i in connected_interfaces:
                    if same_net(i['addr'],ip,i['netmask']):
                        logger.debug(u'  %s is in same subnet as %s/%s local connected interface' % (ip,i['addr'],i['netmask']))
                        return True
                return False

            if self.dnsdomain and self.dnsdomain <> '.':
                # find by dns SRV _wapt._tcp
                try:
                    resolv = dns.resolver.get_default_resolver()
                    resolv.timeout = self.timeout
                    resolv.lifetime = self.timeout
                    logger.debug(u'DNS server %s' % (resolv.nameservers,))
                    logger.debug(u'Trying _wapt._tcp.%s SRV records' % self.dnsdomain)
                    answers = resolv.query('_wapt._tcp.%s.' % self.dnsdomain,'SRV')
                    working_url = []
                    for a in answers:
                        # get first numerical ipv4 from SRV name record
                        try:
                            wapthost = a.target.to_text()[0:-1]
                            ip = resolv.query(a.target)[0].to_text()
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
                            logging.debug('Unable to resolve : error %s' % (ensure_unicode(e),))

                    if working_url:
                        working_url.sort()
                        logger.debug(u'  Accessible servers : %s' % (working_url,))
                        return working_url[-1][1]

                    if not answers:
                        logger.debug(u'  No _wapt._tcp.%s SRV record found' % self.dnsdomain)
                except dns.exception.Timeout,e:
                    logger.debug(u'  DNS resolver timedout _SRV records: %s' % (ensure_unicode(e),))
                    raise

                except dns.exception.DNSException,e:
                    logger.debug(u'  DNS resolver failed looking for _SRV records: %s' % (ensure_unicode(e),))

                # find by dns CNAME
                try:
                    logger.debug(u'Trying wapt.%s CNAME records' % self.dnsdomain)
                    answers = resolv.query('wapt.%s.' % self.dnsdomain,'CNAME')
                    for a in answers:
                        wapthost = a.target.canonicalize().to_text()[0:-1]
                        url = 'https://%s/wapt' % (wapthost,)
                        if tryurl(url+'/Packages'):
                            return url
                        url = 'http://%s/wapt' % (wapthost,)
                        if tryurl(url+'/Packages'):
                            return url
                    if not answers:
                        logger.debug(u'  No wapt.%s CNAME record found' % self.dnsdomain)

                except dns.exception.Timeout,e:
                    logger.debug(u'  DNS resolver timedout CNAME records: %s' % (ensure_unicode(e),))
                    raise
                except dns.exception.DNSException,e:
                    logger.warning(u'  DNS resolver error : %s' % (ensure_unicode(e),))

                # find by dns A
                try:
                    wapthost = 'wapt.%s.' % self.dnsdomain
                    logger.debug(u'Trying %s A records' % wapthost)
                    answers = resolv.query(wapthost,'A')
                    if answers:
                        url = 'https://%s/wapt' % (wapthost,)
                        if tryurl(url+'/Packages'):
                            return url
                        url = 'http://%s/wapt' % (wapthost,)
                        if tryurl(url+'/Packages'):
                            return url
                    if not answers:
                        logger.debug(u'  No %s A record found' % wapthost)

                except dns.exception.Timeout,e:
                    logger.debug(u'  DNS resolver timedout A records: %s' % (ensure_unicode(e),))
                    raise

                except dns.exception.DNSException,e:
                    logger.warning(u'  DNS resolver error : %s' % (ensure_unicode(e),))
            else:
                logger.warning(u'Local DNS domain not found, skipping SRV _wapt._tcp and CNAME search ')

            return None
        except dns.exception.Timeout,e:
            logger.critical(u'DNS resolver timeout: %s' % (e,))
            raise

    @repo_url.setter
    def repo_url(self,value):
        """Wapt main repository URL"""
        # remove / at the end
        if value:
            value = value.rstrip('/')
        self._repo_url = value

    def load_config(self,config,section=''):
        """Load waptrepo configuration from inifile
        """
        if section:
            self.name = section
        if config.has_section(self.name):
            if config.has_option(self.name,'repo_url'):
                self.repo_url = config.get(self.name,'repo_url')
            if config.has_option(self.name,'http_proxy'):
                self.proxies = {'http':config.get(self.name,'http_proxy')}
            if config.has_option(self.name,'timeout'):
                self.timeout = config.get_float(self.name,'timeout')
        return self

    @property
    def packages_url(self):
        """return url of Packages index file"""
        return self.repo_url + '/Packages'

    def need_update(self,waptdb):
        """Return True if index has changed on repo and local db needs an update
        >>> repo = WaptRepo(name='main',url='http://wapt/wapt',timeout=4)
        >>> waptdb = WaptDB('c:/wapt/db/waptdb.sqlite')
        >>> res = repo.need_update(waptdb)
        >>> isinstance(res,bool)
        True
        """
        if not waptdb:
            logger.debug(u'need_update : no waptdb provided, update is needed')
            return True
        else:
            last_update = waptdb.get_param('last-%s' % self.repo_url[:59])
            if last_update:
                logger.debug(u'Check last-modified header for %s to avoid unecessary update' % (self.packages_url,))
                current_update = self.is_available()
                if current_update == last_update:
                    logger.info(u'Index from %s has not been updated (last update %s), skipping update' % (self.packages_url,last_update))
                    return False
                else:
                    return True
            else:
                return True

    def is_available(self):
        """Try to access the repo and return last modified date of repo index or None if not accessible
        >>> repo = WaptRepo(name='main',url='http://wapt/wapt',timeout=1)
        >>> repo.is_available() <= datetime2isodate()
        True
        >>> repo = WaptRepo(name='main',url='http://badwapt/wapt',timeout=1)
        >>> repo.is_available() is None
        True
        """
        logger.debug(u'Checking availability of %s' % (self.packages_url,))
        try:
            packages_last_modified = requests.head(
                self.packages_url,
                timeout=self.timeout,
                proxies=self.proxies,
                verify=False,
                headers={'cache-control':'no-cache','pragma':'no-cache'}
                ).headers['last-modified']
            return httpdatetime2isodate(packages_last_modified)
        except requests.RequestException as e:
            self._cached_dns_repo_url = None
            logger.warning(u'Repo packages index %s is not available : %s'%(self.packages_url,e))
            return None

    def load_packages(self):
        """Try to load index of packages as PackageEntry list from repository
                return {'added','removed'}
        """
        new_packages = []
        logger.debug(u'Read remote Packages zip file %s' % self.packages_url)
        packages_answer = requests.get(self.packages_url,proxies=self.proxies,timeout=self.timeout, verify=False,headers={'cache-control':'no-cache','pragma':'no-cache'})
        packages_answer.raise_for_status

        # Packages file is a zipfile with one Packages file inside
        packages_lines = codecs.decode(ZipFile(
              StringIO.StringIO(packages_answer.content)
            ).read(name='Packages'),'UTF-8').splitlines()

        startline = 0
        endline = 0
        def add(start,end):
            if start <> end:
                package = PackageEntry()
                package.load_control_from_wapt(packages_lines[start:end])
                logger.info(u"%s (%s)" % (package.package,package.version))
                package.repo_url = self.repo_url
                package.repo = self.name
                new_packages.append(package)

        for line in packages_lines:
            if line.strip()=='':
                add(startline,endline)
                endline += 1
                startline = endline
            # add ettribute to current package
            else:
                endline += 1
        # last one
        add(startline,endline)
        added = [ p for p in new_packages if not p in self.packages]
        removed = [ p for p in self.packages if not p in new_packages]
        self.packages = new_packages
        return {'added':added,'removed':removed,'last-modified': httpdatetime2isodate(packages_answer.headers['last-modified'])}

    def update_db(self,force=False,waptdb=None):
        """Get Packages from http repo and update local package database
            return last-update header
        >>> import common
        >>> repo = common.WaptRepo('main','http://wapt/wapt')
        >>> localdb = common.WaptDB('c:/wapt/db/waptdb.sqlite')
        >>> last_update = repo.is_available()
        >>> repo.update_db(waptdb=localdb) == last_update
        True
        """
        try:
            result = None
            # Check if updated
            if force or self.need_update(waptdb):
                logger.debug(u'Read remote Packages index file %s' % self.packages_url)
                delta = self.load_packages()
                waptdb.purge_repo(self.name)
                for package in self.packages:
                    waptdb.add_package_entry(package)
                logger.debug(u'Commit wapt_package updates')
                waptdb.db.commit()
                last_modified =delta['last-modified']
                logger.debug(u'Storing last-modified header for repo_url %s : %s' % (self.repo_url,last_modified))
                waptdb.set_param('last-%s' % self.repo_url[:59],last_modified)
                return last_modified
            else:
                return waptdb.get_param('last-%s' % self.repo_url[:59])
        except:
            logger.debug(u'rollback delete package')
            waptdb.db.rollback()
            raise

class WaptHostRepo(WaptRepo):
    """Dummy http repository for host packages"""
    def update_db(self,force=False,waptdb=None,hosts_list=[]):
        """get a list of host packages from remote repo"""
        current_host = setuphelpers.get_hostname()
        if not current_host in hosts_list:
            hosts_list.append(current_host)
        result = {}
        for host in hosts_list:
            (entry,result[host]) = self.update_host(host,waptdb,force=force)

    def update_host(self,host,waptdb,force=False):
        """Update host package from repo. returns (host package entry,entry date on server)
        >>> repo = WaptHostRepo(name='wapt-host',timeout=4)
        >>> print repo.dnsdomain
        tranquilit.local
        >>> print repo.repo_url
        http://srvwapt.tranquilit.local/wapt-host
        >>> waptdb = WaptDB(':memory:')
        >>> repo.update_host('test-dummy',waptdb)
        (None, None)
        """
        try:
            host_package_url = "%s/%s.wapt" % (self.repo_url,host)
            host_cachedate = 'date-%s' % (host,)
            host_request = requests.head(host_package_url,proxies=self.proxies,verify=False,headers={'cache-control':'no-cache','pragma':'no-cache'})
            try:
                host_request.raise_for_status()
                host_package_date = httpdatetime2isodate(host_request.headers['last-modified'])
                package = None
                if host_package_date:
                    if force or host_package_date <> waptdb.get_param(host_cachedate) or not waptdb.packages_matching(host):
                        host_package = requests.get(host_package_url,proxies=self.proxies,verify=False,headers={'cache-control':'no-cache','pragma':'no-cache'})
                        host_package.raise_for_status

                        # Packages file is a zipfile with one Packages file inside
                        control = codecs.decode(ZipFile(
                              StringIO.StringIO(host_package.content)
                            ).read(name='WAPT/control'),'UTF-8').splitlines()

                        logger.debug(u'Purge packages table')
                        waptdb.db.execute('delete from wapt_package where package=?',(host,))

                        package = PackageEntry()
                        package.load_control_from_wapt(control)
                        logger.info(u"%s (%s)" % (package.package,package.version))
                        package.repo_url = self.repo_url
                        package.repo = self.name
                        waptdb.add_package_entry(package)

                        logger.debug(u'Commit wapt_package updates')
                        waptdb.db.commit()
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
                package,host_package_date=(None,None)
                logger.debug(u'No host package available at %s' % host_package_url)
                waptdb.db.execute('delete from wapt_package where package=?',(host,))
                waptdb.db.commit()
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
            if not self._cached_dns_repo_url:
                self._cached_dns_repo_url = self.find_wapt_repo_url()+'-host'
            return self._cached_dns_repo_url

    @repo_url.setter
    def repo_url(self,value):
        """Wapt main repository URL"""
        # remove / at the end
        if value:
            value = value.rstrip('/')
        self._repo_url = value


######################"""
key_passwd = None


class Wapt(object):
    """Global WAPT engine"""

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
        self.dry_run = False
        self.private_key = ''
        self.allow_unsigned = False
        self.upload_cmd = None
        self.upload_cmd_host = self.upload_cmd
        self.after_upload = None
        self.proxies = None
        self.wapt_server = None
        self.language = None
        self.wapt_base_dir = os.path.dirname(__file__)

        self.disable_update_server_status = disable_update_server_status

        self.config = config
        self.config_filename = config_filename
        if not self.config_filename:
            self.config_filename = os.path.join(self.wapt_base_dir,'wapt-get.ini')

        # get the list of certificates to use :
        self.public_certs = glob.glob(os.path.join(self.wapt_base_dir,'ssl','*.crt'))

        self.package_cache_dir = os.path.join(self.wapt_base_dir,'cache')
        if not os.path.exists(self.package_cache_dir):
            os.makedirs(self.package_cache_dir)

        # to allow/restrict installation, supplied to packages
        self.user = setuphelpers.get_current_user()
        self.usergroups = None

        self.load_config(config_filename = self.config_filename)

        self.options = OptionParser()
        self.options.force = False

        # list of process pids launched by run command
        self.pidlist = []

        import pythoncom
        pythoncom.CoInitialize()

    def load_config(self,config_filename=None):
        """Load configuration parameters from supplied inifilename
        """
        # default config file
        defaults = {
            'repo_url':'',
            'templates_repo_url':'',
            'private_key':'',
            'wapt_server':'',
            'loglevel':'warning',
            'default_package_prefix':'tis',
            'default_sources_suffix':'wapt',
            'default_sources_root':'c:\\waptdev',
            'default_sources_url':'',
            'upload_cmd':'',
            'upload_cmd_host':'',
            'after_upload':'',
            'allow_unsigned':'0',
            'http_proxy':'',
            'tray_check_interval':2,
            'service_interval':2,
            }

        if not self.config:
            self.config = RawConfigParser(defaults = defaults)

        if config_filename:
            self.config_filename = config_filename

        self.config.read(self.config_filename)

        """ deprecated
        self._wapt_repourl = self.config.get('global','repo_url')
        if self._wapt_repourl and self._wapt_repourl[-1] == '/':
            self._wapt_repourl = self._wapt_repourl.rstrip('/')
        """

        if self.config.has_option('global','dbdir'):
            self.dbdir =  self.config.get('global','dbdir')
        else:
            self.dbdir = os.path.join(self.wapt_base_dir,'db')
        if not os.path.exists(self.dbdir):
            os.makedirs(self.dbdir)
        self.dbpath = os.path.join(self.dbdir,'waptdb.sqlite')

        if self.config.has_option('global','private_key'):
            self.private_key = self.config.get('global','private_key')

        if self.config.has_option('global','allow_unsigned'):
            self.allow_unsigned = self.config.getboolean('global','allow_unsigned')

        if self.config.has_option('global','upload_cmd'):
            self.upload_cmd = self.config.get('global','upload_cmd')

        if self.config.has_option('global','upload_cmd_host'):
            self.upload_cmd_host = self.config.get('global','upload_cmd_host')

        if self.config.has_option('global','after_upload'):
            self.after_upload = self.config.get('global','after_upload')

        if self.config.has_option('global','http_proxy'):
            if self.config.has_option('global', 'use_local_connection_proxy'):
                if self.config.get('global', 'use_local_connection_proxy') == 'True':
                    self.proxies = {'http':self.config.get('global','http_proxy')}
                else:
                    self.proxies = None
            else:
                self.proxies = {'http':self.config.get('global','http_proxy')}

        if self.config.has_option('global','wapt_server'):
            self.wapt_server = self.config.get('global','wapt_server')

        if self.config.has_option('global','language'):
            self.language = self.config.get('global','language')

        # Get the configuration of all repositories (url, ...)
        self.repositories = []
        # secondary
        if self.config.has_option('global','repositories'):
            names = [n.strip() for n in self.config.get('global','repositories').split(',')]
            logger.info(u'Other repositories : %s' % (names,))
            for name in names:
                if name:
                    w = WaptRepo(name=name).load_config(self.config)
                    self.repositories.append(w)
                    logger.debug(u'    %s:%s' % (w.name,w.repo_url))
        # last is main repository so it overrides the secondary repositories
        main = WaptRepo(name='global').load_config(self.config)
        self.repositories.append(main)

        # add an automatic host repo
        host_repo = WaptHostRepo(name='wapt-host').load_config(self.config)
        if main._repo_url and not host_repo._repo_url:
            host_repo.repo_url = main.repo_url+'-host'

        self.repositories.append(host_repo)

    def write_config(self,config_filename=None):
        """Update configuration parameters to supplied inifilename
        """
        for key in self.config.defaults():
            if hasattr(self,key) and getattr(self,key) <> self.config.defaults()[key]:
                logger.debug('update config global.%s : %s' % (key,getattr(self,key)))
                self.config.set('global',key,getattr(self,key))
        repositories_names = ','.join([ r.name for r in self.repositories if r.name not in ('global','wapt-host')])
        if self.config.has_option('global','repositories') and repositories_names <> '':
            self.config.set('global','repositories',repositories_names)
        self.config.write(open(self.config_filename,'wb'))

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
        logger.info('Status : %s' % ensure_unicode(waptstatus))
        self.write_param('runstatus',waptstatus)
        if not self.disable_update_server_status and self.wapt_server:
            try:
                self.update_server_status()
            except Exception,e:
                logger.critical('Unable to update server with current status : %s' % ensure_unicode(e))


    def upload_package(self,cmd_dict,wapt_server_user=None,wapt_server_passwd=None):
      if not self.upload_cmd and not wapt_server_user:
        wapt_server_user = raw_input('WAPT Server user :')
        wapt_server_passwd = getpass.getpass('WAPT Server password :').encode('ascii')
      auth =  (wapt_server_user, wapt_server_passwd)

      if cmd_dict['waptdir'] == "wapt-host":
        if self.upload_cmd_host:
          cmd_dict['waptfile'] = ' '.join(cmd_dict['waptfile'])
          return self.run(self.upload_cmd_host % cmd_dict)
        else:
           #upload par http vers un serveur WAPT  (url POST upload_host)
           for file in cmd_dict['waptfile']:
    			file =  file[1:-1]
    			with open(file,'rb') as afile:
    				req = requests.post("%s/upload_host" % (self.wapt_server,),files={'file':afile},proxies=self.proxies,verify=False,auth=auth)
    				req.raise_for_status()

           return req.content

      else:
        if self.upload_cmd:
          cmd_dict['waptfile'] = ' '.join(cmd_dict['waptfile'])
          return self.run(self.upload_cmd % cmd_dict)
        else:
          for file in cmd_dict['waptfile']:
            # file is surrounded by quotes for shell usage
            file = file[1:-1]
            #upload par http vers un serveur WAPT  (url POST upload_package)
            with open(file,'rb') as afile:
                req = requests.post("%s/upload_package/%s" % (self.wapt_server,os.path.basename(file)),data=afile,proxies=self.proxies,verify=False,auth=auth)
                req.raise_for_status()
          return req.content

    def check_install_running(self,max_ttl=60):
        """ Check if an install is in progress, return list of pids of install in progress
            Kill old stucked wapt-get processes/children and update db status
            max_ttl is maximum age of wapt-get in minutes
        """

        logger.debug('Checking if old install in progress')
        # kill old wapt-get
        mindate = time.time() - max_ttl*60

        killed=[]
        for p in psutil.process_iter():
            try:
                if p.pid <> os.getpid() and (p.create_time() < mindate) and p.name() in ('wapt-get','wapt-get.exe'):
                    logger.debug('Killing process tree of pid %i' % p.pid)
                    setuphelpers.killtree(p.pid)
                    logger.debug('Killing pid %i' % p.pid)
                    killed.append(p.pid)
            except (psutil.NoSuchProcess,psutil.AccessDenied):
                pass

        # reset install_status
        logger.debug('reset stalled install_status in database')
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

    def registry_uninstall_snapshot(self):
        """Return list of uninstall ID from registry
             launched before and after an installation to capture uninstallkey
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
        """return the (quiet) command stored in registry to uninstall a software given its registry key"""
        def get_fromkey(uninstall):
            key = reg_openkey_noredir(HKEY_LOCAL_MACHINE,"%s\\%s" % (uninstall,guid))
            try:
                cmd = QueryValueEx(key,'QuietUninstallString')[0]
                return cmd
            except WindowsError:
                try:
                    cmd = QueryValueEx(key,'UninstallString')[0]
                    if 'msiexec' in cmd.lower():
                        cmd = cmd.replace('/I','/X').replace('/i','/X')
                        args = shlex.split(cmd,posix=False)
                        if not '/q' in cmd.lower():
                            args.append('/q')
                    else:
                        # separer commande et parametres pour eventuellement
                        cmd_arg = re.match(r'([^/]*?)\s+([/-].*)',cmd)
                        if cmd_arg:
                            (prog,arg) = cmd_arg.groups()
                            args = [ prog ]
                            args.extend(shlex.split(arg,posix=False))
                        # mozilla et autre
                        # si pas de "" et des espaces et pas d'option, alors encadrer avec des quotes
                        elif not(' -' in cmd or ' /' in cmd) and ' ' in cmd:
                            args = [ cmd ]
                        else:
                        #sinon splitter sur les paramètres
                            args = shlex.split(cmd,posix=False)

                        # remove double quotes if any
                        if args[0].startswith('"') and args[0].endswith('"') and (not "/" in cmd or not "--" in cmd):
                            args[0] = args[0][1:-1]

                        if ('spuninst' in cmd.lower()):
                             if not ' /quiet' in cmd.lower():
                                args.append('/quiet')
                        elif ('uninst' in cmd.lower() or 'helper.exe' in cmd.lower()) :
                            if not ' /s' in cmd.lower():
                                args.append('/S')
                        elif ('unins000' in cmd.lower()):
                             if not ' /silent' in cmd.lower():
                                args.append('/silent')
                    return args
                except WindowsError:
                    is_msi = QueryValueEx(key,'WindowsInstaller')[0]
                    if is_msi == 1:
                        return u'msiexec /quiet /norestart /X %s' % guid
                    else:
                        raise

        try:
            return get_fromkey("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        except:
            if platform.machine() == 'AMD64':
                return get_fromkey("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
            else:
                raise

    def corrupted_files_sha1(self,rootdir,manifest):
        """check hexdigest sha1 for the files in manifest
        returns a list of non matching files (corrupted files)"""
        assert os.path.isdir(rootdir)
        assert isinstance(manifest,list) or isinstance(manifest,tuple)
        errors = []
        for (filename,sha1) in manifest:
            fullpath = os.path.join(rootdir,filename)
            if sha1 <> sha1_for_file(fullpath):
                errors.append(filename)
        return errors

    def set_local_password(self,pwd):
        """Set password for waptservice in ini file as a MD5 hex hash"""
        import md5
        conf = RawConfigParser()
        conf.read(self.config_filename)
        conf.set('global','md5_password',md5.md5(pwd).hexdigest())
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
        except Exception,e:
            print u'Warning : %s' % e
            return ''

    def install_wapt(self,fname,params_dict={},explicit_by=None):
        """Install a single wapt package given its WAPT filename.
        return install status"""
        install_id = None
        old_hdlr = None
        old_stdout = None
        old_stderr = None

        self.check_cancelled()
        logger.info(u"Register start of install %s as user %s to local DB with params %s" % (fname, setuphelpers.get_current_user(), params_dict))
        logger.info(u"Interactive user:%s, usergroups %s" % (self.user,self.usergroups))
        status = 'INIT'
        if not self.public_certs and not self.allow_unsigned:
            raise Exception(u'install_wapt %s: No public Key provided for package signature checking, and unsigned packages install is not allowed.\
                    If you want to allow unsigned packages, add "allow_unsigned=1" in wapt-get.ini file'%(fname,))
        previous_uninstall = self.registry_uninstall_snapshot()
        entry = PackageEntry()
        entry.load_control_from_wapt(fname)
        self.runstatus="Installing package %s version %s ..." % (entry.package,entry.version)
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
            logger.info(u"Installing package " + fname)
            # case where fname is a wapt zipped file, else directory (during developement)
            istemporary = False
            if os.path.isfile(fname):
                packagetempdir = tempfile.mkdtemp(prefix="wapt")
                logger.info(u'  unzipping %s to temporary %s' % (fname,packagetempdir))
                zip = ZipFile(fname)
                zip.extractall(path=packagetempdir)
                istemporary = True
            elif os.path.isdir(fname):
                packagetempdir = fname
            else:
                raise Exception('%s is not a file nor a directory, aborting.' % fname)

            # chech sha1
            self.check_cancelled()
            manifest_filename = os.path.join( packagetempdir,'WAPT','manifest.sha1')
            if os.path.isfile(manifest_filename):
                manifest_data = open(manifest_filename,'r').read()
                # check signature of manifest
                signature_filename = os.path.join( packagetempdir,'WAPT','signature')
                # if public key provided, and signature in wapt file, check it
                if not self.allow_unsigned:
                    if self.public_certs and os.path.isfile(signature_filename):
                        signature = open(signature_filename,'r').read().decode('base64')
                        try:
                            subject = ssl_verify_content(manifest_data,signature,self.public_certs)
                            logger.info('Package issued by %s' % (subject,))
                        except:
                            raise Exception('Package file %s signature is invalid' % fname)
                    else:
                        if not self.allow_unsigned:
                            raise Exception('No certificate provided for %s or package does not contain a signature, and unsigned packages install is not allowed' % fname)

                manifest = json.loads(manifest_data)
                errors = self.corrupted_files_sha1(packagetempdir,manifest)
                if errors:
                    raise Exception('Error in package %s, files corrupted, SHA1 not matching for %s' % (fname,errors,))
            else:
                # we allow unsigned in development mode where fname is a directory
                if not self.allow_unsigned and istemporary:
                    raise Exception('Package %s does not contain a manifest.sha1 file, and unsigned packages install is not allowed' % fname)

            self.check_cancelled()
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
                        params_dict[p] = raw_input("%s: " % p)
                    else:
                        raise Exception('Required parameters %s is not supplied' % p)
            logger.info('Install parameters : %s' % (params_dict,))

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
                    logger.critical(u'Fatal error in install script: %s' % ensure_unicode(e))
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
                new_uninstall_key = setup.uninstallkey
            else:
                new_uninstall = self.registry_uninstall_snapshot()
                new_uninstall_key = [ k for k in new_uninstall if not k in previous_uninstall]

            # get uninstallstring from setup module (string or array of strings)
            if hasattr(setup,'uninstallstring'):
                uninstallstring = setup.uninstallstring
            else:
                uninstallstring = None
            logger.info(u'  uninstall keys : %s' % (new_uninstall_key,))
            logger.info(u'  uninstall strings : %s' % (uninstallstring,))

            logger.info(u"Install script finished with status %s" % status)
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

        except Exception,e:
            if install_id:
                try:
                    try:
                        uerror = repr(e).decode(locale.getpreferredencoding())
                    except:
                        uerror = ensure_unicode(e)
                    self.waptdb.update_install_status(install_id,'ERROR',uerror)
                except Exception,e2:
                    logger.critical(ensure_unicode(e2))
            else:
                logger.critical(ensure_unicode(e))
            raise e
        finally:
            if 'setup' in dir():
                del setup
            """
            if old_hdlr:
                logger.handlers[0] = old_hdlr
            else:
                logger.removeHandler(hdlr)
            """
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
            if upgrades is not None:
                status["upgrades"] = upgrades
            else:
                status["upgrades"] = [ "%s" % (p.asrequirement(),) for p in self.list_upgrade()]

            logger.debug("store status in DB")
            self.write_param('last_update_status',jsondump(status))
            return status
        except Exception,e:
            logger.critical('Unable to store status of update in DB : %s'% ensure_unicode(e))

    def get_sources(self,package):
        """Download sources of package (if referenced in package as a https svn)
           in the current directory"""
        entry = self.waptdb.packages_matching(package)[-1]

        if not entry.sources:
            if self.config.has_option('global','default_sources_url'):
                entry.sources = self.config.get('global','default_sources_url') % {'packagename':package}

        if not entry.sources:
            raise Exception('No sources defined in package control file')
        if "PROGRAMW6432" in os.environ:
            svncmd = os.path.join(os.environ['PROGRAMW6432'],'TortoiseSVN','bin','svn.exe')
        else:
            svncmd = os.path.join(os.environ['PROGRAMFILES'],'TortoiseSVN','bin','svn.exe')
        logger.debug(u'svn command : %s'% svncmd)
        if not os.path.isfile(svncmd):
            raise Exception('svn.exe command not available, please install TortoiseSVN with commandline tools')

        # checkout directory
        co_dir = self.get_default_development_dir(entry.package, section = entry.section)

        logger.info('sources : %s'% entry.sources)
        logger.info('checkout dir : %s'% co_dir)
        # if already checked out...
        if os.path.isdir(os.path.join(co_dir,'.svn')):
            print ensure_unicode(self.run(u'"%s" up "%s"' % (svncmd,co_dir)))
        else:
            print ensure_unicode(self.run(u'"%s" co "%s" "%s"' % (svncmd,entry.sources,co_dir)))
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
        """Remove cached WAPT files from local disk"""
        result = []
        logger.info('Cleaning up WAPT cache directory')
        cachepath = self.package_cache_dir
        for f in glob.glob(os.path.join(cachepath,'*.wapt')):
            if os.path.isfile(f):
                logger.debug(u'Removing %s' % f)
                try:
                    os.remove(f)
                    result.append(f)
                except Exception,e:
                    logger.warning('Unable to remove %s : %s' % (f,ensure_unicode(e)))
        return result

    def update(self,force=False,register=True):
        """Update local database with packages definition from repositories
            returns a dict of
                "added","removed","count","repos","upgrades","date"
            force : update even if Packages on repository has not been updated
                    since last update (based on http headers)
			register : Send informations about packages to waptserver
        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> updates = wapt.update()
        >>> 'count' in updates and 'added' in updates and 'upgrades' in updates and 'date' in updates and 'removed' in updates
        True

        """
        previous = self.waptdb.known_packages()
        # (main repo is at the end so that it will used in priority)
        self.waptdb.update_repos_list(self.repositories,proxies=self.proxies,force=force)

        current = self.waptdb.known_packages()
        result = {
            "added":   [ p for p in current if not p in previous ],
            "removed": [ p for p in previous if not p in current],
            "count" : len(current),
            "repos" : [r.repo_url for r in self.repositories],
            "upgrades": [ "%s" % (p.asrequirement(),) for p in self.list_upgrade()],
            "date":datetime2isodate(),
            }

        self.store_upgrade_status(result['upgrades'])
        if not self.disable_update_server_status and register:
		    try:
			    self.update_server_status()
		    except Exception,e:
		        logger.critical('Unable to update server with current status : %s' % ensure_unicode(e))
        return result

    def check_depends(self,apackages,forceupgrade=False,force=False,assume_removed=[]):
        """Given a list of packagename or requirement "name (=version)",
                return a dictionnary of {'additional' 'upgrade' 'install' 'skipped' 'unavailable'} of
                    [packagerequest,matching PackageEntry]
            forceupgrade : check if the current installed packages is the latest available
            force : install the latest version even if the package is already there and match the requirement
            assume_removed: list of packagename which are assumed to be absent even if they are installed to check the
                            consequences of removal of packages, implies force=True
        """
        if not isinstance(apackages,list):
            apackages = [apackages]

        if not isinstance(assume_removed,list):
            assume_removed = [assume_removed]
        if assume_removed:
            force=True
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

            # removes "assumed removed" packages
            if old_matches:
                for packagename in assume_removed:
                    if old_matches.match(packagename):
                        old_matches = None
                        break

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
                    if [request,None] not in unavailable:
                        unavailable.append([request,None])

        # get dependencies of not installed top packages
        if forceupgrade:
            (depends,missing) = self.waptdb.build_depends(apackages)
        else:
            (depends,missing) = self.waptdb.build_depends([p[0] for p in packages])

        for p in missing:
            if p not in unavailable:
                unavailable.append(p)

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
                skipped.append([request,old_matches])
            else:
                # check if installable or upgradable ?
                new_availables = self.waptdb.packages_matching(request)
                if new_availables:
                    if not old_matches or (forceupgrade and old_matches < new_availables[-1]):
                        additional_install.append([request,new_availables[-1]])
                    else:
                        skipped.append([request,old_matches])
                else:
                    unavailable.append([request,None])
        result =  {'additional':additional_install,'upgrade':to_upgrade,'install':packages,'skipped':skipped,'unavailable':unavailable}
        return {'additional':additional_install,'upgrade':to_upgrade,'install':packages,'skipped':skipped,'unavailable':unavailable}

    def check_remove(self,apackages):
        """return a list of additional package to remove if apackages are removed"""
        if not isinstance(apackages,list):
            apackages = [apackages]
        result = []
        installed = [ p.package for p in self.installed().values() if p.package not in apackages ]
        for packagename in installed:
            # test for each installed package if the removal would imply a reinstall
            test = self.check_depends(packagename,assume_removed=apackages)
            # get package names only
            reinstall = [ p[0] for p in (test['upgrade'] + test['additional'])]
            for p in reinstall:
                if p in apackages and not packagename in result:
                    result.append(packagename)
        return result

    def check_install(self,apackages):
        """Return a list of actions required for install of apackages list of packages

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

        to_install = []
        to_install.extend(additional_install)
        to_install.extend(to_upgrade)
        to_install.extend(packages)

        # get package entries to install to_install is a list of (request,package)
        packages = [ p[1] for p in to_install ]



    def install(self,apackages,
            force=False,
            params_dict = {},
            download_only=False,
            usecache=True,
            printhook=None):
        """Install a list of packages and its dependencies
            Returns a dictionary of (package requirement,package) with 'install','skipped','additional'

            apackages : list of packages requirements "packagename(=version)" or list of PackageEntry.
            force : reinstalls the packages even if it is already installed
            params_dict : dict of parameters passed to the install() procedure in the packages setup.py of all packages
                          as params variables and as "setup module" attributes
            download_only : don't install package, but only download them
            usecache : use the already downloaded packages if available in cache directory
            printhook: hook for progress print
        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> def nullhook(*args):
        ...     pass
        >>> res = wapt.install(['tis-wapttest'],usecache=False,printhook=nullhook,params_dict=dict(company='toto'))
        ???
        >>> isinstance(res['upgrade'],list) and isinstance(res['errors'],list) and isinstance(res['additional'],list) and isinstance(res['install'],list) and isinstance(res['unavailable'],list)
        True
        >>> res = wapt.remove('tis-wapttest')
        ???
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

        to_install = []
        to_install.extend(additional_install)
        to_install.extend(to_upgrade)
        to_install.extend(packages)

        # get package entries to install to_install is a list of (request,package)
        packages = [ p[1] for p in to_install ]

        downloaded = self.download_packages(packages,usecache=usecache,printhook=printhook)
        if downloaded.get('errors',[]):
            raise Exception(u'Error downloading some files : %s',(downloaded['errors'],))

        # check downloaded packages signatures and merge control data in local database
        if not self.allow_unsigned:
            for fname in downloaded['downloaded'] + downloaded['skipped']:
                waptfile = zipfile.ZipFile(fname,'r',allowZip64=True)
                control = waptfile.open(u'WAPT/control').read().decode('utf8')
                manifest_content = waptfile.open(u'WAPT/manifest.sha1').read()
                manifest = json.loads(manifest_content)
                signature = waptfile.open(u'WAPT/signature').read().decode('base64')
                try:
                    subject = ssl_verify_content(manifest_content,signature,self.public_certs)
                    logger.info('Package issued by %s' % (subject,))
                except:
                    raise Exception('Package file %s signature is invalid' % fname)

                for (fn,sha1) in manifest:
                    if fn == 'WAPT\\control':
                        if sha1 <> sha1_for_data(control.encode('utf8')):
                            raise Exception("WAPT/control file of %s is corrupted, sha1 digests don't match" % fname)
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
                    logger.info('switch to manual mode for %s' % (request,))
                    self.waptdb.switch_to_explicit_mode(p.package,self.user)

            for (request,p) in to_install:
                try:
                    print u"Installing %s" % (p.package,)
                    result = self.install_wapt(fname(p.filename),
                        params_dict = params_dict,
                        explicit_by=self.user if request in apackages else None
                        )
                    if result:
                        for k in result.as_dict():
                            p[k] = result[k]

                    if not result or result['install_status']<>'OK':
                        actions['errors'].append([request,p])
                        logger.critical(u'Package %s not installed due to errors' %(request,))
                except Exception as e:
                    actions['errors'].append([request,p])
                    logger.critical(u'Package %s not installed due to errors : %s' %(request,ensure_unicode(e)))

            return actions
        else:
            logger.info(u'Download only, no install performed')
            return actions

    def download_packages(self,package_requests,usecache=True,printhook=None):
        r"""Download a list of packages (requests are of the form packagename (>version) )
           returns a dict of {"downloaded,"skipped","errors"}

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> def nullhook(*args):
        ...     pass
        >>> wapt.download_packages(['tis-firefox','tis-waptdev'],usecache=False,printhook=nullhook)
        {'downloaded': [u'cache\\tis-firefox_28.0.0-1_all.wapt', u'cache\\tis-waptdev.wapt'], 'skipped': [], 'errors': []}
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
                    raise Exception('Unavailable package %s' % (p,))
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
                    cached.load_control_from_wapt(fullpackagepath,calc_md5=False)
                    if entry == cached:
                        skipped.append(fullpackagepath)
                        logger.info("  Use cached package file from " + fullpackagepath)
                        skip = True
                except Exception,e:
                    # error : reload
                    logger.debug('Cache file %s is corrupted, reloading it' % fullpackagepath )

            if not skip:
                logger.info("  Downloading package from %s" % download_url)
                try:
                    def report(received,total,speed,url):
                        self.check_cancelled()
                        try:
                            if total>1:
                                stat = u'%s : %i / %i (%.0f%%) (%.0f KB/s)\r' % (url,received,total,100.0*received/total, speed)
                                print stat,
                            else:
                                stat = ''
                            self.runstatus='Downloading %s : %s' % (entry.package,stat)
                        except:
                            self.runstatus='Downloading %s' % (entry.package,)

                    if not printhook:
                        printhook = report

                    self.runstatus='Downloading %s' % download_url
                    setuphelpers.wget( download_url, self.package_cache_dir,proxies=self.proxies,printhook = printhook)
                    downloaded.append(fullpackagepath)
                    self.runstatus=''
                except Exception as e:
                    self.runstatus=''
                    if os.path.isfile(fullpackagepath):
                        os.remove(fullpackagepath)
                    logger.critical(u"Error downloading package from http repository, please update... error : %s" % ensure_unicode(e))
                    errors.append((download_url,"%s" % ensure_unicode(e)))
        return {"downloaded":downloaded,"skipped":skipped,"errors":errors}

    def remove(self,package,force=False):
        """Removes a package giving its package name, unregister from local status DB"""
        result = {'removed':[],'errors':[]}
        try:
            self.check_cancelled()
            # development mode, remove a package by its directory
            if os.path.isfile(os.path.join(package,'WAPT','control')):
                package = PackageEntry().load_control_from_wapt(package).package

            q = self.waptdb.query("""\
               select * from wapt_localstatus
                where package=?
               """ , (package,) )
            if not q:
                logger.warning(u"Package %s not installed, removal aborted" % package)
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
                                logger.info('Running %s' % guid)
                                logger.info(self.run(guid))
                            except Exception,e:
                                logger.warning("Warning : %s" % ensure_unicode(e))

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
                                    print ensure_unicode(self.run(uninstall_cmd))
                            except Exception,e:
                                logger.critical(u"Critical error during uninstall cmd %s: %s" % (uninstall_cmd,ensure_unicode(e)))
                                result['errors'].append(package)

                else:
                    logger.debug(u'uninstall key not registered in local DB status.')

                if mydict['install_status'] <> 'ERROR':
                    try:
                        self.uninstall(package)
                    except Exception as e:
                        logger.critical('Error running uninstall script: %s'%e)
                        result['errors'].append(package)

                logger.info('Remove status record from local DB for %s' % package)
                self.waptdb.remove_install_status(package)
                result['removed'].append(package)

                if reversed(additional_removes):
                    logger.info('Additional packages to remove : %s' % additional_removes)
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
        hostresult = {}
        logger.debug(u'Check if host package "%s" is available' % (self.host_packagename(), ))
        host_packages = self.is_available(self.host_packagename())
        if host_packages and not self.is_installed(host_packages[-1].asrequirement()):
            return host_packages[-1]
        else:
            return None

    def upgrade(self):
        """\
        Install "well known" host package from main repository if not already installed
        then
        Query localstatus database for packages with a version older than repository
        and install all newest packages
        """
        self.runstatus='Upgrade system'
        try:
            host_package = self.check_host_package_outdated()
            if host_package:
                logger.info('Host package %s is available and not installed, installing host package...' % (host_package.package,) )
                hostresult = self.install(host_package,force=True)
            else:
                hostresult = []

            upgrades = self.waptdb.upgradeable()
            logger.debug(u'upgrades : %s' % upgrades.keys())
            result = self.install(upgrades.keys(),force=True)
            self.store_upgrade_status()

            # merge results
            return merge_dict(result,hostresult)
        finally:
            self.runstatus=''

    def list_upgrade(self):
        """Returns a list of packages which can be upgraded
           Package,Current Version,Available version
        """
        result = []
        # only most up to date (first one in list)
        result.extend([p[0] for p in self.waptdb.upgradeable().values() if p])
        host_package = self.check_host_package_outdated()
        if host_package and not host_package in result:
            result.append(host_package)
        return result

    def search(self,searchwords=[],exclude_host_repo=True,section_filter=None):
        """Returns a list of packages which have the searchwords
           in their description
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

        return available

    def list(self,searchwords=[]):
        """Returns a list of installed packages which have the searchwords
           in their description
        """
        return self.waptdb.installed_search(searchwords=searchwords,)

    def download_upgrades(self):
        """Download packages that can be upgraded"""
        self.runstatus='Download upgrades'
        try:
            to_download = self.list_upgrade()
            return self.install(to_download,download_only=True)
        finally:
            self.runstatus=''

    def register_computer(self,description=None,force=False):
        """Send computer informations to WAPT Server
            if decsription is provided, updates local registry with new description
        """
        if description:
            out = self.run("WMIC os set description='%s'" % description.encode(sys.getfilesystemencoding()) ,shell=False)
            logger.info(out)

        inv = self.inventory()
        # store uuid for future use to avoid the use of dmidecode
        if not self.read_param('uuid') or self.read_param('uuid') <> inv['uuid']:
            self.write_param('uuid',inv['uuid'])
        if force:
            inv['force']=True
        if self.wapt_server:
            req = requests.post("%s/add_host" % (self.wapt_server,),json.dumps(inv),proxies=self.proxies,verify=False)
            req.raise_for_status()
            return req.content
        else:
            return json.dumps(inv,indent=True)

    def get_last_update_status(self):
        status = json.loads(self.read_param('last_update_status','{"date": "", "running_tasks": [], "errors": [], "upgrades": []}'))
        status['runstatus'] = self.read_param('runstatus','')
        return json.loads(json.dumps(status))

    def update_server_status(self,force=False):
        """Send packages and software informations to WAPT Server, don't send dmi
        """
        uuid = self.read_param('uuid')
        if not uuid:
            self.register_computer(force=force)
        else:
            inv = {'uuid': uuid}
            inv['wapt'] = self.wapt_status()
            inv['host'] = setuphelpers.host_info()
            inv['softwares'] = setuphelpers.installed_softwares('')
            inv['packages'] = [p.as_dict() for p in self.waptdb.installed(include_errors=True).values()]
            inv['update_status'] = self.get_last_update_status()
            if force:
                inv['force']=True

            if self.wapt_server:
                req = requests.post("%s/update_host" % (self.wapt_server,),json.dumps(inv),proxies=self.proxies,verify=False)
                try:
                    req.raise_for_status()
                except Exception,e:
                    logger.warning('Unable to update server status : %s' % ensure_unicode(e))
                result = json.loads(req.content)
                # force register if computer has not been registered or hostname has changed
                if not result or not 'host' in result or result['host']['computer_fqdn'] <> setuphelpers.get_hostname():
                    self.register_computer()
                return result
            else:
                return json.dumps(inv,indent=True)

    def waptserver_available(self):
        """Return ident of waptserver if defined and available, else False"""
        if self.wapt_server:
            try:
                httpreq = requests.get('%s/ident'%(self.wapt_server),timeout=self.timeout)
                httpreq.raise_for_code()
                return httpreq.text
            except Exception as e:
                return False
        else:
            return False

    def wapt_status(self):
        """return wapt version info"""
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
        return result


    def inventory(self):
        """Return software inventory of the computer as a dictionary"""
        inv = {}
        inv['host'] = setuphelpers.host_info()
        inv['dmi'] = setuphelpers.dmi_info()
        inv['wapt'] = self.wapt_status()
        inv['softwares'] = setuphelpers.installed_softwares('')
        inv['packages'] = [p.as_dict() for p in self.waptdb.installed(include_errors=True).values()]
        try:
            inv['uuid'] = inv['dmi']['System_Information']['UUID']
        except:
            inv['uuid'] = inv['host']['computer_fqdn']
        return inv

    def get_repo(self,name):
        for r in self.repositories:
            if r.name == name:
                return r
        return None

    def sign_package(self,zip_or_directoryname,excludes=['.svn','.git*','*.pyc','src'],private_key=None,callback=pwd_callback):
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
            waptzip = ZipFile(zip_or_directoryname,'a',allowZip64=True,compression=zipfile.ZIP_DEFLATED)
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

    def build_package(self,directoryname,inc_package_release=False,excludes=['.svn','.git*','*.pyc','src']):
        """Build the WAPT package from a directory
            return a dict {'filename':waptfilename,'files':[list of files]}
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
            setup = import_setup(os.path.join(directoryname,'setup.py'),'_waptsetup_')
             # be sure some minimal functions are available in setup module at install step
            logger.debug(u'Source import OK')

            # check minimal requirements of setup.py
            # check encoding
            try:
                codecs.open(os.path.join(directoryname,'setup.py'),mode='r',encoding='utf8')
            except:
                raise Exception('Encoding of setup.py is not utf8')

            if hasattr(setup,'uninstallstring'):
                mandatory = [('install',types.FunctionType) ,('uninstallstring',types.ListType),]
            else:
                mandatory = [('install',types.FunctionType) ,('uninstallkey',types.ListType),]
            for (attname,atttype) in mandatory:
                if not hasattr(setup,attname):
                    raise Exception('setup.py has no %s (%s)' % (attname,atttype))

            control_filename = os.path.join(directoryname,'WAPT','control')
            force_utf8_no_bom(control_filename)

            entry = PackageEntry()
            logger.info('Load control informations from control file')
            entry.load_control_from_wapt(directoryname)

            # optionally, setup.py can update some attributes of control files using
            # a procedure called update_control(package_entry)
            # this can help automates version maintenance
            # a check of version collision is operated automatically
            if hasattr(setup,'update_control'):
                logger.info('Update control informations with update_control function from setup.py file')
                setup.update_control(entry)

                logger.debug('Check existing versions and increment it')
                older_packages = self.is_available(entry.package)
                if older_packages and entry<=older_packages[-1]:
                    entry.version = older_packages[-1].version
                    entry.inc_build()
                    logger.warning('Older package with same name exists, incrementing packaging version to %s' % (entry.version,))

                # save control file
                entry.save_control_to_wapt(directoryname)

            # check version syntax
            parse_major_minor_patch_build(entry.version)

            # check architecture
            if not entry.architecture in ArchitecturesList:
                raise Exception('Architecture should one of %s' % (ArchitecturesList,))

            if inc_package_release:
                entry.inc_build()
                """
                current_release = entry.version.split('-')[-1]
                new_release = "%02i" % (int(current_release) + 1,)
                new_version = "-".join(entry.version.split('-')[0:-1]+[new_release])
                logger.info('Increasing version of package from %s to %s' % (entry.version,new_version))
                entry.version = new_version
                """
                entry.save_control_to_wapt(directoryname)

            package_filename =  entry.make_package_filename()
            logger.debug(u'Control data : \n%s' % entry.ascontrol())
            result_filename = os.path.abspath(os.path.join( directoryname,'..',package_filename))

            allfiles = create_recursive_zip_signed(
                zipfn = result_filename,
                source_root = directoryname,
                target_root = '' ,
                excludes=excludes)
            return {'filename':result_filename,'files':allfiles,'package':entry}
        finally:
            if 'setup' in dir():
                del setup
            else:
                logger.critical(u'Unable to read setup.py file')
            sys.path = oldpath
            logger.debug(u'  Change current directory to %s' % previous_cwd)
            os.chdir(previous_cwd)

    def build_upload(self,sources_directories,private_key_passwd=None,wapt_server_user=None,wapt_server_passwd=None,inc_package_release=False,delete_package=False):
        """Build a list of packages and upload the resulting packages to the main repository.
           if section of package is group or host, user specific wapt-host or wapt-group
        """
        if not isinstance(sources_directories,list):
            sources_directories = [sources_directories]
        result = []
        for source_dir in [os.path.abspath(p) for p in sources_directories]:
            if os.path.isdir(source_dir):
                print('Building  %s' % source_dir)
                if inc_package_release==False:
                    buildresult = self.build_package(source_dir)
                else:
                    buildresult = self.build_package(source_dir,inc_package_release=True)
                package_fn = buildresult['filename']
                if package_fn:
                    result.append(buildresult)
                    print('...done. Package filename %s' % (package_fn,))

                    def pwd_callback(*args):
                        """Default password callback for opening private keys"""
                        return private_key_passwd

                    def pwd_callback2(*args):
                        """Default password callback for opening private keys"""
                        global key_passwd
                        if not key_passwd:
                            key_passwd = getpass.getpass('Private key password :').encode('ascii')
                        return key_passwd

                    if self.private_key:
                        print('Signing %s' % package_fn)
                        if private_key_passwd is None:
                            signature = self.sign_package(package_fn,callback=pwd_callback2)
                        else:
                            signature = self.sign_package(package_fn,callback=pwd_callback)
                        print u"Package %s signed : signature :\n%s" % (package_fn,signature)
                    else:
                        logger.warning(u'No private key provided, package %s is unsigned !' % package_fn)

                else:
                    logger.critical(u'package %s not created' % package_fn)
            else:
                logger.critical(u'Directory %s not found' % source_dir)

        print 'Uploading files...'
        # groups by www target : wapt or wapt-host
        hosts = ('wapt-host',[])
        others = ('wapt',[])
        # split by destination
        for p in result:
            if p['package'].section == 'host':
                hosts[1].append(p['filename'])
            else:
                others[1].append(p['filename'])
        for package_group in (hosts,others):
            if package_group[1]:
                # add quotes for command line
                files_list = ['"%s"' % f for f in package_group[1]]
                cmd_dict =  {'waptfile': files_list,'waptdir':package_group[0]}
                print ensure_unicode(self.upload_package(cmd_dict,wapt_server_user,wapt_server_passwd))

                if delete_package:
                    dir=os.path.dirname(files_list[0][1:-1])
                    if os.path.isdir(dir):
                        logger.debug(u'Deleting directory %s' % dir )
                        shutil.rmtree(dir)

                if package_group<>hosts:
                    if self.after_upload:
                        print 'Run after upload script...'
                        print ensure_unicode(self.run(self.after_upload % cmd_dict))
                    elif self.upload_cmd:
                        print "Don't forget to update Packages index on repository !"


        return result

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
        session_db =  WaptSessionDB(self.user) # WaptSessionDB()
        with session_db:
            if force or os.path.isdir(packagename) or not session_db.is_installed(package_entry.package,package_entry.version):
                try:
                    previous_cwd = os.getcwd()

                    # source setup.py to get session_setup func
                    if os.path.isdir(packagename):
                        package_fn = os.path.join(packagename,'setup.py')
                        setup = import_setup(package_fn,'__waptsetup__')
                        logger.debug(u'Source import OK from %s' % package_fn)
                    else:
                        logger.debug(u'Sourcing setup from DB (only if session_setup found)')
                        setuppy = package_entry['setuppy']
                        if not setuppy:
                            raise Exception('Source setup.py of package %s not stored in local database' % packagename)
                        if 'session_setup()' in setuppy:
                            setup = import_code(setuppy,'__waptsetup__')
                            logger.debug(u'Source setup.py import OK from database')
                        else:
                            setup = None

                    required_params = []

                     # be sure some minimal functions are available in setup module at install step
                    if setup and hasattr(setup,'session_setup'):
                        logger.info('Launch session_setup')
                        # initialize a session record for this package
                        install_id = session_db.add_start_install(package_entry.package,package_entry.version,package_entry.architecture)

                        # redirect output to get print into session db log
                        sys.stderr = sys.stdout = install_output = LogInstallOutput(sys.stderr,session_db,install_id)
                        try:
                            setattr(setup,'run',self.run)
                            setattr(setup,'run_notfatal',self.run_notfatal)
                            setattr(setup,'user',self.user)
                            setattr(setup,'usergroups',self.usergroups)
                            setattr(setup,'WAPT',self)
                            setattr(setup,'language',self.language or setuphelpers.get_language() )

                            # get definitions of required parameters from setup module
                            if hasattr(setup,'required_params'):
                                required_params = setup.required_params

                            # get value of required parameters from system wide install
                            try:
                                params_dict=json.loads(self.waptdb.query("select install_params from wapt_localstatus where package=?",[package_entry.package,])[0]['install_params'])
                            except:
                                logger.warning('Unable to get installation parameters from wapt database for package %s' % package_entry.package)
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
                            session_db.update_install_status(install_id,'OK','session_setup() done\n')
                            return result

                        except Exception,e:
                            if install_id:
                                try:
                                    try:
                                        uerror = repr(e).decode(locale.getpreferredencoding())
                                    except:
                                        uerror = ensure_unicode(e)
                                    session_db.update_install_status(install_id,'ERROR',uerror)
                                except Exception,e2:
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
                        print 'No session-setup.',
                finally:
                    # cleanup
                    if 'setup' in dir():
                        del setup
                    else:
                        logger.critical(u'Unable to read setup.py file.')
                    sys.path = oldpath
                    logger.debug(u'  Change current directory to %s.' % previous_cwd)
                    os.chdir(previous_cwd)
            else:
                print 'Already installed.',

    def uninstall(self,packagename,params_dict={}):
        """Launch the uninstall script of an installed package"
           Source setup.py from database or filename
        """
        logger.info("setup.uninstall for package %s with params %s" % (packagename,params_dict))
        oldpath = sys.path
        try:
            previous_cwd = os.getcwd()
            if os.path.isdir(packagename):
                entry = PackageEntry().load_control_from_wapt(packagename)
                setup = import_setup(os.path.join(packagename,'setup.py'),'__waptsetup__')
            else:
                logger.debug(u'Sourcing setup from DB')
                entry = self.is_installed(packagename)
                setup = import_code(entry['setuppy'],'__waptsetup__')

            required_params = []
             # be sure some minimal functions are available in setup module at install step
            logger.debug(u'Source import OK')
            if hasattr(setup,'uninstall'):
                logger.info('Launch uninstall')
                setattr(setup,'run',self.run)
                setattr(setup,'run_notfatal',self.run_notfatal)
                setattr(setup,'user',self.user)
                setattr(setup,'usergroups',self.usergroups)
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
                del setup
            else:
                logger.critical(u'Unable to read setup.py file')
            sys.path = oldpath
            logger.debug(u'  Change current directory to %s' % previous_cwd)
            os.chdir(previous_cwd)


    def checkinstalled(self):
        """Source setup.py and launch checkinstalled"""
        result = False
        oldpath = sys.path
        try:
            previous_cwd = os.getcwd()
            logger.debug(u'  Change current directory to %s' % directoryname)
            os.chdir(directoryname)
            if not os.getcwd() in sys.path:
                sys.path = [os.getcwd()] + sys.path
                logger.debug(u'new sys.path %s' % sys.path)
            logger.debug(u'Sourcing %s' % os.path.join(directoryname,'setup.py'))
            setup = import_setup(os.path.join(directoryname,'setup.py'),'_waptsetup_')
             # be sure some minimal functions are available in setup module at install step
            logger.debug(u'Source import OK')
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
                logger.critical(u'Unable to read setup.py file')
            sys.path = oldpath
            logger.debug(u'  Change current directory to %s' % previous_cwd)
            os.chdir(previous_cwd)
            return result

    def getsilentflags(self,installer_path):
        """Detect the type of installer and returns silent silent install flags"""
        (product_name,ext) = os.path.splitext(installer_path)
        ext = ext.lower()
        if ext=='.exe':
            silentflag = '/VERYSILENT'
            props = setuphelpers.get_file_properties(installer_path)
            if props.get('InternalName','').lower() == 'sfxcab.exe':
                silentflag = '/quiet'
            elif props.get('InternalName','').lower() == '7zs.sfx':
                silentflag = '/s'
            elif props.get('InternalName','').lower() == 'setup launcher':
                silentflag = '/s'
            elif props.get('InternalName','').lower() == 'wextract':
                silentflag = '/Q'
            else:
                content = open(installer_path,'rb').read(600000)
                if 'Inno.Setup' in content:
                    silentflag = '/VERYSILENT'
                elif 'Quiet installer' in content:
                    silentflag = '-q'
                elif 'nsis.sf.net' in content or 'Nullsoft.NSIS' in content:
                    silentflag = '/S'

        elif ext=='.msi':
            silentflag = '/q /norestart'
        elif ext=='.msu':
            silentflag = '/quiet /norestart'
        else:
            silentflag = ''
        return silentflag

    def getproductprops(self,installer_path):
        """returns a dict {'product','description','version','publisher'}"""
        (product_name,ext) = os.path.splitext(installer_path.lower())
        product_name = os.path.basename(product_name)
        product_desc = product_name
        version ='0.0.0'
        publisher =''

        if ext=='.exe':
            props = setuphelpers.get_file_properties(installer_path)
            product_name = props['ProductName'] or product_desc
        elif ext=='.msi':
            props = setuphelpers.get_msi_properties(installer_path)
            product_name = props['ProductName'] or props['FileDescription'] or product_desc
        else:
            props = {}

        if 'Manufacturer' in props and props['Manufacturer']:
            publisher = props['Manufacturer']
        elif 'CompanyName' in props and props['CompanyName']:
            publisher = props['CompanyName']

        if publisher:
            product_desc = "%s (%s)" % (product_name,publisher)
        else:
            product_desc = "%s" % (product_name,)

        if 'FileVersion' in props and props['FileVersion']:
            version = props['FileVersion']
        elif 'ProductVersion' in props and props['ProductVersion']:
            version = props['ProductVersion']

        props['product'] = product_name
        props['description'] = product_desc
        props['version'] = version
        props['publisher'] = publisher
        return props

    def make_package_template(self,installer_path,packagename='',directoryname='',section='',description='',depends=''):
        r"""Build a skeleton of WAPT package based on the properties of the supplied installer
           Return the path of the skeleton
        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> wapt.dbdir = ':memory:'
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
            props = self.getproductprops(installer_path)
            silentflags = self.getsilentflags(installer_path)
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

        template = codecs.open(os.path.join(self.wapt_base_dir,'templates','setup_package_template.py'),encoding='utf8').read() % locals()
        setuppy_filename = os.path.join(directoryname,'setup.py')
        if not os.path.isfile(setuppy_filename):
            codecs.open(setuppy_filename,'w',encoding='utf8').write(template)
        else:
            logger.info('setup.py file already exists, skip create')
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
            logger.info('control file already exists, skip create')

        psproj_filename = os.path.join(directoryname,'WAPT','wapt.psproj')
        if not os.path.isfile(psproj_filename):
            proj_template = codecs.open(os.path.join(self.wapt_base_dir,'templates','wapt.psproj'),encoding='utf8').read() % locals()
            codecs.open(psproj_filename,'w',encoding='utf8').write(proj_template)
        return directoryname

    def make_host_template(self,packagename='',depends=None,directoryname=''):
        return self.make_group_template(packagename=packagename,depends=depends,directoryname=directoryname,section='host')

    def make_group_template(self,packagename='',depends=None,directoryname='',section='group',description=''):
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
        {'target': 'c:\\tmp\\dummy', 'source_dir': 'c:\\tmp\\dummy', 'package': "testgroupe (=0)"}
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

        if not os.path.isdir(os.path.join(directoryname,'WAPT')):
            os.makedirs(os.path.join(directoryname,'WAPT'))
        template_fn = os.path.join(self.wapt_base_dir,'templates','setup_%s_template.py' % section)
        if not os.path.isfile(template_fn):
            raise Exception("setup.py template %s doesn't exist" % template_fn)
        template = codecs.open(template_fn,encoding='utf8').read() % locals()
        setuppy_filename = os.path.join(directoryname,'setup.py')
        if not os.path.isfile(setuppy_filename):
            codecs.open(setuppy_filename,'w',encoding='utf8').write(template)
        else:
            logger.info('setup.py file already exists, skip create')

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
            depends = depends[1:]
            current = entry.depends.split(',')
            for d in depends.split(','):
                if not d in current:
                    current.append(d)
            depends = current
        else:
            append_depends = False

        if depends and not isinstance(depends,list):
            depends = [s.strip() for s in depends.split(',')]

        if depends:
            # use supplied list of packages
            entry.depends = ','.join([u'%s' % p for p in depends if p and p<>packagename ])

        codecs.open(control_filename,'w',encoding='utf8').write(entry.ascontrol())

        result = {}
        result['package'] = entry
        result['source_dir'] = directoryname
        result['target'] = directoryname
        return result


    def is_installed(self,packagename):
        """Checks if a package is installed.
            Return package entry and additional local status or None"""
        return self.waptdb.installed_matching(packagename)

    def installed(self,include_errors=False):
        """returns all installed packages with their status"""
        return self.waptdb.installed(include_errors=include_errors)

    def is_available(self,packagename):
        """Checks if a package (with optional version condition) is available.
            Return package entry or None"""
        return self.waptdb.packages_matching(packagename)

    def get_default_development_dir(self,packagecond,section='base'):
        """Returns the default developement directory for package named "packagecond" based on default_sources_root and default_sources_suffix ini parameters*
            packagecond can be of the form "name (=version)" or a simple package name
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

    def edit_package(self,packagename,target_directory='',use_local_sources=True,
            append_depends=None):
        r"""Download an existing package from repositories into target_directory for modification
            if use_local_sources is True and no newer package exists on repos, updates current local edited data
              else if target_directory exists and is not empty, raise an exception
            Return {'target':target_directory,'source_dir':target_directory,'package':package_entry}

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> wapt.dbdir = ':memory:'
        >>> tmpdir = 'c:/tmp/dummy'
        >>> wapt.edit_package('tis-wapttest',target_directory=tmpdir,append_depends='tis-firefox')
        {'source_dir': 'c:\\tmp\\dummy', 'target': 'c:\\tmp\\dummy', 'package': "tis-wapttest (=111)"}
        >>> import shutil
        >>> shutil.rmtree(tmpdir)

        """
        # check if available in repos
        entries = self.is_available(packagename)
        if entries:
            entry = entries[-1]
            # the package can be downloaded
            if not target_directory:
                target_directory = self.get_default_development_dir(entry.package,section=entry.section)
        else:
            # argument is a wapt package
            entry = self.is_wapt_package_file(packagename)
            if entry:
                if not target_directory:
                    target_directory = tempfile.mkdtemp(prefix="wapt")
                zip = ZipFile(packagename)
                zip.extractall(path=target_directory)
                packagename = entry.package
            else:
                raise Exception('%s is neither a package name nor a package filename' % packagename)

        local_dev_entry = self.is_wapt_package_development_dir(target_directory)
        if local_dev_entry:
            if use_local_sources:
                if entry>local_dev_entry:
                    raise Exception('A newer package version %s is already in repository "%s", local source %s is %s aborting' % (entry.asrequirement(),entry.repo,target_directory,local_dev_entry.asrequirement()))
                if local_dev_entry.match(packagename):
                    if append_depends:
                        if not isinstance(append_depends,list):
                            append_depends = [s.strip() for s in append_depends.split(',')]
                        prev_depends = local_dev_entry.depends.split(',')
                        for d in append_depends:
                            if not d in prev_depends:
                                prev_depends.append(d)
                        local_dev_entry.depends = ','.join(prev_depends)
                        local_dev_entry.save_control_to_wapt(target_directory)

                    psproj_filename = os.path.join(target_directory,'WAPT','wapt.psproj')
                    if not os.path.isfile(psproj_filename):
                        proj_template = codecs.open(os.path.join(self.wapt_base_dir,'templates','wapt.psproj'),encoding='utf8').read() % locals()
                        codecs.open(psproj_filename,'w',encoding='utf8').write(proj_template)
                    return {'target':target_directory,'source_dir':target_directory,'package':local_dev_entry}
                else:
                    raise Exception('Local target %s directory is the sources of a different package %s than expected %s' % (target_directory,local_dev_entry.package,packagename))
            else:
                raise Exception('%s wapt developement directory exists' % target_directory)
        if entry:
            # edit an existing package by using
            return self.duplicate_package(packagename=entry.asrequirement(),newname=entry.package,target_directory=target_directory,build=False,append_depends = append_depends)
        else:
            # create a new one
            return self.duplicate_package(packagename=packagename,newname=packagename,target_directory=target_directory,build=False,append_depends = append_depends)

    def is_wapt_package_development_dir(self,directory):
        """Return PackageEntry if directory is a wapt developement directory (a WAPT/control file exists) or False"""
        return os.path.isfile(os.path.join(directory,'WAPT','control')) and PackageEntry().load_control_from_wapt(directory,calc_md5=False)

    def is_wapt_package_file(self,filename):
        """Return PackageEntry if filename is a wapt package or False"""
        (root,ext)=os.path.splitext(filename)
        if ext<>'.wapt' or not os.path.isfile(filename):
            return False
        try:
            entry = PackageEntry().load_control_from_wapt(filename,calc_md5=False)
            return entry
        except:
            return False

    def edit_host(self,hostname,target_directory='',use_local_sources=True,append_depends=None,printhook=None):
        """Download and extract a host package from host repositories into target_directory for modification
                Return dict {'target': 'c:\\\\tmp\\\\dummy', 'source_dir': 'c:\\\\tmp\\\\dummy', 'package': "dummy.tranquilit.local (=0)"}

           hostname          : fqdn of the host to edit
           target_directory  : where to place the developments files. if empty, use default one from wapt-get.ini configuration
           use_local_sources : don't raise an exception if local sources are newer or same than repo version
           append_depends    : list or comma separated list of package requirements

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> tmpdir = 'c:/tmp/dummy'
        >>> wapt.edit_host('dummy.tranquilit.local',target_directory=tmpdir,append_depends='tis-firefox')
        {'target': 'c:\\\\tmp\\\\dummy', 'source_dir': 'c:\\\\tmp\\\\dummy', 'package': "dummy.tranquilit.local (=0)"}
        >>> import shutil
        >>> shutil.rmtree(tmpdir)
        >>> host = wapt.edit_host('htlaptop.tranquilit.local',target_directory=tmpdir,append_depends='tis-firefox')
        ???
        >>> shutil.rmtree(tmpdir)
        """
        # target_directory is not provided, calc default one
        if not target_directory:
            target_directory = self.get_default_development_dir(hostname,section='host')

        # check if host package exists on repos
        (entry,entry_date) = self.repositories[-1].update_host(hostname,self.waptdb)
        if entry:
            # target is already an "in-progress" package developement
            local_dev_entry = self.is_wapt_package_development_dir(target_directory)
            if local_dev_entry:
                if use_local_sources:
                    if entry>local_dev_entry:
                        raise Exception('A newer package version %s is already in repository "%s", local sources %s is %s, aborting' % (entry.asrequirement(),entry.repo,target_directory, local_dev_entry.asrequirement()))
                    if local_dev_entry.match(hostname):
                        if append_depends:
                            if not isinstance(append_depends,list):
                                append_depends = [s.strip() for s in append_depends.split(',')]
                            prev_depends = local_dev_entry.depends.split(',')
                            for d in append_depends:
                                if not d in prev_depends:
                                    prev_depends.append(d)
                            local_dev_entry.depends = ','.join(prev_depends)
                            local_dev_entry.save_control_to_wapt(target_directory)
                        return {'target':target_directory,'source_dir':target_directory,'package':local_dev_entry}
                    else:
                        raise Exception('Local target %s directory is the sources of a different package %s than expected %s' % (target_directory,local_dev_entry.package,hostname))
                else:
                    raise Exception('directory %s is already a package development directory, aborting.' % target_directory)
            elif os.path.isdir(target_directory) and os.listdir(target_directory):
                raise Exception('directory %s is not empty, aborting.' % target_directory)

            return self.duplicate_package(
                    packagename=hostname,
                    newname=hostname,
                    target_directory=target_directory,
                    build=False,
                    append_depends = append_depends,
                    usecache=False,
                    printhook=printhook)
        elif os.path.isdir(target_directory) and os.listdir(target_directory):
            raise Exception('directory %s is not empty, aborting.' % target_directory)
        else:
            return self.make_host_template(packagename=hostname,directoryname=target_directory,depends=append_depends)

    def duplicate_package(self,
            packagename,
            newname=None,
            newversion=None,
            target_directory=None,
            build=True,
            excludes=['.svn','.git*','*.pyc','src'],
            private_key=None,
            callback=pwd_callback,
            append_depends=None,
            auto_inc_version=True,
            usecache=True,
            printhook=None):
        r"""Duplicate an existing package from repositories into targetdirectory with newname.
            Return  {'target':new package or new source directory,'package':new PackageEntry,'source_dir':new source directory}
            unzip: unzip packages at end for modifications, don't sign, return directory name
            excludes: excluded files for signing
            append_depends : comma str or list of depends to append.
            auto_inc_version : if version is less than existing package in repo, set version to repo version+1
            printhook: hook for download progress
        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
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
        ...     excludes=['.svn','.git*','*.pyc','src'],
        ...     private_key=None,
        ...     callback=pwd_callback,
        ...     append_depends=None,
        ...     auto_inc_version=True,
        ...     usecache=False,
        ...     printhook=nullhook)
        >>> print p
        {'source_dir': 'c:\\tmp\\testdup-wapt', 'target': 'c:\\tmp\\testdup-wapt', 'package': "testdup (=20.0-0)"}
        >>> if os.path.isdir(tmpdir):
        ...     import shutil
        ...     shutil.rmtree(tmpdir)
        """

        # suppose target directory
        if not target_directory:
            p = self.is_available(packagename)
            if p:
                target_directory = self.get_default_development_dir(newname,section=p[-1].section)
            else:
                target_directory = self.get_default_development_dir(newname)
            if not target_directory:
                target_directory = os.getcwd()

        if target_directory:
             target_directory = os.path.abspath(target_directory)

        if os.path.isdir(target_directory) and os.listdir(target_directory):
            raise Exception('Target directory "%s" is not empty, aborting.' % target_directory)

        # if no newname supplied, suppose this is for creating a new machine package
        if not newname:
            newname = setuphelpers.get_hostname().lower()
        else:
            newname = newname.lower()

        p = self.is_available(packagename)
        if p:
            if not target_directory:
                target_directory = self.get_default_development_dir(newname,section=p[-1].section)
        else:
            if not target_directory:
                target_directory = self.get_default_development_dir(newname)

        # default empty result
        result = {'target':target_directory,'package':PackageEntry(),'source_dir':target_directory}

        # download the source package in cache
        if os.path.isdir(packagename):
            source_control = PackageEntry().load_control_from_wapt(packagename)
            target_directory = self.get_default_development_dir(newname,section=source_control.section)
            if packagename<>target_directory:
                shutil.copytree(packagename,target_directory)
        elif os.path.isfile(packagename):
            source_filename = packagename
            source_control = PackageEntry().load_control_from_wapt(source_filename)
            target_directory = self.get_default_development_dir(newname,section=source_control.section)
            logger.info('  unzipping %s to directory %s' % (source_filename,target_directory))
            if os.path.isdir(target_directory):
                raise Exception('Target directory "%s" for package source already exist' % target_directory)
            zip = ZipFile(source_filename,allowZip64=True)
            zip.extractall(path=target_directory)
        else:
            filenames = self.download_packages([packagename],usecache=usecache,printhook=printhook)
            source_filename = (filenames['downloaded'] or filenames['skipped'])[0]
            source_control = PackageEntry().load_control_from_wapt(source_filename)
            if not target_directory:
                target_directory = self.get_default_development_dir(newname,section=source_control.section)
            logger.info('  unzipping %s to directory %s' % (source_filename,target_directory))
            zip = ZipFile(source_filename,allowZip64=True)
            zip.extractall(path=target_directory)

        # duplicate package informations
        dest_control = PackageEntry()
        for a in source_control.all_attributes:
            dest_control[a] = source_control[a]

        if append_depends:
            if not isinstance(append_depends,list):
                append_depends = [s.strip() for s in append_depends.split(',')]
            prev_depends = dest_control.depends.split(',')
            for d in append_depends:
                if not d in prev_depends:
                    prev_depends.append(d)
            dest_control.depends = ','.join(prev_depends)

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
            target_filename = self.build_package(target_directory,inc_package_release=False,excludes=excludes)['filename']
            #get default private_key if not provided
            if not private_key:
                private_key = self.private_key
            # sign package
            if private_key:
                self.sign_package(target_filename,excludes=excludes,private_key=private_key,callback=callback)
                logger.debug('Package signed')
            else:
                logger.warning(u'No private key provided, package is not signed !')
            result['target'] = target_filename
        else:
            result['target'] = target_directory
        result['package'] = dest_control
        result['source_dir'] = target_directory
        return result

    def check_waptupgrades(self):
        if self.config.has_option('global','waptupgrade_url'):
            upgradeurl = self.config.get('global','waptupgrade_url')
        pass

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
        u'20130523'
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
            for dep in packages[-1].depends.split(','):
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
        """Return most up to date packages entries for packages_names
        packages_names is either a list or a string
        return a dictionnary with {'packages':[],'missing':[]}"""
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

    def add_iconpng_wapt(self,package,iconpath='',private_key_passwd=None):
        """Add a WAPT/icon.png file to existing WAPT package without icon
            wapt =
        """
        if not os.path.isfile(package) and not self.is_available(package):
            raise Exception('{} package does not exist'.format(package))
        has_icon = None
        if os.path.isfile(package):
            with zipfile.ZipFile(fname,'r',allowZip64=True) as myzip:
                try:
                    icon_info = myzip.getinfo(u'WAPT/icon.png')
                    logger.warning('Already an icon in package {}, keeping it'.format(package))
                    has_icon = True
                except KeyError:
                    has_icon = False
        if not has_icon:
            tempdir = tempfile.mkdtemp()
            try:
                result = self.edit_package(package,target_directory = tempdir)
                target_icon_path = os.path.join(result['target'],'WAPT','icon.png')
                has_icon = os.path.exists(target_icon_path)
                if not has_icon:
                    if not os.path.isfile(iconpath):
                        # we take an icon in the local cache ...
                        iconpath = os.path.join(self.wapt_base_dir,u'cache',u'{}.png'.format(result['package'].package))
                        if not os.path.isfile(iconpath):
                            # try to find an icon in the first exe file we find...
                            logger.info('No suitable icon in cache, trying exe')
                            from extract_icon import extract_icon
                            for exefile in glob.glob( os.path.join(result['target'],'*.exe')):
                                try:
                                    icon = extract_icon(exefile)
                                    if len(icon)>10:
                                        logger.info('Using icon from {}'.format(exefile))
                                        with open(target_icon_path,'wb') as png:
                                            png.write(icon)
                                            has_icon = True
                                            break
                                except:
                                    pass
                            if not has_icon:
                                raise Exception('{} icon does not exist'.format(iconpath))
                        else:
                            shutil.copyfile(iconpath,target_icon_path)

                    build = self.build_package(result['target'])

                    def pwd_callback(*args):
                        """Default password callback for opening private keys"""
                        return private_key_passwd

                    def pwd_callback2(*args):
                        """Default password callback for opening private keys"""
                        global key_passwd
                        if not key_passwd:
                            key_passwd = getpass.getpass('Private key password :').encode('ascii')
                        return key_passwd

                    if self.private_key:
                        print('Signing %s' % build['filename'])
                        if private_key_passwd is None:
                            signature = self.sign_package(build['filename'],callback=pwd_callback2)
                        else:
                            signature = self.sign_package(build['filename'],callback=pwd_callback)

                    if not signature:
                        raise Exception('Unable to sign package {}'.format(package))
                    logger.info('Package {} successfully built'.format(build['filename']))
                    return build
                else:
                    logger.warning('There is already an icon in package {}, keeping it'.format(package))
                    return None
            finally:
                shutil.rmtree(tempdir,ignore_errors=True)
        else:
            return None

    def register_windows_uninstall(self,package_entry):
        """Add a windows registry key for custom installer"""
        setuphelpers.register_uninstall(
            package_entry.package,
            'wapt-get uninstall %s' % package_entry.package,
            display_name=package_entry.description,
            display_version=package_entry.version,
            publisher=package_entry.maintainer)

    def network_reconfigure(self):
        """Called whenever the network configuration has changed"""
        try:
            for repo in self.repositories:
                repo.reset_network()
            if not self.disable_update_server_status and self.wapt_server:
                self.update_server_status()
        except Exception as e:
            logger.warning(u'Problème lors du changement de réseau : %s'%setuphelpers.ensure_unicode(e))

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

