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
__version__ = "1.6.2.7"

import os
import sys
import re
import subprocess
import logging
import types
import datetime
import time
import json
import random
import string
import email
import copy
import platform
import codecs
import glob
import requests
import locale
import custom_zip as zipfile
from custom_zip import ZipFile
import tempfile
import fnmatch
import urlparse
import hashlib
import traceback
import imp
import shutil
import threading

if hasattr(sys.stdout,'name') and sys.stdout.name == '<stdout>':
    # not in pyscripter debugger
    try:
        from clint.textui.progress import Bar as ProgressBar
    except ImportError:
        # for build time
        ProgressBar = None
else:
    ProgressBar = None

def setloglevel(logger,loglevel):
    """set loglevel as string"""
    if loglevel in ('debug','warning','info','error','critical'):
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: {}'.format(loglevel))
        logger.setLevel(numeric_level)

logger = logging.getLogger()

if platform.system() == 'Windows':
    try:
        import ctypes
        import win32api
        import pythoncom

        class _disable_file_system_redirection:
            r"""Context manager to disable temporarily the wow3264 file redirector

            >>> with disable_file_system_redirection():
            ...     winshell.get_path(shellcon.CSIDL_PROGRAM_FILES)
            u'C:\\Program Files (x86)'
            """
            try:
                _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
                _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
            except:
                _disable = None
                _revert = None
            def __enter__(self):
                if self._disable:
                    self.old_value = ctypes.c_long()
                    self.success = self._disable(ctypes.byref(self.old_value))
            def __exit__(self, type, value, traceback):
                if self._revert and self.success:
                    self._revert(self.old_value)
    except Exception as e:
        class _disable_file_system_redirection:
            def __enter__(self):
                pass

            def __exit__(self, type, value, traceback):
                pass

    def _programfiles():
        """Return native program directory, ie C:\Program Files for both 64 and 32 bits"""
        if 'PROGRAMW6432' in os.environ:
            return os.environ['PROGRAMW6432']
        else:
            return os.environ['PROGRAMFILES']


else:
    class _disable_file_system_redirection:
        def __enter__(self):
            pass

        def __exit__(self, type, value, traceback):
            pass

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


def format_bytes(bytes):
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
            l = 12              # or default arg ...
        l = max(l, len(dd[0]))  # handle long names
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
            if isinstance(name,(list,tuple)):
                name = name[0]
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


def generate_unique_string():
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))


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

# from opsi
def ensure_unicode(data):
    u"""Return a unicode string from data object
    It is sometimes difficult to know in advance what we will get from command line
    application output.

    This is to ensure we get a (not always accurate) representation of the data
    mainly for logging purpose.

    Args:
        data: either str or unicode or object having a __unicode__ or WindowsError or Exception

    Returns:
        unicode: unicode string representing the data

    >>> ensure_unicode(str('éé'))
    u'\xe9\xe9'
    >>> ensure_unicode(u'éé')
    u'\xe9\xe9'
    >>> ensure_unicode(Exception("test"))
    u'Exception: test'
    >>> ensure_unicode(Exception())
    u'Exception: '
    """
    try:
        if data is None:
            return None
        if isinstance(data,types.UnicodeType):
            return data
        if isinstance(data,types.StringType):
            try:
                return data.decode('utf8')
            except UnicodeError:
                if platform.system() == 'Windows':
                    try:
                        # cmd output mostly cp850 in france ?
                        return data.decode('cp850')
                    except UnicodeError:
                        try:
                            return data.decode(sys.getfilesystemencoding())
                        except UnicodeError:
                            return data.decode(sys.getdefaultencoding(),'ignore')
                else:
                    return data.decode(sys.getfilesystemencoding(),'replace')
        if platform.system() == 'Windows' and isinstance(data,pythoncom.com_error):
            try:
                error_msg = ensure_unicode(win32api.FormatMessage(data.args[2][5]))
                return u"%s (%s): %s (%s)" % (data.args[0], data.args[1].decode('cp850'),data.args[2][5],error_msg)
            except:
                try:
                    return u"%s : %s" % (data.args[0], data.args[1].decode('cp850'))
                except UnicodeError:
                    return u"%s : %s" % (data.args[0], data.args[1].decode(sys.getfilesystemencoding(),'ignore'))

        if platform.system() == 'Windows' and isinstance(data,WindowsError):
            try:
                return u"%s : %s" % (data.args[0], data.args[1].decode('cp850'))
            except UnicodeError:
                return u"%s : %s" % (data.args[0], data.args[1].decode(sys.getfilesystemencoding(),'ignore'))
        if isinstance(data,UnicodeError):
            return u"%s : faulty string is '%s'" % (data,repr(data.args[1]))
        if isinstance(data,Exception):
            try:
                return u"%s: %s" % (data.__class__.__name__,("%s"%data).decode(sys.getfilesystemencoding(),'replace'))
            except UnicodeError:
                try:
                    return u"%s: %s" % (data.__class__.__name__,("%s"%data).decode('utf8','replace'))
                except:
                    try:
                        return u"%s: %s" % (data.__class__.__name__,u"%s"%data)
                    except:
                        return u"%s" % (data.__class__.__name__,)
        if hasattr(data, '__unicode__'):
            try:
                return data.__unicode__()
            except:
                pass
        return unicode(data)
    except UnicodeError:
        if logger.level != logging.DEBUG:
            return("Error in ensure_unicode / %s"%(repr(data)))
        else:
            raise

def ensure_list(csv_or_list,ignore_empty_args=True,allow_none = False):
    """if argument is not a list, return a list from a csv string

    Args:
        csv_or_list (list or str):
        ignore_empty_args (bool): if True, empty string found in csv are not appended to the list.
        allow_none (bool): if True, if csv_or_list is None, return None, else return empty list/

    Returns:
        list
    """
    if csv_or_list is None:
        if allow_none:
            return None
        else:
            return []

    if isinstance(csv_or_list,(tuple,list)):
        return list(csv_or_list)
    elif isinstance(csv_or_list,(str,unicode)):
        if ignore_empty_args:
            return [s.strip() for s in csv_or_list.split(u',') if s.strip() != '']
        else:
            return [s.strip() for s in csv_or_list.split(u',')]
    else:
        return [csv_or_list]

def datetime2isodate(adatetime = None):
    if not adatetime:
        adatetime = datetime.datetime.now()
    assert(isinstance(adatetime,datetime.datetime))
    return adatetime.isoformat()


def httpdatetime2isodate(httpdate):
    """Convert a date string as returned in http headers or mail headers to isodate (UTC)

    >>> import requests
    >>> last_modified = requests.head('http://wapt/wapt/Packages',headers={'cache-control':'no-cache','pragma':'no-cache'}).headers['last-modified']
    >>> len(httpdatetime2isodate(last_modified)) == 19
    True
    """
    date_time_tz = email.utils.parsedate_tz(httpdate)
    return datetime2isodate(datetime.datetime(*date_time_tz[:6]) - datetime.timedelta(seconds=date_time_tz[9]))


def httpdatetime2datetime(httpdate):
    """convert a date string as returned in http headers or mail headers to isodate (UTC)

    Args:
        httpdate (str): form '2018-07-11T04:53:01'

    Returns:
        datetime

    >>> import requests
    >>> last_modified = requests.head('http://wapt/wapt/Packages',headers={'cache-control':'no-cache','pragma':'no-cache'}).headers['last-modified']
    >>> len(httpdatetime2isodate(last_modified)) == 19
    True
    """
    date_time_tz = email.utils.parsedate_tz(httpdate)
    return datetime.datetime(*date_time_tz[:6]) - datetime.timedelta(seconds=date_time_tz[9])

def httpdatetime2time(httpdate):
    """convert a date string as returned in http headers or mail headers to isodate

    >>> import requests
    >>> last_modified = requests.head('http://wapt/wapt/Packages',headers={'cache-control':'no-cache','pragma':'no-cache'}).headers['last-modified']
    >>> len(httpdatetime2isodate(last_modified)) == 19
    True
    """
    date_time_tz = email.utils.parsedate_tz(httpdate)
    return time.mktime(date_time_tz[:9]) - date_time_tz[9]


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
    """Returns last update date time from filename in local time"""
    return datetime.datetime.fromtimestamp(os.stat(filename).st_mtime).isoformat()

def fileutcdate(filename):
    """Returns last update date time from filename in UTC

    Returns:
        datetime
    """
    return datetime.datetime.utcfromtimestamp(os.stat(filename).st_mtime)

def fileutcmtime(filename):
    if time.daylight:
        return os.path.getmtime(filename) + time.altzone
    else:
        return os.path.getmtime(filename) + time.timezone

def fileisoutcdate(filename):
    """Returns last update date time from filename in UTC"""
    return datetime2isodate(fileutcdate(filename))

def dateof(adatetime):
    return adatetime.replace(hour=0,minute=0,second=0,microsecond=0)

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

def expand_args(args,expand_file_wildcards=None):
    """Return list of unicode file paths expanded from wildcard list args"""
    def from_system_encoding(t):
        if isinstance(t,unicode):
            return t
        else:
            try:
                return t.decode(sys.getfilesystemencoding())
            except:
                return ensure_unicode(t)

    all_args = []
    if expand_file_wildcards is None:
        expand_file_wildcards = True if [p for p in args if ('*' in p) or (':' in p) or (os.pathsep in p)] else False
    if expand_file_wildcards:
        for a in ensure_list(args):
            all_args.extend([os.path.abspath(p) for p in glob.glob(from_system_encoding(a))])
    else:
        all_args.extend([from_system_encoding(a) for a in args])

    return all_args



def default_http_headers():
    return {
        'cache-control':'no-cache',
        'pragma':'no-cache',
        'user-agent':'wapt/{}'.format(__version__),
        }


def http_resource_datetime(url,proxies=None,timeout=2,auth=None,verify_cert=False,cert=None):
    """Try to get header for the supplied URL, returns None if no answer within the specified timeout

    Args:
        url (str)      : URL to document
        proxies (dict) : proxies to use. eg {'http':'http://wpad:3128','https':'http://wpad:3128'}
        timeout (int)  : seconds to wait for answer before giving up
        auth (list)    : (user,password) to authenticate wirh basic auth
        verify_cert (bool or str) : either False, True (verify with embedded CA list), or path to a directory or PEM encoded CA bundle file
                                    to check https certificate signature against.
        cert (list)    : pair of (x509certfilename,pemkeyfilename) for authenticating the client

    Returns:
        datetime : last-modified date of document on server
    """
    try:
        headers = requests.head(url,
            proxies=proxies,timeout=timeout,
            auth=auth,
            verify=verify_cert,
            headers=default_http_headers(),
            cert=cert,
            allow_redirects=True)
        if headers.ok:
            return httpdatetime2datetime(headers.headers.get('last-modified',None))
        else:
            headers.raise_for_status()
    except Exception as e:
        return None

def http_resource_isodatetime(url,proxies=None,timeout=2,auth=None,verify_cert=False,cert=None):
    # try to get header for the supplied URL, returns None if no answer within the specified timeout or UTC iso datetime of resource from server
    try:
        headers = requests.head(url,proxies=proxies,timeout=timeout,auth=auth,
            verify=verify_cert,
            headers=default_http_headers(),
            cert=cert,
            allow_redirects=True)
        if headers.ok:
            return httpdatetime2isodate(headers.headers.get('last-modified',None))
        else:
            headers.raise_for_status()
    except Exception as e:
        return None

def get_disk_free_space(filepath):
    """
    Returns the number of free bytes on the drive that filepath is on
    """
    if os.name == 'nt':
        import win32file
        secs_per_cluster, bytes_per_sector, free_clusters, total_clusters = win32file.GetDiskFreeSpace(filepath) #pylint: disable=no-member
        return secs_per_cluster * bytes_per_sector * free_clusters
    else:
        # like shutil
        def disk_usage(path):
            # pylint: disable=no-member
            # no error
            st = os.statvfs(path)
            free = st.f_bavail * st.f_frsize
            total = st.f_blocks * st.f_frsize
            used = (st.f_blocks - st.f_bfree) * st.f_frsize
            return (total, used, free)
        total, used, free = disk_usage(filepath)
        return free

def _hash_file(fname, block_size=2**20,hash_func=hashlib.md5):
    with open(fname,'rb') as f:
        hash_obj = hash_func()
        while True:
            data = f.read(block_size)
            if not data:
                break
            hash_obj.update(data)
    return hash_obj.hexdigest()

def _check_hash_for_file(fname, block_size=2**20,md5=None,sha1=None,sha256=None):
    if sha256 is not None:
        return _hash_file(fname, block_size,hashlib.sha256) == sha256
    elif sha1 is not None:
        return _hash_file(fname, block_size,hashlib.sha1) == sha1
    elif md5 is not None:
        return _hash_file(fname, block_size,hashlib.md5) == md5
    else:
        raise Exception('No hash to check file')

def wget(url,target=None,printhook=None,proxies=None,connect_timeout=10,download_timeout=None,verify_cert=False,referer=None,user_agent=None,cert=None,resume=False,md5=None,sha1=None,sha256=None,cache_dir=None):
    r"""Copy the contents of a file from a given URL to a local file.

    Args:
        url (str): URL to document
        target (str) : full file path of downloaded file. If None, put in a temporary dir with supplied url filename (final part of url)
        proxies (dict) : proxies to use. eg {'http':'http://wpad:3128','https':'http://wpad:3128'}
        timeout (int)  : seconds to wait for answer before giving up
        auth (list)    : (user,password) to authenticate wirh basic auth
        verify_cert (bool or str) : either False, True (verify with embedded CA list), or path to a directory or PEM encoded CA bundle file
                                    to check https certificate signature against.
        cert (list) : pair of (x509certfilename,pemkeyfilename) for authenticating the client
        referer (str):
        user_agent:
        resume (bool):
        md5 (str) :
        sha1 (str) :
        sha256 (str) :
        cache_dir (str) : if file exists here, and md5 matches, copy from here instead of downloading. If not, put a copy of the file here after downloading.

    Returns:
        str : path to downloaded file

    >>> respath = wget('http://wapt.tranquil.it/wapt/tis-firefox_28.0.0-1_all.wapt','c:\\tmp\\test.wapt',proxies={'http':'http://proxy:3128'})
    ???
    >>> os.stat(respath).st_size>10000
    True
    >>> respath = wget('http://localhost:8088/runstatus','c:\\tmp\\test.json')
    ???
    """
    start_time = time.time()
    last_time_display = 0.0
    last_downloaded = 0

    def reporthook(received,total):
        total = float(total)
        if total>1 and received>1:
            # print only every second or at end
            if (time.time()-start_time>1) and ((time.time()-last_time_display>=1) or (received>=total)):
                speed = received /(1024.0 * (time.time()-start_time))
                if printhook:
                    printhook(received,total,speed,url)
                elif sys.stdout is not None:
                    try:
                        if received == 0:
                            print(u"Downloading %s (%.1f Mb)" % (url,int(total)/1024/1024))
                        elif received>=total:
                            print(u"  -> download finished (%.0f Kb/s)" % (total /(1024.0*(time.time()+.001-start_time))))
                        else:
                            print(u'%i / %i (%.0f%%) (%.0f KB/s)\r' % (received,total,100.0*received/total,speed))
                    except:
                        return False
                return True
            else:
                return False

    if target is None:
        target = tempfile.gettempdir()

    if os.path.isdir(target):
        target = os.path.join(target,'')

    (dir,filename) = os.path.split(target)
    if not filename:
        url_parts = urlparse.urlparse(url)
        filename = url_parts.path.split('/')[-1]
    if not dir:
        dir = os.getcwd()

    if not os.path.isdir(dir):
        os.makedirs(dir)

    if verify_cert == False:
        requests.packages.urllib3.disable_warnings() # pylint: disable=no-member
    header=default_http_headers()
    if referer != None:
        header.update({'referer': '%s' % referer})
    if user_agent != None:
        header.update({'user-agent': '%s' % user_agent})

    target_fn = os.path.join(dir,filename)

    # return cached file if md5 matches.
    if (md5 is not None or sha1 is not None or sha256 is not None) and cache_dir is not None and os.path.isdir(cache_dir):
        cached_filename = os.path.join(cache_dir,filename)
        if os.path.isfile(cached_filename):
            if _check_hash_for_file(cached_filename,md5=md5,sha1=sha1,sha256=sha256):
                resume = False
                if cached_filename != target_fn:
                    shutil.copy2(cached_filename,target_fn)
                return target_fn
    else:
        cached_filename = None

    if os.path.isfile(target_fn) and resume:
        try:
            actual_size = os.stat(target_fn).st_size
            size_req = requests.head(url,
                proxies=proxies,
                timeout=connect_timeout,
                verify=verify_cert,
                headers=header,
                cert = cert,
                allow_redirects=True)

            target_size = int(size_req.headers['content-length'])
            file_date = size_req.headers.get('last-modified',None)

            if target_size > actual_size:
                header.update({'Range':'bytes=%s-' % (actual_size,)})
                write_mode = 'ab'
            elif target_size < actual_size:
                target_size = None
                write_mode = 'wb'
        except Exception as e:
            target_size = None
            write_mode = 'wb'

    else:
        file_date = None
        actual_size = 0
        target_size = None
        write_mode = 'wb'

    # check hashes if size equal
    if resume and (md5 is not None or sha1 is not None or sha256 is not None) and target_size is not None and (target_size <= actual_size):
        if not _check_hash_for_file(target_fn,md5=md5,sha1=sha1,sha256=sha256):
            # restart download...
            target_size = None
            write_mode = 'wb'


    if not resume or target_size is None or (target_size - actual_size) > 0:
        httpreq = requests.get(url,stream=True,
            proxies=proxies,
            timeout=connect_timeout,
            verify=verify_cert,
            headers=header,
            cert = cert,
            allow_redirects=True)

        httpreq.raise_for_status()

        total_bytes = int(httpreq.headers['content-length'])
        target_free_bytes = get_disk_free_space(os.path.dirname(os.path.abspath(target)))
        if total_bytes > target_free_bytes:
            raise Exception('wget : not enough free space on target drive to get %s MB. Total size: %s MB. Free space: %s MB' % (url,total_bytes // (1024*1024),target_free_bytes // (1024*1024)))

        # 1Mb max, 1kb min
        chunk_size = min([1024*1024,max([total_bytes/100,2048])])

        cnt = 0
        if printhook is None and ProgressBar is not None:
            progress_bar = ProgressBar(label=filename,expected_size=target_size or total_bytes, filled_char='=')
            progress_bar.show(actual_size)

        with open(target_fn,write_mode) as output_file:
            last_time_display = time.time()
            last_downloaded = 0
            if httpreq.ok:
                for chunk in httpreq.iter_content(chunk_size=chunk_size):
                    output_file.write(chunk)
                    output_file.flush()
                    if download_timeout is not None and (time.time()-start_time>download_timeout):
                        raise requests.Timeout(r'Download of %s takes more than the requested %ss'%(url,download_timeout))
                    if printhook is None and ProgressBar is not None:
                        if (time.time()-start_time>0.2) and (time.time()-last_time_display>=0.2):
                            progress_bar.show(actual_size + cnt*len(chunk))
                            last_time_display = time.time()
                    else:
                        if reporthook(cnt*len(chunk),total_bytes):
                            last_time_display = time.time()
                    last_downloaded += len(chunk)
                    cnt +=1
                if printhook is None and ProgressBar is not None:
                    progress_bar.show(total_bytes)
                    progress_bar.done()
                    last_time_display = time.time()
                elif reporthook(last_downloaded,total_bytes):
                    last_time_display = time.time()

        # check hashes
        if sha256 is not None:
            file_hash =  _hash_file(target_fn,hash_func=hashlib.sha256)
            if file_hash != sha256:
                raise Exception(u'Downloaded file %s sha256 %s does not match expected %s' % (url,file_hash,sha256))
        elif sha1 is not None:
            file_hash = _hash_file(target_fn,hash_func=hashlib.sha1)
            if file_hash != sha1:
                raise Exception(u'Downloaded file %s sha1 %s does not match expected %s' % (url,file_hash,sha1))
        elif md5 is not None:
            file_hash = _hash_file(target_fn,hash_func=hashlib.md5)
            if file_hash != md5:
                raise Exception(u'Downloaded file %s md5 %s does not match expected %s' % (url,file_hash,md5))

        file_date = httpreq.headers.get('last-modified',None)

    if file_date:
        file_datetime_utc = httpdatetime2time(file_date)
        if time.daylight:
            file_datetime_local = file_datetime_utc - time.altzone
        else:
            file_datetime_local = file_datetime_utc - time.timezone
        os.utime(target_fn,(file_datetime_local,file_datetime_local))

    # cache result
    if cache_dir:
        if not os.path.isdir(cache_dir):
            os.makedirs(cache_dir)
        cached_filename = os.path.join(cache_dir,filename)
        if target_fn != cached_filename:
            shutil.copy2(target_fn,cached_filename)

    return target_fn


def wgets(url,proxies=None,verify_cert=False,referer=None,user_agent=None,timeout=None):
    """Return the content of a remote resource as a String with a http get request.

    Raise an exception if remote data can't be retrieved.

    Args:
        url (str): http(s) url
        proxies (dict): proxy configuration as requests requires it {'http': url, 'https':url}
    Returns:
        str : content of remote resource

    >>> data = wgets('https://wapt/ping')
    >>> "msg" in data
    True
    """
    if verify_cert == False:
        requests.packages.urllib3.disable_warnings() # pylint: disable=no-member
    header=default_http_headers()
    if referer != None:
        header.update({'referer': '%s' % referer})
    if user_agent != None:
        header.update({'user-agent': '%s' % user_agent})

    r = requests.get(url,proxies=proxies,verify=verify_cert,headers=header,timeout=timeout,allow_redirects=True)
    if r.ok:
        return r.content
    else:
        r.raise_for_status()

class FileChunks(object):
    def __init__(self, filename, chunk_size=2*1024*1024,progress_hook=None):
        self.chunk_size = chunk_size
        self.amount_seen = 0
        self.filename = filename
        self.file_obj = open(filename,'rb')
        self.file_size = os.fstat(self.file_obj.fileno()).st_size
        self.progress_hook = progress_hook
        if self.progress_hook is None and ProgressBar is not None:
            self.progress_bar = ProgressBar(label=filename,expected_size=self.file_size, filled_char='=')
            #self.progress_bar.show(self.amount_seen)
        else:
            self.progress_bar = None

    def get(self):
        try:
            data = self.file_obj.read(self.chunk_size)
            while len(data)>0:
                self.amount_seen += len(data)
                if self.progress_hook is not None:
                    cancel_request = self.progress_hook(self.filename,self.amount_seen,self.file_size)
                    if cancel_request:
                        raise Exception('Post canceled by user')
                if self.progress_bar is not None:
                    self.progress_bar.show(self.amount_seen)
                if self.progress_bar is None and self.progress_hook is None:
                    print('Uploading %s: %s / %s\r' % (self.filename,self.amount_seen,self.file_size))
                yield data
                data = self.file_obj.read(self.chunk_size)
        finally:
            if self.progress_bar is not None:
                self.progress_bar.done()
            if self.progress_bar is None and self.progress_hook is None:
                print('Done Uploading %s' % (self.filename,))
            self.file_obj.close()

    def close(self):
        if not self.file_obj.closed:
            self.file_obj.close()


class Version(object):
    """Version object of form 0.0.0
    can compare with respect to natural numbering and not alphabetical

    Args:
        version (str) : version string
        member_count (int) : number of version memebers to take in account.
                             If actual members in version is less, add missing memeber with 0 value
                             If actual members count is higher, removes last ones.

    >>> Version('0.10.2') > Version('0.2.5')
    True
    >>> Version('0.1.2') < Version('0.2.5')
    True
    >>> Version('0.1.2') == Version('0.1.2')
    True
    >>> Version('7') < Version('7.1')
    True

    .. versionchanged:: 1.6.2.5
        truncate version members list to members_count if provided.
    """

    def __init__(self,version,members_count=None):
        if version is None:
            version = ''
        assert isinstance(version,types.ModuleType) or isinstance(version,str) or isinstance(version,unicode) or isinstance(version,Version)
        if isinstance(version,types.ModuleType):
            self.versionstring =  getattr(version,'__version__',None)
        elif isinstance(version,Version):
            self.versionstring = getattr(version,'versionstring',None)
        else:
            self.versionstring = version
        self.members = [ v.strip() for v in self.versionstring.split('.')]
        self.members_count = members_count
        if members_count is not None:
            if len(self.members)<members_count:
                self.members.extend(['0'] * (members_count-len(self.members)))
            else:
                self.members = self.members[0:members_count]

    def __cmp__(self,aversion):
        def nat_cmp(a, b):
            a = a or ''
            b = b or ''

            def convert(text):
                if text.isdigit():
                    return int(text)
                else:
                    return text.lower()

            def alphanum_key(key):
                return [convert(c) for c in re.split('([0-9]+)', key)]

            return cmp(alphanum_key(a), alphanum_key(b))

        if not isinstance(aversion,Version):
            aversion = Version(aversion,self.members_count)
        for i in range(0,max([len(self.members),len(aversion.members)])):
            if i<len(self.members):
                i1 = self.members[i]
            else:
                i1 = ''
            if i<len(aversion.members):
                i2 = aversion.members[i]
            else:
                i2=''
            v = nat_cmp(i1,i2)
            if v:
                return v
        return 0

    def __str__(self):
        return '.'.join(self.members)

    def __repr__(self):
        return "Version('{}')".format('.'.join(self.members))

def create_recursive_zip(zipfn, source_root, target_root = u"",excludes = [u'.svn',u'.git',u'.gitignore',u'*.pyc',u'*.dbg',u'src'],
        excludes_full=[os.path.join(u'WAPT','manifest.sha256'),os.path.join(u'WAPT','manifest.sha1'),os.path.join(u'WAPT','signature')]):
    """Create a zip file with filename zipf from source_root directory with target_root as new root.
    Don't include file which match excludes file pattern

    Args;
        zipfn (unicode or ZipFile) : filename for zip file to create
        source_root (unicode) : root directory of filetree to zip
        target_root (unicode) ! root directory for all in zip file
        excludes (list)  : list of glob pattern of files to excludes
        excludes_full (list) : full relative filepath of files to exclude

    Returns:
        list : list of zipped filepath
    """
    result = []
    if not isinstance(source_root,unicode):
        source_root = unicode(source_root)
    if not isinstance(target_root,unicode):
        target_root = unicode(target_root)

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
        if zip_item_fn in excludes_full:
            continue
        if os.path.isfile(source_item_fn):
            #if logger: logger.debug(u' adding file %s' % source_item_fn)
            zipf.write(source_item_fn, zip_item_fn)
            result.append(zip_item_fn)
        elif os.path.isdir(source_item_fn):
            #if logger: logger.debug(u'Add directory %s' % source_item_fn)
            result.extend(create_recursive_zip(zipf, source_item_fn, zip_item_fn,excludes=excludes,excludes_full=excludes_full))
    if isinstance(zipfn,str) or isinstance(zipfn,unicode):
        zipf.close()
    return result


def find_all_files(rootdir,include_patterns=None,exclude_patterns=None):
    """Generator which recursively find all files from rootdir and sub directories
    matching the (dos style) patterns (example: *.exe)

    Args;
        rootdir (str): root dir where to start looking for files
        include_patterns (str or list) : list of glob pattern of files to return
        exclude_patterns (str or list) : list of glob pattern of files to exclude
                                         (if a file is both in include and exclude, it is excluded)


    >>> for fn in find_all_files('c:\\tmp','*.txt'):
            print(fn)
    >>>
    """
    rootdir = os.path.abspath(rootdir)

    if include_patterns and not isinstance(include_patterns,list):
        include_patterns = [include_patterns]

    if exclude_patterns and not isinstance(exclude_patterns,list):
        exclude_patterns = [exclude_patterns]

    def match(fn):
        if include_patterns:
            result = False
            for pattern in include_patterns:
                if glob.fnmatch.fnmatch(fn,pattern):
                    result = True
                    break
        else:
            result = True

        if exclude_patterns:
            for pattern in exclude_patterns:
                if glob.fnmatch.fnmatch(fn,pattern):
                    result = False
                    break
        return result

    for fn in os.listdir(rootdir):
        full_fn = os.path.join(rootdir,fn)
        if os.path.isdir(full_fn):
            for fn in find_all_files(full_fn,include_patterns,exclude_patterns):
                yield fn
        else:
            if match(fn):
                yield full_fn


def all_files(rootdir,pattern=None):
    """Recursively return all files from rootdir and sub directories
    matching the (dos style) pattern (example: *.exe)
    """
    rootdir = os.path.abspath(rootdir)
    result = []
    for fn in os.listdir(rootdir):
        full_fn = os.path.join(rootdir,fn)
        if os.path.isdir(full_fn):
            result.extend(all_files(full_fn,pattern))
        else:
            if not pattern or glob.fnmatch.fnmatch(fn,pattern):
                result.append(full_fn)
    return result


def touch(filename):
    if not os.path.isdir(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))
    if not os.path.isfile(filename):
        open(filename,'w').write()
    else:
        os.utime(filename,None)


def import_code(code,name='',add_to_sys_modules=0):
    """\
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

    Args:
        code (str): python code to load as a module
        name (str): import code as module name
        add_to_sys_modules (bool): True if module must be globally available as a sys module

    Returns:
        module: module object
    """
    import sys,imp

    if not name:
        name = u'__waptsetup_%s__'%generate_unique_string()

    logger.debug(u'Import source code as %s'%(name))
    module = imp.new_module(name)

    exec(code, module.__dict__)
    if add_to_sys_modules:
        sys.modules[name] = module

    return module


def import_setup(setupfilename,modulename=''):
    """Import setupfilename as modulename, return the module object

    Args:
        setupfilename (str): path to module

    Returns:
        module: loaded module
    """
    try:
        mod_name,file_ext = os.path.splitext(os.path.split(setupfilename)[-1])
        if not modulename:
            #modulename=mod_name
            modulename = u'__waptsetup_%s__'%generate_unique_string()
        # can debug but keep module in memory
        logger.debug(u'Import source %s as %s'%(setupfilename,modulename))
        py_mod = imp.load_source(modulename, setupfilename.encode(sys.getfilesystemencoding()))
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
        result.append(h.replace('coding:','coding is').replace('coding=','coding is').replace(u'\ufeff',''))
    result.extend(headers[3:])
    return "\n".join(result)

def list_intersection(list1, list2):
    if list1 is None or list2 is None:
        return []
    return [item for item in list1 if item in list2]

def get_language():
    """Get the default locale like fr, en, pl etc..  etc

    >>> get_language()
    'fr'
    """
    return locale.getdefaultlocale()[0].split('_')[0]


class BaseObjectClass(object):
    def _pyobject(self):
        """Return pure python reference for calls in FreePascal"""
        return self


class LogOutput(BaseObjectClass):
    """File like contextual object to log print output to a db installstatus
    using update_status_hook

    output list gather all the stout / stderr output

    Args:
        console (fileout): print message here
        update_status_hook (func): hook to call when printing.
                                            Must accept "append_output" and "set_status" kwargs
                                            and will get context "**hook_args" at each call.

    Returns:
        stout file like object


    >>> def update_status(append_output,set_status=None,**kwargs):
            if set_status is not None:
                print('+ Status to: %s' % set_status)
            print(u'+out %s: %s' % (kwargs,append_output))
    >>> with LogInstallOutput(sys.stdout,update_status_hook=update_status,install_id=12,user='moi'):
            print('Install in progress')

    """
    def __init__(self,console=None,update_status_hook=None,running_status='RUNNING',exit_status='OK',error_status='ERROR',**hook_args):
        self.old_stdout = None
        self.old_stderr = None

        self.output = []
        self.console = console

        self.update_status_hook = update_status_hook
        self.hook_args = hook_args
        self.threadid = threading.current_thread()

        self.lock = threading.RLock()

        self.running_status = running_status
        self.error_status = error_status
        self.exit_status = exit_status

        self.update_buffer_time = 5
        self.last_update_time = 0
        self.last_update_idx = 0

    def _send_tail_to_updatehook(self):
        """send pending output to hook"""
        append_txt = u'\n'.join(self.output[self.last_update_idx:])

        if append_txt and append_txt[-1] != u'\n':
            txtdb = append_txt+u'\n'
        else:
            txtdb = append_txt
        try:
            self.update_status_hook(append_output=txtdb,set_status=self.running_status,**self.hook_args)
            self.last_update_idx = len(self.output)
            self.last_update_time = time.time()
        except Exception as e:
            logger.info(u'Unable to update db status %s' % e)

    def write(self,txt):
        with self.lock:
            txt = ensure_unicode(txt)
            if txt != '\n':
                self.output.append(txt)
                if self.update_status_hook and threading.current_thread() == self.threadid and (time.time()-self.last_update_time>=self.update_buffer_time):
                    # wait update_buffer_time before sending data to update_hook to avoid high frequency I/O
                    self._send_tail_to_updatehook()

            if self.console:
                try:
                    self.console.write(txt)
                except:
                    self.console.write(repr(txt))

    def __enter__(self):
        self.old_stdout = sys.stdout
        self.old_stderr = sys.stderr
        sys.stderr = sys.stdout = self
        return self

    def __exit__(self, type, value, tb):
        try:
            if self.update_status_hook:
                self._send_tail_to_updatehook()
                if tb:
                    self.update_status_hook(set_status=self.error_status,append_output=traceback.format_exc(),**self.hook_args)
                else:
                    if self.exit_status is not None:
                        self.update_status_hook(set_status=self.exit_status,**self.hook_args)
        finally:
            self.update_status_hook = None
            self.console = None

            if self.old_stdout:
                sys.stdout = self.old_stdout
            if self.old_stderr:
                sys.stderr = self.old_stderr


    def __getattr__(self, name):
        return getattr(self.console,name)


def get_time_delta(schedule):
    if schedule is not None:
        if schedule.endswith('m'):
            timedelta = datetime.timedelta(minutes=float(schedule[:-1]))
        elif schedule.endswith('h'):
            timedelta = datetime.timedelta(hours=float(schedule[:-1]))
        elif schedule.endswith('d'):
            timedelta = datetime.timedelta(days=float(schedule[:-1]))
        elif schedule.endswith('w'):
            timedelta = datetime.timedelta(days=7*float(schedule[:-1]))
        else:
            timedelta = datetime.timedelta(minutes=float(schedule))
    else:
        timedelta = None
    return timedelta



if __name__ == '__main__':
    import doctest
    import sys
    reload(sys)
    sys.setdefaultencoding("UTF-8")
    import doctest
    doctest.ELLIPSIS_MARKER = '???'
    doctest.testmod(optionflags=doctest.ELLIPSIS)
    sys.exit(0)
