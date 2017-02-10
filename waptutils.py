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
__version__ = "1.3.11"

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

if platform.system() == 'Windows':
    try:
        import ctypes
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

logger = logging.getLogger()

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
            except:
                return data.decode(sys.getfilesystemencoding(),'replace')
        if platform.system() == 'Windows' and isinstance(data,WindowsError):
            return u"%s : %s" % (data.args[0], data.args[1].decode(sys.getfilesystemencoding(),'replace'))
        if isinstance(data,(UnicodeDecodeError,UnicodeEncodeError)):
            return u"%s : faulty string is '%s'" % (data,repr(data.args[1]))
        if isinstance(data,Exception):
            try:
                return u"%s: %s" % (data.__class__.__name__,("%s"%data).decode(sys.getfilesystemencoding(),'replace'))
            except:
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
    except:
        if logger.level != logging.DEBUG:
            return("Error in ensure_unicode / %s"%(repr(data)))
        else:
            raise

def ensure_list(csv_or_list,ignore_empty_args=True,allow_none = False):
    """if argument is not a list, return a list from a csv string"""
    if csv_or_list is None:
        if allow_none:
            return None
        else:
            return []

    if isinstance(csv_or_list,tuple):
        return list(csv_or_list)
    elif not isinstance(csv_or_list,list):
        if ignore_empty_args:
            return [s.strip() for s in csv_or_list.split(',') if s.strip() != '']
        else:
            return [s.strip() for s in csv_or_list.split(',')]
    else:
        return csv_or_list

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

def fileisoutcdate(filename):
    return datetime2isodate(datetime.datetime.utcfromtimestamp(os.stat(filename).st_mtime))

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

def zip_remove_files(zipfilename,filenames):
    """Remove a list of files from a ZIP using 7-zip or zip (python ZipFile can't do that

    >>> zip_remove_files('c:/wapt/cache/tis-java8_8.111-23_all.wapt',['WAPT/signature'])
    """

    try:
        if platform.system() == 'Windows':
            with _disable_file_system_redirection():
                sevenzip = os.path.join(_programfiles(),'7-zip','7z.exe')
                if not os.path.isfile(sevenzip):
                    sevenzip = os.path.join(os.path.expandvars('%ProgramFiles(x86)%'),'7-zip','7z.exe')
                if not os.path.isfile(sevenzip):
                    raise Exception('7-Zip is not installed, unable to remove files %s from %s' % (filenames,zipfilename))
                if os.path.isfile(zipfilename+'.tmp'):
                    os.unlink(zipfilename+'.tmp')
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                result = subprocess.check_call([sevenzip,'d',zipfilename]+filenames,startupinfo = si)
        else:
            if platform.system() == 'Linux':
                result = subprocess.check_call(['zip','-d',zipfilename]+filenames)
    except Exception as e:
        if os.path.isfile(zipfilename+'.tmp'):
            os.unlink(zipfilename+'.tmp')
        raise Exception('Unable to remove files %s from %s: error %s' % (filenames,zipfilename,e))
    return result

def expand_args(args):
    """Return list of unicode file paths expanded from wildcard list args"""
    all_args = []
    for a in ensure_list(args):
        all_args.extend([os.path.abspath(p) for p in glob.glob(ensure_unicode(a))])
    return all_args

def default_http_headers():
    return {
        'cache-control':'no-cache',
        'pragma':'no-cache',
        'user-agent':'wapt/{}'.format(__version__),
        }

def get_disk_free_space(filepath):
    """
    Returns the number of free bytes on the drive that filepath is on
    """
    if os.name == 'nt':
        import win32file
        secs_per_cluster, bytes_per_sector, free_clusters, total_clusters = win32file.GetDiskFreeSpace(filepath)
        return secs_per_cluster * bytes_per_sector * free_clusters
    else:
        import shutil
        total, used, free = shutil.disk_usage(filepath)
        return free

def wget(url,target,printhook=None,proxies=None,connect_timeout=10,download_timeout=None,verify_cert=False,referer=None,user_agent=None):
    r"""Copy the contents of a file from a given URL to a local file.
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
                else:
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

    if os.path.isdir(target):
        target = os.path.join(target,'')

    (dir,filename) = os.path.split(target)
    if not filename:
        filename = url.split('/')[-1]
    if not dir:
        dir = os.getcwd()

    if not os.path.isdir(dir):
        os.makedirs(dir)

    if verify_cert == False:
        requests.packages.urllib3.disable_warnings()
    header=default_http_headers()
    if referer != None:
        header.update({'referer': '%s' % referer})
    if user_agent != None:
        header.update({'user-agent': '%s' % user_agent})

    httpreq = requests.get(url,stream=True, proxies=proxies, timeout=connect_timeout,verify=verify_cert,headers=header)

    httpreq.raise_for_status()

    total_bytes = int(httpreq.headers['content-length'])
    target_free_bytes = get_disk_free_space(os.path.dirname(os.path.abspath(target)))
    if total_bytes > target_free_bytes:
        raise Exception('wget : not enough free space on target drive to get %s MB. Total size: %s MB. Free space: %s MB' % (url,total_bytes // (1024*1024),target_free_bytes // (1024*1024)))

    # 1Mb max, 1kb min
    chunk_size = min([1024*1024,max([total_bytes/100,2048])])

    cnt = 0
    reporthook(last_downloaded,total_bytes)

    with open(os.path.join(dir,filename),'wb') as output_file:
        last_time_display = time.time()
        last_downloaded = 0
        if httpreq.ok:
            for chunk in httpreq.iter_content(chunk_size=chunk_size):
                output_file.write(chunk)
                if download_timeout is not None and (time.time()-start_time>download_timeout):
                    raise requests.Timeout(r'Download of %s takes more than the requested %ss'%(url,download_timeout))
                if reporthook(cnt*len(chunk),total_bytes):
                    last_time_display = time.time()
                last_downloaded += len(chunk)
                cnt +=1
            if reporthook(last_downloaded,total_bytes):
                last_time_display = time.time()


    return os.path.join(dir,filename)

if __name__ == '__main__':
    import doctest
    import sys
    reload(sys)
    sys.setdefaultencoding("UTF-8")
    import doctest
    doctest.ELLIPSIS_MARKER = '???'
    doctest.testmod(optionflags=doctest.ELLIPSIS)
    sys.exit(0)
