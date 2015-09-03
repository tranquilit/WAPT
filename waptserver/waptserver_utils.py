#!/usr/bin/env python
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

__version__="1.3.1"

import bson.json_util
import datetime
import email.utils
import errno
import flask
import json
import logging
import os
import pymongo
import requests
import traceback

__all__ = []

##### Date/Time utilities #####
def datetime2isodate(adatetime = None):
    if not adatetime:
        adatetime = datetime.datetime.now()
    assert(isinstance(adatetime,datetime.datetime))
    return adatetime.isoformat()

def isodate2datetime(isodatestr):
    # we remove the microseconds part as it is not working for python2.5 strptime
    return datetime.datetime.strptime(isodatestr.split('.')[0] , "%Y-%m-%dT%H:%M:%S")

def httpdatetime2isodate(httpdate):
    """convert a date string as returned in http headers or mail headers to isodate
    >>> import requests
    >>> last_modified = requests.head('http://wapt/wapt/Packages',headers={'cache-control':'no-cache','pragma':'no-cache'}).headers['last-modified']
    >>> len(httpdatetime2isodate(last_modified)) == 19
    True
    """
    return datetime2isodate(datetime.datetime(*email.utils.parsedate(httpdate)[:6]))

__all__ += ['datetime2isodate']
__all__ += ['isodate2datetime']
__all__ += ['httpdatetime2isodate']


##### Misc. utilities #####
def ensure_list(csv_or_list,ignore_empty_args=True):
    """if argument is not a list, return a list from a csv string"""
    if csv_or_list is None:
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

utils_devel_mode = False
def utils_set_devel_mode(devel):
    global utils_devel_mode
    utils_devel_mode = devel

def mkdir_p(path):
    import errno
    try:
        os.makedirs(path)
    except OSError, exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def wget(url,target,proxies=None,connect_timeout=10,download_timeout=None, chunk_callback=None):
    r"""Copy the contents of a file from a given URL to a local file.
    >>> respath = wget('http://wapt.tranquil.it/wapt/tis-firefox_28.0.0-1_all.wapt','c:\\tmp\\test.wapt',proxies={'http':'http://proxy:3128'})
    ???
    >>> os.stat(respath).st_size>10000
    True
    >>> respath = wget('http://localhost:8088/runstatus','c:\\tmp\\test.json')
    ???
    """

    def default_chunk_callback(expected_size, downloaded_size):
        # nothing
        pass

    if chunk_callback is None:
        chunk_callback = default_chunk_callback

    if os.path.isdir(target):
        target = os.path.join(target,'')

    (dir,filename) = os.path.split(target)
    if not filename:
        filename = url.split('/')[-1]
    if not dir:
        dir = os.getcwd()

    if not os.path.isdir(dir):
        os.makedirs(dir)

    httpreq = requests.get(url,stream=True, proxies=proxies, timeout=connect_timeout, verify=False)

    total_bytes = int(httpreq.headers['content-length'])

    # 1MB max, 2KB min
    chunk_size = min([1024*1024,max([total_bytes/100,2048])])

    httpreq.raise_for_status()

    with open(os.path.join(dir,filename),'wb') as output_file:
        downloaded_bytes = 0
        if httpreq.ok:
            for chunk in httpreq.iter_content(chunk_size=chunk_size):
                chunk_callback(total_bytes, downloaded_bytes)
                output_file.write(chunk)
                if download_timeout is not None and (time.time()-start_time>download_timeout):
                    raise requests.Timeout(r'Download of %s takes more than the requested %ss'%(url,download_timeout))
                if len(chunk) != 0:
                    downloaded_bytes += len(chunk)
                    chunk_callback(total_bytes, downloaded_bytes)

    # restore mtime of file if information is provided.
    if 'last-modified' in httpreq.headers:
        last_modified = httpreq.headers['last-modified']
        unix_timestamp = float(email.utils.mktime_tz(email.utils.parsedate_tz(last_modified)))
        os.utime(os.path.join(dir,filename),(unix_timestamp,unix_timestamp))
    return os.path.join(dir,filename)


def get_disk_space(directory):

    ret = None

    if os.name == 'posix':
        stats = os.statvfs(directory)
        ret = (stats.f_bavail * stats.f_bsize, stats.f_blocks * stats.f_bsize)
    else:
        import wmi

        drive = os.path.splitdrive(os.path.abspath(directory))[0].lower()

        for d in wmi.WMI().Win32_LogicalDisk():
            if str(d.Name).lower() == drive:
                ret = (int(d.FreeSpace), int(d.Size))

    return ret


__all__ += ['ensure_list']
__all__ += ['mkdir_p']
__all__ += ['utils_set_devel_mode']
__all__ += ['wget']
__all__ += ['get_disk_space']


##### Logging #####
logger = logging.getLogger()
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')

def setloglevel(logger,loglevel):
    """set loglevel as string"""
    if loglevel in ('debug','warning','info','error','critical'):
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(_('Invalid log level: {}'.format(loglevel)))
        logger.setLevel(numeric_level)

__all__ += ['logger']
__all__ += ['setloglevel']


##### API V2 #####
def make_response(result = {},success=True,error_code='',msg='',status=200):
    data = dict(
            success = success,
            msg = msg,
            )
    if not success:
        data['error_code'] = error_code
    else:
        data['result'] = result
    return flask.Response(
            response=bson.json_util.dumps(data),
            status=status,
            mimetype="application/json")

def make_response_from_exception(exception,error_code='',status=200):
    """Return a error flask http response from an exception object
        success : False
        msg : message from exception
        error_code : classname of exception if not provided
        status: 200 if not provided
    """
    if not error_code:
        error_code = type(exception).__name__.lower()
    data = dict(
            success = False,
            error_code = error_code
            )
    if utils_devel_mode:
        data['msg'] = traceback.format_exc()
        raise
    else:
        data['msg'] = u"%s" % (exception,)
    return flask.Response(
            response=json.dumps(data),
            status=status,
            mimetype="application/json")

__all__ += ['make_response']
__all__ += ['make_response_from_exception']


##### Custom exceptions #####
class EWaptMissingHostData(Exception):
    pass

class EWaptUnknownHost(Exception):
    pass

class EWaptHostUnreachable(Exception):
    pass

class EWaptForbiddden(Exception):
    pass

class EWaptMissingParameter(Exception):
    pass

class EWaptSignalReceived(Exception):
    pass

class EWaptDatabaseError(Exception):
    pass

__all__ += ['EWaptMissingHostData']
__all__ += ['EWaptUnknownHost']
__all__ += ['EWaptHostUnreachable']
__all__ += ['EWaptForbiddden']
__all__ += ['EWaptMissingParameter']
__all__ += ['EWaptSignalReceived']
__all__ += ['EWaptDatabaseError']
