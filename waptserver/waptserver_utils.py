#!/usr/bin/env python
# -*-: coding: utf-8 -*-

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
    return datetime2isodate(datetime.datetime(*_email_utils.parsedate(httpdate)[:6]))

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

utils_mongodb_ip = ''
utils_mongodb_port = ''

def utils_setup_db(ip, port):
    global utils_mongodb_ip, utils_mongodb_port
    utils_mongodb_ip = ip
    utils_mongodb_port = port

def utils_get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    try:
        logger.debug('Connecting to mongo db %s:%s'%(utils_mongodb_ip, int(utils_mongodb_port)))
        mongo_client = pymongo.MongoClient(utils_mongodb_ip, int(utils_mongodb_port))
        return mongo_client.wapt
    except Exception as e:
        raise Exception("Could not connect to mongodb database: {}.".format((repr(e),)))


def mkdir_p(path):
    import errno
    try:
        os.makedirs(path)
    except OSError, exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def wget(url,target,proxies=None,connect_timeout=10,download_timeout=None):
    r"""Copy the contents of a file from a given URL to a local file.
    >>> respath = wget('http://wapt.tranquil.it/wapt/tis-firefox_28.0.0-1_all.wapt','c:\\tmp\\test.wapt',proxies={'http':'http://proxy:3128'})
    ???
    >>> os.stat(respath).st_size>10000
    True
    >>> respath = wget('http://localhost:8088/runstatus','c:\\tmp\\test.json')
    ???
    """
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

    with open(os.path.join(dir,filename),'wb') as output_file:
        last_downloaded = 0
        if httpreq.ok:
            for chunk in httpreq.iter_content(chunk_size=chunk_size):
                output_file.write(chunk)
                if download_timeout is not None and (time.time()-start_time>download_timeout):
                    raise requests.Timeout(r'Download of %s takes more than the requested %ss'%(url,download_timeout))
                last_downloaded += len(chunk)
        else:
            httpreq.raise_for_status()

    # restore mtime of file if information is provided.
    if 'last-modified' in httpreq.headers:
        last_modified = httpreq.headers['last-modified']
        unix_timestamp = float(email.utils.mktime_tz(email.utils.parsedate_tz(last_modified)))
        os.utime(os.path.join(dir,filename),(unix_timestamp,unix_timestamp))
    return os.path.join(dir,filename)

__all__ += ['ensure_list']
__all__ += ['mkdir_p']
__all__ += ['utils_get_db']
__all__ += ['utils_setup_db']
__all__ += ['wget']


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
    if options.devel:
        data['msg'] = traceback.format_exc()
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

__all__ += ['EWaptMissingHostData']
__all__ += ['EWaptUnknownHost']
__all__ += ['EWaptHostUnreachable']
__all__ += ['EWaptForbiddden']
__all__ += ['EWaptMissingParameter']
