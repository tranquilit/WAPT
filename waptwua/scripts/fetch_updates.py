#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

try:
    #wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
    wapt_root_dir = '/opt/wapt'
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0,os.path.join(wapt_root_dir))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib'))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib','site-packages'))


import datetime
import email.utils
import hashlib
import pymongo
import requests
import time
import urlparse
import uuid
import ConfigParser


try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

config_file = '/opt/wapt/waptserver/waptserver.ini'
config = ConfigParser.RawConfigParser()
if os.path.exists(config_file):
    config.read(config_file)
else:
    raise Exception('')


if config.has_option('options', 'wapt_folder'):
    wapt_folder = config.get('options', 'wapt_folder')
    if wapt_folder.endswith('/'):
        wapt_folder = wapt_folder[:-1]
else:
    wapt_folder = os.path.join(wapt_root_dir,'waptserver','repository','wapt')

if config.has_option('options', 'waptwua_folder'):
    waptwua_folder = config.get('options', 'waptwua_folder')
    if waptwua_folder.endswith('/'):
        waptwua_folder = waptwua_folder[:-1]
else:
    waptwua_folder = wapt_folder+'wua'




def wget(url,target=None,proxies=None,connect_timeout=10,download_timeout=None):
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
        filedate = isodate2datetime(httpdatetime2isodate(httpreq.headers['last-modified']))
        unixtime = time.mktime(filedate.timetuple())
        os.utime(os.path.join(dir,filename),(unixtime,unixtime))


client = pymongo.MongoClient()
db = client.wapt

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

def sha1_for_file(fname, block_size=2**20):
    f = open(fname,'rb')
    sha1 = hashlib.sha1()
    while True:
        data = f.read(block_size)
        if data == '':
            break
        sha1.update(data)
    return sha1.hexdigest()

def fetch_update(update_info):
    def check_sha1_filename(target):
        # check sha1 sum if possible...
        if os.path.isfile(target):
            sha1sum_parts = os.path.basename(target).rsplit('.')[0].rsplit('_',1)
            if sha1sum_parts:
                sha1sum = sha1sum_parts[1]
                #looks like hex sha1
                if len(sha1sum) == 40 and (sha1sum != sha1_for_file(target)):
                    return False
            return True

    url = update_info['url']
    url_parts = urlparse.urlparse(url)
    if url_parts.netloc not in ['download.windowsupdate.com','www.download.windowsupdate.com']:
        raise Exception('Unauthorized location')
    fileparts = urlparse.urlparse(url).path.split('/')
    target = os.path.join(waptwua_folder,*fileparts)

    if os.path.isfile(target) and not check_sha1_filename(target):
        os.remove(target)

    if not os.path.isfile(target):
        if not os.path.isdir(os.path.join(waptwua_folder,*fileparts[:-1])):
            os.makedirs(os.path.join(waptwua_folder,*fileparts[:-1]))
        wget(url, target)
        if not check_sha1_filename(target):
            os.remove(target)
            raise Exception('Error during download, sha1 mismatch')

def main():

    if len(sys.argv) != 1:
        print >> sys.stderr, "Usage: %s" % sys.argv[0]
        exit(1)

    wsus_fetch_info = db.wsus_fetch_info
    for update in wsus_fetch_info.find():
        try:
            if update.get('todo', 'true') == 'true':
                fetch_update(update)
                wsus_fetch_info.update({ 'id': update['id'] }, { "$set": { 'todo': 'false' } })
        except Exception as e:
            raise


if __name__ == '__main__':
    main()
