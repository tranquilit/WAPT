#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2015  Tranquil IT Systems http://www.tranquil.it
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
__version__="1.3.2"

__all__ = [
    'trigger_wsusscan2_download',
    'wsusscan2_status',
    'wsusscan2_history',
    'windows_products',
    'windows_updates_options',
    'windows_updates',
    'download_windows_updates',
    'select_windows_update',
    'windows_updates_rules',
    'windows_updates_urls',
    'windows_updates_classifications',
]

import os
import sys

try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0,os.path.join(wapt_root_dir))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib'))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib','site-packages'))

import collections
import email.utils
from flask import request
import hashlib
import json
from lxml import etree as ET
import pymongo
import requests
import shutil
import stat
import subprocess
import time
import traceback
import urlparse
import uuid
import re
from waptserver_config import conf, huey
from huey import crontab
import random

# i18n
from flask.ext.babel import Babel
try:
    from flask.ext.babel import gettext
except ImportError:
    gettext = (lambda s:s)
_ = gettext

from waptserver_utils import *

waptwua_folder = conf['waptwua_folder']

def utils_get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    try:
        ip = conf['mongodb_ip']
        port = int(conf['mongodb_port'])
        logger.debug('Connecting to mongo db %s:%s'%(ip,port))
        mongo_client = pymongo.MongoClient(ip,port)
        return mongo_client.wapt
    except Exception as e:
        raise Exception("Could not connect to mongodb database: {}.".format((repr(e),)))


def cabextract(cabfile, **kwargs):
    check_only = []
    if kwargs.get('check_only', False):
        check_only = ['-t']

    dstdir = []
    if kwargs.get('dstdir'):
        dstdir = ['-d', kwargs['dstdir']]

    ionice = []
    _ionice = None
    if os.getenv('PATH'):
        for directory in os.getenv('PATH').split(os.pathsep):
            if os.path.exists(os.path.join(directory, 'ionice')):
                _ionice = 'ionice'
    if _ionice:
        ionice = ['ionice', '-c3']

    command = ionice + ['cabextract'] + check_only + dstdir + [cabfile]

    return subprocess.check_output(command)


def make_dl_task_descr(force=False, dryrun=False):
    """Create a template dict describing a wsusscn2.cab download task.
    The task will be inserted in MongoDB wapt.wsusscan2_history and updated
    until it is done.
    """
    dl_uuid = str(uuid.uuid4())

    task_descr = {
        'status': 'pending',
        'reason': '',
        'run_date': datetime2isodate(),
        'forced': force,
        'uuid': dl_uuid,
        'file_date': None,
        'file_size': None,
    }

    wsusscan2_history =  utils_get_db().wsusscan2_history
    wsusscan2_history.ensure_index('uuid', unique=True)
    wsusscan2_history.ensure_index([('run_date', pymongo.DESCENDING)])
    wsusscan2_history.insert(task_descr)

    return task_descr


# Between 2h00 and 2h59
@huey.periodic_task(crontab(hour='3', minute=str(30 + random.randrange(-30, +30))))
def download_wsusscan_crontab():
    descr = make_dl_task_descr()
    return download_wsusscan(task_descr=descr)


@huey.task()
def download_wsusscan(task_descr, force=False, dryrun=False):
    """Launch a task to update current wsus offline cab file
        download in a temporary well known file
        abort if the temporary file is present (means another download is in progress

    """
    cab_url = 'http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab'
    wsus_filename = os.path.join(waptwua_folder,'wsusscn2.cab')
    tmp_filename = os.path.join(waptwua_folder,'wsusscn2.cab.part')

    wsusscan2_history = utils_get_db().wsusscan2_history

    stats = task_descr
    dl_uuid = stats['uuid']

    # should we remove the tmp filename when we get an error?
    cleanup_on_error = False

    if os.path.isfile(tmp_filename):
        os.unlink(tmp_filename)

    try:

        reply = requests.head(cab_url)
        last_modified = reply.headers['last-modified']

        stats['file_date'] = httpdatetime2isodate(last_modified)

        new_cab_timestamp = float(email.utils.mktime_tz(email.utils.parsedate_tz(last_modified)))
        if os.path.isfile(wsus_filename):
            current_cab_timestamp = os.stat(wsus_filename).st_mtime
        else:
            current_cab_timestamp = 0.0

        logger.info('download_wsuscan: current cab timestamp: %f, New cab timestamp: %f' % (current_cab_timestamp,new_cab_timestamp))

        if not os.path.isfile(wsus_filename) or (new_cab_timestamp > current_cab_timestamp) or force:

            logger.info('Downloading because of: file not found == %s, timestamps == %s, force == %s', \
                            str(os.path.isfile(wsus_filename) == False), str(new_cab_timestamp > current_cab_timestamp), force)

            if not os.path.isfile(wsus_filename):
                stats['reason'] = 'file missing'
            elif (new_cab_timestamp > current_cab_timestamp):
                stats['reason'] = 'newer available'
            elif force:
                stats['reason'] = 'forced download'
            else:
                logger.error('download_wsusscan: logic error')
                assert False
            stats['status'] = 'downloading'
            stats['target_size'] = None
            if 'content-length' in reply.headers:
                stats['target_size'] = int(reply.headers['content-length'])
            stats['file_size'] = None
            wsusscan2_history.save(stats)

            def download_wsusscan_callback(total_bytes, downloaded_bytes):
                wsusscan2_history.update(
                    {
                        'uuid': dl_uuid
                    },
                    {
                        '$set': {
                            'file_size': total_bytes,
                        }
                    }
                )

            cleanup_on_error = True
            if dryrun:
                try:
                    os.link(wsus_filename, tmp_filename)
                except:
                    pass
            else:
                wget(cab_url, tmp_filename, chunk_callback=download_wsusscan_callback)

            file_stats = os.stat(tmp_filename)
            stats['file_date'] = httpdatetime2isodate(email.utils.formatdate(file_stats[stat.ST_MTIME], usegmt=True))
            stats['file_size'] = stats['target_size'] = file_stats[stat.ST_SIZE]
            stats['status'] = 'checking'
            wsusscan2_history.save(stats)

            # TODO: verify cryptographic signatures, cabextract -t is not enough

            # check integrity
            if sys.platform == 'win32':
                cablist = subprocess.check_output('expand -D "%s"' % tmp_filename, shell = True).decode('cp850').splitlines()
            else:
                cablist = cabextract(tmp_filename, check_only=True).splitlines()
            stats['cablist'] = cablist

            if os.path.isfile(wsus_filename):
                os.unlink(wsus_filename)
            os.rename(tmp_filename, wsus_filename)

            stats['status'] = 'parsing'
            wsusscan2_history.save(stats)

            parse_wsusscan2(dl_uuid=dl_uuid)

            stats['status'] = 'finished'
            wsusscan2_history.save(stats)

        else:
            stats['status'] = 'finished'
            stats['skipped'] = True
            wsusscan2_history.save(stats)

        return 'OK'

    except Exception as e:
        stats['status'] = 'finished'
        stats['error'] = str(e)
        wsusscan2_history.save(stats)

        if cleanup_on_error and os.path.isfile(tmp_filename):
            os.unlink(tmp_filename)

        logger.error("Error in download_wsusscan: %s", str(e))
        logger.error('Trace:\n%s', traceback.format_exc())
        return 'ERROR'


def wsusscan2_extract_cabs(wsusscan2, tmpdir):
    result = {}

    if not os.path.exists(wsusscan2):
        raise Exception("File %s not found" % wsusscan2)


    mkdir_p(tmpdir)

    cabextract(wsusscan2, dstdir=tmpdir)
    cabextract(os.path.join(tmpdir, 'package.cab'), dstdir=tmpdir)

    cab_list = sorted(filter(lambda f: f.endswith('.cab'), os.listdir(tmpdir)))
    cab_info = utils_get_db().wsus_cab_info

    for cab in cab_list:
        cab_path = os.path.join(tmpdir, cab)

        old_cksum = ''
        before = time.time()
        new_cksum = sha1_for_file(cab_path)
        after = time.time()
        logger.debug('sha1 for file %s processed in %s sec', cab, str(after - before))

        # mark file as processable
        result[cab] = new_cksum

        cur = cab_info.find({ 'cab_name': cab }, limit=1)
        if cur.count():
            old_cksum = cur.next()['cksum']

        logger.debug('cab %s, old [%s]', cab, old_cksum)
        logger.debug('cab %s, new [%s]', cab, new_cksum)

        if old_cksum == new_cksum:
            # no need to extract / process it
            result.pop(cab)
        else:
            logger.info('extracting %s', cab)
            package_dir = cab_path[:-len('.cab')]
            mkdir_p(package_dir)
            cabextract(cab_path, dstdir=package_dir)

    return result

# end of cab extraction

# start of updates parsing

OFFLINE_SYNC_PFX = '{http://schemas.microsoft.com/msus/2004/02/OfflineSync}'

def off_sync_qualify(tag):
    return OFFLINE_SYNC_PFX + tag

UpdateCategories = [
    'Company',
    'Product',
    'ProductFamily',
    'UpdateClassification',
]

def wsusscan2_do_parse_update(update, db, min_rev, stats):

    upd = {}

    upd['update_id'] = update.get('UpdateId')

    if update.get('RevisionId', False) != False:
        upd['revision_id'] = update.get('RevisionId')
        if min_rev > int(upd['revision_id']):
            return

    if update.get('RevisionNumber', False) != False:
        upd['revision_number'] = update.get('RevisionNumber')

    if db.wsus_updates.find(upd).count() != 0:
        return

    if update.get('IsBundle', False):
        upd['is_bundle'] = True

    if update.get('IsLeaf', False):
        upd['is_leaf'] = True

    if update.get('DeploymentAction', False) != False:
        upd['deployment_action'] = update.get('DeploymentAction')

    if update.get('CreationDate', False) != False:
        upd['creation_date'] = update.get('CreationDate')

    categories = update.findall(off_sync_qualify('Categories'))
    if categories:
        upd['categories'] = {}
        for cat in categories:
            for subcat in cat.getchildren():
                type_ = subcat.get('Type')
                assert type_ in UpdateCategories
                upd['categories'][type_] = subcat.get('Id').lower()

    languages = update.findall(off_sync_qualify('Languages'))
    if languages:
        upd['languages'] = []
        assert len(languages) == 1
        for l in languages[0].findall(off_sync_qualify('Language')):
            upd['languages'].append(l.get('Name'))

    prereqs = update.findall(off_sync_qualify('Prerequisites'))
    if prereqs:
        upd['prereqs'] = []
        assert len(prereqs) == 1
        for update_ in prereqs[0].iterchildren(off_sync_qualify('UpdateId')):
                upd['prereqs'].append(update_.get('Id').lower())

    files = update.findall(off_sync_qualify('PayloadFiles'))
    if files:
        upd['payload_files'] = []
        for files_ in files:
            for f in files_.iter(off_sync_qualify('File')):
                upd['payload_files'].append(f.get('Id'))

    bundled_by = update.findall(off_sync_qualify('BundledBy'))
    if bundled_by:
        assert len(bundled_by) == 1
        revisions = bundled_by[0].findall(off_sync_qualify('Revision'))
        old_id = None
        for rev in revisions:
            if old_id is None:
                id_ = rev.get('Id')
            else:
                assert old_id == rev.get('Id')
        upd['bundled_by'] = id_

    languages = update.findall(off_sync_qualify('Languages'))
    if languages:
        assert len(languages) == 1
        upd['languages'] = []
        langs = languages[0].findall(off_sync_qualify('Language'))
        for l in langs:
            upd['languages'].append(l.get('Name'))

    ret = db.wsus_updates.update(upd, upd, upsert=True)
    # TODO use 'ret' and amend stats


def wsusscan2_do_parse_file_location(location, db, stats):

    location_id = location.get('Id')
    location_url = location.get('Url')

    locations_collection = db.wsus_locations
    ret = locations_collection.update(
        { 'id': location_id },
        {
            'id': location_id,
            'url': location_url,
        },
        upsert=True
    )
    # TODO use 'ret' and amend stats


def wsusscan2_parse_updates(tmpdir, db, last_known_rev=0):

    package_xml = os.path.join(tmpdir, 'package.xml')

    updates_stats = {
        'updates': {
            'inserted': 0,
            'modified': 0,
        },
        'file_locations': {
            'inserted': 0,
            'modified': 0,
        },
    }

    for _, elem in ET.iterparse(package_xml):
        if elem.tag == off_sync_qualify('Update'):
            wsusscan2_do_parse_update(elem, db, min_rev=last_known_rev, stats=updates_stats)
        elif elem.tag == off_sync_qualify('FileLocation'):
            wsusscan2_do_parse_file_location(elem, db, stats=updates_stats)

    return updates_stats


# end of updates parsing

# start of metadata parsing

UPDATE_SCHEMA_PFX = "{http://schemas.microsoft.com/msus/2002/12/Update}"

def update_qualify(tag):
    return UPDATE_SCHEMA_PFX + tag

def wsusscn2_parse_metadata(descr_file):

    data = {}

    if not os.path.exists(descr_file):
        return
    if os.path.getsize(descr_file) == 0:
        return

    try:
        xml_str = file(descr_file, 'r').read()
        root = ET.fromstring(xml_str)

        logger.debug("")

        props = root.find(update_qualify('Properties'))

        creation_date = props.get('CreationDate')
        if creation_date is not None:
            data['creation_date2'] = creation_date

        msrc_severity = props.get('MsrcSeverity')
        if msrc_severity is not None:
            data['msrc_severity'] = msrc_severity
            logger.debug('MsrcSeverity: %s', data['msrc_severity'])

        elem = props.find(update_qualify('KBArticleID'))
        if elem is not None:
            data['kb_article_id'] = elem.text
            logger.debug('KBArticleID: %s', data['kb_article_id'])

        elem = props.find(update_qualify('SecurityBulletinID'))
        if elem is not None:
            data['security_bulletin_id'] = elem.text
            logger.debug('SecurityBulletinID: %s', data['security_bulletin_id'])

        localized_properties_collection = root.find(update_qualify('LocalizedPropertiesCollection'))
        for elem in localized_properties_collection.iter():
            if elem.tag.endswith('LocalizedProperties'):

                lang = elem.find(update_qualify('Language'))
                if lang is not None:
                    if lang.text != 'en':
                        break
                else:
                    continue

                title = elem.find(update_qualify('Title'))
                if title is not None and title.text != '':
                    data['title'] = title.text
                    logger.debug('Title: %s', data['title'])

                descr = elem.find(update_qualify('Description'))
                if descr is not None and descr.text != '':
                    data['description'] = descr.text
                    logger.debug('Description: %s', data['description'])

    except Exception, e:
        logger.warning("Error while using %s: %s", descr_file, str(e))

    return data


def amend_metadata(directory, to_parse, db):

    def find_cab(rev, cabset):
        for start, cab in cabset.items():
            if int(rev) > int(start):
                return cab

    xmlindex = os.path.join(directory, 'index.xml')
    tree = ET.parse(xmlindex)
    root = tree.getroot()
    cablist = root.find('CABLIST').findall('CAB')

    cabs = {}
    for cab in cablist:
        cabname = cab.get('NAME')
        rangestart = cab.get('RANGESTART')
        # 'package.cab' has no rangestart attribute
        if rangestart is None:
            continue
        cabs[rangestart] = cabname

    cabs = collections.OrderedDict(
        sorted(
            cabs.items(),
            key=lambda i: int(i[0]),
            reverse=True
        )
    )

    for update in db.wsus_updates.find(fields=['revision_id']):

        rev = update.get('revision_id')
        # no revision -> no metadata on disk
        if rev is None:
            continue

        cab = find_cab(rev, cabs)
        if cab not in to_parse:
            continue

        # strip the extension, keep the directory name
        cab_dir = cab[:-len('.cab')]

        descr_file = os.path.join(directory, cab_dir, 's', rev)
        metadata = wsusscn2_parse_metadata(descr_file)
        if metadata:
            db.wsus_updates.update(
                { "_id": update["_id"] },
                {
                    "$set": metadata,
                }
            )

    # everything went fine, update cksums for updated package*.cab so
    # that we can skip them next time
    cab_info = utils_get_db().wsus_cab_info
    for cab, cksum in to_parse.items():
        logger.info('Updating checksum for cab %s', cab)
        cab_info.update({ 'cab_name': cab }, { 'cab_name': cab, 'cksum': cksum }, upsert=True)


# end of metadata parsing

def parse_wsusscan_entrypoint(dl_uuid=None):
    wsusscan2 = os.path.join(waptwua_folder, 'wsusscn2.cab')

    db = utils_get_db()
    wsusscan2_history = db.wsusscan2_history

    db.wsus_updates.ensure_index([('revision_id', pymongo.DESCENDING)], unique=True)
    db.wsus_updates.ensure_index('update_id')

    db.wsus_locations.ensure_index('id', unique=True)

    last_known_rev = None
    cursor = db.wsus_updates.find(fields=['revision_id'], sort=[('revision_id', pymongo.DESCENDING)], limit=1)
    if cursor.count() != 0:
        last_known_rev = int(cursor[0]['revision_id'])

    tmpdir = os.path.join(waptwua_folder, 'packages.tmp')
    if os.path.exists(tmpdir):
        shutil.rmtree(tmpdir)
    mkdir_p(tmpdir)

    to_parse = wsusscan2_extract_cabs(wsusscan2, tmpdir)
    logger.info('cab archives to parse: %s', str(to_parse.keys()))

    if dl_uuid:
        logger.info('parse_wsusscan_entrypoint: updating dl_uuid \'%s\' with attributes \'%s\'', dl_uuid, to_parse)
        wsusscan2_history.update(
            {
                'uuid': dl_uuid
            },
            {
                '$set': {
                    'changed_cabs': str(to_parse)
                }
            }
        )

    packages = os.path.join(waptwua_folder, 'packages')
    if os.path.exists(packages):
        shutil.rmtree(packages)
    shutil.move(tmpdir, packages)

    if 'package.cab' in to_parse:
        logger.info('starting wsusscan2_parse_updates')
        before = time.time()
        update_stats = wsusscan2_parse_updates(packages, db, last_known_rev)
        if update_stats:
            wsusscan2_history.update(
                {
                    'uuid': dl_uuid
                },
                {
                    '$set': {
                        'updates': str(update_stats)
                    }
                }
            )
        after = time.time()
        logger.info('wsusscan2_parse_updates in %s secs', str(after - before))
    else:
        # No new updates / file locations
        logger.info('parse_wsusscan_entrypoint: skipping updates parsing')

    logger.info('starting amend_metadata')
    before = time.time()
    amend_metadata(packages, to_parse, db)
    after = time.time()
    logger.info('amend_metadata in %s secs', str(after - before))


def parse_wsusscan2(dl_uuid):
    try:
        parse_wsusscan_entrypoint(dl_uuid)
    except Exception as e:
        logger.error('Exception in parse_wsusscan2: %s', repr(e))
        logger.error('Traceback: %s', traceback.format_exc())


#@app.route('/api/v2/download_wsusscan')
def trigger_wsusscan2_download():
    dryrun = bool(int(request.args.get('dryrun', 0)))
    force = bool(int(request.args.get('force', 0)))

    logger.info('Triggering download_wsusscan with parameter ' + str(force))

    task_descr = make_dl_task_descr(dryrun=dryrun, force=force)

    download_wsusscan(task_descr, dryrun=dryrun, force=force)

    return make_response(result=task_descr)


#@app.route('/api/v2/wsusscan2_status')
def wsusscan2_status():
    wsus_filename = os.path.join(waptwua_folder,'wsusscn2.cab')
    tmp_filename = os.path.join(waptwua_folder,'wsusscn2.cab.tmp')

    success = False
    downloading = False
    exc_type = 'unknown'
    data = {}

    try:
        stats = os.stat(wsus_filename)
        success = True
        data.update({
            'wsus_timestamp': stats[stat.ST_MTIME],
            'wsus_size':      stats[stat.ST_SIZE],
        })
    except Exception as e:
        exc_type = type(e).__name__.lower()

    try:
        tmp_stats = os.stat(tmp_filename)
        downloading = True
        data.update({
            'tmp_wsus_timestamp': tmp_stats[stat.ST_MTIME],
            'tmp_wsus_size':      tmp_stats[stat.ST_SIZE],
        })
    except Exception:
        pass

    if success:
        msg = 'wsusscn2.cab present'
        error_code = ''
    else:
        if downloading:
            msg = 'wsusscn2.cab absent, is another download running?'
        else:
            msg = 'wsusscn2.cab absent, please download it first'
        error_code = exc_type

    return make_response(success=success, result=data, msg=msg, error_code=error_code)

#@app.route('/api/v2/wsusscan2_history')
def wsusscan2_history():
    try:
        if request.method == 'GET':
            data = []
            filter = {}
            if 'uuid' in request.args:
               filter['uuid'] = {'$in':ensure_list(request.args['uuid'])}
            if 'status' in request.args:
               filter['status'] = {'$in':ensure_list(request.args['status'])}
            if 'skipped' in request.args:
               if int(request.args['skipped']) == 1:
                   filter['skipped'] = True
               else:
                   filter['skipped'] = {'$exists':False}

            limit = int(request.args.get('limit','0'))
            query = wsusscan2_history = utils_get_db().wsusscan2_history.find(filter,limit=limit).sort('run_date',pymongo.DESCENDING)
            for log in query:
                data.append(log)
            return make_response(result=data)
        elif request.method == 'DELETE':
            uuids = ensure_list(request.args['uuid'])
            result = utils_get_db().wsusscan2_history.remove({'uuid':{'$in':uuids}})
            if result['err']:
                raise EWaptDatabaseError(result['err'])
            return make_response(result = result,msg='%s tasks deleted' % result['n'])
    except Exception as e:
        return make_response_from_exception(e)


#https://msdn.microsoft.com/en-us/library/ff357803%28v=vs.85%29.aspx
update_classifications_id = {
 '28bc880e-0592-4cbf-8f95-c79b17911d5f': 'UpdateRollups',    # Ensemble de mises à jour
 'b54e7d24-7add-428f-8b75-90a396fa584f': 'FeaturePacks',     # feature packs
 'e6cf1350-c01b-414d-a61f-263d14d133b4': 'CriticalUpdates',  # Mises à jour critiques
 '0fa1201d-4330-4fa8-8ae9-b877473b6441': 'SecurityUpdates',  # Mises à jour de la sécurité
 'cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83': 'Updates',          # Mises à jour
 'e0789628-ce08-4437-be74-2495b842f43b': 'DefinitionUpdates',# Mises à jour de définitions
 'b4832bd8-e735-4761-8daf-37f882276dab': 'Tools',            # Outils
 'ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0': 'Drivers',          # Pilotes
 '68c5b0a3-d1a6-4553-ae49-01d3a7827828': 'ServicePacks',     # Services pack
 '434de588-ed14-48f5-8eed-a15e09a991f6': 'Connectors',       #
 '5c9376ab-8ce6-464a-b136-22113dd69801': 'Application',      #
 '9511d615-35b2-47bb-927f-f73d8e9260bb': 'Guidance',         #
 'e140075d-8433-45c3-ad87-e72345b36078': 'DeveloperKits',    #
 }

#https://msdn.microsoft.com/en-us/library/bb902472%28v=vs.85%29.aspx
detectoid_id = {
 '59653007-e2e9-4f71-8525-2ff588527978': 'x64-based systems',
 'aabd43ad-a183-4f0b-8eee-8dbbcd67687f': 'Itanium-based systems',
 '3e0afb10-a9fb-4c16-a60e-5790c3803437': 'x86-based systems',
}


products_id = {
    "fdcfda10-5b1f-4e57-8298-c744257e30db":"Active Directory Rights Management Services Client 2.0",
    "57742761-615a-4e06-90bb-008394eaea47":"Active Directory",
    "5d6a452a-55ba-4e11-adac-85e180bda3d6":"Antigen for Exchange/SMTP",
    "116a3557-3847-4858-9f03-38e94b977456":"Antigen",
    "b86cf33d-92ac-43d2-886b-be8a12f81ee1":"Bing Bar",
    "2b496c37-f722-4e7b-8467-a7ad1e29e7c1":"Bing",
    "34aae785-2ae3-446d-b305-aec3770edcef":"BizTalk Server 2002",
    "86b9f801-b8ec-4d16-b334-08fba8567c17":"BizTalk Server 2006R2",
    "b61793e6-3539-4dc8-8160-df71054ea826":"BizTalk Server 2009",
    "61487ade-9a4e-47c9-baa5-f1595bcdc5c5":"BizTalk Server 2013",
    "ed036c16-1bd6-43ab-b546-87c080dfd819":"BizTalk Server",
    "83aed513-c42d-4f94-b4dc-f2670973902d":"CAPICOM",
    "236c566b-aaa6-482c-89a6-1e6c5cac6ed8":"Category for System Center Online Client",
    "ac615cb5-1c12-44be-a262-fab9cd8bf523":"Compute Cluster Pack",
    "eb658c03-7d9f-4bfa-8ef3-c113b7466e73":"Data Protection Manager 2006",
    "48ce8c86-6850-4f68-8e9d-7dc8535ced60":"Developer Tools, Runtimes, and Redistributables",
    "f76b7f51-b762-4fd0-a35c-e04f582acf42":"Dictionary Updates for Microsoft IMEs",
    "83a83e29-7d55-44a0-afed-aea164bc35e6":"Exchange 2000 Server",
    "3cf32f7c-d8ee-43f8-a0da-8b88a6f8af1a":"Exchange Server 2003",
    "ab62c5bd-5539-49f6-8aea-5a114dd42314":"Exchange Server 2007 and Above Anti-spam",
    "26bb6be1-37d1-4ca6-baee-ec00b2f7d0f1":"Exchange Server 2007",
    "9b135dd5-fc75-4609-a6ae-fb5d22333ef0":"Exchange Server 2010",
    "d3d7c7a6-3e2f-4029-85bf-b59796b82ce7":"Exchange Server 2013",
    "352f9494-d516-4b40-a21a-cd2416098982":"Exchange",
    "fa9ff215-cfe0-4d57-8640-c65f24e6d8e0":"Expression Design 1",
    "f3b1d39b-6871-4b51-8b8c-6eb556c8eee1":"Expression Design 2",
    "18a2cff8-9fd2-487e-ac3b-f490e6a01b2d":"Expression Design 3",
    "9119fae9-3fdd-4c06-bde7-2cbbe2cf3964":"Expression Design 4",
    "5108d510-e169-420c-9a4d-618bdb33c480":"Expression Media 2",
    "d8584b2b-3ac5-4201-91cb-caf6d240dc0b":"Expression Media V1",
    "a33f42ac-b33f-4fd2-80a8-78b3bfa6a142":"Expression Web 3",
    "3b1e1746-d99b-42d4-91fd-71d794f97a4d":"Expression Web 4",
    "ca9e8c72-81c4-11dc-8284-f47156d89593":"Expression",
    "d72155f3-8aa8-4bf7-9972-0a696875b74e":"Firewall Client for ISA Server",
    "0a487050-8b0f-4f81-b401-be4ceacd61cd":"Forefront Client Security",
    "a38c835c-2950-4e87-86cc-6911a52c34a3":"Forefront Endpoint Protection 2010",
    "86134b1c-cf56-4884-87bf-5c9fe9eb526f":"Forefront Identity Manager 2010 R2",
    "d7d32245-1064-4edf-bd09-0218cfb6a2da":"Forefront Identity Manager 2010",
    "a6432e15-a446-44af-8f96-0475c472aef6":"Forefront Protection Category",
    "f54d8a80-c7e1-476c-9995-3d6aee4bfb58":"Forefront Server Security Category",
    "84a54ea9-e574-457a-a750-17164c1d1679":"Forefront Threat Management Gateway, Definition Updates for HTTP Malware Inspection",
    "06bdf56c-1360-4bb9-8997-6d67b318467c":"Forefront TMG MBE",
    "59f07fb7-a6a1-4444-a9a9-fb4b80138c6d":"Forefront TMG",
    "f8c3c9a9-10de-4f09-bc16-5eb1b861fb4c":"Forefront",
    "f0474daf-de38-4b6e-9ad6-74922f6f539d":"Fotogalerie-Installation und -Upgrades",
    "d84d138e-8423-4102-b317-91b1339aa9c9":"HealthVault Connection Center Upgrades",
    "2e068336-2ead-427a-b80d-5b0fffded7e7":"HealthVault Connection Center",
    "0c6af366-17fb-4125-a441-be87992b953a":"Host Integration Server 2000",
    "784c9f6d-959a-433f-b7a3-b2ace1489a18":"Host Integration Server 2004",
    "eac7e88b-d8d4-4158-a828-c8fc1325a816":"Host Integration Server 2006",
    "42b678ae-2b57-4251-ae57-efbd35e7ae96":"Host Integration Server 2009",
    "3f3b071e-c4a6-4bcc-b6c1-27122b235949":"Host Integration Server 2010",
    "5964c9f1-8e72-4891-a03a-2aed1c4115d2":"HPC Pack 2008",
    "4f93eb69-8b97-4677-8de4-d3fca7ed10e6":"HPC Pack",
    "d123907b-ba63-40cb-a954-9b8a4481dded":"Installation von OneCare Family Safety",
    "b627a8ff-19cd-45f5-a938-32879dd90123":"Internet Security and Acceleration Server 2004",
    "2cdbfa44-e2cb-4455-b334-fce74ded8eda":"Internet Security and Acceleration Server 2006",
    "0580151d-fd22-4401-aa2b-ce1e3ae62bc9":"Internet Security and Acceleration Server",
    "5cc25303-143f-40f3-a2ff-803a1db69955":"Lokal veröffentlichte Pakete",
    "7c40e8c2-01ae-47f5-9af2-6e75a0582518":"Lokaler Herausgeber",
    "00b2d754-4512-4278-b50b-d073efb27f37":"Microsoft Application Virtualization 4.5",
    "c755e211-dc2b-45a7-be72-0bdc9015a63b":"Microsoft Application Virtualization 4.6",
    "1406b1b4-5441-408f-babc-9dcb5501f46f":"Microsoft Application Virtualization 5.0",
    "523a2448-8b6c-458b-9336-307e1df6d6a6":"Microsoft Application Virtualization",
    "7e903438-3690-4cf0-bc89-2fc34c26422b":"Microsoft BitLocker Administration and Monitoring v1",
    "c8c19432-f207-4d9d-ab10-764f3d29744d":"Microsoft BitLocker Administration and Monitoring",
    "587f7961-187a-4419-8972-318be1c318af":"Microsoft Dynamics CRM 2011 SHS",
    "2f3d1aba-2192-47b4-9c8d-87b41f693af4":"Microsoft Dynamics CRM 2011",
    "0dbc842c-730f-4361-8811-1b048f11c09b":"Microsoft Dynamics CRM",
    "e7ba9d21-4c88-4f88-94cb-a23488e59ebd":"Microsoft HealthVault",
    "5e870422-bd8f-4fd2-96d3-9c5d9aafda22":"Microsoft Lync 2010",
    "04d85ac2-c29f-4414-9cb6-5bcd6c059070":"Microsoft Lync Server 2010",
    "01ce995b-6e10-404b-8511-08142e6b814e":"Microsoft Lync Server 2013",
    "2af51aa0-509a-4b1d-9218-7e7508f05ec3":"Microsoft Lync Server and Microsoft Lync",
    "935c5617-d17a-37cc-dbcf-423e5beab8ea":"Microsoft Online Services",
    "b0247430-6f8d-4409-b39b-30de02286c71":"Microsoft Online Services-Anmelde-Assistent",
    "a8f50393-2e42-43d1-aaf0-92bec8b60775":"Microsoft Research AutoCollage 2008",
    "0f3412f2-3405-4d86-a0ff-0ede802227a8":"Microsoft Research AutoCollage",
    "b567e54e-648b-4ac6-9171-149a19a73da8":"Microsoft Security Essentials",
    "e9ece729-676d-4b57-b4d1-7e0ab0589707":"Microsoft SQL Server 2008 R2 - PowerPivot for Microsoft Excel 2010",
    "56750722-19b4-4449-a547-5b68f19eee38":"Microsoft SQL Server 2012",
    "fe324c6a-dac1-aca8-9916-db718e48fa3a":"Microsoft SQL Server PowerPivot for Excel",
    "a73eeffa-5729-48d4-8bf4-275132338629":"Microsoft StreamInsight V1.0",
    "4c1a298e-8dbd-5d8b-a52f-6c176fdd5904":"Microsoft StreamInsight",
    "5ef2c723-3e0b-4f87-b719-78b027e38087":"Microsoft System Center Data Protection Manager",
    "bf6a6018-83f0-45a6-b9bf-074a78ec9c82":"Microsoft System Center DPM 2010",
    "29fd8922-db9e-4a97-aa00-ca980376b738":"Microsoft System Center Virtual Machine Manager 2007",
    "7e5d0309-78dd-4f52-a756-0259f88b634b":"Microsoft System Center Virtual Machine Manager 2008",
    "b790e43b-f4e4-48b4-9f0c-499194f00841":"Microsoft Works 8",
    "e9c87080-a759-475a-a8fa-55552c8cd3dc":"Microsoft Works 9",
    "56309036-4c77-4dd9-951a-99ee9c246a94":"Microsoft",
    "6b9e8b26-8f50-44b9-94c6-7846084383ec":"MS Security Essentials",
    "4217668b-66f0-42a0-911e-a334a5e4dbad":"Network Monitor 3",
    "35c4463b-35dc-42ac-b0ba-1d9b5c505de2":"Network Monitor",
    "8508af86-b85e-450f-a518-3b6f8f204eea":"New Dictionaries for Microsoft IMEs",
    "6248b8b1-ffeb-dbd9-887a-2acf53b09dfe":"Office 2002/XP",
    "1403f223-a63f-f572-82ba-c92391218055":"Office 2003",
    "041e4f9f-3a3d-4f58-8b2f-5e6fe95c4591":"Office 2007",
    "84f5f325-30d7-41c4-81d1-87a0e6535b66":"Office 2010",
    "704a0a4a-518f-4d69-9e03-10ba44198bd5":"Office 2013",
    "22bf57a8-4fe1-425f-bdaa-32b4f655284b":"Office Communications Server 2007 R2",
    "e164fc3d-96be-4811-8ad5-ebe692be33dd":"Office Communications Server 2007",
    "504ae250-57c5-484a-8a10-a2c35ea0689b":"Office Communications Server And Office Communicator",
    "8bc19572-a4b6-4910-b70d-716fecffc1eb":"Office Communicator 2007 R2",
    "03c7c488-f8ed-496c-b6e0-be608abb8a79":"Office Live",
    "ec231084-85c2-4daf-bfc4-50bbe4022257":"Office Live-Add-In",
    "477b856e-65c4-4473-b621-a8b230bb70d9":"Office",
    "dd78b8a1-0b20-45c1-add6-4da72e9364cf":"OOBE ZDP",
    "7cf56bdd-5b4e-4c04-a6a6-706a2199eff7":"Report Viewer 2005",
    "79adaa30-d83b-4d9c-8afd-e099cf34855f":"Report Viewer 2008",
    "f7f096c9-9293-422d-9be8-9f6e90c2e096":"Report Viewer 2010",
    "9f9b1ace-a810-11db-bad5-f7f555d89593":"SDK Components",
    "ce62f77a-28f3-4d4b-824f-0f9b53461d67":"Search Enhancement Pack",
    "6cf036b9-b546-4694-885a-938b93216b66":"Security Essentials",
    "9f3dd20a-1004-470e-ba65-3dc62d982958":"Silverlight",
    "fe729f7e-3945-11dc-8e0c-cd1356d89593":"Silverlight",
    "6750007f-c908-4f2c-8aff-48ca6d36add6":"Skype for Windows",
    "1e602215-b397-46ca-b1a8-7ea0059517bc":"Skype",
    "7145181b-9556-4b11-b659-0162fa9df11f":"SQL Server 2000",
    "60916385-7546-4e9b-836e-79d65e517bab":"SQL Server 2005",
    "bb7bc3a7-857b-49d4-8879-b639cf5e8c3c":"SQL Server 2008 R2",
    "c5f0b23c-e990-4b71-9808-718d353f533a":"SQL Server 2008",
    "7fe4630a-0330-4b01-a5e6-a77c7ad34eb0":"SQL Server 2012 Product Updates for Setup",
    "c96c35fc-a21f-481b-917c-10c4f64792cb":"SQL Server Feature Pack",
    "0a4c6c73-8887-4d7f-9cbe-d08fa8fa9d1e":"SQL Server",
    "daa70353-99b4-4e04-b776-03973d54d20f":"System Center 2012 - App Controller",
    "b0c3b58d-1997-4b68-8d73-ab77f721d099":"System Center 2012 - Data Protection Manager",
    "bf05abfb-6388-4908-824e-01565b05e43a":"System Center 2012 - Operations Manager",
    "ab8df9b9-8bff-4999-aee5-6e4054ead976":"System Center 2012 - Orchestrator",
    "6ed4a93e-e443-4965-b666-5bc7149f793c":"System Center 2012 - Virtual Machine Manager",
    "50d71efd-1e60-4898-9ef5-f31a77bde4b0":"System Center 2012 SP1 - App Controller",
    "dd6318d7-1cff-44ed-a0b1-9d410c196792":"System Center 2012 SP1 - Data Protection Manager",
    "80d30b43-f814-41fd-b7c5-85c91ea66c45":"System Center 2012 SP1 - Operation Manager",
    "ba649061-a2bd-42a9-b7c3-825ce12c3cd6":"System Center 2012 SP1 - Virtual Machine Manager",
    "ae4500e9-17b0-4a78-b088-5b056dbf452b":"System Center Advisor",
    "d22b3d16-bc75-418f-b648-e5f3d32490ee":"System Center Configuration Manager 2007",
    "23f5eb29-ddc6-4263-9958-cf032644deea":"System Center Online",
    "9476d3f6-a119-4d6e-9952-8ad28a55bba6":"System Center Virtual Machine Manager",
    "26a5d0a5-b108-46f1-93fa-f2a9cf10d029":"System Center",
    "5a456666-3ac5-4162-9f52-260885d6533a":"Systems Management Server 2003",
    "78f4e068-1609-4e7a-ac8e-174288fa70a1":"Systems Management Server",
    "ae4483f4-f3ce-4956-ae80-93c18d8886a6":"Threat Management Gateway Definition Updates for Network Inspection System",
    "cd8d80fe-5b55-48f1-b37a-96535dca6ae7":"TMG Firewall Client",
    "4ea8aeaf-1d28-463e-8179-af9829f81212":"Update zur Browserauswahl in Europa (nur Europa)",
    "c8a4436c-1043-4288-a065-0f37e9640d60":"Virtual PC",
    "6d992428-3b47-4957-bb1a-157bd8c73d38":"Virtual Server",
    "f61ce0bd-ba78-4399-bb1c-098da328f2cc":"Virtual Server",
    "a0dd7e72-90ec-41e3-b370-c86a245cd44f":"Visual Studio 2005",
    "e3fde9f8-14d6-4b5c-911c-fba9e0fc9887":"Visual Studio 2008",
    "cbfd1e71-9d9e-457e-a8c5-500c47cfe9f3":"Visual Studio 2010 Tools for Office Runtime",
    "c9834186-a976-472b-8384-6bb8f2aa43d9":"Visual Studio 2010",
    "abddd523-04f4-4f8e-b76f-a6c84286cc67":"Visual Studio 2012",
    "cf4aa0fc-119d-4408-bcba-181abb69ed33":"Visual Studio 2013",
    "3b4b8621-726e-43a6-b43b-37d07ec7019f":"Windows 2000",
    "bfe5b177-a086-47a0-b102-097e4fa1f807":"Windows 7",
    "3e5cc385-f312-4fff-bd5e-b88dcf29b476":"Windows 8 Language Interface Packs",
    "97c4cee8-b2ae-4c43-a5ee-08367dab8796":"Windows 8 Language Packs",
    "405706ed-f1d7-47ea-91e1-eb8860039715":"Windows 8.1 Drivers",
    "18e5ea77-e3d1-43b6-a0a8-fa3dbcd42e93":"Windows 8.1 Dynamic Update",
    "14a011c7-d17b-4b71-a2a4-051807f4f4c6":"Windows 8.1 Language Interface Packs",
    "01030579-66d2-446e-8c65-538df07e0e44":"Windows 8.1 Language Packs",
    "6407468e-edc7-4ecd-8c32-521f64cee65e":"Windows 8.1",
    "2ee2ad83-828c-4405-9479-544d767993fc":"Windows 8",
    "393789f5-61c1-4881-b5e7-c47bcca90f94":"Windows Consumer Preview Dynamic Update",
    "8c3fcc84-7410-4a95-8b89-a166a0190486":"Windows Defender",
    "50c04525-9b15-4f7c-bed4-87455bcd7ded":"Windows Dictionary Updates",
    "f14be400-6024-429b-9459-c438db2978d4":"Windows Embedded Developer Update",
    "f4b9c883-f4db-4fb5-b204-3343c11fa021":"Windows Embedded Standard 7",
    "a36724a5-da1a-47b2-b8be-95e7cd9bc909":"Windows Embedded",
    "6966a762-0c7c-4261-bd07-fb12b4673347":"Windows Essential Business Server 2008 Setup Updates",
    "e9b56b9a-0ca9-4b3e-91d4-bdcf1ac7d94d":"Windows Essential Business Server 2008",
    "649f3e94-ed2f-42e8-a4cd-e81489af357c":"Windows Essential Business Server Preinstallation Tools",
    "41dce4a6-71dd-4a02-bb36-76984107376d":"Windows Essential Business Server",
    "470bd53a-c36a-448f-b620-91feede01946":"Windows GDR-Dynamic Update",
    "5ea45628-0257-499b-9c23-a6988fc5ea85":"Windows Live Toolbar",
    "0ea196ba-7a32-4e76-afd8-46bd54ecd3c6":"Windows Live",
    "afd77d9e-f05a-431c-889a-34c23c9f9af5":"Windows Live",
    "b3d0af68-8a86-4bfc-b458-af702f35930e":"Windows Live",
    "e88a19fb-a847-4e3d-9ae2-13c2b84f58a6":"Windows Media Dynamic Installer",
    "8c27cdba-6a1c-455e-af20-46b7771bbb96":"Windows Next Graphics Driver Dynamic update",
    "2c62603e-7a60-4832-9a14-cfdfd2d71b9a":"Windows RT 8.1",
    "0a07aea1-9d09-4c1e-8dc7-7469228d8195":"Windows RT",
    "7f44c2a7-bc36-470b-be3b-c01b6dc5dd4e":"Windows Server 2003, Datacenter Edition",
    "dbf57a08-0d5a-46ff-b30c-7715eb9498e9":"Windows Server 2003",
    "fdfe8200-9d98-44ba-a12a-772282bf60ef":"Windows Server 2008 R2",
    "ec9aaca2-f868-4f06-b201-fb8eefd84cef":"Windows Server 2008 Server-Manager - Dynamic Installer",
    "ba0ae9cc-5f01-40b4-ac3f-50192b5d6aaf":"Windows Server 2008",
    "26cbba0f-45de-40d5-b94a-3cbe5b761c9d":"Windows Server 2012 Language Packs",
    "8b4e84f6-595f-41ed-854f-4ca886e317a5":"Windows Server 2012 R2 Language Packs",
    "d31bd4c3-d872-41c9-a2e7-231f372588cb":"Windows Server 2012 R2",
    "a105a108-7c9b-4518-bbbe-73f0fe30012b":"Windows Server 2012",
    "eef074e9-61d6-4dac-b102-3dbe15fff3ea":"Windows Server Solutions Best Practices Analyzer 1.0",
    "4e487029-f550-4c22-8b31-9173f3f95786":"Windows Server-Manager - Windows Server Updates Services (WSUS) Dynamic Installer",
    "032e3af5-1ac5-4205-9ae5-461b4e8cd26d":"Windows Small Business Server 2003",
    "7fff3336-2479-4623-a697-bcefcf1b9f92":"Windows Small Business Server 2008 Migration Preparation Tool",
    "575d68e2-7c94-48f9-a04f-4b68555d972d":"Windows Small Business Server 2008",
    "1556fc1d-f20e-4790-848e-90b7cdbedfda":"Windows Small Business Server 2011 Standard",
    "68623613-134c-4b18-bcec-7497ac1bfcb0":"Windows Small Business Server",
    "e7441a84-4561-465f-9e0e-7fc16fa25ea7":"Windows Ultimate Extras",
    "90e135fb-ef48-4ad0-afb5-10c4ceb4ed16":"Windows Vista Dynamic Installer",
    "a901c1bd-989c-45c6-8da0-8dde8dbb69e0":"Windows Vista Ultimate Language Packs",
    "26997d30-08ce-4f25-b2de-699c36a8033a":"Windows Vista",
    "a4bedb1d-a809-4f63-9b49-3fe31967b6d0":"Windows XP 64-Bit Edition Version 2003",
    "4cb6ebd5-e38a-4826-9f76-1416a6f563b0":"Windows XP x64 Edition",
    "558f4bc3-4827-49e1-accf-ea79fd72d4c9":"Windows XP",
    "6964aab4-c5b5-43bd-a17d-ffb4346a8e1d":"Windows",
    "81b8c03b-9743-44b1-8c78-25e750921e36":"Works 6-9 Converter",
    "2425de84-f071-4358-aac9-6bbd6e0bfaa7":"Works",
    "a13d331b-ce8f-40e4-8a18-227bf18f22f3":"Writer-Installation und -Upgrades",
}

def get_product_id(expr):
    """Find product ids matching expr"""
    result = []
    match = re.compile(expr,re.IGNORECASE)
    for key,value in products_id.iteritems():
        if match.match(value) or expr == key:
            result.append(key)
    return result


def simplematch(expr):
    words = expr.split()
    match = re.compile('[ \s.,:]*'.join(words) ,re.IGNORECASE)
    return match

#@app.route('/api/v2/windows_products')
def windows_products():
    result = []
    if 'search' in request.args:
        match = simplematch(request.args['search'])
        result = [ dict(product=product,title=title) for (product,title) in products_id.iteritems()
                    if match.match(title) or product == request.args['search']]
    else:
        result = [ dict(product=product,title=title) for (product,title) in products_id.iteritems()]
    if 'selected' in request.args and bool(int(request.args['selected'])):
        selection = get_selected_products()
        result = [ r for r in result if r['product'] in selection]
    return make_response(msg = _('Windows Products'), result = result )


#@app.route('/api/v2/windows_updates_options',methods=['GET','POST'])
def windows_updates_options():
    key = request.args.get('key','default')
    if request.method == 'POST':
        data = json.loads(request.data)
        result = utils_get_db().wsus_options.update({'key':key},{'key':key,'value': data},upsert=True)
    else:
        if key == 'default':
            result = utils_get_db().wsus_options.find()
            return make_response(msg='Win updates global options', result=result)
        else:
            result = utils_get_db().wsus_options.find({ 'key': key })
    return make_response(msg = _('Win updates global option for key %(key)s',key=key),result=result)


def get_selected_products():
     result = utils_get_db().wsus_options.find({'key':'products_selection'})
     if result:
         for r in result:
             return r['value']
         else:
             return []
     else:
         return []


#@app.route('/api/v2/windows_updates_classifications')
def windows_updates_classifications():
    result = []
    ids = request.args.get('id',None)
    if ids is not None:
        ids = ensure_list(ids)
    for k in update_classifications_id:
        if ids is None or k in ids:
            result.append(dict(id=k,name=update_classifications_id[k]))
    return make_response(msg = _('Win updates classifications'),result=result)


#@app.route('/api/v2/windows_updates')
def windows_updates():
    """
{
	"_id": ObjectId("555ca6dfe9cd567f6ee3308b"),
	"categories": {
		"ProductFamily": "6964aab4-c5b5-43bd-a17d-ffb4346a8e1d",
		"Company": "56309036-4c77-4dd9-951a-99ee9c246a94",
		"UpdateClassification": "0fa1201d-4330-4fa8-8ae9-b877473b6441",
		"Product": "558f4bc3-4827-49e1-accf-ea79fd72d4c9"
    	},
	"description": "A security issue has been identified in a Microsoft software product that could affect your system. You can help protect your system by installing this update from Microsoft. For a complete listing of the issues that are included in this update, see the associated Microsoft Knowledge Base article. After you install this update, you may have to restart your system.",
	"kb_article_id": "2929961",
	"msrc_severity": "Critical",
	"prereqs": ["824c2b95-8529-4939-956c-587f30b1a024",
    	"3e0afb10-a9fb-4c16-a60e-5790c3803437",
    	"0fa1201d-4330-4fa8-8ae9-b877473b6441",
    	"558f4bc3-4827-49e1-accf-ea79fd72d4c9"],
	"revision_id": "11542192",
	"security_bulletin_id": "MS14-013",
	"title": "Security Update for Windows XP (KB2929961)",
	"update_id": "fe81ecb6-6b64-450b-a2a6-f3bf4b124556"
}
{
	"_id": ObjectId("555cae69e9cd5606eb22aea0"),
	"revision_id": "11542192",
	"prereqs": ["824c2b95-8529-4939-956c-587f30b1a024",
    	"3e0afb10-a9fb-4c16-a60e-5790c3803437",
    	"0fa1201d-4330-4fa8-8ae9-b877473b6441",
    	"558f4bc3-4827-49e1-accf-ea79fd72d4c9"],
	"update_id": "fe81ecb6-6b64-450b-a2a6-f3bf4b124556",
	"categories": {
		"ProductFamily": "6964aab4-c5b5-43bd-a17d-ffb4346a8e1d",
		"Company": "56309036-4c77-4dd9-951a-99ee9c246a94",
		"UpdateClassification": "0fa1201d-4330-4fa8-8ae9-b877473b6441",
		"Product": "558f4bc3-4827-49e1-accf-ea79fd72d4c9"
	}
}
    """
    wsus_updates = utils_get_db().wsus_updates
    query = {}

    supported_filters = [
        'has_kb',
        'kb',
        'languages', # none pour les updates non specifiques a un langage, fr pour francais, etc
        'product',
        'products',
        'selected_products',
        'severity',
        'update_classifications',
        'update_ids',
    ]

    filters = {}
    got_filter = False
    for f in supported_filters:
        filters[f] = request.args.get(f, False)
        if filters[f]:
            got_filter = True
    if not got_filter:
        return make_response(msg='Error, no valid request filter provided', success=False)

    # collect invalid parameters, for logging and debugging purposes
    unknown_filters = []
    for arg in request.args.keys():
        if arg not in supported_filters:
            unknown_filters.append(arg)

    top_and_query_list = []

    # has_kb
    if filters['has_kb']:
        top_and_query_list.append({ 'kb_article_id': { '$exists': True } })
    # kb
    if filters['kb']:
        kbs = []
        for kb in ensure_list(filters['kb']):
            if kb.upper().startswith('KB'):
                kbs.append(kb[2:])
            else:
                kbs.append(kb)
        top_and_query_list.append({ 'kb_article_id': { '$in':kbs } })
    # languages
    if filters['languages']:
        languages = ensure_list(filters['languages'])
        or_languages_list = []
        try:
            languages.remove('none')
            or_languages_list.append({ 'languages': { '$exists': False } })
        except ValueError:
            pass
        or_languages_list.append({ 'languages': { '$in': languages } })
        top_and_query_list.append({ '$or': or_languages_list })
    # product
    if filters['product']:
        top_and_query_list.append({ 'categories.Product': { '$in': get_product_id(filters['product']) } })
    # products
    if filters['products']:
        top_and_query_list.append({ 'categories.Product': { '$in': ensure_list(filters['products'])   } })
    # selected_products
    if filters['selected_products']:
        top_and_query_list.append({ 'categories.Product': { '$in': get_selected_products()            } })
    # severity
    if filters['severity']:
        top_and_query_list.append({ 'msrc_severity':      { '$in': ensure_list(filters['severity'])   } })
    # update_classifications
    if filters['update_classifications']:
        update_classifications = []
        for update_classification in ensure_list(filters['update_classifications']):
            update_classifications.append(update_classification)
        top_and_query_list.append({ 'categories.UpdateClassification': { '$in': update_classifications } })
    # update_ids
    if filters['update_ids']:
        top_and_query_list.append({ 'update_id': { '$in': ensure_list(filters['update_ids']) } })

    query = { '$and': top_and_query_list }

    result = wsus_updates.find(query)
    cnt = result.count()
    return make_response(msg = _('Windows Updates, filter: %(query)s, count: %(cnt)s, unknown params: %(unknown)s',query=query,cnt=cnt,unknown=unknown_filters),result = result)


#@app.route('/api/v2/windows_updates_urls',methods=['GET'])
def windows_updates_urls():
    """Return list of URL of files to download for the selected update_id

    Args:
        update_id
    Returns:
        urls
    """

    try:
        update_id = request.args.get('update_id')
        if not update_id:
            return make_response(msg='Missing update_id parameter', success=False)
        wsus_updates = utils_get_db().wsus_updates
        def get_payloads(id):
            result = []
            updates = [ u for u in wsus_updates.find({'update_id':id},{'prereqs':1,'payload_files':1})]
            if updates:
                for update in updates:
                    result.extend(update.get('payload_files',[]))
                    for req in update.get('prereqs',[]):
                        result.extend(get_payloads(req))
            return result

        update_id = request.args['update_id']
        files_id = get_payloads(update_id)
        result = utils_get_db().wsus_locations.find({'id':files_id},{'url':1})
        cnt = result.count()
        logger.info('returning from windows_updates_urls')
    except Exception as e:
        logger.error('Got an exception in windows_updates_urls: %s', str(e))
        return make_response_from_exception(e)
    return make_response(msg = _('Downloads for Windows Updates %(update_id)s, count: %(cnt)s',update_id=update_id,cnt=cnt),result = files_id)


def sha1_for_file(fname, block_size=2**20):
    f = open(fname,'rb')
    sha1 = hashlib.sha1()
    while True:
        data = f.read(block_size)
        if not data:
            break
        sha1.update(data)
    return sha1.hexdigest()


# XXX returns None (ie False in boolean context) if nothing looks like a sha1
# hash in the file name -> false positives?
def check_sha1_filename(target):
    # check sha1 sum if possible...
    if os.path.isfile(target):
        sha1sum_parts = os.path.basename(target).rsplit('.',1)[0].rsplit('_',1)
        if sha1sum_parts:
            sha1sum = sha1sum_parts[1]
            # looks like hex sha1
            if len(sha1sum) == 40 and (sha1sum != sha1_for_file(target)):
                return False
        return True


#@app.route('/api/v2/download_windows_update')
def download_windows_updates():

    try:
        kb_article_id = request.args.get('kb_article_id', None)
        if kb_article_id != None:
            requested_kb = utils_get_db().requested_kb
            requested_kb.update({ 'kb_article_id': kb_article_id }, { 'kb_article_id': kb_article_id, '$inc': { 'request_count', int(1) } }, upsert=True)
    except Exception as e:
            logger.error('download_windows_updates: %s', str(e))

    try:
        url = request.args['url']
        url_parts = urlparse.urlparse(url)
        if url_parts.netloc not in ['download.windowsupdate.com','www.download.windowsupdate.com']:
            raise Exception('Unauthorized location')
        fileparts = urlparse.urlparse(url).path.split('/')
        target = os.path.join(waptwua_folder,*fileparts)

        # check sha1 sum if possible...
        if os.path.isfile(target) and not check_sha1_filename(target):
            os.remove(target)

        if not os.path.isfile(target):
            download_windows_update_task(url)
            raise Exception('Download triggered, come back later!')

        result = {'url':'/waptwua%s'% ('/'.join(fileparts),),'size':os.stat(target).st_size}
        return make_response(msg='Windows patch available',result=result)
    except Exception as e:
        return make_response_from_exception(e)


@huey.task(retries=3, retry_delay=60)
def download_windows_update_task(url):
    url_parts = urlparse.urlparse(url)
    if url_parts.netloc not in ['download.windowsupdate.com','www.download.windowsupdate.com']:
        raise Exception('Unauthorized location')
    fileparts = urlparse.urlparse(url).path.split('/')
    target = os.path.join(waptwua_folder,*fileparts)

    # check sha1 sum if possible...
    if os.path.isfile(target) and not check_sha1_filename(target):
        os.remove(target)

    if not os.path.isdir(os.path.join(waptwua_folder,*fileparts[:-1])):
        os.makedirs(os.path.join(waptwua_folder,*fileparts[:-1]))
    tmp_target = target + '.part'
    if os.path.isfile(tmp_target):
        os.unlink(tmp_target)
    wget(url, tmp_target)
    if check_sha1_filename(tmp_target) == False:
        os.remove(target)
        raise Exception('Error during download, sha1 mismatch')
    else:
        os.rename(tmp_target, target)

    return True


def do_resolve_update(update_map, update_id, recursion_level):

    update = update_map[update_id]

    status = update.get('done', False)
    if status:
        return

    recursion_level += 1

    if recursion_level > 30:
        raise Exception('Max recursion reached when resolving update.')

    wsus_locations = utils_get_db().wsus_locations

    wsus_locations.ensure_index('id', unique=True)

    files = update.get('payload_files', [])
    if files:
        file_locations = []
        for f in files:
            for fl in wsus_locations.find({ 'id': f }):
                file_locations.append(fl)
        update_map[update_id]['file_locations'] = file_locations

    wsus_updates = utils_get_db().wsus_updates

    db.wsus_updates.ensure_index([('revision_id', pymongo.DESCENDING)], unique=True)
    db.wsus_updates.ensure_index('update_id')
    db.wsus_updates.ensure_index('bundled_by')

    if update.get('is_bundle') or update.get('deployment_action') == 'Bundle':
        bundles = wsus_updates.find({ 'bundled_by': update['revision_id'] })
        for b in bundles:
            if b['update_id'] not in update_map:
                update_map[b['update_id']] = b
            do_resolve_update(update_map, b['update_id'], recursion_level)

    for p in update.get('prereqs', []):
        sub_updates = wsus_updates.find({ 'update_id': p })
        for s in sub_updates:
            if s['update_id'] not in update_map:
                update_map[s['update_id']] = s
            do_resolve_update(update_map, s['update_id'], recursion_level)

    update_map[update_id]['done'] = True


#@app.route('/api/v2/select_windows_update', methods=['GET'])
def select_windows_update():
    """
    """
    try:
        try:
            update_id = request.args['update_id']
            forget = request.args.get('forget', False)
        except:
            raise Exception('Invalid or missing parameters')

        try:
            # normalize
            update = str(uuid.UUID(update_id))
        except:
            raise Exception('Invalid update_id format')

        wsus_updates = utils_get_db().wsus_updates
        update_map = {}
        for update in wsus_updates.find({ 'update_id': update_id }):
            update_map[update['update_id']] = update
        if not update_map:
            raise Exception('No such update_id')

        # the real work
        do_resolve_update(update_map, update_id, 0)

        dl_info = []
        for u in update_map:
            for fl in update_map[u].get('file_locations', []):
                del fl['_id']
                dl_info.append(fl)

        # not needed any more, free resources
        del update_map

        wsus_fetch_info = utils_get_db().wsus_fetch_info
        wsus_fetch_info.ensure_index('id', unique=True)

        ok = 0
        total = len(dl_info)
        for fl in dl_info:
            try:
                if forget:
                    wsus_fetch_info.remove({ 'id': fl['id'] })
                else:
                    wsus_fetch_info.insert(fl)
                ok += 1
            except:
                pass

        raise Exception('WARNING: method called with no auth ; forget=' + str(forget) + ', ok=' + str(ok) + '/' + str(total))

    except Exception as e:
        import traceback
        traceback.print_exc()
        return make_response_from_exception(e)


#@app.route('/api/v2/windows_updates_rules',methods=['GET','POST','DELETE'])
def windows_updates_rules():
    if request.method == 'POST':
        group = request.args.get('group','default')
        data = json.loads(request.data)
        if not 'group' in data:
            data['group'] = group
        result = utils_get_db().wsus_rules.update({'group':group},{"$set": data},upsert=True)
    elif request.method == 'DELETE':
        group = request.args.get('group','default')
        result = utils_get_db().wsus_rules. update({'group':group},{"$set": data},upsert=True)
    else:
        if 'group' in  request.args:
            group = request.args.get('group','default')
            result = utils_get_db().wsus_rules.find({'group':group})
        else:
            result = utils_get_db().wsus_rules.find()

    return make_response(msg = _('Win updates rules'),result = result)


def wuredist_extract_and_fetch(wuredist, tmpdir):
    cabextract(wuredist, dstdir=tmpdir)
    wuredist_xml = os.path.join(tmpdir, 'wuredist.xml')
    if not os.path.exists(wuredist_xml):
        raise Exception('wuredist.cab does not contain a wuredist.xml file')

    tree = ET.parse(wuredist_xml)
    root = tree.getroot()
    cablist = root.find('StandaloneRedist').findall('architecture')
    for cab in cablist:
        url = cab.get('downloadUrl')
        url_parts = urlparse.urlparse(url)
        if url_parts.netloc not in ['download.windowsupdate.com','www.download.windowsupdate.com']:
            raise Exception('Unauthorized location')
        fileparts = url_parts.path.split('/')
        target = os.path.join(waptwua_folder,*fileparts)
        if not os.path.isfile(target):
            folder = os.path.join(waptwua_folder,*fileparts[:-1])
            if not os.path.isdir(folder):
                os.makedirs(folder)
            wget(url, target)


#@app.route('/api/v2/download_wuredist')
def download_wuredist():
    cab_url = 'http://update.microsoft.com/redist/wuredist.cab'
    wuredist_filename = os.path.join(waptwua_folder, 'wuredist.cab')
    tmp_filename = wuredist_filename + '.part'

    # should we remove the tmp filename when we get an error?
    cleanup_on_error = False

    force = request.args.get('force', False)
    dryrun = request.args.get('dryrun', False)

    stats = {}

    if os.path.isfile(tmp_filename):
        os.unlink(tmp_filename)

    try:

        last_modified = requests.head(cab_url).headers['last-modified']

        new_cab_timestamp = float(email.utils.mktime_tz(email.utils.parsedate_tz(last_modified)))
        if os.path.isfile(wuredist_filename):
            current_cab_timestamp = os.stat(wuredist_filename).st_mtime
        else:
            current_cab_timestamp = 0.0

        logger.info('download_wuredist: current cab timestamp: %f, New cab timestamp: %f' % (current_cab_timestamp,new_cab_timestamp))

        if not os.path.isfile(wuredist_filename) or (new_cab_timestamp > current_cab_timestamp) or force:

            cleanup_on_error = True
            if dryrun:
                try:
                    if os.path.exists(tmp_filename):
                        os.unlink(tmp_filename)
                    os.link(wuredist_filename, tmp_filename)
                except Exception as e:
                    logger.error('download_wuredist: exception %s', str(e))
                    pass
            else:
                wget(cab_url, tmp_filename)

            file_stats = os.stat(tmp_filename)
            stats['file_timestamp'] = file_stats[stat.ST_MTIME]
            stats['file_size'] = file_stats[stat.ST_SIZE]
            stats['status'] = 'checking'
            #wuredist_history.save(stats)

            # TODO verify cryptographic signatures

            # check integrity
            if sys.platform == 'win32':
                cablist = subprocess.check_output('expand -D "%s"' % tmp_filename, shell = True).decode('cp850').splitlines()
            else:
                cablist = cabextract(tmp_filename, check_only=True).splitlines()
            stats['cablist'] = cablist

            if os.path.isfile(wuredist_filename):
                os.unlink(wuredist_filename)
            os.rename(tmp_filename, wuredist_filename)

            stats['status'] = 'parsing'
            #wuredist_history.save(stats)

            tmpdir = os.path.join(waptwua_folder, 'wuredist.tmp')
            if os.path.exists(tmpdir):
                shutil.rmtree(tmpdir)
            mkdir_p(tmpdir)
            wuredist_extract_and_fetch(wuredist_filename, tmpdir)

            stats['status'] = 'finished'
            #wuredist_history.save(stats)

        else:
            stats['skipped'] = True
            #wuredist_history.save(stats)

    except Exception as e:
        stats['error'] = str(e)
        #wuredist_history.save(stats)

        if cleanup_on_error and os.path.isfile(tmp_filename):
            os.unlink(tmp_filename)

        logger.error("Error in download_wuredist: %s", str(e))
        logger.error('Trace:\n%s', traceback.format_exc())
        return make_response_from_exception(e)

    return make_response(msg=str(stats), success=True)
