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


import collections
import errno
import logging
import pymongo
import shutil
import subprocess
import tempfile
from lxml import etree as ET


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError, exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def pp(elem):
    print ET.tostring(elem, pretty_print=True)

# start of cab extraction

def extract_cabs(wsusscan2, tmpdir):

    if not os.path.exists(wsusscan2):
        print >> sys.stderr, "%s does not exist" % wsusscan2

    packages = os.path.join(tmpdir, 'packages')

    mkdir_p(packages)

    subprocess.check_output(['cabextract', '-d', packages, wsusscan2])

    cab_list = filter(lambda f: f.endswith('.cab'), os.listdir(packages))

    for cab in cab_list:
        cab_path = os.path.join(packages, cab)
        package_dir = cab_path[:-len('.cab')]
        mkdir_p(package_dir)
        subprocess.check_output(['cabextract', '-d', package_dir, cab_path])

    subprocess.check_output(['cabextract', '-d', packages, os.path.join(packages, 'package.cab')])

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

def parse_update(update, db):

    superseded = update.findall(off_sync_qualify('SupersededBy'))
    if superseded:
        return

    upd = {}

    upd['update_id'] = update.get('UpdateId')

    if update.get('IsBundle', False):
        upd['is_bundle'] = True

    if update.get('IsLeaf', False):
        upd['is_leaf'] = True

    if update.get('RevisionId', False) != False:
        upd['revision_id'] = update.get('RevisionId')

    if update.get('RevisionNumber', False) != False:
        upd['revision_number'] = update.get('RevisionNumber')

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

    db.wsus_updates.insert(upd)


def parse_file_location(location, db):

    location_id = location.get('Id')
    location_url = location.get('Url')

    locations_collection = db.wsus_locations
    locations_collection.insert({
        'id': location_id,
        'url': location_url,
    })


def fetch_updates(tmpdir, db):
    package_xml = os.path.join(tmpdir, 'package.xml')
    for _, elem in ET.iterparse(package_xml):
        if elem.tag == off_sync_qualify('Update'):
            parse_update(elem, db)
        elif elem.tag == off_sync_qualify('FileLocation'):
            parse_file_location(elem, db)

# end of updates parsing

# start of metadata parsing

UPDATE_SCHEMA_PFX = "{http://schemas.microsoft.com/msus/2002/12/Update}"

def update_qualify(tag):
    return UPDATE_SCHEMA_PFX + tag

def parse_metadata(upd, descr_file):

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


def amend_metadata(directory, db):

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
        # strip the extension, keep the directory name
        cabs[rangestart] = cabname[:-len('.cab')]

    cabs = collections.OrderedDict(
        sorted(
            cabs.items(),
            key=lambda i: int(i[0]),
            reverse=True
        )
    )

    for update in db.wsus_updates.find():

        rev = update.get('revision_id')
        # no revision -> no metadata on disk
        if rev is None:
            continue

        cab_dir = find_cab(rev, cabs)

        descr_file = os.path.join(directory, cab_dir, 's', rev)
        metadata = parse_metadata(update, descr_file)
        if metadata:
            db.wsus_updates.update(
                { "_id": update["_id"] },
                {
                    "$set": metadata,
                }
            )

# end of metadata parsing

if __name__ == '__main__':

    if len(sys.argv) != 2:
        logger.error('Usage: %s /path/to/wsusscan2.cab', sys.argv[0])
        exit(1)

    wsusscan2 = sys.argv[1]

    client = pymongo.MongoClient()
    db = client.wapt

    tempfile.tempdir = '/home/tisadmin/tmp/'
    #tmpdir = tempfile.mkdtemp()
    tmpdir = '/home/tisadmin/tmp/tmp.h2dAeGWT84'
    logger.info('working in %s', tmpdir)
    logger.info('extracting cabs')
    #extract_cabs(wsusscan2, tmpdir)
    packages = os.path.join(tmpdir, 'packages')
    logger.info('fetching updates')
    fetch_updates(packages, db)
    logger.info('amending metadata')
    amend_metadata(packages, db)



