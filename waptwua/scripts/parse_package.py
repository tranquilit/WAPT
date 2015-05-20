#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os,sys
try:
    #wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
    wapt_root_dir = '/opt/wapt'
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0,os.path.join(wapt_root_dir))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib'))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib','site-packages'))

import logging
from pymongo import MongoClient

from lxml import etree as ET

OFFLINE_SYNC_NAMESPACE = 'http://schemas.microsoft.com/msus/2004/02/OfflineSync'
OFFLINE_SYNC = '{' + OFFLINE_SYNC_NAMESPACE + '}'

UpdateClassification = {
    '5C9376AB-8CE6-464A-B136-22113DD69801'.lower(): 'Application',
    '434DE588-ED14-48F5-8EED-A15E09A991F6'.lower(): 'Connectors',
    'E6CF1350-C01B-414D-A61F-263D14D133B4'.lower(): 'CriticalUpdates',
    'E0789628-CE08-4437-BE74-2495B842F43B'.lower(): 'DefinitionUpdates',
    'E140075D-8433-45C3-AD87-E72345B36078'.lower(): 'DeveloperKits',
    'B54E7D24-7ADD-428F-8B75-90A396FA584F'.lower(): 'FeaturePacks',
    '9511D615-35B2-47BB-927F-F73D8E9260BB'.lower(): 'Guidance',
    '0FA1201D-4330-4FA8-8AE9-B877473B6441'.lower(): 'SecurityUpdates',
    '68C5B0A3-D1A6-4553-AE49-01D3A7827828'.lower(): 'ServicePacks',
    'B4832BD8-E735-4761-8DAF-37F882276DAB'.lower(): 'Tools',
    '28BC880E-0592-4CBF-8F95-C79B17911D5F'.lower(): 'UpdateRollups',
    'CD5FFD1E-E932-4E3A-BF74-18BF0B1BBD83'.lower(): 'Updates',
}

UpdateCategories = [
    'Company',
    'Product',
    'ProductFamily',
    'UpdateClassification',
]

updates = 0
locations = 0
payload_files_found = 0

client = MongoClient()
db = client.wapt
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()


def qualify(tag):
    return OFFLINE_SYNC + tag

def parse_update(update):
    global updates, payload_files_found

    superseded = update.findall(qualify('SupersededBy'))
    if superseded:
        return

    updates += 1

    upd = {}

    upd['update_id'] = update.get('UpdateId')

    if update.get('isBundle', False):
        upd['isBundle'] = True

    if update.get('isLeaf', False):
        upd['isLeaf'] = True

    if update.get('RevisionId', False) != False:
        upd['revision_id'] = update.get('RevisionId')

    categories = update.findall(qualify('Categories'))
    if categories:
        upd['categories'] = {}
        for cat in categories:
            for subcat in cat.getchildren():
                type_ = subcat.get('Type')
                if type_ in UpdateCategories:
                    upd['categories'][type_] = subcat.get('Id', '').lower()

    prereqs = update.findall(qualify('Prerequisites'))
    if prereqs:
        upd['prereqs'] = []
        for prereq in prereqs:
            for update_ in prereq.iterchildren(qualify('UpdateId')):
                upd['prereqs'].append(update_.get('Id').lower())

    files = update.findall(qualify('PayloadFiles'))
    if files:
        upd['payload_files'] = []
        for files_ in files:
            payload_files_found += 1
            for f in files_.iter(qualify('File')):
                upd['payload_files'].append(f.get('Id'))

    db.wsus_updates.insert(upd)


def parse_file_location(location):
    global locations
    locations += 1

    location_id = location.get('Id')
    location_url = location.get('Url')

    locations_collection = db.wsus_locations
    locations_collection.insert({
        'id': location_id,
        'url': location_url,
    })


def get_dl_urls(package_xml):
    for _, elem in ET.iterparse(package_xml):
        if elem.tag == qualify('Update'):
            parse_update(elem)
        elif elem.tag == qualify('FileLocation'):
            parse_file_location(elem)


def main(args):
    global updates, locations, payload_files_found

    try:
        get_dl_urls(args[0])
    except Exception, e:
        logger.error("Warning: %s", str(e))
    logger.info("Updates inserted: %d", updates)
    logger.info("Locations inserted: %d", locations)
    logger.info("PayloadFiles statements found: %d", payload_files_found)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        logger.error('Usage: %s /path/to/package.xml', sys.argv[0])
        exit(1)
    main(sys.argv[1:])
