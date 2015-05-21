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
import logging
import pymongo

from lxml import etree as ET

PFX = "{http://schemas.microsoft.com/msus/2002/12/Update}"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

def qualify(tag):
    return PFX + tag

def find_cab(rev, cabset):
    for start, cab in cabset.items():
        if int(rev) > int(start):
            return cab


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

        props = root.find(qualify('Properties'))

        creation_date = props.get('CreationDate')
        if creation_date is not None:
            data['creation_date'] = creation_date

        msrc_severity = props.get('MsrcSeverity')
        if msrc_severity is not None:
            data['msrc_severity'] = msrc_severity
            logger.debug('MsrcSeverity: %s', data['msrc_severity'])

        elem = props.find(qualify('KBArticleID'))
        if elem is not None:
            data['kb_article_id'] = elem.text
            logger.debug('KBArticleID: %s', data['kb_article_id'])

        elem = props.find(qualify('SecurityBulletinID'))
        if elem is not None:
            data['security_bulletin_id'] = elem.text
            logger.debug('SecurityBulletinID: %s', data['security_bulletin_id'])

        localized_properties_collection = root.find(qualify('LocalizedPropertiesCollection'))
        for elem in localized_properties_collection.iter():
            if elem.tag.endswith('LocalizedProperties'):

                lang = elem.find(qualify('Language'))
                if lang is not None:
                    if lang.text != 'en':
                        break
                else:
                    continue

                title = elem.find(qualify('Title'))
                if title is not None and title.text != '':
                    data['title'] = title.text
                    logger.debug('Title: %s', data['title'])

                descr = elem.find(qualify('Description'))
                if descr is not None and descr.text != '':
                    data['description'] = descr.text
                    logger.debug('Description: %s', data['description'])

    except Exception, e:
        logger.warning("Error while using %s: %s", descr_file, str(e))

    return data


def main(directory):
    if not os.path.isdir(directory):
        print >> sys.stderr, '%s is not a directory' % directory

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

    client = pymongo.MongoClient()
    db = client.wapt

    for update in db.wsus_updates.find():

        rev = update.get('revision_id')
        # no revision -> no metadata on disk
        if rev is None:
            continue

        cab_dir = find_cab(rev, cabs)

        descr_file = os.path.join(directory, cab_dir, 's', rev)
        metadata = parse_metadata(update, descr_file)
        # if metadata:
        #     # XXX add data to MongoDB
        #     db.wsus_updates.update(
        #         { "_id": update["_id"] },
        #         {
        #             "$set": metadata,
        #         }
        #     )
if __name__ == '__main__':
    if len(sys.argv) != 2:
        logger.error('Usage: %s <packages_directory>', sys.argv[0])
        exit(1)
    main(sys.argv[1])
