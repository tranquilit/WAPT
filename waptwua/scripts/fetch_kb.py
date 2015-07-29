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


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

client = pymongo.MongoClient()
db = client.wapt


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError, exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


level = 0

def solve_update(update_map, update):
    global level

    status = update_map[update['update_id']].get('done', False)
    if status:
        return

    level += 1

    print '%s%s %s %s' % (' ' * (level * 4), 'update', update['update_id'], update.get('title', ''))

    files = update.get('payload_files', [])
    if files:
        urls = []
        for f in files:
            for fl in db.wsus_locations.find({ 'id': f }):
                print '%s%s%s' % (' ' * (level * 4), '  url ', fl['url'])
                urls.append(fl['url'])
        update_map[update['update_id']]['urls'] = urls

    if update.get('is_bundle') or update.get('deployment_action') == 'Bundle':
        bundles = db.wsus_updates.find({ 'bundled_by': update['revision_id'] })
        for b in bundles:
            if b['update_id'] not in update_map:
                update_map[b['update_id']] = b
            solve_update(update_map, b)

    for p in update.get('prereqs', []):
        sub_updates = db.wsus_updates.find({ 'update_id': p })
        for s in sub_updates:
            if s['update_id'] not in update_map:
                update_map[s['update_id']] = s
            solve_update(update_map, s)

    update_map[update['update_id']]['done'] = True

    level -= 1


def solve_kb(kb_id):

    update_map = {}
    docs = db.wsus_updates.find({ "kb_article_id": kb_id })

    for d in docs:
        update_map[d['update_id']] = d
        solve_update(update_map, d)

    if not update_map:
        raise Exception("No such KB ID (%s)" % kb_id)


def main():

    if len(sys.argv) != 2:
        print >> sys.stderr, "Usage: %s <kb_id>" % sys.argv[0]
        exit(1)

    solve_kb(sys.argv[1])


if __name__ == '__main__':
    main()
