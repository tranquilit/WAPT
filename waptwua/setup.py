# -*- coding: utf-8 -*-
from setuphelpers import *
import json
import random
import datetime

uninstallkey = []

def update_control(control):
    try:
        restrictions = WAPT.waptserver.get('api/v2/windows_updates_rules?group=default')['result']
        open('windows_updates_rules.json','w').write(restrictions)
    except:
        print('Unable to get restrictions from waptserver, default to stored ones on workstations')
        restrictions = None
        remove_file('windows_updates_rules.json')

def install():
    waptpython_path = makepath(WAPT.wapt_base_dir,'waptpython.exe')
    waptwua_path = makepath(WAPT.wapt_base_dir,'waptwua')
    waptwuabin_path = WAPT.wapt_base_dir

    # cleanup old settings
    WAPT.delete_param('waptwua.allowed_updates')
    WAPT.delete_param('waptwua.forbidden_updates')
    WAPT.delete_param('waptwua.allowed_severities')
    WAPT.delete_param('waptwua.allowed_classifications')

    if isfile('windows_updates_rules.json'):
        windows_updates_rules = open('windows_updates_rules.json','r').read()
        WAPT.write_param('waptwua.windows_updates_rules',windows_updates_rules)

    # to host wsusscn2.cab file
    mkdirs(makepath(waptwua_path,'cache'))
    mkdirs(waptwuabin_path)
    if task_exists('waptwua'):
        delete_task('waptwua')
    if task_exists('waptwua-scan'):
        delete_task('waptwua-scan')
    if task_exists('waptwua-install'):
        delete_task('waptwua-install')

     # randowmize a little the scan
    dt = datetime.datetime.now()+datetime.timedelta(hours=random.randrange(0,5),minutes=random.randrange(0,59))
    create_daily_task('waptwua-scan',waptpython_path,'"%s" download -C CriticalUpdates' % (makepath(waptwuabin_path,'waptwua.py'),),start_hour=dt.hour,start_minute=dt.minute)
    create_daily_task('waptwua-install',waptpython_path,'"%s" install -C CriticalUpdates' % (makepath(waptwuabin_path,'waptwua.py'),),start_hour=3,start_minute=0)

def uninstall():
    if task_exists('waptwua-scan'):
        run_task
        delete_task('waptwua-scan')
    if task_exists('waptwua-install'):
        delete_task('waptwua-install')
    WAPT.delete_param('waptwua.windows_updates_rules')
    WAPT.delete_param('waptwua.allowed_updates')
    WAPT.delete_param('waptwua.forbidden_updates')
    WAPT.delete_param('waptwua.allowed_severities')
    WAPT.delete_param('waptwua.allowed_classifications')
    waptwua_path = makepath(WAPT.wapt_base_dir,'waptwua')
    remove_tree(waptwua_path)
