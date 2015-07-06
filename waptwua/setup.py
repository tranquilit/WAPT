# -*- coding: utf-8 -*-
from setuphelpers import *
import json
import random
import datetime

uninstallkey = []

def update_control(control):
    restrictions = WAPT.waptserver.get('api/v2/windows_updates_restrictions?group=default')['result']
    if restrictions:
        allowed = restrictions[0]['allowed']
        if allowed:
            open('allowed_updates.lst','w').write('\n'.join(allowed))
        else:
            remove_file('allowed_updates.lst')

        forbidden = restrictions[0]['forbidden']
        if forbidden:
            open('forbidden_updates.lst','w').write('\n'.join(forbidden))
        else:
            remove_file('forbidden_updates.lst')

def install():
    waptpython_path = makepath(WAPT.wapt_base_dir,'waptpython.exe')
    waptwua_path = makepath(WAPT.wapt_base_dir,'waptwua')
    waptwuabin_path = WAPT.wapt_base_dir

    """
    if isfile('allowed_updates.lst'):
        allowed = open('allowed_updates.lst','r').read().splitlines()
        WAPT.write_param('waptwua.allowed_updates',json.dumps(allowed))

    if isfile('forbidden_updates.lst'):
        forbidden = open('forbidden_updates.lst','r').read().splitlines()
        WAPT.write_param('waptwua.forbidden_updates',json.dumps(forbidden))

    if isfile('allowed_severities.lst'):
        allowed_severities = open('allowed_severities.lst','r').read().splitlines()
        WAPT.write_param('waptwua.allowed_severities',json.dumps(allowed_severities))

    if isfile('allowed_classifications.lst'):
        allowed_classifications = open('allowed_classifications.lst','r').read().splitlines()
        WAPT.write_param('waptwua.allowed_classifications',json.dumps(allowed_classifications))
    """

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
    WAPT.delete_param('waptwua.allowed_updates')
    WAPT.delete_param('waptwua.forbidden_updates')
    WAPT.delete_param('waptwua.allowed_severities')
    WAPT.delete_param('waptwua.allowed_classifications')
    waptwua_path = makepath(WAPT.wapt_base_dir,'waptwua')
    remove_tree(waptwua_path)
