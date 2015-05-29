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

    if isfile('allowed_updates.lst'):
        allowed = open('allowed_updates.lst','r').read().splitlines()
        WAPT.write_param('waptwua.allowed_updates',json.dumps(allowed))

    if isfile('forbidden_updates.lst'):
        forbidden = open('forbidden_updates.lst','r').read().splitlines()
        WAPT.write_param('waptwua.forbidden_updates',json.dumps(forbidden))

    if isfile('allowed_severities.lst'):
        allowed_severities = open('allowed_severities.lst','r').read().splitlines()
        WAPT.write_param('waptwua.allowed_severities',json.dumps(allowed_severities))

    mkdirs(makepath(waptwua_path,'cache'))
    mkdirs(waptwuabin_path)
    if task_exists('waptwua'):
        delete_task('waptwua')

    dt = datetime.datetime.now()+datetime.timedelta(hours=random.randrange(0,5),minutes=random.randrange(0,59))
    create_daily_task('waptwua',waptpython_path,'"%s" download' % (makepath(waptwuabin_path,'waptwua.py'),),start_hour=dt.hour,start_minute=dt.minute)

def uninstall():
    delete_task('waptwua')
    waptwua_path = makepath(WAPT.wapt_base_dir,'waptwua')
    WAPT.delete_param('waptwua.allowed_updates')
    WAPT.delete_param('waptwua.forbidden_updates')
    WAPT.delete_param('waptwua.allowed_severities')
    WAPT.delete_param('waptwua.allowed_severities')
    remove_tree(waptwua_path)

