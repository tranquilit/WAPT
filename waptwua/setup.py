# -*- coding: utf-8 -*-
from setuphelpers import *
import json

uninstallkey = []

def update_control(control):
    restrictions = WAPT.waptserver.get('api/v2/windows_updates_restrictions?group=default')['result']
    if restrictions:
        enabled = restrictions[0]['enabled']
        if enabled:
            open('enabled_updates.lst','w').write('\n'.join(enabled))
        else:
            remove_file('enabled_updates.lst')

        discarded = restrictions[0]['discarded']
        if discarded:
            open('discarded_updates.lst','w').write('\n'.join(discarded))
        else:
            remove_file('discarded_updates.lst')

def install():
    print('installing tis-waptwsus')
    waptpython_path = makepath(WAPT.wapt_base_dir,'waptpython.exe')
    waptwua_path = makepath(WAPT.wapt_base_dir,'waptwua')
    waptwuabin_path = WAPT.wapt_base_dir

    if isfile('enabled_updates.lst'):
        enabled = open('enabled_updates.lst','r').read().splitlines()
        WAPT.write_param('waptwua.allowed_updates',json.dumps(enabled))

    mkdirs(makepath(waptwua_path,'cache'))
    mkdirs(waptwuabin_path)
    if task_exists('waptwua'):
        delete_task('waptwua')

    if isfile('enabled_updates.lst'):
        create_daily_task('waptwua',waptpython_path,'"%s" download' % (makepath(waptwuabin_path,'waptwua.py'),))
    else:
        create_daily_task('waptwua',waptpython_path,'"%s" --critical download' % (makepath(waptwuabin_path,'waptwua.py'),))
    run_task('waptwua')

def uninstall():
    delete_task('waptwua')
    waptwua_path = makepath(WAPT.wapt_base_dir,'waptwua')
    remove_tree(waptwua_path)

