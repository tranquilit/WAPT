# -*- coding: utf-8 -*-
from setuphelpers import *
import json
import random
import datetime
from iniparse import RawConfigParser

uninstallkey = []

wuagroup = 'default'

def update_control(control):
    try:
        restrictions = WAPT.waptserver.get('api/v2/windows_updates_rules?group={}'.format(wuagroup))['result']
        if restrictions:
            #control.package = '{}-waptwua-{}'.format(WAPT.config.get('global','default_package_prefix'),wuagroup)
            control.description = restrictions[0]['description']
            open('windows_updates_rules.json','w').write(json.dumps(restrictions[0]['rules'],indent=True))
        else:
            raise Exception('Empty ruleset')

    except Exception as e:
        print('Unable to get restrictions from waptserver, default to stored ones on workstations: {}'.format(e))
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
        print('Windows Updates rules : {}'.format(windows_updates_rules))
    else:
        print('No Windows uUdate rules in package')

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
    create_daily_task('waptwua-scan',waptpython_path,'"{}" download'.format(makepath(waptwuabin_path,'waptwua.py'),),start_hour=dt.hour,start_minute=dt.minute,max_runtime=120)
    create_daily_task('waptwua-install',waptpython_path,'"{}" install'.format(makepath(waptwuabin_path,'waptwua.py'),),start_hour=3,start_minute=0,max_runtime=180)

    # enable waptwua in ini file
    WAPT.waptwua_enabled = True
    inifile_writestring(WAPT.config_filename,'global','waptwua_enabled',True)



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
