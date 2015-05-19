# -*- coding: utf-8 -*-
from setuphelpers import *

uninstallkey = []

def install():
    print('installing tis-waptwsus')
    waptpython_path = makepath(WAPT.wapt_base_dir,'waptpython.exe')
    waptwua_path = makepath(WAPT.wapt_base_dir,'waptwua')
    waptwuabin_path = makepath(WAPT.wapt_base_dir,'waptwua','bin')

    mkdirs(makepath(waptwua_path,'cache'))
    mkdirs(waptwuabin_path)
    filecopyto('waptwua.py',waptwuabin_path)
    create_daily_task('waptwua',waptpython_path,'"%s" download' % (makepath(waptwuabin_path,'waptwua.py'),))

def uninstall():
    delete_task('waptwua')
    waptwua_path = makepath(WAPT.wapt_base_dir,'waptwua')
    remove_tree(waptwua_path)

