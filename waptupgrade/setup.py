# -*- coding: utf-8 -*-
from setuphelpers import *

# registry key(s) where WAPT will find how to remove the application(s)
uninstallkey = []

# command(s) to launch to remove the application(s)
uninstallstring = []

# list of required parameters names (string) which can be used during install
required_params = []

def update_control(entry):
    """Update package control file before build-upload"""
    if isdir('patchs'):
        remove_tree('patchs')
    # waptservice
    def ignore(src,names):
        result = []
        for name in names:
            for pattern in ['*.pyc','*.exe']:
                if glob.fnmatch.fnmatch(name,pattern):
                    result.append(name)
        return result

    copytree2(
        src=makepath(WAPT.wapt_base_dir,'waptservice'),
        dst=makepath('patchs','waptservice'),
        onreplace = default_overwrite,
        ignore=ignore)
    # other pyfile
    waptfiles = ['wapt-get.exe','wapttray.exe','wapt-get.py','common.py','setuphelpers.py','waptpackage.py','waptdevutils.py']
    for f in waptfiles:
        filecopyto(makepath(WAPT.wapt_base_dir,f),'patchs')
    waptget = get_file_properties(r'patchs\wapt-get.exe')
    entry.version = waptget['FileVersion']+'-0'

def oncopy(msg,src,dst):
    print(u'%s : "%s" to "%s"' % (ensure_unicode(msg),ensure_unicode(src),ensure_unicode(dst)))
    return True

def update_registry_version():
    registry_setstring(HKEY_LOCAL_MACHINE,'

def install():
    # if you want to modify the keys depending on environment (win32/win64... params..)
    print('Mise a jour partielle du client Wapt')
    killalltasks('wapttray.exe')
    copytree2('patchs',WAPT.wapt_base_dir, onreplace = default_overwrite,oncopy=oncopy)
    if service_installed('waptservice') and service_is_running('waptservice'):
        print('Restart waptservice')
        service_stop('waptservice')
        service_start('waptservice')
        print('Waptservice restarted')
    print('Upgrade done')

