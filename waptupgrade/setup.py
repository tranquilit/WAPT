# -*- coding: utf-8 -*-
from setuphelpers import *
import os

# registry key(s) where WAPT will find how to remove the application(s)
uninstallkey = []

def update_sources():
    files = [
         'common.py',
         'setuphelpers.py',
         'wapt-get.exe',
         'wapt-get.exe.manifest',
         'wapt-get.py',
         'waptdevutils.py',
         'waptpackage.py',
         'wapttray.exe',
         'keyfinder.py',
         'COPYING.txt',
         'version',
         'templates',
         'waptconsole.exe',
         'waptconsole.exe.manifest',
         'waptservice',
    ]

    def ignore(src,names):
        result = []
        for name in names:
            for pattern in ['*.pyc','*.exe']:
                if glob.fnmatch.fnmatch(name,pattern):
                    result.append(name)
        return result

    checkout_dir = os.path.abspath(os.path.join(os.getcwd(),'..'))

    # cleanup patchs dir
    shutil.rmtree(os.path.join(checkout_dir,'waptupgrade','patchs'))
    os.makedirs(os.path.join(checkout_dir,'waptupgrade','patchs'))
    for f in files:
        fn = os.path.join(checkout_dir,f)
        target_fn = os.path.join(checkout_dir,'waptupgrade','patchs',f)
        if os.path.isfile(fn):
            filecopyto(fn,target_fn)
        elif os.path.isdir(fn):
            copytree2(
                src=fn,
                dst=target_fn,
                onreplace = default_overwrite,
                ignore=ignore)


def update_control(entry):
    """Update package control file before build-upload"""
    update_sources()
    waptget = get_file_properties(r'patchs\wapt-get.exe')
    entry.version = waptget['FileVersion']+'-0'

def oncopy(msg,src,dst):
    print(u'%s : "%s" to "%s"' % (ensure_unicode(msg),ensure_unicode(src),ensure_unicode(dst)))
    return True

def update_registry_version(version):
    import _winreg
    with _winreg.CreateKeyEx(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WAPT_is1',\
            0, _winreg.KEY_READ| _winreg.KEY_WRITE ) as waptis:
        reg_setvalue(waptis,"DisplayName","WAPT %s" % version)
        reg_setvalue(waptis,"DisplayVersion","WAPT %s" % version)
        reg_setvalue(waptis,"InstallDate",currentdate())

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
    update_registry_version(control.version.split('-')[0])
    print('Upgrade done')

