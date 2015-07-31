# -*- coding: utf-8 -*-
from setuphelpers import *
import os
import _winreg
import tempfile
import shutil

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
         'windnsquery.py',
         'waptwua.py',
         'wapttray.exe',
         'waptexit.exe',
         'keyfinder.py',
         'COPYING.txt',
         'templates',
         'waptconsole.exe',
         'waptconsole.exe.manifest',
         'waptservice',
         'languages',
         'revision.txt',


         r'lib\site-packages\babel\__init__.py',
         r'lib\site-packages\babel\_compat.py',
         r'lib\site-packages\babel\core.py',
         r'lib\site-packages\babel\global.dat',
         r'lib\site-packages\babel\localtime',
         r'lib\site-packages\babel\plural.py',
         r'lib\site-packages\babel\localedata\en.dat',
         r'lib\site-packages\babel\localedata\fr.dat',
         r'lib\site-packages\babel\messages',
         r'lib\site-packages\babel\support.py',
         r'lib\site-packages\babel\compat.py',
         r'lib\site-packages\babel\dates.py',
         r'lib\site-packages\babel\localedata.py',
         r'lib\site-packages\babel\numbers.py',
         r'lib\site-packages\babel\util.py',

         r'lib\site-packages\flask_babel',
         r'lib\site-packages\pytz',
         r'lib\site-packages\speaklater',
         r'lib\site-packages\requests_kerberos_sspi',
         r'lib\site-packages\lib\site-packages\flask_kerberos_sspi.py',
         r'lib\site-packages\kerberos_sspi.py',
         r'lib\site-packages\wapt.pth',
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
    if os.path.exists(os.path.join(checkout_dir,'waptupgrade','patchs')):
        shutil.rmtree(os.path.join(checkout_dir,'waptupgrade','patchs'))

    os.makedirs(os.path.join(checkout_dir,'waptupgrade','patchs'))
    for f in files:
        fn = os.path.join(checkout_dir,f)
        target_fn = os.path.join(checkout_dir,'waptupgrade','patchs',f)
        if os.path.isfile(fn):
            if not os.path.exists(os.path.dirname(target_fn)):
                os.makedirs(os.path.dirname(target_fn))
            filecopyto(fn,target_fn)
        elif os.path.isdir(fn):
            copytree2(
                src=fn,
                dst=target_fn,
                onreplace = default_overwrite,
                ignore=ignore)
    return True

def update_control(entry):
    """Update package control file before build-upload"""
    if update_sources():
        waptget = get_file_properties(r'patchs\wapt-get.exe')
        rev = open('../version').read().strip()
        entry.package = '%s-waptupgrade' % WAPT.config.get('global','default_package_prefix')
        entry.version = '%s-%s' % (waptget['FileVersion'],rev)
    else:
        print(u'Keeping current control data %s (%s)'%(control.package,control.version))

def update_registry_version(version):
    # updatethe registry
    with _winreg.CreateKeyEx(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WAPT_is1',\
            0, _winreg.KEY_READ| _winreg.KEY_WRITE ) as waptis:
        reg_setvalue(waptis,"DisplayName","WAPT %s" % version)
        reg_setvalue(waptis,"DisplayVersion","WAPT %s" % version)
        reg_setvalue(waptis,"InstallDate",currentdate())



def copytree2(src, dst, ignore=None,onreplace=default_skip,oncopy=default_oncopy,enable_replace_at_reboot=True,onerror=None):
    """Copy src directory to dst directory. dst is created if it doesn't exists
        src can be relative to installation temporary dir
        oncopy is called for each file copy. if False is returned, copy is skipped
        onreplace is called when a file will be overwritten.
    """
    logger.debug('Copy tree from "%s" to "%s"' % (ensure_unicode(src),ensure_unicode(dst)))
    # path relative to temp directory...
    tempdir = os.getcwd()
    if not os.path.isdir(src) and os.path.isdir(os.path.join(tempdir,src)):
        src = os.path.join(tempdir,src)

    names = os.listdir(src)
    if callable(ignore) and ignore is not None:
        ignored_names = ignore(src, names)
    else:
        ignored_names = set()

    if not os.path.isdir(dst):
        if oncopy('create directory',src,dst):
            os.makedirs(dst)
    errors = []
    for name in names:
        if name in ignored_names:
            continue
        srcname = os.path.join(src, name)
        dstname = os.path.join(dst, name)
        try:
            if os.path.isdir(srcname):
                if oncopy('directory',srcname,dstname):
                    copytree2(srcname, dstname, ignore = ignore,onreplace=onreplace,oncopy=oncopy)
            else:
                if os.path.isfile(dstname):
                    if onreplace(srcname,dstname) and oncopy('overwrites',srcname,dstname):
                        os.unlink(dstname)
                        shutil.copy2(srcname, dstname)
                else:
                    if oncopy('copy',srcname,dstname):
                        shutil.copy2(srcname, dstname)

        except (IOError, os.error) as why:
            #print(u'IO Error copying from "%s" to "%s" : %s' % (ensure_unicode(src),ensure_unicode(dst),ensure_unicode(why)))
            if onerror is not None and callable(onerror):
                try:
                    onerror(srcname,dstname,why)
                except Exception as e:
                    errors.append((srcname,dstname,ensure_unicode(e)))
            else:
                errors.append((srcname,dstname,ensure_unicode(why)))

        # catch the Error from the recursive copytree so that we can
        # continue with other files
        except shutil.Error as err:
            logger.critical(u'shutil Error copying from "%s" to "%s" : %s' % (ensure_unicode(srcname),ensure_unicode(dstname),ensure_unicode(err)))
            errors.extend(err.args[0])
    try:
        shutil.copystat(src, dst)
    except OSError, why:
        if WindowsError is not None and isinstance(why, WindowsError):
            # Copying file access times may fail on Windows
            pass
        else:
            print(u'Error copying stats from "%s" to "%s" : %s' % (ensure_unicode(src),ensure_unicode(dst),ensure_unicode(why)))
            errors.append((src, dst, str(why)))
    if errors:
        raise shutil.Error, errors



def add_at_cmd(cmd,delay=1):
    import datetime
    at_time = (datetime.datetime.now() + datetime.timedelta(minutes=delay)).strftime('%H:%M:%S')
    print(run('at %s "%s"'%(at_time,cmd)))


def install():
    # if you want to modify the keys depending on environment (win32/win64... params..)
    print(u'Partial upgrade of WAPT  client')
    killalltasks('wapttray.exe')
    killalltasks('waptconsole.exe')

    def onerror(srcname,dstname,e):
        print u"Error %s %s %s" %(srcname,dstname,ensure_unicode(e))
        if e[0] == 5:   # locked
            filecopyto(srcname,dstname+'.pending')
            replace_at_next_reboot(None, dstname)
        else:
            raise e

    def check_exe_version(src,dst):
        if os.path.splitext(dst)[1] in ('.exe','.dll'):
            try:
                ov = get_file_properties(dst)['FileVersion']
                nv = get_file_properties(src)['FileVersion']
                return Version(ov)<Version(nv)
            except:
                return True
        else:
            return True

    copytree2('patchs',WAPT.wapt_base_dir,
        onreplace = check_exe_version,
        onerror = onerror)

    update_registry_version(control.version)

    # restart of service can not be done by service...
    if service_installed('waptservice') and service_is_running('waptservice'):
        import requests,json
        try:
            res = json.loads(requests.get('http://127.0.0.1:8088/waptservicerestart.json').text)
        except:
            tmp_bat = tempfile.NamedTemporaryFile(prefix='waptrestart',suffix='.cmd',mode='wt',delete=False)
            tmp_bat.write('net stop waptservice\n')
            tmp_bat.write('net start waptservice\n')
            tmp_bat.write('del "%s"\n'%tmp_bat.name)
            tmp_bat.close()
            add_at_cmd(tmp_bat.name)
    print(u'Upgrade done')

