# -*- coding: utf-8 -*-
from setuphelpers import *
import os
import _winreg
import tempfile
import shutil
import hashlib
import time
import pythoncom
from win32com.taskscheduler import taskscheduler

# registry key(s) where WAPT will find how to remove the application(s)
uninstallkey = []

import types,re
class Version(object):
    """Version object of form 0.0.0
        can compare with respect to natural numbering and not alphabetical

    >>> Version('0.10.2') > Version('0.2.5')
    True
    >>> Version('0.1.2') < Version('0.2.5')
    True
    >>> Version('0.1.2') == Version('0.1.2')
    True
    """

    def __init__(self,version,members_count=None):
        if version is None:
            version = ''
        assert isinstance(version,types.ModuleType) or isinstance(version,str) or isinstance(version,unicode) or isinstance(version,Version)
        if isinstance(version,types.ModuleType):
            self.versionstring = version.__version__
        elif isinstance(version,Version):
            self.versionstring = version.versionstring
        else:
            self.versionstring = version
        self.members = [ v.strip() for v in self.versionstring.split('.')]
        if members_count is not None:
            if len(self.members)<members_count:
                self.members.extend(['0'] * (members_count-len(self.members)))
            else:
                del self.members[members_count:]

    def __cmp__(self,aversion):
        def nat_cmp(a, b):
            a = a or ''
            b = b or ''

            def convert(text):
                if text.isdigit():
                    return int(text)
                else:
                    return text.lower()

            def alphanum_key(key):
                return [convert(c) for c in re.split('([0-9]+)', key)]

            return cmp(alphanum_key(a), alphanum_key(b))

        if not isinstance(aversion,Version):
            aversion = Version(aversion)
        for i in range(0,min([len(self.members),len(aversion.members)])):
            i1,i2  = self.members[i], aversion.members[i]
            v = nat_cmp(i1,i2)
            if v:
                return v
        return 0

    def __str__(self):
        return '.'.join(self.members)

    def __repr__(self):
        return "Version('{}')".format('.'.join(self.members))



def update_sources():
    files = [
         'common.py',
         'setuphelpers.py',
         'wapt-get.exe',
         'waptdeploy.exe',
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
         'version',
    ]

    def ignore(src,names):
        result = []
        for name in names:
            for pattern in ['*.pyc','*.exe']:
                if glob.fnmatch.fnmatch(name,pattern):
                    result.append(name)
        return result

    checkout_dir = os.getcwd()
    # cleanup patchs dir
    if os.path.exists(os.path.join(checkout_dir,'patchs')):
        shutil.rmtree(os.path.join(checkout_dir,'patchs'))

    os.makedirs(os.path.join(checkout_dir,'patchs'))
    for f in files:
        fn = os.path.join(WAPT.wapt_base_dir,f)
        target_fn = os.path.join(checkout_dir,'patchs',f)
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
        waptget = get_file_properties(makepath('patchs','wapt-get.exe'))
        rev = open(makepath('patchs','version')).read().strip()
        entry.package = '%s-waptupgrade' % WAPT.config.get('global','default_package_prefix')
        entry.version = '%s-%s' % (waptget['FileVersion'],rev)
    else:
        print(u'Keeping current control data %s (%s)'%(control.package,control.version))

def update_registry_version(version):
    # updatethe registry
    with _winreg.CreateKeyEx(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WAPT_is1',\
            0, _winreg.KEY_READ| _winreg.KEY_WRITE ) as waptis:
        reg_setvalue(waptis,"DisplayName","WAPT %s" % version)
        reg_setvalue(waptis,"DisplayVersion","%s" % version)
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



def sha1_for_file(fname, block_size=2**20):
    f = open(fname,'rb')
    sha1 = hashlib.sha1()
    while True:
        data = f.read(block_size)
        if not data:
            break
        sha1.update(data)
    return sha1.hexdigest()


def sha256_for_file(fname, block_size=2**20):
    f = open(fname,'rb')
    sha256 = hashlib.sha256()
    while True:
        data = f.read(block_size)
        if not data:
            break
        sha256.update(data)
    return sha256.hexdigest()


def download_waptagent(waptagent_path,expected_sha256):
    if WAPT.repositories:
        for r in WAPT.repositories:
            try:
                waptagent_url = "%s/waptagent.exe" % r.repo_url
                print('Trying %s'%waptagent_url)
                print wget(waptagent_url,waptagent_path)
                wapt_agent_sha256 =  sha256_for_file(waptagent_path)
                # eefac39c40fdb2feb4aa920727a43d48817eb4df   waptagent.exe
                if expected_sha256 != wapt_agent_sha256:
                    print('Error : bad  SHA256 for the downloaded waptagent.exe\n Expected : %s \n Found : %s '%(expected_sha256,wapt_agent_sha256))
                    continue
                return waptagent_url
            except Exception as e:
                print('Error when trying %s: %s'%(r.name,e))
        error('No proper waptagent downlaoded')
    error('No repository found for the download of waptagent.exe')


def create_onetime_task(name,cmd,parameters, delay_minutes=2,max_runtime=10, retry_count=3,retry_delay_minutes=1):
    """creates a one time Windows scheduled task and activate it.
    """
    ts = pythoncom.CoCreateInstance(taskscheduler.CLSID_CTaskScheduler,None,
                                    pythoncom.CLSCTX_INPROC_SERVER,
                                    taskscheduler.IID_ITaskScheduler)

    if task_exists(name):
        delete_task(name)

    task = ts.NewWorkItem(name)
    task.SetApplicationName(cmd)
    task.SetParameters(parameters)
    task.SetAccountInformation('', None)
    if max_runtime:
        task.SetMaxRunTime(max_runtime * 60*1000)
    # not implemented...
    #task.SetErrorRetryCount(retry_count)
    #task.SetErrorRetryInterval(retry_delay_minutes)
    task.SetFlags(task.GetFlags() | taskscheduler.TASK_FLAG_DELETE_WHEN_DONE)
    ts.AddWorkItem(name, task)
    run_time = time.localtime(time.time() + delay_minutes*60)
    tr_ind, tr = task.CreateTrigger()
    tt = tr.GetTrigger()
    tt.Flags = 0
    tt.BeginYear = int(time.strftime('%Y', run_time))
    tt.BeginMonth = int(time.strftime('%m', run_time))
    tt.BeginDay = int(time.strftime('%d', run_time))
    tt.StartMinute = int(time.strftime('%M', run_time))
    tt.StartHour = int(time.strftime('%H', run_time))
    tt.TriggerType = int(taskscheduler.TASK_TIME_TRIGGER_ONCE)
    tr.SetTrigger(tt)
    pf = task.QueryInterface(pythoncom.IID_IPersistFile)
    pf.Save(None,1)
    #task.Run()
    task = ts.Activate(name)
    #exit_code, startup_error_code = task.GetExitCode()
    return task


def full_waptagent_install(min_version,at_startup=False):
    # get it from
    waptagent_path = makepath(tempfile.gettempdir(),'waptagent.exe')
    waptdeploy_path = makepath(tempfile.gettempdir(),'waptdeploy.exe')
    filecopyto(makepath('patchs','waptdeploy.exe'),waptdeploy_path)

    expected_sha256 = open('waptagent.sha256','r').read().splitlines()[0].split()[0]
    if isfile('waptagent.exe'):
        filecopyto('waptagent.exe',waptagent_path)
    if not isfile(waptagent_path) or sha256_for_file(waptagent_path) != expected_sha256:
        download_waptagent(waptagent_path,expected_sha256)
    #create_onetime_task('fullwaptupgrade',waptagent_path,'/VERYSILENT',delay_minutes=15)

    if at_startup or isrunning('waptexit.exe'):
        cmd = '%s --hash=%s --waptsetupurl=%s --wait=15 --temporary --min_version=%s' %(waptdeploy_path,expected_sha256,waptagent_path,min_version)
        if not at_startup:
            print('waptexit is running, scheduling a one time task at system startup with command %s'%cmd)
        # task at system startup
        try:
            run('schtasks /Create /RU SYSTEM /SC ONSTART /TN waptupgradetmp /TR "%s" /F /V1 /Z' % cmd)
        except:
            # windows xp doesn't support one time startup task /Z nor /F
            run_notfatal('schtasks /Delete /TN waptupgradetmp /F')
            run('schtasks /Create /RU SYSTEM /SC ONSTART /TN waptupgradetmp /TR "%s"' % cmd)
    else:
        # use embedded waptagent.exe, wait 15 minutes for other tasks to complete.
        create_onetime_task('fullwaptupgrade',waptdeploy_path,'--hash=%s --waptsetupurl=%s --wait=15 --temporary --min_version=%s'%(expected_sha256,waptagent_path,min_version),delay_minutes=1)


def install():
    # if you want to modify the keys depending on environment (win32/win64... params..)
    import common
    if installed_softwares(uninstallkey='WAPT Server_is1'):
        error('Wapt server installed on this host. Aborting')

    installed_wapt = installed_softwares(uninstallkey='WAPT_is1')
    if installed_wapt:
        installed_wapt_version = installed_wapt[0]['version'].replace('WAPT ','')
        if '-' in installed_wapt_version:
            (wapt_version,installed_packaging) = wapt_version.split('-')
            installed_packaging = int(installed_packaging)
        else:
            installed_packaging = 0
    else:
        print('WAPT current version can not be found in registry (key is "WAPT_is1") ...full upgrade')
        installed_wapt_version = '0.0.0'
        installed_packaging = 0

    # get upgrade package informations
    (package_wapt_version,package_packaging) = control.version.split('-')
    package_packaging = int(package_packaging)

    if Version(installed_wapt_version,4) > Version(package_wapt_version,4):
        print('Your current wapt (%s) is more recent than the upgrade package (%s). Skipping...'%(installed_wapt_version,control.version))
    elif Version(installed_wapt_version,4) < Version(package_wapt_version,4):
        print('Your current wapt version (%s) is too old to be upgraded, a full waptagent.exe install will be planned for %s'%(installed_wapt_version,time.ctime(time.time() + 1*60)))
        full_waptagent_install(str(Version(package_wapt_version,4)))
    else:
        print(u'Partial upgrade of WAPT client')
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
                create_onetime_task('waptrestart',tmp_bat.name)
        print(u'Upgrade done')

    #remove winshell in root waptdir
    for fn in glob.glob(makepath(WAPT.wapt_base_dir,'winshell.py*')):
        print(u'Removing old %s' % fn)
        remove_file(fn)

if __name__ == '__main__':
    pass
    #create_onetime_task('fullwaptupgrade','c:/tranquilit/wapt/waptupgrade/waptagent.exe','/VERYSILENT')
