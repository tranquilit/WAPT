#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013  Tranquil IT Systems http://www.tranquil.it
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users PC.
#
#    WAPT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    WAPT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with WAPT.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------

__version__ = "0.3.3"

from winshell import *
import os
import sys
import logging
import urllib,urllib2
import tempfile
import shutil
import subprocess
import win32api
import win32con
import win32pdhutil
import win32net
import msilib
import win32service
import win32serviceutil
import glob

import _winreg
import platform

logger = logging.getLogger()

# ensure there is a tempdir available for local work. This is deleted at program exit.
if not 'tempdir' in globals():
    tempdir = tempfile.mkdtemp()
    logger.info('Temporary directory created : %s' % tempdir)

import atexit
@atexit.register
def cleanuptemp():
    if 'tempdir' in globals():
        logger.debug('Removing temporary directory : %s' % tempdir)
        shutil.rmtree(tempdir)

# Temporary dir where to unzip/get all files for setup
# helper assumes files go and comes here per default
if not 'packagetempdir' in globals():
    packagetempdir = tempdir

def ensure_dir(f):
    """Be sure the directory of f exists on disk. Make it if not"""
    d = os.path.dirname(f)
    if not os.path.isdir(d):
        os.makedirs(d)

def create_shortcut(path, target='', wDir='', icon=''):
    ext = path[-3:]
    if ext == 'url':
        shortcut = file(path, 'w')
        shortcut.write('[InternetShortcut]\n')
        shortcut.write('URL=%s' % target)
        shortcut.close()
    else:
        CreateShortcut(path,target,'',wDir,(icon,0),'')

def create_desktop_shortcut(label, target='', wDir='', icon=''):
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    create_shortcut(os.path.join(desktop(1),label),target,wDir,icon)

def create_programs_menu_shortcut(label, target='', wDir='', icon=''):
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    sc = os.path.join(start_menu(1),label)
    if os.path.isfile(sc):
        os.remove(sc)
    create_shortcut(sc,target,wDir,icon)

def wgets(url):
    """Return the content of a remote resources as a String"""
    return urllib2.urlopen(url).read()

class WaptURLopener(urllib.FancyURLopener):
  def http_error_default(self, url, fp, errcode, errmsg, headers):
    raise urllib2.HTTPError(url,errcode,errmsg,headers,fp)

last_progress_display = 0

def wget(url,target,reporthook=None):
    """Copy the contents of a file from a given URL
    to a local file.
    """
    def report(bcount,bsize,total):
        global last_progress_display

        if total>0 and bsize>0:
            if bcount * bsize * 100 / total - last_progress_display >= 10:
                print '%i / %i (%.0f%%)\r' % (bcount*bsize,total,100.0*bcount*bsize/total),
                last_progress_display = bcount * bsize * 100 / total

    if os.path.isdir(target):
        target = os.path.join(target,'')

    (dir,filename) = os.path.split(target)
    if not filename:
        filename = url.split('/')[-1]
    if not dir:
        dir = tempdir

    if not os.path.isdir(dir):
        os.makedirs(dir)

    global last_progress_display
    last_progress_display = 0
    (localpath,headers) = WaptURLopener().retrieve(url,os.path.join(dir,filename),reporthook or report)
    print "download %s finished" % url
    return os.path.join(dir,filename)

def filecopyto(filename,target):
    """Copy file from package temporary directory to target directory
        target is either a full filename or a directory name
        if filename is .exe or .dll, logger prints version numbers"""
    (dir,fn) = os.path.split(filename)
    if not dir:
        dir = tempdir

    if os.path.isdir(target):
        target = os.path.join(target,os.path.basename(filename))
    if os.path.isfile(target):
        if os.path.splitext(target)[1] in ('.exe','.dll'):
            ov = get_file_properties(target)['FileVersion']
            nv = get_file_properties(filename)['FileVersion']
            logger.info('Replacing %s (%s) -> %s' % (target,ov,nv))
        else:
            logger.info('Replacing %s' % target)
    else:
        if os.path.splitext(target)[1] in ('.exe','.dll'):
            nv = get_file_properties(filename)['FileVersion']
            logger.info('Copying %s (%s)' % (target,nv))
        else:
            logger.info('Copying %s' % (target))
    shutil.copy(filename,target)

def copytree2(src, dst, symlinks=False, ignore=None,onreplace=None):
    """Copy src dir to dst directory. dst is created if it doesn't exists
        overwrites existing files on target
    """
    # path relative to temp directory...
    if not os.path.isdir(src) and os.path.isdir(os.path.join(tempdir,src)):
        src = os.path.join(tempdir,src)

    names = os.listdir(src)
    if ignore is not None:
        ignored_names = ignore(src, names)
    else:
        ignored_names = set()

    logger.info('Copy tree from %s to %s' % (src,dst))
    if not os.path.isdir(dst):
        logger.info('  create target dir  : %s' % dst)
        os.makedirs(dst)
    errors = []
    skipped = []
    for name in names:
        if name in ignored_names:
            continue
        srcname = os.path.join(src, name)
        dstname = os.path.join(dst, name)
        try:
            if symlinks and os.path.islink(srcname):
                linkto = os.readlink(srcname)
                os.symlink(linkto, dstname)
            elif os.path.isdir(srcname):
                copytree2(srcname, dstname, symlinks, ignore)
            else:
                if os.path.isfile(dstname):
                    logger.info(' overwrites %s' % dstname)
                    os.unlink(dstname)
                else:
                    logger.info(' copy %s' % dstname)
                shutil.copy2(srcname, dstname)
        except (IOError, os.error), why:
            errors.append((srcname, dstname, str(why)))
        # catch the Error from the recursive copytree so that we can
        # continue with other files
        except Error, err:
            errors.extend(err.args[0])
    try:
        copystat(src, dst)
    except WindowsError:
        # can't copy file access times on Windows
        pass
    except OSError, why:
        errors.extend((src, dst, str(why)))
    if errors:
        raise Error(errors)



def run(*cmd):
    """Runs the command and wait for it termination
    returns output, raise exc eption if exitcode is not null"""
    print 'Run "%s"' % (cmd,)
    return subprocess.check_output(*cmd,shell=True)

def run_notfatal(*cmd):
    """Runs the command and wait for it termination
    returns output, don't raise exception if exitcode is not null but return '' """
    try:
        print 'Run "%s"' % (cmd,)
        return subprocess.check_output(*cmd,shell=True)
    except Exception,e:
        print 'Warning : %s' % e
        return ''

def shell_launch(cmd):
    """Launch a command (without arguments) but doesn't wait for its termination"""
    os.startfile(cmd)

def isrunning(processname):
    try:
        return len(win32pdhutil.FindPerformanceAttributesByName( processname ))> 0
    except:
        return False

def killalltasks(*exenames):
    for c in exenames:
      run_notfatal('taskkill /t /im "%s" /f' % c)

def messagebox(title,msg):
    win32api.MessageBox(0, msg, title, win32con.MB_ICONINFORMATION)

def showmessage(msg):
    win32api.MessageBox(0, msg, 'Information', win32con.MB_ICONINFORMATION)

def programfiles64():
    """Return 64 bits program folder"""
    if 'PROGRAMW6432' in os.environ :
        return os.environ['PROGRAMW6432']
    else:
        return os.environ['PROGRAMFILES']

def programfiles():
    """Return native program directory, ie C:\Program Files for both 64 and 32 bits"""
    #return get_path(shellcon.CSIDL_PROGRAM_FILES)
    if 'PROGRAMW6432' in os.environ:
        return os.environ['PROGRAMW6432']
    else:
        return os.environ['PROGRAMFILES']

def programfiles32():
    """Return 32bits applications folder."""
    if 'PROGRAMW6432' in os.environ and 'PROGRAMFILES(X86)' in os.environ:
        return os.environ['PROGRAMFILES(X86)']
    else:
        return os.environ['PROGRAMFILES']

def iswin64():
    return 'PROGRAMW6432' in os.environ

def getcomputername():
    return socket.gethostname()

def getloggedinusers():
    return []

def _environ_params(dict_or_module={}):
    """set some environment params in the supplied module or dict"""
    if type(dict_or_module) is dict:
        params_dict = dict_or_module
    else:
        params_dict = {}

    params_dict['programfiles32'] = programfiles32()
    params_dict['programfiles64'] = programfiles64()
    params_dict['programfiles'] = programfiles()
    params_dict['domainname'] = get_domain_fromregistry()
    params_dict['computername'] = os.environ['COMPUTERNAME']
    from types import ModuleType
    if type(dict_or_module) is ModuleType:
        for k,v in params_dict.items():
            setattr(dict_or_module,k,v)
    return params_dict

###########
def reg_getvalue(key,name,default=None):
    try:
        return _winreg.QueryValueEx(key,name)[0]
    except WindowsError,e:
        if e.errno in(259,2):
            # WindowsError: [Errno 259] No more data is available
            # WindowsError: [Error 2] Le fichier spécifié est introuvable
            return default
        else:
            raise


def reg_setvalue(key,name,value,type=_winreg.REG_SZ ):
    return _winreg.SetValueEx(key,name,0,type,value)

def reg_openkey_noredir(key, sub_key, sam=_winreg.KEY_READ,create_if_missing=False):
    try:
        if platform.machine() == 'AMD64':
            return _winreg.OpenKey(key,sub_key,0, sam | _winreg.KEY_WOW64_64KEY)
        else:
            return _winreg.OpenKey(key,sub_key,0,sam)
    except WindowsError,e:
        if e.errno == 2:
            if create_if_missing:
                if platform.machine() == 'AMD64':
                    return _winreg.CreateKeyEx(key,sub_key,0, sam | _winreg.KEY_WOW64_64KEY | _winreg.KEY_WRITE )
                else:
                    return _winreg.CreateKeyEx(key,sub_key,0,sam | _winreg.KEY_WRITE )
            else:
                raise WindowsError(e.errno,'The key %s can not be opened' % sub_key)


def installed_softwares(keywords=''):
    """return list of installed software from registry (both 32bit and 64bit"""
    def check_words(target,words):
        mywords = target.lower()
        result = not words or mywords
        for w in words:
            result = result and w in mywords
        return result

    def list_fromkey(uninstall):
        result = []
        key = reg_openkey_noredir(_winreg.HKEY_LOCAL_MACHINE,uninstall)
        mykeywords = keywords.lower().split()
        i = 0
        while True:
            try:
                subkey = _winreg.EnumKey(key, i).decode('iso8859')
                appkey = reg_openkey_noredir(_winreg.HKEY_LOCAL_MACHINE,"%s\\%s" % (uninstall,subkey.encode('iso8859')))
                display_name = reg_getvalue(appkey,'DisplayName','')
                display_version = reg_getvalue(appkey,'DisplayVersion','')
                install_date = reg_getvalue(appkey,'InstallDate','')
                install_location = reg_getvalue(appkey,'InstallLocation','')
                uninstallstring = reg_getvalue(appkey,'UninstallString','')
                publisher = reg_getvalue(appkey,'Publisher','')
                if display_name and check_words(subkey+' '+display_name+' '+publisher,mykeywords):
                    result.append({'key':subkey,
                        'name':display_name,'version':display_version,
                        'install_date':install_date,'install_location':install_location,
                        'uninstallstring':uninstallstring,'publisher':publisher,})
                i += 1
            except WindowsError,e:
                # WindowsError: [Errno 259] No more data is available
                if e.winerror == 259:
                    break
                else:
                    raise
        return result
    result = list_fromkey("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
    if platform.machine() == 'AMD64':
        result.extend(list_fromkey("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"))
    return result

def currentdate():
    import time
    return time.strftime('%Y%m%d')

def currentdatetime():
    import time
    return time.strftime('%Y%m%d-%H%M%S')

def register_uninstall(uninstallkey,uninstallstring,win64app=False,
        quiet_uninstall_string='',
        install_location = None, display_name=None,display_version=None,publisher=''):
    if iswin64() and not win64app:
        root = "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    else:
        root = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    appkey = reg_openkey_noredir(_winreg.HKEY_LOCAL_MACHINE,"%s\\%s" % (root,uninstallkey.encode('iso8859')),
        sam=_winreg.KEY_ALL_ACCESS,create_if_missing=True)
    reg_setvalue(appkey,'UninstallString',uninstallstring)
    reg_setvalue(appkey,'install_date',currentdate())
    if quiet_uninstall_string:
        reg_setvalue(appkey,'QuietUninstallString',quiet_uninstall_string)
    if display_name:
        reg_setvalue(appkey,'DisplayName',display_name)
    if display_version:
        reg_setvalue(appkey,'DisplayVersion',display_version)
    if install_location:
        reg_setvalue(appkey,'InstallLocation',install_location)
    if publisher:
        reg_setvalue(appkey,'Publisher',publisher)

def unregister_uninstall(uninstallkey):
    pass

def host_info():
    info = {}
    info['waptgetversion'] = ""
    info['computername'] =  getcomputername()
    info['dnsdomain'] = get_domain_fromregistry()
    info['workgroupname'] = ""
    info['biosinfo'] = ""
    info['biosdate'] = "2012-08-15T00:00:00,0+01:00"
    info['wmibiosinfo']= {
        'SerialNumber': "",
        'Manufacturer': ""}
    info['macaddresses'] =[]
    info['processorcount'] = 1
    info['ipaddresses'] = []
    info['physicalmemory'] = 0
    info['virtualmemory'] = 0
    info['systemmanufacturer'] = ""
    info['biosversion'] = ""
    info['systemproductname'] = "",
    info['cpuname'] = "Intel(R) Core(TM) i5-2520M CPU @ 2.50GHz"
    return info


# from http://stackoverflow.com/questions/580924/python-windows-file-version-attribute
def get_file_properties(fname):
#==============================================================================
    """
    Read all properties of the given file return them as a dictionary.
    """
    propNames = ('Comments', 'InternalName', 'ProductName',
        'CompanyName', 'LegalCopyright', 'ProductVersion',
        'FileDescription', 'LegalTrademarks', 'PrivateBuild',
        'FileVersion', 'OriginalFilename', 'SpecialBuild')
    props = {}
    for propName in propNames:
        props[propName] = ''

    try:
        # backslash as parm returns dictionary of numeric info corresponding to VS_FIXEDFILEINFO struc
        fixedInfo = win32api.GetFileVersionInfo(fname, '\\')
        props['FileVersion'] = "%d.%d.%d.%d" % (fixedInfo['FileVersionMS'] / 65536,
                fixedInfo['FileVersionMS'] % 65536, fixedInfo['FileVersionLS'] / 65536,
                fixedInfo['FileVersionLS'] % 65536)

        # \VarFileInfo\Translation returns list of available (language, codepage)
        # pairs that can be used to retreive string info. We are using only the first pair.
        lang, codepage = win32api.GetFileVersionInfo(fname, '\\VarFileInfo\\Translation')[0]

        # any other must be of the form \StringfileInfo\%04X%04X\parm_name, middle
        # two are language/codepage pair returned from above

        for propName in propNames:
            strInfoPath = u'\\StringFileInfo\\%04X%04X\\%s' % (lang, codepage, propName)
            ## print str_info
            props[propName] = (win32api.GetFileVersionInfo(fname, strInfoPath) or '').strip()

    except Exception,e:
        logger.warning("%s" % e)

    return props

# from http://stackoverflow.com/questions/3157955/get-msi-product-name-version-from-command-line
def get_msi_properties(msi_filename):
    db = msilib.OpenDatabase(msi_filename, msilib.MSIDBOPEN_READONLY)
    view = db.OpenView ("SELECT * FROM Property")
    view.Execute(None)
    result = {}
    r = view.Fetch()
    while r:
        try:
            result[r.GetString(1)] = r.GetString(2)
        except:
            print"erreur pour %s" % r.GetString(0)
        try:
            r = view.Fetch()
        except:
            break
    return result

get_computer_name = win32api.GetComputerName
get_domain_name = win32api.GetDomainName

# some const
programfiles = programfiles()
programfiles32 = programfiles32()
programfiles64 = programfiles64()

makepath = os.path.join

def service_installed(service_name):
    try:
        service_is_running(service_name)
        return True
    except win32service.error,e :
         if e.winerror == 1060:
            return False
         else:
            raise

def service_start(service_name):
    win32serviceutil.StartService(service_name)
    return win32serviceutil.WaitForServiceStatus(service_name, win32service.SERVICE_RUNNING, waitSecs=4)

def service_stop(service_name):
    win32serviceutil.StopService(service_name)
    #
    win32api.Sleep(1000)
    return win32serviceutil.WaitForServiceStatus(service_name, win32service.SERVICE_STOPPED, waitSecs=4)

def service_is_running(service_name):
    return win32serviceutil.QueryServiceStatus(service_name)[1] == win32service.SERVICE_RUNNING

# to help pyscripter code completion in setup.py
params = {}
"""Specific parameters for install scripts"""

if __name__=='__main__':
    assert isrunning('explorer')
    assert service_installed('waptservice')
    if not service_is_running('waptservice'):
        service_start('waptservice')
    assert service_is_running('waptservice')
    service_stop('waptservice')
    assert not service_is_running('waptservice')
    service_start('waptservice')
    assert not service_installed('wapt')
    assert get_computer_name() <> ''
    #print getloggedinusers()
    assert get_domain_name() <> ''
    assert get_msi_properties(glob.glob('C:\\Windows\\Installer\\*.msi')[0])['Manufacturer'] <> ''
    assert installed_softwares('offi')[0]['uninstallstring'] <> ''
    assert get_file_properties('c:\\wapt\\waptservice.exe')['FileVersion'] <>''
    assert get_file_properties('c:\\wapt\\wapt-get.exe')['FileVersion'] <> ''