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

__version__ = "0.4.8"

import os
import sys
import logging
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
import ctypes

import requests
import time
import socket

import _winreg
import platform
import winshell
from win32com.shell import shell, shellcon

from iniparse import RawConfigParser

logger = logging.getLogger()

# ensure there is a tempdir available for local work. This is deleted at program exit.
#if not 'tempdir' in globals():
#    tempdir = tempfile.mkdtemp()
#    logger.info('Temporary directory created : %s' % tempdir)

#import atexit
#@atexit.register
#def cleanuptemp():
#    if 'tempdir' in globals():
#        logger.debug('Removing temporary directory : %s' % tempdir)
#        shutil.rmtree(tempdir)

# Temporary dir where to unzip/get all files for setup
# helper assumes files go and comes here per default
#if not 'packagetempdir' in globals():
#   packagetempdir = tempdir

# common windows diectories
desktop = winshell.desktop
application_data = winshell.application_data
bookmarks = winshell.bookmarks
start_menu = winshell.start_menu
programs = winshell.programs
startup = winshell.startup
my_documents= winshell.my_documents
recent = winshell.recent
sendto = winshell.sendto

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
        winshell.CreateShortcut(path,target,'',wDir,(icon,0),'')

def create_desktop_shortcut(label, target='', wDir='', icon=''):
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    sc_path = os.path.join(desktop(1),label)
    if os.path.isfile(sc_path):
        os.remove(sc_path)
    create_shortcut(sc_path,target,wDir,icon)
    return sc_path


def create_user_desktop_shortcut(label, target='', wDir='', icon=''):
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    sc_path = os.path.join(desktop(0),label)
    if os.path.isfile(sc_path):
        os.remove(sc_path)
    create_shortcut(sc_path,target,wDir,icon)
    return sc_path

def create_programs_menu_shortcut(label, target='', wDir='', icon=''):
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    sc = os.path.join(start_menu(1),label)
    if os.path.isfile(sc):
        os.remove(sc)
    create_shortcut(sc,target,wDir,icon)
    return sc

def create_user_programs_menu_shortcut(label, target='', wDir='', icon=''):
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    sc = os.path.join(start_menu(0),label)
    if os.path.isfile(sc):
        os.remove(sc)
    create_shortcut(sc,target,wDir,icon)
    return sc

def wgets(url,proxies=None):
    """Return the content of a remote resources as a String"""
    r = requests.get(url,proxies=proxies)
    if r.ok:
        return r.text
    else:
        r.raise_for_status()

last_time_display = 0

def wget(url,target,reporthook=None,proxies=None):
    """Copy the contents of a file from a given URL
    to a local file.
    """
    def report(bcount,bsize,total):
        global last_time_display
        if total>0 and bsize>0:
            # print only every second or at end
            if (time.time()-last_time_display>=.1) or (bcount*bsize>=total) :
                print '%i / %i (%.0f%%) (%.0f KB/s)\r' % (bcount*bsize,total,100.0*bcount*bsize/total, bsize/(1024*(time.time()-last_time_display))),
                last_time_display = time.time()

    if os.path.isdir(target):
        target = os.path.join(target,'')

    (dir,filename) = os.path.split(target)
    if not filename:
        filename = url.split('/')[-1]
    if not dir:
        dir = os.getcwd()

    if not os.path.isdir(dir):
        os.makedirs(dir)

    global last_progress_display
    last_progress_display = 0
    start_time = time.time()
    r = requests.get(url,stream=True, proxies=proxies)

    total_bytes = int(r.headers['content-length'])
    chunk_size = max([total_bytes/100,1000])
    print "Downloading %s (%.1f Mb)" % (url,int(total_bytes)/1024/1024)

    output_file = open(os.path.join(dir,filename),'wb')
    try:
        if not reporthook:
            reporthook = report
        reporthook(0,chunk_size,total_bytes)
        cnt = 0
        if r.ok:
            for chunk in r.iter_content(chunk_size=chunk_size):
                output_file.write(chunk)
                reporthook(cnt,len(chunk),total_bytes)
                cnt +=1
            reporthook(total_bytes/chunk_size,chunk_size,total_bytes)

        else:
            r.raise_for_status()
    finally:
        output_file.close()

    #(localpath,headers) = WaptURLopener(proxies=proxies).retrieve(url=url, filename=os.path.join(dir,filename),reporthook=reporthook or report,)
    print "  -> download finished (%.0f Kb/s)" % (total_bytes/(1024*(time.time()-start_time)))
    return os.path.join(dir,filename)

def filecopyto(filename,target):
    """Copy file from package temporary directory to target directory
        target is either a full filename or a directory name
        if filename is .exe or .dll, logger prints version numbers"""
    (dir,fn) = os.path.split(filename)
    if not dir:
        dir = os.getcwd()

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


# Copy of an entire tree from install temp directory to target
def default_oncopy(msg,src,dst):
    print(u'%s : "%s" to "%s"' % (msg,src,dst))
    return True

def default_skip(src,dst):
    return False

def default_overwrite(src,dst):
    return True

def default_overwrite_older(src,dst):
    if os.stat(src).st_mtime <= os.stat(dst).st_mtime:
        logger.debug(u'Skipping, file on target is newer than source: "%s"' % (dst,))
        return False
    else:
        logger.debug(u'Overwriting file on target is older than source: "%s"' % (dst,))
        return True

def register_ext(appname,fileext,shellopen,icon=None,otherverbs=[]):
    """Associates a file extension with an application, and command to open it"""
    def setvalue(key,path,value):
        rootpath = os.path.dirname(path)
        name = os.path.basename(path)
        k = reg_openkey_noredir(key,path,sam=KEY_READ | KEY_WRITE,create_if_missing=True)
        if value<>None:
            reg_setvalue(k,'',value)
    filetype = appname+fileext
    setvalue(HKEY_CLASSES_ROOT,fileext,filetype)
    setvalue(HKEY_CLASSES_ROOT,filetype,appname+ " file")
    if icon:
        setvalue(HKEY_CLASSES_ROOT,makepath(filetype,"DefaultIcon"),icon)
    setvalue(HKEY_CLASSES_ROOT,makepath(filetype,"shell"),'')
    setvalue(HKEY_CLASSES_ROOT,makepath(filetype,"shell","open"),'')
    setvalue(HKEY_CLASSES_ROOT,makepath(filetype,"shell","open","command"),shellopen)
    if otherverbs:
        for (verb,cmd) in otherverbs:
            setvalue(HKEY_CLASSES_ROOT,makepath(filetype,"shell",verb),'')
            setvalue(HKEY_CLASSES_ROOT,makepath(filetype,"shell",verb,"command"),cmd)

def copytree2(src, dst, ignore=None,onreplace=default_skip,oncopy=default_oncopy):
    """Copy src directory to dst directory. dst is created if it doesn't exists
        src can be relative to installation temporary dir
        oncopy is called for each file copy. if False is returned, copy is skipped
        onreplace is called when a file will be overwritten.
    """
    # path relative to temp directory...
    tempdir = os.getcwd()
    if not os.path.isdir(src) and os.path.isdir(os.path.join(tempdir,src)):
        src = os.path.join(tempdir,src)

    names = os.listdir(src)
    if ignore is not None:
        ignored_names = ignore(src, names)
    else:
        ignored_names = set()

    if not os.path.isdir(dst):
        if oncopy('create directory',src,dst):
            os.makedirs(dst)
    errors = []
    skipped = []
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
        except (IOError, os.error), why:
            errors.append((srcname, dstname, str(why)))
        # catch the Error from the recursive copytree so that we can
        # continue with other files
        except Error, err:
            errors.extend(err.args[0])
    try:
        shutil.copystat(src, dst)
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
        return len(win32pdhutil.FindPerformanceAttributesByName( processname,bRefresh=1 ))> 0
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

def get_computername():
    """Return host name (without domain part)"""
    return socket.gethostname()

def get_hostname():
    """Return host fully qualified domain name"""
    return socket.getfqdn().lower()


def get_domain_fromregistry():
    """Return main DNS domain of the computer"""
    key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters")
    try:
        (domain,atype) = _winreg.QueryValueEx(key,'DhcpDomain')
    except:
        (domain,atype) = _winreg.QueryValueEx(key,'Domain')
    return domain

def get_loggedinusers():
    raise NotImplementedError()
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
                    return _winreg.CreateKeyEx(key,sub_key,0, sam | _winreg.KEY_READ| _winreg.KEY_WOW64_64KEY | _winreg.KEY_WRITE )
                else:
                    return _winreg.CreateKeyEx(key,sub_key,0,sam | _winreg.KEY_READ | _winreg.KEY_WRITE )
            else:
                raise WindowsError(e.errno,'The key %s can not be opened' % sub_key)
HKEY_CLASSES_ROOT = _winreg.HKEY_CLASSES_ROOT
HKEY_CURRENT_USER = _winreg.HKEY_CURRENT_USER
HKEY_LOCAL_MACHINE = _winreg.HKEY_LOCAL_MACHINE
HKEY_USERS = _winreg.HKEY_USERS
HKEY_CURRENT_CONFIG = _winreg.HKEY_CURRENT_CONFIG

KEY_WRITE = _winreg.KEY_WRITE
KEY_READ = _winreg.KEY_READ

REG_SZ = _winreg.REG_SZ
REG_MULTI_SZ = _winreg.REG_MULTI_SZ
REG_DWORD = _winreg.REG_DWORD
REG_EXPAND_SZ = _winreg.REG_EXPAND_SZ

def registry_readstring(root,path,keyname,default=''):
    """Get a string from registry given root (HKLM..) a path and a keyname
    the path can be either with backslash or slash"""
    path = path.replace(u'/',u'\\')
    key = reg_openkey_noredir(root,path)
    try:
        result = reg_getvalue(key,keyname,default)
        return result
    except:
        return default

def inifile_readstring(inifilename,section,key,default=''):
    """Read a string parameter from inifile"""
    inifile = RawConfigParser()
    inifile.read(inifilename)
    if inifile.has_section(section) and inifile.has_option(section,key):
        return inifile.get(section,key)
    else:
        return default


def inifile_writestring(inifilename,section,key,value):
    """Write a string parameter to inifile"""
    inifile = RawConfigParser()
    inifile.read(inifilename)
    inifile.set(section,key,value)
    inifile.write(open(inifilename,'w'))



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
                        'uninstall_string':uninstallstring,'publisher':publisher,})
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
    """Register the uninstall method in Windows registry,
        so that the application is displayed in Cntrol Panel / Programs and features"""
    if not uninstallkey:
        raise Exception('No uninstall key provided')
    if not uninstallstring:
        raise Exception('No uninstallstring provided')
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
    else:
        reg_setvalue(appkey,'QuietUninstallString',uninstallstring)
    if display_name:
        reg_setvalue(appkey,'DisplayName',display_name)
    if display_version:
        reg_setvalue(appkey,'DisplayVersion',display_version)
    if install_location:
        reg_setvalue(appkey,'InstallLocation',install_location)
    if publisher:
        reg_setvalue(appkey,'Publisher',publisher)

def unregister_uninstall(uninstallkey,win64app=False):
    """Remove uninstall method from registry"""
    if not uninstallkey:
        raise Exception('No uninstall key provided')
    if iswin64():
        if not win64app:
            root = "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"+uninstallkey
        else:
            root = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"+uninstallkey
        #key = reg_openkey_noredir(_winreg.HKEY_LOCAL_MACHINE,root)
        _winreg.DeleteKeyEx(_winreg.HKEY_LOCAL_MACHINE,root.encode('iso8859'))
    else:
        root = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"+uninstallkey
        _winreg.DeleteKey(_winreg.HKEY_LOCAL_MACHINE,root.encode('iso8859'))

wincomputername = win32api.GetComputerName
windomainname = win32api.GetDomainName

def host_info():
    info = {}

    info['computer_name'] =  wincomputername()
    info['computer_fqdn'] =  get_hostname()
    info['dns_domain'] = get_domain_fromregistry()
    info['workgroup_name'] = windomainname()
    info['mac_addresses'] =[]
    info['ip_addresses'] = []
    info['cpu_name'] = ""
    info['cpu_count'] = 1
    info['physical_memory'] = 0
    info['virtual_memory'] = 0
    info['system_manufacturer'] = ""
    info['system_productname'] = "",
    info['win64'] = iswin64(),

    info['wmi'] = {}
    try:
        import wmi
        wm = wmi.WMI()
        info['wmi']['Win32_ComputerSystem'] = {}
        cs = wm.Win32_ComputerSystem()[0]
        for k in cs.properties.keys():
            prop = cs.wmi_property(k)
            if prop:
                info['wmi']['Win32_ComputerSystem'][k] = prop.Value
        info['wmi']['Win32_ComputerSystemProduct'] = {}
        cs = wm.Win32_ComputerSystemProduct()[0]
        for k in cs.properties.keys():
            prop = cs.wmi_property(k)
            if prop:
                info['wmi']['Win32_ComputerSystemProduct'][k] = prop.Value
        info['wmi']['Win32_BIOS'] = {}
        cs = wm.Win32_BIOS()[0]
        for k in cs.properties.keys():
            prop = cs.wmi_property(k)
            if prop:
                info['wmi']['Win32_BIOS'][k] = prop.Value
        info['wmi']['Win32_BaseBoard'] = {}
        cs = wm.Win32_BaseBoard()[0]
        for k in cs.properties.keys():
            prop = cs.wmi_property(k)
            if prop:
                info['wmi']['Win32_BaseBoard'][k] = prop.Value
        na = info['wmi']['Win32_NetworkAdapter'] = []
        for cs in wm.Win32_NetworkAdapter():
            na.append({})
            for k in cs.properties.keys():
                prop = cs.wmi_property(k)
                if prop:
                    na[-1][k] = prop.Value

    except:
        raise

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

# some const
programfiles = programfiles()
programfiles32 = programfiles32()
programfiles64 = programfiles64()

makepath = os.path.join

def service_installed(service_name):
    """Return True if the service is installed"""
    try:
        service_is_running(service_name)
        return True
    except win32service.error,e :
         if e.winerror == 1060:
            return False
         else:
            raise

def service_start(service_name):
    """Start a service by its service name"""
    win32serviceutil.StartService(service_name)
    return win32serviceutil.WaitForServiceStatus(service_name, win32service.SERVICE_RUNNING, waitSecs=4)

def service_stop(service_name):
    win32serviceutil.StopService(service_name)
    win32api.Sleep(2000)
    return win32serviceutil.WaitForServiceStatus(service_name, win32service.SERVICE_STOPPED, waitSecs=4)

def service_is_running(service_name):
    """Return True if the service is running"""
    return win32serviceutil.QueryServiceStatus(service_name)[1] == win32service.SERVICE_RUNNING

def user_appdata():
    return winshell.get_path(shellcon.CSIDL_APPDATA)

remove_file=os.unlink
remove_tree=shutil.rmtree

def mkdirs(path):
    """Create directory path if it doesn't exists yet"""
    if not os.path.isdir(path):
        os.makedirs(path)

isfile=os.path.isfile
isdir=os.path.isdir

def user_desktop():
    """return path to current logged in user desktop"""
    return desktop(0)

def common_desktop():
    """return path to public desktop (visible by all users)"""
    return desktop(1)

def register_dll(dllpath):
    """Register a COM/OLE server DLL in registry (similar to regsvr32)"""
    dll = ctypes.windll[dllpath]
    result = dll.DllRegisterServer()
    logger.info('DLL %s registered' % dllpath)
    if result:
        raise Exception('Register DLL %s failed, code %i' % (dllpath,result))

def unregister_dll(dllpath):
    """Unregister a COM/OLE server DLL from registry"""
    dll = ctypes.windll[dllpath]
    result = dll.DllUnregisterServer()
    logger.info('DLL %s unregistered' % dllpath)
    if result:
        raise Exception('Unregister DLL %s failed, code %i' % (dllpath,result))

def add_to_system_path(path):
    key = reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',sam=KEY_READ | KEY_WRITE)
    system_path = reg_getvalue(key,'Path').lower().split(';')
    if not path.lower() in system_path:
        system_path.append(path)
        reg_setvalue(key,'Path',';'.join(system_path),type=REG_EXPAND_SZ)
        win32api.SendMessage(win32con.HWND_BROADCAST,win32con.WM_SETTINGCHANGE,0,'Environment')
    return system_path

class EWaptSetupException(Exception):
    pass

def error(reason):
    """Raise a fatal error"""
    raise EWaptSetupException('Fatal error : %s' % reason)

# to help pyscripter code completion in setup.py
params = {}
"""Specific parameters for install scripts"""

if __name__=='__main__':
    print registry_readstring(HKEY_LOCAL_MACHINE,'SYSTEM/CurrentControlSet/services/Tcpip/Parameters','Hostname')
    print registry_readstring(HKEY_LOCAL_MACHINE,'SYSTEM/CurrentControlSet/services/Tcpip/Parameters','DhcpDomain')

    copytree2('c:\\tmp','c:\\tmp2\\toto',onreplace=default_overwrite)
    copytree2('c:\\tmp','c:\\tmp2\\toto',onreplace=default_skip)
    create_desktop_shortcut('test','c:\\')
    assert isfile(makepath(common_desktop(),'test.lnk'))
    shell_launch(makepath(common_desktop(),'test.lnk'))
    remove_file(makepath(common_desktop(),'test.lnk'))
    assert not isfile(makepath(common_desktop(),'test.lnk'))

    create_user_desktop_shortcut('test2','c:\\')
    assert isfile(makepath(desktop(0),'test2.lnk'))
    remove_file(makepath(desktop(0),'test2.lnk'))
    assert not isfile(makepath(desktop(0),'test2.lnk'))

    assert isrunning('explorer')
    assert service_installed('waptservice')
    if not service_is_running('waptservice'):
        service_start('waptservice')
    assert service_is_running('waptservice')
    service_stop('waptservice')
    assert not service_is_running('waptservice')
    service_start('waptservice')
    assert not service_installed('wapt')
    assert get_computername() <> ''
    #print getloggedinusers()
    #assert get_domainname() <> ''
    assert get_msi_properties(glob.glob('C:\\Windows\\Installer\\*.msi')[0])['Manufacturer'] <> ''
    assert installed_softwares('offi')[0]['uninstallstring'] <> ''
    assert get_file_properties('c:\\wapt\\waptservice.exe')['FileVersion'] <>''
    assert get_file_properties('c:\\wapt\\wapt-get.exe')['FileVersion'] <> ''