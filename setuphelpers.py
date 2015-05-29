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
__version__ = "1.2.4"

__all__ = \
['EWaptSetupException',
 'HKEY_CLASSES_ROOT',
 'HKEY_CURRENT_CONFIG',
 'HKEY_CURRENT_USER',
 'HKEY_LOCAL_MACHINE',
 'HKEY_USERS',
 'KEY_ALL_ACCESS',
 'KEY_READ',
 'KEY_WRITE',
 'PackageEntry',
 'REG_DWORD',
 'REG_EXPAND_SZ',
 'REG_MULTI_SZ',
 'REG_SZ',
 'TimeoutExpired',
 'Version',
 '__version__',
 'add_shutdown_script',
 'add_to_system_path',
 'add_user_to_group',
 'adjust_current_privileges',
 'application_data',
 'bookmarks',
 'common_desktop',
 'control',
 'copytree2',
 'create_daily_task',
 'create_desktop_shortcut',
 'create_group',
 'create_programs_menu_shortcut',
 'create_shortcut',
 'create_user',
 'create_user_desktop_shortcut',
 'create_user_programs_menu_shortcut',
 'critical_system_pending_updates',
 'currentdate',
 'currentdatetime',
 'default_oncopy',
 'default_overwrite',
 'default_overwrite_older',
 'default_skip',
 'delete_at_next_reboot',
 'delete_group',
 'delete_task',
 'delete_user',
 'desktop',
 'disable_file_system_redirection',
 'disable_task',
 'dmi_info',
 'enable_task',
 'ensure_dir',
 'ensure_unicode',
 'error',
 'filecopyto',
 'find_processes',
 'get_appath',
 'get_computername',
 'get_current_user',
 'get_domain_fromregistry',
 'get_file_properties',
 'get_hostname',
 'get_language',
 'get_loggedinusers',
 'get_msi_properties',
 'get_task',
 'getproductprops',
 'getsilentflags',
 'glob',
 'host_info',
 'inifile_hasoption',
 'inifile_readstring',
 'inifile_writestring',
 'installed_softwares',
 'install_exe_if_needed',
 'install_msi_if_needed',
 'isdir',
 'isfile',
 'isrunning',
 'iswin64',
 'killalltasks',
 'killtree',
 'local_admins',
 'local_groups',
 'local_users',
 'local_desktops',
 'logger',
 'makepath',
 'memory_status',
 'messagebox',
 'mkdirs',
 'my_documents',
 'networking',
 'need_install',
 'os',
 'params',
 'programfiles',
 'programfiles32',
 'programfiles64',
 'programs',
 'reboot_machine',
 'recent',
 'reg_closekey',
 'reg_delvalue',
 'reg_getvalue',
 'reg_openkey_noredir',
 'reg_setvalue',
 'register_dll',
 'register_ext',
 'register_uninstall',
 'register_windows_uninstall',
 'registered_organization',
 'registry_delete',
 'registry_readstring',
 'registry_set',
 'registry_setstring',
 'remove_desktop_shortcut',
 'remove_file',
 'remove_from_system_path',
 'remove_programs_menu_shortcut',
 'remove_shutdown_script',
 'remove_tree',
 'remove_user_desktop_shortcut',
 'remove_user_from_group',
 'remove_user_programs_menu_shortcut',
 'replace_at_next_reboot',
 'run',
 'run_notfatal',
 'run_task',
 'sendto',
 'service_installed',
 'service_is_running',
 'service_is_stopped',
 'service_start',
 'service_stop',
 'set_environ_variable',
 'set_file_hidden',
 'set_file_visible',
 'shell_launch',
 'showmessage',
 'shutdown_scripts_ui_visible',
 'shutil',
 'start_menu',
 'startup',
 'system32',
 'task_exists',
 'taskscheduler',
 'uninstall_cmd',
 'unregister_dll',
 'unregister_uninstall',
 'unset_environ_variable',
 'user_appdata',
 'user_desktop',
 'wget',
 'wgets',
 'wincomputername',
 'windomainname',
 'winshell',
 'wmi_info',
 'wmi_info_basic',
 'datetime2isodate',
 'httpdatetime2isodate',
 'isodate2datetime',
 'time2display',
 'hours_minutes',
 'fileisodate',
 'dateof',
 'ensure_list',
 'reg_enum_subkeys',
 'win_startup_info',
 ]

import os
import sys
import logging
import tempfile
import shutil
import shlex

import _subprocess
import subprocess
from subprocess import Popen, PIPE
import psutil

import win32api
import win32net
import win32gui
import win32netcon
import win32security
import ntsecuritycon

import win32con
import win32pdhutil
import msilib
import win32service
import win32serviceutil
import glob
import ctypes

import requests
import time
import datetime
import socket

import _winreg
import platform
import winshell
import pythoncom
from win32com.shell import shell, shellcon
from win32com.taskscheduler import taskscheduler
import locale
import types
import re
import threading
import codecs
import email.utils
from waptpackage import PackageEntry
from waptpackage import Version as Version
from types import ModuleType

from iniparse import RawConfigParser
import keyfinder
logger = logging.getLogger()

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

def ensure_dir(filename):
    """Be sure the directory of filename exists on disk. Create it if not

    The intermediate directories are created either.

    Args:
        filename (str): path to a future file for which to create directory.
    Returns:
        None

    """
    d = os.path.dirname(filename)
    if not os.path.isdir(d):
        os.makedirs(d)


# from opsi
def ensure_unicode(data):
    ur"""Return a unicode string from data object

    It is sometimes diffcult to know in advance what we will get from command line
     application output.

    This is to ensure we get a (not always accurate) representation of the data
     mainly for logging purpose.

    Args:
        data: either str or unicode or object having a __unicode__ or WindowsError or Exception
    Returns:
        unicode: unicode string representing the data

    >>> ensure_unicode(str('éé'))
    u'\xe9\xe9'
    >>> ensure_unicode(u'éé')
    u'\xe9\xe9'
    >>> ensure_unicode(Exception("test"))
    u'Exception: test'
    >>> ensure_unicode(Exception())
    u'Exception: '
    """
    try:
        if type(data) is types.UnicodeType:
            return data
        if type(data) is types.StringType:
            return unicode(data, 'utf8', 'replace')
        if isinstance(data,WindowsError):
            return u"%s : %s" % (data.args[0], data.args[1].decode(sys.getfilesystemencoding()))
        if isinstance(data,(UnicodeDecodeError,UnicodeEncodeError)):
            return u"%s : faulty string is '%s'" % (data,repr(data.args[1]))
        if isinstance(data,Exception):
            try:
                return u"%s: %s" % (data.__class__.__name__,("%s"%data).decode(sys.getfilesystemencoding()))
            except:
                try:
                    return u"%s: %s" % (data.__class__.__name__,("%s"%data).decode('utf8'))
                except:
                    try:
                        return u"%s: %s" % (data.__class__.__name__,u"%s"%data)
                    except:
                        return u"%s" % (data.__class__.__name__,)
        if hasattr(data, '__unicode__'):
            try:
                return data.__unicode__()
            except:
                pass
        return unicode(data)
    except:
        if logger.level != logging.DEBUG:
            return("Error in ensure_unicode / %s"%(repr(data)))
        else:
            raise


def ensure_list(csv_or_list,ignore_empty_args=True):
    """if argument is not a list, return a list from a csv string"""
    if csv_or_list is None:
        return []
    if isinstance(csv_or_list,tuple):
        return list(csv_or_list)
    elif not isinstance(csv_or_list,list):
        if ignore_empty_args:
            return [s.strip() for s in csv_or_list.split(',') if s.strip() != '']
        else:
            return [s.strip() for s in csv_or_list.split(',')]
    else:
        return csv_or_list


def create_shortcut(path, target='', arguments='', wDir='', icon=''):
    r"""Create a windows shortcut

    Args:
        path (str) : As what file should the shortcut be created?
        target (str): What command should the desktop use?
        arguments (str): What arguments should be supplied to the command?
        wdir (str) : working directory. What folder should the command start in?
        icon (str or list) : filename or (filename, index) (only for file sc)
                              What icon should be used for the shortcut

    Returns:
        None

    >>> create_shortcut(r'c:\\tmp\\test.lnk',target='c:\\wapt\\waptconsole.exe')
    """
    ext = os.path.splitext(path)[1].lower()
    if ext == '.url':
        shortcut = file(path, 'w')
        shortcut.write('[InternetShortcut]\n')
        shortcut.write('URL=%s\n' % target)
        shortcut.write('IconFile="%s"\n' % icon)
        shortcut.write('IconIndex=0\n')
        shortcut.close()
    else:
        winshell.CreateShortcut(path,target,arguments,wDir,(icon,0),'')


def create_desktop_shortcut(label, target='', arguments ='', wDir='', icon=''):
    r"""Create a desktop shortcut link for all users

    Args:
        label  (str): Name of the shorcut (.lnk extension is appended if not provided)
        target (str) : path to application
        arguments (str): argument to pass to application
        wDir (str): working directory
        icon (str): path to ico file

    Returns:
        str: Path to the shortcut

    >>> create_desktop_shortcut(r'WAPT Console Management',target=r'c:\wapt\waptconsole.exe')
    u'C:\\Users\\Public\\Desktop\\WAPT Console Management.lnk'
    >>> create_desktop_shortcut(r'WAPT local status',target='http://localhost:8088/')
    u'C:\\Users\\Public\\Desktop\\WAPT local status.url'
    """
    ext = os.path.splitext(label)[1].lower()
    if not ext in ('.lnk','.url'):
        if target.startswith('http://') or target.startswith('https://'):
            label += '.url'
        else:
            label += '.lnk'
    sc_path = os.path.join(desktop(1),label)
    if os.path.isfile(sc_path):
        os.remove(sc_path)
    create_shortcut(sc_path,target,arguments, wDir,icon)
    return sc_path


def create_user_desktop_shortcut(label, target='',arguments='', wDir='', icon=''):
    r"""Create a desktop shortcut link for current user

    Args:
        label  (str): Name of the shorcut (.lnk extension is appended if not provided)
        target (str) : path to application
        arguments (str): argument to pass to application
        wDir (str): working directory
        icon (str): path to ico file

    Returns:
        str: Path to the shortcut


    >>> create_user_desktop_shortcut(r'WAPT Console Management',target='c:\\wapt\\waptconsole.exe')
    u'C:\\Users\\htouvet\\Desktop\\WAPT Console Management.lnk'
    >>> create_user_desktop_shortcut(r'WAPT local status',target='http://localhost:8088/')
    u'C:\\Users\\htouvet\\Desktop\\WAPT local status.url'
    """
    ext = os.path.splitext(label)[1].lower()
    if not ext in ('.lnk','.url'):
        if target.startswith('http://') or target.startswith('https://'):
            label += '.url'
        else:
            label += '.lnk'
    sc_path = os.path.join(desktop(0),label)
    if os.path.isfile(sc_path):
        os.remove(sc_path)
    create_shortcut(sc_path,target,arguments,wDir,icon)
    return sc_path


def create_programs_menu_shortcut(label, target='', arguments='', wDir='', icon=''):
    r"""Create a program menu shortcut link for all users

    if label's extension is url, a http shortcut is created, else creates a file system shortcut.

    Args:
        label  : Name of the shorcut (.lnk extension is appended if not provided.)
        target : path to application
        arguments : argument to pass to application
        wDir : working directory
        icon : path to ico file
    Returns:
        str: Path to the shortcut

    >>> create_programs_menu_shortcut('Dev-TranquilIT', target='http://dev.tranquil.it')
    u'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Dev-TranquilIT.url'
    >>> create_programs_menu_shortcut('Console WAPT', target=makepath('c:/wapt','waptconsole.exe'))
    u'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Console WAPT.lnk'

    """
    ext = os.path.splitext(label)[1].lower()
    if not ext in ('.lnk','.url'):
        if target.startswith('http://') or target.startswith('https://'):
            label += '.url'
        else:
            label += '.lnk'
    sc = os.path.join(start_menu(1),label)
    if os.path.isfile(sc):
        os.remove(sc)
    create_shortcut(sc,target,arguments,wDir,icon)
    return sc


def create_user_programs_menu_shortcut(label, target='', arguments='', wDir='', icon=''):
    r"""Create a shortcut in the start menu of the current user

       If label extension is url, create a Http shortcut, else a file system shortcut.

    Args:
        label  : Name of the shorcut (.lnk or .url extension is appended if not provided.)
        target : path to application
        arguments : argument to pass to application
        wDir : working directory
        icon : path to ico file
    Returns:
        str: Path to the shortcut

    >>> create_user_programs_menu_shortcut('Dev-TranquilIT', target='http://dev.tranquil.it')
    u'C:\\Users\\htouvet\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Dev-TranquilIT.url'
    >>> create_user_programs_menu_shortcut('Console WAPT', target=makepath('c:/wapt','waptconsole.exe'))
    u'C:\\Users\\htouvet\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Console WAPT.lnk'
    """
    ext = os.path.splitext(label)[1].lower()
    if not ext in ('.lnk','.url'):
        if target.startswith('http://') or target.startswith('https://'):
            label += '.url'
        else:
            label += '.lnk'
    sc = os.path.join(start_menu(0),label)
    if os.path.isfile(sc):
        os.remove(sc)
    create_shortcut(sc,target,arguments,wDir,icon)
    return sc


def remove_programs_menu_shortcut(label):
    """Remove a shortcut from the start menu of all users

    Args:
        label (str): label of shortcut with extension lnk or url
    """
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    remove_file(makepath(start_menu(common=1),label))

def remove_user_programs_menu_shortcut(label):
    """Remove a shortcut from the start menu of current user

    Args:
        label (str): label of shortcut with extension lnk or url
    """
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    remove_file(makepath(start_menu(common=0),label))

def remove_desktop_shortcut(label):
    """Remove a shortcut from the desktop of all users

    Args:
        label (str): label of shortcut with extension lnk or url
    """
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    remove_file(os.path.join(desktop(1),label))

def remove_user_desktop_shortcut(label):
    """Remove a shortcut from the desktop of current user

    Args:
        label (str): label of shortcut with extension lnk or url
    """
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    remove_file(os.path.join(desktop(0),label))

def wgets(url,proxies=None,verify_cert=False):
    """Return the content of a remote resource as a String with a http get request.

    Raise an exception if remote data can't be retrieved.

    Args:
        url (str): http(s) url
        proxies (dict): proxy configuration as requests requires it {'http': url, 'https':url}
    Returns:
        str : content of remote resource

    >>> data = wgets('https://wapt/ping')
    >>> "msg" in data
    True
    """
    r = requests.get(url,proxies=proxies,verify=verify_cert)
    if r.ok:
        return r.text
    else:
        r.raise_for_status()


def wget(url,target,printhook=None,proxies=None,connect_timeout=10,download_timeout=None,verify_cert=False):
    r"""Copy the contents of a file from a given URL to a local file.
    >>> respath = wget('http://wapt.tranquil.it/wapt/tis-firefox_28.0.0-1_all.wapt','c:\\tmp\\test.wapt',proxies={'http':'http://proxy:3128'})
    ???
    >>> os.stat(respath).st_size>10000
    True
    >>> respath = wget('http://localhost:8088/runstatus','c:\\tmp\\test.json')
    ???
    """
    start_time = time.time()
    last_time_display = 0.0
    last_downloaded = 0

    def reporthook(received,total):
        total = float(total)
        if total>1 and received>1:
            # print only every second or at end
            if (time.time()-start_time>1) and ((time.time()-last_time_display>=1) or (received>=total)):
                speed = received /(1024.0 * (time.time()-start_time))
                if printhook:
                    printhook(received,total,speed,url)
                else:
                    try:
                        if received == 0:
                            print u"Downloading %s (%.1f Mb)" % (url,int(total)/1024/1024)
                        elif received>=total:
                            print u"  -> download finished (%.0f Kb/s)" % (total /(1024.0*(time.time()+.001-start_time)))
                        else:
                            print u'%i / %i (%.0f%%) (%.0f KB/s)\r' % (received,total,100.0*received/total,speed ),
                    except:
                        return False
                return True
            else:
                return False

    if os.path.isdir(target):
        target = os.path.join(target,'')

    (dir,filename) = os.path.split(target)
    if not filename:
        filename = url.split('/')[-1]
    if not dir:
        dir = os.getcwd()

    if not os.path.isdir(dir):
        os.makedirs(dir)

    httpreq = requests.get(url,stream=True, proxies=proxies, timeout=connect_timeout,verify=verify_cert)

    total_bytes = int(httpreq.headers['content-length'])
    # 1Mb max, 1kb min
    chunk_size = min([1024*1024,max([total_bytes/100,2048])])

    cnt = 0
    reporthook(last_downloaded,total_bytes)

    with open(os.path.join(dir,filename),'wb') as output_file:
        last_time_display = time.time()
        last_downloaded = 0
        if httpreq.ok:
            for chunk in httpreq.iter_content(chunk_size=chunk_size):
                output_file.write(chunk)
                if download_timeout is not None and (time.time()-start_time>download_timeout):
                    raise requests.Timeout(r'Download of %s takes more than the requested %ss'%(url,download_timeout))
                if reporthook(cnt*len(chunk),total_bytes):
                    last_time_display = time.time()
                last_downloaded += len(chunk)
                cnt +=1
            if reporthook(last_downloaded,total_bytes):
                last_time_display = time.time()
        else:
            httpreq.raise_for_status()

    return os.path.join(dir,filename)


def filecopyto(filename,target):
    """Copy file from absolute or package temporary directory to target directory

    If file is dll or exe, logs the original and new version.

    Args:
        filename (str): absolute path to file to copy,
                        or relative path to temporary package install content directory.

        target (str) : absolute path to target directory where to copy file.

        target is either a full filename or a directory name
        if filename is .exe or .dll, logger prints version numbers

    >>> if not os.path.isfile('c:/tmp/fc.test'):
    ...     with open('c:/tmp/fc.test','wb') as f:
    ...         f.write('test')
    >>> if not os.path.isdir('c:/tmp/target'):
    ...    os.mkdir('c:/tmp/target')
    >>> if os.path.isfile('c:/tmp/target/fc.test'):
    ...    os.unlink('c:/tmp/target/fc.test')
    >>> filecopyto('c:/tmp/fc.test','c:/tmp/target')
    >>> os.path.isfile('c:/tmp/target/fc.test')
    True
    """
    (dir,fn) = os.path.split(filename)
    if not dir:
        dir = os.getcwd()

    if os.path.isdir(target):
        target = os.path.join(target,os.path.basename(filename))
    if os.path.isfile(target):
        if os.path.splitext(target)[1] in ('.exe','.dll'):
            try:
                ov = get_file_properties(target)['FileVersion']
                nv = get_file_properties(filename)['FileVersion']
                logger.info(u'Replacing %s (%s) -> %s' % (ensure_unicode(target),ov,nv))
            except:
                logger.info(u'Replacing %s' % target)
        else:
            logger.info(u'Replacing %s' % target)
    else:
        if os.path.splitext(target)[1] in ('.exe','.dll'):
            try:
                nv = get_file_properties(filename)['FileVersion']
                logger.info(u'Copying %s (%s)' % (ensure_unicode(target),nv))
            except:
                logger.info(u'Copying %s' % (ensure_unicode(target)))
        else:
            logger.info(u'Copying %s' % (ensure_unicode(target)))
    shutil.copy(filename,target)


def register_ext(appname,fileext,shellopen,icon=None,otherverbs=[]):
    """Associates a file extension with an application, and command to open it

    Args:
        appname (str): descriptive name of the type of file / appication
        fileext (str): extension with dot prefix of


    >>> register_ext(
    ...     appname='WAPT.Package',
    ...     fileext='.wapt',
    ...     icon=r'c:\wapt\wapt.ico',
    ...     shellopen=r'"7zfm.exe" "%1"',otherverbs=[
    ...        ('install',r'"c:\wapt\wapt-get.exe" install "%1"'),
    ...        ('edit',r'"c:\wapt\wapt-get.exe" edit "%1"'),
    ...     ])
    >>>
    """
    def setvalue(key,path,value):
        rootpath = os.path.dirname(path)
        name = os.path.basename(path)
        with reg_openkey_noredir(key,path,sam=KEY_READ | KEY_WRITE,create_if_missing=True) as k:
            if value != None:
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


# Copy of an entire tree from install temp directory to target
def default_oncopy(msg,src,dst):
    logger.debug(u'%s : "%s" to "%s"' % (ensure_unicode(msg),ensure_unicode(src),ensure_unicode(dst)))
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


def copytree2(src, dst, ignore=None,onreplace=default_skip,oncopy=default_oncopy,enable_replace_at_reboot=True):
    r"""Copy src directory to dst directory. dst is created if it doesn't exists
        src can be relative to installation temporary dir

        oncopy is called for each file copy. if False is returned, copy is skipped
        onreplace is called when a file will be overwritten.

    Args:
        src (str): path to source directory (absolute path or relative to package extraction tempdir)
        dst (str): path to target directory (created if not present)
        ignore (func) : callback func(root_dir,filenames) which returns names to ignore
        onreplace (func) : callback func(src,dst):boolean called when a file will be replaced to decide what to do.
                        default is to not replace if target exist. can be default_override or default_override_older.
        oncopy (func) : callback func(msg,src,dst) called when a file is copied.
                        default is to log in debug level the operation
        enable_replace_at_reboot (boolean): if True, files which are locked will be scheduled for replace at next reboot
    Returns:

    Exceptions:

    >>> copytree2(r'c:\tranquilit\wapt\tests',r'c:\tranquilit\wapt\tests2')
    >>> isdir(r'c:\tranquilit\wapt\tests2')
    True
    >>> remove_tree(r'c:\tranquilit\wapt\tests2')
    >>> isdir(r'c:\tranquilit\wapt\tests2')
    False
    """
    logger.debug('Copy tree from "%s" to "%s"' % (ensure_unicode(src),ensure_unicode(dst)))
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
                try:
                    if os.path.isfile(dstname):
                        if onreplace(srcname,dstname) and oncopy('overwrites',srcname,dstname):
                            os.unlink(dstname)
                            shutil.copy2(srcname, dstname)
                    else:
                        if oncopy('copy',srcname,dstname):
                            shutil.copy2(srcname, dstname)
                except (IOError, os.error) as e:
                    # file is locked...
                    if enable_replace_at_reboot and e.errno in (5,13):
                        filecopyto(srcname,dstname+'.pending')
                        replace_at_next_reboot(tmp_filename=dstname+'.pending',target_filename=dstname)
                    else:
                        raise

        except (IOError, os.error), why:
            logger.critical(u'Error copying from "%s" to "%s" : %s' % (ensure_unicode(src),ensure_unicode(dst),ensure_unicode(why)))
            errors.append((srcname, dstname, str(why)))
        # catch the Error from the recursive copytree so that we can
        # continue with other files
        except shutil.Error, err:
            #errors.extend(err.args[0])
            errors.append(err)
    try:
        shutil.copystat(src, dst)
    except WindowsError:
        # can't copy file access times on Windows
        pass
    except OSError, why:
        errors.extend((src, dst, str(why)))
    if errors:
        raise shutil.Error(errors)


class RunReader(threading.Thread):
    # helper thread to read output of run command
    def __init__(self, callable, *args, **kwargs):
        super(RunReader, self).__init__()
        self.callable = callable
        self.args = args
        self.kwargs = kwargs
        self.setDaemon(True)

    def run(self):
        try:
            self.callable(*self.args, **self.kwargs)
        except Exception, e:
            print e


class TimeoutExpired(Exception):
    """This exception is raised when the timeout expires while waiting for a
    child process.
    """
    def __init__(self, cmd, output=None, timeout=None):
        self.cmd = cmd
        self.output = output
        self.timeout = timeout

    def __str__(self):
        return ("Command '%s' timed out after %s seconds with output '%s'" %
                (self.cmd, self.timeout, self.output))


def run(*cmd,**kwargs):
    r"""Run the command cmd in a shell and return the output and error text as string

    Args:
        *cmd : command and arguments, either as a string or as a list of arguments

    Kwargs:
        shell (boolean) : True is assumed
        timeout (int) : maximum time to wait for cmd completion is second (default = 600)
                        a TimeoutExpired exception is raised if tiemout is reached.
        on_write : callback when a new line is printed on stdout or stderr by the subprocess
                        func(linestr)
        accept_returncodes (list) : list of return code which are considered OK default = (0,1601)
        pidlist (list): external list where to append the pid of the launched process.

        all other parameters from the psutil.Popen constructor are accepted

    Returns:
        unicode : merged output of stdout and stderr streams

    Exceptions:
        CalledProcessError: if return code of cmd is not in accept_returncodes list
        TimeoutExpired:  if process is running for more than timeout time.

    >>> run(r'dir /B c:\windows\explorer.exe')
    u'explorer.exe\r\n'

    >>> out = []
    >>> pids = []
    >>> def getlines(line):
    ...    out.append(line)
    >>> run(r'dir /B c:\windows\explorer.exe',pidlist=pids,on_write=getlines)
    u'explorer.exe\r\n'

    >>> print out
    ['explorer.exe\r\n']
    >>> try:
    ...     run(r'ping /t 127.0.0.1',timeout=3)
    ... except TimeoutExpired:
    ...     print('timeout')
    timeout
    """
    logger.info(u'Run "%s"' % (ensure_unicode(cmd),))
    output = []

    def worker(pipe,on_write=None):
        while True:
            line = pipe.readline()
            if line == '':
                break
            else:
                if on_write:
                    on_write(line)
                output.append(line)

    if 'timeout' in kwargs:
        timeout = kwargs['timeout']
        del kwargs['timeout']
    else:
        timeout = 10*60.0

    if not "shell" in kwargs:
        kwargs['shell']=True

    if not 'accept_returncodes' in kwargs:
        # 1603 : souvent renvoyé quand déjà installé.
        # 3010 : reboot required.
        valid_returncodes = [0,1603,3010]
    else:
        valid_returncodes = kwargs['accept_returncodes']
        del kwargs['accept_returncodes']

    if 'pidlist' in kwargs and isinstance(kwargs['pidlist'],list):
        pidlist = kwargs['pidlist']
        kwargs.pop('pidlist')
    else:
        pidlist = []

    if 'on_write' in kwargs and isinstance(kwargs['on_write'],types.FunctionType):
        on_write = kwargs['on_write']
        kwargs.pop('on_write')
    else:
        on_write = None

    proc = psutil.Popen(*cmd, bufsize=1, stdout=PIPE, stderr=PIPE,**kwargs)
    # keep track of launched pid if required by providing a pidlist argument to run
    if not proc.pid in pidlist:
        pidlist.append(proc.pid)

    stdout_worker = RunReader(worker, proc.stdout,on_write)
    stderr_worker = RunReader(worker, proc.stderr,on_write)
    stdout_worker.start()
    stderr_worker.start()
    stdout_worker.join(timeout)
    if stdout_worker.is_alive():
        # kill the task and all subtasks
        if proc.pid in pidlist:
            pidlist.remove(proc.pid)
            killtree(proc.pid)
        raise TimeoutExpired(cmd,''.join(output),timeout)
    stderr_worker.join(timeout)
    if stderr_worker.is_alive():
        if proc.pid in pidlist:
            pidlist.remove(proc.pid)
            killtree(proc.pid)
        raise TimeoutExpired(cmd,''.join(output),timeout)
    proc.returncode = _subprocess.GetExitCodeProcess(proc._handle)
    if proc.pid in pidlist:
        pidlist.remove(proc.pid)
        killtree(proc.pid)
    if not proc.returncode in valid_returncodes:
        raise subprocess.CalledProcessError(proc.returncode,cmd,''.join(output))
    else:
        if proc.returncode == 0:
            logger.info(u'%s command returns code %s' % (ensure_unicode(cmd),proc.returncode))
        else:
            logger.warning(u'%s command returns code %s' % (ensure_unicode(cmd),proc.returncode))
    return ensure_unicode(''.join(output))


def run_notfatal(*cmd,**args):
    """Runs the command and wait for it termination, returns output
    Ignore exit status code of command, return '' instead
    """
    try:
        return run(*cmd,**args)
    except Exception,e:
        print u'Warning : %s' % ensure_unicode(e)
        return ''


def shell_launch(cmd):
    """Launch a command (without arguments) but doesn't wait for its termination

    .>>> open('c:/tmp/test.txt','w').write('Test line')
    .>>> shell_launch('c:/tmp/test.txt')
    """
    os.startfile(cmd)


def isrunning(processname):
    """Check if a process is running,

    >>> isrunning('explorer')
    True
    """
    processname = processname.lower()
    for p in psutil.process_iter():
        try:
            if p.name().lower() == processname or p.name().lower() == processname+'.exe':
                return True
        except (psutil.AccessDenied,psutil.NoSuchProcess):
            pass
    return False


def killalltasks(exenames,include_children=True):
    """Kill the task by their exename

    >>> killalltasks('firefox.exe')
    """
    logger.debug('Kill tasks %s' % (exenames,))
    if not isinstance(exenames,list):
        exenames = [exenames]
    exenames = [exe.lower() for exe in exenames]+[exe.lower()+'.exe' for exe in exenames]
    for p in psutil.process_iter():
        try:
            if p.name().lower() in exenames:
                logger.debug('Kill process %i' % (p.pid,))
                if include_children:
                    killtree(p.pid)
                else:
                    p.kill()
        except (psutil.AccessDenied,psutil.NoSuchProcess):
            pass

    """
    for c in exenames:
      run(u'taskkill /t /im "%s" /f' % c)
    """


def killtree(pid, including_parent=True):
    try:
        parent = psutil.Process(pid)
        if parent:
            for child in parent.get_children(recursive=True):
                child.kill()
            if including_parent:
                parent.kill()
    except psutil.NoSuchProcess as e:
        pass


def find_processes(process_name):
    """Return list of Process names process_name

    Args;
        process_name (str): process name to lookup

    Returns:
        list: list of processes (Process) named process_name or process_name.exe

    >>> [p.pid for p in find_processes('explorer')]
    [2756, 4024]
    """
    process_name = process_name.lower()
    result = []
    for p in psutil.process_iter():
        try:
            if p.name().lower() in [process_name,process_name+'.exe']:
                result.append(p)
        except (psutil.AccessDenied,psutil.NoSuchProcess):
            pass

    return result


def messagebox(title,msg):
    win32api.MessageBox(0, msg, title, win32con.MB_ICONINFORMATION)


def showmessage(msg):
    win32api.MessageBox(0, msg, 'Information', win32con.MB_ICONINFORMATION)


def programfiles64():
    """Return 64 bits program folder

    >>> programfiles64
    'C:\\Program Files'
    """
    if 'PROGRAMW6432' in os.environ :
        return os.environ['PROGRAMW6432']
    else:
        return os.environ['PROGRAMFILES']


def programfiles():
    """Return native program directory, ie C:\Program Files for both 64 and 32 bits"""
    #return winshell.get_path(shellcon.CSIDL_PROGRAM_FILES)
    if 'PROGRAMW6432' in os.environ:
        return os.environ['PROGRAMW6432']
    else:
        return os.environ['PROGRAMFILES']


def programfiles32():
    """Return 32bits applications folder.

    Returns:
        str: path of programs files (x86) (on win64) or programs files (on 32bits)

    >>> programfiles32
    'C:\\Program Files (x86)'
    """
    if 'PROGRAMW6432' in os.environ and 'PROGRAMFILES(X86)' in os.environ:
        return os.environ['PROGRAMFILES(X86)']
    else:
        return os.environ['PROGRAMFILES']


def iswin64():
    """Check whether operating system is 64bits

    Returns:
        boolean

    >>> iswin64()
    True
    """

    # could be
    # return platform.machine()=='AMD64'
    return 'PROGRAMW6432' in os.environ


def get_computername():
    """Return host name (without domain part)"""
    return socket.gethostname()


def get_hostname():
    """Return host fully qualified domain name in lower case"""
    return socket.getfqdn().lower()


def get_domain_fromregistry():
    """Return main DNS domain of the computer

    Returns:
        str: domain name

    >>> get_domain_fromregistry()
    u'tranquilit.local'
    """
    key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters")
    try:
        (domain,atype) = _winreg.QueryValueEx(key,'Domain')
        if domain=='':
            (domain,atype) = _winreg.QueryValueEx(key,'DhcpDomain')
    except:
        try:
            (domain,atype) = _winreg.QueryValueEx(key,'DhcpDomain')
        except:
            domain = None
    return domain


def get_loggedinusers():
    """Return the list of logged in users on this host

    Returns:
        list: list of users logins

    >>> get_loggedinusers()
    [u'htouvet']
    """
    result = []
    try:
        import win32ts
        for session in win32ts.WTSEnumerateSessions():
            if session['State']==win32ts.WTSActive:
                result.append(win32ts.WTSQuerySessionInformation(win32ts.WTS_CURRENT_SERVER_HANDLE,session['SessionId'],win32ts.WTSUserName))
        return result
    except:
        return [get_current_user()]


def registered_organization():
    return registry_readstring(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion','RegisteredOrganization')


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
    if type(dict_or_module) is ModuleType:
        for k,v in params_dict.items():
            setattr(dict_or_module,k,v)
    return params_dict

###########
# root key
HKEY_CLASSES_ROOT = _winreg.HKEY_CLASSES_ROOT
HKEY_CURRENT_USER = _winreg.HKEY_CURRENT_USER
HKEY_LOCAL_MACHINE = _winreg.HKEY_LOCAL_MACHINE
HKEY_USERS = _winreg.HKEY_USERS
HKEY_CURRENT_CONFIG = _winreg.HKEY_CURRENT_CONFIG

# Access modes when opening registry keys
KEY_WRITE = _winreg.KEY_WRITE
KEY_READ = _winreg.KEY_READ
KEY_ALL_ACCESS = _winreg.KEY_ALL_ACCESS

# Types of value
REG_SZ = _winreg.REG_SZ
REG_MULTI_SZ = _winreg.REG_MULTI_SZ
REG_DWORD = _winreg.REG_DWORD
REG_EXPAND_SZ = _winreg.REG_EXPAND_SZ

def reg_closekey(hkey):
    """Close a registry key opened with reg_openkey_noredir

    """
    _winreg.CloseKey(hkey)

def reg_openkey_noredir(rootkey, subkeypath, sam=_winreg.KEY_READ,create_if_missing=False):
    """Open the registry key\subkey with access rights sam

    The Wow6432Node redirector is disabled. So one can access 32 and 64 part or the registry
     even if python is running in 32 bits mode.

    Args:
       rootkey    : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
       subkeypath : string like "software\\microsoft\\windows\\currentversion"
       sam        : a boolean combination of KEY_READ | KEY_WRITE
       create_if_missing : True to create the subkeypath if not exists, access rights will include KEY_WRITE

    Returns:
        keyhandle :   a key handle for reg_getvalue and reg_set_value

    >>>

    """
    try:
        if platform.machine() == 'AMD64':
            result = _winreg.OpenKey(rootkey,subkeypath,0, sam | _winreg.KEY_WOW64_64KEY)
        else:
            result = _winreg.OpenKey(rootkey,subkeypath,0,sam)
        return result
    except WindowsError,e:
        if e.errno == 2:
            if create_if_missing:
                if platform.machine() == 'AMD64':
                    return _winreg.CreateKeyEx(rootkey,subkeypath,0, sam | _winreg.KEY_READ| _winreg.KEY_WOW64_64KEY | _winreg.KEY_WRITE )
                else:
                    return _winreg.CreateKeyEx(rootkey,subkeypath,0,sam | _winreg.KEY_READ | _winreg.KEY_WRITE )
            else:
                raise WindowsError(e.errno,'The key %s can not be opened' % subkeypath)

def reg_key_exists(rootkey, subkeypath):
    """Check if a key exists in registry

    The Wow6432Node redirector is disabled. So one can access 32 and 64 part or the registry
     even if python is running in 32 bits mode.

    Args:
       rootkey     : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
       subkeypath : string like "software\\microsoft\\windows\\currentversion"

    Returns:
        boolean

    >>> if reg_key_exists(HKEY_LOCAL_MACHINE,makepath('SOFTWARE','VideoLAN','VLC')):
    ...     print('VLC key exists')
    ???
    """
    try:
        with reg_openkey_noredir(rootkey,subkeypath):
            return True
    except WindowsError as e:
        if e.errno == 2:
            return False
        else:
            raise

def reg_value_exists(rootkey, subkeypath,value_name):
    """Check if there is value named value_name in the subkeypath registry key of rootkey

    Args:
        rootkey (int): branch of registry HKEY_LOCAL_MACHINE,HKEY_USERS,HKEY_CURRENT_USER,HKEY_CURRENT_CONFIG
        subkeypath (str): path with back slashes like 'SOFTWARE\\VideoLAN\\VLC'
        value_name (str) : value key like "Version"

    Returns:
        boolean: True if there is a value called value_name in the subkeypath of rootkey

    >>> if reg_value_exists(HKEY_LOCAL_MACHINE,makepath('SOFTWARE','VideoLAN','VLC'),'Version'):
    ...     print('VLC seems to be installed')
    ???
    """
    try:
        with reg_openkey_noredir(rootkey,subkeypath) as key:
            value = _winreg.QueryValueEx(key,value_name)[0]
            return True

    except WindowsError as e:
        if e.errno in(259,2):
            return False
        else:
            raise

def reg_getvalue(key,name,default=None):
    r"""Return the value of specified name inside 'key' folder

    >>> with reg_openkey_noredir(HKEY_LOCAL_MACHINE,'SOFTWARE\\7-Zip') as zkey:
    ...     path = reg_getvalue(zkey,'Path')
    >>> print path
    c:\Program Files\7-Zip\

    Args:
         key  : handle of registry key as returned by reg_openkey_noredir()
         name : value name or None for key default value
         default : value returned if specified name doesn't exist
    Returns:
        int or str or list: depends on type of value named name.
    """
    try:
        value = _winreg.QueryValueEx(key,name)[0]
        if type(value) is types.StringTypes:
            return ensure_unicode(value)
        else:
            return value
    except WindowsError,e:
        if e.errno in(259,2):
            # WindowsError: [Errno 259] No more data is available
            # WindowsError: [Error 2] Le fichier spécifié est introuvable
            return default
        else:
            raise


def reg_setvalue(key,name,value,type=_winreg.REG_SZ ):
    """Set the value of specified name inside 'key' folder

         key  : handle of registry key as returned by reg_openkey_noredir()
         name : value name
         type : type of value (REG_SZ,REG_MULTI_SZ,REG_DWORD,REG_EXPAND_SZ)
    """
    return _winreg.SetValueEx(key,name,0,type,value)


def reg_delvalue(key,name):
    """Remove the value of specified name inside 'key' folder
         key  : handle of registry key as returned by reg_openkey_noredir()
         name : value name
    """
    try:
        _winreg.DeleteValue(key,name)
        return True
    except WindowsError,e:
        # WindowsError: [Errno 2] : file does not exist
        if e.winerror == 2:
            return False
        else:
            raise


def reg_enum_subkeys(rootkey):
    os_encoding=locale.getpreferredencoding()
    i = 0
    while True:
        try:
            subkey_name = _winreg.EnumKey(rootkey, i).decode(os_encoding)
            if subkey_name is not None:
                yield subkey_name
            i += 1
        except WindowsError,e:
            # WindowsError: [Errno 259] No more data is available
            if e.winerror == 259:
                break
            else:
                raise

def reg_enum_values(rootkey):
    os_encoding=locale.getpreferredencoding()
    i = 0
    while True:
        try:
            subkey_name = _winreg.EnumKey(rootkey, i).decode(os_encoding)
            if subkey_name is not None:
                yield subkey_name
            i += 1
        except WindowsError,e:
            # WindowsError: [Errno 259] No more data is available
            if e.winerror == 259:
                break
            else:
                raise


def registry_setstring(root,path,keyname,value,type=_winreg.REG_SZ):
    """Set the value of a string key in registry
    the path can be either with backslash or slash

    Args:
        root    : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
        path    : string like "software\\microsoft\\windows\\currentversion"
                           or "software\\wow6432node\\microsoft\\windows\\currentversion"
        keyname : None for value of key or str for a specific value like 'CommonFilesDir'
        value   : string to put in keyname
    """
    path = path.replace(u'/',u'\\')
    with reg_openkey_noredir(root,path,sam=KEY_WRITE,create_if_missing=True) as key:
        return reg_setvalue(key,keyname,value,type=type)


def registry_readstring(root,path,keyname,default=''):
    """Return a string from registry

    Args:
        root    : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
        path    : string like "software\\microsoft\\windows\\currentversion"
                           or "software\\wow6432node\\microsoft\\windows\\currentversion"
        keyname : None for value of key or str for a specific value like 'CommonFilesDir'
        the path can be either with backslash or slash

    >>> registry_readstring(HKEY_LOCAL_MACHINE,r'SYSTEM/CurrentControlSet/services/Tcpip/Parameters','Hostname').upper()
    u'HTLAPTOP'
    """
    path = path.replace(u'/',u'\\')
    try:
        with reg_openkey_noredir(root,path) as key:
            return reg_getvalue(key,keyname,default)
    except:
        return default


def registry_set(root,path,keyname,value,type=None):
    """Set the value of a key in registry, taking in account value type

    Args:
        root    : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
        path    : string like "software\\microsoft\\windows\\currentversion"
                           or "software\\wow6432node\\microsoft\\windows\\currentversion"
        keyname : None for value of key or str for a specific value like 'CommonFilesDir'
        value   : value (integer or string type) to put in keyname
    the path can be either with backslash or slash"""
    path = path.replace(u'/',u'\\')
    with reg_openkey_noredir(root,path,sam=KEY_WRITE,create_if_missing=True) as key:
        if not type:
            if isinstance(value,list):
                type = REG_MULTI_SZ
            elif isinstance(value,int):
                type = REG_DWORD
            else:
                type = REG_SZ
        return reg_setvalue(key,keyname,value,type=type)

def registry_delete(root,path,valuename):
    """Delete the valuename inside specified registry path

    the path can be either with backslash or slash

    Args:
        root    : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
        path    : string like "software\\microsoft\\windows\\currentversion"
                           or "software\\wow6432node\\microsoft\\windows\\currentversion"
        valuename : None for value of key or str for a specific value like 'CommonFilesDir'

    """
    result = False
    path = path.replace(u'/',u'\\')
    try:
        with reg_openkey_noredir(root,path,sam=KEY_WRITE) as key:
            return _winreg.DeleteValue(key,valuename)
    except WindowsError as e:
        logger.warning('registry_delete:%s'%ensure_unicode(e))
    return result


def inifile_hasoption(inifilename,section,key):
    """Read a string parameter from inifile

    >>> inifile_writestring('c:/tranquilit/wapt/tests/test.ini','global','version','1.1.2')
    >>> print inifile_hasoption('c:/tranquilit/wapt/tests/test.ini','global','version')
    True
    >>> print inifile_hasoption('c:/tranquilit/wapt/tests/test.ini','global','dontexist')
    False

    """
    inifile = RawConfigParser()
    inifile.read(inifilename)
    return inifile.has_section(section) and inifile.has_option(section,key)


def inifile_readstring(inifilename,section,key,default=None):
    """Read a string parameter from inifile

    >>> inifile_writestring('c:/tranquilit/wapt/tests/test.ini','global','version','1.1.2')
    >>> print inifile_readstring('c:/tranquilit/wapt/tests/test.ini','global','version')
    1.1.2
    >>> print inifile_readstring('c:/tranquilit/wapt/tests/test.ini','global','undefaut','defvalue')
    defvalue
    """


    inifile = RawConfigParser()
    inifile.read(inifilename)
    if inifile.has_section(section) and inifile.has_option(section,key):
        return inifile.get(section,key)
    else:
        return default


def inifile_writestring(inifilename,section,key,value):
    r"""Write a string parameter to inifile

    >>> inifile_writestring('c:/tranquilit/wapt/tests/test.ini','global','version','1.1.1')
    >>> print inifile_readstring('c:/tranquilit/wapt/tests/test.ini','global','version')
    1.1.1
    """
    inifile = RawConfigParser()
    inifile.read(inifilename)
    if not inifile.has_section(section):
        inifile.add_section(section)
    inifile.set(section,key,value)
    inifile.write(open(inifilename,'w'))


class disable_file_system_redirection:
    r"""Context manager to diable temporarily the wow3264 file redirector

    >>> with disable_file_system_redirection():
    ...     winshell.get_path(shellcon.CSIDL_PROGRAM_FILES)
    u'C:\\Program Files (x86)'
    """
    if iswin64():
        _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
        _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
    else:
        _disable = None
        _revert = None

    def __enter__(self):
        if self._disable:
            self.old_value = ctypes.c_long()
            self.success = self._disable(ctypes.byref(self.old_value))
    def __exit__(self, type, value, traceback):
        if self._revert and self.success:
            self._revert(self.old_value)

def system32():
    r"""returns the path of system32directory

    Returns:
        str: path to system32 directory

    >>> print system32()
    C:\Windows\system32

    """
    return win32api.GetSystemDirectory()

def set_file_visible(path):
    """Unset the hidden attribute of file located at path

    Utility function for shutdown gpo script

    Args:
        path (str): path to the file
    """
    FILE_ATTRIBUTE_HIDDEN = 0x02
    old_att = ctypes.windll.kernel32.GetFileAttributesW(unicode(path))
    ret = ctypes.windll.kernel32.SetFileAttributesW(unicode(path),old_att  & ~FILE_ATTRIBUTE_HIDDEN)
    if not ret:
        raise ctypes.WinError()

def set_file_hidden(path):
    """Set the hidden attribute of file located at path

    Utility function for shutdown gpo script

    Args:
        path (str): path to the file
    """
    FILE_ATTRIBUTE_HIDDEN = 0x02
    old_att = ctypes.windll.kernel32.GetFileAttributesW(unicode(path))
    ret = ctypes.windll.kernel32.SetFileAttributesW(unicode(path),old_att | FILE_ATTRIBUTE_HIDDEN)
    if not ret:
        raise ctypes.WinError()

def replace_at_next_reboot(tmp_filename,target_filename):
    r"""Schedule a file rename at next reboot using standard Windows PendingFileRenameOperations

    Creates a key in HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager with content :
            PendingFileRenameOperations
                Data type : REG_MULTI_SZ Value
                data: \??\c:\temp\win32k.sys !\??\c:\winnt\system32\win32k.s

    Args:
        tmp_filename (str):  Temporary path to file to rename (defaults to <target_filename>.pending)
        target_filename (str): Final target filename
    """
    if not tmp_filename:
        tmp_filename=target_filename+'.pending'
    with reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'System\CurrentControlSet\Control\Session Manager',sam=KEY_WRITE|KEY_READ) as key:
        pending = reg_getvalue(key,'PendingFileRenameOperations',default=[])
        tmp = '\??\{}'.format(tmp_filename)
        target = '!\??\{}'.format(target_filename)
        if not tmp in pending:
            pending.extend ([tmp,target])
            reg_setvalue(key,'PendingFileRenameOperations',pending,type=REG_MULTI_SZ)

def delete_at_next_reboot(target_filename):
    r"""delete at next reboot using standard Windows PendingFileRenameOperations

    Creates a key in HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager with content :
            PendingFileRenameOperations
                Data type : REG_MULTI_SZ Value
                data: [\??\path,\0]

    Args:
        target_filename (str): File to delete
    """
    with reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'System\CurrentControlSet\Control\Session Manager',sam=KEY_WRITE|KEY_READ) as key:
        pending = reg_getvalue(key,'PendingFileRenameOperations',default=[])
        target = '\??\{}'.format(target_filename)
        if not target in pending:
            pending.extend ([target,'\0'])
            reg_setvalue(key,'PendingFileRenameOperations',pending,type=REG_MULTI_SZ)


def ini2winstr(ini):
    """Returns a unicode string from an iniparse.RawConfigParser with windows crlf

    Utility function for local gpo
    """
    items = []
    for sub in [ (u"%s"%l).strip() for l in ini.data._data.contents]:
        items.extend(sub.splitlines())
    return u'\r\n'.join(items)

def _lower(s):
    return s.lower()

def add_shutdown_script(cmd,parameters):
    """ Adds a local shutdown script as a local GPO

    Args:
        cmd (str): absolute path to exe or bat file (without parameters)
        parameters (str): parameters to append to command
    Returns:
        int: index of command into the list of shutdown scripts

    >>> index = add_shutdown_script(r'c:\wapt\wapt-get.exe','update')
    """
    gp_path = makepath(system32(),'GroupPolicy')
    gptini_path = makepath(gp_path,'gpt.ini')
    scriptsini_path = makepath(gp_path,'Machine','Scripts','scripts.ini')
    update_gpt = False

    # manage GPT.INI file
    with disable_file_system_redirection():
        ensure_dir(scriptsini_path)
        gptini = RawConfigParser()
        # be sure to have section names case unsensitive
        gptini.data._sectionxform = _lower
        if os.path.isfile(gptini_path):
            gptini.readfp(codecs.open(gptini_path,mode='r',encoding='utf8'))
        if not gptini.has_section('General'):
            gptini.add_section('General')
        # set or extend extensionnames
        if not gptini.has_option('General','gPCMachineExtensionNames'):
            gptini.set('General','gPCMachineExtensionNames','[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]')
            update_gpt = True
        else:
            ext = gptini.get('General','gPCMachineExtensionNames').strip().replace('][','],[').split(',')
            # fix malformed array : should be a list of pairs [{i1}{i2}][{j1}{j2}][{k1}{k2}]
            if ext:
                # calc a new list of pairs
                newext = []
                bad = False
                for e in ext:
                    e = e.strip('[]')
                    guids = e.replace('}{','},{').split(',')
                    if len(guids)>2:
                        bad = True
                        i = 0
                        while i < len(guids):
                            newext.append('[%s%s]'%(guids[i],guids[i+1]))
                            i+=2
                    else:
                        newext.append(e)
                if bad:
                    ext = newext
                    update_gpt = True

            if not '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]' in ext:
                ext.append('[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]')
                update_gpt = True
            gptini.set('General','gPCMachineExtensionNames',''.join(ext))
        # increment version
        if gptini.has_option('General','Version'):
            version = gptini.getint('General','Version')
            user_version = version & 0xffff0000
            computer_version = version & 0x0000ffff
            computer_version += 1
            version = computer_version | user_version
        else:
            version = 1
        gptini.set('General','Version',version)

        # update shutdown/Scripts.ini
        scriptsini = RawConfigParser()
        if os.path.isfile(scriptsini_path):
            try:
                scriptsini.readfp(codecs.open(scriptsini_path,mode='r',encoding='utf16'))
            except UnicodeError:
                # bug http://roundup.tranquil.it/wapt/issue233
                scriptsini.readfp(codecs.open(scriptsini_path,mode='r',encoding='utf8'))
        if not scriptsini.has_section('Shutdown'):
            scriptsini.add_section('Shutdown')

        # check if cmd already exist in shutdown scripts
        cmd_index = -1
        param_index = -1
        script_index = None
        i = -1
        for (key,value) in scriptsini.items('Shutdown'):
            # keys are lowercase in iniparser !
            if key.endswith('cmdline'):
                i = int(key.split('cmdline')[0])
                if value.lower() == cmd.lower():
                    cmd_index = i
            if key.endswith('parameters'):
                i = int(key.split('parameters')[0])
                if value.lower() == parameters.lower():
                    param_index = i
            # cmd and params are matching... => script already exists
            if cmd_index>=0 and param_index>=0 and cmd_index == param_index:
                script_index = cmd_index
                break
        if script_index is None:
            update_gpt = True
            script_index = i+1
            scriptsini.set('Shutdown','%iCmdLine'%(script_index,),cmd)
            scriptsini.set('Shutdown','%iParameters'%(script_index,),parameters)
            if not os.path.isdir(os.path.dirname(scriptsini_path)):
                os.makedirs(os.path.dirname(scriptsini_path))
            if os.path.isfile(scriptsini_path):
                set_file_visible(scriptsini_path)
            try:
                with codecs.open(scriptsini_path,'w',encoding='utf16') as f:
                    f.write(ini2winstr(scriptsini))
            finally:
                set_file_hidden(scriptsini_path)

        if update_gpt:
            if not os.path.isdir(os.path.dirname(gptini_path)):
                os.makedirs(os.path.dirname(gptini_path))
            with codecs.open(gptini_path,'w',encoding='utf8') as f:
                f.write(ini2winstr(gptini))
            run('GPUPDATE /Target:Computer /Force /Wait:30')
            return script_index
        else:
            return None

def remove_shutdown_script(cmd,parameters):
    """ Removes a local shutdown GPO script

    >>> index = remove_shutdown_script(r'c:\wapt\wapt-get.exe','update')
    """
    gp_path = makepath(system32(),'GroupPolicy')
    gptini_path = makepath(gp_path,'gpt.ini')
    scriptsini_path = makepath(gp_path,'Machine','Scripts','scripts.ini')

    # manage GPT.INI file
    with disable_file_system_redirection():
        ensure_dir(scriptsini_path)
        gptini = RawConfigParser()
        # be sure to have section names case unsensitive
        gptini.data._sectionxform = _lower

        if os.path.isfile(gptini_path):
            gptini.readfp(codecs.open(gptini_path,mode='r',encoding='utf8'))
        if not gptini.has_section('General'):
            gptini.add_section('General')

        # increment version
        if gptini.has_option('General','Version'):
            version = gptini.getint('General','Version')
            version += 1
        else:
            version = 1
        gptini.set('General','Version',version)

        # update shutdown/Scripts.ini
        scriptsini = RawConfigParser()
        if os.path.isfile(scriptsini_path):
            try:
                scriptsini.readfp(codecs.open(scriptsini_path,mode='r',encoding='utf16'))
            except UnicodeError:
                # bug http://roundup.tranquil.it/wapt/issue233
                scriptsini.readfp(codecs.open(scriptsini_path,mode='r',encoding='utf8'))
        if not scriptsini.has_section('Shutdown'):
            scriptsini.add_section('Shutdown')

        # check if cmd already exist in shutdown scripts
        last_cmd_index = None
        last_param_index = None
        script_index = None

        scripts = []
        for (key,value) in scriptsini.items('Shutdown'):
            # keys are lowercase in iniparser !
            if key.endswith('cmdline'):
                last_cmd_index = int(key.split('cmdline')[0])
                last_cmd = value
            if key.endswith('parameters'):
                last_param_index = int(key.split('parameters')[0])
                last_param = value
            if last_cmd_index>=0 and last_param_index>=0 and last_cmd_index == last_param_index:
                if last_cmd.lower() == cmd.lower() and last_param.lower() == parameters.lower():
                    script_index = last_cmd_index
                else:
                    scripts.append((last_cmd,last_param))

        if script_index is not None:
            # reorder remaining scripts
            scriptsini.remove_section('Shutdown')
            scriptsini.add_section('Shutdown')
            i = 0
            for (c,p) in scripts:
                scriptsini.set('Shutdown','%iCmdLine'%(i,),c)
                scriptsini.set('Shutdown','%iParameters'%(i,),p)
                i += 1

            if not os.path.isdir(os.path.dirname(scriptsini_path)):
                os.makedirs(os.path.dirname(scriptsini_path))
            if os.path.isfile(scriptsini_path):
                set_file_visible(scriptsini_path)
            try:
                with codecs.open(scriptsini_path,'w',encoding='utf16') as f:
                    f.write(ini2winstr(scriptsini))
            finally:
                set_file_hidden(scriptsini_path)

            if not os.path.isdir(os.path.dirname(gptini_path)):
                os.makedirs(os.path.dirname(gptini_path))
            with codecs.open(gptini_path,'w',encoding='utf8') as f:
                f.write(ini2winstr(gptini))
            run('GPUPDATE /Target:Computer /Force /Wait:30')
            return script_index
        else:
            return None


def shutdown_scripts_ui_visible(state=True):
    """Enable or disable the GUI for windows shutdown scripts

    >>> shutdown_scripts_ui_visible(None)
    >>> shutdown_scripts_ui_visible(False)
    >>> shutdown_scripts_ui_visible(True)
    """
    with reg_openkey_noredir(HKEY_LOCAL_MACHINE,\
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',sam=KEY_ALL_ACCESS) as key:
        if state is None:
            _winreg.DeleteValue(key,'HideShutdownScripts')
        elif state:
            reg_setvalue(key,'HideShutdownScripts',0,REG_DWORD)
        elif not state:
            reg_setvalue(key,'HideShutdownScripts',1,REG_DWORD)


def uninstall_cmd(guid):
    r"""return the (quiet) command stored in registry to uninstall a software given its registry key

    >>> old_softs = installed_softwares('notepad++')
    >>> for soft in old_softs:
    ...     print uninstall_cmd(soft['key'])
    [u'C:\\Program Files (x86)\\Notepad++\\uninstall.exe', '/S']
    """
    def get_fromkey(uninstall):
        with reg_openkey_noredir(HKEY_LOCAL_MACHINE,"%s\\%s" % (uninstall,guid)) as key:
            try:
                cmd = _winreg.QueryValueEx(key,'QuietUninstallString')[0]
                return cmd
            except WindowsError:
                try:
                    cmd = _winreg.QueryValueEx(key,'UninstallString')[0]
                    if 'msiexec' in cmd.lower():
                        cmd = cmd.replace('/I','/X').replace('/i','/X')
                        args = shlex.split(cmd,posix=False)
                        if not '/q' in cmd.lower():
                            args.append('/q')
                        if not '/norestart' in cmd.lower():
                            args.append('/norestart')

                    else:
                        # separer commande et parametres pour eventuellement
                        cmd_arg = re.match(r'([^/]*?)\s+([/-].*)',cmd)
                        if cmd_arg:
                            (prog,arg) = cmd_arg.groups()
                            args = [ prog ]
                            args.extend(shlex.split(arg,posix=False))
                        # mozilla et autre
                        # si pas de "" et des espaces et pas d'option, alors encadrer avec des quotes
                        elif not(' -' in cmd or ' /' in cmd) and ' ' in cmd:
                            args = [ cmd ]
                        else:
                        #sinon splitter sur les paramètres
                            args = shlex.split(cmd,posix=False)

                        # remove double quotes if any
                        if args[0].startswith('"') and args[0].endswith('"') and (not "/" in cmd or not "--" in cmd):
                            args[0] = args[0][1:-1]

                        if ('spuninst' in cmd.lower()):
                            if not ' /quiet' in cmd.lower():
                                args.append('/quiet')
                        elif ('uninst' in cmd.lower() or 'helper.exe' in cmd.lower()) :
                            if not ' /s' in cmd.lower():
                                args.append('/S')
                        elif ('unins000' in cmd.lower()):
                            if not ' /silent' in cmd.lower():
                                args.append('/silent')
                    return args
                except WindowsError:
                    is_msi = _winreg.QueryValueEx(key,'WindowsInstaller')[0]
                    if is_msi == 1:
                        return u'msiexec /quiet /norestart /X %s' % guid
                    else:
                        raise

    try:
        return get_fromkey("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
    except:
        if platform.machine() == 'AMD64':
            return get_fromkey("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        else:
            raise


def installed_softwares(keywords='',uninstallkey=None):
    """return list of installed software from registry (both 32bit and 64bit

    Args;
        keywords (str or list): string to lookup in key, display_name or publisher fields
        uninstallkey : filter on a specific uninstall key instead of fuzzy search

    Returns
        dict: {'key', 'name', 'version', 'install_date', 'install_location'
                     'uninstall_string', 'publisher','system_component'}

    >>> softs = installed_softwares('libre office')
    >>> if softs:
    ...     for soft in softs:
    ...         print uninstall_cmd(soft['key'])
    ???
    """
    def check_words(target,words):
        mywords = target.lower()
        result = not words or mywords
        for w in words:
            result = result and w in mywords
        return result

    def list_fromkey(uninstall):
        result = []
        os_encoding=locale.getpreferredencoding()
        with reg_openkey_noredir(_winreg.HKEY_LOCAL_MACHINE,uninstall) as key:
            if isinstance(keywords,str) or isinstance(keywords,unicode):
                mykeywords = keywords.lower().split()
            else:
                mykeywords = [ ensure_unicode(k).lower() for k in keywords ]

            i = 0
            while True:
                try:
                    subkey = _winreg.EnumKey(key, i).decode(os_encoding)
                    appkey = reg_openkey_noredir(_winreg.HKEY_LOCAL_MACHINE,"%s\\%s" % (uninstall,subkey.encode(os_encoding)))
                    display_name = reg_getvalue(appkey,'DisplayName','')
                    display_version = reg_getvalue(appkey,'DisplayVersion','')
                    install_date = reg_getvalue(appkey,'InstallDate','')
                    install_location = reg_getvalue(appkey,'InstallLocation','')
                    uninstallstring = reg_getvalue(appkey,'UninstallString','')
                    publisher = reg_getvalue(appkey,'Publisher','')
                    if reg_getvalue(appkey,'ParentKeyName','') == 'OperatingSystem' or reg_getvalue(appkey,'SystemComponent',0) == 1:
                        system_component = 1
                    else:
                        system_component = 0
                    if (uninstallkey is None and display_name and check_words(subkey+' '+display_name+' '+publisher,mykeywords)) or\
                            (uninstallkey is not None and (subkey == uninstallkey)):
                        result.append({'key':subkey,
                            'name':display_name,
                            'version':display_version,
                            'install_date':install_date,
                            'install_location':install_location,
                            'uninstall_string':uninstallstring,
                            'publisher':publisher,
                            'system_component':system_component,})
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
        so that the application is displayed in Control Panel / Programs and features

    """
    if not uninstallkey:
        raise Exception('No uninstall key provided')
    if not uninstallstring:
        raise Exception('No uninstallstring provided')
    if iswin64() and not win64app:
        root = "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    else:
        root = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    with reg_openkey_noredir(_winreg.HKEY_LOCAL_MACHINE,"%s\\%s" % (root,uninstallkey.encode(locale.getpreferredencoding())),
           sam=_winreg.KEY_ALL_ACCESS,create_if_missing=True) as appkey:
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


def register_windows_uninstall(package_entry):
    """Add a windows registry key for custom installer"""
    register_uninstall(
        package_entry.package,
        'wapt-get uninstall %s' % package_entry.package,
        display_name=package_entry.description,
        display_version=package_entry.version,
        publisher=package_entry.maintainer)


def unregister_uninstall(uninstallkey,win64app=False):
    """Remove uninstall method from registry"""
    if not uninstallkey:
        raise Exception('No uninstall key provided')
    if iswin64():
        if not win64app:
            root = "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"+uninstallkey
        else:
            root = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"+uninstallkey
        try:
            _winreg.DeleteKeyEx(_winreg.HKEY_LOCAL_MACHINE,root.encode(locale.getpreferredencoding()))
        except WindowsError,e:
            logger.warning(u'Unable to remove key %s, error : %s' % (ensure_unicode(root),ensure_unicode(e)))

    else:
        root = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"+uninstallkey
        try:
            _winreg.DeleteKey(_winreg.HKEY_LOCAL_MACHINE,root.encode(locale.getpreferredencoding()))
        except WindowsError,e:
            logger.warning(u'Unable to remove key %s, error : %s' % (ensure_unicode(root),ensure_unicode(e)))

wincomputername = win32api.GetComputerName
windomainname = win32api.GetDomainName


def networking():
    """return a list of (iface,mac,{addr,broadcast,netmask})

    """
    import netifaces
    ifaces = netifaces.interfaces()
    local_ips = socket.gethostbyname_ex(socket.gethostname())[2]

    res = []
    for i in ifaces:
        params = netifaces.ifaddresses(i)
        if netifaces.AF_LINK in params and params[netifaces.AF_LINK][0]['addr'] and not params[netifaces.AF_LINK][0]['addr'].startswith('00:00:00'):
            iface = {'iface':i,'mac':params
            [netifaces.AF_LINK][0]['addr']}
            if netifaces.AF_INET in params:
                iface.update(params[netifaces.AF_INET][0])
                iface['connected'] = 'addr' in iface and iface['addr'] in local_ips
            res.append( iface )
    return res


# from http://stackoverflow.com/questions/2017545/get-memory-usage-of-computer-in-windows-with-python
def memory_status():
    """Return system memory statistics

    """
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

        def __init__(self):
            # have to initialize this to the size of MEMORYSTATUSEX
            self.dwLength = ctypes.sizeof(self)
            super(MEMORYSTATUSEX, self).__init__()

    stat = MEMORYSTATUSEX()
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
        return stat
    else:
        raise Exception('Error in function GlobalMemoryStatusEx')


def dmi_info():
    """Hardware System information from BIOS estracted with dmidecode

        Convert dmidecode -q output to python dict

    Returns:
        dict

    >>> dmi = dmi_info()
    >>> 'UUID' in dmi['System_Information']
    True
    >>> 'Product_Name' in dmi['System_Information']
    True
    """

    result = {}
    try:
        dmiout = run('dmidecode -q',shell=False)
        new_section = True
        for l in dmiout.splitlines():
            if not l.strip() or l.startswith('#'):
                new_section = True
                continue

            if not l.startswith('\t') or new_section:
                currobject={}
                key = l.strip().replace(' ','_')
                # already here... so add as array...
                if (key in result):
                    if not isinstance(result[key],list):
                        result[key] = [result[key]]
                    result[key].append(currobject)
                else:
                    result[key]  = currobject
                if l.startswith('\t'):
                    print l
            else:
                if not l.startswith('\t\t'):
                    currarray = []
                    if ':' in l:
                        (name,value)=l.split(':',1)
                        currobject[name.strip().replace(' ','_')]=value.strip()
                    else:
                        print "Error in line : %s" % l
                else:
                    # first line of array
                    if not currarray:
                        currobject[name.strip().replace(' ','_')]=currarray
                    currarray.append(l.strip())
            new_section = False
        if not 'System_Information' in result or not 'UUID' in result['System_Information']:
            result = wmi_info_basic()
    except:
        # dmidecode fails on some BIOS.
        # TODO : fall back to wmi for most impirtant parameters
        result = wmi_info_basic()
    return result


def win_startup_info():
    """Return the application started at boot or login"""
    result = {}
    with reg_openkey_noredir(HKEY_LOCAL_MACHINE,makepath('Software','Microsoft','Windows','CurrentVersion','Run')) as run_key:
        for key in reg_enum_subkeys(run_key):
            print key



def wmi_info(keys=['Win32_ComputerSystem','Win32_ComputerSystemProduct','Win32_BIOS','Win32_NetworkAdapter','Win32_Printer','Win32_VideoController']):
    """Get WMI machine informations as dictionaries

    """
    result = {}
    import wmi
    wm = wmi.WMI()
    for key in keys:
        cs = getattr(wm,key)()
        if len(cs)>1:
            na = result[key] = []
            for cs2 in cs:
                na.append({})
                for k in cs2.properties.keys():
                    prop = cs2.wmi_property(k)
                    if prop:
                        na[-1][k] = prop.Value
        else:
            result[key] = {}
            for k in cs[0].properties.keys():
                prop = cs[0].wmi_property(k)
                if prop:
                    result[key][k] = prop.Value

    """na = result['Win32_NetworkAdapter'] = []
    for cs in wm.Win32_NetworkAdapter():
        na.append({})
        for k in cs.properties.keys():
            prop = cs.wmi_property(k)
            if prop:
                na[-1][k] = prop.Value
    """
    return result


def wmi_info_basic():
    """Return uuid, serial, model, vendor from WMI

    Returns:
        dict: minimal informations for wapt registration

    >>> r = wmi_info_basic()
    >>> 'System_Information' in r
    True
    """
    res = run('echo "" | wmic PATH Win32_ComputerSystemProduct GET UUID,IdentifyingNumber,Name,Vendor /VALUE')
    wmiout = {}
    for line in res.splitlines():
        if line.strip():
            (key,value) = line.strip().split('=')
            wmiout[key] = value
    result = {
            u'System_Information':{
                u'UUID':wmiout[u'UUID'],
                u'Manufacturer':wmiout[u'Vendor'],
                u'Product_Name':wmiout[u'Name'],
                u'Serial_Number':wmiout[u'IdentifyingNumber'],
                }
            }
    return result

def critical_system_pending_updates():
    """Return list of not installed critical updates

    Returns:
        list: list of title of WSUS crititcal updates not applied

    """
    import win32com.client
    updateSession = win32com.client.Dispatch("Microsoft.Update.Session")
    updateSearcher = updateSession.CreateupdateSearcher()
    searchResult = updateSearcher.Search("IsInstalled=0 and Type='Software'")
    return [ update.Title for update in searchResult.Updates if update.MsrcSeverity == 'Critical']

def host_info():
    """Read main workstation inforamtions, returned as a dict

    Returns:
        dict: main properties of host, networking and windows system

    >>> hi = host_info()
    >>> 'computer_fqdn' in hi and 'connected_ips' in hi and 'computer_name' in hi and 'mac' in hi
    True
    """
    info = {}
    info['description'] = registry_readstring(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\services\LanmanServer\Parameters','srvcomment')

    #info['serial_nr'] = dmi_info.get('System_Information',{}).get('Serial_Number','')
    info['system_manufacturer'] = registry_readstring(HKEY_LOCAL_MACHINE,r'HARDWARE\DESCRIPTION\System\BIOS','SystemManufacturer')
    info['system_productname'] = registry_readstring(HKEY_LOCAL_MACHINE,r'HARDWARE\DESCRIPTION\System\BIOS','SystemProductName')

    info['computer_name'] =  wincomputername()
    info['computer_fqdn'] =  get_hostname()
    info['dns_domain'] = get_domain_fromregistry()
    info['workgroup_name'] = windomainname()

    try:
        import win32security
        domain_data = win32security.DsGetDcName()
        info['domain_name'] = domain_data.get('DomainName',None)
        info['domain_controller'] = domain_data.get('DomainControllerName',None)
        info['domain_controller_address'] = domain_data.get('DomainControllerAddress',None)
    except:
        info['domain_name'] = registry_readstring(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History','NetworkName',None)
        info['domain_controller'] = registry_readstring(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History','DCName',None)
        info['domain_controller_address'] = None

    info['networking'] = networking()
    info['connected_ips'] = socket.gethostbyname_ex(socket.gethostname())[2]
    info['mac'] = [ c['mac'] for c in networking() if 'mac' in c and 'addr' in c and c['addr'] in info['connected_ips']]
    info['win64'] = iswin64()
    info['description'] = registry_readstring(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\services\LanmanServer\Parameters','srvcomment')

    info['registered_organization'] =  registry_readstring(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion','RegisteredOrganization')
    info['registered_owner'] =  registry_readstring(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion','RegisteredOwner')
    win_info = keyfinder.windows_product_infos()
    info['windows_version'] =  platform.platform()
    info['windows_product_infos'] =  win_info
    info['installation_date'] = datetime.datetime.fromtimestamp(int(registry_readstring(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion','InstallDate','0'))).isoformat()

    info['cpu_name'] = registry_readstring(HKEY_LOCAL_MACHINE,r'HARDWARE\DESCRIPTION\System\CentralProcessor\0','ProcessorNameString','').strip()

    info['physical_memory'] = memory_status().ullTotalPhys
    info['virtual_memory'] = memory_status().ullTotalVirtual

    info['current_user'] = get_loggedinusers()
    return info


# from http://stackoverflow.com/questions/580924/python-windows-file-version-attribute
def get_file_properties(fname):
    r"""Read all properties of the given file return them as a dictionary.

    Args:
        fname : path to Windows executable or DLL

    Returns:
        dict: properties of executable

    >>> xp = get_file_properties(r'c:\windows\explorer.exe')
    >>> 'FileVersion' in xp and 'FileDescription' in xp
    True
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
        logger.warning(u"%s" % ensure_unicode(e))

    return props


# from http://stackoverflow.com/questions/3157955/get-msi-product-name-version-from-command-line
def get_msi_properties(msi_filename):
    r"""Return a dict of msi installer properties

    Args:
        msi_filename (str): path to msi file

    Returns:
        dict: properties of msi. at least there seems to be keys like
             'Manufacturer','ProductCode','ProductName','ProductVersion'

    >>> zprop = get_msi_properties(r'C:\tranquilit\wapt\tests\7z920.msi')
    >>> 'ProductVersion' in zprop and 'ProductCode' in zprop and 'ProductName' in zprop
    True
    """
    db = msilib.OpenDatabase(msi_filename, msilib.MSIDBOPEN_READONLY)
    view = db.OpenView ("SELECT * FROM Property")
    view.Execute(None)
    result = {}
    r = view.Fetch()
    while r:
        try:
            result[ensure_unicode(r.GetString(1))] = ensure_unicode(r.GetString(2))
        except:
            logger.warning(u"erreur pour %s" % ensure_unicode(r.GetString(0)))
        try:
            r = view.Fetch()
        except:
            break
    return result

# local user / groups management (from winsys examples)
def create_user (user, password,full_name=None,comment=None):
    """Creates a local user

    """
    user_info = dict (
      name = user,
      password = password,
      priv = win32netcon.USER_PRIV_USER,
      home_dir = None,
      comment = comment,
      full_name = full_name,
      flags = win32netcon.UF_SCRIPT,
      script_path = None,
      password_expired = 1
    )
    win32net.NetUserAdd(None, 1, user_info)

def create_group (group):
    """Creates a local group

    """
    group_info = dict (
      name = group
    )
    win32net.NetLocalGroupAdd (None, 0, group_info)

def add_user_to_group (user, group):
    """Add membership to a local group for a user

    """
    user_group_info = dict (
      domainandname = user
    )
    win32net.NetLocalGroupAddMembers (None, group, 3, [user_group_info])

def remove_user_from_group (user, group):
    """Remove membership from a local group for a user

    """
    win32net.NetLocalGroupDelMembers (None, group, [user])

def delete_user (user):
    """Delete a local user

    """
    try:
        win32net.NetUserDel (None, user)
    except win32net.error as error:
        errno, errctx, errmsg = error.args
        if errno != 2221: raise

def delete_group (group):
    """Delete a local user group

    """

    try:
        win32net.NetLocalGroupDel (None, group)
    except win32net.error as error:
        errno, errctx, errmsg = error.args
        if errno != 2220: raise

def local_users():
    """Returns local users

    >>> local_users()
    [u'Administrateur',
     u'ASPNET',
     u'cyg_user',
     u'install',
     u'Invit\xe9',
     u'newadmin',
     u'sshd',
     u'toto',
     u'UpdatusUser']
    >>>
    """
    return [u['name'] for u in win32net.NetUserEnum(None,2)[0]]

def local_groups():
    """Returns local groups

    >>> local_groups()
    [u'Administrateurs',
     u'Duplicateurs',
     u'IIS_IUSRS',
     u'Invit\xe9s',
     u'Lecteurs des journaux d\u2019\xe9v\xe9nements',
     u'Op\xe9rateurs de chiffrement',
     u'Op\xe9rateurs de configuration r\xe9seau',
     u'Op\xe9rateurs de sauvegarde',
     u'Utilisateurs',
     u'Utilisateurs avec pouvoir',
     u'Utilisateurs de l\u2019Analyseur de performances',
     u'Utilisateurs du Bureau \xe0 distance',
     u'Utilisateurs du journal de performances',
     u'Utilisateurs du mod\xe8le COM distribu\xe9',
     u'IIS_WPG',
     u'test']
     """
    return [g['name'] for g in win32net.NetLocalGroupEnum(None,0)[0]]

def local_admins():
    """List local users who are local administrators

    >>> local_admins()
    [u'Administrateur', u'cyg_user', u'install', u'toto']    """
    return [g['name'] for g  in win32net.NetUserEnum(None,2)[0] if g['priv'] == win32netcon.USER_PRIV_ADMIN ]


def adjust_current_privileges(priv, enable = 1):
    # Get the process token.
    htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_ALL_ACCESS)
    # Get the ID for the system shutdown privilege.
    id = win32security.LookupPrivilegeValue(None, priv)
    # Now obtain the privilege for this process.
    # Create a list of the privileges to be added.
    if enable:
        new_privileges = [(id, win32con.SE_PRIVILEGE_ENABLED)]
    else:
        new_privileges = [(id, 0)]
    # and make the adjustment.
    win32security.AdjustTokenPrivileges(htoken, False, new_privileges)

def reboot_machine(message="Machine Rebooting", timeout=30, force=0, reboot=1):
    r"""Reboot the current host within specified timeout, display a message to the user

    This can not be cancelled bu the user.

    Args:
        message (str) : displayed to user to warn him
        timeout (int) : timeout in seconds before proceeding
        force (int) : If this parameter is 1, applications with unsaved changes
                        are to be forcibly closed.
                      If this parameter is 0, the system displays a dialog box instructing
                        the user to close the applications.
        reboot (int) : 1 to reboot after shutdown; If 0, the system halt.

    """
    adjust_current_privileges(win32con.SE_SHUTDOWN_NAME)
    try:
        win32api.InitiateSystemShutdown(None, message, timeout, force, reboot)
    finally:
        # Now we remove the privilege we just added.
        adjust_current_privileges(win32con.SE_SHUTDOWN_NAME, 0)

# some const
programfiles = programfiles()
programfiles32 = programfiles32()
programfiles64 = programfiles64()

# some shortcuts
isfile=os.path.isfile
isdir=os.path.isdir

def remove_file(path):
    r"""Try to remove a single file
        log a warning msg if file doesn't exist
        log a critical msg if file can't be removed

    Args:
        path (str): path to file

    >>> remove_file(r'c:\tmp\fc.txt')

    """
    if os.path.isfile(path):
        try:
            os.unlink(path)
        except Exception as e:
            logger.critical('Unable to remove file %s : error %s' %(path,e))
    else:
        logger.warning(u"File %s doesn't exist, so not removed" % (path))

def remove_tree(*args, **kwargs):
    r"""Convenience function to delete a directory tree, with any error
    ignored by default.  Pass ignore_errors=False to access possible
    errors.

    Args:
        path (str): path to directory to remove
        ignore_errors (boolean) : default to True to ignore exceptions on children deletion
        onerror (func) : hook called with (os.path.islink, path, sys.exc_info())
                         on each delete exception. Should raise if stop is required.

    >>> remove_tree(r'c:\tmp\target')
    """
    if 'ignore_errors' not in kwargs:
        kwargs['ignore_errors'] = True
    return shutil.rmtree(*args, **kwargs)

def makepath(a, *p):
    r"""Create a path given the components passed, but with saner defaults
    than os.path.join.

    In particular, removes ending path separators (backslashes) from components

    >>> makepath('c:',programfiles)
    'C:\\Program Files'
    """
    p = [e.lstrip(os.path.sep) for e in p]
    return os.path.join(a, *p)

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
    """Start a service by its service name

    """
    logger.debug('Starting service %s' % service_name)
    win32serviceutil.StartService(service_name)
    return win32serviceutil.WaitForServiceStatus(service_name, win32service.SERVICE_RUNNING, waitSecs=4)


def service_stop(service_name):
    logger.debug('Stopping service %s' % service_name)
    win32serviceutil.StopService(service_name)
    win32api.Sleep(2000)
    return win32serviceutil.WaitForServiceStatus(service_name, win32service.SERVICE_STOPPED, waitSecs=4)


def service_is_running(service_name):
    """Return True if the service is running

    >>> state = service_is_running('waptservice')
    """
    return win32serviceutil.QueryServiceStatus(service_name)[1] == win32service.SERVICE_RUNNING

def service_is_stopped(service_name):
    """Return True if the service is running

    >>> state = service_is_running('waptservice')
    """
    return win32serviceutil.QueryServiceStatus(service_name)[1] == win32service.SERVICE_STOPPED

def user_appdata():
    r"""Return the roaming appdata profile of current user

    Returns:
        str: path like u'C:\\Users\\username\\AppData\\Roaming'
    """
    return ensure_unicode((winshell.get_path(shellcon.CSIDL_APPDATA)))


def mkdirs(path):
    """Create directory path if it doesn't exists yet
        Creates intermediate directories too.

    """
    if not os.path.isdir(path):
        os.makedirs(path)

def user_desktop():
    r"""return path to current logged in user desktop

    >>> user_desktop()
    u'C:\\Users\\htouvet\\Desktop'
    """
    return unicode(desktop(0))


def common_desktop():
    r"""return path to public desktop (visible by all users)

    >>> common_desktop()
    u'C:\\Users\\Public\\Desktop'
    """
    return unicode(desktop(1))


def register_dll(dllpath):
    """Register a COM/OLE server DLL in registry (similar to regsvr32)

    """
    dll = ctypes.windll[dllpath]
    result = dll.DllRegisterServer()
    logger.info('DLL %s registered' % dllpath)
    if result:
        raise Exception(u'Register DLL %s failed, code %i' % (dllpath,result))


def unregister_dll(dllpath):
    """Unregister a COM/OLE server DLL from registry

    """
    dll = ctypes.windll[dllpath]
    result = dll.DllUnregisterServer()
    logger.info('DLL %s unregistered' % dllpath)
    if result:
        raise Exception(u'Unregister DLL %s failed, code %i' % (dllpath,result))


def add_to_system_path(path):
    """Add path to the global search PATH environment variable if it is not yet

    """
    with reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',sam=KEY_READ | KEY_WRITE) as key:
        system_path = reg_getvalue(key,'Path').split(';')
        if not path.lower() in [p.lower() for p in system_path]:
            system_path.append(path)
            reg_setvalue(key,'Path',';'.join(system_path),type=REG_EXPAND_SZ)
            win32gui.SendMessageTimeout(win32con.HWND_BROADCAST, win32con.WM_SETTINGCHANGE, 0, "Environment", win32con.SMTO_ABORTIFHUNG, 5000 )
    return system_path


def remove_from_system_path(path):
    """Remove a path from the global search PATH environment variable if it is set

    """
    with reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',sam=KEY_READ | KEY_WRITE) as key:
        system_path = reg_getvalue(key,'Path').split(';')
        if path.lower() in [p.lower() for p in system_path]:
            for p in system_path:
                if p.lower() == path.lower():
                    system_path.remove(p)
                    break
            reg_setvalue(key,'Path',';'.join(system_path),type=REG_EXPAND_SZ)
            win32gui.SendMessageTimeout(win32con.HWND_BROADCAST, win32con.WM_SETTINGCHANGE, 0, "Environment", win32con.SMTO_ABORTIFHUNG, 5000 )
    return system_path


def set_environ_variable(name,value,type=REG_EXPAND_SZ):
    r"""Add or update a system wide persistent environment variable

    .>>> set_environ_variable('WAPT_HOME','c:\\wapt')
    .>>> import os
    .>>> os.environ['WAPT_HOME']
    'c:\\wapt'
    """
    with reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
            sam=KEY_READ | KEY_WRITE) as key:
        reg_setvalue(key,name,value,type=type)
    # force to get new environ variable, as it is not reloaded immediately.
    os.environ[name] = value
    win32gui.SendMessageTimeout(win32con.HWND_BROADCAST, win32con.WM_SETTINGCHANGE, 0, "Environment", win32con.SMTO_ABORTIFHUNG, 5000 )


def unset_environ_variable(name):
    r"""Remove a system wide persistent environment variable if it exist. Fails silently if it doesn't exist

    """
    with reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
            sam=KEY_READ | KEY_WRITE) as key:
        result = reg_delvalue(key,name)
    # force to get new environ variable, as it is not reloaded immediately.
    if name in os.environ:
        del(os.environ[name])
        wwin32gui.SendMessageTimeout(win32con.HWND_BROADCAST, win32con.WM_SETTINGCHANGE, 0, "Environment", win32con.SMTO_ABORTIFHUNG, 5000 )
    return result


def get_task(name):
    """Return an instance of PyITask given its name (without .job)

    """
    ts = pythoncom.CoCreateInstance(taskscheduler.CLSID_CTaskScheduler,None,
                                    pythoncom.CLSCTX_INPROC_SERVER,
                                    taskscheduler.IID_ITaskScheduler)
    if '%s.job' % name not in ts.Enum():
        raise KeyError("%s doesn't exists" % name)

    task = ts.Activate(name)
    return task


def run_task(name):
    """Launch immediately the Windows Scheduled task

    """
    get_task(name).Run()


def task_exists(name):
    """Return true if a sheduled task names 'name.job' is defined

    """
    ts = pythoncom.CoCreateInstance(taskscheduler.CLSID_CTaskScheduler,None,
                                    pythoncom.CLSCTX_INPROC_SERVER,
                                    taskscheduler.IID_ITaskScheduler)
    return '%s.job' % name in ts.Enum()


def delete_task(name):
    """Removes a Windows scheduled task

    Args:
        name (str) : name of the tasks as created in create_daily_task
    """
    ts = pythoncom.CoCreateInstance(taskscheduler.CLSID_CTaskScheduler,None,
                                    pythoncom.CLSCTX_INPROC_SERVER,
                                    taskscheduler.IID_ITaskScheduler)
    if '%s.job' % name not in ts.Enum():
        raise KeyError("%s doesn't exists" % name)
    ts.Delete(name)


def disable_task(name):
    """Disable a Windows scheduled task"""
    return run('schtasks /Change /TN "%s" /DISABLE' % name)
    """
    task = get_task(name)
    task.SetFlags(task.GetFlags() | taskscheduler.TASK_FLAG_DISABLED)
    pf = task.QueryInterface(pythoncom.IID_IPersistFile)
    pf.Save(None,1)
    return task
    """


def enable_task(name):
    """Enable (start of) a Windows scheduled task

    Args:
        name (str) : name of the tasks as created in create_daily_task
    """
    return run('schtasks /Change /TN "%s" /ENABLE' % name)

    """
    task = get_task(name)
    task.SetFlags(task.GetFlags() & ~taskscheduler.TASK_FLAG_DISABLED)
    pf = task.QueryInterface(pythoncom.IID_IPersistFile)
    pf.Save(None,1)
    return task
    """


def create_daily_task(name,cmd,parameters, max_runtime=10, repeat_minutes=None, start_hour=None, start_minute=None):
    """creates a Windows scheduled daily task and activate it.

    Args:
        name (str): name of task for reference
        cmd(str) :  command line
        parameters (str) : arguments to append to cmd
        max_runtime (int): maximum running time in minutes
        repeat_minutes (int): interval in minutes between run
        start_hour   (int): hour time of start
        start_minute (int): minute time of start

    Returns:
        PyITask: scheduled task
    """
    ts = pythoncom.CoCreateInstance(taskscheduler.CLSID_CTaskScheduler,None,
                                    pythoncom.CLSCTX_INPROC_SERVER,
                                    taskscheduler.IID_ITaskScheduler)

    if '%s.job' % name not in ts.Enum():
        task = ts.NewWorkItem(name)

        task.SetApplicationName(cmd)
        task.SetParameters(parameters)
        task.SetAccountInformation('', None)
        if max_runtime:
            task.SetMaxRunTime(max_runtime * 60*1000)
        #task.SetFlags(task.GetFlags() | taskscheduler.TASK_FLAG_)
        ts.AddWorkItem(name, task)
        run_time = time.localtime(time.time() + 300)
        tr_ind, tr = task.CreateTrigger()
        tt = tr.GetTrigger()
        tt.Flags = 0
        tt.BeginYear = int(time.strftime('%Y', run_time))
        tt.BeginMonth = int(time.strftime('%m', run_time))
        tt.BeginDay = int(time.strftime('%d', run_time))
        if start_minute is None:
            tt.StartMinute = int(time.strftime('%M', run_time))
        else:
            tt.StartMinute = start_minute
        if start_hour is None:
            tt.StartHour = int(time.strftime('%H', run_time))
        else:
            tt.StartHour = start_hour
        tt.TriggerType = int(taskscheduler.TASK_TIME_TRIGGER_DAILY)
        if repeat_minutes:
            tt.MinutesInterval = repeat_minutes
            tt.MinutesDuration = 24*60
        tr.SetTrigger(tt)
        pf = task.QueryInterface(pythoncom.IID_IPersistFile)
        pf.Save(None,1)
        #task.Run()
    else:
        raise KeyError("%s already exists" % name)

    task = ts.Activate(name)
    #exit_code, startup_error_code = task.GetExitCode()
    return task


def get_current_user():
    r"""Get the login name for the current user.

    >>> get_current_user()
    u'htouvet'
    """
    import ctypes
    MAX_PATH = 260                  # according to a recent WinDef.h
    name = ctypes.create_unicode_buffer(MAX_PATH)
    namelen = ctypes.c_int(len(name))  # len in chars, NOT bytes
    if not ctypes.windll.advapi32.GetUserNameW(name, ctypes.byref(namelen)):
        raise ctypes.WinError()
    return ensure_unicode(name.value)


def get_language():
    """Get the default locale like fr, en, pl etc..  etc

    >>> get_language()
    'fr'
    """
    return locale.getdefaultlocale()[0].split('_')[0]


def get_appath(exename):
    r"""Get the registered application location from registry given its executable name

    >>> get_appath('firefox.exe')
    u'C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe'
    >>> get_appath('wapt-get.exe')
    u'C:\\wapt\\wapt-get.exe'
    """
    if iswin64():
        with reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\%s' % exename) as key:
            return reg_getvalue(key,None)
    else:
        with reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\%s' % exename) as key:
            return reg_getvalue(key,None)



def getsilentflags(installer_path):
    """Detect the type of installer and returns silent silent install flags

    Args:
        installer_path (str): filepath to installer

    Returns:
        str: detected command line flags to append to installer

    >>> getsilentflags(r'C:\tranquilit\wapt\tests\7z920.msi')
    '/q /norestart'
    """
    (product_name,ext) = os.path.splitext(installer_path)
    ext = ext.lower()
    if ext=='.exe':
        silentflag = '/VERYSILENT'
        props = get_file_properties(installer_path)
        if props.get('InternalName','').lower() == 'sfxcab.exe':
            silentflag = '/quiet'
        elif props.get('InternalName','').lower() == '7zs.sfx':
            silentflag = '/s'
        elif props.get('InternalName','').lower() == 'setup launcher':
            silentflag = '/s'
        elif props.get('InternalName','').lower() == 'wextract':
            silentflag = '/Q'
        else:
            content = open(installer_path,'rb').read(600000)
            if 'Inno.Setup' in content:
                silentflag = '/VERYSILENT'
            elif 'Quiet installer' in content:
                silentflag = '-q'
            elif 'nsis.sf.net' in content or 'Nullsoft.NSIS' in content:
                silentflag = '/S'

    elif ext=='.msi':
        silentflag = '/q /norestart'
    elif ext=='.msu':
        silentflag = '/quiet /norestart'
    else:
        silentflag = ''
    return silentflag


def getproductprops(installer_path):
    """get the properties (product, version, description...) of an exe file or a msi file

    Args:
        installer_path (str): filepath to exe or msi file

    Returns:
        dict: {'product','description','version','publisher'}

    """
    (product_name,ext) = os.path.splitext(installer_path.lower())
    product_name = os.path.basename(product_name)
    product_desc = product_name
    version ='0.0.0'
    publisher =''

    if ext=='.exe':
        props = get_file_properties(installer_path)
        product_name = props['ProductName'] or product_desc
    elif ext=='.msi':
        props = get_msi_properties(installer_path)
        product_name = props['ProductName'] or props['FileDescription'] or product_desc
    else:
        props = {}

    if 'Manufacturer' in props and props['Manufacturer']:
        publisher = props['Manufacturer']
    elif 'CompanyName' in props and props['CompanyName']:
        publisher = props['CompanyName']

    if publisher:
        product_desc = "%s (%s)" % (product_name,publisher)
    else:
        product_desc = "%s" % (product_name,)

    if 'FileVersion' in props and props['FileVersion']:
        version = props['FileVersion']
    elif 'ProductVersion' in props and props['ProductVersion']:
        version = props['ProductVersion']

    props['product'] = product_name
    props['description'] = product_desc
    props['version'] = version
    props['publisher'] = publisher
    return props



def need_install(key,min_version=None,force=False):
    """Return True if the software with key can be found in uninstall registry
        and the registred version is equal or greater than min_version

    Args:
        key (str) : uninstall key
        min_version (str) : minimum version or None if don't check verion
    Returns:
        boolean

    """
    if force or not key:
        return True
    else:
        current = installed_softwares(uninstallkey=key)
        for soft in current:
            if not min_version or Version(soft['version']) >= Version(min_version):
                return False
        return True

def install_msi_if_needed(msi,min_version=None,killbefore=[]):
    """Install silently the supplied msi file, and add the uninstall key to
    global uninstall key list

    uninstall key, min_version and silent flags are guessed from msi file.

    Raises an error if, after the msi install, the uninstall key is not found in registry.

    The matching is done on key

    Args:
        msi (str) : path to the MSI file
        min_version (str) : if installed version is equal or gretaer than this, don't install
                            if not provided, guess it from exe setup file properties.
        kill_before (list of str) : processes to kill before setup, to avoid file locks
                                    issues.

    Returns:
        None

    """
    if not isfile(msi):
        error('msi file %s not found in package' % msi)
    key = get_msi_properties(msi)['ProductCode']
    # will try to add key in the caller's (setup.py) uninstallkey list
    import inspect
    caller_globals = inspect.stack()[1][0].f_globals
    WAPT = caller_globals.get('WAPT',None)
    force = WAPT and WAPT.options.force

    if not min_version:
        min_version = getproductprops(msi)['version']

    if need_install(key,min_version=min_version,force=force):
        if killbefore:
            killalltasks(killbefore)
        run(r'msiexec /norestart /q /i "%s"' % msi)
        if not installed_softwares(uninstallkey=key):
            error('MSI %s has been installed but the uninstall key %s can not be found' % (msi,key))
    else:
        print('MSI %s already installed. Skipping msiexec' % msi)
    if key:
        if 'uninstallkey' in caller_globals and not key in caller_globals['uninstallkey']:
            caller_globals['uninstallkey'].append(key)

def install_exe_if_needed(exe,silentflags='',key=None,min_version=None,killbefore=[]):
    """Install silently the supplied setup executable file, and add the uninstall key to
    global uninstallkey list if it is defined.

    Check if already installed at the supllied min_version.

    Kill the processes in killbefore list before launching the setup.

    Raises an error if, after the setup install, the uninstall key is not found in registry.

    Args:
        exe (str) : path to the setup exe file
        silentflags (str) : flags to append to the exe command line for silent install
                            if not provided, tries to guess them.
        key (str) : uninstall key to check in registry and to add to uninstallkey global list
        min_version (str) : if installed version is equal or gretaer than this, don't install
                            if not provided, guess it from exe setup file properties.
        kill_before (list of str) : processes to kill before setup, to avoid file locks
                                    issues.
    Returns:
        None

    """
    if not isfile(exe):
        error('setup exe file %s not found in package' % exe)
    if not silentflags:
        silentflags = getsilentflags(exe)
    if not min_version:
        min_version = getproductprops(exe)['version']

    import inspect
    caller_globals = inspect.stack()[1][0].f_globals
    WAPT = caller_globals.get('WAPT',None)
    force = WAPT and WAPT.options.force

    if need_install(key,min_version=min_version,force=force):
        if killbefore:
            killalltasks(killbefore)
        run(r'"%s" %s' % (exe,silentflags))
        if key and not installed_softwares(uninstallkey=key):
            error('Setup %s has been ran but the uninstall key %s can not be found' % (exe,key))
    else:
        print('Exe setup %s already installed. Skipping' % exe)
    if key:
        # will try to add key in the caller's (setup.py) uninstallkey list
        if 'uninstallkey' in caller_globals and not key in caller_globals['uninstallkey']:
            caller_globals['uninstallkey'].append(key)

def local_desktops():
    """Return a list of all local user's desktops paths

    Args:
        None

    Returns:
        list : list of desktop path

    >>> local_desktops()
    [u'C:\\Windows\\ServiceProfiles\\LocalService\\Desktop',
     u'C:\\Windows\\ServiceProfiles\\NetworkService\\Desktop',
     u'C:\\Users\\install\\Desktop',
     u'C:\\Users\\UpdatusUser\\Desktop',
     u'C:\\Users\\administrateur\\Desktop',
     u'C:\\Users\\htouvet-adm\\Desktop']
    """
    result = []
    profiles_path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    key = reg_openkey_noredir(HKEY_LOCAL_MACHINE,profiles_path)

    import _winreg
    import locale
    os_encoding=locale.getpreferredencoding()
    i = 0
    while True:
        try:
            profid = _winreg.EnumKey(key, i).decode(os_encoding)
            prof_key = reg_openkey_noredir(_winreg.HKEY_LOCAL_MACHINE,"%s\\%s"%(profiles_path,profid))
            image_path = reg_getvalue(prof_key,'ProfileImagePath','')
            if isdir(makepath(image_path,'Desktop')):
                result.append(makepath(image_path,'Desktop'))
            if isdir(makepath(image_path,'Bureau')):
                result.append(makepath(image_path,'Bureau'))

            i += 1
        except WindowsError,e:
            # WindowsError: [Errno 259] No more data is available
            if e.winerror == 259:
                break
            else:
                raise
    return result

def datetime2isodate(adatetime = None):
    if not adatetime:
        adatetime = datetime.datetime.now()
    assert(isinstance(adatetime,datetime.datetime))
    return adatetime.isoformat()


def httpdatetime2isodate(httpdate):
    """convert a date string as returned in http headers or mail headers to isodate
    >>> import requests
    >>> last_modified = requests.head('http://wapt/wapt/Packages',headers={'cache-control':'no-cache','pragma':'no-cache'}).headers['last-modified']
    >>> len(httpdatetime2isodate(last_modified)) == 19
    True
    """
    return datetime2isodate(datetime.datetime(*email.utils.parsedate(httpdate)[:6]))


def isodate2datetime(isodatestr):
    # we remove the microseconds part as it is not working for python2.5 strptime
    return datetime.datetime.strptime(isodatestr.split('.')[0] , "%Y-%m-%dT%H:%M:%S")


def time2display(adatetime):
    return adatetime.strftime("%Y-%m-%d %H:%M")


def hours_minutes(hours):
    if hours is None:
        return None
    else:
        return "%02i:%02i" % ( int(hours) , int((hours - int(hours)) * 60.0))


def fileisodate(filename):
    return datetime.datetime.fromtimestamp(os.stat(filename).st_mtime).isoformat()


def dateof(adatetime):
    return adatetime.replace(hour=0,minute=0,second=0,microsecond=0)



class EWaptSetupException(Exception):
    pass

CalledProcessError = subprocess.CalledProcessError


def error(reason):
    """Raise a WAPT fatal error"""
    raise EWaptSetupException(u'Fatal error : %s' % reason)

"""Specific parameters for install scripts"""
params = {}
control = PackageEntry()


if __name__=='__main__':
    import doctest
    import sys
    reload(sys)
    sys.setdefaultencoding("UTF-8")
    import doctest
    doctest.ELLIPSIS_MARKER = '???'
    doctest.testmod(optionflags=doctest.ELLIPSIS)
    sys.exit(0)

