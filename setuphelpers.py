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
__version__ = "0.8.22"
import os
import sys
import logging
import tempfile
import shutil

# use backported subprocess from python 3.2
#import subprocess32 as subprocess
#from subprocess32 import Popen, PIPE

import _subprocess
import subprocess
from subprocess import Popen, PIPE
import psutil

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
import pythoncom
from win32com.shell import shell, shellcon
from win32com.taskscheduler import taskscheduler
import locale
import types
import re
import threading
from types import ModuleType

from waptpackage import PackageEntry
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

def ensure_dir(f):
    """Be sure the directory of f exists on disk. Make it if not"""
    d = os.path.dirname(f)
    if not os.path.isdir(d):
        os.makedirs(d)

# from opsi
def ensure_unicode(data):
    ur"""Return a unicode string from data object
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
        if type(data) is WindowsError:
            return u"%s : %s" % (data.args[0], data.args[1].decode(sys.getfilesystemencoding()))
        if type(data) is UnicodeDecodeError:
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
        try:
            return unicode(data)
        except:
           pass
    except:
        return("Error in ensure_unicode / %s"%(repr(data)))

def create_shortcut(path, target='', arguments='', wDir='', icon=''):
    """Create a windows shortcut
          path - As what file should the shortcut be created?
          target - What command should the desktop use?
          arguments - What arguments should be supplied to the command?
          wdir - What folder should the command start in?
          icon - (filename, index) What icon should be used for the shortcut?
    >>> create_shortcut(r'c:\\tmp\\test.lnk',target='c:\\wapt\\wapt-get.exe')
    """
    ext = path[-3:]
    if ext == 'url':
        shortcut = file(path, 'w')
        shortcut.write('[InternetShortcut]\n')
        shortcut.write('URL=%s' % target)
        shortcut.close()
    else:
        winshell.CreateShortcut(path,target,arguments,wDir,(icon,0),'')

def create_desktop_shortcut(label, target='', arguments ='', wDir='', icon=''):
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    sc_path = os.path.join(desktop(1),label)
    if os.path.isfile(sc_path):
        os.remove(sc_path)
    create_shortcut(sc_path,target,arguments, wDir,icon)
    return sc_path


def create_user_desktop_shortcut(label, target='',arguments='', wDir='', icon=''):
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    sc_path = os.path.join(desktop(0),label)
    if os.path.isfile(sc_path):
        os.remove(sc_path)
    create_shortcut(sc_path,target,arguments,wDir,icon)
    return sc_path

def create_programs_menu_shortcut(label, target='', arguments='', wDir='', icon=''):
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    sc = os.path.join(start_menu(1),label)
    if os.path.isfile(sc):
        os.remove(sc)
    create_shortcut(sc,target,arguments,wDir,icon)
    return sc

def create_user_programs_menu_shortcut(label, target='', arguments='', wDir='', icon=''):
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    sc = os.path.join(start_menu(0),label)
    if os.path.isfile(sc):
        os.remove(sc)
    create_shortcut(sc,target,arguments,wDir,icon)
    return sc

def wgets(url,proxies=None):
    """Return the content of a remote resources as a String"""
    r = requests.get(url,proxies=proxies)
    if r.ok:
        return r.text
    else:
        r.raise_for_status()

def wget(url,target,printhook=None,proxies=None):
    r"""Copy the contents of a file from a given URL
    to a local file.
    >>> respath = wget('http://wapt.tranquil.it/wapt/tis-firefox_28.0.0-1_all.wapt','c:\\tmp\\test.wapt',proxies={'http':'proxy:3128'})
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

    httpreq = requests.get(url,stream=True, proxies=proxies, timeout=10)

    total_bytes = int(httpreq.headers['content-length'])
    # 1Mb max, 1kb min
    chunk_size = min([1024*1024,max([total_bytes/100,1000])])

    cnt = 0
    reporthook(last_downloaded,total_bytes)

    with open(os.path.join(dir,filename),'wb') as output_file:
        last_time_display = time.time()
        last_downloaded = 0
        if httpreq.ok:
            for chunk in httpreq.iter_content(chunk_size=chunk_size):
                output_file.write(chunk)
                if reporthook(cnt*len(chunk),total_bytes):
                    last_time_display = time.time()
                last_downloaded += len(chunk)
                cnt +=1
            if reporthook(last_downloaded,total_bytes):
                last_time_display = time.time()
        else:
            httpreq.raise_for_status()

    reporthook(last_downloaded,total_bytes)
    return os.path.join(dir,filename)

def filecopyto(filename,target):
    """Copy file from package temporary directory to target directory
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
            ov = get_file_properties(target)['FileVersion']
            nv = get_file_properties(filename)['FileVersion']
            logger.info(u'Replacing %s (%s) -> %s' % (ensure_unicode(target),ov,nv))
        else:
            logger.info(u'Replacing %s' % target)
    else:
        if os.path.splitext(target)[1] in ('.exe','.dll'):
            nv = get_file_properties(filename)['FileVersion']
            logger.info(u'Copying %s (%s)' % (ensure_unicode(target),nv))
        else:
            logger.info(u'Copying %s' % (ensure_unicode(target)))
    shutil.copy(filename,target)


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
                if os.path.isfile(dstname):
                    if onreplace(srcname,dstname) and oncopy('overwrites',srcname,dstname):
                        os.unlink(dstname)
                        shutil.copy2(srcname, dstname)
                else:
                    if oncopy('copy',srcname,dstname):
                        shutil.copy2(srcname, dstname)
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

def run(*cmd,**args):
    """Run the command cmd and return the output and error text
        shell=True is assumed
        timeout=600 (seconds) after that time, a TimeoutExpired is raised
        if return code of cmd is non zero, a CalledProcessError is raised
        on_write : called when a new line is printed on stdout or stderr by the subprocess
        accept_returncodes=[0,1601]

        pidlist : list wher to append
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

    if 'timeout' in args:
        timeout = args['timeout']
        del args['timeout']
    else:
        timeout = 10*60.0

    if not "shell" in args:
        args['shell']=True

    if not 'accept_returncodes' in args:
        # 1603 : souvent renvoyé quand déjà installé.
        # 3010 : reboot required.
        valid_returncodes = [0,1603,3010]
    else:
        valid_returncodes = args['accept_returncodes']
        del args['accept_returncodes']

    if 'pidlist' in args and isinstance(args['pidlist'],list):
        pidlist = args['pidlist']
        args.pop('pidlist')
    else:
        pidlist = []

    proc = psutil.Popen(*cmd, bufsize=1, stdout=PIPE, stderr=PIPE,**args)
    # keep track of launched pid if required by providing a pidlist argument to run
    if not proc.pid in pidlist:
        pidlist.append(proc.pid)

    stdout_worker = RunReader(worker, proc.stdout,args.get('on_write',None))
    stderr_worker = RunReader(worker, proc.stderr,args.get('on_write',None))
    stdout_worker.start()
    stderr_worker.start()
    stdout_worker.join(timeout)
    if stdout_worker.is_alive():
        # kill the task and all subtasks
        if proc.pid in pidlist:
            pidlist.remove(proc.pid)
            killtree(proc.pid)
        raise TimeoutExpired(cmd,timeout,''.join(output))
    stderr_worker.join(timeout)
    if stderr_worker.is_alive():
        if proc.pid in pidlist:
            pidlist.remove(proc.pid)
            killtree(proc.pid)
        raise TimeoutExpired(cmd,timeout,''.join(output))
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
    """Runs the command and wait for it termination
    returns output, don't raise exception if exitcode is not null but return '' """
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
    """Check if a process is running, example isrunning('explorer')"""
    processname = processname.lower()
    for p in psutil.process_iter():
        try:
            if p.name().lower() == processname or p.name().lower() == processname+'.exe':
                return True
        except (psutil.AccessDenied,psutil.NoSuchProcess):
            pass
    return False

def killalltasks(exenames,include_children=True):
    """Kill the task by their exename : example killalltasks('explorer.exe') """
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
      run(u'taskkill /t /im "%s" /f /FI "STATUS eq RUNNING"' % c)
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

def processnames_list():
    """return all process name of running processes in lower case"""
    return list(set([p.name().lower() for p in psutil.get_process_list()]))

def find_processes(process_name):
    """Return list of Process having process_name"""
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
    """Return host fully qualified domain name in lower case"""
    return socket.getfqdn().lower()

def get_domain_fromregistry():
    """Return main DNS domain of the computer"""
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

def reg_openkey_noredir(key, sub_key, sam=_winreg.KEY_READ,create_if_missing=False):
    """Open the registry key\subkey with access rights sam
        Returns a key handle for reg_getvalue and reg_set_value
       key     : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
       sub_key : string like "software\\microsoft\\windows\\currentversion"
       sam     : a boolean comination of KEY_READ | KEY_WRITE
       create_if_missing : True to create the sub_key if not exists, access rights will include KEY_WRITE
    """
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

def reg_getvalue(key,name,default=None):
    """Return the value of specified name inside 'key' folder
         key  : handle of registry key as returned by reg_openkey_noredir()
         name : value name or None for key default value
         default : value returned if specified name doesn't exist
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

def registry_setstring(root,path,keyname,value,type=_winreg.REG_SZ):
    """Set the value of a string key in registry
        root    : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
        path    : string like "software\\microsoft\\windows\\currentversion"
                           or "software\\wow6432node\\microsoft\\windows\\currentversion"
        keyname : None for value of key or str for a specific value like 'CommonFilesDir'
        value   : string to put in keyname
    the path can be either with backslash or slash"""
    path = path.replace(u'/',u'\\')
    key = reg_openkey_noredir(root,path,sam=KEY_WRITE,create_if_missing=True)
    result = reg_setvalue(key,keyname,value,type=type)
    return result

def registry_readstring(root,path,keyname,default=''):
    """Return a string from registry
        root    : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
        path    : string like "software\\microsoft\\windows\\currentversion"
                           or "software\\wow6432node\\microsoft\\windows\\currentversion"
        keyname : None for value of key or str for a specific value like 'CommonFilesDir'
        the path can be either with backslash or slash
    >>> registry_readstring(HKEY_LOCAL_MACHINE,r'SYSTEM/CurrentControlSet/services/Tcpip/Parameters','Hostname')
    u'HTLAPTOP'
    """
    path = path.replace(u'/',u'\\')
    try:
        key = reg_openkey_noredir(root,path)
        result = reg_getvalue(key,keyname,default)
        return result
    except:
        return default

def registry_set(root,path,keyname,value,type=None):
    """Set the value of a key in registry, tajing in account calue type
        root    : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
        path    : string like "software\\microsoft\\windows\\currentversion"
                           or "software\\wow6432node\\microsoft\\windows\\currentversion"
        keyname : None for value of key or str for a specific value like 'CommonFilesDir'
        value   : value (integer or string type) to put in keyname
    the path can be either with backslash or slash"""
    path = path.replace(u'/',u'\\')
    key = reg_openkey_noredir(root,path,sam=KEY_WRITE,create_if_missing=True)
    if not type:
        if isinstance(value,list):
            type = REG_MULTI_SZ
        elif isinstance(value,int):
            type = REG_DWORD
        else:
            type = REG_SZ
    result = reg_setvalue(key,keyname,value,type=type)
    return result

def inifile_hasoption(inifilename,section,key):
    """Read a string parameter from inifile"""
    inifile = RawConfigParser()
    inifile.read(inifilename)
    return inifile.has_section(section) and inifile.has_option(section,key)

def inifile_readstring(inifilename,section,key,default=None):
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
    if not inifile.has_section(section):
        inifile.add_section(section)
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
        os_encoding=locale.getpreferredencoding()
        key = reg_openkey_noredir(_winreg.HKEY_LOCAL_MACHINE,uninstall)
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
        so that the application is displayed in Control Panel / Programs and features"""
    if not uninstallkey:
        raise Exception('No uninstall key provided')
    if not uninstallstring:
        raise Exception('No uninstallstring provided')
    if iswin64() and not win64app:
        root = "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    else:
        root = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    appkey = reg_openkey_noredir(_winreg.HKEY_LOCAL_MACHINE,"%s\\%s" % (root,uninstallkey.encode(locale.getpreferredencoding())),
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
    """return a list of (iface,mac,{addr,broadcast,netmask})"""
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
    # Return system memory statistics
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
    """Convert dmidecode -q output to python dict
    >>> dmi = dmi_info()
    >>> dmi['UUID']
    >>> print dmi

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
                result[l.strip().replace(' ','_')]=currobject
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

def wmi_info(keys=['Win32_ComputerSystem','Win32_ComputerSystemProduct','Win32_BIOS','Win32_NetworkAdapter']):
    """Get WMI machine informations as dictionaries"""
    result = {}
    import wmi
    wm = wmi.WMI()
    for key in keys:
        cs = getattr(wm,key)()
        if len(cs)>1:
            for cs2 in cs:
                na = result[key] = []
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
    >>> r = wmi_info_basic()
    >>> 'System_Information' in r
    True
    """
    res = run('wmic PATH Win32_ComputerSystemProduct GET UUID,IdentifyingNumber,Name,Vendor /VALUE')
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

def host_info():
    info = {}
    info['description'] = registry_readstring(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\services\LanmanServer\Parameters','srvcomment')

    #info['serial_nr'] = dmi_info.get('System_Information',{}).get('Serial_Number','')
    info['system_manufacturer'] = registry_readstring(HKEY_LOCAL_MACHINE,r'HARDWARE\DESCRIPTION\System\BIOS','SystemManufacturer')
    info['system_productname'] = registry_readstring(HKEY_LOCAL_MACHINE,r'HARDWARE\DESCRIPTION\System\BIOS','SystemProductName')

    info['computer_name'] =  wincomputername()
    info['computer_fqdn'] =  get_hostname()
    info['dns_domain'] = get_domain_fromregistry()
    info['workgroup_name'] = windomainname()
    info['networking'] = networking()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("wapt", 0))
        info['connected_ips'] = s.getsockname()[0]
        s.close()
    except:
        info['connected_ips'] = socket.gethostbyname_ex(socket.gethostname())[2]
    info['mac'] = [ c['mac'] for c in networking() if 'mac' in c and 'addr' in c and c['addr'] in info['connected_ips']]
    info['win64'] = iswin64()
    info['description'] = registry_readstring(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\services\LanmanServer\Parameters','srvcomment')

    info['registered_organization'] =  registry_readstring(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion','RegisteredOrganization')
    info['registered_owner'] =  registry_readstring(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion','RegisteredOwner')
    win_info = keyfinder.windows_product_infos()
    info['windows_version'] =  platform.platform()
    info['windows_product_infos'] =  win_info

    info['cpu_name'] = registry_readstring(HKEY_LOCAL_MACHINE,r'HARDWARE\DESCRIPTION\System\CentralProcessor\0','ProcessorNameString','')

    info['physical_memory'] = memory_status().ullTotalPhys
    info['virtual_memory'] = memory_status().ullTotalVirtual

    info['current_user'] = get_loggedinusers()
    return info

# from http://stackoverflow.com/questions/580924/python-windows-file-version-attribute
def get_file_properties(fname):
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
        logger.warning(u"%s" % ensure_unicode(e))

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
            result[ensure_unicode(r.GetString(1))] = ensure_unicode(r.GetString(2))
        except:
            logger.warning(u"erreur pour %s" % ensure_unicode(r.GetString(0)))
        try:
            r = view.Fetch()
        except:
            break
    return result

# some const
programfiles = programfiles()
programfiles32 = programfiles32()
programfiles64 = programfiles64()

# some shortcuts
isfile=os.path.isfile
isdir=os.path.isdir
remove_file=os.unlink
remove_tree=shutil.rmtree
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
    logger.debug('Starting service %s' % service_name)
    win32serviceutil.StartService(service_name)
    return win32serviceutil.WaitForServiceStatus(service_name, win32service.SERVICE_RUNNING, waitSecs=4)

def service_stop(service_name):
    logger.debug('Stopping service %s' % service_name)
    win32serviceutil.StopService(service_name)
    win32api.Sleep(2000)
    return win32serviceutil.WaitForServiceStatus(service_name, win32service.SERVICE_STOPPED, waitSecs=4)

def service_is_running(service_name):
    """Return True if the service is running"""
    return win32serviceutil.QueryServiceStatus(service_name)[1] == win32service.SERVICE_RUNNING

def user_appdata():
    return ensure_unicode((winshell.get_path(shellcon.CSIDL_APPDATA)))

def mkdirs(path):
    """Create directory path if it doesn't exists yet"""
    if not os.path.isdir(path):
        os.makedirs(path)


def user_desktop():
    """return path to current logged in user desktop"""
    return unicode(desktop(0))

def common_desktop():
    """return path to public desktop (visible by all users)"""
    return unicode(desktop(1))

def register_dll(dllpath):
    """Register a COM/OLE server DLL in registry (similar to regsvr32)"""
    dll = ctypes.windll[dllpath]
    result = dll.DllRegisterServer()
    logger.info('DLL %s registered' % dllpath)
    if result:
        raise Exception(u'Register DLL %s failed, code %i' % (dllpath,result))

def unregister_dll(dllpath):
    """Unregister a COM/OLE server DLL from registry"""
    dll = ctypes.windll[dllpath]
    result = dll.DllUnregisterServer()
    logger.info('DLL %s unregistered' % dllpath)
    if result:
        raise Exception(u'Unregister DLL %s failed, code %i' % (dllpath,result))

def add_to_system_path(path):
    """Add path to the global search PATH environment variable if it is not yet"""
    key = reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',sam=KEY_READ | KEY_WRITE)
    system_path = reg_getvalue(key,'Path').lower().split(';')
    if not path.lower() in system_path:
        system_path.append(path)
        reg_setvalue(key,'Path',';'.join(system_path),type=REG_EXPAND_SZ)
        win32api.SendMessage(win32con.HWND_BROADCAST,win32con.WM_SETTINGCHANGE,0,'Environment')
    return system_path

def get_task(name):
    """Return an instance of PyITask given its name (without .job)"""
    ts = pythoncom.CoCreateInstance(taskscheduler.CLSID_CTaskScheduler,None,
                                    pythoncom.CLSCTX_INPROC_SERVER,
                                    taskscheduler.IID_ITaskScheduler)
    if '%s.job' % name not in ts.Enum():
        raise KeyError("%s doesn't exists" % name)

    task = ts.Activate(name)
    return task

def run_task(name):
    """Launch immediately the Windows Scheduled task"""
    get_task(name).Run()

def task_exists(name):
    """Return true if a sheduled task names 'name.job' is defined"""
    ts = pythoncom.CoCreateInstance(taskscheduler.CLSID_CTaskScheduler,None,
                                    pythoncom.CLSCTX_INPROC_SERVER,
                                    taskscheduler.IID_ITaskScheduler)
    return '%s.job' % name in ts.Enum()

def delete_task(name):
    """removes a Windows scheduled task"""
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
    """Enable a Windows scheduled task"""
    return run('schtasks /Change /TN "%s" /ENABLE' % name)

    """
    task = get_task(name)
    task.SetFlags(task.GetFlags() & ~taskscheduler.TASK_FLAG_DISABLED)
    pf = task.QueryInterface(pythoncom.IID_IPersistFile)
    pf.Save(None,1)
    return task
    """

def create_daily_task(name,cmd,parameters, max_runtime=10, repeat_minutes=None, start_hour=None, start_minute=None):
    """creates a Windows scheduled daily task
        Return an instance of PyITask
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
            tt.StartMinute = minute
        if start_hour is None:
            tt.StartHour = int(time.strftime('%H', run_time))
        else:
            tt.StartHour = hour
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
    """
    Get the login name for the current user.
    """
    import ctypes
    MAX_PATH = 260                  # according to a recent WinDef.h
    name = ctypes.create_unicode_buffer(MAX_PATH)
    namelen = ctypes.c_int(len(name)) # len in chars, NOT bytes
    if not ctypes.windll.advapi32.GetUserNameW(name, ctypes.byref(namelen)):
        raise ctypes.WinError()
    return ensure_unicode(name.value)

def get_language():
    """Get the default locale like fr, en, pl etc..  etc"""
    return locale.getdefaultlocale()[0].split('_')[0]

def get_appath(exename):
    """Get the registered application location from registry given its executable name"""
    if iswin64():
        key = reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\%s' % exename)
    else:
        key = reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\%s' % exename)
    return reg_getvalue(key,None)

class Version():
    """Version object of form 0.0.0
        can compare with respect to natural numbering and not alphabetical
    >>> Version('0.10.2') > Version('0.2.5')
    True
    >>> Version('0.1.2') < Version('0.2.5')
    True
    >>> Version('0.1.2') == Version('0.1.2')
    True
    """
    def __init__(self,versionstring):
        assert isinstance(versionstring,types.ModuleType) or isinstance(versionstring,str) or isinstance(versionstring,unicode)
        if isinstance(versionstring,ModuleType):
            versionstring = versionstring.__version__
        self.members = [ v.strip() for v in versionstring.split('.')]
    def __cmp__(self,aversion):
        def nat_cmp(a, b):
            a, b = a or '', b or ''
            def convert(text):
                if text.isdigit():
                    return int(text)
                else:
                    return text.lower()
            alphanum_key = lambda key: [convert(c) for c in re.split('([0-9]+)', key)]
            return cmp(alphanum_key(a), alphanum_key(b))

        assert isinstance(aversion,Version)
        for i in range(0,min([len(self.members),len(aversion.members)])):
            i1,i2  = self.members[i], aversion.members[i]
            v = nat_cmp(i1,i2)
            if v:
                return v
        return 0

    def __repr__(self):
        return '.'.join(self.members)

class EWaptSetupException(Exception):
    pass

CalledProcessError = subprocess.CalledProcessError

def error(reason):
    """Raise a WAPT fatal error"""
    raise EWaptSetupException(u'Fatal error : %s' % reason)

# to help pyscripter code completion in setup.py
params = {}
"""Specific parameters for install scripts"""

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
    assert installed_softwares('offi')[0]['uninstall_string'] <> ''
    assert get_file_properties('c:\\wapt\\waptservice.exe')['FileVersion'] <>''
    assert get_file_properties('c:\\wapt\\wapt-get.exe')['FileVersion'] <> ''