#-------------------------------------------------------------------------------
# Name:        setuphelpers
# Purpose:     common functions to help setup tasks
#
# Author:      33
#
# Created:     22/05/2012
# Copyright:   (c) 33 2012
# Licence:     GPL
#-------------------------------------------------------------------------------
#!/usr/bin/env python

__version__ = "0.1"

from winshell import *
import os
import urllib,urllib2
import tempfile
import shutil
from regutil import *
import subprocess
import win32pdhutil
import win32api,win32con
from _winreg import HKEY_LOCAL_MACHINE,EnumKey,OpenKey,QueryValueEx,EnableReflectionKey,DisableReflectionKey,QueryReflectionKey,QueryInfoKey,KEY_READ,KEY_WOW64_32KEY,KEY_WOW64_64KEY
import platform

import logging
logger = logging.getLogger('wapt-get')

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
    if not os.path.exists(d):
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
    create_shortcut(os.path.join(start_menu(1),label),target,wDir,icon)

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
    """Copy file from package temporary directory to target"""
    (dir,fn) = os.path.split(filename)
    if not dir:
        dir = tempdir
    #shutil.copy(os.path.join(dir,fn),target)
    shutil.copy(filename,target)

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

def shelllaunch(cmd):
    """Launch a command (without arguments) but doesn't wait for its termination"""
    os.startfile(cmd)

def registerapplication(applicationname,uninstallstring):
    pass

def unregisterapplication(applicationname):
    pass

def isrunning(processname):
    try:
        return len(win32pdhutil.FindPerformanceAttributesByName( processname ))> 0
    except:
        return False

def killalltasks(exename):
    run_notfatal('taskkill /im "%s" /f % exename')

def messagebox(title,msg):
    win32api.MessageBox(0, msg, title, win32con.MB_ICONINFORMATION)

def programfiles64():
    return os.environ['PROGRAMFILES']

def programfiles():
    #return get_path(shellcon.CSIDL_PROGRAM_FILES)
    return os.environ['PROGRAMFILES']

def programfiles32():
    if 'PROGRAMW6432' in os.environ and 'PROGRAMFILES(X86)' in os.environ:
        return os.environ['PROGRAMFILES(X86)']
    else:
        return os.environ['PROGRAMFILES']

def iswin64():
    return 'PROGRAMW6432' in os.environ

def OpenKeyNoredir(key, sub_key, sam=KEY_READ):
    if platform.machine() == 'AMD64':
        return OpenKey(key,sub_key,0, sam | KEY_WOW64_64KEY)
    else:
        return OpenKey(key,sub_key,0,sam)

def get_domain_fromregistry():
    key = OpenKey(HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters")
    try:
        (domain,atype) = QueryValueEx(key,'DhcpDomain')
    except:
        (domain,atype) = QueryValueEx(key,'Domain')
    return domain

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

# some const
programfiles = programfiles()
programfiles32 = programfiles32()
programfiles64 = programfiles64()
domainname = get_domain_fromregistry()
computername = os.environ['COMPUTERNAME']

# to help pyscripter code completion in setup.py
params = {}

