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
from winshell import *
import urllib,urllib2
import tempfile
import shutil
from regutil import *
import subprocess
import win32pdhutil
import win32api,win32con

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
    shutil.copy(os.path.join(dir,fn),target)

def run(cmd):
    """Runs the command and wait for it termination
    returns output, raise exc eption if exitcode is not null"""
    print 'Run "%s"' % cmd
    return subprocess.check_output(cmd,shell=True)

def run_notfatal(cmd):
    """Runs the command and wait for it termination
    returns output, don't raise exception if exitcode is not null but return '' """
    try:
        print 'Run "%s"' % cmd
        return subprocess.check_output(cmd,shell=True)
    except Exception,e:
        print 'Warning : %s' % e.message
        return ''

def shelllaunch(cmd):
    """Launch a command (without arguments) but doesn't wait for its termination"""
    os.startfile(cmd)

def registerapplication(applicationname):
    pass

def unregisterapplication(applicationname):
    pass

def isrunning(processname):
    try:
        return len(win32pdhutil.FindPerformanceAttributesByName( processname ))> 0
    except:
        return False

def killalltasks(exename):
    os.system('taskkill /im "%s" /f % exename')

def messagebox(title,msg):
    win32api.MessageBox(0, msg, title, win32con.MB_ICONINFORMATION)

if __name__ == '__main__':
    main()

