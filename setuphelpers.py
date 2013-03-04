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

__version__ = "0.2"

from winshell import *
import os,sys
import logging
import urllib,urllib2
import tempfile
import shutil
from regutil import *
import subprocess
import win32pdhutil
import win32api,win32con
from _winreg import HKEY_LOCAL_MACHINE,EnumKey,OpenKey,QueryValueEx,EnableReflectionKey,DisableReflectionKey,QueryReflectionKey,QueryInfoKey,KEY_READ,KEY_WOW64_32KEY,KEY_WOW64_64KEY
import platform
import socket
import dns.resolver
import netifaces

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

def killalltasks(*exenames):
    for c in exenames:
      run_notfatal('taskkill /t /im "%s" /f' % c)

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

def getcomputername():
    return socket.gethostname()

def getloggedinusers():
    return []

def openkey_noredir(key, sub_key, sam=KEY_READ):
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

def installed_softwares(keywords=''):
    """return list of installed softwrae from registry (both 32bit and 64bit"""
    def regget(key,name,default=None):
        try:
            return QueryValueEx(key,name)[0]
        except WindowsError:
            # WindowsError: [Errno 259] No more data is available
            return default

    def check_words(target,words):
        mywords = target.lower()
        result = not words or mywords
        for w in words:
            result = result and w in mywords
        return result

    def list_fromkey(uninstall):
        result = []
        key = openkey_noredir(HKEY_LOCAL_MACHINE,uninstall)
        mykeywords = keywords.lower().split()
        i = 0
        while True:
            try:
                subkey = EnumKey(key, i).decode('iso8859')
                appkey = openkey_noredir(HKEY_LOCAL_MACHINE,"%s\\%s" % (uninstall,subkey.encode('iso8859')))
                display_name = regget(appkey,'DisplayName','')
                display_version = regget(appkey,'DisplayVersion','')
                install_date = regget(appkey,'InstallDate','')
                install_location = regget(appkey,'InstallLocation','')
                uninstallstring = regget(appkey,'UninstallString','')
                publisher = regget(appkey,'Publisher','')
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


def ipv4_to_int(ipaddr):
    (a,b,c,d) = ipaddr.split('.')
    return (int(a) << 24) + (int(b) << 16) + (int(c) << 8) + int(d)

def same_net(ip1,ip2,netmask):
    """Given 2 ipv4 address and mask, return True if in same subnet"""
    return (ipv4_to_int(ip1) & ipv4_to_int(netmask)) == (ipv4_to_int(ip2) & ipv4_to_int(netmask))

def host_ipv4():
    """return a list of (iface,mac,{addr,broadcast,netmask})"""
    ifaces = netifaces.interfaces()
    res = []
    for i in ifaces:
        params = netifaces.ifaddresses(i)
        if netifaces.AF_LINK in params and params[netifaces.AF_LINK][0]['addr'] and not params[netifaces.AF_LINK][0]['addr'].startswith('00:00:00'):
            iface = {'iface':i,'mac':params[netifaces.AF_LINK][0]['addr']}
            if netifaces.AF_INET in params:
                iface.update(params[netifaces.AF_INET][0])
            res.append( iface )
    return res

def host_info():
    info = {}
    info['waptgetversion'] = "0.5.11"
    info['computername'] =  "PC623"
    info['workgroupname'] = "SERMOSTH"
    info['biosinfo'] = ""
    info['biosdate'] = "2012-08-15T00:00:00,0+01:00"
    info['wmibiosinfo']= {
        'SerialNumber': "GN5Q2Q1",
        'Manufacturer': "Dell Inc."}
    info['macaddresses'] = ["5C-26-0A-68-1E-3A"]
    info['processorcount'] = 4
    info['ipaddresses'] = [
      "192.168.149.198"]
    info['physicalmemory'] = 6317723648
    info['virtualmemory'] = 2147352576
    info['systemmanufacturer'] = "Dell Inc."
    info['biosversion'] = "A15"
    info['systemproductname'] = "Latitude E6520",
    info['cpuname'] = "Intel(R) Core(TM) i5-2520M CPU @ 2.50GHz"
    return info


def _tryurl(url):
    try:
        logger.debug('  trying %s' % url)
        urllib2.urlopen(url)
        logger.debug('  OK')
        return True
    except Exception,e:
        logger.debug('  Not available : %s' % e)
        return False

def find_wapt_server(configparser):
    """Search the nearest working WAPT repository given the following priority
       - URL defined in ini file
       - first SRV record in the same network as one of the connected network interface
       - first SRV record with the heigher weight
       - wapt CNAME in the local dns domain (https first then http)
       - hardcoded http://wapt/wapt

    """
    local_ips = socket.gethostbyname_ex(socket.gethostname())[2]
    logger.debug('All interfaces : %s' % [ "%s/%s" % (i['addr'],i['netmask']) for i in host_ipv4() if 'addr' in i and 'netmask' in i])
    connected_interfaces = [ i for i in host_ipv4() if 'addr' in i and 'netmask' in i and i['addr'] in local_ips ]
    logger.debug('Local connected IPs: %s' % [ "%s/%s" % (i['addr'],i['netmask']) for i in connected_interfaces])

    def is_inmysubnets(ip):
        """Return True if IP is in one of my connected subnets"""
        for i in connected_interfaces:
            if same_net(i['addr'],ip,i['netmask']):
                logger.debug('  %s is in same subnet as %s/%s local connected interface' % (ip,i['addr'],i['netmask']))
                return True
        return False

    #dnsdomain = dns.resolver.get_default_resolver().domain.to_text()
    dnsdomain = get_domain_fromregistry()
    logger.debug('Default DNS domain: %s' % dnsdomain)

    if configparser:
        url = configparser.get('global','repo_url')
        if url:
            if _tryurl(url+'/Packages'):
                return url
            else:
                logger.warning('URL defined in ini file %s is not available' % url)
        if not url:
            logger.debug('No url defined in ini file')

    if dnsdomain and dnsdomain <> '.':
        # find by dns SRV _wapt._tcp
        try:
            logger.debug('Trying _wapt._tcp.%s SRV records' % dnsdomain)
            answers = dns.resolver.query('_wapt._tcp.%s' % dnsdomain,'SRV')
            working_url = []
            for a in answers:
                # get first numerical ipv4 from SRV name record
                try:
                    wapthost = a.target.to_text()[0:-1]
                    ip = dns.resolver.query(a.target)[0].to_text()
                    if a.port == 80:
                        url = 'http://%s/wapt' % (wapthost,)
                        if _tryurl(url+'/Packages'):
                            working_url.append((a.weight,url))
                            if is_inmysubnets(ip):
                                return url
                    elif a.port == 443:
                        url = 'https://%s/wapt' % (wapthost,)
                        if _tryurl(url+'/Packages'):
                            working_url.append((a.weight,url))
                            if is_inmysubnets(ip):
                                return url
                    else:
                        url = 'http://%s:%i/wapt' % (wapthost,a.port)
                        if _tryurl(url+'/Packages'):
                            working_url.append((a.weight,url))
                            if is_inmysubnets(ip):
                                return url
                except Exception,e:
                    logging.debug('Unable to resolve : error %s' % (e,))

            if working_url:
                working_url.sort()
                logger.debug('  Accessible servers : %s' % (working_url,))
                return working_url[-1][0][1]

            if not answers:
                logger.debug('  No _wapt._tcp.%s SRV record found' % dnsdomain)
        except dns.exception.DNSException,e:
            logger.warning('  DNS resolver error : %s' % (e,))

        # find by dns CNAME
        try:
            logger.debug('Trying wapt.%s CNAME records' % dnsdomain)
            answers = dns.resolver.query('wapt.%s' % dnsdomain,'CNAME')
            for a in answers:
                wapthost = a.target.canonicalize().to_text()[0:-1]
                url = 'https://%s/wapt' % (wapthost,)
                if _tryurl(url+'/Packages'):
                    return url
                url = 'http://%s/wapt' % (wapthost,)
                if _tryurl(url+'/Packages'):
                    return url
            if not answers:
                logger.debug('  No wapt.%s CNAME SRV record found' % dnsdomain)

        except dns.exception.DNSException,e:
            logger.warning('  DNS resolver error : %s' % (e,))
    else:
        logger.warning('Local DNS domain not found, skipping SRV _wapt._tcp and CNAME search ')

    # hardcoded wapt
    url = 'http://wapt/wapt'
    if _tryurl(url+'/Packages'):
        return url

    return None

# some const
programfiles = programfiles()
programfiles32 = programfiles32()
programfiles64 = programfiles64()
domainname = get_domain_fromregistry()
computername = os.environ['COMPUTERNAME']

# to help pyscripter code completion in setup.py
params = {}

