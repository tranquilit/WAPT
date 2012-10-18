#!/usr/bin/python
# -*- coding: UTF-8 -*-
import sys
import os
import zipfile
import urllib2
import shutil
from iniparse import ConfigParser
from optparse import OptionParser
import logging
import datetime
from common import WaptDB
from common import Package_Entry
from common import update_packages
from common import pptable
import dns.resolver
import pprint
import socket
import codecs
from setuphelpers import *
import json
import glob
from _winreg import HKEY_LOCAL_MACHINE,EnumKey,OpenKey,QueryValueEx,EnableReflectionKey,DisableReflectionKey,QueryReflectionKey,QueryInfoKey

usage="""\
%prog -c configfile action

WAPT install system.

action is either :
  install [packages]: install one or several packages
  update : update package database
  upgrade : upgrade installed packages

  download [packages]: force download one or several packages
  show [packages]: show attributes of one or more packages

  list [keywords]: list installed packages
  list-upgrade  : list upgradable packages
  list-registry [keywords] : list installed software from Windows Registry
  search [keywords] : search installable packages whose description contains keywords
  cleanup : remove all WAPT cached files from local drive

  update-packages <directory> : rebuild a "Packages" file for http package repository

"""

version = "0.5.6"

parser=OptionParser(usage=usage,version="%prog " + version)
parser.add_option("-c","--config", dest="config", default='c:\\wapt\\wapt-get.ini', help="Config file full path (default: %default)")
parser.add_option("-l","--loglevel", dest="loglevel", default='info', type='choice',  choices=['debug','warning','info','error','critical'], metavar='LOGLEVEL',help="Loglevel (default: %default)")
parser.add_option("-d","--dry-run",    dest="dry_run",    default=False, action='store_true', help="Dry run (default: %default)")
parser.add_option("-f","--force",    dest="force",    default=False, action='store_true', help="Force (default: %default)")
parser.add_option("-p","--params", dest="params", default='{}', help="Setup params as a JSon Object (default: %default)")

(options,args)=parser.parse_args()

# setup Logger
logger = logging.getLogger('wapt-get')
config_file =options.config
loglevel = options.loglevel

hdlr = logging.StreamHandler(sys.stdout)
hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logger.addHandler(hdlr)

# set loglevel
if loglevel in ('debug','warning','info','error','critical'):
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)
    logger.setLevel(numeric_level)

def psource(module):
    file = os.path.basename( module )
    dir = os.path.dirname( module )
    toks = file.split( '.' )
    modname = toks[0]

    # Check if the file directory already exists in the sys.path array
    if os.path.exists( dir ) and not dir in sys.path:
        sys.path.append( dir )

    exec ('import ' + modname) in globals()
    exec( 'reload( ' + modname + ' )' ) in globals()

    # This returns the namespace of the file imported
    return modname

def find_wapt_server(configparser):
    def tryurl(url):
        try:
            logger.debug('Trying %s' % url)
            urllib2.urlopen(url+'/')
            logger.debug('OK')
            return True
        except Exception,e:
            logger.debug('Not available, %s' % e)
            return False

    local_ips = socket.gethostbyname_ex(socket.gethostname())[2]
    logger.debug('Local IPs: %s' % local_ips)

    dnsdomain = dns.resolver.get_default_resolver().domain.to_text()
    logger.debug('Default DNS domain: %s' % dnsdomain)

    url = configparser.get('global','repo_url')
    if url:
        if tryurl(url):
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
            for a in answers:
                if a.port == 80:
                    url = 'http://%s/wapt' % (a.target.canonicalize().to_text()[0:-1])
                    if tryurl(url):
                        return url
                else:
                    url = 'http://%s:%i/wapt' % (a.target.canonicalize().to_text()[0:-1],a.port)
                    if tryurl(url):
                        return url
            if not answers:
                logger.debug('  No _wapt._tcp.%s SRV record found' % dnsdomain)
        except dns.resolver.NXDOMAIN:
            pass

        # find by dns CNAME
        try:
            logger.debug('Trying wapt.%s CNAME records' % dnsdomain)
            answers = dns.resolver.query('wapt.%s' % dnsdomain,'CNAME')
            for a in answers:
                url = 'http://%s/wapt' % (a.target.canonicalize().to_text()[0:-1])
                if tryurl(url):
                    return url
            if not answers:
                logger.debug('  No wapt.%s CNAME SRV record found' % dnsdomain)

        except dns.resolver.NXDOMAIN:
            pass
    else:
        logger.warning('Local DNS domain not found, skipping SRV _wapt._tcp and CNAME search ')

    # hardcoded wapt
    url = 'http://wapt/wapt'
    if tryurl(url):
        return url

    url = 'http://wapt/tiswapt'
    if tryurl(url):
        return url

    return None

class LogInstallOutput(object):
    """file like to log print output to db installstatus"""
    def __init__(self,console,waptdb,rowid):
        self.output = []
        self.console = console
        self.waptdb = waptdb
        self.rowid = rowid

    def write(self,txt):
        self.console.write(txt)
        if txt <> '\n':
            try:
                txt = txt.decode('utf8')
            except:
                try:
                    txt = txt.decode('iso8859')
                except:
                    pass
            self.output.append(txt)
            if txt and txt[-1]<>'\n':
                txtdb = txt+'\n'
            else:
                txtdb = txt
            self.waptdb.update_install_status(self.rowid,'RUNNING',txtdb if not txtdb == None else None)

    def __getattrib__(self, name):
        if hasattr(self.console,'__getattrib__'):
            return self.console.__getattrib__(name)
        else:
            return self.console.__getattribute__(name)

class Wapt:
    def __init__(self):
        self.wapt_repourl=""
        self.packagecachedir = ""
        self.dry_run = False
        self.dbpath = 'c:\\wapt\\db\\waptdb.sqlite'
        self._waptdb = None

    @property
    def waptdb(self):
        if not self._waptdb:
            self._waptdb = WaptDB(dbpath=self.dbpath)
        return self._waptdb

    def registry_uninstall_snapshot(self):
        """return list of uninstall ID from registry"""
        result = []
        key = OpenKey(HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        try:
            i = 0
            while True:
                subkey = EnumKey(key, i)
                result.append(subkey)
                i += 1
        except WindowsError:
            # WindowsError: [Errno 259] No more data is available
            pass
        return result

    def registry_installed_softwares(self,keywords=''):
        """return list of uninstall ID from registry"""
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

        result = []
        key = OpenKey(HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        try:
            mykeywords = keywords.lower().split()
            i = 0
            while True:
                subkey = EnumKey(key, i).decode('iso8859')
                appkey = OpenKey(HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\%s" % subkey.encode('iso8859'))
                displayname = regget(appkey,'DisplayName','')
                displayversion = regget(appkey,'DisplayVersion','')
                installdate = regget(appkey,'InstallDate','')
                if displayname and check_words(subkey+' '+displayname+' ',mykeywords):
                    result.append({'key':subkey,'DisplayName':displayname,'DisplayVersion':displayversion,'InstallDate':installdate})
                i += 1
        except WindowsError:
            # WindowsError: [Errno 259] No more data is available
            pass
        return result

    def uninstall_cmd(self,guid):
        """return cmd to uninstall from registry"""
        key = OpenKey(HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\%s" % guid)
        try:
            cmd = QueryValueEx(key,'QuietUninstallString')[0]
        except WindowsError:
            cmd = QueryValueEx(key,'UninstallString')[0]
            if 'msiexec' in cmd.lower():
                cmd = cmd.replace('/I','/X').replace('/i','/X')
                if not '/q' in cmd:
                    cmd = cmd + ' /q'
            else:
                # mozilla et autre
                if ('uninst' in cmd.lower() or 'helper.exe' in cmd.lower()) and not ' /s' in cmd.lower():
                    cmd = cmd + ' /S'

        return cmd



    def install_wapt(self,fname,params_dict={}):
        logger.info("Register start of install %s to local DB with params %s" % (fname,params_dict))
        status = 'INIT'
        previous_uninstall = self.registry_uninstall_snapshot()
        entry = Package_Entry()
        entry.load_control_from_wapt(fname)
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        install_id = None
        install_id = self.waptdb.add_start_install(entry.Package ,entry.Version)
        # we setup a redirection of stdout to catch print output from install scripts
        sys.stderr = sys.stdout = installoutput = LogInstallOutput(sys.stdout,self.waptdb,install_id)
        hdlr = logging.StreamHandler(installoutput)
        hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        old_hdlr = logger.handlers[0]
        logger.handlers[0] = hdlr
        try:
            logger.info("Installing package " + fname)
            # ... inutile ?
            #global packagetempdir
            # case wapt is a zipped file, else directory (during developement)
            istemporary = False
            if os.path.isfile(fname):
                packagetempdir = tempfile.mkdtemp(prefix="wapt")
                logger.info('  unzipping %s to temporary' % (fname))
                zip = zipfile.ZipFile(fname)
                zip.extractall(path=packagetempdir)
                istemporary = True
            elif os.path.isdir(fname):
                packagetempdir = fname
            else:
                raise Exception('%s is not a file nor a directory, aborting.' % fname)

            setup_filename = os.path.join( packagetempdir,'setup.py')
            previous_cwd = os.getcwd()
            os.chdir(os.path.dirname(setup_filename))

            logger.info("  sourcing install file %s " % setup_filename )
            psource(setup_filename)

            required_params = []
            global setup
            setattr(setup,'basedir',os.path.dirname(setup_filename))
            setattr(setup,'run',run)
            setattr(setup,'run_notfatal',run_notfatal)

            if hasattr(setup,'required_params'):
                required_params = setup.required_params

            for p in required_params:
                if not p in params_dict:
                    params_dict[p] = raw_input("%s: " % p)

            # set params dictionary
            setattr(setup,'params',params_dict)
            if not self.dry_run:
                try:
                    logger.info("  executing install script")
                    exitstatus = setup.install()
                except Exception,e:
                    logger.critical('Fatal error in install script: %s' % e)
                    raise

            if exitstatus is None:
                status = 'UNKNOWN'
            elif exitstatus == 0:
                status = 'OK'
            else:
                status = 'ERROR'
            if hasattr(setup,'uninstallkey'):
                new_uninstall_key = '%s' % (setup.uninstallkey,)
            else:
                new_uninstall = self.registry_uninstall_snapshot()
                new_uninstall_key = [ k for k in new_uninstall if not k in previous_uninstall]
            logger.info('  uninstall keys : %s' % (new_uninstall_key,))

            if hasattr(setup,'uninstallstring'):
                uninstallstring = setup.uninstallstring
            else:
                uninstallstring = None

            logger.info("Install script finished with status %s" % status)
            if istemporary:
                os.chdir(previous_cwd)
                logger.debug("Cleaning package tmp dir")
                shutil.rmtree(packagetempdir)

            self.waptdb.update_install_status(install_id,status,'',str(new_uninstall_key),uninstallstring)
            # (entry.Package,entry.Version,status,json.dumps({'output':installoutput.output,'exitstatus':exitstatus}))

        except Exception,e:
            if install_id:
                try:
                    try:
                        uerror = repr(e).decode('iso8859')
                    except:
                        try:
                            uerror = repr(e).decode('utf8')
                        except:
                            uerror = repr(e)
                    self.waptdb.update_install_status(install_id,'ERROR',uerror)
                except Exception,e2:
                    logger.critical(e2)
            raise
        finally:
            if 'setup' in dir():
                del setup
            logger.handlers[0] = old_hdlr
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    def get_sources(self,package):
        """Download sources of package (if referenced in package as a https svn
           in the current directory"""
        entry = self.waptdb.package_entry_from_db(package)
        if not entry.Sources:
            raise Exception('No source defined in package control file')
        if "PROGRAMW6432" in os.environ:
            svncmd = os.path.join(environ['PROGRAMW6432'],'TortoiseSVN','svn.exe')
        else:
            svncmd = os.path.join(environ['PROGRAMFILES'],'TortoiseSVN','svn.exe')
        if not os.path.isfile(svncmd):
            raise Exception('svn.exe command not available, please install TortoiseSVN with commandline tools')
        co_dir = entry.source.replace('/trunk','').replace('/tags','').replace('/branch','')
        print subprocess.check_output('svn co %s %s' % (svncmd,codir))


    def showlog(self,package):
        q = self.waptdb.query("""\
           select InstallStatus,InstallOutput from wapt_localstatus
            where Package=?
           """ , (package,) )
        if not q:
            print "ERROR : Package %s not found in local DB status" % package
            return False

        print "Last install log from %s: status : %s\n%s" % ( package, q[0]['InstallStatus'], q[0]['InstallOutput'])

    def cleanup(self):
        """Remove cached WAPT file from local disk"""
        logger.info('Cleaning up WAPT cache directory')
        cachepath = 'c:/wapt/cache'
        for f in glob.glob(os.path.join(cachepath,'*.wapt')):
            if os.path.isfile(f):
                logger.debug('Removing %s' % f)
                os.remove(f)

    def install(self,apackages,force=False,params_dict = {}):
        """Install a list of packages and its dependencies"""
        allupgrades = self.waptdb.upgradeable()
        allinstalled = self.waptdb.installed()
        packages = []
        if not force:
            for p in apackages:
                if not p in allupgrades and p in allinstalled:
                    print "Package %s already at the latest version (%s), skipping install." % (p,allinstalled[p]['Version'])
                else:
                    packages.append(p)
        else:
            packages = apackages
        # get dependencies of all packages
        depends = self.waptdb.build_depends(packages)
        to_upgrade =  [ p for p in depends if p in allupgrades.keys() ]
        additional_install = [ p for p in depends if not p in allinstalled.keys() ]
        if additional_install:
            print "Additional packages to install :\n   %s" % (','.join(additional_install),)
        if to_upgrade:
            print "Packages to upgrade :\n   %s" % (','.join(to_upgrade),)

        to_install = []
        to_install.extend(additional_install)
        to_install.extend(to_upgrade)
        to_install.extend(packages)
        # [[package/version],]
        self.download_packages([(p,None) for p in to_install])
        def fname(packagefilename):
            return os.path.join(self.packagecachedir,packagefilename)

        for p in additional_install:
            self.install_wapt(fname(self.waptdb.package_entry_from_db(p).Filename),params_dict)
        for p in to_upgrade:
            self.install_wapt(fname(to_upgrade[p]['Filename']),params_dict)
        for p in packages:
            self.install_wapt(fname(self.waptdb.package_entry_from_db(p).Filename),params_dict)

    def download_packages(self,packages,usecache=True):
        for (package,version) in packages:
            entry = self.waptdb.package_entry_from_db(package,version)
            packagefilename = entry.Filename.strip('./')
            download_url = entry.repo_url+'/'+packagefilename
            fullpackagepath = os.path.join(self.packagecachedir,packagefilename)
            if os.path.isfile(fullpackagepath) and os.path.getsize(fullpackagepath)>0 and usecache:
                print ("  using cached package file from " + fullpackagepath)
            else:
                print ("  downloading package from %s" % download_url)
                try:
                    wget( download_url, self.packagecachedir)
                except BaseException as e:
                    if os.path.isfile(fullpackagepath):
                        os.remove(fullpackagepath)
                    print "Error downloading package from http repository, please update... error : %s" % e
                    raise

    def remove(self,package):
        q = self.waptdb.query("""\
           select * from wapt_localstatus
            where Package=?
           """ , (package,) )
        if not q:
            print "Package %s not installed, aborting" % package
            return True

        mydict = q[0]
        print "Removing package %s version %s from computer..." % (mydict['Package'],mydict['Version'])

        if mydict['UninstallString']:
            print subprocess.check_output(mydict['UninstallString'])
            logger.info('Remove status record from local DB')
            self.waptdb.remove_install_status(package)
        elif mydict['UninstallKey']:
            if mydict['UninstallKey'][0] not in ['[','"',"'"]:
                guids = mydict['UninstallKey']
            else:
                try:
                    guids = eval(mydict['UninstallKey'])
                except:
                    guids = mydict['UninstallKey']

            if isinstance(guids,(unicode,str)):
                guids = [guids]

            for guid in guids:
                uninstall_cmd = self.uninstall_cmd(guid)
                logger.info('Launch uninstall cmd %s' % (uninstall_cmd,))
                print subprocess.check_output(uninstall_cmd)
            logger.info('Remove status record from local DB')
            self.waptdb.remove_install_status(package)
        else:
            self.waptdb.remove_install_status(package)
            raise Exception('  uninstall key not registered in local DB status, unable to remove. Unregistering anyway. Please remove manually')

    def upgrade(self):
        q = self.waptdb.query("""\
           select wapt_repo.Package,wapt_repo.Version from wapt_localstatus
            left join wapt_repo on wapt_repo.Package=wapt_localstatus.Package
            where wapt_localstatus.Version<wapt_repo.Version
           """)
        if not q:
            print "Nothing to upgrade"
        else:
            self.install([p['Package'] for p in q])

    def list_upgrade(self):
        q = self.waptdb.db.execute("""\
           select wapt_repo.Package,wapt_localstatus.Version as Installed,wapt_repo.Version as Available from wapt_localstatus
            left join wapt_repo on wapt_repo.Package=wapt_localstatus.Package
            where wapt_localstatus.Version<wapt_repo.Version
           """)
        if not q:
            print "Nothing to upgrade"
        else:
            print pptable(q,None,1,None)

    def list_repo(self,search):
        print self.waptdb.list_repo(search)

    def list_installed_packages(self,search):
        print self.waptdb.list_installed_packages(search)

def main():
    if len(args) == 0:
        print "ERROR : You must provide one action to perform"
        parser.print_usage()
        sys.exit(2)

    action = args[0]

    # Config file
    if not os.path.isfile(config_file):
        logger.error("Error : could not find file : " + config_file + ", please check the path")

    logger.debug('Config file: %s' % config_file)
    cp = ConfigParser( )
    cp.read(config_file)

    wapt_repourl = find_wapt_server(cp)
    if not wapt_repourl:
        print "No valid accessible repository found... aborting"
        sys.exit(2)
    logger.info("Using wapt Repository %s" % wapt_repourl)
    wapt_base_dir = cp.get('global','base_dir')

    log_dir = os.path.join(wapt_base_dir,'log')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    packagecachedir = os.path.join(wapt_base_dir,'cache')
    if not os.path.exists(packagecachedir):
        os.makedirs(packagecachedir)
    logger.debug('Package cache dir : %s' % packagecachedir)

    mywapt = Wapt()
    mywapt.packagecachedir = packagecachedir
    mywapt.wapt_repourl = wapt_repourl
    mywapt.dry_run = options.dry_run

    try:
        if action=='install':
            if len(args)<2:
                print "You must provide at least one package name"
                sys.exit(1)
            params_dict = {}
            try:
                params_dict = json.loads(options.params.replace("'",'"'))
            except:
                raise Exception('Install Parameters should be in json format')

            if os.path.isdir(args[1]) or os.path.isfile(args[1]):
                mywapt.install_wapt(args[1],params_dict = params_dict)
            else:
                mywapt.install(args[1:],force = options.force,params_dict = params_dict)

        elif action=='download':
            if len(args)<2:
                print "You must provide at least one package name to download"
                sys.exit(1)
            mywapt.download_packages([(p,None) for p in args[1:]],usecache = not options.force )

        elif action=='show':
            if len(args)<2:
                print "You must provide at least one package name to show"
                sys.exit(1)
            for packagename in args[1:]:
                entry = mywapt.waptdb.package_entry_from_db(packagename)
                print entry


        elif action=='list-registry':
            print "%-39s%-70s%-20s" % ('UninstallKey','Software','Version')
            print '-'*39+'-'*70 + '-'*20
            for p in mywapt.registry_installed_softwares(' '.join(args[1:])) :
                print u"%-39s%-70s%-20s" % (p['key'],p['DisplayName'],p['DisplayVersion'])


        elif action=='showlog':
            if len(args)<2:
                print "You must provide at least one package name"
                sys.exit(1)
            for packagename in args[1:]:
                mywapt.showlog(packagename)

        elif action=='remove':
            if len(args)<2:
                print "You must provide at least one package name to remove"
                sys.exit(1)
            for packagename in args[1:]:
                mywapt.remove(packagename)

        elif action=='update':
            mywapt.waptdb.update_packages_list(mywapt.wapt_repourl)

        elif action=='upgrade':
            mywapt.upgrade()
            sys.exit(0)

        elif action=='list-upgrade':
            mywapt.list_upgrade()

        elif action=='update-packages':
            if len(args)<2:
                print "You must provide the directory"
                sys.exit(1)
            update_packages(args[1])

        elif action=='source':
            if len(args)<2:
                print "You must provide the package name"
                sys.exit(1)
            mywapt.get_sources(args[1])

        elif action=='search':
            mywapt.list_repo(args[1:])

        elif action=='cleanup':
            mywapt.cleanup()

        elif action=='list':
            mywapt.list_installed_packages(args[1:])
        else:
            print 'Unknown action %s' % action
            sys.exit(1)
    except Exception,e:
        print "FATAL ERROR : %s" % e
        if logger.level == logging.DEBUG:
            raise
        sys.exit(3)

if __name__ == "__main__":
    logger.debug('Python path %s' % sys.path)
    main()
