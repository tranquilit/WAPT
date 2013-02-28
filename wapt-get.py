#!/usr/bin/python
# -*- coding: UTF-8 -*-

__version__ = "0.7.2"

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
import pprint
import socket
import codecs
import setuphelpers
from setuphelpers import *
import json
import glob
import platform
import imp
import shlex

from _winreg import HKEY_LOCAL_MACHINE,EnumKey,OpenKey,QueryValueEx,EnableReflectionKey,DisableReflectionKey,QueryReflectionKey,QueryInfoKey,KEY_READ,KEY_WOW64_32KEY,KEY_WOW64_64KEY

usage="""\
%prog -c configfile action

WAPT install system.

action is either :
  install [packages]: install one or several packages
  update : update package database
  upgrade : upgrade installed packages

  download [packages]: force download one or several packages
  show [packages]: show attributes of one or more packages
  showparams package: show required and optional parameters of one package

  list [keywords]: list installed packages
  list-upgrade  : list upgradable packages
  list-registry [keywords] : list installed software from Windows Registry
  search [keywords] : search installable packages whose description contains keywords
  cleanup : remove all WAPT cached files from local drive

  update-packages <directory> : rebuild a "Packages" file for http package repository

"""


parser=OptionParser(usage=usage,version="%prog " + __version__+' setuphelpers '+setuphelpers.__version__)
parser.add_option("-c","--config", dest="config", default='c:\\wapt\\wapt-get.ini', help="Config file full path (default: %default)")
parser.add_option("-l","--loglevel", dest="loglevel", default='info', type='choice',  choices=['debug','warning','info','error','critical'], metavar='LOGLEVEL',help="Loglevel (default: %default)")
parser.add_option("-d","--dry-run",    dest="dry_run",    default=False, action='store_true', help="Dry run (default: %default)")
parser.add_option("-f","--force",    dest="force",    default=False, action='store_true', help="Force (default: %default)")
parser.add_option("-p","--params", dest="params", default='{}', help="Setup params as a JSon Object (example : {'licence':'AZE-567-34','company':'TIS'}} (default: %default)")
parser.add_option("-r","--repository", dest="wapt_url", default='', help="URL of wapt repository (override url of ini file, example http://wapt/wapt) (default: %default)")

(options,args)=parser.parse_args()

# setup Logger
logger = logging.getLogger('wapt-get')
config_file =options.config
loglevel = options.loglevel

if len(logger.handlers)<1:
    hdlr = logging.StreamHandler(sys.stdout)
    hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(hdlr)

# set loglevel
if loglevel in ('debug','warning','info','error','critical'):
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)
    logger.setLevel(numeric_level)

wapt_base_dir = os.path.split(sys.argv[0])[0]
WAPTDBPATH = os.path.join(wapt_base_dir,'db','waptdb.sqlite')

logger.debug('WAPT base directory : %s' % wapt_base_dir)

def import_setup(setupfilename,modulename=''):
    """Import setupfilename as modulename, return the module object"""
    mod_name,file_ext = os.path.splitext(os.path.split(setupfilename)[-1])
    if not modulename:
        modulename=mod_name
    py_mod = imp.load_source(modulename, setupfilename)
    return py_mod


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
        self.dbpath = WAPTDBPATH
        self._waptdb = None

    @property
    def waptdb(self):
        if not self._waptdb:
            self._waptdb = WaptDB(dbpath=self.dbpath)
        return self._waptdb

    def registry_uninstall_snapshot(self):
        """return list of uninstall ID from registry"""
        result = []
        key = openkey_noredir(HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        try:
            i = 0
            while True:
                subkey = EnumKey(key, i)
                result.append(subkey)
                i += 1
        except WindowsError,e:
            # WindowsError: [Errno 259] No more data is available
            if e.winerror == 259:
                pass
            else:
                raise
        if platform.machine() == 'AMD64':
            key = openkey_noredir(HKEY_LOCAL_MACHINE,"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
            try:
                i = 0
                while True:
                    subkey = EnumKey(key, i)
                    result.append(subkey)
                    i += 1
            except WindowsError,e:
                # WindowsError: [Errno 259] No more data is available
                if e.winerror == 259:
                    pass
                else:
                    raise
        return result

    def uninstall_cmd(self,guid):
        """return cmd to uninstall from registry"""
        def get_fromkey(uninstall):
            key = openkey_noredir(HKEY_LOCAL_MACHINE,"%s\\%s" % (uninstall,guid))
            try:
                cmd = QueryValueEx(key,'QuietUninstallString')[0]
                return cmd
            except WindowsError:
                cmd = QueryValueEx(key,'UninstallString')[0]
                if 'msiexec' in cmd.lower():
                    cmd = cmd.replace('/I','/X').replace('/i','/X')
                    args = shlex.split(cmd,posix=False)
                    if not '/q' in cmd.lower():
                        args.append('/q')
                else:
                    # mozilla et autre
                    args = shlex.split(cmd,posix=False)
                    # remove double quotes if any
                    if args[0].startswith('"') and args[0].endswith('"'):
                        args[0] = args[0][1:-1]
                    if ('uninst' in cmd.lower() or 'helper.exe' in cmd.lower()) and not ' /s' in cmd.lower():
                        args.append('/S')
                    if ('unins000' in cmd.lower()) and not ' /silent' in cmd.lower():
                        args.append('/silent')
                return args
        try:
            return get_fromkey("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        except:
            if platform.machine() == 'AMD64':
                return get_fromkey("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
            else:
                raise

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

            # import the setup module from package file
            logger.info("  sourcing install file %s " % setup_filename )
            setup = import_setup(setup_filename,'_waptsetup_')
            required_params = []

            # be sure some minimal functions are available in setup module at install step
            setattr(setup,'basedir',os.path.dirname(setup_filename))
            setattr(setup,'run',run)
            setattr(setup,'run_notfatal',run_notfatal)
            setattr(setup,'WAPT',self)

            # get definitions of required parameters from setup module
            if hasattr(setup,'required_params'):
                required_params = setup.required_params

            # get value of required parameters if not already supplied
            for p in required_params:
                if not p in params_dict:
                    params_dict[p] = raw_input("%s: " % p)

            # set params dictionary
            if not hasattr(setup,'params'):
                # create a params variable for the setup module
                setattr(setup,'params',params_dict)
            else:
                # update the already created params with additional params from command line
                setup.params.update(params_dict)

            if not self.dry_run:
                try:
                    logger.info("  executing install script")
                    exitstatus = setup.install()
                except Exception,e:
                    logger.critical('Fatal error in install script: %s' % e)
                    raise

            if exitstatus is None or exitstatus == 0:
                status = 'OK'
            else:
                status = 'ERROR'

            # get uninstallkey from setup module (string or array of strings)
            if hasattr(setup,'uninstallkey'):
                new_uninstall_key = '%s' % (setup.uninstallkey,)
            else:
                new_uninstall = self.registry_uninstall_snapshot()
                new_uninstall_key = [ k for k in new_uninstall if not k in previous_uninstall]

            # get uninstallstring from setup module (string or array of strings)
            if hasattr(setup,'uninstallstring'):
                uninstallstring = setup.uninstallstring
            else:
                uninstallstring = None
            logger.info('  uninstall keys : %s' % (new_uninstall_key,))
            logger.info('  uninstall strings : %s' % (uninstallstring,))

            logger.info("Install script finished with status %s" % status)
            if istemporary:
                os.chdir(previous_cwd)
                logger.debug("Cleaning package tmp dir")
                shutil.rmtree(packagetempdir)

            self.waptdb.update_install_status(install_id,status,'',str(new_uninstall_key) if new_uninstall_key else '',str(uninstallstring) if uninstallstring else '')
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
        """Install a list of packages and its dependencies
            apackages is a list of packages names. A specifi version can be specified
            force=True reinstalls the packafes even if it is already installed
            params_dict is passed to the install() procedure in the packages setup.py of all packages
                as params variables and as "setup module" attributes
        """
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
            print "  Additional packages to install :\n   %s" % (','.join(additional_install),)
        if to_upgrade:
            print "  Packages to upgrade :\n   %s" % (','.join(to_upgrade),)

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
                print ("  Use cached package file from " + fullpackagepath)
            else:
                print ("  Downloading package from %s" % download_url)
                try:
                    wget( download_url, self.packagecachedir)
                except BaseException as e:
                    if os.path.isfile(fullpackagepath):
                        os.remove(fullpackagepath)
                    print "Error downloading package from http repository, please update... error : %s" % e
                    raise

    def remove(self,package):
        """Removes a package giving its package name, unregister from local status DB"""
        q = self.waptdb.query("""\
           select * from wapt_localstatus
            where Package=?
           """ , (package,) )
        if not q:
            print "Package %s not installed, aborting" % package
            return True

        # several versions installed of teh same package... ?
        for mydict in q:
            print "Removing package %s version %s from computer..." % (mydict['Package'],mydict['Version'])

            if mydict['UninstallString']:
                if mydict['UninstallString'][0] not in ['[','"',"'"]:
                    guids = mydict['UninstallString']
                else:
                    try:
                        guids = eval(mydict['UninstallString'])
                    except:
                        guids = mydict['UninstallString']
                if isinstance(guids,(unicode,str)):
                    guids = [guids]
                for guid in guids:
                    try:
                        logger.info('Running %s' % guid)
                        logger.info(subprocess.check_output(guid))
                    except Exception,e:
                        logger.info("Warning : %s" % e)
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
                    print subprocess.check_output(uninstall_cmd,shell=True)
                logger.info('Remove status record from local DB')
                self.waptdb.remove_install_status(package)
            else:
                self.waptdb.remove_install_status(package)
                raise Exception('  uninstall key not registered in local DB status, unable to remove. Unregistering anyway. Please remove manually')

    def upgrade(self):
        """\
Query localstatus database for packages with a version older than repository
and install all newest packages"""
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
        """Displays a list of packages that can be upgraded"""
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

    def inventory(self):
        inv = {}
        inv['softwares'] = installed_softwares('')
        inv['packages'] = self.waptdb.installed()
        return inv

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

    if options.wapt_url:
        wapt_repourl = options.wapt_url
        logger.info("Trying wapt Repository %s" % wapt_repourl)
        if not _tryurl(wapt_repourl):
            print "Supplied repository %s is not accessible ... aborting" % wapt_repourl
            sys.exit(2)
    else:
        wapt_repourl = find_wapt_server(cp)
    if not wapt_repourl:
        print "No valid accessible repository found... aborting"
        sys.exit(2)
    logger.info("Using wapt Repository %s" % wapt_repourl)

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
            if os.path.isdir(args[1]) or os.path.isfile(args[1]):
                entry = Package_Entry().load_control_from_wapt(args[1])
                print "%s" % entry
            else:
                for packagename in args[1:]:
                    entry = mywapt.waptdb.package_entry_from_db(packagename)
                    print "%s" % entry
        elif action=='showparams':
            if len(args)<2:
                print "You must provide at one package name to show params for"
                sys.exit(1)
            for packagename in args[1:]:
                params = mywapt.waptdb.params(packagename)
                print "%s" % params

        elif action=='list-registry':
            print "%-39s%-70s%-20s%-70s" % ('UninstallKey','Software','Version','Uninstallstring')
            print '-'*39+'-'*70 + '-'*20 + '-'*70
            for p in installed_softwares(' '.join(args[1:])) :
                print u"%-39s%-70s%-20s%-70s" % (p['key'],p['name'],p['version'],p['uninstallstring'])

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

        elif action=='inventory':
            print mywapt.inventory()

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
