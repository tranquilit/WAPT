#!/usr/bin/python
# -*- coding: UTF-8 -*-
import sys
import os
import zipfile
import cStringIO
import urllib2
import shutil
from iniparse import ConfigParser
from optparse import OptionParser
import logging
import datetime
from common import WaptDB
from common import Package_Entry
from common import update_packages
import dns.resolver
import pprint
import socket
import codecs
from setuphelpers import *
import json



usage="""\
%prog -c configfile action

WAPT install system.

action is either :
  install [packages]: install one or several packages
  update : update package database
  upgrade : upgrade installed packages
  list : list installed packages
  list-upgrade : list upgradable packages
  search [keywords] : search packages whose description contains keywords

  update-packages <directory> : rebuild a "Packages" file for http package repository

"""

version = "0.5.3"

parser=OptionParser(usage=usage,version="%prog " + version)
parser.add_option("-c","--config", dest="config", default='c:\\wapt\\wapt-get.ini', help="Config file full path (default: %default)")
parser.add_option("-l","--loglevel", dest="loglevel", default='info', type='choice',  choices=['debug','warning','info','error','critical'], metavar='LOGLEVEL',help="Loglevel (default: %default)")
parser.add_option("-d","--dry-run",    dest="dry_run",    default=False, action='store_true', help="Dry run (default: %default)")
parser.add_option("-f","--force",    dest="force",    default=False, action='store_true', help="Force (default: %default)")

(options,args)=parser.parse_args()

# setup Logger
logger = logging.getLogger('wapt-get')
config_file =options.config
loglevel = options.loglevel

hdlr = logging.StreamHandler()
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
    if url and tryurl(url):
        return url
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

class LogOutput(object):
    def __init__(self,console):
        self.output = []
        self.console = console

    def write(self,txt):
        self.console.write(txt)
        if txt <> '\n':
            self.output.append(txt)

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


    def install_wapt(self,fname):
        old_stdout = sys.stdout
        # we setup a redirection of stdout to catch print output from install scripts
        sys.stdout = installoutput = LogOutput(sys.stdout)
        try:
            logger.info("installing package " + fname)
            global packagetempdir
            packagetempdir = tempfile.mkdtemp(prefix="wapt")
            logger.info('  unzipping %s ' % (fname))
            zip = zipfile.ZipFile(fname)
            zip.extractall(path=packagetempdir)

            logger.info("  sourcing install file")
            psource(os.path.join( packagetempdir,'setup.py'))

            if not self.dry_run:
                logger.info("  executing install script")
                #sys.stdout.flush()
                exitstatus = setup.install()

            logger.info("Add package to local DB")
            entry = Package_Entry()
            entry.load_control_from_wapt(fname)
            if exitstatus is None:
                status = 'UNKNOWN'
            elif exitstatus == 0:
                status = 'OK'
            else:
                status = 'ERROR'

            self.waptdb.add_installed_package(entry.Package,entry.Version,status,json.dumps({'output':installoutput.output,'exitstatus':exitstatus}))

            logger.info("Install script finished with status %s" % status)
            logger.debug("Cleaning package tmp dir")
            #sys.stdout.flush()
            shutil.rmtree(packagetempdir)
        finally:
            sys.stdout = old_stdout

    def install(self,package):
        #sys.stdout.flush()
        if os.path.isfile(package):
            self.install_wapt(package)
        else:
            q = self.waptdb.query("""\
               select wapt_repo.*,wapt_localstatus.Version as CurrentVersion from wapt_repo
                left join wapt_localstatus on wapt_repo.Package=wapt_localstatus.Package
                where wapt_repo.Package=?
               """ , (package,) )
            if not q:
                print "ERROR : Package %s not found in local DB, try update" % package
                return False
            mydict = q[0]
            logger.debug(pprint.pformat(mydict))
            if not options.force and mydict['CurrentVersion']>=mydict['Version']:
                print "Package %s already installed at the latest version" % package
                return True
            packagefilename = mydict['Filename'].strip('./')
            download_url = mydict['repo_url'] + '/' + packagefilename
            logger.debug('Download URL: %s' % download_url)
            fullpackagepath = os.path.join(self.packagecachedir,packagefilename)

            if os.path.isfile(fullpackagepath) and os.path.getsize(fullpackagepath)>0:
                print ("  using cached package file from " + fullpackagepath)
            else:
                print ("  downloading package from " + mydict['repo_url'])
                #sys.stdout.flush()
                wget( download_url, self.packagecachedir)

            self.install_wapt(fullpackagepath)

    def update(self,repourl=''):
        """Get Packages from http repo and update local package database"""
        if not repourl:
            repourl = self.wapt_repourl
        logger.debug('Temporary directory: %s' % tempdir)
        packageListFile = codecs.decode(zipfile.ZipFile(
              cStringIO.StringIO( urllib2.urlopen( repourl + '/Packages').read())
            ).read(name='Packages'),'UTF-8').splitlines()

        package = Package_Entry()
        for line in packageListFile:
            # new package
            if line.strip()=='':
                logger.debug(package)
                package.repo_url = repourl
                self.waptdb.add_package_entry(package)
                package = Package_Entry()
            # add ettribute to current package
            else:
                splitline= line.split(':')
                setattr(package,splitline[0].strip(),splitline[1].strip())
        # last one
        if package.Package:
            self.waptdb.add_package_entry(package)

        self.waptdb.db.commit()

    def upgrade(self):
        q = self.waptdb.query("""\
           select wapt_repo.Package,wapt_repo.Version from wapt_localstatus
            left join wapt_repo on wapt_repo.Package=wapt_localstatus.Package
            where wapt_localstatus.Version<wapt_repo.Version
           """)
        if not q:
            print "Nothing to upgrade"
            sys.exit(1)
        for package in q:
            self.install(package['Package'])

    def list_upgrade(self):
        q = self.waptdb.query("""\
           select wapt_repo.Package,wapt_repo.Version from wapt_localstatus
            left join wapt_repo on wapt_repo.Package=wapt_localstatus.Package
            where wapt_localstatus.Version<wapt_repo.Version
           """)
        if not q:
            print "Nothing to upgrade"
            sys.exit(1)
        print common.pp(q,None,1,None)


    def list_repo(self,search):
        print self.waptdb.list_repo(search)

    def list_installed_packages(self):
        print self.waptdb.list_installed_packages()

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

    if action=='install':
        if len(args)<2:
            print "You must provide at least one package name"
            sys.exit(1)
        for packagename in args[1:]:
            mywapt.install(packagename)

    elif action=='update':
        mywapt.update()

    elif action=='upgrade':
        mywapt.upgrade()

    elif action=='list-upgrade':
        mywapt.list_upgrade()

    elif action=='remove':
        mywapt.remove()

    elif action=='update-packages':
        if len(args)<2:
            print "You must provide the directory"
            sys.exit(1)
        update_packages(args[1])

    elif action=='init':
        mywapt.make_packages()

    elif action=='search':
        mywapt.list_repo(args[1:])

    elif action=='list':
        mywapt.list_installed_packages()
    else:
        print 'Unknown action %s' % action

if __name__ == "__main__":
    logger.debug('Python path %s' % sys.path)
    main()

