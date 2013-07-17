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

__version__ = "0.6.29"

import sys
import os
import shutil
from optparse import OptionParser
import logging
import datetime
from common import WaptDB
from waptpackage import PackageEntry
from waptpackage import update_packages
from common import ppdicttable
from common import jsondump
import setuphelpers
from setuphelpers import ensure_unicode

import locale

#from setuphelpers import *
import json
import glob
import codecs
import getpass

from common import Wapt

usage="""\
%prog -c configfile action

WAPT install system.

action is either :
  install [packages]: install one or several packages by name, directory or wapt file
  update : update package database
  upgrade : upgrade installed packages, install host package if not installed.
  remove [packages] : remove installed packages

  download [packages]: force download one or several packages
  show [packages]: show attributes of one or more packages

  list [keywords]   : list installed packages containing keywords
  list-upgrade      : list upgradable packages
  download-upgrade  : download available upgradable packages
  search [keywords] : search installable packages whose description contains keywords
  clean             : remove all WAPT cached files from local drive

  setup-tasks       : creates Windows daily scheduled tasks for update/download-upgrade/upgrade
  enable-tasks
  disable-tasks

  register [description] : Add the computer to the WAPT server database,
                                     change the description of the computer.
  inventory         : get json encoded list of host data, installed packages and softwares as supplied to server with register
  update-status     : Send packages and softwares status to the WAPT server,

 For user session setup
  session-setup [packages,ALL] : setup local user environment for specific or all installed packages

 For packages development
  list-registry [keywords]  : list installed software from Windows Registry
  sources <package>         : checkout or update sources of a package from SVN repository (if attribute Sources was supplied in control file)
  make-template <installer-path> [<packagename> [<source directoryname>]] : initializes a package template with an installer (exe or msi)
  make-host-template <machinename> [[<package>,<package>,...] [directory]] :
                                initializes a package meta template with packages.
                                If no package name is given, use FQDN
                                If no packages are given, use currently installed
  make-group-template <groupname> [[<package>,<package>,...] [directory]] :
                                initializes a meta package template with supplied dependencies.

  build-package <directory> : creates a WAPT package from supplied directory
  sign-package <directory or package>  : add a signature of the manifest using a private SSL key
  build-upload <directory> : creates a WAPT package from supplied directory, sign it and upload it
  duplicate <directory or package> <new-package-name> [<new-version> [<target directory>]] : duplicate an existing package,
                                            changing its name (can be used for duplication of host packages...)
  edit <package> : download and unzip a package. Open in Explorer the target directory
  edit-host <host fwqdn> : download an unzip a host package. Open in Explorer the target directory

 For repository management
  upload-package  <filenames> : upload package to repository (using winscp for example.)
  update-packages <directory> : rebuild a "Packages" file for http package repository

"""

parser=OptionParser(usage=usage,version="%prog " + __version__+' setuphelpers '+setuphelpers.__version__)
parser.add_option("-c","--config", dest="config", default=os.path.join(os.path.dirname(sys.argv[0]),'wapt-get.ini') , help="Config file full path (default: %default)")
parser.add_option("-l","--loglevel", dest="loglevel", default=None, type='choice',  choices=['debug','warning','info','error','critical'], metavar='LOGLEVEL',help="Loglevel (default: warning)")
parser.add_option("-d","--dry-run",    dest="dry_run",    default=False, action='store_true', help="Dry run (default: %default)")
parser.add_option("-u","--update-packages",    dest="update_packages",  default=False, action='store_true', help="Update Packages first then action (default: %default)")
parser.add_option("-f","--force",    dest="force",    default=False, action='store_true', help="Force (default: %default)")
parser.add_option("-p","--params", dest="params", default='{}', help="Setup params as a JSon Object (example : {'licence':'AZE-567-34','company':'TIS'}} (default: %default)")
parser.add_option("-r","--repository", dest="wapt_url", default='', help="URL of main wapt repository (override url from ini file, example http://wapt/wapt) (default: %default)")
parser.add_option("-i","--inc-release",    dest="increlease",    default=False, action='store_true', help="Increase release number when building package (default: %default)")
parser.add_option("-j","--json",    dest="json_output",    default=False, action='store_true', help="Switch to json output for scripts purpose (default: %default)")
parser.add_option("-e","--encoding",    dest="encoding",    default=None, help="Chararacter encoding for the output (default: no change)")
parser.add_option("-x","--excludes",    dest="excludes",    default='.svn,.git*,*.pyc,*.dbg,src', help="Comma separated list of files or directories to exclude for build-package (default: %default)")
parser.add_option("-k","--private-key", dest="private_key",    default='', help="Path to the PEM RSA private key to sign packages. Package are unsigned if not provided (default: %default)")
parser.add_option("-w","--private-key-passwd", dest="private_key_passwd", default='', help="Path to the password of the private key. (default: %default)")
parser.add_option("-U","--user", dest="user", default=None, help="Interactive user (default: no change)")
parser.add_option("-g","--usergroups", dest="usergroups", default='[]', help="Groups of the final user as a JSon array for checking install permission (default: %default)")
parser.add_option("-t","--maxttl", type='int',  dest="max_ttl", default=60, help="Max run time of wapt-get process before being killed by subsequent wapt-get (default: %default)")
parser.add_option("-L","--language",    dest="language",    default=setuphelpers.get_language(), help="Override language for install (example : fr) (default: %default)")

(options,args)=parser.parse_args()

encoding = options.encoding
if not encoding:
    encoding = sys.stdout.encoding or 'cp850'

sys.stdout = codecs.getwriter(encoding)(sys.stdout,'replace')
sys.stderr = codecs.getwriter(encoding)(sys.stderr,'replace')

# setup Logger
logger = logging.getLogger()
config_file =options.config
loglevel = options.loglevel

if len(logger.handlers)<1:
    hdlr = logging.StreamHandler(sys.stderr)
    hdlr.setFormatter(logging.Formatter(u'%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(hdlr)

def setloglevel(loglevel):
    """set loglevel as string"""
    if loglevel in ('debug','warning','info','error','critical'):
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % loglevel)
        logger.setLevel(numeric_level)

if loglevel:
    setloglevel(loglevel)
else:
    setloglevel('warning')

logger.debug(u'Default encoding : %s ' % sys.getdefaultencoding())
logger.debug(u'Setting encoding for stdout and stderr to %s ' % encoding)

key_passwd = None

class JsonOutput(object):
    """file like to print output to json"""
    def __init__(self,output,logger):
        self.output = output
        self.logger = logger

    def write(self,txt):
        txt = ensure_unicode(txt)
        if txt <> '\n':
            logger.info(txt)
            self.output.append(txt)

    def __getattrib__(self, name):
        if hasattr(self.console,'__getattrib__'):
            return self.console.__getattrib__(name)
        else:
            return self.console.__getattribute__(name)

def main():
    jsonresult = {'output':[]}
    if options.json_output:
        # redirect output to json list
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stderr = sys.stdout = output = JsonOutput(jsonresult['output'],logger)

    try:
        if len(args) == 0:
            print u"ERROR : You must provide one action to perform"
            parser.print_usage()
            sys.exit(2)

        action = args[0]

        # Config file
        if not os.path.isfile(config_file):
            logger.error(u"Error : could not find file : " + config_file + ", please check the path")

        logger.debug(u'Config file: %s' % config_file)


        mywapt = Wapt(config_filename=config_file)
        if options.wapt_url:
            mywapt.config.set('global','repo_url',options.wapt_url)

        global loglevel
        if not loglevel and mywapt.config.has_option('global','loglevel'):
            loglevel = mywapt.config.get('global','loglevel')
            setloglevel(loglevel)

        mywapt.options = options

        if options.private_key:
            mywapt.private_key = options.private_key

        if options.language:
            mywapt.language = options.language

        if options.usergroups:
            mywapt.usergroups = json.loads(options.usergroups.replace("'",'"'))
            logger.info(u'User Groups:%s' % (mywapt.usergroups,))

        if options.user:
            mywapt.user = options.user
            logger.info(u'Interactive user :%s' % (mywapt.user,))

        mywapt.dry_run = options.dry_run

        logger.debug(u'WAPT base directory : %s' % mywapt.wapt_base_dir)
        logger.debug(u'Package cache dir : %s' %  mywapt.packagecachedir)
        logger.debug(u'WAPT DB Structure version;: %s' % mywapt.waptdb.db_version)

        try:
            params_dict = {}
            try:
                params_dict = json.loads(options.params.replace("'",'"'))
            except:
                raise Exception('Installation Parameters must be in json format')

            # cleanup environement, remove stalled wapt-get, update install_status
            if action in ('install','download','remove','uninstall','update','upgrade'):
                running_install = mywapt.check_install_running(max_ttl=options.max_ttl)
            else:
                running_install = []

            if action=='install' or action=='download':
                if len(args)<2:
                    print u"You must provide at least one package name"
                    sys.exit(1)

                if os.path.isdir(args[1]) or os.path.isfile(args[1]):
                    print u"Installing WAPT file %s" % args[1]
                    if action=='install':
                        # abort if there is already a running install in progress
                        if running_install:
                            raise Exception('Running wapt-get in progress, please wait...')
                        result= {'install':[ (args[1],mywapt.install_wapt(args[1],params_dict = params_dict))]}
                else:
                    print u"%sing WAPT packages %s" % (action,','.join(args[1:]))
                    if options.update_packages:
                        print u"Update package list"
                        mywapt.update()

                    if running_install and action=='install':
                        raise Exception('Running wapt-get in progress, please wait...')
                    result = mywapt.install(args[1:],force = options.force,params_dict = params_dict,
                        download_only= (action=='download'),
                        )

                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print u"\nResults :"
                    if action<>'download':
                        for k in ('install','additional','upgrade','skipped','errors'):
                            if result.get(k,[]):
                                print u"\n=== %s packages ===\n%s" % (k,'\n'.join( ["  %-30s | %s (%s)" % (s[0],s[1].package,s[1].version) for s in  result[k]]),)
                    else:
                        for k in ('downloaded','skipped','errors'):
                            if result.get('downloads', {'downloaded':[],'skipped':[],'errors':[]} )[k]:
                                print u"\n=== %s packages ===\n%s" % (k,'\n'.join(["  %s" % (s,) for s in result['downloads'][k]]),)
                if mywapt.wapt_server:
                    try:
                        mywapt.update_server_status()
                    except Exception,e:
                        logger.critical('Unable to update server with current status : %s' % ensure_unicode(e))


            elif action=='download':
                if len(args)<2:
                    print u"You must provide at least one package name to download"
                    sys.exit(1)
                if options.update_packages:
                    print u"Update package list"
                    mywapt.update()
                print u"Downloading packages %s" % (','.join(args[1:]),)
                result = mywapt.download_packages(args[1:],usecache = not options.force )
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    if result['downloaded']:
                        print u"\nDownloaded packages : \n%s" % u"\n".join([ "  %s" % p for p in result['downloaded'] ])
                    if result['skipped']:
                        print u"Skipped packages : \n%s" % u"\n".join([ u"  %s" % p for p in result['skipped'] ])
                if result['errors']:
                    logger.critical(u'Unable to download some files : %s'% (result['errors'],))
                    sys.exit(1)

            elif action=='show':
                if len(args)<2:
                    print u"You must provide at least one package name to show"
                    sys.exit(1)
                result = []
                if os.path.isdir(args[1]) or os.path.isfile(args[1]):
                    result.append[PackageEntry().load_control_from_wapt(args[1])]
                else:
                    if options.update_packages:
                        print u"Update packages list"
                        mywapt.update()
                    for packagename in args[1:]:
                        result.extend(mywapt.waptdb.packages_matching(packagename))

                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print u"Display package control data for %s\n" % (','.join(args[1:]),)
                    for p in result:
                        print p.ascontrol(with_non_control_attributes=True)

            elif action=='show-params':
                if len(args)<2:
                    print u"You must provide at one package name to show params for"
                    sys.exit(1)
                for packagename in args[1:]:
                    params = mywapt.waptdb.params(packagename)
                    print u"%s" % params

            elif action=='list-registry':
                result = setuphelpers.installed_softwares(' '.join(args[1:]))
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print u"%-39s%-70s%-20s%-70s" % ('UninstallKey','Software','Version','Uninstallstring')
                    print u'-'*39+'-'*70 + '-'*20 + '-'*70
                    for p in result:
                        print u"%-39s%-70s%-20s%-70s" % (p['key'],p['name'],p['version'],p['uninstall_string'])

            elif action=='showlog':
                if len(args)<2:
                    print u"You must provide at least one package name"
                    sys.exit(1)
                for packagename in args[1:]:
                    result = mywapt.last_install_log(packagename)
                    print u"Package : %s\nStatus : %s\n\nInstallation log:\n%s" % (packagename,result['status'],result['log'])

            elif action=='remove':
                if len(args)<2:
                    print u"You must provide at least one package name to remove"
                    sys.exit(1)
                # abort if there is already a running install in progress
                if running_install:
                    raise Exception('Running wapt-get in progress, please wait...')
                for packagename in args[1:]:
                    print u"Removing %s ..." % (packagename,)
                    result = mywapt.remove(packagename,force=options.force)

                    if mywapt.wapt_server:
                        try:
                            mywapt.update_server_status()
                        except Exception,e:
                            logger.critical('Unable to update server with current status : %s' % ensure_unicode(e))

                    if options.json_output:
                        jsonresult['result'] = result
                        if not result['removed']:
                            print "No package removed"
                            sys.exit(2)
                    else:
                        if result['removed']:
                            print u"Removed packages : \n%s" % u"\n".join([ u"  %s" % p for p in result['removed'] ])
                        else:
                            print "No package removed"
                            sys.exit(2)
                    if result['errors']:
                        logger.critical(u'Errors removing some packages : %s'% (result['errors'],))
                        sys.exit(1)

            elif action=='session-setup':
                if len(args)<2:
                    print u"You must provide at least one package to be configured in user's session or ALL (in uppercase) for all currently installed packages of this system"
                    sys.exit(1)
                result = []
                if args[1] == 'ALL':
                    packages_list = mywapt.installed().keys()
                else:
                    packages_list =  args[1:]
                for packagename in packages_list:
                    try:
                        print u"Configuring %s ..." % (packagename,),
                        result.append(mywapt.session_setup(packagename))
                        print "Done"
                    except Exception,e:
                        logger.critical(ensure_unicode(e))
                if options.json_output:
                    jsonresult['result'] = result

            elif action=='uninstall':
                # launch the setup.uninstall() procedure for the given packages
                # can be used when registering in registry a custom install with a python script
                if len(args)<2:
                    print u"You must provide at least one package to be uninstalled"
                    sys.exit(1)

                for packagename in args[1:]:
                    print u"Uninstalling %s ..." % (packagename,),
                    print mywapt.uninstall(packagename,params_dict=params_dict)
                    print u"Uninstallation done"

            elif action=='update':
                # abort if there is already a running install in progress
                if running_install:
                    raise Exception('Running wapt-get in progress, please wait...')
                print u"Update package list"
                result = mywapt.update(force=options.force)
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print u"Total packages : %i" % result['count']
                    print u"Added packages : \n%s" % "\n".join([ "  %s (%s)" % p for p in result['added'] ])
                    print u"Removed packages : \n%s" % "\n".join([ "  %s (%s)" % p for p in result['removed'] ])
                    print u"Upgradable packages : \n%s" % "\n".join([ "  %s" % p for p in result['upgrades'] ])
                    print u"Repositories URL : \n%s" % "\n".join([ "  %s" % p for p in result['repos'] ])

            elif action=='upgradedb':
                # abort if there is already a running install in progress
                if running_install:
                    raise Exception('Running wapt-get in progress, please wait...')
                (old,new) = mywapt.waptdb.upgradedb(force=options.force)
                if old == new:
                    print u"No database upgrade required, current %s, required %s" % (old,mywapt.waptdb.curr_db_version)
                else:
                    print u"Old version : %s to new : %s" % (old,new)

            elif action=='upgrade':
                if options.update_packages:
                    print u"Update packages list"
                    mywapt.update()
                # abort if there is already a running install in progress
                if running_install:
                    raise Exception('Running wapt-get in progress, please wait...')
                result = mywapt.upgrade()

                if options.json_output:
                    jsonresult['result'] = result
                else:
                    if not result['install'] and not result['additional'] and not result['upgrade'] and not result['skipped']:
                        print u"Nothing to upgrade"
                    else:
                        for k in ('install','additional','upgrade','skipped','errors'):
                            if result[k]:
                                print u"\n=== %s packages ===\n%s" % (k,'\n'.join( ["  %-30s | %s (%s)" % (s[0],s[1].package,s[1].version) for s in  result[k]]),)
                if mywapt.wapt_server:
                    try:
                        mywapt.update_server_status()
                    except Exception,e:
                        logger.critical('Unable to update server with current status : %s' % ensure_unicode(e))
                sys.exit(0)

            elif action=='list-upgrade':
                if options.update_packages:
                    print u"Update package list"
                    mywapt.update()
                result = mywapt.list_upgrade()
                if not result:
                    print u"Nothing to upgrade"
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print ppdicttable([ p for p in  result],[ ('package',20),('version',10)])

            elif action=='download-upgrade':
                # abort if there is already a running install in progress
                if running_install:
                    raise Exception('Running wapt-get in progress, please wait...')
                if options.update_packages:
                    print u"Update packages list"
                    mywapt.update()
                result = mywapt.download_upgrades()
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print u"Downloaded packages : \n%s" % "\n".join([ "  %s" % p for p in result['downloaded'] ])
                    print u"Skipped packages : \n%s" % "\n".join([ "  %s" % p for p in result['skipped'] ])

                    if result['errors']:
                        logger.critical(u'Unable to download some files : %s'% (result['errors'],))
                        sys.exit(1)

            elif action=='update-packages':
                if len(args)<2:
                    print u"You must provide the directory"
                    sys.exit(1)
                print update_packages(args[1])

            elif action=='sources':
                if len(args)<2:
                    print u"You must provide the package name"
                    sys.exit(1)
                os.startfile(mywapt.get_sources(args[1]))

            elif action=='make-template':
                if len(args)<2:
                    print u"You must provide the installer path"
                    sys.exit(1)
                result = mywapt.maketemplate(*args[1:])
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print u"Template created. You can build the WAPT package by launching\n  %s build-package %s" % (sys.argv[0],result)
                    if mywapt.upload_cmd:
                        print u"You can build and upload the WAPT package by launching\n  %s build-upload %s" % (sys.argv[0],result)
                    os.startfile(result)

            elif action in ('make-host-template','make-group-template'):
                if action == 'make-host-template':
                    result = mywapt.make_host_template(*args[1:])
                else:
                    result = mywapt.make_group_template(*args[1:])
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print u"Template created. You can build the WAPT package by launching\n  %s build-package %s" % (sys.argv[0],result)
                    if mywapt.upload_cmd:
                        print u"You can build and upload the WAPT package by launching\n  %s build-upload %s" % (sys.argv[0],result)
                    os.startfile(result)

            elif action=='duplicate':
                if len(args)<3:
                    print u"You must provide the source package and the new name"
                    sys.exit(1)
                result = mywapt.duplicate_package(*args[1:5],build=True,private_key=options.private_key)
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    if os.path.isdir(result['target']):
                        os.startfile( result)
                        print u"Package duplicated. You can build the new WAPT package by launching\n  %s build-package %s" % (sys.argv[0],result['source_dir'])
                        if mywapt.upload_cmd:
                            print u"You can build and upload the new WAPT package by launching\n  %s build-upload %s" % (sys.argv[0],result['source_dir'])
                    else:
                        print u"Package duplicated. You can upload the new WAPT package to repository by launching\n  %s upload-package %s" % (sys.argv[0],result['target'])
                        print u"You can rebuild and upload the new WAPT package by launching\n  %s build-upload %s" % (sys.argv[0],result['source_dir'])

            elif action=='edit':
                if len(args)<2:
                    print u"You must provide the package to edit"
                    sys.exit(1)
                result = mywapt.edit_package(*args[1:5])
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    if os.path.isdir(result['target']):
                        os.startfile( result['target'])
                        if mywapt.upload_cmd:
                            print u"Package edited. You can build and upload the new WAPT package by launching\n  %s build-upload %s" % (sys.argv[0],result['target'])
                        else:
                            print u"Package edited. You can build the new WAPT package by launching\n  %s build-package %s" % (sys.argv[0],result['target'])

            elif action=='edit-host':
                if len(args)<2:
                    print u"You must provide the host fqdn package to edit"
                    sys.exit(1)
                result = mywapt.edit_host(*args[1:5])
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    if os.path.isdir(result['target']):
                        os.startfile( result['target'])
                        if mywapt.upload_cmd:
                            print u"Package edited. You can build and upload the new WAPT package by launching\n  %s build-upload %s" % (sys.argv[0],result['target'])
                        else:
                            print u"Package edited. You can build the new WAPT package by launching\n  %s build-package %s" % (sys.argv[0],result['target'])

            elif action in ('build-package','build-upload'):
                if len(args)<2:
                    print u"You must provide at least one source directory for package building"
                    sys.exit(1)
                packages = []
                for source_dir in [os.path.abspath(p) for p in args[1:]]:
                    if os.path.isdir(source_dir):
                        print('Building  %s' % source_dir)
                        result = mywapt.build_package(source_dir,
                            inc_package_release=options.increlease,
                            excludes=options.excludes.split(','))
                        package_fn = result['filename']
                        if package_fn:
                            packages.append(result)
                            if not options.json_output:
                                print u"Package %s content:" % (result ['package'].asrequirement(),)
                                for f in result['files']:
                                    print u" %s" % f[0]
                            print('...done. Package filename %s' % (package_fn,))

                            def pwd_callback(*args):
                                """Default password callback for opening private keys"""
                                return open(options.private_key_passwd,'r').read()

                            def pwd_callback2(*args):
                                """Default password callback for opening private keys"""
                                global key_passwd
                                if not key_passwd:
                                    key_passwd = getpass.getpass('Private key password :').encode('ascii')
                                return key_passwd

                            if mywapt.private_key:
                                print('Signing %s' % package_fn)
                                if options.private_key_passwd:
                                    signature = mywapt.sign_package(package_fn,
                                        excludes=options.excludes.split(','),callback=pwd_callback)
                                else:
                                    signature = mywapt.sign_package(package_fn,
                                        excludes=options.excludes.split(','),callback=pwd_callback2)
                                print u"Package %s signed : signature :\n%s" % (package_fn,signature)
                            else:
                                logger.warning(u'No private key provided, package %s is unsigned !' % package_fn)

                        else:
                            logger.critical(u'package %s not created' % package_fn)
                            sys.exit(1)
                    else:
                        logger.critical(u'Directory %s not found' % source_dir)
                        sys.exit(1)

                # continue with upload
                if action == 'build-upload':
                    print 'Uploading files...'
                    # groups by www target : wapt or wapt-host
                    hosts = ('wapt-host',[])
                    others = ('wapt',[])
                    # split by destination
                    for p in packages:
                        if p['package'].section == 'host':
                            hosts[1].append(p['filename'])
                        else:
                            others[1].append(p['filename'])
                    for package_group in (hosts,others):
                        if package_group[1]:
                            # add quotes for command line
                            files_list = ['"%s"' % f for f in package_group[1]]
                            cmd_dict =  {'waptfile': files_list,'waptdir':package_group[0]}
                            print mywapt.upload_package(cmd_dict)


                            if package_group<>hosts:
                                if mywapt.after_upload:
                                    print 'Run after upload script...'
                                    print setuphelpers.run(mywapt.after_upload % cmd_dict)

                else:
                    print u'\nYou can upload to repository with\n  %s upload-package %s ' % (sys.argv[0],'"%s"' % (' '.join([p['filename'] for p in packages]),) )

            elif action=='sign-package':
                if len(args)<2:
                    print u"You must provide at least one source directory or package to sign"
                    sys.exit(1)
                for waptfile in [os.path.abspath(p) for p in args[1:]]:
                    if os.path.isdir(waptfile) or os.path.isfile(waptfile):
                        print('Signing %s' % waptfile)
                        signature = mywapt.sign_package(waptfile,
                            excludes=options.excludes.split(','))
                        print u"Package %s signed : signature :\n%s" % (waptfile,signature)
                        sys.exit(0)
                    else:
                        logger.critical(u'Package %s not found' % waptfile)
                        sys.exit(1)

            elif action=='upload-package':
                if len(args)<2:
                    print u"You must provide a package to upload"
                    sys.exit(1)
                waptfiles = []
                for a in args[1:]:
                    waptfiles += glob.glob(a)

                # groups by www target : wapt or wapt-host
                hosts = ('wapt-host',[])
                others = ('wapt',[])
                # split by destination
                for w in waptfiles:
                    p = PackageEntry()
                    p.load_control_from_wapt(w)
                    if p.section == 'host':
                        hosts[1].append(w)
                    else:
                        others[1].append(w)

                for package_group in (hosts,others):
                    if package_group[1]:
                        # add quotes for command line
                        files_list = ['"%s"' % f for f in package_group[1]]
                        cmd_dict =  {'waptfile': files_list,'waptdir':package_group[0]}

                        print mywapt.upload_package(cmd_dict)
                        if package_group<>hosts:
                            if mywapt.after_upload:
                                print 'Run after upload script...'
                                print setuphelpers.run(mywapt.after_upload % cmd_dict)

            elif action=='search':
                if options.update_packages:
                    print u"Update package list"
                    mywapt.update()
                result = mywapt.search(args[1:])
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print ppdicttable(result,(('status',10),('package',30),('version',10),('description',80),('repo',10)))

            elif action in ('clean','cleanup'):
                result = mywapt.cleanup()
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print u"Removed files : \n%s" % "\n".join([ "  %s" % p for p in result ])

            elif action=='register':
                result = mywapt.register_computer(description=" ".join(args[1:]),force=options.force)
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print u"%s" % result

            elif action=='update-status':
                result = mywapt.update_server_status (force=options.force)
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print u"%s" % result

            elif action=='inventory':
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print jsondump(mywapt.inventory(),indent=True)

            elif action=='setup-tasks':
                result = mywapt.setup_tasks()
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print result

            elif action=='enable-tasks':
                result = mywapt.enable_tasks()
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print result

            elif action=='disable-tasks':
                result = mywapt.disable_tasks()
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print result

            elif action=='list':
                def cb(fieldname,value):
                    if value and fieldname=='install_date':
                        return value[0:16]
                    else:
                        return value
                result = mywapt.list(args[1:])
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print ppdicttable(result,(('package',20),('version',15),('install_status',10),('install_date',16),('description',80)),callback=cb)

            else:
                print u'Unknown action %s' % action
                sys.exit(1)

        except Exception,e:
            print "FATAL ERROR : %s" % (ensure_unicode(e),)
            if logger.level == logging.DEBUG:
                raise
            sys.exit(3)

    except SystemExit,e:
        # catch exit code for json output
        if options.json_output:
            jsonresult['exit_code'] = e.code
        raise

    except Exception,e:
        # catch exceptions for json output
        if options.json_output:
            jsonresult['error'] = ensure_unicode(e)
        raise

    finally:
        if options.json_output:
            # restore stdin/stdout
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            # print final result
            print jsondump(jsonresult,indent=True)



if __name__ == "__main__":
    logger.debug(u'Python path %s' % sys.path)
    main()

