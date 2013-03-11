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

__version__ = "0.8.0"

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
from waptpackage import Package_Entry
from waptpackage import update_packages
from common import pptable
from common import create_recursive_zip_signed
from common import tryurl
import setuphelpers
#from setuphelpers import *
import json
import glob

from common import Wapt

usage="""\
%prog -c configfile action

WAPT install system.

action is either :
  install [packages]: install one or several packages by name, directory or wapt file
  update : update package database
  upgrade : upgrade installed packages
  remove [packages] : remove installed packages

  download [packages]: force download one or several packages
  show [packages]: show attributes of one or more packages
  show-params package: show required and optional parameters of one package

  list [keywords]   : list installed packages containing keywords
  list-upgrade      : list upgradable packages
  download-upgrade  : download available upgradable packages
  search [keywords] : search installable packages whose description contains keywords
  cleanup           : remove all WAPT cached files from local drive

 For repository management
  update-packages <directory> : rebuild a "Packages" file for http package repository

 For packages development
  list-registry [keywords] : list installed software from Windows Registry
  sources <package> : get sources of a package (if attribute Sources was supplied in control file)
  build-package <directory> : creates a WAPT package from supplied directory
  make-template <installer-path> [<packagename> [<source directoryname>]] : initializes a package template with an installer
"""

parser=OptionParser(usage=usage,version="%prog " + __version__+' setuphelpers '+setuphelpers.__version__)
parser.add_option("-c","--config", dest="config", default=os.path.join(os.path.dirname(sys.argv[0]),'wapt-get.ini') , help="Config file full path (default: %default)")
parser.add_option("-l","--loglevel", dest="loglevel", default='info', type='choice',  choices=['debug','warning','info','error','critical'], metavar='LOGLEVEL',help="Loglevel (default: %default)")
parser.add_option("-d","--dry-run",    dest="dry_run",    default=False, action='store_true', help="Dry run (default: %default)")
parser.add_option("-f","--force",    dest="force",    default=False, action='store_true', help="Force (default: %default)")
parser.add_option("-p","--params", dest="params", default='{}', help="Setup params as a JSon Object (example : {'licence':'AZE-567-34','company':'TIS'}} (default: %default)")
parser.add_option("-r","--repository", dest="wapt_url", default='', help="URL of wapt repository (override url of ini file, example http://wapt/wapt) (default: %default)")
parser.add_option("-i","--inc-release",    dest="increlease",    default=False, action='store_true', help="Increase release number when building package (default: %default)")

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
    cp = ConfigParser()
    cp.read(config_file)

    wapt_repourl = options.wapt_url
    # override main repo URL by command line option
    if wapt_repourl:
        logger.info("Trying command line WAPT Repository %s" % wapt_repourl)
        if not tryurl(wapt_repourl):
            print "Supplied repository %s is not accessible ... aborting" % wapt_repourl
            sys.exit(2)

    mywapt = Wapt(config=cp)
    if wapt_repourl:
        mywapt.wapt_repourl = wapt_repourl
    else:
        mywapt.wapt_repourl = mywapt.find_wapt_server()
    mywapt.dry_run = options.dry_run
    logger.info("Main wapt Repository %s" % mywapt.wapt_repourl)
    logger.debug('WAPT base directory : %s' % mywapt.wapt_base_dir)
    logger.debug('Package cache dir : %s' %  mywapt.packagecachedir)

    logger.info('WAPT DB Structure version;: %s' % mywapt.waptdb.db_version)

    try:
        print "Action : %s" % action
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
                result = mywapt.install(args[1:],force = options.force,params_dict = params_dict)
                if result['install']:
                    print "Installed packages:\n%s" % ('\n'.join( ["  %s" %s for s in  result['install']]),)
                if result['skipped']:
                    print "Skipped packages (already at the latest version) :\n%s" %('\n'.join( ["  %s (%s)" %s for s in  result['skipped']]),)
                if result['additional']:
                    print "Additional installed packages :\n%s" % ('\n'.join(["  %s" %s for s in  result['additional']]),)
                if result['upgrade']:
                    print "Packages upgraded :\n%s" % (','.join(["  %s" %s for s in  result['upgrade']]),)

        elif action=='download':
            if len(args)<2:
                print "You must provide at least one package name to download"
                sys.exit(1)
            result = mywapt.download_packages([(p,None) for p in args[1:]],usecache = not options.force )
            print "Downloaded packages : \n%s" % "\n".join([ "  %s" % p for p in result['downloaded'] ])
            print "Skipped packages : \n%s" % "\n".join([ "  %s" % p for p in result['skipped'] ])

            if result['errors']:
                logger.critical('Unable to download some files : %s'% (result['errors'],))
                sys.exit(1)

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
                    print "%s" % entry.ascontrol(with_non_control_attributes=True)
        elif action=='show-params':
            if len(args)<2:
                print "You must provide at one package name to show params for"
                sys.exit(1)
            for packagename in args[1:]:
                params = mywapt.waptdb.params(packagename)
                print "%s" % params

        elif action=='list-registry':
            print "%-39s%-70s%-20s%-70s" % ('UninstallKey','Software','Version','Uninstallstring')
            print '-'*39+'-'*70 + '-'*20 + '-'*70
            for p in setuphelpers.installed_softwares(' '.join(args[1:])) :
                print u"%-39s%-70s%-20s%-70s" % (p['key'],p['name'],p['version'],p['uninstallstring'])

        elif action=='showlog':
            if len(args)<2:
                print "You must provide at least one package name"
                sys.exit(1)
            for packagename in args[1:]:
                result = mywapt.last_install_log(packagename)
                print "Package : %s\nStatus : %s\n\nInstallation log:\n%s" % (packagename,result['status'],result['log'])

        elif action=='remove':
            if len(args)<2:
                print "You must provide at least one package name to remove"
                sys.exit(1)
            for packagename in args[1:]:
                print "Removing %s ..." % (packagename,),
                mywapt.remove(packagename,force=options.force)
                print "done"

        elif action=='update':
            result = mywapt.update()
            print "Total packages : %i" % result['count']
            print "Added packages : \n%s" % "\n".join([ "  %s (%s)" % p for p in result['added'] ])
            print "Removed packages : \n%s" % "\n".join([ "  %s (%s)" % p for p in result['removed'] ])


        elif action=='upgrade':
            result = mywapt.upgrade()
            if not result:
                print "Nothing to upgrade"
            else:
                print "Upgraded packages :\n%s" % ( '\n'.join([' %s (%s)' % (p[0],p[1]) for p in result]),)

            sys.exit(0)

        elif action=='list-upgrade':
            q = mywapt.list_upgrade()
            if not q:
                print "Nothing to upgrade"
            else:
                print pptable(q,None,1,None)

        elif action=='download-upgrade':
            result = mywapt.download_upgrades()
            print "Downloaded packages : \n%s" % "\n".join([ "  %s" % p for p in result['downloaded'] ])
            print "Skipped packages : \n%s" % "\n".join([ "  %s" % p for p in result['skipped'] ])

            if result['errors']:
                logger.critical('Unable to download some files : %s'% (result['errors'],))
                sys.exit(1)

        elif action=='update-packages':
            if len(args)<2:
                print "You must provide the directory"
                sys.exit(1)
            update_packages(args[1])

        elif action=='sources':
            if len(args)<2:
                print "You must provide the package name"
                sys.exit(1)
            mywapt.get_sources(args[1])

        elif action=='make-template':
            if len(args)<2:
                print "You must provide the installer path"
                sys.exit(1)
            source_dir = mywapt.maketemplate(*args[1:])
            print "Template created. You can build the WAPT package by launching\n  %s build-package %s" % (sys.argv[0],source_dir)
            setuphelpers.shelllaunch(source_dir)

        elif action=='build-package':
            if len(args)<2:
                print "You must provide at least one source directory for package build"
                sys.exit(1)
            for source_dir in args[1:]:
                if os.path.isdir(source_dir):
                    print('Building  %s' % source_dir)
                    package_fn = mywapt.buildpackage(source_dir,inc_package_release=options.increlease)
                    print('...done. Package filename %s ' % package_fn)
                else:
                    logger.critical('Directory %s not found' % source_dir)

        elif action=='upload-package':
            if len(args)<2:
                print "You must provide a package to upload"
                sys.exit(1)
            waptfiles = []
            for a in args[1:]:
                waptfiles += glob.glob(a)
            waptfile_arg = " ".join(['"%s"' % f for f in waptfiles])
            setuphelpers.run(cp.get('global','upload_cmd',raw=True,) % {'waptfile': waptfile_arg  })

        elif action=='search':
            mywapt.list_repo(args[1:])

        elif action=='cleanup':
            result = mywapt.cleanup()
            print "Removed files : \n%s" % "\n".join([ "  %s" % p for p in result ])


        elif action=='inventory':
            print mywapt.inventory()

        elif action=='list':
            def cb(fieldname,value):
                if fieldname=='InstallDate':
                    return value[0:16]
                else:
                    return value
            print pptable(mywapt.list_installed_packages(args[1:]),None,1,cb)

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
