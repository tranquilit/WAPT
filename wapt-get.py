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

__version__ = "0.8.8"

import sys
import os
import zipfile
import urllib2
import shutil
from iniparse import RawConfigParser
from optparse import OptionParser
import logging
import datetime
from common import WaptDB
from waptpackage import PackageEntry
from waptpackage import update_packages
from common import pptable,ppdicttable
from common import create_recursive_zip_signed
from common import tryurl
import setuphelpers
#from setuphelpers import *
import json
import glob
import codecs

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

  list [keywords]   : list installed packages containing keywords
  list-upgrade      : list upgradable packages
  download-upgrade  : download available upgradable packages
  search [keywords] : search installable packages whose description contains keywords
  cleanup           : remove all WAPT cached files from local drive

 For user session setup
  setup-session [packages,all] : setup local user environment for specific or all installed packages

 For packages development
  list-registry [keywords]  : list installed software from Windows Registry
  sources <package>         : get sources of a package (if attribute Sources was supplied in control file)
  make-template <installer-path> [<packagename> [<source directoryname>]] : initializes a package template with an installer (exe or msi)
  build-package <directory> : creates a WAPT package from supplied directory
  sign-package <directory or package>  : add a signature of the manifest using a private SSL key

 For repository management
  upload-package  <filenames> : upload package to repository (using winscp for example.)
  update-packages <directory> : rebuild a "Packages" file for http package repository

"""

parser=OptionParser(usage=usage,version="%prog " + __version__+' setuphelpers '+setuphelpers.__version__)
parser.add_option("-c","--config", dest="config", default=os.path.join(os.path.dirname(sys.argv[0]),'wapt-get.ini') , help="Config file full path (default: %default)")
parser.add_option("-l","--loglevel", dest="loglevel", default='info', type='choice',  choices=['debug','warning','info','error','critical'], metavar='LOGLEVEL',help="Loglevel (default: %default)")
parser.add_option("-d","--dry-run",    dest="dry_run",    default=False, action='store_true', help="Dry run (default: %default)")
parser.add_option("-f","--force",    dest="force",    default=False, action='store_true', help="Force (default: %default)")
parser.add_option("-p","--params", dest="params", default='{}', help="Setup params as a JSon Object (example : {'licence':'AZE-567-34','company':'TIS'}} (default: %default)")
parser.add_option("-r","--repository", dest="wapt_url", default='', help="URL of main wapt repository (override url from ini file, example http://wapt/wapt) (default: %default)")
parser.add_option("-i","--inc-release",    dest="increlease",    default=False, action='store_true', help="Increase release number when building package (default: %default)")
parser.add_option("-e","--encoding",    dest="encoding",    default=None, help="Chararacter encoding for the output (default: no change)")
parser.add_option("-x","--excludes",    dest="excludes",    default='.svn,.git*,*.pyc,*.dbg,src', help="Comma separated list of files or directories to exclude for build-package (default: %default)")
parser.add_option("-k","--private-key", dest="private_key",    default='', help="Path to the PEM RSA private key to sign packages. Package are unsigned if not provided (default: %default)")

(options,args)=parser.parse_args()

# setup Logger
logger = logging.getLogger()
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

if options.encoding:
    logger.debug('Default encoding : %s ' % sys.getdefaultencoding())
    logger.debug('Setting encoding for stdout and stderr to %s ' % options.encoding)
    sys.stdout = codecs.getwriter(options.encoding)(sys.stdout)
    sys.stderr = codecs.getwriter(options.encoding)(sys.stderr)


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

    defaults = {
        'repositories':'',
        'repo_url':'',
        'default_source_url':'',
        'private_key':'',
        'public_cert':'',
        'default_development_base':'c:\tranquilit',
        'default_package_prefix':'tis',
        'default_sources_suffix':'wapt',
        'default_sources_url':'',
        'upload_cmd':'',
        'wapt_server':'',
        }

    cp = RawConfigParser(defaults = defaults)
    cp.add_section('global')
    cp.read(config_file)

    mywapt = Wapt(config=cp)
    if options.wapt_url:
        mywapt.wapt_repourl = options.wapt_url

    if options.private_key:
        mywapt.private_key = options.private_key
    else:
        mywapt.private_key = cp.get('global','private_key')

    mywapt.dry_run = options.dry_run
    #logger.info("Main wapt Repository %s" % mywapt.wapt_repourl)
    logger.debug('WAPT base directory : %s' % mywapt.wapt_base_dir)
    logger.debug('Package cache dir : %s' %  mywapt.packagecachedir)
    logger.debug('WAPT DB Structure version;: %s' % mywapt.waptdb.db_version)

    try:
        if action=='install' or action=='download':
            if len(args)<2:
                print "You must provide at least one package name"
                sys.exit(1)
            params_dict = {}
            try:
                params_dict = json.loads(options.params.replace("'",'"'))
            except:
                raise Exception('Install Parameters should be in json format')

            if os.path.isdir(args[1]) or os.path.isfile(args[1]):
                print "installing WAPT file %s" % args[1]
                if action=='install':
                    mywapt.install_wapt(args[1],params_dict = params_dict)
            else:
                print "%sing WAPT packages %s" % (action,','.join(args[1:]))
                result = mywapt.install(args[1:],force = options.force,params_dict = params_dict,
                    download_only= (action=='download'),
                    )
                print "\nResults :"
                if action<>'download':
                    for k in ('install','additional','upgrade','skipped','errors'):
                        if result.get(k,[]):
                            print "\n=== %s packages ===\n%s" % (k,'\n'.join( ["  %-30s | %s (%s)" % (s[0],s[1].package,s[1].version) for s in  result[k]]),)
                else:
                    for k in ('downloaded','skipped','errors'):
                        if result.get('downloads', {'downloaded':[],'skipped':[],'errors':[]} )[k]:
                            print "\n=== %s packages ===\n%s" % (k,'\n'.join(["  %s" % (s,) for s in result['downloads'][k]]),)

        elif action=='download':
            if len(args)<2:
                print "You must provide at least one package name to download"
                sys.exit(1)
            print "Downloading packages %s" % (','.join(args[1:]),)
            result = mywapt.download_packages(args[1:],usecache = not options.force )
            if result['downloaded']:
                print "\nDownloaded packages : \n%s" % "\n".join([ "  %s" % p for p in result['downloaded'] ])
            if result['skipped']:
                print "Skipped packages : \n%s" % "\n".join([ "  %s" % p for p in result['skipped'] ])
            if result['errors']:
                logger.critical('Unable to download some files : %s'% (result['errors'],))
                sys.exit(1)

        elif action=='show':
            if len(args)<2:
                print "You must provide at least one package name to show"
                sys.exit(1)
            if os.path.isdir(args[1]) or os.path.isfile(args[1]):
                entry = PackageEntry().load_control_from_wapt(args[1])
                print "%s" % entry
            else:
                print "Display package control data for %s\n" % (','.join(args[1:]),)
                for packagename in args[1:]:
                    entries = mywapt.waptdb.packages_matching(packagename)
                    if entries:
                        for e in entries:
                            print "%s\n" % e.ascontrol(with_non_control_attributes=True)
                    else:
                        print "None packages found matching package name and version"
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
                print u"%-39s%-70s%-20s%-70s" % (p['key'],p['name'],p['version'],p['uninstall_string'])

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

        elif action=='upgradedb':
            (old,new) = mywapt.waptdb.upgradedb()
            if old == new:
                print "No database upgrade required, current %s, required %s" % (old,mywapt.waptdb.curr_db_version)
            else:
                print "Old version : %s to new : %s" % (old,new)

        elif action=='upgrade':
            result = mywapt.upgrade()
            if not result['install'] and not result['additional'] and not result['upgrade'] and not result['skipped']:
                print "Nothing to upgrade"
            else:
                for k in ('install','additional','upgrade','skipped','errors'):
                    if result[k]:
                        print "\n=== %s packages ===\n%s" % (k,'\n'.join( ["  %-30s | %s (%s)" % (s[0],s[1].package,s[1].version) for s in  result[k]]),)

            sys.exit(0)

        elif action=='list-upgrade':
            q = mywapt.list_upgrade()
            if not q:
                print "Nothing to upgrade"
            else:
                print ppdicttable([ p[0] for p in  q],[ ('package',20),('version',10)])

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
            print update_packages(args[1])

        elif action=='sources':
            if len(args)<2:
                print "You must provide the package name"
                sys.exit(1)
            os.startfile(mywapt.get_sources(args[1]))

        elif action=='make-template':
            if len(args)<2:
                print "You must provide the installer path"
                sys.exit(1)
            source_dir = mywapt.maketemplate(*args[1:])
            print "Template created. You can build the WAPT package by launching\n  %s build-package %s" % (sys.argv[0],source_dir)
            os.startfile(source_dir)

        elif action=='build-package':
            if len(args)<2:
                print "You must provide at least one source directory for package build"
                sys.exit(1)
            for source_dir in [os.path.abspath(p) for p in args[1:]]:
                if os.path.isdir(source_dir):
                    print('Building  %s' % source_dir)
                    result = mywapt.buildpackage(source_dir,
                        inc_package_release=options.increlease,
                        excludes=options.excludes.split(','))
                    package_fn = result['filename']
                    if package_fn:
                        print "Package content:"
                        for f in result['files']:
                            print " %s" % f[0]
                        print('...done. Package filename %s' % (package_fn,))
                        if mywapt.private_key:
                            print '\nYou can sign the package with\n  %s sign-package %s' % (sys.argv[0],package_fn)
                        if mywapt.upload_cmd:
                            print '\nYou can upload to repository with\n  %s upload-package %s ' % (sys.argv[0],package_fn )
                        return 0
                    else:
                        logger.critical('package not created')
                        return 1
                else:
                    logger.critical('Directory %s not found' % source_dir)

        elif action=='sign-package':
            if len(args)<2:
                print "You must provide at least one source directory or package to sign"
                sys.exit(1)
            for waptfile in [os.path.abspath(p) for p in args[1:]]:
                if os.path.isdir(waptfile) or os.path.isfile(waptfile):
                    print('Signing %s' % waptfile)
                    signature = mywapt.signpackage(waptfile,
                        excludes=options.excludes.split(','))
                    print "Package %s signed : signature :\n%s" % (waptfile,signature)
                else:
                    logger.critical('Package %s not found' % waptfile)
                    return 1

        elif action=='upload-package':
            if len(args)<2:
                print "You must provide a package to upload"
                sys.exit(1)
            waptfiles = []
            for a in args[1:]:
                waptfiles += glob.glob(a)
            waptfile_arg = " ".join(['"%s"' % f for f in waptfiles])
            setuphelpers.run(mywapt.upload_cmd % {'waptfile': waptfile_arg  })

        elif action=='search':
            result = mywapt.waptdb.packages_search(args[1:])
            print ppdicttable(result,(('package',30),('version',10),('description',80)))

        elif action=='cleanup':
            result = mywapt.cleanup()
            print "Removed files : \n%s" % "\n".join([ "  %s" % p for p in result ])


        elif action=='inventory':
            print mywapt.inventory()

        elif action=='list':
            def cb(fieldname,value):
                if value and fieldname=='install_date':
                    return value[0:16]
                else:
                    return value
            print ppdicttable(mywapt.waptdb.installed_search(args[1:]).values(),(('package',20),('version',15),('install_status',10),('install_date',16),('description',80)),callback=cb)
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
