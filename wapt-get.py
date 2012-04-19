#!/usr/bin/python
# -*- coding: UTF-8 -*-
import sys
import os
import zipfile
import cStringIO
import tempfile
import urllib2
import shutil
from iniparse import ConfigParser
from optparse import OptionParser
import logging
import datetime
from common import WaptDB
from common import Package_Entry
import pprint

usage="""\
%prog -c configfile action

WAPT install system.

action is either :
 install : launch all backups or a specific one if -s option is used
 update : removed backups older than retension period
 upgrade : dump the content of database for the last 20 backups
"""

version = "0.2"

parser=OptionParser(usage=usage,version="%prog " + version)
parser.add_option("-c","--config", dest="config", default='c:\\wapt\\wapt-get.ini', help="Config file full path (default: %default)")
parser.add_option("-l","--loglevel", dest="loglevel", default='info', type='choice',  choices=['debug','warning','info','error','critical'], metavar='LOGLEVEL',help="Loglevel (default: %default)")
parser.add_option("-d","--dry-run",    dest="dry_run",    default=False, action='store_true', help="Dry run (default: %default)")

(options,args)=parser.parse_args()


if len(args) == 0:
  print "ERROR : You must provide one action to perform"
  parser.print_usage()
  sys.exit(2)

def download(url,destdir):
  """Copy the contents of a file from a given URL
  to a local file.
  """
  import urllib
  if not os.path.isdir(destdir):
    os.makedirs(destdir)
  urllib.urlretrieve(url,os.path.join(destdir,url.split('/')[-1]))

def ensure_dir(f):
  d = os.path.dirname(f)
  if not os.path.exists(d):
    os.makedirs(d)

def psource(module):

  file = os.path.basename( module )
  dir = os.path.dirname( module )

  toks = file.split( '.' )
  modname = toks[0]

  # Check if dirrectory is really a directory
  if( os.path.exists( dir ) ):

  # Check if the file directory already exists in the sys.path array
    paths = sys.path
    pathfound = 0
    for path in paths:
      if(dir == path):
        pathfound = 1

  # If the dirrectory is not part of sys.path add it
    if not pathfound:
      sys.path.append( dir )

  exec ('import ' + modname) in globals()

  # reload the file to make sure its up to date
  exec( 'reload( ' + modname + ' )' ) in globals()

  # This returns the namespace of the file imported
  return modname




class wapt:
  wapt_repourl=""
  packagecachedir = ""
  wapttempdir=""
  dry_run = False
  dbpath = 'c:\\wapt\\db\\waptdb.sqlite'


  def install(self,package):
    print ("starting installation")
    sys.stdout.flush()
    print ("installing package " + package)

    waptdb = WaptDB(dbpath=self.dbpath)
    mydict= waptdb.query("select * from wapt_repo where Package=?",(package,))[0]
    pprint.pprint (mydict)
    packagename = mydict['Filename'].strip('./')
    download_url = mydict['repo_url'] + '/' + packagename
    print download_url

    print ("download package from " + mydict['repo_url'])
    sys.stdout.flush()


    download( download_url, self.packagecachedir)

    # When you import a file you must give it the full path
    tempdirname = tempfile.mkdtemp(dir=self.wapttempdir)
    print ('unziping %s ' % (os.path.join(self.packagecachedir,packagename)))
    sys.stdout.flush()
    zip = zipfile.ZipFile( os.path.join(self.packagecachedir , packagename))
    zip.extractall(path=tempdirname)

    print ("sourcing install file")
    sys.stdout.flush()
    psource(os.path.join( tempdirname,'setup.py'))

    if not self.dry_run:
      print ("executing install script")
      sys.stdout.flush()
      setup.install()

    print ("install script finished")
    print ("cleaning tmp dir")
    sys.stdout.flush()
    shutil.rmtree(tempdirname)

  def update(self):
    print self.wapttempdir
    packageListFile = zipfile.ZipFile(cStringIO.StringIO(urllib2.urlopen(self.wapt_repourl + 'Packages').read())).read(name='Packages')

    waptdb = WaptDB(dbpath=self.dbpath)
    packageListFile = open(os.path.join(self.wapttempdir,'Packages'))

    package = Package_Entry()
    for line in packageListFile:
      if line.strip()=='':
        print package
        package.repo_url = self.wapt_repourl
        waptdb.add_package_entry(package)
        package = Package_Entry()
        continue
      splitline= line.split(':')
      setattr(package,splitline[0].strip(),splitline[1].strip())

  def list_repo(self):
    waptdb = WaptDB(dbpath=self.dbpath)
    print waptdb.list_repo()

def main(argv):
  wapt_start_date = datetime.datetime.now().strftime('%Y%m%d-%Hh%Mm%S')
  action = args[0]
  if action=='install':
    packagename=args[1]

  config_file =options.config
  loglevel = options.loglevel

  # setup Logger
  logger = logging.getLogger('wapt-get')
  hdlr = logging.StreamHandler()
  hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
  logger.addHandler(hdlr)

  # set loglevel
  if loglevel in ('debug','warning','info','error','critical'):
    numeric_level = getattr(logging, loglevel.upper(), None)
  if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % loglevel)
  logger.setLevel(numeric_level)

  # Config file
  if not os.path.isfile(config_file):
    logger.error("Error : could not find file : " + config_file + ", please check the path")
  logger.info("Using " + config_file + " config file")

  print config_file
  cp = ConfigParser( )
  cp.read(config_file)

  wapt_repourl = cp.get('global','repo_url')
  wapt_base_dir = cp.get('global','base_dir')

  log_dir = os.path.join(wapt_base_dir,'log')
  if not os.path.exists(log_dir):
    os.makedirs(log_dir)

  packagecachedir = os.path.join(wapt_base_dir,'cache')
  if not os.path.exists(packagecachedir):
    os.makedirs(packagecachedir)
  print packagecachedir
  wapttempdir = os.path.join(wapt_base_dir, 'tmp')
  if not os.path.exists(wapttempdir):
    os.makedirs(wapttempdir)

  mywapt = wapt()
  mywapt.packagecachedir = packagecachedir
  mywapt.wapttempdir = wapttempdir
  mywapt.wapt_repourl = wapt_repourl
  mywapt.dry_run = options.dry_run

  if action=='install':
    mywapt.install(packagename)

  if action=='update':
    mywapt.update()

  if action=='upgrade':
    mywapt.upgrade()

  if action=='remove':
    mywapt.remove()

  if action=='list':
    mywapt.list_repo()

  #shutil.rmtree(tempdirname)

if __name__ == "__main__":
  main(sys.argv[1:])

