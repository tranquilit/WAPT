#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
#    This file is part of WAPT-GET
#
#    TISBackup is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    TISBackup is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with TISBackup.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------

import os
import subprocess
import re
import logging
import datetime
import time
import sqlite3
import shutil
import sys
import pprint



def datetime2isodate(adatetime = datetime.datetime.now()):
  assert(isinstance(adatetime,datetime.datetime))
  return adatetime.isoformat()

def isodate2datetime(isodatestr):
  # we remove the microseconds part as it is not working for python2.5 strptime
  return datetime.datetime.strptime(isodatestr.split('.')[0] , "%Y-%m-%dT%H:%M:%S")

def time2display(adatetime):
  return adatetime.strftime("%Y-%m-%d %H:%M")

def hours_minutes(hours):
  if hours is None:
    return None
  else:
    return "%02i:%02i" % ( int(hours) , int((hours - int(hours)) * 60.0))

def fileisodate(filename):
  return datetime.datetime.fromtimestamp(os.stat(filename).st_mtime).isoformat()

def dateof(adatetime):
  return adatetime.replace(hour=0,minute=0,second=0,microsecond=0)

#####################################
# http://code.activestate.com/recipes/498181-add-thousands-separator-commas-to-formatted-number/
# Code from Michael Robellard's comment made 28 Feb 2010
# Modified for leading +, -, space on 1 Mar 2010 by Glenn Linderman
#
# Tail recursion removed and  leading garbage handled on March 12 2010, Alessandro Forghieri
def splitThousands( s, tSep=',', dSep='.'):
  '''Splits a general float on thousands. GIGO on general input'''
  if s == None:
    return 0
  if not isinstance( s, str ):
    s = str( s )

  cnt=0
  numChars=dSep+'0123456789'
  ls=len(s)
  while cnt < ls and s[cnt] not in numChars: cnt += 1

  lhs = s[ 0:cnt ]
  s = s[ cnt: ]
  if dSep == '':
    cnt = -1
  else:
    cnt = s.rfind( dSep )
  if cnt > 0:
    rhs = dSep + s[ cnt+1: ]
    s = s[ :cnt ]
  else:
    rhs = ''

  splt=''
  while s != '':
    splt= s[ -3: ] + tSep + splt
    s = s[ :-3 ]

  return lhs + splt[ :-1 ] + rhs


def call_external_process(shell_string):
  p = subprocess.call(shell_string, shell=True)
  if (p != 0 ):
    raise Exception('shell program exited with error code ' + str(p), shell_string)

def check_string(test_string):
  pattern = r'[^\.A-Za-z0-9\-_]'
  if re.search(pattern, test_string):
    #Character other then . a-z 0-9 was found
    print 'Invalid : %r' % (test_string,)

def convert_bytes(bytes):
  if bytes is None:
    return None
  else:
    bytes = float(bytes)
    if bytes >= 1099511627776:
      terabytes = bytes / 1099511627776
      size = '%.2fT' % terabytes
    elif bytes >= 1073741824:
      gigabytes = bytes / 1073741824
      size = '%.2fG' % gigabytes
    elif bytes >= 1048576:
      megabytes = bytes / 1048576
      size = '%.2fM' % megabytes
    elif bytes >= 1024:
      kilobytes = bytes / 1024
      size = '%.2fK' % kilobytes
    else:
      size = '%.2fb' % bytes
    return size

## {{{ http://code.activestate.com/recipes/81189/ (r2)
def pp(cursor, data=None, rowlens=0, callback=None):
  """
  pretty print a query result as a table
  callback is a function called for each field (fieldname,value) to format the output
  """
  def defaultcb(fieldname,value):
    return value

  if not callback:
    callback = defaultcb

  d = cursor.description
  if not d:
    return "#### NO RESULTS ###"
  names = []
  lengths = []
  rules = []
  if not data:
    data = cursor.fetchall()
  for dd in d:    # iterate over description
    l = dd[1]
    if not l:
      l = 12             # or default arg ...
    l = max(l, len(dd[0])) # handle long names
    names.append(dd[0])
    lengths.append(l)
  for col in range(len(lengths)):
    if rowlens:
      rls = [len(str(callback(d[col][0],row[col]))) for row in data if row[col]]
      lengths[col] = max([lengths[col]]+rls)
    rules.append("-"*lengths[col])
  format = " ".join(["%%-%ss" % l for l in lengths])
  result = [format % tuple(names)]
  result.append(format % tuple(rules))
  for row in data:
    row_cb=[]
    for col in range(len(d)):
      row_cb.append(callback(d[col][0],row[col]))
    result.append(format % tuple(row_cb))
  return "\n".join(result)
## end of http://code.activestate.com/recipes/81189/ }}}


def html_table(cur,callback=None):
  """
      cur est un cursor issu d'une requete
      callback est une fonction qui prend (rowmap,fieldname,value)
      et renvoie une representation texte
  """
  def safe_unicode(iso):
    if iso is None:
      return None
    elif isinstance(iso, str):
      return iso.decode('iso8859')
    else:
      return iso

  def itermap(cur):
    for row in cur:
      yield dict((cur.description[idx][0], value)
                 for idx, value in enumerate(row))

  head=u"<tr>"+"".join(["<th>"+c[0]+"</th>" for c in cur.description])+"</tr>"
  lines=""
  if callback:
    for r in itermap(cur):
      lines=lines+"<tr>"+"".join(["<td>"+str(callback(r,c[0],safe_unicode(r[c[0]])))+"</td>" for c in cur.description])+"</tr>"
  else:
    for r in cur:
      lines=lines+"<tr>"+"".join(["<td>"+safe_unicode(c)+"</td>" for c in r])+"</tr>"

  return "<table border=1  cellpadding=2 cellspacing=0>%s%s</table>" % (head,lines)


class WaptDB:
  dbpath = ''
  db = None
  logger = logging.getLogger('wapt-get')

  def __init__(self,dbpath):
    self.dbpath = dbpath

    if not os.path.isfile(self.dbpath):
      dirname =os.path.dirname(self.dbpath)
      print dirname
      if os.path.isdir (dirname)==False:
        os.makedirs(dirname)
      os.path.dirname(self.dbpath)
      self.db=sqlite3.connect(self.dbpath)
      self.initdb()
    else:
      self.db=sqlite3.connect(self.dbpath)

  def initdb(self):
    assert(isinstance(self.db,sqlite3.Connection))
    self.logger.debug('Initialize stat database')
    self.db.execute("""
    create table wapt_repo (
      Package TEXT,
      Version TEXT,
      Section TEXT,
      Priority TEXT,
      Architecture TEXT,
      Maintainer TEXT,
      Description TEXT,
      Filename TEXT,
      Size TEXT,
      MD5sum TEXT,
      repo_url TEXT
      )"""
                    )
    self.db.execute("""
    create index idx_package_name on wapt_repo(Package);""")
    self.db.commit()

  def start(self,backup_name,server_name,description='',backup_location=None):
    """ Add in stat DB a record for the newly running backup"""
    return self.add(backup_name=backup_name,server_name=server_name,description=description,backup_start=datetime2isodate(),status='Running')

  def finish(self,rowid,total_files_count=None,written_files_count=None,total_bytes=None,written_bytes=None,log=None,status='OK',backup_end=datetime2isodate(),backup_duration=None,backup_location=None):
    """ Update record in stat DB for the finished backup"""
    if backup_duration == None:
      try:
        # get duration using start of backup datetime
        backup_duration = (isodate2datetime(backup_end) - isodate2datetime(self.query('select backup_start from stats where rowid=?',(rowid,))[0]['backup_start'])).seconds / 3600.0
      except:
        backup_duration = None

    # update stat record
    self.db.execute("""\
          update stats set
            total_files_count=?,written_files_count=?,total_bytes=?,written_bytes=?,log=?,status=?,backup_end=?,backup_duration=?,backup_location=?
          where
            rowid = ?
        """,(total_files_count,written_files_count,total_bytes,written_bytes,log,status,backup_end,backup_duration,backup_location,rowid))
    self.db.commit()

  def add_package(self,
                  Package='',
                  Version='',
                  Section='',
                  Priority='',
                  Architecture='',
                  Maintainer='',
                  Description='',
                  Filename='',
                  Size='',
                  MD5sum='',
                  repo_url=''):

    print "Size : " + str(Size)
    print "MD5sum : " + MD5sum
    cur = self.db.execute("""\
          insert into wapt_repo (
              Package,
            Version,
            Section,
            Priority,
            Architecture,
            Maintainer,
            Description,
            Filename,
            Size,
            MD5sum,
            repo_url) values (?,?,?,?,?,?,?,?,?,?,?)
        """,(
             Package,
             Version,
             Section,
             Priority,
             Architecture,
             Maintainer,
             Description,
             Filename,
             Size,
             MD5sum,
             repo_url)
           )

    self.db.commit()
    return cur.lastrowid

  def list_repo(self):
    def fcb(fieldname,value):
      if fieldname in ('backup_start','backup_end'):
        return time2display(isodate2datetime(value))
      elif 'bytes' in fieldname:
        return convert_bytes(value)
      elif 'count' in fieldname:
        return splitThousands(value,' ','.')
      elif 'backup_duration' in fieldname:
        return hours_minutes(value)
      else:
        return value
    cur = self.db.execute("select * from wapt_repo")
    return pp(cur,None,1,None)

  def add_package_entry(self,package_entry):
    package_name = package_entry.Package
    print "package_name : " + package_name
    cur = self.db.execute("""delete from wapt_repo where Package=?""" ,(package_name,))

    self.add_package(package_entry.Package,
                     package_entry.Version,
                     package_entry.Section,
                     package_entry.Priority,
                     package_entry.Architecture,
                     package_entry.Maintainer,
                     package_entry.Description,
                     package_entry.Filename,
                     package_entry.Size,
                     package_entry.MD5sum,
                     package_entry.repo_url)


  def query(self,query, args=(), one=False):
    """
    execute la requete query sur la db et renvoie un tableau de dictionnaires
    """
    cur = self.db.execute(query, args)
    rv = [dict((cur.description[idx][0], value)
               for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv

  def last_backups(self,backup_name,count=30):
    if backup_name:
      cur = self.db.execute('select  * from stats where backup_name=? order by backup_end desc limit ?',(backup_name,count))
    else:
      cur = self.db.execute('select  * from stats order by backup_end desc limit ?',(count,))

    def fcb(fieldname,value):
      if fieldname in ('backup_start','backup_end'):
        return time2display(isodate2datetime(value))
      elif 'bytes' in fieldname:
        return convert_bytes(value)
      elif 'count' in fieldname:
        return splitThousands(value,' ','.')
      elif 'backup_duration' in fieldname:
        return hours_minutes(value)
      else:
        return value

    #for r in self.query('select  * from stats where backup_name=? order by backup_end desc limit ?',(backup_name,count)):
    print pp(cur,None,1,fcb)


  def fcb(self,fields,fieldname,value):
    if fieldname in ('backup_start','backup_end'):
      return time2display(isodate2datetime(value))
    elif 'bytes' in fieldname:
      return convert_bytes(value)
    elif 'count' in fieldname:
      return splitThousands(value,' ','.')
    elif 'backup_duration' in fieldname:
      return hours_minutes(value)
    else:
      return value

  def as_html(self,cur):
    if cur:
      return html_table(cur,self.fcb)
    else:
      return html_table(self.db.execute('select * from stats order by backup_start asc'),self.fcb)

class Package_Entry:
  Package=''
  Version=''
  Section=''
  Priority=''
  Architecture=''
  Maintainer=''
  Description=''
  Filename=''
  Size=''
  MD5sum=''
  repo_url=''

  def register_package(self,fname ):
    myzip = zipfile.ZipFile(fname,'r')
    tempdir = tempfile.mkdtemp(prefix='/tmp/wapt-')
    myzip.extract(path=tempdir,member='control')
    file = open(tempdir + "/control")
    self.Filename = fname
    self.MD5sum = md5_for_file(fname)
    self.Size = os.path.getsize(fname)
    keyvalue = {}
    while 1:
      line = file.readline()
      if not line:
        break
      if line.strip()=='':
        break
      splitline = line.split(':')
      #keyvalue[splitline[0]] = splitline[1]
      #print splitline[0] + " " + splitline[1]
      setattr(self,splitline[0].strip(),splitline[1].strip())

    shutil.rmtree(tempdir)

  def __str__(self):
    val = """\
Package : %(Package)s
Version : %(Version)s
Section : %(Section)s
Priority : %(Priority)s
Architecture : %(Architecture)s
Maintainer :   %(Maintainer)s
Description :  %(Description)s
Filename :      %(Filename)s
Size :   %(Size)s
MD5sum : %(MD5sum)s
"""  % self.__dict__
    return val

if __name__ == '__main__':
  logger = logging.getLogger('wapt-db')
  logger.setLevel(logging.DEBUG)
  formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
  handler = logging.StreamHandler()
  handler.setFormatter(formatter)
  logger.addHandler(handler)
  waptdb = WaptDB(dbpath='c:/wapt/db/waptdb.sqlite')
  #pprint.pprint(waptdb.query("select * from wapt_repo"))

  waptdb.add_package(
    Package='Packagetest',
    Version='Versiontest',
    Section='Sessiontest',
    Priority='Prioritytest',
    Architecture='Architecturetest',
    Maintainer='Maintainertest',
    Description='Descriptiontest',
    Filename='FilenameTest',
    Size=100,
    MD5sum='MD5Sumtest')
  print
