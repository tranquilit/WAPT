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
__version__ = '1.5.1.0'

# old function to install waptserver on windows. need to be rewritten (switch to nginx, websocket, etc.)

import os
import sys

try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..','..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0, os.path.join(wapt_root_dir))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib'))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib', 'site-packages'))

import subprocess
import time
import sys
import os
from setuphelpers import *

pgsql_root_dir = r'%s\waptserver\pgsql' % wapt_root_dir

# we support that the server is not running (first install)

if os.path.exists(os.path.join(pgsql_root_dir,'data','postgresql.conf')):
    print('database already instanciated')
    sys.exit(0)

print ("initialising database directory")
cmd = r"%s\bin\initdb -E=UTF8 -D %s/data/" % (pgsql_root_dir,pgsql_root_dir.replace('\\','/'))
print cmd
run(cmd,shell=True)

print("start postgresql database")
cmd = r"%s\bin\pg_ctl.exe -D %s/data/ start" % (pgsql_root_dir,pgsql_root_dir.replace('\\','/'))
devnull = open(os.devnull,'wb')
print(subprocess.Popen(cmd,shell=True))

# waiting for postgres to be ready
time.sleep(5)

print("creating wapt database")
run(r"""%s\bin\psql.exe --command="create database wapt;" template1""" % pgsql_root_dir,shell=True)
run(r"""%s\bin\psql.exe --command="create extension hstore;" wapt""" % pgsql_root_dir,shell=True)
run(r"""%s\waptpython.exe %s\waptserver\waptserver_model.py init_db""" % (wapt_root_dir,wapt_root_dir))

time.sleep(2)
print ("stopping postgesql database")
cmd = r"%s\bin\pg_ctl.exe -D %s/data/ stop" %  (pgsql_root_dir,pgsql_root_dir.replace('\\','/'))
print cmd
print(subprocess.Popen(cmd,shell=True))

