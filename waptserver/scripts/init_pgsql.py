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
pgsql_data_dir = r'%s\waptserver\pgsql_data' % wapt_root_dir
pgsql_data_dir = pgsql_data_dir.replace('\\','/')

# we support that the server is not running (first install)

if os.path.exists(os.path.join(pgsql_data_dir,'postgresql.conf')):
    print('database already instanciated')
    sys.exit(0)

# postgresql db initialisation cannot be done with a privileged users.
# so it is started through a scheduled task with user NT AUTHORITY\NetworkService
# which will be used
print ("initialising database directory")
cmd = r"%s\bin\initdb -U postgres -E=UTF8 -D %s" % (pgsql_root_dir, pgsql_data_dir)
print cmd
run(cmd,shell=True)


