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

import sys
import os

import logging
import datetime
from common import WaptDB
from iniparse import RawConfigParser
from common import WaptDB

from waptpackage import Package_Entry
import setuphelpers
import json
import glob
import codecs

from common import Wapt

logger = logging.getLogger()
config_file ='c:\\wapt\\wapt-get.ini'
loglevel = 'debug'

defaults = {
    'repositories':'',
    'repo_url':'',
    'default_source_url':'',
    'gpgkey':'',
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

mywapt = Wapt(config=cp)
mywapt.wapt_repourl = mywapt.find_wapt_server()
print mywapt.wapt_repourl

