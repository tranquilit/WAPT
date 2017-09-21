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
__version__ = "1.5.0.17"

import os
import sys

try:
    wapt_root_dir = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0,os.path.join(wapt_root_dir))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib'))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib','site-packages'))

from waptpackage import update_packages

from optparse import OptionParser
import logging

logger = logging.getLogger()

__doc__ = """\
%prog <wapt_directory>

Build a "Packages" file from all wapt file in the specified directory
"""

def setloglevel(loglevel):
    """set loglevel as string"""
    if loglevel in ('debug','warning','info','error','critical'):
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % loglevel)
        logger.setLevel(numeric_level)



def main():
    parser=OptionParser(usage=__doc__)
    parser.add_option("-f","--force",    dest="force",    default=False, action='store_true', help="Force (default: %default)")
    parser.add_option("-l","--loglevel", dest="loglevel", default=None, type='choice',  choices=['debug','warning','info','error','critical'], metavar='LOGLEVEL',help="Loglevel (default: warning)")
    (options,args) = parser.parse_args()

    loglevel = options.loglevel

    if len(logger.handlers) < 1:
        hdlr = logging.StreamHandler(sys.stderr)
        hdlr.setFormatter(logging.Formatter(
            u'%(asctime)s %(levelname)s %(message)s'))
        logger.addHandler(hdlr)

    if loglevel:
        setloglevel(loglevel)
    else:
        setloglevel('warning')

    if len(args) != 1:
        parser.usage
        sys.exit(1)

    wapt_path = args[0]
    if os.path.exists(wapt_path)==False:
        logger.error("Directory does not exist: %s", wapt_path)
        sys.exit(1)
    if os.path.isdir(wapt_path)==False:
        logger.error("%s is not a directory", wapt_path)
        sys.exit(1)

    res = update_packages(wapt_path,force = options.force)

    if res and os.name == 'posix':
        logger.info('Set Packages file ownership to wapt')
        import pwd
        pwd_entry = pwd.getpwnam('wapt')
        uid, gid = pwd_entry.pw_uid, pwd_entry.pw_gid
        os.chown(res['packages_filename'], uid, gid)

if __name__ == "__main__":
    main()
