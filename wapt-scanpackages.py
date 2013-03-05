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

import os
import zipfile
import glob
import tempfile

import codecs
import sys

from optparse import OptionParser
import logging

try:
  import common
except:
  sys.path.append("/opt/wapt")
  import common

usage="""\
%prog <wapt_directory>

Build a "Packages" file from all wapt file in the specified directory
"""
def main():
    if len(sys.argv) < 2:
        sys.stderr.write('Usage: wapt-scanpackage <wapt_directory>\n')
        sys.exit(1)
    wapt_path = sys.argv[1]
    print wapt_path
    if os.path.exists(wapt_path)==False:
        print "Directory does not exists : %s " % wapt_path
        sys.exit(1)
    if os.path.isdir(wapt_path)==False:
        print "%s does not exists " % wapt_path
        sys.exit(1)

    common.update_packages(wapt_path)

if __name__ == "__main__":
    main()
