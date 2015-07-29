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
# ---------------------------------------------------------------------
#
# Sample script which updates dependencies of all hosts registered on waptserver
# - append a list of basic packages that all hosts should install
# - query active directory for the groups of each host.
#     if the CN of the group match a wapt package, the package is appended as dependency
#
#  This allows to install packages based on computers active directory memberships
#------------------------------------------------
"""
    Sample script which updates dependencies of all hosts registered on waptserver
     - append a list of basic packages that all hosts should install
     - query active directory for the groups of each host.
         if the CN of the group match a wapt package, the package is appended as dependency

    This allows to install packages based on computers active directory memberships
"""

import sys,os
from common import *
from waptpackage import *
from tempfile import mkdtemp
from shutil import rmtree
from getpass import getpass
import active_directory

from optparse import OptionParser

def ensure_list(csv_or_list,ignore_empty_args=True):
    """if argument is not a list, return a list from a csv string"""
    if csv_or_list is None:
        return []
    if isinstance(csv_or_list,tuple):
        return list(csv_or_list)
    elif not isinstance(csv_or_list,list):
        if ignore_empty_args:
            return [s.strip() for s in csv_or_list.split(',') if s.strip() != '']
        else:
            return [s.strip() for s in csv_or_list.split(',')]
    else:
        return csv_or_list

def get_computer_groups(computername):
    """Try to finc the computer in the Active Directory
        and return the list of groups
    """
    groups = []
    computer = active_directory.find_computer(computername)
    if computer:
        computer_groups = computer.memberOf
        if computer_groups:
            computer_groups = ensure_list(computer_groups)
            for group in computer_groups:
                # extract first component of group's DN
                cn = group.split(',')[0].split('=')[1]
                groups.append(cn)
    return groups

if __name__ == '__main__':
    parser=OptionParser(usage=__doc__)
    parser.add_option("-g","--groups", dest="groups", default='', help="List of packages to append to all hosts (default: %default)")
    parser.add_option("-c","--config", dest="config", default=os.path.join(os.path.dirname(sys.argv[0]),'wapt-get.ini') , help="Config file full path (default: %default)")
    parser.add_option("-d","--dry-run", dest="dry_run",    default=False, action='store_true', help="Dry run (default: %default)")
    (options,args) = parser.parse_args()

    # put at least these packages to all computers
    base_packages = ensure_list(options.groups)
    server_password = getpass('Please input wapt server admin password:')


    # initialise wapt api with local config file
    wapt = Wapt(config_filename = options.config)
    wapt.dbpath=':memory:'

    # get current packages status from repositories
    wapt.update()

    for package in base_packages:
        if not wapt.is_available(package):
            raise Exception('Package %s is not available in your repository.'%package)

    # get the collection of hosts from waptserver inventory
    hosts =  wapt.waptserver.get('api/v1/hosts',auth=('admin',server_password))

    for h in hosts['result']:
        try:
            hostname = h['host']['computer_fqdn']
            print 'Computer %s... ' % hostname,

            groups = base_packages + get_computer_groups(h['host']['computer_name'])

            # try to get comp

            # now update the host package : download and append missing packages
            tmpdir = mkdtemp()
            try:
                package = wapt.edit_host(hostname,target_directory = tmpdir, use_local_sources=False)
                control = package['package']
                depends =  ensure_list(control.depends)
                additional = [ group for group in groups if not group in depends and wapt.is_available(group) ]

                #there ara additional packages to add as dependencies to host package
                if additional:
                    control.depends = ','.join(depends+additional)
                    control.save_control_to_wapt(package['source_dir'])
                    # build and post the new wapt package
                    if options.dry_run:
                        result = wapt.build_package(package['source_dir'])
                    else:
                        result = wapt.build_upload(package['source_dir'], wapt_server_user='admin', wapt_server_passwd=server_password,inc_package_release=True)[0]
                    print "  done, new packages: %s" % (','.join(additional))
                    if os.path.isfile(result['filename']):
                        os.remove(result['filename'])
                else:
                    print " skipped, current packages: %s" % (','.join(depends))
            finally:
                # cleanup of temporary
                if os.path.isdir(tmpdir):
                    rmtree(tmpdir)
        except Exception as e:
            print " error %s" % e
            raise
