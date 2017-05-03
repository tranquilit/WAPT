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

import sys,os
from common import *
from common import *
from waptpackage import *
from tempfile import mkdtemp
from shutil import rmtree
from getpass import getpass
import active_directory
import glob
import pyad

from optparse import OptionParser

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

    # get the collection of hosts from waptserver inventory
    hosts =  wapt.waptserver.get('api/v1/hosts',auth=('dcardon-ext-adm',server_password))


    from pyad import *
     # exemple transfert utilisateur dansune autre OU...
    # si droits admin necssaires :
    # pyad.set_defaults(ldap_server="dc1.mcc.ad.culture.fr", username="deploy", password="***")
    #user = aduser.ADUser.from_cn('nathalie.lanckriet')
    bons_enfants_ou = adcontainer.ADContainer.from_dn('OU=utilisateurs,OU=bons-enfants,DC=mcc,DC=ad,DC=culture,DC=fr')
    pyramides_ou = adcontainer.ADContainer.from_dn('OU=utilisateurs,OU=pyramides,DC=mcc,DC=ad,DC=culture,DC=fr')
    #user.move(bons_enfants_ou)

    #open('c:/temp/hosts.txt','w').write(json.dumps(hosts))
    sites = {
        '143.126.68.':pyramides_ou,
        '143.126.69.':pyramides_ou,
        '192.168.':pyramides_ou,
    }

    result = {}
    for h in hosts['result']:
        try:
            hostname = h['computer_fqdn']
            current_user = h['connected_users']
            ips = h['connected_ips']
            sites_host = []
            #list les sites possibles pour cette IP
            for ip in ips:
                sites_host.extend([sites[prefix] for prefix in sites.keys() if ip.startswith(prefix)])
            if not sites_host:
                sites_host.append('OTHER')

            # pour chaque site, ajoute le/les utilisateurs connectés
            for site in sites_host:
                if not site in result:
                    result[site] = []
                for user in current_user:
                    if not user in result[site]:
                        # récuprération ou actuelle de l'utilisateur
                        #ad_user = active_directory.find_user(user)
                        #result[site].append(u"%s;%s"%(user,ad_user and ad_user.path()[7:] or ''))
                        # our avec pyad :
                        try:
                            ad_user = aduser.ADUser.from_cn(user)
                            target_ou = sites[site]

                            if ad_user.parent_container_path != target_ou.dn:
                                print('Move %s to %s'%(ad_user.cn,target_ou.dn))
                                ad_user.move(target_ou)
                        except:
                            ad_user = None
                        #result[site].append(u"%s;%s"%(user,ad_user and ad_user.parent_container_path or ''))

        except Exception as e:
            print(" error %s" % e)
            raise
    for site in result:
        open('c:/temp/users_%s.csv'%site,'w').write('\n'.join(sorted(result[site])))
