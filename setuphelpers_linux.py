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
from __future__ import absolute_import
import os
import socket
import struct
import getpass
import platform
import configparser
import platform
import psutil
import netifaces
import json
import cpuinfo
import sys
import subprocess
import logging
import glob
import datetime
import platform
import re

from setuphelpers_unix import *

try:
    import apt
except:
    apt=None

try:
    import rpm
except:
    rpm=None

logger = logging.getLogger('waptcore')

def isLinux64():
    return platform.machine().endswith('64')

def get_distrib_version():
    return platform.linux_distribution()[1]

def get_distrib_linux():
    return platform.linux_distribution()[0]

def type_debian():
    return platform.dist()[0].lower() in ('debian','linuxmint','ubuntu')

def type_redhat():
    return platform.dist()[0].lower() in ('redhat','centos','fedora')

def host_info():
    info = host_info_common_unix()
    info['platform'] = platform.system()
    info['os_name'] = platform.linux_distribution()[0]
    info['os_version'] = platform.linux_distribution()[1]
    info['linux64'] = isLinux64()
    info['distrib'] = get_distrib_linux()
    info['distrib_version'] = get_distrib_version()
    
    info['local_groups'] = {g.gr_name:g.gr_mem for g in grp.getgrall()}
    info['local_users'] = []
    for u in pwd.getpwall():
        info['local_users'].append(u.pw_name)

        gr_struct=grp.getgrgid(u.pw_gid)
        if info['local_groups'].has_key(gr_struct.gr_name):
            if u.pw_name not in info['local_groups'][gr_struct.gr_name]:
                info['local_groups'][gr_struct.gr_name].append(u.pw_name)
        else:
            info['local_groups'][gr_struct.gr_name]=[u.pw_name]

    return info


def dmi_info():
    return dmi_info_common_unix()


def installed_softwares(keywords='',name=None):
    """ Return list of installed software from apt or rpm

        Args:
            keywords (str or list): string to lookup in key, display_name or publisher fields

        Returns:
            list of dicts: [{'key', 'name', 'version', 'install_date', 'install_location'
                         'uninstall_string', 'publisher','system_component'}]
    """
    name_re = re.compile(name) if name is not None else None
    list_installed_softwares=[]

    if isinstance(keywords,str) or isinstance(keywords,unicode):
        keywords = keywords.lower().split()
    else:
        keywords = [ k.lower() for k in keywords ]

    def check_words(target,words):
        mywords = target.lower()
        result = not words or mywords
        for w in words:
            result = result and w in mywords
        return result

    if apt:
        for pkg in apt.Cache():
            path_dpkg_info ="/var/lib/dpkg/info/"
            if pkg.is_installed and ((name_re is None or name_re.match(pkg.name) or name_re.match(pkg.fullname)) or check_words(' '.join[pkg.name,pkg.fullname,pkg.versions[0].homepage],keywords)):
                try:
                    if os.path.isfile(os.path.join(path_dpkg_info,(pkg.name+'.list'))):
                        install_date=os.path.getctime(os.path.join(path_dpkg_info,(pkg.name+'.list')))
                    else:
                        install_date=os.path.getctime(os.path.join(path_dpkg_info,(pkg.fullname+'.list')))
                    install_date=datetime.datetime.fromtimestamp(install_date).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    install_date=''
                list_installed_softwares.append({'key':'','name':pkg.name,'version':str(pkg.installed).rsplit('=',1)[-1],'install_date':install_date,'install_location':'','uninstall_string':'','publisher':pkg.versions[0].homepage,'system_component':''})
    elif rpm:
        trans = rpm.TransactionSet()
        for header in trans.dbMatch():
            if (name_re is None or name_re.match(header['name'])) or check_words(' '.join[header['name'],header['url']],keywords):
                list_installed_softwares.append({'key':'','name':header['name'],'version':header['version'],'install_date':datetime.datetime.strptime(header.sprintf("%{INSTALLTID:date}"),'%a %b %d %H:%M:%S %Y').strftime('%Y-%m-%d %H:%M:%S'),'install_location':'','uninstall_string':'','publisher':header['url'],'system_component':''})
    else:
        list_installed_softwares.append({'key':'Distribution not supported yet', 'name':'Distribution not supported yet', 'version':'Distribution not supported yet', 'install_date':'Distribution not supported yet', 'install_location':'Distribution not supported yet', 'uninstall_string':'Distribution not supported yet', 'publisher':'Distribution not supported yet','system_component':'Distribution not supported yet'})
    return list_installed_softwares

def install_apt(package,allow_unauthenticated=False):
    """
    Install .deb package from apt repositories
    """
    update_apt()
    if allow_unauthenticated:
        return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-unauthenticated %s' %package)
    else:
        return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get install -y %s' %package)

def uninstall_apt(package):
    """
    Remove a .deb package
    """
    return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get remove -y %s' %package)

def install_deb(path_to_deb):
    """
    Install .deb package from file
    """
    try:
        return run('LANG=C DEBIAN_FRONTEND=noninteractive dpkg -i %s' % path_to_deb)
    except:
        return install_required_dependencies_apt()

def purge_deb(deb_name):
    return run('LANG=C DEBIAN_FRONTEND=noninteractive dpkg --purge %s' % deb_name)

def install_required_dependencies_apt():
    return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get -f -y install')

def autoremove_apt():
    return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get -y autoremove')

def install_yum(package):
    return run('LANG=C yum install -y %s' % (package))

def uninstall_yum(package):
    return run('LANG=C yum remove -y %s' % package)

def autoremove_yum():
    return run('LANG=C yum autoremove -y')

def update_apt():
    return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get -y update')

def upgrade_apt():
    return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get -y upgrade')

def update_yum():
    return run('LANG=C yum update -y')

def upgrade_yum():
    return run('LANG=C yum upgrade -y')

def install_rpm(package):
    return run('LANG=C yum localinstall -y %s' % (package))