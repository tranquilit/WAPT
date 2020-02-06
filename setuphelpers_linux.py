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
    return info

def installed_softwares(keywords='',uninstallkey=None,name=None):
    if apt:
        list_installed_softwares=[]
        for pkg in apt.Cache():
            path_dpkg_info ="/var/lib/dpkg/info/"
            if pkg.is_installed:
                try:
                    if os.path.isfile(os.path.join(path_dpkg_info,(pkg.name+'.list'))):
                        install_date=os.path.getctime(os.path.join(path_dpkg_info,(pkg.name+'.list')))
                    else:
                        install_date=os.path.getctime(os.path.join(path_dpkg_info,(pkg.fullname+'.list')))
                    install_date=datetime.datetime.fromtimestamp(install_date).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    install_date=''
                pkg_dict={'key':'','name':pkg.name,'version':str(pkg.installed).split('=',1)[1],'install_date':install_date,'install_location':'','uninstall_string':'','publisher':pkg.versions[0].homepage,'system_component':''}
                list_installed_softwares.append(pkg_dict)
        return list_installed_softwares
    elif rpm:
        list_installed_softwares=[]
        trans = rpm.TransactionSet()
        for header in trans.dbMatch():
            pkg_dict={'key':'','name':header['name'],'version':header['version'],'install_date':datetime.datetime.strptime(header.sprintf("%{INSTALLTID:date}"),'%a %b %d %H:%M:%S %Y').strftime('%Y-%m-%d %H:%M:%S'),'install_location':'','uninstall_string':'','publisher':header['url'],'system_component':''}
            list_installed_softwares.append(pkg_dict)
        return list_installed_softwares
    else:
        return [{'key':'Distribution not supported yet', 'name':'Distribution not supported yet', 'version':'Distribution not supported yet', 'install_date':'Distribution not supported yet', 'install_location':'Distribution not supported yet', 'uninstall_string':'Distribution not supported yet', 'publisher':'Distribution not supported yet','system_component':'Distribution not supported yet'}]

def apt_install(package,allow_unauthenticated=False):
    if allow_unauthenticated:
        return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-unauthenticated %s' %package)
    else:
        return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get install -y %s' %package)

def apt_remove(package):
    return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get remove -y %s' %package)

def dpkg_install(path_to_deb):
    return run('LANG=C DEBIAN_FRONTEND=noninteractive dpkg -i %s' % path_to_deb)

def dpkg_purge(deb_name):
    return run('LANG=C DEBIAN_FRONTEND=noninteractive dpkg --purge %s' % deb_name)

def apt_install_required_dependencies():
    return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get -f -y install')

def apt_autoremove():
    return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get -y autoremove')

def yum_install(package):
    return run('LANG=C yum install -y %s' % package)

def yum_remove(package):
    return run('LANG=C yum remove -y %s' % package)

def yum_autoremove():
    return run('LANG=C yum autoremove -y')

def apt_update():
    return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get -y update')

def apt_upgrade():
    return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get -y upgrade')

def yum_update():
    return run('LANG=C yum update -y')

def yum_upgrade():
    return run('LANG=C yum upgrade -y')