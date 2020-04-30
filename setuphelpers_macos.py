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
import plistlib
import datetime
import platform
import shutil
import re
from packaging import version

import xml.etree.ElementTree as etree

from setuphelpers_unix import *

logger = logging.getLogger('waptcore')

def host_info():
    """ Read main workstation informations, returned as a dict """
    info = host_info_common_unix()
    info['os_name']=platform.system()
    info['os_version']=platform.release()
    info['platform'] = 'macOS'
    return info

def get_info_plist_path(app_dir):
    """ Applications typically contain an Info.plist file that shows information
        about the app.
        It's typically located at {APPDIR}/Contents/Info.plist .
    """
    return app_dir + '/Contents/Info.plist'


def get_plist_obj(plist_file):
    """ Returns a plist obj when given the path to a plist file. """
    def get_file_type(file):
        path_file = file.replace(' ', '\ ')
        file_output = run('file ' + path_file)
        file_type = file_output.split(file)[1][2:-1] # Removing ": " and "\n"
        return file_type

    file_type = get_file_type(plist_file)

    if file_type == 'Apple binary property list':
        tmp_plist = '/tmp/wapt_tmp_info.plist'
        subprocess.check_call('plutil -convert xml1 \'' + plist_file + '\' -o ' + tmp_plist, shell=True)
        return plistlib.readPlist(tmp_plist)
    else: # regular plist
        return plistlib.readPlist(plist_file)


def get_applications_info_files():
    """ Returns a list of the Info.plist files in the /Applications folder. """
    app_dirs = [file for file in glob.glob('/Applications/*.app')]
    plist_files = [get_info_plist_path(app_dir) for app_dir in app_dirs]
    return plist_files


def mount_dmg(dmg_path):
    """ Mounts a dmg file.

    Returns: The path to the mount point.
    """
    try:
        output = run('hdiutil mount ' + dmg_path)
    except subprocess.CalledProcessError, e:
        logger.warning('Error in mount_dmg : {0}'.format(e.output))
        return e.output

    return output.split('\t')[-1].rstrip()


def unmount_dmg(dmg_mount_path):
    """ Unmounts a dmg file, given the path to the mount point.

    Returns the value of the 'hdiutil unmount' command ran.
    """
    return run('hdiutil unmount \'' + dmg_mount_path + '\'')


def is_local_app_installed(appdir, check_version=None):
    """ Checks whether or not an application is already installed on the machine.

    Arguments:
        appdir          The path to the .app directory
        check_version   If true, also checks if the local package's version is
                        equal or superior to its possibly already installed version.

    Returns:
        True if it's already installed, False if it isn't. If check_version
        is specified, will also return False if it is already installed AND
        its version is inferior to the local package's version.
    """
    def get_installed_apps_info():
        app_info_files = get_applications_info_files()
        for f in app_info_files:
            yield get_plist_obj(f)

    # TODO check version

    local_app_info = get_info_plist_path(appdir)
    local_app_info = get_plist_obj(local_app_info)

    for installed_info in get_installed_apps_info():
        if installed_info['CFBundleName'] == local_app_info['CFBundleName']:
            if check_version == False:
                return True
            else:
                return version.parse(local_app_info['CFBundleShortVersionString']) <= version.parse(installed_info['CFBundleShortVersionString'])
    return False


def get_installed_pkgs():
    """ Returns the list of the IDs of the already installed packages. """
    return run('pkgutil --pkgs').rstrip().split('\n')


def get_pkg_info(pkg_id):
    """ Gets an installed pkg's info, given its ID.

    Returns: a dict made from data in plist format
    """
    pkginfo_str = run('pkgutil --pkg-info-plist {0}'.format(pkg_id))
    pkginfo = plistlib.readPlistFromString(pkginfo_str)
    return dict(pkginfo)


def is_local_pkg_installed(pkg_path, check_version=False):
    """ Checks whether or not a package file is already installed on the machine.

    Arguments:
        pkg_path        The path to the .pkg file
        check_version   If true, also checks if the local package's version is
                        equal or superior to its possibly already installed version.

    Returns:
        True if it's already installed, False if it isn't. If check_version
        is specified, will also return False if it is already installed AND
        its version is inferior to the local package's version.
    """

    tmp_dir = '/tmp/wapt_tmp_pkg'

    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)
    os.makedirs(tmp_dir)

    run('xar -xf {0} -C {1}'.format(pkg_path, tmp_dir))
    tree = etree.parse(tmp_dir + '/' + 'PackageInfo')
    root = tree.getroot()
    local_pkg_attrib = root.attrib

    shutil.rmtree(tmp_dir)

    pkglist = get_installed_pkgs()

    if local_pkg_attrib['identifier'] in pkglist:
        if check_version == False:
            return True
        else:
            installed_pkg_info = get_pkg_info(local_pkg_attrib['identifier'])
            return version.parse(installed_pkg_info['pkg-version']) >= version.parse(local_pkg_attrib['version'])
    return False


def is_dmg_installed(dmg_path, check_version=False):
    """ Checks whether or not a .dmg is already installed, given a path to it.

    Arguments:
        dmg_path        The path to the .dmg file
        check_version   If true, also checks if the local package's version is
                        equal or superior to its possibly already installed version.

    Returns:
        True if it's already installed, False if it isn't. If check_version
        is specified, will also return False if it is already installed AND
        its version is inferior to the local package's version."""
    result_map = []
    dmg_name = os.path.basename(dmg_path)
    dmg_mount_path = mount_dmg(dmg_path)

    try:
        dmg_file_assoc = {'.pkg': is_local_pkg_installed, '.app': is_local_app_installed}
        files = [dmg_mount_path + '/' + fname for fname in os.listdir(dmg_mount_path)]
        for file in files:
            fname, fextension = os.path.splitext(file)
            if fextension in dmg_file_assoc:
                result_map.append(dmg_file_assoc[fextension](file, check_version))
    except:
        logger.warning('Couldn\'t check contents of dmg file at {0}'.format(dmg_path))
        unmount_dmg(dmg_mount_path)
        return True

    unmount_dmg(dmg_mount_path)
    return any(result_map)


def install_pkg(pkg_path):
    """ Installs a pkg file, given its name or a path to it. """
    pkg_name = os.path.basename(pkg_path)
    logger.info('Requiring root access to install the package {0}:'.format(pkg_name))
    run("sudo installer -package {0} -target /".format(pkg_path))
    logger.info('Package {0} has been installed.'.format(pkg_name))


def uninstall_pkg(pkg_name):
    """ Uninstalls a pkg by its name.

    DELETES EVERY FILE. Should not save the user's configuration.

    Returns: True if it succeeded, False otherwise.
    """
    pkg_list = get_installed_pkgs()
    if pkg_name not in pkg_list:
        logger.warning('Couldn\'t uninstall the package {0} : package not installed.'.format(pkg_name))
        return False

    logger.info('Requiring root access to uninstall the package {0}:'.format(pkg_name))
    run('sudo -v')

    # TODO check them before deleting them : moving them to a tmp location?
    pkg_file_list = run('pkgutil --only-files --files {0}'.format(pkg_name)).rstrip().split('\n')
    for f in pkg_file_list:
        f = '/' + f # macOS doesn't put a / character despite it being an absolute path
        os.remove(f)

    run('sudo pkgutil --forget {0}'.format(pkg_name))
    logger.info('Package {0} has been successfully uninstalled.'.format(pkg_name))
    return True


def install_app(app_dir):
    """ Installs an app given a path to it.
    Copies the app directory to /Applications.
    """
    app_name = os.path.basename(app_dir)
    applications_dir = '/Applications'

    logger.info('Installing the contents of {0} in {1}...'.format(app_name, applications_dir))
    try:
        subprocess.check_call('cp -r \'{0}\' {1}'.format(app_dir, applications_dir), shell=True)
    except subprocess.CalledProcessError, e:
        logger.warning('Couldn\'t install {0} to {1}. Error code : {2}'.format(app_name, applications_dir, e.returncode))
    logger.info('{0} succesfully installed in {1}'.format(app_name, applications_dir))


def uninstall_app(app_dir):
    """ Uninstalls an app given a path to it.

    DELETES EVERY FILE. Should not save the user's configuration.
    """
    if app_dir[-4:] != '.app':
        app_dir += '.app'

    run('rm -rf /Applications/{0}'.format(app_dir))


def install_dmg(dmg_path, check_version=False):
    """ Installs a .dmg if it isn't already installed on the system.

    Arguments:
        dmg_path : the path to the dmg file

    Returns:
        True if it succeeded, False otherwise
    """
    ret_val = True

    dmg_name = os.path.basename(dmg_path)
    if is_dmg_installed(dmg_path, check_version):
        logger.info('The dmg file {0} is already installed on this machine.'.format(dmg_name))
        return False

    dmg_mount_path = mount_dmg(dmg_path)

    try:
        dmg_file_assoc = {'.pkg': install_pkg, '.app': install_app}
        files = [dmg_mount_path + '/' + fname for fname in os.listdir(dmg_mount_path)]
        nb_files_handled = 0
        for file in files:
            fname, fextension = os.path.splitext(file)
            if fextension in dmg_file_assoc:
                dmg_file_assoc[fextension](file)
                nb_files_handled += 1

        if nb_files_handled == 0:
            logger.warning('Error : the dmg provided did not contain a package or an application, or none could be found.', file=sys.stderr)
    except:
        ret_val = False
    finally:
        unmount_dmg(dmg_mount_path)

    return ret_val


def installed_softwares(keywords='', name=None):
    """ Return list of every application in the /Applications folder.

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

    app_dirs = [file for file in glob.glob('/Applications/*.app')]
    plist_files = [get_info_plist_path(app_dir) for app_dir in app_dirs]

    for plist_file in plist_files:
        try:
            plist_obj = get_plist_obj(plist_file)
            if (name_re is None or name_re.match(plist_obj['CFBundleName'])) or check_words(' '.join[plist_obj['CFBundleName'],plist_obj['CFBundleIdentifier'].split('.')[1]],keywords):
                list_installed_softwares.append({'key': '',
                            'name': plist_obj['CFBundleName'],
                            'version': plist_obj['CFBundleShortVersionString'],
                            'install_date': datetime.datetime.fromtimestamp(os.path.getmtime(plist_file)).strftime('%Y-%m-%d %H:%M:%S'),
                            'install_location': plist_file[:plist_file.index('.app') + 4],
                            'uninstall_string': '',
                            'publisher': plist_obj['CFBundleIdentifier'].split('.')[1], # "com.publisher.name" => "publisher"
                            'system_component': ''})
        except:
            logger.warning("Application data acquisition failed for {} :".format(plist_file), file=sys.stderr)

    return list_installed_softwares


def brew_install(pkg_name):
    """ Installs a brew package, given its name. """
    return subprocess.call('brew install ' + pkg_name, shell=True)


def brew_uninstall(pkg_name):
    """ Uninstalls a brew package, given its name. """
    return subprocess.call('brew uninstall ' + pkg_name, shell=True)