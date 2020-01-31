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

import glob
import locale
import logging
import os
import platform
import shutil
import socket
import stat
import subprocess
import sys
import time
import psutil
import netifaces
import platform
import time
import getpass
from zipfile import ZipFile
from iniparse import RawConfigParser
from waptpackage import PackageEntry
from waptutils import (Version, __version__, all_files, dateof,
                       datetime2isodate, ensure_list, ensure_unicode,
                       fileisodate, find_all_files, get_disk_free_space,
                       hours_minutes, httpdatetime2isodate, isodate2datetime,
                       time2display, wget, wgets, makepath,killtree,isfile,isdir,
                       CalledProcessErrorOutput,remove_file,mkdirs,get_main_ip)

__all__ = []

__all__.extend([
     '__version__',
     'all_files',
     'CalledProcessError',
     'control',
     'copytree2',
     'currentdate',
     'currentdatetime',
     'dateof',
     'datetime2isodate',
     'default_gateway',
     'default_oncopy',
     'default_overwrite',
     'default_overwrite_older',
     'default_skip',
     'dir_is_empty',
     'dmi_info',
     'ensure_dir',
     'ensure_list',
     'ensure_unicode',
     'error',
     'file_is_locked',
     'filecopyto',
     'fileisodate',
     'find_all_files',
     'find_processes',
     'get_computername',
     'get_current_user',
     'get_default_gateways',
     'get_disk_free_space',
     'get_dns_servers',
     'get_main_ip',
     'get_hostname',
     'get_fqdn',
     'get_language',
     'get_last_logged_on_user',
     'get_loggedinusers',
     'get_os_version',
     'glob',
     'host_info',
     'host_metrics',
     'hours_minutes',
     'httpdatetime2isodate',
     'inifile_deleteoption',
     'inifile_deletesection',
     'inifile_hasoption',
     'inifile_hassection',
     'inifile_readstring',
     'inifile_writestring',
     'installed_softwares',
     'isdir',
     'isfile',
     'isodate2datetime',
     'killtree',
     'logger',
     'makepath',
     'mkdirs',
     'networking',
     'os',
     'PackageEntry',
     'params',
     'processes_for_file',
     'remove_file',
     'run',
     'shell_launch',
     'shutil',
     'time2display',
     'unzip',
     'Version',
     'wget',
     'wgets',
     ])


# Conditionnal imports for setuphelpers
if platform.system() == 'Windows':

    from setuphelpers_windows import *

    __all__.extend([
     'add_double_quotes_around',
     'add_shutdown_script',
     'add_to_system_path',
     'add_user_to_group',
     'adjust_current_privileges',
     'application_data',
     'battery_lifetime',
     'battery_percent',
     'bookmarks',
     'common_desktop',
     'create_daily_task',
     'create_desktop_shortcut',
     'create_group',
     'create_onetime_task',
     'create_programs_menu_shortcut',
     'create_shortcut',
     'create_user',
     'create_user_desktop_shortcut',
     'create_user_programs_menu_shortcut',
     'critical_system_pending_updates',
     'default_user_appdata',
     'default_user_local_appdata',
     'delete_at_next_reboot',
     'delete_group',
     'delete_task',
     'delete_user',
     'desktop',
     'disable_file_system_redirection',
     'disable_task',
     'enable_task',
     'EnsureWUAUServRunning',
     'fix_wmi',
     'get_all_scheduled_tasks',
     'get_app_install_location',
     'get_app_path',
     'get_appath',
     'get_computer_description',
     'get_computer_domain',
     'get_computer_groups',
     'get_domain_fromregistry',
     'get_file_properties',
     'get_installer_defaults',
     'get_local_profiles',
     'get_msi_properties',
     'get_profile_path',
     'get_profiles_users',
     'get_shortcut_properties',
     'get_task',
     'get_user_from_sid',
     'getproductprops',
     'getsilentflags',
     'HKEY_CLASSES_ROOT',
     'HKEY_CURRENT_CONFIG',
     'HKEY_CURRENT_USER',
     'HKEY_LOCAL_MACHINE',
     'HKEY_USERS',
     'InstallerTypes',
     'install_exe_if_needed',
     'install_location',
     'install_msi_if_needed',
     'installed_windows_updates',
     'isrunning',
     'is_any_process_running',
     'iswin64',
     'KEY_ALL_ACCESS',
     'KEY_READ',
     'KEY_WRITE',
     'killalltasks',
     'list_local_printers',
     'local_admins',
     'local_admins',
     'local_desktops',
     'local_drives',
     'local_group_members',
     'local_group_memberships',
     'local_groups',
     'local_users',
     'local_users_profiles',
     'memory_status',
     'messagebox',
     'my_documents',
     'need_install',
     'pending_reboot_reasons',
     'programfiles',
     'programfiles32',
     'programfiles64',
     'programs',
     'reboot_machine',
     'recent',
     'REG_DWORD',
     'REG_EXPAND_SZ',
     'REG_MULTI_SZ',
     'REG_SZ',
     'reg_closekey',
     'reg_delvalue',
     'reg_enum_subkeys',
     'reg_enum_values',
     'reg_getvalue',
     'reg_key_exists',
     'reg_openkey_noredir',
     'reg_setvalue',
     'reg_value_exists',
     'register_dll',
     'register_ext',
     'register_uninstall',
     'register_windows_uninstall',
     'registered_organization',
     'registry_delete',
     'registry_deletekey',
     'registry_readstring',
     'registry_set',
     'registry_setstring',
     'remove_desktop_shortcut',
     'remove_from_system_path',
     'remove_metroapp',
     'remove_printer',
     'remove_programs_menu_folder',
     'remove_programs_menu_shortcut',
     'remove_shutdown_script',
     'remove_tree',
     'remove_user_desktop_shortcut',
     'remove_user_from_group',
     'remove_user_programs_menu_folder',
     'remove_user_programs_menu_shortcut',
     'replace_at_next_reboot',
     'RunOutput',
     'RunReader',
     'run_notfatal',
     'run_powershell',
     'run_powershell_from_file',
     'run_task',
     'running_as_admin',
     'running_as_system',
     'running_on_ac',
     'sendto',
     'service_delete',
     'service_installed',
     'service_is_running',
     'service_is_stopped',
     'service_restart',
     'service_start',
     'service_stop',
     'set_computer_description',
     'set_environ_variable',
     'set_file_hidden',
     'set_file_visible',
     'showmessage',
     'shutdown_scripts_ui_visible',
     'start_menu',
     'startup',
     'system32',
     'task_exists',
     'taskscheduler',
     'TimeoutExpired',
     'uac_enabled',
     'uninstall_cmd',
     'uninstall_key_exists',
     'unregister_dll',
     'unregister_uninstall',
     'unset_environ_variable',
     'user_appdata',
     'user_desktop',
     'user_local_appdata',
     'win_startup_info',
     'wincomputername',
     'windomainname',
     'WindowsVersions',
     'windows_version',
     'winshell',
     'wmi_as_struct',
     'wmi_info',
     'wmi_info_basic',
     'wua_agent_version',
     ])

else:

    __all__.extend([
     'get_kernel_version',
     'get_default_gateways',
     'user_local_appdata',
     'local_drives',
     'host_metrics',
     'default_gateway',
     'networking',
     'get_hostname',
     'get_current_user',
     'is_valid_ipv4_address',
     'get_dns_servers',
     'get_loggedinusers',
     'get_last_logged_on_user',
     'get_domain_batch',
     'host_info_common_unix',
     'get_computername',
     'dmi_info',
    ])

    if platform.system() == 'Darwin':

        from setuphelpers_macos import *

        __all__.extend([
         'get_info_plist_path',
         'get_plist_obj',
         'get_applications_info_files',
         'mount_dmg',
         'unmount_dmg',
         'is_local_app_installed',
         'get_installed_pkgs',
         'get_pkg_info',
         'is_local_pkg_installed',
         'is_dmg_installed',
         'install_pkg',
         'uninstall_pkg',
         'install_app',
         'uninstall_app',
         'install_dmg',
         'installed_softwares',
         'brew_install',
         'brew_uninstall',
        ])

    elif platform.system() == 'Linux':

        from setuphelpers_linux import *

        __all__.extend([
         'isLinux64',
         'apt_install',
         'apt_remove',
         'dpkg_install',
         'dpkg_purge',
         'get_distrib_version',
         'get_distrib_linux',
         'get_kernel_version',
         'apt_install_required_dependencies',
         'apt_autoremove',
         'yum_install',
         'yum_remove',
         'yum_autoremove',
         'apt_update',
         'apt_upgrade',
         'yum_update',
         'yum_upgrade',
         'type_debian',
         'type_redhat'])

logger = logging.getLogger()



def add_double_quotes_around(string):
    r"""Return the string with double quotes around

    Args:
        string (str): a string
    """
    return '"'+string+'"'

def filecopyto(filename,target):
    """Copy file from absolute or package temporary directory to target directory

    If file is dll or exe, logs the original and new version.

    Args:
        filename (str): absolute path to file to copy,
                        or relative path to temporary package install content directory.

        target (str) : absolute path to target directory where to copy file.

        target is either a full filename or a directory name
        if filename is .exe or .dll, logger prints version numbers

    >>> if not os.path.isfile('c:/tmp/fc.test'):
    ...     with open('c:/tmp/fc.test','wb') as f:
    ...         f.write('test')
    >>> if not os.path.isdir('c:/tmp/target'):
    ...    os.mkdir('c:/tmp/target')
    >>> if os.path.isfile('c:/tmp/target/fc.test'):
    ...    os.unlink('c:/tmp/target/fc.test')
    >>> filecopyto('c:/tmp/fc.test','c:/tmp/target')
    >>> os.path.isfile('c:/tmp/target/fc.test')
    True
    """
    (dir,fn) = os.path.split(filename)
    if not dir:
        dir = os.getcwd()

    if os.path.isdir(target):
        target = os.path.join(target,os.path.basename(filename))
    if os.path.isfile(target):
        if os.path.splitext(target)[1] in ('.exe','.dll'):
            try:
                ov = get_file_properties(target)['FileVersion']
                nv = get_file_properties(filename)['FileVersion']
                logger.info(u'Replacing %s (%s) -> %s' % (ensure_unicode(target),ov,nv))
            except:
                logger.info(u'Replacing %s' % target)
        else:
            logger.info(u'Replacing %s' % target)
    else:
        if os.path.splitext(target)[1] in ('.exe','.dll'):
            try:
                nv = get_file_properties(filename)['FileVersion']
                logger.info(u'Copying %s (%s)' % (ensure_unicode(target),nv))
            except:
                logger.info(u'Copying %s' % (ensure_unicode(target)))
        else:
            logger.info(u'Copying %s' % (ensure_unicode(target)))
    shutil.copy(filename,target)

# Copy of an entire tree from install temp directory to target
def default_oncopy(msg,src,dst):
    logger.debug(u'%s : "%s" to "%s"' % (ensure_unicode(msg),ensure_unicode(src),ensure_unicode(dst)))
    return True


def default_skip(src,dst):
    return False


def default_overwrite(src,dst):
    return True


def default_overwrite_older(src,dst):
    if os.stat(src).st_mtime <= os.stat(dst).st_mtime:
        logger.debug(u'Skipping, file on target is newer than source: "%s"' % (dst,))
        return False
    else:
        logger.debug(u'Overwriting file on target is older than source: "%s"' % (dst,))
        return True

def dir_is_empty(path):
    """Check if a directory is empty"""
    return isdir(path) and len(os.listdir(path)) == 0

def file_is_locked(path,timeout=5):
    """Check if a file is locked. waits timout seconds  for the release"""
    count = timeout
    while count>0:
        try:
            f = open(path,'ab')
            f.close()
            return False
        except IOError as e:
            if e.errno==13:
                count -=1
                if count<0:
                    return True
                else:
                    print('Waiting for %s to be released...'%path)
                    time.sleep(1)
            else:
                raise
    return True

def copytree2(src, dst, ignore=None,onreplace=default_skip,oncopy=default_oncopy,enable_replace_at_reboot=True):
    r"""Copy src directory to dst directory. dst is created if it doesn't exists
    src can be relative to installation temporary dir

    oncopy is called for each file copy. if False is returned, copy is skipped
    onreplace is called when a file will be overwritten.

    Args:
        src (str): path to source directory (absolute path or relative to package extraction tempdir)
        dst (str): path to target directory (created if not present)
        ignore (func) : callback func(root_dir,filenames) which returns names to ignore
        onreplace (func) : callback func(src,dst):boolean called when a file will be replaced to decide what to do.
                        default is to not replace if target exists. can be default_overwrite or default_overwrite_older or
                        custom function.
        oncopy (func) : callback func(msg,src,dst) called when a file is copied.
                        default is to log in debug level the operation
        enable_replace_at_reboot (boolean): if True, files which are locked will be scheduled for replace at next reboot

    Returns:

    Raises:

    >>> copytree2(r'c:\tranquilit\wapt\tests',r'c:\tranquilit\wapt\tests2')
    >>> isdir(r'c:\tranquilit\wapt\tests2')
    True
    >>> remove_tree(r'c:\tranquilit\wapt\tests2')
    >>> isdir(r'c:\tranquilit\wapt\tests2')
    False
    """
    logger.debug('Copy tree from "%s" to "%s"' % (ensure_unicode(src),ensure_unicode(dst)))
    # path relative to temp directory...
    tempdir = os.getcwd()
    if not os.path.isdir(src) and os.path.isdir(os.path.join(tempdir,src)):
        src = os.path.join(tempdir,src)

    names = os.listdir(src)
    if ignore is not None:
        ignored_names = ignore(src, names)
    else:
        ignored_names = set()

    if not os.path.isdir(dst):
        if oncopy('create directory',src,dst):
            os.makedirs(dst)
    errors = []
    skipped = []
    for name in names:
        if name in ignored_names:
            continue
        srcname = os.path.join(src, name)
        dstname = os.path.join(dst, name)
        try:
            if os.path.isdir(srcname):
                if oncopy('directory',srcname,dstname):
                    copytree2(srcname, dstname, ignore = ignore,onreplace=onreplace,oncopy=oncopy)
            else:
                try:
                    if os.path.isfile(dstname):
                        if onreplace(srcname,dstname) and oncopy('overwrites',srcname,dstname):
                            os.unlink(dstname)
                            shutil.copy2(srcname, dstname)
                    else:
                        if oncopy('copy',srcname,dstname):
                            shutil.copy2(srcname, dstname)
                except (IOError, os.error) as e:
                    # file is locked...
                    if enable_replace_at_reboot and e.errno in (5,13):
                        filecopyto(srcname,dstname+'.pending')
                        replace_at_next_reboot(tmp_filename=dstname+'.pending',target_filename=dstname)
                    else:
                        raise

        except (IOError, os.error) as why:
            logger.critical(u'Error copying from "%s" to "%s" : %s' % (ensure_unicode(src),ensure_unicode(dst),ensure_unicode(why)))
            errors.append((srcname, dstname, str(why)))
        # catch the Error from the recursive copytree so that we can
        # continue with other files
        except shutil.Error as err:
            #errors.extend(err.args[0])
            errors.append(err)
    try:
        shutil.copystat(src, dst)
    except WindowsError:
        # can't copy file access times on Windows
        pass
    except OSError as why:
        errors.extend((src, dst, str(why)))
    if errors:
        raise shutil.Error(errors)

def shell_launch(cmd):
    """Launch a command (without arguments) but doesn't wait for its termination

    >>> open('c:/tmp/test.txt','w').write('Test line')
    >>> shell_launch('c:/tmp/test.txt')
    """
    os.startfile(cmd)

def processes_for_file(filepath,open_files=True,dll=True):
    """Generator returning processes currently having a open file descriptor for filepath

    If not running as System account, can not access system processes.

    Args:
        filepath (str): file path or pattern (glob *)

    Returns:
        iterator psutil.Process

    """
    for process in psutil.process_iter():
        if dll:
            try:
                for dllproc in process.memory_maps():
                    if glob.fnmatch.fnmatch(dllproc.path,filepath):
                        yield process
                        break
            except Exception as e:
                # often : psutil.AccessDenied
                pass
        if open_files:
            try:
                for open_file in process.open_files():
                    if glob.fnmatch.fnmatch(open_file.path,filepath):
                        yield process
                        break
            except Exception as e:
                # often : psutil.AccessDenied
                pass


def find_processes(process_name):
    """Return list of Process names process_name

    Args:
        process_name (str): process name to lookup

    Returns:
        list: list of processes (Process) named process_name or process_name.exe

    >>> [p.pid for p in find_processes('explorer')]
    [2756, 4024]
    """
    process_name = process_name.lower()
    result = []
    for p in psutil.process_iter():
        try:
            if p.name().lower() in [process_name,process_name+'.exe']:
                result.append(p)
        except (psutil.AccessDenied,psutil.NoSuchProcess):
            pass

    return result

def get_domain():
    """Return main DNS domain of the computer

    Returns:
        str: domain name

    >>> get_domain_fromregistry()
    u'tranquilit.local'
    """
    if sys.platform == 'win32':
        return get_domain_fromregistry()
    elif sys.platform.startswith('linux'):
        return get_domain_batch()

def inifile_hasoption(inifilename,section,key):
    """Check if an option is present in section of the inifile

    Args:
        inifilename (str): Path to the ini file
        section (str): section
        key (str): value key to check

    Returns:
        boolean : True if the key exists

    >>> inifile_writestring('c:/tranquilit/wapt/tests/test.ini','global','version','1.1.2')
    >>> print inifile_hasoption('c:/tranquilit/wapt/tests/test.ini','global','version')
    True
    >>> print inifile_hasoption('c:/tranquilit/wapt/tests/test.ini','global','dontexist')
    False

    """
    inifile = RawConfigParser()
    inifile.read(inifilename)
    return inifile.has_section(section) and inifile.has_option(section,key)


def inifile_hassection(inifilename,section):
    """Check if an option is present in section of the inifile

    Args:
        inifilename (str): Path to the ini file
        section (str): section

    Returns:
        boolean : True if the key exists

    >>> inifile_writestring('c:/tranquilit/wapt/tests/test.ini','global','version','1.1.2')
    >>> print inifile_hassection('c:/tranquilit/wapt/tests/test.ini','global')
    True

    """
    inifile = RawConfigParser()
    inifile.read(inifilename)
    return inifile.has_section(section)


def inifile_deleteoption(inifilename,section,key):
    """Remove a key within the section of the inifile

    Args:
        inifilename (str): Path to the ini file
        section (str): section
        key (str): value key of option to remove

    Returns:
        boolean : True if the key/option has been removed

    >>> inifile_writestring('c:/tranquilit/wapt/tests/test.ini','global','version','1.1.2')
    >>> print inifile_hasoption('c:/tranquilit/wapt/tests/test.ini','global','version')
    True
    >>> print inifile_deleteoption('c:/tranquilit/wapt/tests/test.ini','global','version')
    False

    """
    inifile = RawConfigParser()
    inifile.read(inifilename)
    inifile.remove_option(section,key)
    inifile.write(open(inifilename,'w'))
    return inifile.has_section(section) and not inifile.has_option(section,key)

def get_os_version():
    if sys.platform == 'win32':
        return windows_version_from_registry()
    if sys.platform.startswith('linux'):
        return get_distrib_linux()

def is64():
    return platform.machine().endswith('64')


def inifile_deletesection(inifilename,section):
    """Remove a section within the inifile

    Args:
        inifilename (str): Path to the ini file
        section (str): section to remove

    Returns:
        boolean : True if the section has been removed

    """
    inifile = RawConfigParser()
    inifile.read(inifilename)
    inifile.remove_section(section)
    inifile.write(open(inifilename,'w'))
    return not inifile.has_section(section)


def inifile_readstring(inifilename,section,key,default=None):
    """Read a string parameter from inifile

    >>> inifile_writestring('c:/tranquilit/wapt/tests/test.ini','global','version','1.1.2')
    >>> print inifile_readstring('c:/tranquilit/wapt/tests/test.ini','global','version')
    1.1.2
    >>> print inifile_readstring('c:/tranquilit/wapt/tests/test.ini','global','undefaut','defvalue')
    defvalue
    """


    inifile = RawConfigParser()
    inifile.read(inifilename)
    if inifile.has_section(section) and inifile.has_option(section,key):
        return inifile.get(section,key)
    else:
        return default


def inifile_writestring(inifilename,section,key,value):
    r"""Write a string parameter to inifile

    >>> inifile_writestring('c:/tranquilit/wapt/tests/test.ini','global','version','1.1.1')
    >>> print inifile_readstring('c:/tranquilit/wapt/tests/test.ini','global','version')
    1.1.1
    """
    inifile = RawConfigParser()
    inifile.read(inifilename)
    if not inifile.has_section(section):
        inifile.add_section(section)
    inifile.set(section,key,value)
    inifile.write(open(inifilename,'w'))

def get_fqdn():
    return ensure_unicode(get_hostname()) if os.name == 'nt' else ensure_unicode(socket.getfqdn())

def get_language():
    """Get the default locale like fr, en, pl etc..  etc

    >>> get_language()
    'fr'
    """
    return locale.getdefaultlocale()[0].split('_')[0]

def running_as_system():
    """Dirty way to check if current process is running as system user
    """
    user = getpass.getuser()
    return user.endswith('$') and user[:-1].upper() == get_computername().upper()

def unzip(zipfn,target=None,filenames=None):
    """Unzip the files from zipfile with patterns in filenames to target directory

    Args:
        zipfn (str) : path to zipfile. (can be relative to temporary unzip location of package)
        target (str) : target location. Defaults to dirname(zipfile) + basename(zipfile)
        filenames (str or list of str): list of filenames / glob patterns (path sep is normally a slash)

    Returns:
        list : list of extracted files

    >>> unzip(r'C:\tranquilit\wapt\tests\packages\tis-7zip_9.2.0-15_all.wapt')
    [u'C:\\tranquilit\\wapt\\tests\\packages\\tis-7zip_9.2.0-15_all\\7z920-x64.msi',
     u'C:\\tranquilit\\wapt\\tests\\packages\\tis-7zip_9.2.0-15_all\\7z920.msi',
     u'C:\\tranquilit\\wapt\\tests\\packages\\tis-7zip_9.2.0-15_all\\setup.py',
     u'C:\\tranquilit\\wapt\\tests\\packages\\tis-7zip_9.2.0-15_all\\WAPT/control',
     u'C:\\tranquilit\\wapt\\tests\\packages\\tis-7zip_9.2.0-15_all\\WAPT/wapt.psproj',
     u'C:\\tranquilit\\wapt\\tests\\packages\\tis-7zip_9.2.0-15_all\\WAPT/manifest.sha256',
     u'C:\\tranquilit\\wapt\\tests\\packages\\tis-7zip_9.2.0-15_all\\WAPT/signature']

    >>> unzip(r'C:\tranquilit\wapt\tests\packages\tis-7zip_9.2.0-15_all.wapt',filenames=['*.msi','*.py'])
    [u'C:\\tranquilit\\wapt\\tests\\packages\\tis-7zip_9.2.0-15_all\\7z920-x64.msi',
     u'C:\\tranquilit\\wapt\\tests\\packages\\tis-7zip_9.2.0-15_all\\7z920.msi',
     u'C:\\tranquilit\\wapt\\tests\\packages\\tis-7zip_9.2.0-15_all\\setup.py']

    >>> unzip(r'C:\tranquilit\wapt\tests\packages\tis-7zip_9.2.0-15_all.wapt',filenames='WAPT/*')
    [u'C:\\tranquilit\\wapt\\tests\\packages\\tis-7zip_9.2.0-15_all\\WAPT/control',
     u'C:\\tranquilit\\wapt\\tests\\packages\\tis-7zip_9.2.0-15_all\\WAPT/wapt.psproj',
     u'C:\\tranquilit\\wapt\\tests\\packages\\tis-7zip_9.2.0-15_all\\WAPT/manifest.sha256',
     u'C:\\tranquilit\\wapt\\tests\\packages\\tis-7zip_9.2.0-15_all\\WAPT/signature']

    >>> unzip(r'C:\tranquilit\wapt\tests\packages\tis-7zip_9.2.0-15_all.wapt',filenames='WAPT/control')
    [u'C:\\tranquilit\\wapt\\tests\\packages\\tis-7zip_9.2.0-15_all\\WAPT\\control']

    .. versionadded:: 1.3.11

    """
    zipf = ZipFile(zipfn,allowZip64=True)
    if target is None:
        target=makepath(os.path.dirname(os.path.abspath(zipfn)),os.path.splitext(os.path.basename(zipfn))[0])

    if filenames is not None:
        filenames = [ pattern.replace('\\','/') for pattern in ensure_list(filenames)]

    def match(fn,filenames):
        # return True if fn matches one of the pattern in filenames
        if filenames is None:
            return True
        else:
            for pattern in filenames:
                if glob.fnmatch.fnmatch(fn,pattern):
                    return True
            return False
    if filenames is not None:
        files = [fn for fn in zipf.namelist() if match(fn,filenames)]
        zipf.extractall(target,members=files)
    else:
        files = zipf.namelist()
        zipf.extractall(target)

    return [makepath(target,fn.replace('/',os.sep)) for fn in files]

CalledProcessError = subprocess.CalledProcessError

# Specific parameters for install scripts
params = {}
control = PackageEntry()

if __name__=='__main__':
    pass
