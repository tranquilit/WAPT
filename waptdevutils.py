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
"""
 A collection of utility python functions for WaptConsole lazarus application.

 This module is imported in waptconsole using python4delphi.

 Some tasks are easier to script in Python than to use raw Freepascal
 as common.Wapt class already implements many use full mechanisms.

 Notes :
  - This module will be less and less used as Wapconsole will use waptserver
    exported functions instead of local Wapt functions (except crypto signatures)

"""
from __future__ import print_function
from waptutils import __version__

import sys,os
import shutil
import psutil
import common
import json
import jinja2
import requests

import active_directory
import codecs
from iniparse import RawConfigParser
import getpass

import tempfile
from tempfile import mkdtemp

from shutil import rmtree

from setuphelpers import registered_organization,makepath,filecopyto,run
from setuphelpers import mkdirs,isfile,remove_file,get_file_properties,messagebox
from setuphelpers import uac_enabled,inifile_readstring,shell_launch

from waptutils import ensure_list,ensure_unicode
from waptcrypto import check_key_password,SSLCABundle,SSLCertificate,SSLPrivateKey
from waptcrypto import NOPASSWORD_CALLBACK,sha256_for_file
from waptpackage import Version,PackageEntry,WaptRemoteRepo

from common import Wapt,WaptServer,WaptHostRepo,logger

def get_private_key_encrypted(certificate_path,password=None):
    """Load certificate and finc matching Key in same dir.
        Return path to private_key if key is encrypted
    Args:
        certificate_path (str): path to personal certificate

    Returns
        str: path to matching private key
    """
    cert = SSLCertificate(certificate_path)
    if isinstance(password,unicode):
        password = password.encode('utf8')
    try:
        if password is None or password == '':
            key = cert.matching_key_in_dirs(password_callback=NOPASSWORD_CALLBACK,private_key_password = None)
        else:
            key = cert.matching_key_in_dirs(private_key_password = password)
        if key:
            return key.private_key_filename
        else:
            return ''
    except Exception as e:
        print(e)
        return ''

def create_wapt_setup(wapt,default_public_cert='',default_repo_url='',default_wapt_server='',destination='',company=''):
    r"""Build a customized waptsetup with provided certificate included.
    Returns filename

    >>> from common import Wapt
    >>> wapt = Wapt(config_filename=r'C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini')
    >>> create_wapt_setup(wapt,r'C:\private\ht.crt',destination='c:\\tranquilit\\wapt\\waptsetup')
    u'c:\\tranquilit\\wapt\\waptsetup\\waptsetup.exe'
    """
    if not company:
        company = registered_organization()
    outputfile = ''
    iss_template = makepath(wapt.wapt_base_dir,'waptsetup','waptsetup.iss')
    custom_iss = makepath(wapt.wapt_base_dir,'waptsetup','custom_waptsetup.iss')
    iss = codecs.open(iss_template,'r',encoding='utf8').read().splitlines()
    new_iss=[]
    for line in iss:
        if line.startswith('#define default_repo_url'):
            new_iss.append('#define default_repo_url "%s"' % (default_repo_url))
        elif line.startswith('#define default_wapt_server'):
            new_iss.append('#define default_wapt_server "%s"' % (default_wapt_server))
        elif line.startswith('#define output_dir'):
            new_iss.append('#define output_dir "%s"' % (destination))
        elif line.startswith('#define Company'):
            new_iss.append('#define Company "%s"' % (company))
        elif line.startswith('#define install_certs'):
            new_iss.append('#define install_certs')
        elif line.startswith('WizardImageFile='):
            pass
        elif not line.startswith('#define signtool'):
            new_iss.append(line)
            if line.startswith('OutputBaseFilename'):
                outputfile = makepath(wapt.wapt_base_dir,'waptsetup','%s.exe' % line.split('=')[1])
    source = os.path.normpath(default_public_cert)
    target = os.path.join(os.path.dirname(iss_template),'..','ssl')
    if not (os.path.normcase(os.path.abspath( os.path.dirname(source))) == os.path.normcase(os.path.abspath(target))):
        filecopyto(source,target)
    codecs.open(custom_iss,'wb',encoding='utf8').write('\n'.join(new_iss))
    #inno_directory = '%s\\Inno Setup 5\\Compil32.exe' % programfiles32
    inno_directory =  makepath(wapt.wapt_base_dir,'waptsetup','innosetup','ISCC.exe')
    if not os.path.isfile(inno_directory):
        raise Exception(u"Innosetup n'est pas disponible (emplacement %s), veuillez l'installer" % inno_directory)
    run('"%s"  %s' % (inno_directory,custom_iss))
    #print('%s compiled successfully' % (outputfile, ))

    # create a sha256 file for waptupgrade package
    result = os.path.abspath(os.path.join(destination,os.path.basename(outputfile)))
    with open(makepath(wapt.wapt_base_dir,'waptupgrade','waptagent.sha256'),'wb') as f:
        f.write("%s %s\n" % (sha256_for_file(result),'waptagent.exe'))
    return result


def upload_wapt_setup(wapt,waptsetup_path, wapt_server_user, wapt_server_passwd,verify_cert=False):
    """Upload waptsetup.exe to wapt repository
    >>> wapt = common.Wapt(config_filename="c:/users/htouvet/AppData/Local/waptconsole/waptconsole.ini")
    >>> upload_wapt_setup(wapt,'c:/tranquilit/wapt/waptsetup/waptsetup.exe', 'admin', 'password')
    '{"status": "OK", "message": "waptsetup.exe uploaded"}'
    """
    auth =  (wapt_server_user, wapt_server_passwd)
    with open(waptsetup_path,'rb') as afile:
        req = requests.post("%s/upload_waptsetup" % (wapt.waptserver.server_url,),files={'file':afile},proxies=wapt.waptserver.proxies,
            verify=verify_cert,auth=auth,headers=common.default_http_headers())
        req.raise_for_status()
        res = json.loads(req.content)
    return res

def diff_computer_ad_wapt(wapt,wapt_server_user='admin',wapt_server_passwd=None):
    """Return the list of computers in the Active Directory but not registred in Wapt database

    >>> wapt = common.Wapt(config_filename=r"c:\users\htouvet\AppData\Local\waptconsole\waptconsole.ini")
    >>> diff_computer_ad_wapt(wapt)
    ???
    """
    computer_ad =  set([ c['dnshostname'].lower() for c in active_directory.search("objectClass='computer'") if c['dnshostname'] and c.operatingSystem and c.operatingSystem.startswith('Windows')])
    computer_wapt = set( [ c['host_info']['computer_fqdn'].lower() for c in  wapt.waptserver.get('api/v1/hosts?columns=host.computer_fqdn',auth=(wapt_server_user,wapt_server_passwd))['result']])
    diff = list(computer_ad-computer_wapt)
    return diff


def diff_computer_wapt_ad(wapt,wapt_server_user='admin',wapt_server_passwd=None):
    """Return the list of computers registered in Wapt database but not in the Active Directory

    >>> wapt = common.Wapt(config_filename=r"c:\users\htouvet\AppData\Local\waptconsole\waptconsole.ini")
    >>> diff_computer_wapt_ad(wapt)

    ???
    """
    computer_ad =  set([ c['dnshostname'].lower() for c in active_directory.search("objectClass='computer'") if c['dnshostname']])
    computer_wapt = set( [ c['computer_fqdn'].lower() for c in  wapt.waptserver.get('api/v1/hosts?columns=computer_fqdn',auth=(wapt_server_user,wapt_server_passwd))['result']])
    result = list(computer_wapt - computer_ad)
    return result


def update_external_repo(repourl,search_string,proxy=None,myrepo=None,my_prefix='',newer_only=False,newest_only=False,verify_cert=True,repo_name='wapt-templates'):
    """Get a list of entries from external templates public repository matching search_string
    >>> firefox = update_tis_repo(r"c:\users\htouvet\AppData\Local\waptconsole\waptconsole.ini","tis-firefox-esr")
    >>> isinstance(firefox,list) and firefox[-1].package == 'tis-firefox-esr'
    True
    """
    repo = WaptRemoteRepo(url=repourl,http_proxy=proxy,name=repo_name)
    if verify_cert == '' or verify_cert == '0':
        verify_cert = False
    repo.verify_cert = verify_cert
    packages = repo.search(search_string,newest_only=newest_only)
    if newer_only and myrepo:
        result = []
        for package in packages:
            if '-' in package.package:
                (prefix,name) = package.package.split('-',1)
                if my_prefix:
                    my_package_name = "%s-%s" % (my_prefix,name)
                else:
                    my_package_name = name
            else:
                my_package_name = package.package
            my_package = myrepo.get(my_package_name)
            if my_package and Version(my_package.version)<Version(package.version):
                result.append(package.as_dict())
        return result
    else:
        return [p.as_dict() for p in packages]

def get_packages_filenames(packages_names,with_depends=True,waptconfigfile=None,repo_name='wapt-templates',remoterepo=None):
    """Returns list of package filenames (latest version) and md5 matching comma separated list of packages names and their dependencies
    helps to batch download a list of selected packages using tools like curl or wget

    Args:
        packages_names (list or csv str): list of package names
        with_depends (bool): get recursively the all depends filenames
        waptconfigfile (str): path to wapt ini file
        repo_name : section name in wapt ini file for repo parameters (repo_url, http_proxy, timeout, verify_cert)
        remoterepo (WaptRemoteRepo) : remote repo to query.
                                      Mutually exclusive with waptconfigfile and repo_name
    Returns:
        list: list of (wapt file basename,md5)

    >>> get_packages_filenames(r"c:\users\htouvet\AppData\Local\waptconsole\waptconsole.ini","tis-firefox-esr,tis-flash,tis-wapttest")
    [u'tis-firefox-esr_24.4.0-0_all.wapt', u'tis-flash_12.0.0.77-3_all.wapt', u'tis-wapttest.wapt', u'tis-wapttestsub_0.1.0-1_all.wapt', u'tis-7zip_9.2.0-15_all.wapt']
    """
    result = []
    defaults = {
        'repo_url':'https://store.wapt.fr/wapt',
        'http_proxy':'',
        'verify_cert':'0',
        }

    if remoterepo is None:
        config = RawConfigParser(defaults=defaults)
        config.read(waptconfigfile)

        remoterepo = WaptRemoteRepo(name=repo_name,config=config)
        remoterepo.update()

    packages_names = ensure_list(packages_names)
    for name in packages_names:
        entries = remoterepo.packages_matching(name)
        if entries:
            pe = entries[-1]
            result.append((pe.filename,pe.md5sum,))
            if with_depends and pe.depends:
                for (fn,md5) in get_packages_filenames(pe.depends,remoterepo = remoterepo):
                    if not fn in result:
                        result.append((fn,md5,))
    return result

def duplicate_from_file(package_filename,new_prefix='test',target_directory=None,authorized_certs=None):
    r"""Duplicate a downloaded package to match prefix defined in waptconfigfile
    renames all dependencies

    Returns:
        str: source directory

    >>> from common import Wapt
    >>> wapt = Wapt(config_filename = r'C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini')
    >>> sources = duplicate_from_external_repo(wapt.config_filename,r'C:\tranquilit\wapt\tests\packages\tis-wapttest.wapt')
    >>> res = wapt.build_upload(sources,wapt_server_user='admin',wapt_server_passwd='password')
    >>> res[0]['package'].depends
    u'test-wapttestsub,test-7zip'
    """
    def rename_package(oldname,prefix):
        sp = oldname.split('-',1)
        if len(sp) == 2:
            return "%s-%s" % (prefix,sp[-1])
        else:
            return oldname

    source_package = PackageEntry(waptfile = package_filename)
    # authorized_certs is a directoyr instead a list of certificates.
    if authorized_certs is not None and authorized_certs != '' and not isinstance(authorized_certs,list):
        bundle = SSLCABundle()
        bundle.add_pems(makepath(authorized_certs,'*.crt'))
        bundle.add_pems(makepath(authorized_certs,'*.cer'))
        bundle.add_pems(makepath(authorized_certs,'*.pem'))
    else:
        bundle = authorized_certs or None

    source_package.unzip_package(target_dir=target_directory,cabundle=bundle)
    source_package.invalidate_signature()

    package = PackageEntry(waptfile = source_package.sourcespath)
    oldname = source_package.package
    package.package = rename_package(oldname,new_prefix)
    package.inc_build()

    result = package['sourcespath']

    # renames dependencies
    if package.depends:
        newdepends = []
        depends = ensure_list(package.depends)
        for dependname in depends:
            newname = rename_package(dependname,new_prefix)
            newdepends.append(newname)

        package.depends = ','.join(newdepends)

    # renames conflicts
    if package.conflicts:
        newconflicts = []
        conflicts = ensure_list(package.conflicts)
        for dependname in conflicts:
            newname = rename_package(dependname,new_prefix)
            newconflicts.append(newname)

        package.conflicts = ','.join(newconflicts)

    package.save_control_to_wapt()
    return result


def build_waptupgrade_package(waptconfigfile,target_directory=None,wapt_server_user=None,wapt_server_passwd=None,key_password=None,sign_digests=None):
    if target_directory is None:
        target_directory = tempfile.gettempdir()

    if not wapt_server_user:
        wapt_server_user = raw_input('WAPT Server user :')
    if not wapt_server_passwd:
        wapt_server_passwd = getpass.getpass('WAPT Server password :').encode('ascii')

    wapt = common.Wapt(config_filename=waptconfigfile,disable_update_server_status=True)
    wapt.dbpath = r':memory:'
    wapt.use_hostpackages = False

    if sign_digests is None:
        sign_digests = wapt.sign_digests

    if not wapt.personal_certificate_path or not os.path.isfile(wapt.personal_certificate_path):
        raise Exception(u'No personal certificate provided or not found (%s) for signing waptupgrade package' % wapt.personal_certificate_path)

    waptget = get_file_properties('wapt-get.exe')
    entry = PackageEntry(waptfile = makepath(wapt.wapt_base_dir,'waptupgrade'))
    patchs_dir = makepath(entry.sourcespath,'patchs')
    mkdirs(patchs_dir)
    filecopyto(makepath(wapt.wapt_base_dir,'waptdeploy.exe'),makepath(patchs_dir,'waptdeploy.exe'))

    entry.package = '%s-waptupgrade' % wapt.config.get('global','default_package_prefix')
    rev = entry.version.split('-')[1]
    entry.version = '%s-%s' % (waptget['FileVersion'],rev)
    entry.inc_build()
    entry.save_control_to_wapt()
    entry.build_package(target_directory=target_directory)
    certs = wapt.personal_certificate()
    key = wapt.private_key(private_key_password=key_password)
    if not certs[0].is_code_signing:
        raise Exception(u'%s is not code signing certificate' % wapt.personal_certificate_path)
    entry.sign_package(private_key=key,certificate = certs,private_key_password=key_password,mds = ensure_list(sign_digests))

    wapt.http_upload_package(entry.localpath,wapt_server_user=wapt_server_user,wapt_server_passwd=wapt_server_passwd)
    return entry.as_dict()


def check_uac():
    res = uac_enabled()
    if res:
        messagebox('UAC Warning',"""The UAC (user account control) is activated on this computer.
        For Wapt package development and debugging, it is recommended to disable UAC.

        If you modify the UAC setting, you must reboot your system to take changes in account.
        """)
        shell_launch('UserAccountControlSettings.exe')

def add_to_csv_list(csv_list,new_items):
    """Add items to csv_list"""
    items = ensure_list(csv_list)
    for item in new_items:
        if not item in items:
            items.append(item)
    return ','.join(items)

def remove_from_csv_list(csv_list,new_items):
    """Remove items from csv_list"""
    items = ensure_list(csv_list)
    for item in new_items:
        if item in items:
            items.remove(item)
    return ','.join(items)

def edit_hosts_depends(waptconfigfile,hosts_list,
        append_depends=[],
        remove_depends=[],
        append_conflicts=[],
        remove_conflicts=[],
        key_password=None,
        wapt_server_user=None,wapt_server_passwd=None,
        cabundle = None,
        ):
    """Add or remove packages from host packages

    Args:

    Returns:
        dict: { updated: of uuid of machines actually updated
                unchanged : list of uuid skipped because of no change needed
                discarded : list of uuid discarded due to errors}

    >>> edit_hosts_depends('c:/wapt/wapt-get.ini','htlaptop.tranquilit.local','toto','tis-7zip','admin','password')
    """
    sign_bundle = SSLCABundle(inifile_readstring(waptconfigfile,'global','personal_certificate_path'))
    sign_certs = sign_bundle.certificates()
    sign_key = sign_certs[0].matching_key_in_dirs(private_key_password=key_password)

    # we assume a unique signer.
    if cabundle is None:
        cabundle = sign_bundle

    hosts_list = ensure_list(hosts_list)
    host_repo = WaptHostRepo(name='wapt-host',host_id=hosts_list,cabundle = cabundle)
    host_repo.load_config_from_file(waptconfigfile)
    total_hosts = len(host_repo.packages)
    discarded_uuids = [p.package for p in host_repo.discarded]

    try:
        import waptconsole
        progress_hook = waptconsole.UpdateProgress
    except ImportError as e:
        def print_progress(show=False,n=0,max=100,msg=''):
            if show:
                print('%s %s/%s\r' % (msg,n,max),end='')
            else:
                if not msg:
                    msg='Done'
                print("%s%s"%(msg,' '*(80-len(msg))))
        progress_hook = print_progress

    hosts_list = ensure_list(hosts_list)
    append_depends = ensure_list(append_depends)
    remove_depends = ensure_list(remove_depends)
    append_conflicts = ensure_list(append_conflicts)
    remove_conflicts = ensure_list(remove_conflicts)

    packages = []
    discarded = []
    unchanged = []

    progress_hook(True,0,len(hosts_list),'Editing %s hosts' % len(hosts_list))
    i = 0
    try:
        for host_id in hosts_list:
            i+=1
            # don't change discarded packages.
            if host_id in discarded_uuids:
                discarded.append(host_id)
            else:
                host = host_repo.get(host_id)
                if host is None:
                    host = PackageEntry(package=host_id,section='host')

                if progress_hook(True,i,len(hosts_list),'Editing %s' % host.package):
                    break

                logger.debug(u'Edit host %s : +%s -%s'%(
                    host.package,
                    append_depends,
                    remove_depends))


                depends = host.depends
                depends = add_to_csv_list(depends,append_depends)
                depends = remove_from_csv_list(depends,remove_depends)

                conflicts = host.conflicts
                conflicts = add_to_csv_list(conflicts,append_conflicts)
                conflicts = remove_from_csv_list(conflicts,remove_conflicts)

                if depends != host.depends or conflicts != host.conflicts:
                    host.depends = depends
                    host.conflicts = conflicts
                    host.inc_build()
                    host_file = host.build_management_package()
                    host.sign_package(sign_certs,sign_key)
                    packages.append(host)
                else:
                    unchanged.append(host.package)

        # upload all in one step...
        progress_hook(True,3,3,'Upload %s host packages' % len(packages))
        server = WaptServer().load_config_from_file(waptconfigfile)
        server.upload_packages(packages,auth=(wapt_server_user,wapt_server_passwd),progress_hook=progress_hook)
        return dict(updated = [p.package for p in packages],
                    discarded = discarded,
                    unchanged = unchanged)

    finally:
        logger.debug('Cleanup')
        try:
            i = 0
            for s in packages:
                i+=1
                progress_hook(True,i,len(packages),'Cleanup')
                if os.path.isfile(s.localpath):
                    os.remove(s.localpath)
            progress_hook(False)
        except WindowsError as e:
            logger.critical('Unable to remove temporary directory %s: %s'% (s,repr(e)))
            progress_hook(False)


def get_computer_groups(computername):
    """Try to finc the computer in the Active Directory
        and return the list of groups
    """
    groups = []
    computer = active_directory.find_computer(computername)
    if computer:
        computer_groups = computer.memberOf
        if computer_groups:
            if not isinstance(computer_groups,(tuple,list)):
                computer_groups = [computer_groups]
            for group in computer_groups:
                # extract first component of group's DN
                cn = group.split(',')[0].split('=')[1]
                groups.append(cn)
    return groups

def add_ads_groups(waptconfigfile,hosts_list,wapt_server_user,wapt_server_passwd,key_password=None):
    # initialise wapt api with local config file
    wapt = Wapt(config_filename = waptconfigfile)
    wapt.dbpath=':memory:'

    # get current packages status from repositories
    wapt.update(register=False,filter_on_host_cap=False)

    hosts_list = ensure_list(hosts_list)

    # get the collection of hosts from waptserver inventory
    all_hosts = wapt.waptserver.get('api/v1/hosts?columns=uuid,computer_fqdn,depends',auth=(wapt_server_user,wapt_server_passwd))['result']
    if hosts_list:
        hosts = [ h for h in all_hosts if h['computer_fqdn'] in hosts_list]
    else:
        hosts = hosts_list

    result = []

    for h in hosts:
        try:
            hostname = h['computer_fqdn']
            print('Computer %s... \r' % hostname,end='')

            groups = get_computer_groups(h['computer_name'])
            wapt_groups = h['depends']
            additional = [ group for group in groups if not group in wapt_groups and wapt.is_available(group) ]

            if additional:
                # now update the host package : download and append missing packages
                tmpdir = mkdtemp()
                try:
                    package = wapt.edit_host(hostname,target_directory = tmpdir)
                    control = package['package']
                    depends =  ensure_list(control.depends)

                    control.depends = ','.join(depends+additional)
                    control.save_control_to_wapt(package.sourcespath)
                    buid_res = wapt.build_upload(package.sourcespath, private_key_passwd = key_password, wapt_server_user=wapt_server_user,wapt_server_passwd=wapt_server_passwd,
                        inc_package_release=True)[0]
                    print("  done, new packages: %s" % (','.join(additional)))
                    if os.path.isfile(buid_res):
                        os.remove(buid_res)
                    result.append(hostname)
                finally:
                    # cleanup of temporary
                    if os.path.isdir(tmpdir):
                        rmtree(tmpdir)
        except Exception as e:
            print(" error %s" % e)
            raise

    return result

def create_waptwua_package(waptconfigfile,wuagroup='default',wapt_server_user=None,wapt_server_passwd=None,key_password=None):
    """Create/update - upload a package to enable waptwua and set windows_updates_rules
    based on the content of database.
    """
    wapt = common.Wapt(config_filename=waptconfigfile,disable_update_server_status=True)
    wapt.dbpath = r':memory:'
    wapt.use_hostpackages = False
    # be sure to be up to date
    wapt.update(register=False,filter_on_host_cap=False)
    packagename = '{}-waptwua-{}'.format(wapt.config.get('global','default_package_prefix'),wuagroup)
    """
    packages = wapt.is_available(packagename)
    if not packages:
        # creates a new package based on waptwua template
        res = wapt.make_group_template(packagename,directoryname = mkdtemp('wapt'),section='waptwua')
    else:
        res = wapt.edit_package(packagename,target_directory = mkdtemp('wapt'),use_local_sources = False)
    """
    group_entry = wapt.make_group_template(packagename,directoryname = mkdtemp('wapt'),section='waptwua')
    build_res = wapt.build_upload(group_entry.sourcespath,
        private_key_passwd = key_password,
        wapt_server_user=wapt_server_user,
        wapt_server_passwd=wapt_server_passwd,
        inc_package_release=True)
    group_entry.delete_localsources()
    packagefilename = group_entry.localpath
    if isfile(packagefilename):
        remove_file(packagefilename)
    return build_res

def sign_actions(actions,certfilename,key_password=None):
    """Sign a list of claims with private key defined in waptconfigfile

    Args:
        waptconfigfile :
        actions (list of dict): actions to sign

    Returns:
        str : python json representation of signed actions

    >>> actions = [dict(action='install',package='tis-7zip'),dict(action='install',package='tis-firefox')]
    >>> sign_actions(r"C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini",actions,'test')
        [{'action': 'install',
          'package': 'tis-7zip',
          'signature': 'm/m/0kQFXq406MmTCjJdJ+C5zTgNvBX0+BzSnFmDJOVzmYD3HOcuROI60mr34qbUhDqG2ZOfmUbSLHCp5L8VnSm6h3uvc5xjXUWkbB8GRMS+q4yizMOQxwYHcw+X9bm4+9sW7m2IQXsXw66lYmaqPAWxk0C7ZOgyosJml2bGFTqp38a9hKSFIPJy0KxeshSlxne248MO1MoJB8iQrq823rm9SfoQNbpvAHfPrqHYw90nusvuzygH8UIqraquw2qg/ogQF8UN6kmhi+Vwyg4bCm7uV1499MntRS+wmV847Za/dwZKebN5aaBsoZRFe+PZjozrEaIvNKTvM1pr89BdSA==',
          'signature_date': '2017-06-06T17:16:10.648000',
          'signed_attributes': ['action', 'package'],
          'signer': 'Moi-autre',
          'signer_fingerprint': '195DEFCC322C945018E917BF217CD1323FC4C79F'},
         {'action': 'install',
          'package': 'tis-firefox',
          'signature': 'lkh6YdFqfYtYwTJDyJgb9XkR7ioTL0tWKrbqJFNU/ty74c9vDlBqS2Kh2c8eW2k6BHx2hBsohTLhLlWrUZ/JbqV0DAo66oyq9WDrsMx6xOj9DNhJDPgZRLDZ0+d2h7vW1kRZ31f0MZpGaVXxHyshG2ts+8EYlcCzfg9kTVJjLtUGXKllEemVUIylhgP9+LMIBkg+K1JRo2cscvpJYBJxGnMMp84uw1xsO+japXguzF48Vpu1W6tjiEpDDxDKWe6/8UwU4kZ+UZgv/eoDZOE8y2eEP+9ich3YgMx9rE7T4ra5ad6kuAbfEiEkfNLCvMlIDc3p92Q60c/f6VilA63dmA==',
          'signature_date': '2017-06-06T17:16:10.653000',
          'signed_attributes': ['action', 'package'],
          'signer': 'Moi-autre',
          'signer_fingerprint': '195DEFCC322C945018E917BF217CD1323FC4C79F'}]
    >>>
    """
    certs = SSLCABundle(certfilename).certificates()
    key = certs[0].matching_key_in_dirs(private_key_password=key_password)
    if isinstance(actions,(str,unicode)):
        actions = json.loads(actions)
    assert(isinstance(actions,list))

    result = []
    for action in actions:
        result.append(key.sign_claim(action,certificate=certs))
    return json.dumps(result)

def change_key_password(private_key_path,old_password=None,new_password=None):
    if not os.path.isfile(private_key_path):
        raise Exception(u'The private key %s does not exists' % private_key_path)
    key = SSLPrivateKey(filename = private_key_path,password=old_password)
    if os.path.isfile(private_key_path+'.backup'):
        raise Exception(u'Backup file %s already exists, previous password change has failed.' % private_key_path+'.backup')
    shutil.copyfile(private_key_path,private_key_path+'.backup')
    try:
        key.save_as_pem(filename = private_key_path,password = new_password)
        os.unlink(private_key_path+'.backup')
        return private_key_path
    except Exception as e:
        logger.critical(u'Unable to change key password: %s' % e)
        shutil.copyfile(private_key_path+'.backup',private_key_path)
        os.unlink(private_key_path+'.backup')
        raise

def render_jinja2_template(template_str,json_data):
    try:
        jinja_env = jinja2.Environment()
        template = jinja_env.from_string(template_str)
        template_data = json.loads(json_data)
        open('c:/tmp/template_data.json','w').write(json.dumps(template_data))
        return template.render(template_data)
    except:
        return json_data

if __name__ == '__main__':
    edit_hosts_depends(r'C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini',['C5921400-3476-11E2-9D6F-F806DF88E3E5','54313B54-F9E3-DC41-9EE5-EBBE7A9BB584'],
        append_depends='socle',key_password='test',wapt_server_user='admin',wapt_server_passwd='calimero')

    import doctest
    import sys
    reload(sys)
    sys.setdefaultencoding("UTF-8")
    import doctest
    doctest.ELLIPSIS_MARKER = '???'
    doctest.testmod(optionflags=doctest.ELLIPSIS)
    sys.exit(0)
