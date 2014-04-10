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
__version__ = "0.8.26"

import common
import json
from setuphelpers import *
from waptpackage import *
import active_directory
import codecs
from iniparse import RawConfigParser


create_self_signed_key = common.create_self_signed_key
is_encrypt_private_key = common.private_key_has_password
is_match_password = common.check_key_password


def create_wapt_setup(wapt,default_public_cert='',default_repo_url='',default_wapt_server='',destination='',company=''):
    r"""Build a customized waptsetup.exe with included provided certificate
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
    return os.path.abspath(os.path.join(destination,os.path.basename(outputfile)))


def upload_wapt_setup(wapt,waptsetup_path, wapt_server_user, wapt_server_passwd):
    """Upload waptsetup.exe to wapt repository
    >>> wapt = common.Wapt(config_filename="c:/users/htouvet/AppData/Local/waptconsole/waptconsole.ini")
    >>> upload_wapt_setup(wapt,'c:/tranquilit/wapt/waptsetup/waptsetup.exe', 'admin', 'password')
    '{"status": "OK", "message": "waptsetup.exe uploaded"}'
    """
    auth =  (wapt_server_user, wapt_server_passwd)
    with open(waptsetup_path,'rb') as afile:
        req = requests.post("%s/upload_waptsetup" % (wapt.wapt_server,),files={'file':afile},proxies=wapt.proxies,verify=False,auth=auth)
        req.raise_for_status()
        res = json.loads(req.content)
    return res


def diff_computer_ad_wapt(wapt):
    """Return the computer in the Active Directory but not in Wapt Serveur
    >>> wapt = common.Wapt(config_filename=r"c:\users\htouvet\AppData\Local\waptconsole\waptconsole.ini")
    >>> diff_computer_ad_wapt(wapt)
    ???
    """
    computer_ad =  set([ c['dnshostname'].lower() for c in active_directory.search("objectClass='computer'") if c['dnshostname']])
    computer_wapt = set( [ c['host']['computer_fqdn'].lower() for c in json.loads(requests.request('GET','%s/json/host_list'%wapt.wapt_server).text)])
    diff = list(set(computer_ad)-set(computer_wapt))
    return diff


def diff_computer_wapt_ad(wapt):
    """Return the computer in Wapt Serveur but not in the Active Directory
    >>> wapt = common.Wapt(config_filename=r"c:\users\htouvet\AppData\Local\waptconsole\waptconsole.ini")
    >>> diff_computer_wapt_ad(wapt)
    ???
    """
    computer_ad =  set([ c['dnshostname'].lower() for c in active_directory.search("objectClass='computer'") if c['dnshostname']])
    computer_wapt = set( [ c['host']['computer_fqdn'].lower() for c in json.loads(requests.request('GET','%s/json/host_list'%wapt.wapt_server).text)])
    result = list(set(computer_wapt)-set(computer_ad))
    return result


def search_bad_waptsetup(wapt,wapt_version):
    """Return list of computers in the Wapt Server who have not the version of Wapt specified"""
    hosts =  json.loads(requests.request('GET','%s/json/host_data'%wapt.wapt_server).content)
    result = dict()
    for i in hosts:
        wapt = [w for w in  i['softwares'] if w['key'] == 'WAPT_is1' ]
        if wapt[0]['version'] != wapt_version:
            result[i['name']] = wapt[0]['version']
    return result


def update_tis_repo(waptconfigfile,search_string):
    """Get a list of entries from TIS public repository matching search_string
    >>> firefox = update_tis_repo(r"c:\users\htouvet\AppData\Local\waptconsole\waptconsole.ini","tis-firefox-esr")
    >>> isinstance(firefox,list) and firefox[-1].package == 'tis-firefox-esr'
    True
    """
    wapt = common.Wapt(config_filename=waptconfigfile,disable_update_server_status=True)
    repo = wapt.config.get('global','templates_repo_url')
    wapt.repositories[0].repo_url = repo if repo else 'http://wapt.tranquil.it/wapt'
    wapt.proxies =  {'http':wapt.config.get('global','http_proxy')}
    wapt.dbpath = r':memory:'
    wapt.update(register=False)
    return wapt.search(search_string)


def get_packages_filenames(waptconfigfile,packages_names):
    """Returns list of package filenames (latest version) matching comma seperated list of packages names)
    >>> get_packages_filenames(r"c:\users\htouvet\AppData\Local\waptconsole\waptconsole.ini","tis-firefox-esr,tis-flash")
    [u'tis-firefox-esr_24.4.0-0_all.wapt', u'tis-flash_12.0.0.77-3_all.wapt']
    """
    result = []
    wapt = common.Wapt(config_filename=waptconfigfile,disable_update_server_status=True)
    repo = wapt.config.get('global','templates_repo_url')
    wapt.repositories[0].repo_url = repo if repo else 'http://wapt.tranquil.it/wapt'
    wapt.proxies =  {'http':wapt.config.get('global','http_proxy')}
    wapt.dbpath = r':memory:'
    wapt.update(register=False)
    for name in packages_names.split(','):
        entries = wapt.is_available(name)
        if entries:
            result.append(entries[-1].filename)
    return result


def duplicate_from_tis_repo(waptconfigfile,file_name,depends=[]):
    """Duplicate a package from  to supplied wapt repository
    ;>>> duplicate_from_tis_repo(r'C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini','tis-firefox')
    """
    import tempfile
    wapt = common.Wapt(config_filename=waptconfigfile,disable_update_server_status=True)
    prefix = wapt.config.get('global','default_package_prefix')
    wapt.proxies =  {'http':wapt.config.get('global','http_proxy')}
    if not prefix:
        prefix = "tis"
    old_file_name = PackageEntry().load_control_from_wapt(file_name).package
    new_file_name ="%s-%s" % (prefix, old_file_name.split('-',1)[-1])
    wapt.config.set('global','default_sources_root',tempfile.mkdtemp())

    result = wapt.duplicate_package(file_name,new_file_name,build=False,auto_inc_version=False)
    print result
    source_dir = []
    new_depends = []
    if 'source_dir' in result:
        package =  result['package']
        source_dir.append(result['source_dir'])
        if package.depends:
            for depend in depends:
                old_file_name = PackageEntry().load_control_from_wapt(depend).package
                new_file_name ="%s-%s" % (prefix, old_file_name.split('-',1)[-1])
                new_depends.append(new_file_name)
                result = wapt.duplicate_package(depend,new_file_name,build=False,auto_inc_version=False)
                source_dir.append(result['source_dir'])

        if new_depends:
            package.depends = ','.join(new_depends)
            package.save_control_to_wapt(source_dir[0])

    return source_dir


def wapt_sources_edit(wapt_sources_dir):
    psproj_filename = os.path.join(wapt_sources_dir,'WAPT','wapt.psproj')
    control_filename = os.path.join(wapt_sources_dir,'WAPT','control')
    setup_filename = os.path.join(wapt_sources_dir,'setup.py')
    pyscripter_filename = os.path.join(programfiles32,'PyScripter','PyScripter.exe')
    if os.path.isfile(pyscripter_filename) and os.path.isfile(psproj_filename):
        import psutil
        p = psutil.Popen('"%s" --newinstance --project "%s" "%s" "%s"' % (pyscripter_filename,psproj_filename,setup_filename,control_filename),
            cwd = os.path.join(programfiles32,'PyScripter'))
    else:
        os.startfile(wapt_sources_dir)


def login_to_waptserver(url, login, passwd,newPass=""):
    try:
        data = {"username":login, "password": passwd}
        if newPass:
            data['newPass'] = newPass
        resp = requests.post(url, json.dumps(data))
        return resp.text
    except Exception as e:
        return unicode(str(e.message), 'ISO-8859-1')

def add_packages_to_hosts(waptconfigfile,hosts_list,packages_list,key_password=None):
    wapt = common.Wapt(config_filename=waptconfigfile,disable_update_server_status=True)
    if not isinstance(hosts_list,list):
        hosts_list = [hosts_list]
    if not isinstance(packages_list,list):
        hosts_list = [packages_list]
    for host in hosts_list:
        target = tempfile.mkdtemp('wapt')
        package = wapt.edit_host(host,target_directory = target,use_local_sources=False,append_depends = packages_list)



if __name__ == '__main__':
    import doctest
    import sys
    reload(sys)
    sys.setdefaultencoding("UTF-8")
    import doctest
    doctest.ELLIPSIS_MARKER = '???'
    doctest.testmod(optionflags=doctest.ELLIPSIS)
    sys.exit(0)

    #searchLastPackageTisRepo(r'C:\Users\Administrateur\AppData\Local\waptconsole\waptconsole.ini','')
