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
__version__ = "0.9.1"

import common
import json
from setuphelpers import *
from waptpackage import *
import active_directory
import codecs
from iniparse import RawConfigParser
import getpass

create_self_signed_key = common.create_self_signed_key
is_encrypt_private_key = common.private_key_has_password
is_match_password = common.check_key_password
import tempfile


def create_wapt_setup(wapt,default_public_cert='',default_repo_url='',default_wapt_server='',destination='',company=''):
    r"""Build a customized waptagent.exe with included provided certificate
    Returns filename
    >>> from common import Wapt
    >>> wapt = Wapt(config_filename=r'C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini')
    >>> create_wapt_setup(wapt,r'C:\private\ht.crt',destination='c:\\tranquilit\\wapt\\waptsetup')
    u'c:\\tranquilit\\wapt\\waptsetup\\waptagent.exe'
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
    return os.path.abspath(os.path.join(destination,os.path.basename(outputfile)))


def upload_wapt_setup(wapt,waptsetup_path, wapt_server_user, wapt_server_passwd):
    """Upload waptagent.exe to wapt repository
    >>> wapt = common.Wapt(config_filename="c:/users/htouvet/AppData/Local/waptconsole/waptconsole.ini")
    >>> upload_wapt_setup(wapt,'c:/tranquilit/wapt/waptsetup/waptagent.exe', 'admin', 'password')
    '{"status": "OK", "message": "waptagent.exe uploaded"}'
    """
    auth =  (wapt_server_user, wapt_server_passwd)
    with open(waptsetup_path,'rb') as afile:
        req = requests.post("%s/upload_waptsetup" % (wapt.waptserver.server_url,),files={'file':afile},proxies=wapt.waptserver.proxies,verify=False,auth=auth)
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
    computer_wapt = set( [ c['host']['computer_fqdn'].lower() for c in json.loads(requests.request('GET','%s/json/host_list'%wapt.waptserver.server_url).text)])
    diff = list(set(computer_ad)-set(computer_wapt))
    return diff


def diff_computer_wapt_ad(wapt):
    """Return the computer in Wapt Serveur but not in the Active Directory
    >>> wapt = common.Wapt(config_filename=r"c:\users\htouvet\AppData\Local\waptconsole\waptconsole.ini")
    >>> diff_computer_wapt_ad(wapt)
    ???
    """
    computer_ad =  set([ c['dnshostname'].lower() for c in active_directory.search("objectClass='computer'") if c['dnshostname']])
    computer_wapt = set( [ c['host']['computer_fqdn'].lower() for c in json.loads(requests.request('GET','%s/json/host_list'%wapt.waptserver.server_url).text)])
    result = list(set(computer_wapt)-set(computer_ad))
    return result


def search_bad_waptsetup(wapt,wapt_version):
    """Return list of computers in the Wapt Server who have not the version of Wapt specified"""
    hosts =  wapt.waptserver.get('hosts')
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
    wapt.use_hostpackages = False
    repo = wapt.config.get('global','templates_repo_url')
    wapt.repositories[0].repo_url = repo if repo else 'http://wapt.tranquil.it/wapt'
    wapt.proxies =  wapt.use_http_proxy_for_templates and {'http':wapt.config.get('global','http_proxy')} or None
    wapt.dbpath = r':memory:'
    wapt.update(register=False)
    return wapt.search(search_string)


def get_packages_filenames(waptconfigfile,packages_names):
    """Returns list of package filenames (latest version) matching comma seperated list of packages names and their dependencies
        helps to batch download a list of selected packages using tools like curl or wget
    >>> get_packages_filenames(r"c:\users\htouvet\AppData\Local\waptconsole\waptconsole.ini","tis-firefox-esr,tis-flash,tis-wapttest")
    [u'tis-firefox-esr_24.4.0-0_all.wapt', u'tis-flash_12.0.0.77-3_all.wapt', u'tis-wapttest.wapt', u'tis-wapttestsub_0.1.0-1_all.wapt', u'tis-7zip_9.2.0-15_all.wapt']
    """
    result = []
    wapt = common.Wapt(config_filename=waptconfigfile,disable_update_server_status=True)
    wapt.use_hostpackages = False
    # force to use alternate templates repo
    repo = wapt.config.get('global','templates_repo_url')
    wapt.repositories[0].repo_url = repo if repo else 'http://wapt.tranquil.it/wapt'
    if wapt.use_http_proxy_for_templates:
        wapt.proxies =  {'http':wapt.config.get('global','http_proxy')}
    else:
        wapt.proxies = None
    wapt.dbpath = r':memory:'
    # be sure to be up to date
    wapt.update(register=False)
    packages_names = common.ensure_list(packages_names)
    for name in packages_names:
        entries = wapt.is_available(name)
        if entries:
            pe = entries[-1]
            result.append(pe.filename)
            if pe.depends:
                for fn in get_packages_filenames(waptconfigfile,pe.depends):
                    if not fn in result:
                        result.append(fn)
    return result


def duplicate_from_external_repo(waptconfigfile,package_filename):
    r"""Duplicate a downloaded package to match prefix defined in waptconfigfile
       renames all dependencies
      returns source directory
    >>> from common import Wapt
    >>> wapt = Wapt(config_filename = r'C:\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini')
    >>> sources = duplicate_from_external_repo(wapt.config_filename,r'C:\tranquilit\wapt\tests\packages\tis-wapttest.wapt')
    >>> res = wapt.build_upload(sources,wapt_server_user='admin',wapt_server_passwd='password')
    >>> res[0]['package'].depends
    u'test-wapttestsub,test-7zip'
    """
    wapt = common.Wapt(config_filename=waptconfigfile,disable_update_server_status=True)
    wapt.use_hostpackages = False

    prefix = wapt.config.get('global','default_package_prefix','test')

    def rename_package(oldname,prefix):
        sp = oldname.split('-',1)
        if len(sp) == 2:
            return "%s-%s" % (prefix,sp[-1])
        else:
            return oldname

    oldname = PackageEntry().load_control_from_wapt(package_filename).package
    newname = rename_package(oldname,prefix)

    res = wapt.duplicate_package(package_filename,newname,build=False,auto_inc_version=True)
    result = res['source_dir']

    # renames dependencies
    package =  res['package']
    if package.depends:
        newdepends = []
        depends = [s.strip() for s in package.depends.split(',')]
        for dependname in depends:
            newname = rename_package(dependname,prefix)
            newdepends.append(newname)

        package.depends = ','.join(newdepends)
        package.save_control_to_wapt(result)
    return result

def wapt_sources_edit(wapt_sources_dir):
    """Launch pyscripter if installed, else explorer on supplied wapt sources dir"""
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

def edit_hosts_depends(waptconfigfile,hosts_list,
        append_depends=[],
        remove_depends=[],
        append_conflicts=[],
        remove_conflicts=[],
        key_password=None,
        wapt_server_user=None,wapt_server_passwd=None):
    """Add or remove packages from host packages
    >>> edit_hosts_depends('c:/wapt/wapt-get.ini','htlaptop.tranquilit.local','toto','tis-7zip','admin','password')
    """
    if not wapt_server_user:
        wapt_server_user = raw_input('WAPT Server user :')
    if not wapt_server_passwd:
        wapt_server_passwd = getpass.getpass('WAPT Server password :').encode('ascii')

    wapt = common.Wapt(config_filename=waptconfigfile,disable_update_server_status=True)
    hosts_list = common.ensure_list(hosts_list)
    append_depends = common.ensure_list(append_depends)
    remove_depends = common.ensure_list(remove_depends)
    append_conflicts = common.ensure_list(append_conflicts)
    remove_conflicts = common.ensure_list(remove_conflicts)

    result = []
    sources = []
    build_res = []
    try:
        for host in hosts_list:
            logger.debug(u'Edit host %s : +%s -%s'%(
                host,
                append_depends,
                remove_depends))
            target_dir = tempfile.mkdtemp('wapt')
            edit_res = wapt.edit_host(host,
                use_local_sources = False,
                target_directory = target_dir,
                append_depends = append_depends,
                remove_depends = remove_depends,
                append_conflicts = append_conflicts,
                remove_conflicts = remove_conflicts,
                )
            sources.append(edit_res)
        logger.debug(u'Build upload %s'%[r['source_dir'] for r in sources])
        build_res = wapt.build_upload([r['source_dir'] for r in sources],private_key_passwd = key_password,wapt_server_user=wapt_server_user,wapt_server_passwd=wapt_server_passwd)
    finally:
        logger.debug('Cleanup')
        for s in sources:
            if os.path.isdir(s['source_dir']):
                shutil.rmtree(s['source_dir'])
        for s in build_res:
            if os.path.isfile(s['filename']):
                os.unlink(s['filename'])
    return build_res

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
