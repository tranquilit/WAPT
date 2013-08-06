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

import common
from M2Crypto import EVP
from setuphelpers import *
#import active_directory
import codecs
from iniparse import RawConfigParser

def registered_organization():
    return registry_readstring(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion','RegisteredOrganization')

def is_encrypt_private_key(key):
    def callback(*args):
        return ''
    try:
        EVP.load_key(key, callback)
    except Exception as e:
        if "bad password" in str(e):
            return True
        else:
            print str(e)
    return False



def create_self_signed_key(wapt,orgname,destdir='c:\\private',
        country='FR',
        locality=u'',
        organization=u'',
        unit='',
        commonname='',
        email='',
    ):
    """Creates a self signed key/certificate and returns the paths (keyfilename,crtfilename)"""
    destpem = os.path.join(destdir,'%s.pem' % orgname)
    destcrt = os.path.join(destdir,'%s.crt' % orgname)
    if os.path.isfile(destpem):
        raise Exception('Destination SSL key %s already exist' % destpem)
    if not os.path.isdir(destdir):
        os.makedirs(destdir)
    params = {
        'country':country,
        'locality':locality,
        'organization':organization,
        'unit':unit,
        'commonname':commonname,
        'email':email,
    }
    opensslbin = os.path.join(wapt.wapt_base_dir,'lib','site-packages','M2Crypto','openssl.exe')
    opensslcfg = codecs.open(os.path.join(wapt.wapt_base_dir,'templates','openssl_template.cfg'),'r',encoding='utf8').read() % params
    opensslcfg_fn = os.path.join(destdir,'openssl.cfg')
    codecs.open(opensslcfg_fn,'w',encoding='utf8').write(opensslcfg)
    os.environ['OPENSSL_CONF'] =  opensslcfg_fn
    out = run('%(opensslbin)s req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout %(destpem)s -out %(destcrt)s' %
        {'opensslbin':opensslbin,'orgname':orgname,'destcrt':destcrt,'destpem':destpem})
    print out
    return {'pem_filename':destpem,'crt_filename':destcrt}

def create_wapt_setup(wapt,default_public_cert='',default_repo_url='',company=''):
    """Build a customized waptsetup.exe with included provided certificate
    Returns filename"""
    print default_public_cert
    if not company:
        company = registered_organization()
    outputfile = ''
    iss_template = makepath(wapt.wapt_base_dir,'waptsetup','wapt.iss')
    iss = codecs.open(iss_template,'r',encoding='utf8').read().splitlines()
    new_iss=[]
    for line in iss:
        if line.startswith('#define default_repo_url'):
            new_iss.append('#define default_repo_url "%s"' % (default_repo_url))
        elif not line.startswith('SignTool'):
            new_iss.append(line)
            if line.startswith('OutputBaseFilename'):
                outputfile = makepath(wapt.wapt_base_dir,'waptsetup','%s.exe' % line.split('=')[1])
    print os.path.normpath(default_public_cert)
    filecopyto(os.path.normpath(default_public_cert),os.path.join(os.path.dirname(iss_template),'..','ssl'))
    codecs.open(iss_template,'w',encoding='utf8').write('\n'.join(new_iss))
    inno_directory = '%s\\Inno Setup 5\\Compil32.exe' % programfiles32
    run('"%s" /cc %s' % (inno_directory,iss_template))
    print('%s compiled successfully' % (outputfile, ))
    return outputfile

def diff_computer_ad_wapt(wapt):
    """Return the computer in the Active Directory but not in Wapt Serveur """
    computer_ad =  set([ c['dnshostname'] for c in  list(active_directory.search("objectClass='computer'"))])
    computer_wapt = set( [ c['name'] for c in json.loads(requests.request('GET','%s/json/host_list'%wapt.wapt_server).content)])
    diff = list(set(computer_ad)-set(computer_wapt))
    return diff


def diff_computer_wapt_ad(wapt):
    """Return the computer in Wapt Serveur but not in the Active Directory"""
    computer_ad =  set([ c['dnshostname'] for c in  list(active_directory.search("objectClass='computer'"))])
    computer_wapt = set( [ c['name'] for c in json.loads(requests.request('GET','%s/json/host_list'%wapt.wapt_server).content)])
    result = list(set(computer_wapt)-set(computer_ad))
    return result

def search_bad_waptseup(wapt,wapt_version):
    """Return list of computers in the Wapt Server who have not the version of Wapt specified"""
    hosts =  json.loads(requests.request('GET','%s/json/host_data'%wapt.wapt_server).content)
    result = dict()
    for i in hosts:
        wapt = [w for w in  i['softwares'] if w['key'] == 'WAPT_is1' ]
        if wapt[0]['version'] != wapt_version:
            result[i['name']] = wapt[0]['version']
    return result

def add_remove_option_inifile(wapt,choice,section,option,value):
    wapt_get_ini = RawConfigParser()
    waptini_fn = makepath(wapt.wapt_base_dir,'wapt-get.ini')
    wapt_get_ini.read(waptini_fn)
    if choice == True:
        wapt_get_ini.set(section,option,value)
    elif choice == False:
        wapt_get_ini.remove_option(section,option)
    with open(waptini_fn, 'w') as configfile:
        wapt_get_ini.write(configfile)

def updateTisRepo(wapt,search_string):
    wapt = common.Wapt(config_filename=wapt)
    wapt.update()
    return wapt.search(search_string)

def duplicate_from_tis_repo(wapt,old_file_name,new_file_name):
    wapt = common.Wapt(config_filename=wapt)
    wapt.update()
    result = wapt.duplicate_package(old_file_name,new_file_name)
    if 'source_dir' in result:
        return result['source_dir']
    else:
        return "error"




if __name__ == '__main__':
    #wapt = common.Wapt(config_filename='c://wapt//wapt-get.ini')
    #updateTisRepo(r'C:\tranquilit\wapt\wapt-get-public.ini')
     duplicate_from_tis_repo(r'C:\tranquilit\wapt\wapt-get-public.ini','tis-filezilla','totsso2-filezilla')
    #print(search_bad_waptseup(wapt,'0.6.23'))
    #print diff_computer_ad_wapt(wapt)
    #add_remove_option_inifile(wapt,True,'global','repo_url','http://wapt/wapt-sid')

    #create_wapt_setup(wapt,'C:\private\titit.crt',default_repo_url='',company='')