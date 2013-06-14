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
from setuphelpers import *

def registered_organization():
    return registry_readstring(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion','RegisteredOrganization')

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
    os.environ['OPENSSL_CONF'] =  os.path.join(destdir,'templates','openssl.cfg')
    out = run('%(opensslbin)s req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout %(destpem)s -out %(destcrt)s' %
        {'opensslbin':opensslbin,'orgname':orgname,'destcrt':destcrt,'destpem':destpem})
    print out
    return {'pem_filename':destpem,'crt_filename':destcrt}

def create_wapt_setup(wapt,rep_work,default_public_cert='',default_default_repo_url='',company='',default_wapt_server=''):
    """Build a customized waptsetup.exe with included provided certificate
    Returns filename"""
    if not company:
        company = registered_organization()
    ensure_dir(rep_work)
    iss_template = makepath(wapt.wapt_base_dir,'waptsetup','wapt.iss')
    iss = codecs.open(iss_template,'r',encoding='utf8').read().splitlines()
    new_iss=[]
    for line in iss:
        if line.startswith('#define default_public_cert'):
            new_iss.append('#define default_public_cert "%s"' % (os.path.basename(crt_file),))
        elif line.startswith('#define default_public_cert'):
            new_iss.append('#define default_public_cert "%s"' % (os.path.basename(crt_file),))
        elif not line.startswith('SignTool'):
            new_iss.append(line)
    filecopyto(crt_file,os.path.join(os.path.dirname(iss_template),'..','ssl'))
    codecs.open(iss_template,'w',encoding='utf8').write('\n'.join(new_iss))
    run('"C:\Program Files\Inno Setup 5\Compil32.exe" /cc %s' % iss_template)
    print('waptsetup.exe finish to compile in %s' %os.path.dirname(iss_template))
    return iss_template


