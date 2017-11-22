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
__version__ = '1.5.1.3'

# old function to install waptserver on windows. need to be rewritten (switch to nginx, websocket, etc.)

import os
import sys

try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0, os.path.join(wapt_root_dir))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib'))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib', 'site-packages'))

from waptserver_utils import *
import waptserver_config
from optparse import OptionParser
import logging
import subprocess
import setuphelpers
import datetime
from waptcrypto import SSLPrivateKey,SSLCertificate
import jinja2
import time

DEFAULT_CONFIG_FILE = os.path.join(wapt_root_dir, 'conf', 'waptserver.ini')
config_file = DEFAULT_CONFIG_FILE
conf = waptserver_config.load_config(config_file)

def fqdn():
    result = None
    try:
        import socket
        result = socket.getfqdn()
    except:
        pass
    if not result:
        result = 'wapt'
    if '.' not in result:
        result += '.local'

    return result

def create_dhparam(key_size=2048):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import dh
    parameters = dh.generate_parameters(generator=2, key_size=key_size,backend=default_backend())
    return parameters.parameter_bytes(serialization.Encoding.PEM,format=serialization.ParameterFormat.PKCS3)

def install_windows_nssm_service(
        service_name, service_binary, service_parameters, service_logfile, service_dependencies=None):
    """Setup a program as a windows Service managed by nssm
    >>> install_windows_nssm_service("WAPTServer",
        os.path.abspath(os.path.join(wapt_root_dir,'waptpython.exe')),
        os.path.abspath(__file__),
        os.path.join(log_directory,'nssm_waptserver.log'),
        service_logfile,
        'WAPTApache')
    """
    import setuphelpers
    from setuphelpers import registry_set, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ
    datatypes = {
        'dword': REG_DWORD,
        'sz': REG_SZ,
        'expand_sz': REG_EXPAND_SZ,
        'multi_sz': REG_MULTI_SZ,
    }

    if setuphelpers.service_installed(service_name):
        if not setuphelpers.service_is_stopped(service_name):
            logger.info('Stop running "%s"' % service_name)
            setuphelpers.run('net stop "%s" /yes' % service_name)
            while not setuphelpers.service_is_stopped(service_name):
                logger.debug('Waiting for "%s" to terminate' % service_name)
                time.sleep(2)

        logger.info('Unregister existing "%s"' % service_name)
        setuphelpers.run('sc delete "%s"' % service_name)

    if not setuphelpers.iswin64():
        raise Error('Windows 32bit install not supported')

    nssm = os.path.join(wapt_root_dir, 'waptservice', 'win64', 'nssm.exe')


    logger.info('Register service "%s" with nssm' % service_name)
    cmd = '"{nssm}" install "{service_name}" "{service_binary}" {service_parameters}'.format(
        nssm=nssm,
        service_name=service_name,
        service_binary=service_binary,
        service_parameters=service_parameters
    )
    logger.info('running command : %s' % cmd)
    setuphelpers.run(cmd)

    # fix some parameters (quotes for path with spaces...
    params = {
        'Description': 'sz:%s' % service_name,
        'DelayedAutostart': 1,
        'DisplayName': 'sz:%s' % service_name,
        'AppStdout': r'expand_sz:{}'.format(service_logfile),
        'ObjectName': r'NT AUTHORITY\NetworkService',
        'Parameters\\AppStderr': r'expand_sz:{}'.format(service_logfile),
        'Parameters\\AppParameters': r'expand_sz:{}'.format(service_parameters),
        'Parameters\\AppNoConsole': 1,
    }

    root = setuphelpers.HKEY_LOCAL_MACHINE
    base = r'SYSTEM\CurrentControlSet\services\%s' % service_name
    for key in params:
        if isinstance(params[key], int):
            (valuetype, value) = ('dword', params[key])
        elif ':' in params[key]:
            (valuetype, value) = params[key].split(':', 1)
            if valuetype == 'dword':
                value = int(value)
        else:
            (valuetype, value) = ('sz', params[key])
        fullpath = base + '\\' + key
        (path, keyname) = fullpath.rsplit('\\', 1)
        if keyname == '@' or keyname == '':
            keyname = None
        registry_set(root, path, keyname, value, type=datatypes[valuetype])

    if service_dependencies:
        logger.info(
            'Register dependencies for service "%s" with nssm : %s ' %
            (service_name, service_dependencies))
        cmd = '"{nssm}" set "{service_name}" DependOnService {service_dependencies}'.format(
            nssm=nssm,
            service_name=service_name,
            service_dependencies=service_dependencies
        )
        logger.info('running command : %s' % cmd)
        setuphelpers.run(cmd)

        # fullpath = base+'\\' + 'DependOnService'
        #(path,keyname) = fullpath.rsplit('\\',1)
        # registry_set(root,path,keyname,service_dependencies,REG_MULTI_SZ)


def make_nginx_config(wapt_root_dir, wapt_folder):

    if conf['wapt_folder'].endswith('\\') or conf['wapt_folder'].endswith('/'):
        conf['wapt_folder'] = conf['wapt_folder'][:-1]

    ap_conf_dir = os.path.join(
        wapt_root_dir,
        'waptserver',
        'nginx',
        'conf')
    ap_file_name = 'nginx.conf'
    ap_conf_file = os.path.join(ap_conf_dir, ap_file_name)
    ap_ssl_dir = os.path.join(wapt_root_dir,'waptserver','nginx','ssl')

    setuphelpers.mkdirs(ap_ssl_dir)

    key_fn = os.path.join(ap_ssl_dir,'key.pem')
    key = SSLPrivateKey(key_fn)
    if not os.path.isfile(key_fn):
        print('Create SSL RSA Key %s' % key_fn)
        key.create()
        key.save_as_pem()

    cert_fn = os.path.join(ap_ssl_dir,'cert.pem')
    if os.path.isfile(cert_fn):
        crt = SSLCertificate(cert_fn)
        if crt.cn != fqdn():
            os.rename(cert_fn,"%s-%s.old" % (cert_fn,'{:%Y%m%d-%Hh%Mm%Ss}'.format(datetime.datetime.now())))
            crt = key.build_sign_certificate(cn=fqdn(),is_code_signing=False)
            print('Create X509 cert %s' % cert_fn)
            crt.save_as_pem(cert_fn)
    else:
        crt = key.build_sign_certificate(cn=fqdn(),is_code_signing=False)
        print('Create X509 cert %s' % cert_fn)
        crt.save_as_pem(cert_fn)

    # write config file
    jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.join(wapt_root_dir,'waptserver','scripts')))
    template = jinja_env.get_template('waptwindows.nginxconfig.j2')
    template_variables = {
        'wapt_repository_path': os.path.dirname(conf['wapt_folder']).replace('\\','/'),
        'windows': True,
        'ssl': True,
        'force_https': False,
        'use_kerberos': False,
        'wapt_ssl_key_file': key_fn.replace('\\','/'),
        'wapt_ssl_cert_file': cert_fn.replace('\\','/'),
        'log_dir': os.path.join(wapt_root_dir,'waptserver','nginx','logs').replace('\\','/'),
        'wapt_root_dir' : wapt_root_dir.replace('\\','/'),
    }

    config_string = template.render(template_variables)
    print('Create nginx conf file %s' % ap_conf_file)
    with open(ap_conf_file, 'wt') as dst_file:
        dst_file.write(config_string)


def make_postgres_data_dir(wapt_root_dir):

    print ("init pgsql data directory")
    pg_data_dir = os.path.join(wapt_root_dir,'waptserver','pgsql_data')
    setuphelpers.mkdirs(pg_data_dir)
    setuphelpers.run(r'icacls %s /grant  "*S-1-5-20":(OI)(CI)(M)' % pg_data_dir)

    # should check if tasks already exist or not
    # there is a bug in setuphelper.task_exists()
    try:
        setuphelpers.run("schtasks /delete /tn init_wapt_pgsql /f")
    except:
        pass

    # note: init.pgsql.xml.j2 is utf8 encoded even if the xml header says it is utf16.
    # by default exported xml tasks are utf16-le encoded with BOM, but there are some issue during templating
    # so it is converted to utf8 without bom
    jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.join(wapt_root_dir,'waptserver','scripts')))
    template = jinja_env.get_template('init_pgsql.xml.j2')
    template_variables = {
        'wapt_root_dir': wapt_root_dir,
    }
    task_conf_file= os.path.join(wapt_root_dir,'waptserver','scripts','init_pgsql.xml')
    config_string = template.render(template_variables)
    with open(task_conf_file, 'wt') as dst_file:
        dst_file.write(config_string)

    setuphelpers.run(r"schtasks /create /xml %s /tn init_wapt_pgsql"  % task_conf_file)

    #should check if task is still running
    import time
    time.sleep(15)
    try:
        setuphelpers.run("schtasks /delete /tn init_wapt_pgsql /f")
    except:
        pass

def install_windows_service():
    """Setup waptserver, waptapache as a windows Service managed by nssm
    >>> install_windows_service([])
    """
    pass

def install_nginx_service():
    print("register nginx frontend")
    repository_path = os.path.join(wapt_root_dir,'waptserver','repository')
    for repo_path in ('wapt','wapt-host','wapt-hostref'):
        mkdir_p(os.path.join(repository_path,repo_path))
        setuphelpers.run(r'icacls %s /grant  "*S-1-5-20":(OI)(CI)(M)' % os.path.join(repository_path,repo_path))
    mkdir_p(os.path.join(wapt_root_dir,'waptserver','nginx','temp'))
    setuphelpers.run(r'icacls %s /grant  "*S-1-5-20":(OI)(CI)(M)' % (os.path.join(wapt_root_dir,'waptserver','nginx','temp')))

    setuphelpers.run(r'icacls %s /grant  "*S-1-5-20":(OI)(CI)(M)' % os.path.join(
                wapt_root_dir,'waptserver','nginx','logs'))

    make_nginx_config(wapt_root_dir, conf['wapt_folder'])
    service_binary = os.path.abspath(os.path.join(wapt_root_dir,'waptserver','nginx','nginx.exe'))
    service_parameters = ''
    service_logfile = os.path.join(log_directory, 'nssm_nginx.log')

    service_name = 'WAPTNginx'
    #print('Register "%s" in registry' % service_name)
    install_windows_nssm_service(service_name,service_binary,service_parameters,service_logfile)
    time.sleep(5)

def install_postgresql_service():
    print ("install postgres database")
        
    print ("build database directory")
    if not os.path.exists(os.path.join(wapt_root_dir,'waptserver','pgsql','data','postgresql.conf')):
        make_postgres_data_dir(wapt_root_dir)



    service_binary = os.path.abspath(os.path.join(wapt_root_dir,'waptserver','pgsql','bin','postgres.exe'))
    service_parameters = '-D %s' % os.path.join(wapt_root_dir,'waptserver','pgsql_data')
    service_logfile = os.path.join(log_directory, 'nssm_postgresql.log')
    install_windows_nssm_service('WAPTPostgresql',service_binary,service_parameters,service_logfile)
    setuphelpers.run(r'icacls %s /grant  "*S-1-5-20":(OI)(CI)(M)' % log_directory)

def install_waptserver_service():
    print("install waptserver")
    service_binary = os.path.abspath(os.path.join(wapt_root_dir,'waptpython.exe'))
    service_parameters = '"%s"' % os.path.join(wapt_root_dir,'waptserver','waptserver.py')
    service_logfile = os.path.join(log_directory, 'nssm_waptserver.log')
    service_dependencies = 'WAPTPostgresql'
    install_windows_nssm_service('WAPTServer',service_binary,service_parameters,service_logfile,service_dependencies)

if __name__ == '__main__':
    usage = """\
    %prog [-c configfile] [install_nginx install_postgresql install_waptserver]

    WAPT Server services setup.

    actions is either :
      <nothing> : run service in foreground
      install   : install as a Windows service managed by nssm
      uninstall : uninstall Windows service managed by nssm

    """

    parser = OptionParser(usage=usage, version='waptserver_winsetup.py ' + __version__)
    parser.add_option('-c','--config',dest='configfile',default=DEFAULT_CONFIG_FILE,
           help='Config file full path (default: %default)')

    parser.add_option('-l','--loglevel',dest='loglevel',default=None,type='choice',
            choices=['debug',   'warning','info','error','critical'],
            metavar='LOGLEVEL',help='Loglevel (default: warning)')
    parser.add_option('-d','--devel',dest='devel',default=False,action='store_true',
            help='Enable debug mode (for development only)')

    (options, args) = parser.parse_args()
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')


    if options.loglevel is not None:
        setloglevel(logger, options.loglevel)

    log_directory = os.path.join(wapt_root_dir, 'log')
    if not os.path.exists(log_directory):
        os.mkdir(log_directory)

    if args == ['all']:
        args = ['install_nginx','install_postgresql','install_waptserver']

    for action in args:
        if action == 'install_nginx':
            print('Installing postgresql as a service managed by nssm')
            install_nginx_service()
        elif action == 'install_postgresql':
            print('Installing NGINX as a service managed by nssm')
            install_postgresql_service()
        elif action == 'install_waptserver':
            print('Installing WAPT Server as a service managed by nssm')
            install_waptserver_service()

