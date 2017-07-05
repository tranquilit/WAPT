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
__version__ = '1.5.0.10'

# old function to install waptserver on windows. need to be rewritten (switch to nginx, websocket, etc.)

import os
import sys

try:
    wapt_root_dir = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            '..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0, os.path.join(wapt_root_dir))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib'))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib', 'site-packages'))


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

    if setuphelpers.iswin64():
        nssm = os.path.join(wapt_root_dir, 'waptservice', 'win64', 'nssm.exe')
    else:
        nssm = os.path.join(wapt_root_dir, 'waptservice', 'win32', 'nssm.exe')

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


def make_httpd_config(wapt_root_dir, wapt_folder):
    import jinja2

    if conf['wapt_folder'].endswith('\\') or conf['wapt_folder'].endswith('/'):
        conf['wapt_folder'] = conf['wapt_folder'][:-1]

    ap_conf_dir = os.path.join(
        wapt_root_dir,
        'waptserver',
        'apache-win32',
        'conf')
    ap_file_name = 'httpd.conf'
    ap_conf_file = os.path.join(ap_conf_dir, ap_file_name)
    ap_ssl_dir = os.path.join(
        wapt_root_dir,
        'waptserver',
        'apache-win32',
        'ssl')

    # generate ssl keys
    openssl = os.path.join(
        wapt_root_dir,
        'waptserver',
        'apache-win32',
        'bin',
        'openssl.exe')
    openssl_config = os.path.join(
        wapt_root_dir,
        'waptserver',
        'apache-win32',
        'conf',
        'openssl.cnf')
    fqdn = None
    try:
        import socket
        fqdn = socket.getfqdn()
    except:
        pass
    if not fqdn:
        fqdn = 'wapt'
    if '.' not in fqdn:
        fqdn += '.local'
    void = subprocess.check_output([
        openssl,
        'req',
        '-new',
        '-x509',
        '-newkey', 'rsa:2048',
        '-nodes',
        '-days', '3650',
        '-out', os.path.join(ap_ssl_dir, 'cert.pem'),
        '-keyout', os.path.join(ap_ssl_dir, 'key.pem'),
        '-config', openssl_config,
        '-subj', '/C=/ST=/L=/O=/CN=' + fqdn + '/'
    ], stderr=subprocess.STDOUT)

    # write config file
    jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(ap_conf_dir))
    template = jinja_env.get_template(ap_file_name + '.j2')
    template_variables = {
        'wapt_repository_path': os.path.dirname(conf['wapt_folder']),
        'apache_root_folder': os.path.dirname(ap_conf_dir),
        'windows': True,
        'ssl': True,
        'wapt_ssl_key_file': os.path.join(ap_ssl_dir, 'key.pem'),
        'wapt_ssl_cert_file': os.path.join(ap_ssl_dir, 'cert.pem')
    }
    config_string = template.render(template_variables)
    dst_file = file(ap_conf_file, 'wt')
    dst_file.write(config_string)
    dst_file.close()


def install_windows_service():
    """Setup waptserver, waptapache as a windows Service managed by nssm
    >>> install_windows_service([])
    """
    install_apache_service = not options.without_apache  # '--without-apache' not in options

    # register apache frontend
    if install_apache_service:
        make_httpd_config(wapt_root_dir, conf['wapt_folder'])
        service_binary = os.path.abspath(
            os.path.join(
                wapt_root_dir,
                'waptserver',
                'apache-win32',
                'bin',
                'httpd.exe'))
        service_parameters = ''
        service_logfile = os.path.join(log_directory, 'nssm_apache.log')
        install_windows_nssm_service(
            'WAPTApache',
            service_binary,
            service_parameters,
            service_logfile)

    # register waptserver
    service_binary = os.path.abspath(
        os.path.join(
            wapt_root_dir,
            'waptpython.exe'))
    service_parameters = '"%s"' % os.path.abspath(__file__)
    service_logfile = os.path.join(log_directory, 'nssm_waptserver.log')
    if install_apache_service:
        service_dependencies = ''
    else:
        service_dependencies = ''
    install_windows_nssm_service(
        'WAPTServer',
        service_binary,
        service_parameters,
        service_logfile,
        service_dependencies)
