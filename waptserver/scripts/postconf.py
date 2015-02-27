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
import os,sys
try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'../..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0,os.path.join(wapt_root_dir))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib'))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib','site-packages'))

from iniparse import RawConfigParser
import shutil
import fileinput
import glob
import hashlib
import dialog
import subprocess
import jinja2
import socket

# for python < 2.7
if "check_output" not in dir( subprocess ): # duck punch it in!
    def f(*popenargs, **kwargs):
        if 'stdout' in kwargs:
            raise ValueError('stdout argument not allowed, it will be overridden.')
        process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
        output, unused_err = process.communicate()
        retcode = process.poll()
        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = popenargs[0]
            raise subprocess.CalledProcessError(retcode, cmd)
        return output
    subprocess.check_output = f


# XXX on CentOS 6.5 the first call would fail because of compat mismatch between
# dialog(1) and our recent dialog.py
try:
    postconf = dialog.Dialog(dialog="dialog")
except dialog.UnableToRetrieveBackendVersion:
    postconf = dialog.Dialog(dialog="dialog", use_stdout=True)

def make_httpd_config(wapt_folder, waptserver_root_dir, fqdn):
    if wapt_folder.endswith('\\') or wapt_folder.endswith('/'):
        wapt_folder = wapt_folder[:-1]

    apache_dir = os.path.join(waptserver_root_dir, 'apache')
    wapt_ssl_key_file = os.path.join(apache_dir,'ssl','key.pem')
    wapt_ssl_cert_file = os.path.join(apache_dir,'ssl','cert.pem')

    # write the apache configuration fragment
    jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(apache_dir))
    template = jinja_env.get_template('httpd.conf.j2')

    template_vars = {
        'wapt_repository_path': os.path.dirname(wapt_folder),
        'apache_root_folder': '/not/used',
        'windows': False,
        'ssl': True,
        'wapt_ssl_key_file': wapt_ssl_key_file,
        'wapt_ssl_cert_file': wapt_ssl_cert_file,
        }

    config_string = template.render(template_vars)
    dst_file = file('/etc/apache2/sites-available/wapt', 'wt')
    dst_file.write(config_string)
    dst_file.close()

    # create keys for https:// access
    if not os.path.exists(wapt_ssl_key_file) or \
            not os.path.exists(wapt_ssl_cert_file):
        void = subprocess.check_output([
                'openssl',
                'req',
                '-new',                # create a request
                '-x509',               # no, actually, create a self-signed certificate!
                '-newkey', 'rsa:2048', # and the key that goes along, RSA, 2048 bits
                '-nodes',              # don't put a passphrase on the key
                '-days', '3650',       # the cert is valid for ten years
                '-out', wapt_ssl_cert_file,
                '-keyout', wapt_ssl_key_file,
                # fill in the minimum amount of information needed; to be revisited
                '-subj', '/C=/ST=/L=/O=/CN=' + fqdn + '/'
                ], stderr=subprocess.STDOUT)

if postconf.yesno("Do you want to launch post configuration tool ?") == postconf.DIALOG_OK:
    shutil.copyfile('/opt/wapt/waptserver/waptserver.ini.template','/opt/wapt/waptserver/waptserver.ini')
    waptserver_ini = RawConfigParser()

    waptserver_ini.read('/opt/wapt/waptserver/waptserver.ini')

    # no trailing slash
    wapt_folder = '/var/www/wapt'
    if os.path.isdir(wapt_folder):
        waptserver_ini.set('options','wapt_folder',wapt_folder)
    else:
        # keep in sync with waptserver.py
        wapt_folder = os.path.join(wapt_root_dir,'waptserver','repository','wapt')

    code, tag = postconf.menu("Mongodb server location",
                              choices=[("1", "localhost (default)"),
                                    ("2", "other server")])
    if code == postconf.DIALOG_OK:
        if tag == "1":
            waptserver_ini.set('options','mongodb_ip','127.0.0.1')
        elif tag == "2":
            (code,mongodb_ip) = postconf.inputbox("IP address of the mongodb server:")
            if code != postconf.DIALOG_OK:
                exit(1)
            else:
                waptserver_ini.set('options','mongodb_ip',mongodb_ip)
        elif code != postconf.DIALOG_OK:
            exit(1)

    code, tag = postconf.menu("Mongodb server port: ",
                                  choices=[("1", "27017 (default)"),
                                        ("2", "other")])
    if code == postconf.DIALOG_OK:
        if tag == "1":
            waptserver_ini.set('options','mongodb_port','27017')
        elif tag == "2":
            (code,mongodb_port) = postconf.inputbox("mongodb server port: ")
            if code != postconf.DIALOG_OK:
                exit(1)
            else:
                waptserver_ini.set('options','mongodb_port',mongodb_port)
        elif code != postconf.DIALOG_OK:
            exit(0)

    wapt_password_ok = False
    while not wapt_password_ok:
        wapt_password = ''
        wapt_password_check = ''

        while wapt_password == '':
            (code,wapt_password) = postconf.passwordbox("Please enter the wapt server password:  ", insecure=True)
            if code != postconf.DIALOG_OK:
                exit(0)

        while wapt_password_check == '':
            (code,wapt_password_check) = postconf.passwordbox("Please enter the wapt server password again:  ", insecure=True)
            if code != postconf.DIALOG_OK:
                exit(0)

        if wapt_password != wapt_password_check:
            postconf.msgbox('Password mismatch!')
        else:
            wapt_password_ok = True

    password = hashlib.sha1(wapt_password).hexdigest()
    waptserver_ini.set('options','wapt_password',password) 


    with open('/opt/wapt/waptserver/waptserver.ini','w') as inifile:
        subprocess.check_output("/bin/chmod 640 /opt/wapt/waptserver/waptserver.ini",shell=True) 
        subprocess.check_output("/bin/chown wapt /opt/wapt/waptserver/waptserver.ini",shell=True)
        waptserver_ini.write(inifile)

    final_msg = [
        'Postconfiguration completed.',
        ]

    reply = postconf.yesno("Do you want to configure apache?")
    if reply == postconf.DIALOG_OK:
        try:

            fqdn = socket.getfqdn()
            if not fqdn:
                fqdn = 'wapt'
            if '.' not in fqdn:
                fqdn += '.local'
            msg = 'FQDN for the WAPT server (eg. wapt.acme.com)'
            (code, reply) = postconf.inputbox(text=msg, width=len(msg)+4, init=fqdn)
            if code != postconf.DIALOG_OK:
                exit(1)
            else:
                fqdn = reply

            make_httpd_config(wapt_folder, '/opt/wapt/waptserver', fqdn)
            void = subprocess.check_output(['/etc/init.d/waptserver', 'start'], stderr=subprocess.STDOUT)
            void = subprocess.check_output(['a2dissite', 'default'], stderr=subprocess.STDOUT)
            void = subprocess.check_output(['a2dissite', 'default-ssl'], stderr=subprocess.STDOUT)
            void = subprocess.check_output(['a2enmod', 'ssl'], stderr=subprocess.STDOUT)
            void = subprocess.check_output(['a2enmod', 'proxy'], stderr=subprocess.STDOUT)
            void = subprocess.check_output(['a2enmod', 'proxy_http'], stderr=subprocess.STDOUT)
            void = subprocess.check_output(['a2ensite', 'wapt'], stderr=subprocess.STDOUT)
            void = subprocess.check_output(['/etc/init.d/apache2', 'graceful'], stderr=subprocess.STDOUT)

            reply = postconf.yesno("The Apache config has been reloaded. Do you want to force-restart Apache?")
            if reply == postconf.DIALOG_OK:
                void = subprocess.check_output(['/etc/init.d/apache2', 'restart'], stderr=subprocess.STDOUT)

            final_msg.append('Please connect to https://' + fqdn + '/ to access the server.')

        except subprocess.CalledProcessError as cpe:
            final_msg += [
                'Error while trying to configure Apache!',
                'errno = ' + str(cpe.code) + ', output: ' + cpe.output
                ]
        except Exception as e:
            import traceback
            final_msg += [
            'Error while trying to configure Apache!',
            traceback.format_exc()
            ]

    width = 4 + max(10, len(max(final_msg, key=len)))
    height = 2 + max(5, len(final_msg))
    postconf.msgbox('\n'.join(final_msg), height=height, width=width)
