#!/opt/wapt/bin/python
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
from waptserver.config import __version__


usage = """\
%prog [--config filename] [--force-https] [--quiet]"""

import os,sys
try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),'../..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

import shutil
import fileinput
import glob
import hashlib
import dialog
import subprocess
import jinja2
import socket
import uuid
import platform
import re
import psutil
import datetime
import string
import random
import pwd
import grp
import ConfigParser
from optparse import OptionParser
import nginxparser
from passlib.hash import pbkdf2_sha256
from passlib import pwd

from waptpackage import WaptLocalRepo
import waptserver.config
from waptserver.config import type_debian,type_redhat
from waptserver.model import init_db,upgrade_db_structure,load_db_config
from waptcrypto import SSLCertificate,SSLPrivateKey

def run(*args, **kwargs):
    return subprocess.check_output(*args, shell=True, **kwargs)

def run_verbose(*args, **kwargs):
    output = subprocess.check_output(*args, shell=True, **kwargs)
    print output
    return output

if type_debian():
    MONGO_SVC='mongodb'
    APACHE_SVC='apache2'
    PGSQL_SVC='postgresql'
    wapt_folder = '/var/www/wapt'
    NGINX_GID= grp.getgrnam('www-data').gr_gid
elif type_redhat():
    MONGO_SVC='mongod'
    APACHE_SVC='httpd'
    PGSQL_SVC='postgresql-9.6'
    wapt_folder = '/var/www/html/wapt'
    NGINX_GID= grp.getgrnam('nginx').gr_gid
else:
    print "distrib type unknown"
    sys.exit(1)

quiet = False
postconf = dialog.Dialog(dialog="dialog")

def mkdir(path):
    if not os.path.isdir(path):
        os.makedirs(path)

def make_httpd_config(waptserver_root_dir, fqdn, force_https, server_config):
    ssl_dir = os.path.join(waptserver_root_dir, 'ssl')
    scripts_dir = os.path.join(waptserver_root_dir, 'scripts')
    wapt_ssl_key_file = os.path.join(ssl_dir,'key.pem')
    wapt_ssl_cert_file = os.path.join(ssl_dir,'cert.pem')
    mkdir(ssl_dir)

    # write the apache configuration fragment
    jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(scripts_dir))
    template = jinja_env.get_template('wapt.nginxconfig.template')
    krb5_realm = '.'.join(fqdn.split('.')[1:]).upper()

    template_vars = {
        'waptserver_port': server_config['waptserver_port'],
        'wapt_repository_path': os.path.dirname(server_config['wapt_folder']),
        'windows': False,
        'debian': type_debian(),
        'redhat': type_redhat(),
        'force_https': force_https,
        'wapt_ssl_key_file': wapt_ssl_key_file,
        'wapt_ssl_cert_file': wapt_ssl_cert_file,
        'fqdn': fqdn,
        'use_kerberos': server_config.get('use_kerberos',False),
        'KRB5_REALM': krb5_realm,
        'wapt_root_dir': wapt_root_dir,
        'clients_signing_certificate' : server_config.get('clients_signing_certificate'),
        'use_ssl_client_auth' : server_config.get('use_ssl_client_auth',False)
        }

    if quiet:
        print('[*] Nginx - creating wapt.conf virtualhost')

    config_string = template.render(template_vars)
    if type_debian():
        dst_file = file('/etc/nginx/sites-available/wapt.conf', 'wt')
        if not os.path.exists('/etc/nginx/sites-enabled/wapt.conf'):
            print(subprocess.check_output('ln -s /etc/nginx/sites-available/wapt.conf /etc/nginx/sites-enabled/wapt.conf',shell=True))
        if os.path.exists('/etc/nginx/sites-enabled/default'):
            os.unlink('/etc/nginx/sites-enabled/default')

    elif type_redhat():
        dst_file = file('/etc/nginx/conf.d/wapt.conf', 'wt')
    dst_file.write(config_string)
    dst_file.close()

    # create keys for https:// access
    if not os.path.exists(wapt_ssl_key_file) or \
            not os.path.exists(wapt_ssl_cert_file):
        if quiet:
            print('[*] Nginx - generate self-signed certs')
        old_apache_key = '/opt/wapt/waptserver/apache/ssl/key.pem'
        old_apache_cert = '/opt/wapt/waptserver/apache/ssl/cert.pem'

        if os.path.isfile(old_apache_cert) and os.path.isfile(old_apache_key):
            shutil.copyfile(old_apache_cert,wapt_ssl_cert_file)
            shutil.copyfile(old_apache_key,wapt_ssl_key_file)

        else:
            key = SSLPrivateKey(wapt_ssl_key_file)
            if not os.path.isfile(wapt_ssl_key_file):
                print('Create SSL RSA Key %s' % wapt_ssl_key_file)
                key.create()
                key.save_as_pem()

            if os.path.isfile(wapt_ssl_cert_file):
                crt = SSLCertificate(wapt_ssl_cert_file)
                if crt.cn != fqdn:
                    os.rename(wapt_ssl_cert_file,"%s-%s.old" % (wapt_ssl_cert_file,'{:%Y%m%d-%Hh%Mm%Ss}'.format(datetime.datetime.now())))
                    crt = key.build_sign_certificate(cn=fqdn,dnsname=fqdn,is_code_signing=False)
                    print('Create X509 cert %s' % wapt_ssl_cert_file)
                    crt.save_as_pem(wapt_ssl_cert_file)
            else:
                crt = key.build_sign_certificate(cn=fqdn,dnsname=fqdn,is_code_signing=False)
                print('Create X509 cert %s' % wapt_ssl_cert_file)
                crt.save_as_pem(wapt_ssl_cert_file)


    else:
        if quiet:
	        print('[*] Nginx - self-signed certs already exists, skipping...')


def ensure_postgresql_db(db_name='wapt',db_owner='wapt',db_password=''):
    """ create postgresql wapt db and user if it does not exists """

    def postgresql_running():
        return [p for p in psutil.process_iter() if p.name().lower() in (PGSQL_SVC)]

    if not postgresql_running():
        run('systemctl start %s' % PGSQL_SVC)
        run('systemctl enable %s' % PGSQL_SVC)

    val = run(""" sudo -u postgres psql template1 -c " select usename from pg_catalog.pg_user where usename='wapt';"  """, cwd='/opt/wapt')
    if 'wapt' in val:
        print("[*] postgresql - user wapt already exists, skipping creating user  ")
    else:
        print("[*] postgresql - we suppose that the db does not exist either (or the installation has been screwed up)")
        if not db_password:
            run(""" sudo -u postgres psql template1 -c "create user %s ; " """ % (db_owner), cwd='/opt/wapt/')
        else:
            run(""" sudo -u postgres psql template1 -c "create user %s with password '%s'; " """ % (db_owner,db_password), cwd='/opt/wapt/')

    val = ''
    #val = subprocess.check_output(""" sudo -u postgres psql template1 -c "select schema_name from information_schema.schemata where schema_name='wapt'; "  """, shell= True)
    val = run(""" sudo -u postgres psql template1 -c " SELECT datname FROM pg_database WHERE datname='wapt';   " """, cwd='/opt/wapt/')

    if 'wapt' in val:
        print("[*] postgresql - db already exists, skipping db creation")
    else:
        print('[*] postgresql - creating db wapt')
        run(""" sudo -u postgres psql template1 -c "create database %s with owner=%s encoding='utf-8'; " """ % (db_name,db_owner), cwd='/opt/wapt/')

    # check if hstore (for json) is installed
    val = run(""" sudo -u postgres psql wapt -c "select * from pg_extension where extname='hstore';" """, cwd='/opt/wapt/')
    if 'hstore' in val:
        print("[*] postgresql - hstore extension already loading into database, skipping create extension")
    else:
        run(""" sudo -u postgres psql wapt -c "CREATE EXTENSION hstore;" """, cwd='/opt/wapt/')

def enable_nginx():
    if quiet:
        run('systemctl enable nginx')
    else:
        run_verbose('systemctl enable nginx')

def restart_nginx():
    if quiet:
        run('systemctl restart nginx')
    else:
        run_verbose('systemctl restart nginx')

def enable_waptserver():
    if quiet:
        run('systemctl enable waptserver')
        run('systemctl enable wapttasks')
    else:
        run_verbose('systemctl enable waptserver')
        run_verbose('systemctl enable wapttasks')

def start_waptserver():
    if quiet:
        run("systemctl restart waptserver")
        run("systemctl restart wapttasks")
    else:
        run_verbose("systemctl restart waptserver")
        run_verbose("systemctl restart wapttasks")

def guess_fqdn():
    """ Guess FQDN from hostname - return default value if nothing found"""
    try:
        fqdn = socket.getfqdn()
        if not fqdn:
            fqdn = 'wapt'
        if '.' not in fqdn:
            fqdn += '.lan'
    except:
        fqdn = 'srvwapt'
    return fqdn

def stop_disable_httpd():
    def httpd_running():
        return [p for p in psutil.process_iter() if p.name().lower() in (APACHE_SVC,'httpd.exe')]
    if httpd_running():
        if not quiet:
            try:
                run_verbose('systemctl stop %s' % APACHE_SVC)
                run_verbose('systemctl disable %s' % APACHE_SVC)
            except:
                pass
        else:
            try:
                run('systemctl stop %s' % APACHE_SVC)
                run('systemctl disable %s' % APACHE_SVC)
            except:
                pass

def generate_dhparam():
    dh_filename = '/etc/ssl/certs/dhparam.pem'
    if not os.path.exists(dh_filename):
        if not quiet:
            run_verbose('openssl dhparam -out %s  2048' % dh_filename)
        else:
            run('openssl dhparam -out %s  2048' % dh_filename)
    os.chown(dh_filename, 0, NGINX_GID) #pylint: disable=no-member
    os.chmod(dh_filename, 0o640)        #pylint: disable=no-member

def selinux_rules():
    """ SELinux httpd security rules """
    run('setsebool -P httpd_can_network_connect 1')
    run('setsebool -P httpd_setrlimit on')
    for sepath in ('wapt','wapt-host','waptwua'):
        run('semanage fcontext -a -t httpd_sys_content_t "/var/www/html/%s(/.*)?"' %sepath)
        run('restorecon -R -v /var/www/html/%s' %sepath)

def setup_firewall():
    """ Add permanent rules for firewalld """
    if type_redhat():
        output = run('firewall-cmd --list-ports')
        if '443/tcp' in output and '80/tcp' in output:
            print("[*] Firewall already configured, skipping firewalld configuration")
            return
        if subprocess.call(['firewall-cmd', '--state'], stdout=open(os.devnull, 'w')) == 0:
            run('firewall-cmd --permanent --add-port=443/tcp')
            run('firewall-cmd --permanent --add-port=80/tcp')
            run('firewall-cmd --reload')
        else:
            run('firewall-offline-cmd --add-port=443/tcp')
            run('firewall-offline-cmd --add-port=80/tcp')

def check_mongo2pgsql_upgrade_needed(waptserver_ini):
    """ return True if upgrade2postgres has been processed.
    """
    def mongod_running():
        return [p for p in psutil.process_iter() if p.name().lower() in ('mongod','mongod.exe')]

    ini = ConfigParser.RawConfigParser()
    ini.read(waptserver_ini)

    return ini.has_option('options', 'mongodb_port') and len(mongod_running())>0

def upgrade2postgres(configfilename):
    print ("[*] DB Upgrade - mongodb process running, need to migrate")
    run('sudo -u wapt PYTHONPATH=/opt/wapt PYTHONHOME=/opt/wapt /opt/wapt/bin/python /opt/wapt/waptserver/upgrade.py upgrade2postgres -c "%s"' % configfilename)
    run("systemctl stop mongod")
    run("systemctl disable mongod")

def nginx_set_worker_limit(nginx_conf):
    already_set=False
    for entries in nginx_conf:
        if entries[0]=='worker_rlimit_nofile':
            print( "[*] Nginx - worker_rlimit_nofile already set")
            already_set=True
    if not already_set:
        nginx_conf.insert(3,['worker_rlimit_nofile', '32768'])
    return nginx_conf

def nginx_clean_default_vhost(nginx_conf):
    for entry in nginx_conf:
        if entry[0]==['http']:
            for subentry in entry[1]:
                if subentry[0]==['server']:
                    print('[*] Nginx - removing default vhost')
                    entry[1].remove(subentry)
    return nginx_conf

def nginx_cleanup():
    with open('/etc/nginx/nginx.conf','r') as read_conf:
        nginx_conf = nginxparser.load(read_conf)
        nginx_conf = nginx_set_worker_limit(nginx_conf)
        nginx_conf = nginx_clean_default_vhost(nginx_conf)
    with open("/etc/nginx/nginx.conf", "w") as nginx_conf_file:
        nginx_conf_file.write(nginxparser.dumps(nginx_conf))

def check_if_deb_installed(package_name):
   child = subprocess.Popen('/usr/bin/dpkg -l "%s"' % package_name, stdout=subprocess.PIPE,shell=True)
   streamdata = child.communicate()[0]
   rc = child.returncode
   if rc==0:
       return True
   return False

def main():
    global wapt_folder,NGINX_GID

    parser = OptionParser(usage=usage, version=__version__)
    parser.add_option(
        '-c',
        '--config',
        dest='configfile',
        default=waptserver.config.DEFAULT_CONFIG_FILE,
        help='Config file full path (default: %default)')
    parser.add_option(
        "-s",
        "--force-https",
        dest="force_https",
        default=False,
        action='store_true',
        help="Use https only, http is 301 redirected to https (default: False). Requires a proper DNS name")
    parser.add_option(
        '-q',
        '--quiet',
        dest='quiet',
        default=False,
        action="store_true",
        help='Run quiet postconfiguration - default password and simple behavior')

    (options, args) = parser.parse_args()

    quiet = options.quiet

    if not quiet:
        if postconf.yesno("Do you want to launch post configuration tool ?") != postconf.DIALOG_OK:
            print "canceling wapt postconfiguration"
            sys.exit(1)
    else:
        print('WAPT silent post-configuration')

    # SELinux rules for CentOS/RedHat
    if type_redhat():
        if re.match('^SELinux status:.*enabled', run('sestatus')):
            if not quiet:
                postconf.msgbox('SELinux detected, tweaking httpd permissions.')
                selinux_rules()
                postconf.msgbox('SELinux correctly configured for Nginx reverse proxy')
            else:
                print('[*] Redhat/Centos detected, tweaking SELinux rules')
                selinux_rules()
                print('[*] Nginx - SELinux correctly configured for Nginx reverse proxy')

    # Load existing config file
    server_config = waptserver.config.load_config(options.configfile)

    if os.path.isfile(options.configfile):
        print('[*] Making a backup copy of the configuration file')
        datetime_now = datetime.datetime.now()
        shutil.copyfile(options.configfile,'%s.bck_%s'%  (options.configfile,datetime_now.isoformat()) )

    wapt_folder = server_config['wapt_folder']

    # add secret key initialisation string (for session token)
    if not server_config['secret_key']:
        server_config['secret_key'] = ''.join(random.SystemRandom().choice(string.letters + string.digits) for _ in range(64))

    # add user db and password in ini file
    if server_config['db_host'] in (None,'','localhost','127.0.0.1','::1'):
        ensure_postgresql_db(db_name=server_config['db_name'],db_owner=server_config['db_name'],db_password=server_config['db_password'])

    # Password setup/reset screen
    if not quiet:
        if not server_config['wapt_password'] or \
                postconf.yesno("Do you want to reset admin password ?",yes_label='skip',no_label='reset') != postconf.DIALOG_OK:
            wapt_password_ok = False
            while not wapt_password_ok:
                wapt_password = ''
                wapt_password_check = ''

                while wapt_password == '':
                    (code,wapt_password) = postconf.passwordbox("Please enter the wapt server password (min. 10 characters):  ", insecure=True,width=100)
                    if code != postconf.DIALOG_OK:
                        exit(0)

                while wapt_password_check == '':
                    (code,wapt_password_check) = postconf.passwordbox("Please enter the wapt server password again:  ", insecure=True,width=100)
                    if code != postconf.DIALOG_OK:
                        exit(0)

                if wapt_password != wapt_password_check:
                    postconf.msgbox('Password mismatch !')
                elif len(wapt_password) < 10:
                    postconf.msgbox('Password must be at least 10 characters long !')
                else:
                    wapt_password_ok = True

            password = pbkdf2_sha256.hash(wapt_password.encode('utf8'))
            server_config['wapt_password'] = password
    else:
        wapt_password = ''
        if not server_config['wapt_password']:
            print('[*] Generating random password for WAPT server')
            wapt_password = pwd.genword(entropy=56, charset="ascii_62")
            print('[*] WAPT admin password : %s' % wapt_password)
            password = pbkdf2_sha256.hash(wapt_password.encode('utf8'))
            server_config['wapt_password'] = password

    if not server_config['server_uuid']:
        server_config['server_uuid'] = str(uuid.uuid1())

    # waptagent authentication method
    if not quiet:
        choices = [
                ("1","Allow unauthenticated registration, same behavior as WAPT 1.3", True),
                ("2","Enable kerberos authentication required for machines registration", False),
                ("3","Disable Kerberos but registration require strong authentication", False),
                ]

        code, t = postconf.radiolist("WaptAgent Authentication type?", choices=choices,width=120)
        if code=='cancel':
            print("\n\npostconfiguration canceled\n\n")
            sys.exit(1)
        if t=="1":
            server_config['allow_unauthenticated_registration'] = True
            server_config['use_kerberos'] = False
        if t=="2":
            server_config['allow_unauthenticated_registration'] = False
            server_config['use_kerberos'] = True
        if t=="3":
            server_config['allow_unauthenticated_registration'] = False
            server_config['use_kerberos'] = False
    else:
        print('[*] Set default registration method to : Allow anyone to register + Kerberos disabled')
        server_config['allow_unauthenticated_registration'] = True
        server_config['use_kerberos'] = False


    # Guess fqdn using socket
    fqdn = guess_fqdn()

    clients_signing_certificate =  server_config.get('clients_signing_certificate')
    clients_signing_key = server_config.get('clients_signing_key')

    if not clients_signing_certificate or not clients_signing_key:
        clients_signing_certificate = os.path.join(wapt_root_dir,'conf','ca-%s.crt' % fqdn)
        clients_signing_key = os.path.join(wapt_root_dir,'conf','ca-%s.pem' % fqdn)

        server_config['clients_signing_certificate'] = clients_signing_certificate
        server_config['clients_signing_key'] = clients_signing_key

    if clients_signing_certificate is not None and clients_signing_key is not None and not os.path.isfile(clients_signing_certificate):
        print('Create a certificate and key for clients certificate signing')

        key = SSLPrivateKey(clients_signing_key)
        if not os.path.isfile(clients_signing_key):
            print('Create SSL RSA Key %s' % clients_signing_key)
            key.create()
            key.save_as_pem()

        crt = key.build_sign_certificate(cn=fqdn,is_code_signing=False,is_ca=True)
        print('Create X509 cert %s' % clients_signing_certificate)
        crt.save_as_pem(clients_signing_certificate)

    waptserver.config.write_config_file(cfgfile=options.configfile,server_config=server_config,non_default_values_only=True)

    print('[*] Protecting WAPT config file')
    run("/bin/chmod 640 %s" % options.configfile)
    run("/bin/chown wapt %s" % options.configfile)

    print('[*] Update WAPT repository')
    repo = WaptLocalRepo(wapt_folder)
    repo.update_packages_index(force_all=True)

    final_msg = ['[*] Postconfiguration completed.',]
    if not quiet:
        postconf.msgbox("Press ok to start waptserver and wapttasks daemons")
    enable_waptserver()
    start_waptserver()

    # In this new version Apache is replaced with Nginx? Proceed to disable Apache. After migration one can remove Apache install altogether
    stop_disable_httpd()

    # Nginx configuration
    if quiet:
        try:
            generate_dhparam()
            nginx_cleanup()
            make_httpd_config('/opt/wapt/waptserver', fqdn, options.force_https,server_config)
            enable_nginx()
            restart_nginx()
            setup_firewall()
        except subprocess.CalledProcessError as cpe:
            final_msg += [
                'Error while trying to configure Nginx!',
                'errno = ' + str(cpe.returncode) + ', output: ' + cpe.output
                ]
        except Exception as e:
                import traceback
                final_msg += [
                'Error while trying to configure Nginx!',
                traceback.format_exc()
                ]
    else:
        reply = postconf.yesno("Do you want to configure nginx?")
        if reply == postconf.DIALOG_OK:
            try:
                msg = 'FQDN for the WAPT server (eg. wapt.acme.com)'
                (code, reply) = postconf.inputbox(text=msg, width=len(msg)+4, init=fqdn)
                if code != postconf.DIALOG_OK:
                    exit(1)
                else:
                    fqdn = reply

                generate_dhparam()
                nginx_cleanup()

                if server_config['use_kerberos']:
                    if type_debian():
                        if not check_if_deb_installed('libnginx-mod-http-auth-spnego'):
                            print('[*] Nginx - Missing dependency libnginx-mod-http-auth-spnego, please install first before configuring kerberos')
                            sys.exit(1)

                make_httpd_config('/opt/wapt/waptserver', fqdn, options.force_https, server_config)
                final_msg.append('Please connect to https://' + fqdn + '/ to access the server.')
                postconf.msgbox("The Nginx config is done. We need to restart Nginx?")
                run_verbose('systemctl enable nginx')
                run_verbose('systemctl restart nginx')
                setup_firewall()

            except subprocess.CalledProcessError as cpe:
                final_msg += [
                    'Error while trying to configure Nginx!',
                    'errno = ' + str(cpe.returncode) + ', output: ' + cpe.output
                    ]
            except Exception as e:
                import traceback
                final_msg += [
                'Error while trying to configure Nginx!',
                traceback.format_exc()
                ]

    final_msg.append('Please connect to https://' + fqdn + '/ to access the server.')

    # Check if Mongodb > PostgreSQL migration is necessary
    if not quiet:
        if check_mongo2pgsql_upgrade_needed(options.configfile) and\
                postconf.yesno("It is necessary to migrate current database backend from mongodb to postgres. Press yes to start migration",no_label='cancel') == postconf.DIALOG_OK:
            upgrade2postgres(options.configfile)
    else:
        if check_mongo2pgsql_upgrade_needed(options.configfile):
            upgrade2postgres(options.configfile)

    # Final message
    if not quiet:
        width = 4 + max(10, len(max(final_msg, key=len)))
        height = 2 + max(20, len(final_msg))
        postconf.msgbox('\n'.join(final_msg), height=height, width=width)
    else:
        if wapt_password:
            final_msg.append('[*] WAPT admin password : %s\n' % wapt_password)
        for line in final_msg:
            print(line)


if __name__ == "__main__":
    if not type_debian() and not type_redhat():
        print "unsupported distrib"
        sys.exit(1)
    main()
