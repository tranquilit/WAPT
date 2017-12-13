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
__version__ = "1.5.1"

usage = """\
%prog [--use-kerberos] [--force-https]"""

import os,sys
try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),'../..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'


sys.path.insert(0,os.path.join(wapt_root_dir))
sys.path.insert(0,os.path.join(wapt_root_dir,'waptserver'))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib'))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib','site-packages'))

import iniparse
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


def run(*args, **kwargs):
    return subprocess.check_output(*args, shell=True, **kwargs)

def run_verbose(*args, **kwargs):
    output = subprocess.check_output(*args, shell=True, **kwargs)
    print output
    return output

def type_debian():
    return platform.dist()[0].lower() in ('debian','ubuntu')

def type_redhat():
    return platform.dist()[0].lower() in ('redhat','centos','fedora')

if type_debian():
    MONGO_SVC='mongodb'
    APACHE_SVC='apache2'
    wapt_folder = '/var/www/wapt'
    NGINX_GID= grp.getgrnam('www-data').gr_gid

elif type_redhat():
    MONGO_SVC='mongod'
    APACHE_SVC='httpd'
    wapt_folder = '/var/www/html/wapt'
    NGINX_GID= grp.getgrnam('nginx').gr_gid
else:
    print "distrib type unknown"
    sys.exit(1)

postconf = dialog.Dialog(dialog="dialog")

def mkdir(path):
    if not os.path.isdir(path):
        os.makedirs(path)

def make_httpd_config(wapt_folder, waptserver_root_dir, fqdn, use_kerberos,force_https):
    if wapt_folder.endswith('\\') or wapt_folder.endswith('/'):
        wapt_folder = wapt_folder[:-1]

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
        'wapt_repository_path': os.path.dirname(wapt_folder),
        'apache_root_folder': '/not/used',
        'windows': False,
        'debian': type_debian(),
        'redhat': type_redhat(),
        'force_https': force_https,
        'wapt_ssl_key_file': wapt_ssl_key_file,
        'wapt_ssl_cert_file': wapt_ssl_cert_file,
        'fqdn': fqdn,
        'use_kerberos': use_kerberos,
        'KRB5_REALM': krb5_realm
        }

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

        old_apache_key = '/opt/wapt/waptserver/apache/ssl/key.pem'
        old_apache_cert = '/opt/wapt/waptserver/apache/ssl/cert.pem'

        if os.path.isfile(old_apache_cert) and os.path.isfile(old_apache_key):
            shutil.copyfile(old_apache_cert,wapt_ssl_cert_file)
            shutil.copyfile(old_apache_key,wapt_ssl_key_file)

        else:
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
                    '-subj', '/C=FR/ST=Wapt/L=Wapt/O=Wapt/CN=' + fqdn + '/'
                    ], stderr=subprocess.STDOUT)


def ensure_postgresql_db(db_name='wapt',db_owner='wapt',db_password=''):
    """ create postgresql wapt db and user if it does not exists """
    if type_redhat():
        # we have to check what postgres we use between the upstream packages and the software collection ones
        pass
    elif type_debian():
        run('systemctl start postgresql')
        run('systemctl enable postgresql')

    val = run(""" sudo -u postgres psql template1 -c " select usename from pg_catalog.pg_user where usename='wapt';"  """, cwd='/opt/wapt')
    if 'wapt' in val:
        print ("user wapt already exists, skipping creating user  ")
    else:
        print ("we suppose that the db does not exist either (or the installation has been screwed up")
        if db_password.strip()=='':
            run(""" sudo -u postgres psql template1 -c "create user %s ; " """ % (db_owner), cwd='/opt/wapt/')
        else:
            run(""" sudo -u postgres psql template1 -c "create user %s with password '%s'; " """ % (db_owner,db_password), cwd='/opt/wapt/')

    val = ''
    #val = subprocess.check_output(""" sudo -u postgres psql template1 -c "select schema_name from information_schema.schemata where schema_name='wapt'; "  """, shell= True)
    val = run(""" sudo -u postgres psql template1 -c " SELECT datname FROM pg_database WHERE datname='wapt';   " """, cwd='/opt/wapt/')

    if 'wapt' in val:
        print ("db already exists, skipping db creation")
    else:
        print ('creating db wapt')
        run(""" sudo -u postgres psql template1 -c "create database %s with owner=%s encoding='utf-8'; " """ % (db_name,db_owner), cwd='/opt/wapt/')

    # check if hstore (for json) is installed
    val = run(""" sudo -u postgres psql wapt -c "select * from pg_extension where extname='hstore';" """, cwd='/opt/wapt/')
    if 'hstore' in val:
        print ("hstore extension already loading into database, skipping create extension")
    else:
        run("""  sudo -u postgres psql wapt -c "CREATE EXTENSION hstore;" """, cwd='/opt/wapt/')


def enable_nginx():
    run_verbose('systemctl enable nginx')

def restart_nginx():
    run_verbose('systemctl restart nginx')

def enable_waptserver():
    run_verbose('systemctl restart waptserver')

def start_waptserver():
    run_verbose("systemctl restart waptserver")

def setup_firewall():
    if type_redhat():
        output = run('firewall-cmd --list-ports')
        if '443/tcp' in output and '80/tcp' in output:
            print("firewall already configured, skipping firewalld configuration")
            return
        if subprocess.call(['firewall-cmd', '--state'], stdout=open(os.devnull, 'w')) == 0:
            run('firewall-cmd --permanent --add-port=443/tcp')
            run('firewall-cmd --permanent --add-port=80/tcp')
            run('firewall-cmd --reload')
        else:
            run('firewall-offline-cmd --add-port=443/tcp')
            run('firewall-offline-cmd --add-port=80/tcp')

def check_mongo2pgsql_upgrade_needed(waptserver_ini):
    """ return  0 if nothing needed
                1 if upgrade needed
                2 if something is not clear
    """
    mongodb_configured=0
    for proc in psutil.process_iter():
        if proc.name() == 'mongod':
            if postconf.yesno("It is necessary to migrate current database backend from mongodb to postgres. Press yes to start migration",no_label='cancel')== postconf.DIALOG_OK:
                print ("mongodb process running, need to migrate")
                run_verbose("sudo -u wapt /usr/bin/python /opt/wapt/waptserver/waptserver_upgrade.py upgrade2postgres")
                run_verbose("systemctl stop mongodb")
                run_verbose("systemctl disable mongodb")
            else:
                print ("Post configuration aborted")
                sys.exit(1)

def nginx_set_worker_limit(nginx_conf):
    already_set=False
    for entries in nginx_conf:
        if entries[0]=='worker_rlimit_nofile':
            print( "worker_rlimit_nofile already set")
            already_set=True
    if already_set==False:
        nginx_conf.insert(3,['worker_rlimit_nofile', '32768'])
    return nginx_conf

def nginx_clean_default_vhost(nginx_conf):
    for entry in nginx_conf:
        if entry[0]==['http']:
            for subentry in entry[1]:
                if subentry[0]==['server']:
                    print('removing default vhost')
                    entry[1].remove(subentry)
    return nginx_conf

def check_if_deb_installed(package_name):
   child = subprocess.Popen('/usr/bin/dpkg -l "%s"' % package_name, stdout=subprocess.PIPE,shell=True)
   streamdata = child.communicate()[0]
   rc = child.returncode
   if rc==0:
       return True
   return False

def main():
    global wapt_folder,MONGO_SVC,APACHE_SVC, NGINX_GID


    parser = OptionParser(usage=usage, version='waptserver.py ' + __version__)
    parser.add_option(
        "-k",
        "--use-kerberos",
        dest="use_kerberos",
        default=False,
        action='store_true',
        help="Use kerberos for host registration (default: False)")
    parser.add_option(
        "-s",
        "--force-https",
        dest="force_https",
        default=False,
        action='store_true',
        help="Use https only, http is 301 redirected to https (default: False). Requires a proper DNS name")

    (options, args) = parser.parse_args()

    if postconf.yesno("Do you want to launch post configuration tool ?") != postconf.DIALOG_OK:
        print "canceling wapt postconfiguration"
        sys.exit(1)


    # TODO : check if it a new install or an upgrade (upgrade from mongodb to postgresql)

    if type_redhat():
        if re.match('^SELinux status:.*enabled', run('sestatus')):
            postconf.msgbox('SELinux detected, tweaking httpd permissions.')
            run('setsebool -P httpd_can_network_connect 1')
            run('setsebool -P httpd_setrlimit on')
            for sepath in ('wapt','wapt-host','wapt-hostref'):
                run('semanage fcontext -a -t httpd_sys_content_t "/var/www/html/%s(/.*)?"' %sepath)
                run('restorecon -R -v /var/www/html/%s' %sepath)
            postconf.msgbox('SELinux correctly configured for Nginx reverse proxy')

    if not os.path.isfile('/opt/wapt/conf/waptserver.ini'):
        shutil.copyfile('/opt/wapt/waptserver/waptserver.ini.template','/opt/wapt/conf/waptserver.ini')
    else:
        print('making a backup copy of the configuration file')
        datetime_now = datetime.datetime.now()
        shutil.copyfile('/opt/wapt/conf/waptserver.ini','/opt/wapt/conf/waptserver.ini.bck_%s'%  datetime_now.isoformat() )

    waptserver_ini = iniparse.RawConfigParser()

    waptserver_ini.readfp(file('/opt/wapt/conf/waptserver.ini', 'rU'))

    if waptserver_ini.has_option('options', 'wapt_folder'):
        wapt_folder = waptserver_ini.get('options', 'wapt_folder') 

    if waptserver_ini.has_section('uwsgi'):
        print ('Remove uwsgi options, not used anymore')
        waptserver_ini.remove_section('uwsgi')

    # add secret key initialisation string (for session token)
    if not waptserver_ini.has_option('options','secret_key'):
        waptserver_ini.set('options','secret_key',''.join(random.SystemRandom().choice(string.letters + string.digits) for _ in range(64)))

    # add user db and password in ini file
    ensure_postgresql_db()
    print ("create database schema")
    run(" sudo -u wapt python /opt/wapt/waptserver/waptserver_model.py init_db ")

    mongo_update_status = check_mongo2pgsql_upgrade_needed(waptserver_ini)
    if mongo_update_status==0:
        print ("already running postgresql, trying to upgrade structure")
        run("sudo -u wapt python /opt/wapt/waptserver/waptserver_upgrade.py upgrade_structure")
    elif mongo_update_status==1:
        print ("need to upgrade from mongodb to postgres, please launch python /opt/wapt/waptserver/waptserver_upgrade.py upgrade2postgres")
        sys.exit(1)
    elif mongo_update_status==2:
        print ("something not normal please check your installation first")
        sys.exit(1)

    if os.path.isdir(wapt_folder):
        waptserver_ini.set('options','wapt_folder',wapt_folder)
    else:
        # for install on windows
        # keep in sync with waptserver.py
        wapt_folder = os.path.join(wapt_root_dir,'waptserver','repository','wapt')

    # Password setup/reset screen
    if not waptserver_ini.has_option('options', 'wapt_password') or \
            not waptserver_ini.get('options', 'wapt_password') or \
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
        waptserver_ini.set('options','wapt_password',password)

    if not waptserver_ini.has_option('options', 'server_uuid'):
        waptserver_ini.set('options', 'server_uuid', str(uuid.uuid1()))

    if options.use_kerberos:
        waptserver_ini.set('options','use_kerberos','True')
    else:
        waptserver_ini.set('options','use_kerberos','False')

    # waptagent authentication method
    choices = [
            ("1","Allow unauthenticated registration, same behavior as wapt 1.3", True),
            ("2","Enable kerberos authentication required for machines registration. Registration will ask for password if kerberos not working",        False),
            ("3","Disable Kerberos but registration require strong authentication",        False),
            ]

    code, t = postconf.radiolist("WaptAgent Authentication type?", choices=choices,width=120)
    if code=='cancel':
        print("\n\npostconfiguration canceled\n\n")
        sys.exit(1)
    if t=="1":
        waptserver_ini.set('options','allow_unauthenticated_registration','True')
    if t=="3":
        waptserver_ini.set('options','allow_unauthenticated_registration','False')
        waptserver_ini.set('options','use_kerberos','False')
    if t=="2":
        waptserver_ini.set('options','allow_unauthenticated_registration','False')
        waptserver_ini.set('options','use_kerberos','True')



    with open('/opt/wapt/conf/waptserver.ini','w') as inifile:
       waptserver_ini.write(inifile)
    run("/bin/chmod 640 /opt/wapt/conf/waptserver.ini")
    run("/bin/chown wapt /opt/wapt/conf/waptserver.ini")

    # Restart Apache screen
    run('python /opt/wapt/wapt-scanpackages.py %s ' % wapt_folder)

    final_msg = ['Postconfiguration completed.',]
    postconf.msgbox("Press ok to start waptserver")
    enable_waptserver()
    start_waptserver()

    # In this new version Apache is replaced with Nginx? Proceed to disable Apache. After migration one can remove Apache install altogether
    try:
        run_verbose('systemctl stop %s' % APACHE_SVC)
    except:
        pass
    try:
        run_verbose('systemctl disable %s' % APACHE_SVC)
    except:
        pass

    # nginx configuration dialog
    reply = postconf.yesno("Do you want to configure nginx?")
    if reply == postconf.DIALOG_OK:
        try:
            fqdn = socket.getfqdn()
            if not fqdn:
                fqdn = 'wapt'
            if '.' not in fqdn:
                fqdn += '.lan'
            msg = 'FQDN for the WAPT server (eg. wapt.acme.com)'
            (code, reply) = postconf.inputbox(text=msg, width=len(msg)+4, init=fqdn)
            if code != postconf.DIALOG_OK:
                exit(1)
            else:
                fqdn = reply

            dh_filename = '/etc/ssl/certs/dhparam.pem'
            if not os.path.exists(dh_filename):
                run_verbose('openssl dhparam -out %s  2048' % dh_filename)

            os.chown(dh_filename, 0, NGINX_GID)
            os.chmod(dh_filename, 0o640)

            # cleanup of nginx.conf file
            with open('/etc/nginx/nginx.conf','r') as read_conf:
                nginx_conf = nginxparser.load(read_conf)
            nginx_conf = nginx_set_worker_limit(nginx_conf)
            nginx_conf = nginx_clean_default_vhost(nginx_conf)
            with open("/etc/nginx/nginx.conf", "w") as nginx_conf_file:
                nginx_conf_file.write(nginxparser.dumps(nginx_conf))

            if options.use_kerberos:
                if type_debian():
                    if not check_if_deb_installed('libnginx-mod-http-auth-spnego'):
                        print('missing dependency libnginx-mod-http-auth-spnego, please install first before configuring kerberos')
                        sys.exit(1)
                elif type_redhat():
                    import yum
                    yb = yum.YumBase()
                    yb.conf.cache = os.geteuid() != 1
                    pkgs = yb.rpmdb.returnPackages()
                    found = False
                    for pkg in  pkgs:
                        if pkg.name=='nginx-mod-http-auth-spnego':
                            found = True
                    if found==False:
                        print('missing dependency nginx-mod-http-auth-spnego, please install first before configuring kerberos')
                        sys.exit(1)


            make_httpd_config(wapt_folder, '/opt/wapt/waptserver', fqdn, options.use_kerberos, options.force_https)

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

    width = 4 + max(10, len(max(final_msg, key=len)))
    height = 2 + max(20, len(final_msg))
    postconf.msgbox('\n'.join(final_msg), height=height, width=width)


if __name__ == "__main__":

    if not type_debian() and not type_redhat():
        print "unsupported distrib"
        sys.exit(1)

    main()
