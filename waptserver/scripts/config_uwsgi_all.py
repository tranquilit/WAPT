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

from __future__ import print_function
usage = """\
%prog [-c configfile] [-l loglevel] action

Action:
    upgrade2postgres: import data from mongodb (wapt <1.4)
    upgrade_structure : update the table structure to most current one.
    reset_database : empty the db and recreate tables.
    import_data : import json files
"""

import os
import sys
import glob
import uuid as _uuid
import jinja2
import platform
import subprocess
import iniparse


try:
    wapt_root_dir = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            '..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

import site
site.addsitedir(wapt_root_dir)

from waptserver.config import __version__
from waptserver.model import load_db_config,Hosts,HostGroups
from waptserver.utils import *
from waptserver.scripts import nginxparser
import waptserver

from waptcrypto import SSLCertificate,SSLPrivateKey
from waptpackage import PackageEntry,WaptLocalRepo

import logging
import ConfigParser
from optparse import OptionParser

DEFAULT_CONFIG_FILE = os.path.join(r'c:\wapt', 'conf', 'waptserver.ini')
config_file = DEFAULT_CONFIG_FILE

# setup logging
logger = logging.getLogger()
logging.basicConfig()

def serversconfig_list():
    instances = glob.glob('/opt/wapt/conf/*.ini')
    return [ os.path.join('/opt/wapt/conf',i) for i in instances ]

SERVER_UWSGI = """
[uwsgi]
master = true
processes = 5
wsgi=waptserver.server:app
home=/opt/wapt
chdir=/opt/wapt
max-requests=500
socket=/tmp/{{ application_root }}.sock
uid=wapt
gid=www-data
plugins=python
chmod-socket = 664
env = CONFIG_FILE=/opt/wapt/conf/{{ application_root }}.ini
logto = /var/log/uwsgi/{{ application_root }}.log
log-5xx = true
disable-logging = true
"""

NGINX_UPSTREAM = """

# uwsgi upstream {{ application_root }} server
upstream {{ application_root }} {
   server unix:///tmp/{{ application_root }}.sock;
}

"""

NGINX_INSTANCE = """############## {{ application_root }}

location /{{ application_root }} {
    proxy_set_header X-Real-IP  $remote_addr;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    client_max_body_size 4096m;
    client_body_timeout 1800;

    location ~ ^/{{ application_root }}/(wapt/.*|wapt-host/.*|waptwua/.*)$ {
        root "/var/www/odaim/";
    }

    location /{{ application_root }}/static/$ {
        alias "{{ wapt_root_dir}}/waptserver/static/";
    }

    # we don't want this as client could fake the kerberos basic auth header
    location /{{ application_root }}/add_host_kerberos {
        return 403;
    }

    # we prevent from reading this, as it gives info on hosts
    location /{{ application_root }}/wapt-host/Packages {
        return 403;
    }

    # we need socketio for these actions
    #location /{{ application_root }}/(api/v3/trigger_host_action|api/v3/reset_hosts_sid|api/v3/host_tasks_status|api/v3/trigger_cancel_task) {
    location ~ ^/{{ application_root }}/api/v3/(trigger_host_action|reset_hosts_sid|host_tasks_status|trigger_cancel_task)$ {
        # remove the prefix for upstream uwsgi/flask
        rewrite    /{{ application_root }}/(.*) /$1 break;
        proxy_pass http://127.0.0.1:{{ waptserver_port }};
    }

    # we use uwsgi for all other actions
    location /{{ application_root }} {
        include     /opt/wapt/conf/uwsgi_params;
        uwsgi_pass  {{ application_root }};
        uwsgi_param SCRIPT_NAME /{{ application_root }}; # explicitly set SCRIPT_NAME to match subpath
        uwsgi_modifier1 30; # strips SCRIPT_NAME from PATH_INFO (the url passed to Django)
    }


    # for websockets tunnel
    location /{{ application_root }}/socket.io {
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_pass http://127.0.0.1:{{ waptserver_port }}/socket.io;
    }
}
"""

WAPTSERVER_UWSGI_SERVICE = """[Unit]
Description=WAPT Server {{ application_root }} uWSGI startup script
After=syslog.target
After=postgresql.service

[Service]
WorkingDirectory=/opt/wapt
ExecStart=/usr/bin/uwsgi --ini /opt/wapt/conf/{{ application_root }}.ini
RuntimeDirectory=uwsgi
Restart=always
KillSignal=SIGQUIT
Type=notify
StandardError=syslog
NotifyAccess=all
LimitNOFILE=32768

[Install]
WantedBy=multi-user.target
"""

if __name__ == '__main__':
    parser = OptionParser(usage=usage, version=__version__)
    parser.add_option(
        '-c',
        '--config',
        dest='configfile',
        default=DEFAULT_CONFIG_FILE,
        help='Config file full path (default: %default)')

    parser.add_option('-l', '--loglevel', dest='loglevel', default='info', type='choice',
        choices=['debug', 'warning', 'info', 'error', 'critical'],
        metavar='LOGLEVEL', help='Loglevel (default: warning)')

    (options, args) = parser.parse_args()
    setloglevel(logger,options.loglevel)


    for config_filename in serversconfig_list():
        confname = os.path.basename(config_filename).rsplit('.',1)[0]
        if confname.startswith('odaim_'):
            print('Serveur: %s' % config_filename)
            conf = waptserver.config.load_config(config_filename)
            #wapt_db = Proxy()
            #load_db_config(conf)

            application_root = conf['application_root']
            # ajout fichier service
            service_filename = os.path.join('/usr/lib/systemd/system/waptserver-%s-uwsgi.service' % confname)
            with open(service_filename,'w') as service_file:
                service_file.write(jinja2.Template(WAPTSERVER_UWSGI_SERVICE).render(conf))

            # modif fichier config serveur wapt pour inclure  la section uwsgi
            ini = open(config_filename).read()
            if not '[uwsgi]' in ini:
                with open(config_filename,'a') as server_conf:
                    server_conf.write(jinja2.Template(SERVER_UWSGI).render(conf))
            else:
                inifile = iniparse.RawConfigParser()
                inifile.read(config_filename)
                inifile.set('uwsgi','processes','5' )
                inifile.set('uwsgi','max-requests','500' )
                inifile.set('uwsgi','socket','/tmp/%s.sock' % application_root )
                inifile.set('uwsgi','logto','/var/log/uwsgi/%s.log' % application_root)
                inifile.set('uwsgi','log-5xx','true')
                inifile.set('uwsgi','disable-logging','true')
                inifile.write(open(config_filename,'w'))

            # ajout fichier nginx pour upstream uwsgi
            upstream_filename = os.path.join('/opt/wapt/conf/wapt.d','%s.upstream' % application_root)
            with open(upstream_filename,'w') as nginx_file:
                nginx_file.write(jinja2.Template(NGINX_UPSTREAM).render(conf))

            try:
                print(subprocess.check_output('systemctl enable waptserver-%s-uwsgi' % application_root,shell=True))
                print(subprocess.check_output('systemctl restart waptserver-%s-uwsgi' % application_root,shell=True))
            except:
                pass

            # activation nginx
            # modif config nginx
            if not application_root.startswith('odaim_ac_atl'):
                nginx_filename = os.path.join('/opt/wapt/conf/wapt.d',application_root+'.conf')
                with open(nginx_filename,'w') as nginx_file:
                    nginx_file.write(jinja2.Template(NGINX_INSTANCE).render(conf))


