# -*- coding: UTF-8 -*-
#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      htouvet
#
# Created:     24/11/2017
# Copyright:   (c) htouvet 2017
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import sys
import os

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


import glob
import iniparse
import codecs
from jinja2 import Template
import subprocess
import random
import string
import uuid
from passlib.hash import pbkdf2_sha256


systemd_template = r"""
[Unit]
Description=WAPT Server startup script {{application_root}}
After=syslog.target
After=postgresql-9.4.service

[Service]
Type=simple
PIDFile=/var/run/waptserver.pid
User=wapt
ExecStart=/usr/bin/python2 /opt/wapt/waptserver/waptserver.py -c /opt/wapt/conf/{{application_root}}.ini
Restart=on-abort
LimitNOFILE=32768

[Install]
WantedBy=multi-user.target
"""

nginx_template = r"""
server {
    listen                      80;

    listen                      443 ssl;
    server_name                 _;

    ssl_certificate             "/opt/wapt/waptserver/ssl/cert.pem";
    ssl_certificate_key         "/opt/wapt/waptserver/ssl/key.pem";
    ssl_protocols               TLSv1.2;
    ssl_dhparam                 /etc/ssl/certs/dhparam.pem;
    ssl_prefer_server_ciphers   on;
    ssl_ciphers                 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
    ssl_stapling                on;
    ssl_stapling_verify         on;
    ssl_session_cache           none;
    ssl_session_tickets         off;

    location / {
        proxy_set_header X-Real-IP  $remote_addr;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        location ~ ^/odaim_(.*)/wapt-host/Packages$ {
            return 401;
            break;
        }

        include /opt/wapt/conf/wapt.d/*.conf;
    }
}
"""

instance_template = r"""
############## {{application_root}}
location ~ ^/{{application_root}}/(wapt|wapt-host)/(.*)$ {
    proxy_set_header Cache-Control "store, no-cache, must-revalidate, post-check=0, pre-check=0";
    proxy_set_header Pragma "no-cache";
    proxy_set_header Expires "Sun, 19 Nov 1978 05:00:00 GMT";

    if ( $http_user_agent ~ "^wapt/1\.4.*" ) {
      rewrite ^/{{application_root}}/(.*)$ /sha1/{{application_root}}/$1/$2 break;
    }
    rewrite ^/{{application_root}}/(wapt|wapt-host)/(.*)$ /odaim/{{application_root}}/$1/$2 break;
    root /var/www;
}

location /{{application_root}}/ {
    proxy_set_header X-Real-IP  $remote_addr;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    proxy_pass http://127.0.0.1:{{waptserver_port}}/;
    client_max_body_size 4096m;
    client_body_timeout 1800;
}

location /{{application_root}}/socket.io {
    proxy_http_version 1.1;
    proxy_buffering off;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "Upgrade";
    proxy_pass http://127.0.0.1:{{waptserver_port}}/socket.io;
}
"""

waptserver_template = r"""
[options]
wapt_folder=/var/www/odaim/{{application_root}}/wapt

wapt_user=admin
wapt_password={{wapt_password}}
server_uuid = {{server_uuid}}
secret_key = {{secret_key}}

#client_tasks_timeout=3

use_kerberos = False
allow_unauthenticated_registration = True

application_root={{application_root}}

db_user={{application_root}}
db_password={{application_root}}
db_name={{application_root}}
db_host=127.0.0.1

waptserver_port={{waptserver_port}}

"""

if __name__ == '__main__':
    lst = ['odaim_dreal_bfc', 'odaim_deal_guyane', 'odaim_dreal_normandie', 'odaim_recette',
        'odaim_sg_cp2i_donc', 'odaim_commun', 'odaim_dreal_occitanie',
        'odaim_ac_atl', 'odaim_dir_nord', 'odaim_dtam_975']

    sport = 8080
    ports = []

    for instance in lst:
        ini_fn = '/opt/wapt/conf/%s.ini' % instance

        ini = iniparse.RawConfigParser()
        if os.path.isfile(ini_fn):
            ini.read(ini_fn)
            waptserver_port = ini.get('options','waptserver_port','%s' % sport)
            application_root = ini.get('options','application_root',instance)
            del ini
        else:
            while sport in ports:
                sport +=1
            ports.append(sport)

            application_root=instance
            secret_key=''.join(random.SystemRandom().choice(string.letters + string.digits) for _ in range(64))
            server_uuid=str(uuid.uuid1())
            wapt_password=pbkdf2_sha256.hash('password'.encode('utf8'))
            waptserver_config = Template(waptserver_template).render(**locals())
            open(ini_fn,'wb').write(waptserver_config)

        nginx_fn = '/opt/wapt/conf/wapt.d/%s.conf' % application_root
        if not os.path.isdir('/opt/wapt/conf/wapt.d'):
            os.makedirs('/opt/wapt/conf/wapt.d')
        conf = Template(instance_template).render(**locals())
        codecs.open(nginx_fn,'wb',encoding='utf8').write(conf)

        nginx_fn = '/etc/nginx/sites-available/wapt.conf'
        nginx_conf = Template(nginx_template).render(**locals())
        codecs.open(nginx_fn,'wb',encoding='utf8').write(nginx_conf)

        systemd_fn = '/usr/lib/systemd/system/waptserver-%s.service' % application_root
        if not os.path.isdir('/usr/lib/systemd/system'):
            os.makedirs('/usr/lib/systemd/system')
        systemd_conf = Template(systemd_template).render(**locals())
        open(systemd_fn,'wb').write(systemd_conf)

    subprocess.check_call('systemctl reload nginx',shell=True)

    for application_root in lst:
        subprocess.check_call('systemctl enable %s' % 'waptserver-'+application_root,shell=True)
        subprocess.check_call('systemctl start %s' % 'waptserver-'+application_root,shell=True)

