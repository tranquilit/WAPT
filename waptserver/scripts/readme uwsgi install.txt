Installation serveur Wapt avec service uWsgi séparé multithread

# Installer tis-waptserver build >= 6150

apt-get install uwsgi uwsgi-plugin-python


# configuration ini pour uwsgi :

vi /opt/wapt/conf/waptserver.ini

# ajouter au début : 

---

[uwsgi]
master = true
processes = 10
wsgi=waptserver.server:app
home=/opt/wapt
chdir=/opt/wapt
max-requests=1000
socket=/var/run/waptserver/waptserver.sock
uid=wapt
gid=www-data
plugins=python
chmod-socket = 664
env = CONFIG_FILE=/opt/wapt/conf/waptserver.ini

---

# emplacement socket unix avec droits corrects pour process uwsgi 
mkdir -p /var/run/waptserver
chmod 775 /var/run/waptserver
chown wapt:www-data /var/run/waptserver


# test uwsgi : 

uwsgi --ini /opt/wapt/conf/waptserver.ini

#



# fichier conf variable ennvironnement nginx -> uwsgi 

cat > /opt/wapt/conf/uwsgi_params <<EOF
uwsgi_param  QUERY_STRING       \$query_string;
uwsgi_param  REQUEST_METHOD     \$request_method;
uwsgi_param  CONTENT_TYPE       \$content_type;
uwsgi_param  CONTENT_LENGTH     \$content_length;

uwsgi_param  REQUEST_URI        \$request_uri;
uwsgi_param  PATH_INFO          \$document_uri;
uwsgi_param  DOCUMENT_ROOT      \$document_root;
uwsgi_param  SERVER_PROTOCOL    \$server_protocol;
uwsgi_param  REQUEST_SCHEME     \$scheme;
uwsgi_param  HTTPS              \$https if_not_empty;

uwsgi_param  REMOTE_ADDR        \$remote_addr;
uwsgi_param  REMOTE_PORT        \$remote_port;
uwsgi_param  SERVER_PORT        \$server_port;
uwsgi_param  SERVER_NAME        \$server_name;
EOF

# modif config nginx pour séparer les flux 

vi /etc/nginx/sites-enabled/wapt.conf

---

# uwsgi upstream server
upstream waptserver {
   server unix:///var/run/waptserver/waptserver.sock;
}

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


    #ssl_client_certificate "/opt/wapt/conf/ca-srvwapt.demo.lan.crt";
    #ssl_verify_client optional;


    gzip_min_length     1000;
    gzip_buffers        4 8k;
    gzip_http_version   1.0;
    gzip_disable        "msie6";
    gzip_types          text/plain text/css application/json;
    gzip_vary           on;

    index index.html;


    location / {
        proxy_set_header X-Real-IP  $remote_addr;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        client_max_body_size 4096m;
        client_body_timeout 1800;

        location /static {
            alias "/opt/wapt/waptserver/static";
        }

        location ~ ^/(wapt/waptsetup-tis.exe|wapt/waptagent.exe|wapt/waptdeploy.exe)$ {
            root "/var/www";
        }

        location ~ ^/(wapt/.*|wapt-host/.*|waptwua/.*)$ {
            root "/var/www";
        }

        location / {
            proxy_set_header X-Real-IP  $remote_addr;
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            client_max_body_size 4096m;
            client_body_timeout 1800;

            location /add_host_kerberos {
                return 403;
            }

            # we prevent from reading this, as it gives info on 
            location /wapt-host/Packages {
                    return 403;
            }

            # we need socketio for that
            location ~ ^/api/v3/(trigger_host_action|reset_hosts_sid|host_tasks_status|trigger_cancel_task)$ {
                proxy_pass http://127.0.0.1:8080;
            }

            # use wsgi waptserver instance
            location / {
                include     /opt/wapt/conf/uwsgi_params;
                uwsgi_pass  waptserver;
            }

			# for websockets
            location /socket.io {
                proxy_http_version 1.1;
                proxy_buffering off;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection "Upgrade";
                proxy_pass http://127.0.0.1:8080/socket.io;
            }
        }
    }
}


---


# fichier systemd pour uwsgi

vi /usr/lib/systemd/system/waptserver-uwsgi.service

---

[Unit]
Description=WAPT Server uWSGI startup script
After=syslog.target
After=postgresql.service

[Service]
WorkingDirectory=/opt/wapt
ExecStart=/usr/bin/uwsgi --ini /opt/wapt/conf/waptserver.ini
RuntimeDirectory=uwsgi
Restart=always
KillSignal=SIGQUIT
Type=notify
StandardError=syslog
NotifyAccess=all
LimitNOFILE=32768

[Install]
WantedBy=multi-user.target

---

* systemctl enable systemctl restart waptserver-uwsgi

* systemctl restart waptserver

* systemctl status waptserver-uwsgi

* systemctl restart nginx

* systemctl status nginx



