%define _topdir   .
%define buildroot ./builddir

Name:	tis-waptserver
Version:	1.2.3
Release:	1%{?dist}
Summary:	WAPT Server

Group:	        Development/Tools	
License:	GPL
URL:		http://dev.tranquil.it
Source0:	./waptserver/
Prefix:		/opt

Requires:  httpd python-pymongo mongodb-server dialog uwsgi-plugin-python uwsgi pytz m2crypto python-passlib

# Turn off the brp-python-bytecompile script
%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')

%description

%install
mkdir -p %{buildroot}/opt/wapt/waptserver
mkdir -p %{buildroot}/opt/wapt/waptserver/scripts
mkdir -p %{buildroot}/etc/init.d/
#rsync -aP --exclude 'scripts/waptserver-init-centos' --exclude '*.pyc' --exclude '.svn' --exclude 'apache-win32' --exclude 'deb' --exclude 'rpm' --exclude '.git' --exclude '.gitignore' -aP ../../../waptserver/ %{buildroot}/opt/wapt/waptserver
#rsync -aP ../../../waptserver/scripts/waptserver-init-centos %{buildroot}/etc/init.d/waptserver
#rsync -aP ../../../waptserver/scripts/postconf.py %{buildroot}/opt/wapt/waptserver/scripts/

#for libname in  'requests iniparse dns pefile.py rocket pymongo bson flask werkzeug jinja2 itsdangerous.py markupsafe dialog.py babel flask_babel' ; do \
#    rsync ../../../lib/site-packages/${i} lib),'./builddir/opt/wapt/lib/site-packages/')
cd ..
python  ./createrpm.py


%files
%defattr(-,wapt,apache)
   /opt/wapt/waptserver
   /etc/logrotate.d/waptserver
   /opt/wapt/lib/

%defattr(755,root,root)
   /etc/init.d/waptserver
   /opt/wapt/waptserver/scripts/postconf.py



%pre
getent passwd wapt >/dev/null || \
    useradd -r -g apache -d /opt/wapt -s /sbin/nologin \
    -c "Non privileged account for waptserver" wapt
exit 0 


%post
systemctl enable mongod
systemctl enable httpd
chkconfig --add waptserver
firewall-cmd --add-port=443/tcp
firewall-cmd --add-port=80/tcp
mkdir -p /opt/wapt/log
chown wapt:apache /opt/wapt/log
