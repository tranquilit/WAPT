%define _topdir   .
%define buildroot ./builddir

Name:	tis-waptserver
Version:	1.3.3
Release:	1%{?dist}
Summary:	WAPT Server
BuildArch:	noarch

Group:	        Development/Tools
License:	GPL
URL:		http://dev.tranquil.it
Source0:	./waptserver/
Prefix:		/opt

Requires:  httpd mod_ssl python-pymongo mongodb-server dialog uwsgi-plugin-python uwsgi pytz m2crypto python-passlib python-netifaces python-urllib3 cabextract python-requests python-flask

# Turn off the brp-python-bytecompile script
%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')

%description

%install
set -ex

mkdir -p %{buildroot}/opt/wapt
mkdir -p %{buildroot}/opt/wapt/log
mkdir -p %{buildroot}/opt/wapt/conf

mkdir -p %{buildroot}/opt/wapt/waptserver
mkdir -p %{buildroot}/opt/wapt/waptserver/scripts
ln -sf ../conf/waptserver.ini %{buildroot}/opt/wapt/waptserver/waptserver.ini

mkdir -p %{buildroot}/etc/init.d/

#rsync -aP --exclude 'scripts/waptserver-init-centos' --exclude '*.pyc' --exclude '.svn' --exclude 'apache-win32' --exclude 'deb' --exclude 'rpm' --exclude '.git' --exclude '.gitignore' -aP ../../../waptserver/ %{buildroot}/opt/wapt/waptserver
#rsync -aP ../../../waptserver/scripts/waptserver-init-centos %{buildroot}/etc/init.d/waptserver
#rsync -aP ../../../waptserver/scripts/postconf.py %{buildroot}/opt/wapt/waptserver/scripts/

#for libname in  'requests iniparse dns pefile.py rocket pymongo bson flask werkzeug jinja2 itsdangerous.py markupsafe dialog.py babel flask_babel' ; do \
#    rsync ../../../lib/site-packages/${i} lib),'./builddir/opt/wapt/lib/site-packages/')

(cd .. && python ./createrpm.py)

%files
%defattr(644,root,root,755)

/opt/wapt
/opt/wapt/lib/*
/etc/logrotate.d/waptserver

%attr(755,root,root)/etc/init.d/waptserver
%attr(755,root,root)/opt/wapt/waptserver/scripts/postconf.py

%attr(755,wapt,root)/opt/wapt/conf
%attr(755,wapt,root)/opt/wapt/log

%pre
getent passwd wapt >/dev/null || \
    useradd -r -g apache -d /opt/wapt -s /sbin/nologin \
    -c "Non privileged account for waptserver" wapt
exit 0


%post
set -x

systemctl enable mongod
systemctl enable httpd

chkconfig --add waptserver

firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --reload

old_ini='/opt/wapt/waptserver/waptserver.ini'
new_ini='/opt/wapt/conf/waptserver.ini'
if [ -e "$old_ini" ] && ! [ -L "$old_ini" ]; then
    if mv -n "$old_ini" "$new_ini"; then
	ln -s "$new_ini" "$old_ini"
    fi
fi
