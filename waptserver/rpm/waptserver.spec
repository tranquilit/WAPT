%define _topdir   .
%define buildroot ./builddir

Name:	tis-waptserver
Version:	%{_version}
Release:	1%{?dist}
Summary:	WAPT Server
BuildArch:	x86_64

Group:	        Development/Tools
License:	GPL
URL:		https://wapt.fr
Source0:	./waptserver/
Prefix:		/opt

Requires:  nginx dialog pytz cabextract python-psutil python2-dialog msktutil krb5-workstation

# Turn off the brp-python-bytecompile script
%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')
# to be cleanedup
%global __provides_exclude_from /
%global __requires_exclude_from /

%description

%install
set -ex

mkdir -p %{buildroot}/opt/wapt
mkdir -p %{buildroot}/opt/wapt/log
mkdir -p %{buildroot}/opt/wapt/conf

mkdir -p %{buildroot}/opt/wapt/waptserver
mkdir -p %{buildroot}/opt/wapt/waptserver/scripts
ln -sf ../conf/waptserver.ini %{buildroot}/opt/wapt/waptserver/waptserver.ini

mkdir -p %{buildroot}/usr/lib/systemd/

(cd .. && python ./createrpm.py)

%files
%defattr(644,root,root,755)
/usr/lib/systemd/system/waptserver.service
/opt/wapt/waptserver/*
/opt/wapt/lib/*
/etc/logrotate.d/waptserver
/etc/rsyslog.d/waptserver.conf
/etc/systemd/system/nginx.service.d/nginx_worker_files_limit.conf
/opt/wapt/lib/site-packages/cryptography/x509/
/opt/wapt/wapt*.py
/opt/wapt/custom_zip.py
/usr/bin/wapt-serverpostconf

%attr(755,root,root)/opt/wapt/waptserver/scripts/postconf.py
%attr(755,root,root)/opt/wapt/wapt-scanpackages.py
%attr(755,root,root)/opt/wapt/wapt-signpackages.py
%attr(755,wapt,root)/opt/wapt/conf
%attr(755,wapt,root)/opt/wapt/log

%pre
getent passwd wapt >/dev/null || \
    useradd -r -g apache -d /opt/wapt -s /sbin/nologin \
    -c "Non privileged account for waptserver" wapt
exit 0

%post
old_ini='/opt/wapt/waptserver/waptserver.ini'
new_ini='/opt/wapt/conf/waptserver.ini'
if [ -e "$old_ini" ] && ! [ -L "$old_ini" ]; then
    if mv -n "$old_ini" "$new_ini"; then
	ln -s "$new_ini" "$old_ini"
    fi
fi
# Allow nginx to set higher limit for number of file handles
[ -f $(which setsebool) ] && setsebool -P httpd_setrlimit on
systemctl daemon-reload
