%define _topdir   .
Name:		tis-waptrepo
Version:	1.3.3
Release:	1%{?dist}
Summary:	WAPT Repo
BuildArch:	noarch

Group:	        Development/Tools
License:	GPL
URL:		http://dev.tranquil.it
Source0:	./waptrepo/
Prefix:		/opt

Requires:  httpd dialog pytz m2crypto python-passlib python-requests

%description

%install
cd .. && python createrpm.py

%files
%defattr(-,wapt,apache)
 /opt/wapt/waptrepo/VERSION
 /opt/wapt/waptpackage.py
 /opt/wapt/wapt-scanpackages.py
 /opt/wapt/wapt-scanpackages.pyc
 /opt/wapt/wapt-scanpackages.pyo
 /opt/wapt/waptpackage.pyc
 /opt/wapt/waptpackage.pyo
 /var/www/html/wapt
 /var/www/html/wapt-host
 /var/www/html/wapt-group





%pre
getent passwd wapt >/dev/null || \
    useradd -r -g apache -d /opt/wapt -s /sbin/nologin \
    -c "Non privileged account for waptserver" wapt
exit 0


%post
systemctl enable httpd
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --permanent --add-port=80/tcp
python /opt/wapt/wapt-scanpackages.py /var/www/html/wapt
exit 0
