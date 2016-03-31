%define _topdir   .
Name:		tis-waptrepo
Version:	1.3.6
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

%defattr(644,root,root,755)

/opt/wapt/waptrepo/VERSION
/opt/wapt/waptpackage.py
/opt/wapt/wapt-scanpackages.pyc
/opt/wapt/wapt-scanpackages.pyo
/opt/wapt/waptpackage.pyc
/opt/wapt/waptpackage.pyo
/var/www/html/wapt
/var/www/html/wapt-host
/var/www/html/wapt-group

%attr(755,wapt,apache)/var/www/html/wapt/
%attr(755,wapt,apache)/var/www/html/waptdev/
%attr(755,wapt,apache)/var/www/html/wapt-group/
%attr(755,wapt,apache)/var/www/html/wapt-host/
%attr(755,root,root)/opt/wapt/wapt-scanpackages.py

%pre
getent passwd wapt >/dev/null || \
    useradd -r -g apache -d /opt/wapt -s /sbin/nologin \
    -c "Non privileged account for waptserver" wapt
exit 0

%post
ln -sf /opt/wapt/wapt-scanpackages.py /usr/bin/wapt-scanpackages
python /opt/wapt/wapt-scanpackages.py /var/www/html/wapt
exit 0
