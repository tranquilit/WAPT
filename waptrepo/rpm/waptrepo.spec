%define _topdir   .
Name:		tis-waptrepo
Version:	%{_version}
Release:	1%{?dist}
Summary:	WAPT Repo
BuildArch:	noarch

Group:	        Development/Tools
License:	GPL
URL:		http://dev.tranquil.it
Source0:	./waptrepo/
Prefix:		/opt

Requires:  httpd dialog pytz m2crypto python-passlib python-requests

# Turn off the brp-python-bytecompile script
%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')

%description

%install
cd .. && python createrpm.py

%files

%defattr(644,root,root,755)

/opt/wapt/waptrepo/VERSION
/opt/wapt/waptcrypto.py
/opt/wapt/waptutils.py
/opt/wapt/waptpackage.py
/opt/wapt/custom_zip.py
/var/www/html/wapt
/var/www/html/waptwua
/var/www/html/wapt-host
/var/www/html/wapt-group

%attr(755,wapt,apache)/var/www/html/wapt/
%attr(755,wapt,apache)/var/www/html/waptdev/
%attr(755,wapt,apache)/var/www/html/wapt-group/
%attr(755,wapt,apache)/var/www/html/wapt-host/
%attr(755,wapt,apache)/var/www/html/waptwua/
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
