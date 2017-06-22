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

Requires:  nginx dialog pytz python

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
/opt/wapt/lib/*
/var/www/html/wapt
/var/www/html/waptwua
/var/www/html/wapt-host
/var/www/html/wapt-group

%attr(755,wapt,nginx)/var/www/html/wapt/
%attr(755,wapt,nginx)/var/www/html/waptdev/
%attr(755,wapt,nginx)/var/www/html/wapt-group/
%attr(755,wapt,nginx)/var/www/html/wapt-host/
%attr(755,wapt,nginx)/var/www/html/waptwua/
%attr(755,root,root)/opt/wapt/wapt-scanpackages.py
%attr(755,root,root)/opt/wapt/wapt-signpackages.py

%pre
getent passwd wapt >/dev/null || \
    useradd -r -g nginx -d /opt/wapt -s /sbin/nologin \
    -c "Non privileged account for waptserver" wapt
exit 0

%post
ln -sf /opt/wapt/wapt-scanpackages.py /usr/bin/wapt-scanpackages
ln -sf /opt/wapt/wapt-signpackages.py /usr/bin/wapt-signpackages
python /opt/wapt/wapt-scanpackages.py /var/www/html/wapt
chown -R wapt:nginx /var/www/html/*

exit 0
