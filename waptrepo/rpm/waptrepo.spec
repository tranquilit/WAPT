%define _topdir   .
Name:		tis-waptrepo
Version:	%{_version}
Release:	1%{?dist}
Summary:	WAPT Repo
BuildArch:	x86_64

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
set -e

mkdir -p %{buildroot}/opt/wapt
mkdir -p %{buildroot}/opt/wapt/bin
mkdir -p %{buildroot}/opt/wapt/lib
mkdir -p %{buildroot}/opt/wapt/log
mkdir -p %{buildroot}/opt/wapt/conf
(cd .. && python ./createrpm.py)

%files
%defattr(644,root,root,755)
/opt/wapt/waptpackage.py
/opt/wapt/waptcrypto.py
/opt/wapt/waptutils.py
/opt/wapt/custom_zip.py
/usr/bin/wapt-scanpackages
/usr/bin/wapt-signpackages
/usr/bin/waptpython
/opt/wapt/bin/*
/opt/wapt/lib/*

%attr(755,root,root)/opt/wapt/wapt-scanpackages.py
%attr(755,root,root)/opt/wapt/wapt-signpackages.py
%attr(755,root,root)/usr/bin/wapt-scanpackages
%attr(755,root,root)/usr/bin/wapt-signpackages
%attr(755,root,root)/usr/bin/waptpython
%attr(755,wapt,root)/opt/wapt/conf
%attr(755,wapt,root)/opt/wapt/log
%attr(750,root,nginx)/opt/wapt/waptserver/ssl/

%pre
getent passwd wapt >/dev/null || \
    useradd -r -g nginx -d /opt/wapt -s /sbin/nologin \
    -c "Non privileged account for waptserver" wapt
exit 0

%post
mkdir -p /var/www/html/wapt
mkdir -p /var/www/html/wapt-host
mkdir -p /var/www/html/wapt-hostref
chown -R wapt:nginx /var/www/html/*
echo "User-agent:*\nDisallow: /\n" > /var/www/html/robots.txt

# fix python in wapt virtual env and set PATH
ln -sb /usr/bin/python2 /opt/wapt/bin/python2
cat << EOF > /opt/wapt/.profile
# for python virtualenv
export PYTHONHOME=/opt/wapt
export PYTHONPATH=/opt/wapt
export PATH=/opt/wapt/bin:$PATH
EOF
### end