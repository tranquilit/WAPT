%define _topdir   .
%define buildroot ./builddir
Buildroot:      ./builddir
Name:		tis-waptrepo
Version:	1.2.3
Release:	1%{?dist}
Summary:	WAPT Repo

Group:	        Development/Tools	
License:	GPL
URL:		http://dev.tranquil.it
Source0:	./waptrepo/
Prefix:		/opt

Requires:  httpd dialog pytz m2crypto python-passlib

%description

%install
cd ..
python  ./createrpm.py


%files
%defattr(-,wapt,apache)
 /opt/wapt/waptrepo/VERSION
 /opt/wapt/waptpackage.py
 /opt/wapt/wapt-scanpackages.py
   /opt/wapt/wapt-scanpackages.pyc
   /opt/wapt/wapt-scanpackages.pyo
   /opt/wapt/waptpackage.pyc
   /opt/wapt/waptpackage.pyo




%pre
getent passwd wapt >/dev/null || \
    useradd -r -g apache -d /opt/wapt -s /sbin/nologin \
    -c "Non privileged account for waptserver" wapt
exit 0 


%post
systemctl enable httpd
firewall-cmd --add-port=443/tcp
firewall-cmd --add-port=80/tcp
