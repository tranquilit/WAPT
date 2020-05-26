%define _topdir   .
%define buildroot ./builddir

Name:		tis-waptsetup-linux-mac
Version:	%{_version}
Release:	1%{?dist}
Summary:	WAPT Setup executables
BuildArch:	noarch
Group:	    Development/Tools
License:	GPL
URL:		https://wapt.fr	
Requires:	nginx

%description
Convenience package that ships with linux/mac agents
programs with the appropriate version for your waptserver.

%install
%{__mkdir_p} %{buildroot}/var/www/html/wapt
cp ../waptagent_debian8.deb %{buildroot}/var/www/html/wapt/
cp ../waptagent_debian9.deb %{buildroot}/var/www/html/wapt/
cp ../waptagent_debian10.deb  %{buildroot}/var/www/html/wapt/
cp ../waptagent_ubuntu18.deb  %{buildroot}/var/www/html/wapt/
cp ../waptagent_ubuntu20.deb %{buildroot}/var/www/html/wapt/
cp ../waptagent7.rpm  %{buildroot}/var/www/html/wapt/
cp ../waptagent8.rpm %{buildroot}/var/www/html/wapt/
cp ../waptagent.pkg  %{buildroot}/var/www/html/wapt/

%files
%defattr(644,root,root,755)
/var/www/html/wapt/*
