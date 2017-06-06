%define _topdir   .
%define buildroot ./builddir

Name:		tis-waptsetup
Version:	%{_version}
Release:	1%{?dist}
Summary:	WAPT Setup executables
BuildArch:	noarch
Group:	    Development/Tools
License:	GPL
URL:		https://wapt.fr
Source0:    ./waptsetup/	
Requires:	nginx tis-waptrepo

%description
Convenience package that ships with waptdeploy.exe and waptsetup.exe
programs with the appropriate version for your waptserver.

%install
%{__mkdir_p} %{buildroot}/var/www/html/wapt
cp ../waptsetup-tis.exe %{buildroot}/var/www/html/wapt/
cp ../waptdeploy.exe  %{buildroot}/var/www/html/wapt/

%files
%defattr(644,root,root,755)
/var/www/html/wapt/*
