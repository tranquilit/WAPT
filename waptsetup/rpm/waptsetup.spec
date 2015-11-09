Name:		tis-waptsetup
Version:	1.3.3
Release:	1%{?dist}
Summary:	WAPT Setup executables
BuildArch:	noarch

Group:	        Development/Tools
License:	GPL
URL:		http://dev.tranquil.it
Source0:	waptsetup-tis.exe
Source1:        waptdeploy.exe

Requires:	httpd tis-waptrepo

%description
Convenience package that ships with waptdeploy.exe and waptsetup.exe
programs with the appropriate version for your waptserver.

%install
%{__mkdir_p} %{buildroot}/var/www/html/wapt
%{__install} -m0755 %{SOURCE0} %{buildroot}/var/www/html/wapt/
%{__install} -m0755 %{SOURCE1} %{buildroot}/var/www/html/wapt/

%files
/var/www/html/wapt/*
