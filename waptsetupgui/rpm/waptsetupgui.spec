%define _topdir   .
%define buildroot ./builddir

Name:		tis-waptagent-gui
Version:	%{_version}
Release:	1%{?dist}
Summary:	WAPT Agent executables
BuildArch:	noarch
Group:	    Development/Tools
License:	GPL
URL:		https://wapt.fr	

%description
Convenience package that ships with waptexit and waptself.

%install
%{__mkdir_p} %{buildroot}/opt/wapt
cp ../waptself.bin %{buildroot}/opt/wapt/
cp ../waptexit.bin  %{buildroot}/opt/wapt/

%files
%defattr(644,root,root,755)
/opt/wapt/*

%post
ln -sf /opt/wapt/waptself.bin /usr/bin/waptself
ln -sf /opt/wapt/waptexit.bin /usr/bin/waptexit

%postun
if [ "$1" = 0 ] ; then
	rm -f /usr/bin/waptself /usr/bin/waptexit
fi