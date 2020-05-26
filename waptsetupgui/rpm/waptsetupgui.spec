%define _topdir   .
%define buildroot ./builddir

Name:		tis-waptagent-gui
Version:	%{_version}
Release:	1%{?dist}
Summary:	WAPT Agent executables
BuildArch:	x86_64
Group:	    Development/Tools
License:	GPL
URL:		https://wapt.fr	

%description
Convenience package that ships with waptexit and waptself.

%install
%{__mkdir_p} %{buildroot}/opt/wapt
%{__mkdir_p} %{buildroot}/usr/share/applications
%{__mkdir_p} %{buildroot}/opt/wapt/icons
cp ../waptself.bin %{buildroot}/opt/wapt/
cp ../waptexit.bin  %{buildroot}/opt/wapt/
cp ../../common/waptself.desktop %{buildroot}/usr/share/applications
cp ../../common/waptexit.desktop %{buildroot}/usr/share/applications
if [ `echo $WAPTEDITION | awk '{print tolower($0)}'` = "enterprise" ]
then
	cp ../../common/waptself-enterprise.ico %{buildroot}/opt/wapt/icons/waptself.ico
	cp ../../common/wapt-enterprise.ico %{buildroot}/opt/wapt/icons/waptexit.ico
else
	cp ../../common/waptself-community.ico %{buildroot}/opt/wapt/icons/waptself.ico
	cp ../../common/wapt-community.ico %{buildroot}/opt/wapt/icons/waptexit.ico
fi

%files
%defattr(644,root,root,755)
/opt/wapt/*
/usr/share/applications/*

%post
ln -sf /opt/wapt/waptself.bin /usr/bin/waptself
ln -sf /opt/wapt/waptexit.bin /usr/bin/waptexit
update-desktop-database

%postun
if [ "$1" = 0 ] ; then
	rm -f /usr/bin/waptself /usr/bin/waptexit
	update-desktop-database
fi