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
    convert ../common/waptself-community.png -resize 16x16 %{buildroot}/opt/wapt/icons/waptself-16.png
    convert ../common/waptself-community.png -resize 32x32 %{buildroot}/opt/wapt/icons/waptself-32.png
    convert ../common/waptself-community.png -resize 64x64 %{buildroot}/opt/wapt/icons/waptself-64.png
    convert ../common/waptself-community.png -resize 128x128 %{buildroot}/opt/wapt/icons/waptself-128.png
    convert ../common/waptself-community.png -resize 16x16 %{buildroot}/opt/wapt/icons/waptexit-16.png
    convert ../common/waptself-community.png -resize 32x32 %{buildroot}/opt/wapt/icons/waptexit-32.png
    convert ../common/waptself-community.png -resize 64x64 %{buildroot}/opt/wapt/icons/waptexit-64.png
    convert ../common/waptself-community.png -resize 128x128 %{buildroot}/opt/wapt/icons/waptexit-128.png
else
    convert ../common/waptself-enterprise.png -resize 16x16 %{buildroot}/opt/wapt/icons/waptself-16.png
    convert ../common/waptself-enterprise.png -resize 32x32 %{buildroot}/opt/wapt/icons/waptself-32.png
    convert ../common/waptself-enterprise.png -resize 64x64 %{buildroot}/opt/wapt/icons/waptself-64.png
    convert ../common/waptself-enterprise.png -resize 128x128 %{buildroot}/opt/wapt/icons/waptself-128.png
    convert ../common/waptself-enterprise.png -resize 16x16 %{buildroot}/opt/wapt/icons/waptexit-16.png
    convert ../common/waptself-enterprise.png -resize 32x32 %{buildroot}/opt/wapt/icons/waptexit-32.png
    convert ../common/waptself-enterprise.png -resize 64x64 %{buildroot}/opt/wapt/icons/waptexit-64.png
    convert ../common/waptself-enterprise.png -resize 128x128 %{buildroot}/opt/wapt/icons/waptexit-128.png
fi

%files
%defattr(644,root,root,755)
/opt/wapt/*
/usr/share/applications/*

%post
ln -sf /opt/wapt/waptself.bin /usr/bin/waptself
ln -sf /opt/wapt/waptexit.bin /usr/bin/waptexit

xdg-icon-resource install --size 16  --mode system /opt/wapt/icons/waptself-16.png tis-waptself
xdg-icon-resource install --size 32  --mode system /opt/wapt/icons/waptself-32.png tis-waptself
xdg-icon-resource install --size 64  --mode system /opt/wapt/icons/waptself-64.png tis-waptself
xdg-icon-resource install --size 128  --mode system /opt/wapt/icons/waptself-128.png tis-waptself

xdg-icon-resource install --size 16  --mode system /opt/wapt/icons/waptexit-16.png tis-waptexit
xdg-icon-resource install --size 32  --mode system /opt/wapt/icons/waptexit-32.png tis-waptexit
xdg-icon-resource install --size 64  --mode system /opt/wapt/icons/waptexit-64.png tis-waptexit
xdg-icon-resource install --size 128  --mode system /opt/wapt/icons/waptexit-128.png tis-waptexit

update-desktop-database

%postun
if [ "$1" = 0 ] ; then
    rm -f /usr/bin/waptself /usr/bin/waptexit
    xdg-icon-resource uninstall --size 16  --mode system tis-waptself
    xdg-icon-resource uninstall --size 32  --mode system tis-waptself
    xdg-icon-resource uninstall --size 64  --mode system tis-waptself
    xdg-icon-resource uninstall --size 128  --mode system tis-waptself

    xdg-icon-resource uninstall --size 16  --mode system tis-waptexit
    xdg-icon-resource uninstall --size 32  --mode system tis-waptexit
    xdg-icon-resource uninstall --size 64  --mode system tis-waptexit
    xdg-icon-resource uninstall --size 128  --mode system tis-waptexit

    update-desktop-database
fi