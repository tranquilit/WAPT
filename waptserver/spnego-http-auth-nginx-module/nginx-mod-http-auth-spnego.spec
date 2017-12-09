%define _topdir   .
%define buildroot ./builddir

Name:	    nginx-mod-http-auth-spnego
Version:	1.12.2
Release:	tis1.1.0
Summary:	WAPT Server
BuildArch:	x86_64

Group:	    Development/Tools
License:	GPL
URL:		https://wapt.fr
Source0:	./waptserver/
Prefix:		/usr

Requires:  nginx krb5-workstation

# to be cleanedup
%global __provides_exclude_from /
%global __requires_exclude_from /

%description

%install
set -ex

mkdir -p %{buildroot}/usr/lib64/nginx/modules/
mkdir -p %{buildroot}/usr/share/nginx/modules/

(cd .. && bash ./createrpm.sh)

%files
%defattr(644,root,root,755)
/usr/share/nginx/modules/mod-http_auth_spnego.conf
/usr/lib64/nginx/modules/ngx_http_auth_spnego_module.so

%pre

%post
