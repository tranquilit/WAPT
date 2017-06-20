#!/bin/sh

set -ex
rm -Rf BUILD
rm -Rf RPM
mkdir -p BUILD RPMS
VERSION=$(python ../rpm/get_version.py ../waptserver.py)
echo $VERSION
rm -f  nginx-1.10.2.tar.gz
rm -Rf builddir
rm -Rf nginx-1.10.2
rm -Rf spnego-http-auth-nginx-module-master

rpmbuild -bb --define "_version $VERSION" --buildroot $PWD/builddir -v --clean nginx-mod-http-auth-spnego.spec
rm -f nginx-mod-http-auth-spnego*.rpm
cp RPMS/*/nginx-mod-http-auth-spnego*.rpm .
# temporary addition for builbot
ln -s nginx-mod-http-auth-spnego*.rpm  nginx-mod-http-auth-spnego.rpm
