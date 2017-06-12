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

rpmbuild -bb --define "_version $VERSION" --buildroot $PWD/builddir -v --clean wapt-spnego-http-auth-nginx-module.spec
rm -f tis-wapt-spnego-http-auth-nginx-module*.rpm
cp RPMS/*/tis-wapt-spnego-http-auth-nginx-module*.rpm .
# temporary addition for builbot
ln -s tis-wapt-spnego-http-auth-nginx-module*.rpm tis-wapt-spnego-http-auth-nginx-module.rpm
