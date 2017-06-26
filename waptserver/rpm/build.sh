#!/bin/sh

set -ex
rm -Rf BUILD RPMS BUILDROOT
mkdir -p BUILD RPMS
VERSION=$(python get_version.py ../waptserver.py)
echo $VERSION
rpmbuild -bb --define "_version $VERSION" --buildroot $PWD/builddir -v --clean waptserver.spec
rm -f tis-waptserver*.rpm
cp RPMS/*/tis-waptserver*.rpm .
# temporary addition for builbot
ln -s tis-waptserver*.rpm tis-waptserver.rpm
