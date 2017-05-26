#!/bin/sh

set -ex

mkdir -p BUILD RPMS
VERSION=$(python get_version.py ../waptserver.py)
echo $VERSION
rpmbuild -bb --define "_version $VERSION" --buildroot $PWD/builddir -v --clean waptserver.spec
rm -f tis-waptserver.rpm
cp RPMS/*/tis-waptserver*.rpm .
