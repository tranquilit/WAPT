#!/bin/sh

set -ex
rm -Rf BUILD RPMS BUILDROOT
mkdir -p BUILD RPMS
VERSION=$(python get_version.py ../waptserver_config.py)
rpmbuild -bb --define "_version $VERSION" --buildroot $PWD/builddir -v --clean waptserver.spec 1>&2
rm -f tis-waptserver*.rpm
cp RPMS/*/tis-waptserver*.rpm .
echo tis-waptserver*.rpm
