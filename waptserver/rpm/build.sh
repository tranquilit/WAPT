#!/bin/sh

set -ex

mkdir -p BUILD RPMS
rpmbuild -bb --buildroot $PWD/builddir -v --clean waptserver.spec
rm -f tis-waptserver.rpm
cp RPMS/noarch/tis-waptserver*.rpm tis-waptserver.rpm
