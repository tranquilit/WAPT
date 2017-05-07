#!/bin/sh

set -ex

mkdir -p BUILD BUILDROOT RPMS
rpmbuild -bb --buildroot $PWD/BUILDROOT -v --clean waptrepo.spec
rm -f tis-waptrepo.rpm
cp RPMS/noarch/tis-waptrepo*.rpm .
