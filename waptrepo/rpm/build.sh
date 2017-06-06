#!/bin/sh

set -ex
VERSION=$(python ../../waptserver/rpm/get_version.py ../../waptserver/waptserver.py)
echo $VERSION
mkdir -p BUILD BUILDROOT RPMS
rpmbuild -bb --define "_version $VERSION" --buildroot $PWD/BUILDROOT -v --clean waptrepo.spec
rm -f tis-waptrepo.rpm
cp RPMS/noarch/tis-waptrepo*.rpm .
# temporary for buildbot
ln -s tis-waptrepo-*.rpm tis-waptrepo.rpm
