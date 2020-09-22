#!/usr/bin/bash
set -ex

BUILDDIR=$(dirname "$(readlink -f "$0")")/builddir
WAPTROOTDIR=$(realpath "$(dirname "$(readlink -f "$0")")/../../")

rm -rf $BUILD
rm -rf $BUILDDIR
rm -rf RPMS

mkdir -p BUILD RPMS

VERSION=$(python2 get_version.py ../../waptutils.py)

mkdir -p builddir

rm -f tis-waptsetup*.rpm

if [ "$SETUP_UNIX" = "TRUE" ] 
then
    cp waptagent_debian9.deb ./builddir
    cp waptagent_debian8.deb ./builddir
    cp waptagent_debian10.deb ./builddir
	cp waptagent_ubuntu16.deb ./builddir
    cp waptagent_ubuntu18.deb ./builddir
    cp waptagent_ubuntu20.deb ./builddir
    cp waptagent_RHEL7.rpm ./builddir
    cp waptagent_RHEL8.rpm ./builddir
    cp waptagent.pkg ./builddir
    cp waptagent_debian10_armhf.deb ./builddir
    rpmbuild -bb -v --clean --buildroot $PWD/builddir --define "_version $VERSION"    ./waptsetup_unix.spec 1>&2
else
    cp waptdeploy.exe ./builddir
    cp waptsetup-tis.exe ./builddir
    rpmbuild -bb -v --clean --buildroot $PWD/builddir --define "_version $VERSION"    ./waptsetup.spec 1>&2
fi

cp ./RPMS/noarch/tis-waptsetup*.rpm  .
echo tis-waptsetup*.rpm
