#!/usr/bin/env bash
set -ex
VERSION=$(python get_version.py)

mkdir -p BUILD RPMS SPECS
mkdir -p builddir
cp waptdeploy.exe ./builddir
cp waptsetup-tis.exe ./builddir

rpmbuild -bb -v --clean --buildroot $PWD/builddir --define "_version $VERSION"    ./waptsetup.spec 1>&2

rm -f tis-waptsetup.rpm
cp ./RPMS/noarch/tis-waptsetup*.rpm  .
echo tis-waptsetup*.rpm
