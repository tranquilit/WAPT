#!/usr/bin/env bash

set -ex

rm -Rf rpmbuild
mkdir -p rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

cp waptdeploy.exe rpmbuild/SOURCES
cp waptsetup-tis.exe rpmbuild/SOURCES

cp waptsetup.spec rpmbuild/SPECS

(cd rpmbuild && rpmbuild -bb -v --clean --define "_topdir $(pwd)" SPECS/waptsetup.spec)

rm -f tis-waptsetup.rpm
cp rpmbuild/RPMS/noarch/tis-waptsetup*.rpm tis-waptsetup.rpm
