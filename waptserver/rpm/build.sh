#!/bin/sh

mkdir -p BUILD RPMS
fakeroot rpmbuild -bb --buildroot $PWD/builddir -v --clean waptserver.spec
