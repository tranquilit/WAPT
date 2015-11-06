#!/bin/sh

mkdir -p BUILD RPMS
rpmbuild -bb --buildroot $PWD/builddir -v --clean waptserver.spec
