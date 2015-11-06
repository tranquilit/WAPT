#!/bin/sh

mkdir -p BUILD BUILDROOT RPMS
rpmbuild -bb --buildroot $PWD/BUILDROOT -v --clean waptrepo.spec
