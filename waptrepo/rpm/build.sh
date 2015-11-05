#!/usr/bin/env bash

set -e

for d in BUILD RPMS SOURCES SPECS SRPMS; do
    mkdir -p buildroot/$d
done

rpmbuild -bb --buildroot $PWD/builddir -v --clean ./waptrepo.spec
