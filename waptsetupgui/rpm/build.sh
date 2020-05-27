#!/usr/bin/env bash
set -ex
VERSION=$(python2 get_version.py ../../waptutils.py)

if [[ -d RPMS ]]
then
	rm -rf RPMS
fi

mkdir -p BUILD RPMS SPECS
mkdir -p builddir

rm -f tis-waptagent-gui*.rpm

rpmbuild -bb -v --clean --buildroot $PWD/builddir --define "_version $VERSION"    ./waptsetupgui.spec 1>&2

cp ./RPMS/x86_64/tis-waptagent-gui*.rpm  .
echo tis-waptagent-gui*.rpm
