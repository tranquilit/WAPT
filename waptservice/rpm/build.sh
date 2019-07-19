#!/bin/sh

set -ex

mkdir -p BUILD RPMS

if [ "$WAPTEDITION" = "" ]; then
	WAPTEDITION=community
fi

if [ "$WAPTEDITION" = "enterprise" ]; then
    LICENCE="Commercial license"
else
    LICENCE="GPL"
fi

VERSION=$(python get_version.py ../../waptutils.py)

QA_SKIP_BUILD_ROOT=1 rpmbuild -bb --define "_version $VERSION"  --define "waptedition $WAPTEDITION"  --define "licence $LICENCE" --buildroot $PWD/builddir -v waptagent.spec 1>&2
rm -f tis-waptagent*.rpm
cp RPMS/*/tis-waptagent*.rpm .
rm -rf $PWD/builddir
rm -rf $PWD/BUILD
rm -rf $PWD/RPMS
rm -rf ~/rpmbuild
echo tis-waptagent*.rpm
