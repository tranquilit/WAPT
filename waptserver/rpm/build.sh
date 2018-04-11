#!/bin/sh

set -ex
if [ -d BUILD ]; then
    echo "removing BUILD directory"
    find BUILD -delete
fi
if [ -d RPMS ]; then
    echo "remove RPMS build directory"
    find RPMS -delete
fi
if [ -d BUILDROOT ]; then
    echo "remove BUILDROOT build directory"
    find BUILDROOT -delete
fi

mkdir -p BUILD RPMS
rm -rf $PWD/builddir

if [ "$WAPTEDITION" = "enterprise" ]; then
    LICENCE="Commercial license"
else
    LICENCE="GPL"
fi

VERSION=$(python get_version.py ../config.py)
QA_SKIP_BUILD_ROOT=1 rpmbuild -bb --define "_version $VERSION"  --define "waptedition $WAPTEDITION"  --define "licence $LICENCE" --buildroot $PWD/builddir -v waptserver.spec 1>&2
#rm -rf $PWD/builddir
rm -f tis-waptserver*.rpm
cp RPMS/*/tis-waptserver*.rpm .
echo tis-waptserver*.rpm
