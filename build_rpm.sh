#!/bin/bash
cd /home/tisadmin/tmp/buildbot/basedir/wapt-build-rpm-packages/build
git fetch
git pull
git submodule update
git reset --hard
git clean -fx -d

export REV=$(git rev-list --count HEAD)-$(git rev-parse --short HEAD)

export WAPTEDITION=community

cd waptserver/rpm && sh ./build.sh
rsync -aP *.rpm  buildbot:/home/tisadmin/public_html/wapt-1.5.1.24/$WAPTEDITION/
cd ../../waptsetup/rpm/
wget http://buildbot.ad.tranquil.it/~tisadmin/wapt-1.5.1.24/$WAPTEDITION/waptdeploy.exe -O waptdeploy.exe
wget http://buildbot.ad.tranquil.it/~tisadmin/wapt-1.5.1.24/$WAPTEDITION/waptsetup.exe -O waptsetup-tis.exe
sh ./build.sh
rsync -aP *.rpm  buildbot:/home/tisadmin/public_html/wapt-1.5.1.24/$WAPTEDITION/

cd /home/tisadmin/tmp/buildbot/basedir/wapt-build-rpm-packages/build
git fetch
git pull
git submodule update
git reset --hard
git clean -fx -d

export WAPTEDITION=enterprise
cd waptserver/rpm && sh ./build.sh
rsync -aP *.rpm  buildbot:/home/tisadmin/public_html/wapt-1.5.1.24/$WAPTEDITION/
cd ../../waptsetup/rpm/
wget http://buildbot.ad.tranquil.it/~tisadmin/wapt-1.5.1.24/$WAPTEDITION/waptdeploy.exe -O waptdeploy.exe
wget http://buildbot.ad.tranquil.it/~tisadmin/wapt-1.5.1.24/$WAPTEDITION/waptsetup.exe -O waptsetup-tis.exe
sh ./build.shsh
rsync -aP *.rpm  buildbot:/home/tisadmin/public_html/wapt-1.5.1.24/$WAPTEDITION/
