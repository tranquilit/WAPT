#!/bin/bash
cd /home/tisadmin/tmp/buildbot/basedir/wapt-build-debian-packages/build || cd /home/tisadmin/tmp/buildbot/basedir/wapt-build-debian9-packages/build
git fetch
git pull
git submodule update
git reset --hard
git clean -fx -d

export REV=$(git rev-list --count HEAD)-$(git rev-parse --short HEAD)

export WAPTEDITION=community

cd waptserver/deb && fakeroot python createdeb.py
rsync -aP *.deb  buildbot:/home/tisadmin/public_html/wapt-1.5.1.26/$WAPTEDITION/
cd ../../waptsetup/deb/
wget http://buildbot.ad.tranquil.it/~tisadmin/wapt-1.5.1.26/$WAPTEDITION/waptdeploy.exe -O waptdeploy.exe
wget http://buildbot.ad.tranquil.it/~tisadmin/wapt-1.5.1.26/$WAPTEDITION/waptsetup.exe -O waptsetup-tis.exe
fakeroot python createdeb.py
rsync -aP *.deb  buildbot:/home/tisadmin/public_html/wapt-1.5.1.26/$WAPTEDITION/

cd /home/tisadmin/tmp/buildbot/basedir/wapt-build-debian-packages/build || cd /home/tisadmin/tmp/buildbot/basedir/wapt-build-debian9-packages/build
git fetch
git pull
git submodule update
git reset --hard
git clean -fx -d

export WAPTEDITION=enterprise
cd waptserver/deb && fakeroot python createdeb.py
rsync -aP *.deb  buildbot:/home/tisadmin/public_html/wapt-1.5.1.26/$WAPTEDITION/
cd ../../waptsetup/deb/
wget http://buildbot.ad.tranquil.it/~tisadmin/wapt-1.5.1.26/$WAPTEDITION/waptdeploy.exe -O waptdeploy.exe
wget http://buildbot.ad.tranquil.it/~tisadmin/wapt-1.5.1.26/$WAPTEDITION/waptsetup.exe -O waptsetup-tis.exe
fakeroot python createdeb.py
rsync -aP *.deb  buildbot:/home/tisadmin/public_html/wapt-1.5.1.26/$WAPTEDITION/

