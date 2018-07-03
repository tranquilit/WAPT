#!/bin/bash
cd /home/tisadmin/tmp/buildbot/basedir/wapt-build-debian-packages/build || cd /home/tisadmin/tmp/buildbot/basedir/wapt-build-debian9-packages/build
git fetch
git pull
git submodule update
git reset --hard
git clean -fx -d
export WAPTEDITION=community
cd waptserver/deb && fakeroot python createdeb.py
export REV=git --
rsync -aP *.deb  buildbot:/home/tisadmin/public_html/wapt-1.5.1.24/$WAPTEDITION/
cd ..
