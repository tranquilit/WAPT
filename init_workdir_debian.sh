#!/bin/bash
set -e
# to run in the current wapt dir after checkout

#sudo easy_install pip virtualenv setuptools 


virtualenv --no-site-packages .
./bin/pip install -r requirements.txt 
#ln -s ./bin/python2.7 waptpython
#chmod 755 runwapt-get.sh

# Patch memory leak
cp -f utils/patch-socketio-client-2/__init__.py  ./lib/python2.7/site-packages/socketIO_client
cp -f utils/patch-socketio-client-2/transports.py  ./lib/python2.7/site-packages/socketIO_client

# Patch x509 certificate signature checking
cp -f utils/patch-cryptography/__init__.py  lib/python2.7/site-packages/cryptography/x509/
cp -f utils/patch-cryptography/verification.py  lib/python2.7/site-packages/cryptography/x509/
