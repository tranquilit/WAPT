# -*- coding: UTF-8 -*-
from setuphelpers import *
import os

LAZBUILD = r'waptpython.exe lazbuild.py -p C:\\typhon32-config -k C:\Users\buildbot\Documents\tranquilit2.p12 -w C:\Users\buildbot\Documents\tmpkeypwd'
ISCCBUILD = r'waptpython.exe waptsetup\create_setup_simple.py -k C:\Users\buildbot\Documents\tranquilit2.p12 -w C:\Users\buildbot\Documents\tmpkeypwd'

for lpi in ["wapt-get\\waptget.lpi","wapt-get\\waptguihelper.lpi","waptdeploy\\waptdeploy.lpi","wapttray\\wapttray.lpi","waptconsole\\waptconsole.lpi","waptexit\\waptexit.lpi","waptserver\\postconf\\waptserverpostconf.lpi"]:
    if not isfile(os.path.split(lpi)[1]+'.exe'):
        print(lpi)
        print(run(LAZBUILD+ " -e enterprise "+ lpi ))

run(ISCCBUILD +r" -e enterprise --sign-exe-filenames=waptservice\win32\nssm.exe,waptservice\win64\nssm.exe waptsetup\waptstarter")
run(ISCCBUILD +r" -e enterprise --sign-exe-filenames=waptservice\win32\nssm.exe,waptservice\win64\nssm.exe waptsetup\waptsetup")
run(ISCCBUILD +r" -e enterprise --sign-exe-filenames=waptservice\win32\nssm.exe,waptservice\win64\nssm.exe waptsetup\waptserversetup")

