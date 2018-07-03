# -*- coding: UTF-8 -*-
from setuphelpers import *
import sys
import os


LAZBUILD = r'waptpython.exe lazbuild.py -p C:\\typhon32-config -k C:\Users\buildbot\Documents\tranquilit2.p12 -w C:\Users\buildbot\Documents\tmpkeypwd'
ISCCBUILD = r'waptpython.exe waptsetup\create_setup_simple.py -k C:\Users\buildbot\Documents\tranquilit2.p12 -w C:\Users\buildbot\Documents\tmpkeypwd'

def compile_exes(edition='enterprise',force=False):
    for lpi in ["wapt-get\\waptget.lpi","wapt-get\\waptguihelper.lpi","waptdeploy\\waptdeploy.lpi","wapttray\\wapttray.lpi","waptconsole\\waptconsole.lpi","waptexit\\waptexit.lpi","waptserver\\postconf\\waptserverpostconf.lpi"]:
        if force or not isfile(os.path.split(lpi)[1]+'.exe'):
            print('Compiling %s...' % lpi)
            print(run(LAZBUILD+ r' -e {edition} {lpi}'.format(**locals())))

def compile_setups(edition='enterprise'):
    for iscc in ('waptstarter','waptsetup','waptserversetup'):
        run(ISCCBUILD + r" -e {edition} --sign-exe-filenames=waptservice\win32\nssm.exe,waptservice\win64\nssm.exe waptsetup\{iscc}".format(**locals()))

os.chdir(os.path.dirname(__file__))
if len(sys.argv) == 1:
    editions = ['enterprise','community']
else:
    editions = sys.argv[1:]
 
for edition in sys.argv[1:]:
    print('Edition: %s' % edition)
    compile_exes(edition)
    compile_setups(edition)



