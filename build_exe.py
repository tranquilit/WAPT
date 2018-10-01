# -*- coding: UTF-8 -*-
from setuphelpers import *
import sys
import os
import re

import getpass

force = False
pwd = getpass.getpass('Key password ?')
open(r'C:\Users\buildbot\Documents\tmpkeypwd','wb').write(pwd.encode('utf8'))
try:

    LAZBUILD = r'waptpython.exe lazbuild.py -k C:\Users\buildbot\Documents\tranquilit2.p12 -w C:\Users\buildbot\Documents\tmpkeypwd'
    ISCCBUILD = r'waptpython.exe waptsetup\create_setup_simple.py -k C:\Users\buildbot\Documents\tranquilit2.p12 -w C:\Users\buildbot\Documents\tmpkeypwd'

    def compile_exes(edition='enterprise',force=False):
        for lpi in ["wapt-get\\waptget.lpi","wapt-get\\waptguihelper.lpi","waptdeploy\\waptdeploy.lpi",
                    "wapttray\\wapttray.lpi","waptconsole\\waptconsole.lpi","waptexit\\waptexit.lpi",
                    "waptserver\\postconf\\waptserverpostconf.lpi",
                    "waptconsolepostconf\\waptconsolepostconf.lpi",
                    "waptsetup\\waptsetuputil\\waptsetuputil.lpi",
                    ]:
            lpi_content = open(lpi,'r').read()
            targets = re.findall(r'<Target>\n.*<Filename.* Value="(.*?)".*/>',lpi_content)
            if targets:
                if 'waptguihelper' in lpi:
                    exe = os.path.abspath(os.path.join(os.path.dirname(lpi),targets[0]))
                elif 'waptsetuputil' in lpi:
                    exe = os.path.abspath(os.path.join(os.path.dirname(lpi),targets[0]+'.dll'))
                else:
                    exe = os.path.abspath(os.path.join(os.path.dirname(lpi),targets[0]+'.exe'))
            else:
                exe = ''
            if force or not isfile(exe):
                print('Compiling %s...' % lpi)
                print(run(LAZBUILD+ r' -e {edition} {lpi}'.format(**locals())))
            else:
                print('Skipped %s ' % lpi)

    def compile_setups(edition='enterprise',force=False):
        for iscc in ('waptstarter','waptsetup','waptserversetup'):
            setup_exe = 'waptsetup\{iscc}.exe'.format(**locals())
            if force or not os.path.isfile(setup_exe):
                print('Compiling setup %s for edition %s...' % (iscc,edition))
                run(ISCCBUILD + r" -e {edition} --sign-exe-filenames=waptservice\win32\nssm.exe,waptservice\win64\nssm.exe waptsetup\{iscc}".format(**locals()))
            else:
                print('Skipped %s ' % setup_exe)

    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    if len(sys.argv) == 1:
        editions = ['enterprise','community']
    else:
        editions = sys.argv[1:]

    for edition in sys.argv[1:]:
        print('Edition: %s' % edition)
        compile_exes(edition,force)
        compile_setups(edition,force)

finally:
    if isfile(r'C:\Users\buildbot\Documents\tmpkeypwd'):
        remove_file(r'C:\Users\buildbot\Documents\tmpkeypwd')


