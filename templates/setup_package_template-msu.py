# -*- coding: utf-8 -*-
from setuphelpers import *
import re

uninstallkey = []

def is_kb_installed(hotfixid):
    installed_update = installed_windows_updates()
    if [kb for kb in installed_update if kb['HotFixID' ].upper() == hotfixid.upper()]:
        return True
    return False

def waiting_for_reboot():
    # Query WUAU from the registry
    if reg_key_exists(HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") or \
        reg_key_exists(HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") or \
        reg_key_exists(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Updates\UpdateExeVolatile'):
        return True
    return False

def install():
    kb_files = [
        '%(installer)s',
        ]
    for kb_file in kb_files:
        kb_guess = re.findall(r'^.*-(KB.*)-',kb_file)
        if not kb_guess or not is_kb_installed(kb_guess[0]):
            print('Installing %%s' % kb_file)
            run('wusa.exe "%%s" /quiet /norestart' % kb_file,accept_returncodes=[0,3010,2359302,-2145124329],timeout=3600)

    if waiting_for_reboot():
        print('A reboot is needed !')

