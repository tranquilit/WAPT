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
    with EnsureWUAUServRunning():
        kb_files = [
            '%(installer)s',
            ]
        for kb_file in kb_files:
            kb_guess = re.findall(r'^.*-(KB.*)-',kb_file)
            if not kb_guess or not is_kb_installed(kb_guess[0]):
                print('Installing {}'.format(kb_file))
                run('wusa.exe "{}" /quiet /norestart'.format(kb_file),accept_returncodes=[0,3010,2359302,-2145124329],timeout=3600)
            else:
                print('{} already installed'.format(kb_file))

    if waiting_for_reboot():
        print('A reboot is needed !')

def uninstall():
    pass
    # put here what to do when package is removed from host
    # implicit context variables are WAPT, control, user, params, run

def session_setup():
    print('Session setup for %%s' %% control.asrequirement())
    # put here what to do when package is configured inside a user session
    # implicit context variables are WAPT, control, user, params

def update_package():
    pass
    # put here what to do to update package content with newer installers.
    # launched with command wapt-get update-package-sources <path-to-wapt-directory>
    # implicit context variables are WAPT, basedir, control, user, params, run
    # if attributes in control are changed, they should be explicitly saved to package file with control.save_control_to_wapt()

def audit():
    pass
    # put here code to check periodically that state is matching expectations
    # return "OK", "WARNING" or "ERROR" to report status in console.
    # all print statement are reported too
    return "OK"