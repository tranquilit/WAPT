# -*- coding: utf-8 -*-
from setuphelpers import *

uninstallkey = []

def install():
    rpm_install("%(installer)s")
    
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