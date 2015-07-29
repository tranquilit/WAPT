# -*- coding: utf-8 -*-
from setuphelpers import *
import sys

uninstallkey = []

def update_control(control):
    # try to update package description to match computer description in active directory
    try:
        import active_directory
        for pc in active_directory.search(objectCategory='Computer', objectClass='Computer',dNShostname=control.package):
            if pc.description:
                control.description = pc.description
    except:
        pass

def install():
    if control.description:
        print('Change local computer description to match package description')
        print run_notfatal('WMIC os set description="'+control.description.splitlines()[0].encode(sys.getfilesystemencoding())+'"')
