# -*- coding: utf-8 -*-
from setuphelpers import *
import sys

uninstallkey = []

def update_control(control):
    try:
        import active_directory
        for pc in active_directory.search(objectCategory='Computer', objectClass='Computer',dNShostname='%(packagename)s'):
            if pc.description:
                control.description = pc.description
    except:
        pass

def install():
    if control.description:
        print run_notfatal('WMIC os set description="'+control.description.splitlines()[0].encode(sys.getfilesystemencoding())+'"')

