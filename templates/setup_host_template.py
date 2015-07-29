# -*- coding: utf-8 -*-
from setuphelpers import *
import sys

uninstallkey = []

def install():
    if control.description:
        print('Change local computer description to match package description')
        print run_notfatal('echo "" | WMIC os set description="'+control.description.splitlines()[0].encode(sys.getfilesystemencoding())+'"')
