# -*- coding: utf-8 -*-
from setuphelpers import *

uninstallkey = [%(uninstallkey)s]

def install():
    run(r'"%(installer)s" %(silentflags)s')
