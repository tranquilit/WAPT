# -*- coding: utf-8 -*-
from setuphelpers import *

uninstallkey = [%(uninstallkey)s]

def install():
    print('installing %(packagename)s')
    run(r'"%(installer)s" %(silentflags)s')
