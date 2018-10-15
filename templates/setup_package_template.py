# -*- coding: utf-8 -*-
from setuphelpers import *

uninstallkey = [%(uninstallkey)s]

def install():
    print('installing %s' % control.asrequirement())
    run(r'"%(installer)s" %(silentflags)s')
