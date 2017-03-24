# -*- coding: utf-8 -*-
from setuphelpers import *

uninstallkey = []

def install():
    print('installing %(packagename)s')
    install_exe_if_needed("%(installer)s",'%(silentflags)s',key='%(uninstallkey)s',min_version='0.0.0')
