# -*- coding: utf-8 -*-
from setuphelpers import *

uninstallkey = []

def install():
    install_exe_if_needed("%(installer)s",'%(silentflags)s',key='%(uninstallkey)s',min_version='%(version)s')
