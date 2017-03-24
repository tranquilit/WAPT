# -*- coding: utf-8 -*-
from setuphelpers import *

uninstallkey = []

def install():
    print('installing %(packagename)s')
    install_msi_if_needed('%(installer)s')
