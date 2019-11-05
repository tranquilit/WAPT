# -*- coding: utf-8 -*-
from __future__ import print_function
from setuphelpers import *

uninstallkey = []

def install():
    print('installing %(packagename)s')
    install_msi_if_needed('%(installer)s')
