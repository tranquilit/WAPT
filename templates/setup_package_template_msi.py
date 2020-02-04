# -*- coding: utf-8 -*-
from setuphelpers import *

uninstallkey = []

def install():
    install_msi_if_needed('%(installer)s')
