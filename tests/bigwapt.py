#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      htouvet
#
# Created:     26/01/2015
# Copyright:   (c) htouvet 2015
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import os
from hashlib import md5
from common import *
from waptpackage import PackageEntry

packagedir = 'c:/tranquilit/big-wapt'
os.chdir(packagedir)
for i in range(0,80):
    root = os.path.join(packagedir,"files","directory_%i_%s" %( i, "to" * i))
    if not os.path.isdir(root):
        os.makedirs(root)
    for j in range(0,1000):
        fn = 'fichiers_%i' % j
        if not os.path.isfile(os.path.join(root,fn)):
            open(os.path.join(root,fn),'wb').write(fn)

if not os.path.isdir(os.path.join(packagedir,'WAPT')):
    os.makedirs(os.path.join(packagedir,'WAPT'))

pe = PackageEntry('big')
pe.save_control_to_wapt(packagedir)

setup = """\
from setuphelpers import *

uninstallkey = []

dest = makepath(programfiles,'big')

def install():
    copytree2('files',dest)

"""

open(os.path.join(packagedir,'setup.py'),'wb').write(setup)

w = Wapt()
w.build_package(packagedir)


