#!/usr/bin/env python3
#
# -----------------------------------------------------------------
#    This file is part of WAPT Software Deployment
#    Copyright (C) 2012 - 2020  Tranquil IT https://www.tranquil.it
#    All Rights Reserved.
#
#    WAPT helps systems administrators to efficiently deploy
#    setup, update and configure applications.
# ------------------------------------------------------------------
#
import os
import sys
import shutil
sys.path.insert(0, '..')
from optparse import OptionParser

# import our lib
import buildlib

wapt_base_dir = 'c:/tranquilit/wapt'

def install_lazarus_packages(lazbuild_path, lazarus_conf):
    target_dir=os.path.join(wapt_base_dir, 'submodules')
    lazarus_dir = os.path.abspath(os.path.join(lazbuild_path, os.pardir))
    packages = [
        r'--add-package %(target_dir)s/pltis_dcpcrypt/dcpcrypt_laz.lpk',
        r'--add-package %(target_dir)s/pltis_indy/Lib/indylaz.lpk',
        r'--add-package-link %(target_dir)s/pltis_utils/pltis_utils.lpk',
        r'--add-package-link %(target_dir)s/pltis_superobject/pltis_superobject.lpk',
        r'--add-package-link %(target_dir)s/pltis_tsmbios/Packages/tsmbios.lpk',
        r'--add-package %(target_dir)s/pltis_virtualtrees/pltis_virtualtrees.lpk',
        r'--add-package %(target_dir)s/pltis_virtualtreesextra/pltis_virtualtreesextra.lpk',
        r'--add-package %(target_dir)s/pltis_lclextensions/lclextensions_package.lpk',
        r'--add-package %(target_dir)s/pltis_sogrid/pltis_sogrid.lpk',
        r'--add-package-link %(target_dir)s/pltis_synapse/laz_synapse.lpk',
        r'--add-package %(target_dir)s/pltis_luipack/luicomponents/luicomponents.lpk',
        r'--add-package %(target_dir)s/pltis_luipack/luicontrols/luicontrols.lpk',
        r'--add-package %(target_dir)s/pltis_python4delphi/Packages/FPC/p4dlaz.lpk',
        r'--add-package %(target_dir)s/pltis_bgracontrols/bgracontrols.lpk',
        r'--add-package %(target_dir)s/pltis_bgracontrolsfx/bgracontrolsfx.lpk',
        r'--add-package %(target_dir)s/pltis_visualcontrols/pltis_visualcontrols.lpk',
        r'--add-package %(target_dir)s/pltis_lazarus-exception-logger/ExceptionLogger.lpk',
        r'--add-package-link %(target_dir)s/pltis_bgrabitmap/bgrabitmap/bgrabitmappack.lpk',
        r'--add-package %(lazarus_dir)s/components/anchordocking/design/anchordockingdsgn.lpk',
        r'--add-package %(lazarus_dir)s/components/memds/memdslaz.lpk',
        r'--build-ide=',
        r'--add-package-link %(wapt_base_dir)s/wapt-get/pltis_wapt.lpk',
    ]

    for lpk in packages:
        print('Install %s' % (lpk % locals()))
        try:
            buildlib.run(r'%s %s --pcp=%s' % (lazbuild_path, lpk % locals(), os.path.expandvars(lazarus_conf)))
        except Exception as e:
            print('Skipping %s : %s' % (lpk,e))

def main():
    parser = OptionParser(usage=__doc__)
    parser.add_option("-l", "--lazbuild-path", dest="lazbuildpath", default=r'C:\lazarus\lazbuild.exe' if os.name == 'nt' else os.path.realpath(shutil.which('lazbuild')), help="Path to lazbuild or lazbuild.exe (default: %default)")
    parser.add_option("-p", "--primary-config-path", dest="primary_config_path", default='%LOCALAPPDATA%\\lazarus' if os.name == 'nt' else os.path.join(os.path.expanduser("~"), ".lazarus"), help="Path to lazbuild primary config dir. (default: %default)")
    (options, args) = parser.parse_args()

    install_lazarus_packages(lazbuild_path = options.lazbuildpath, lazarus_conf = options.primary_config_path)

if __name__ == "__main__":
    main()