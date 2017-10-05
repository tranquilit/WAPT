#-------------------------------------------------------------------------------
# Name:
# Purpose:     get pgsql and nginx binaries
#
# Author:      htouvet
#
# Created:     03/10/2017
# Copyright:   (c) htouvet 2017
# Licence:
#-------------------------------------------------------------------------------

import sys
import os
import shutil

try:
    wapt_base_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..','..'))
except Exception as e:
    print('Error getting wapt basedir : %s' % e)
    wapt_base_dir = r'c:\tranquilit\wapt'

old_os_path = os.environ.get('PATH', '')
os.environ['PATH'] = wapt_base_dir + os.pathsep + old_os_path
base = wapt_base_dir
site_packages = os.path.join(base, 'Lib', 'site-packages')

prev_sys_path = list(sys.path)
import site
site.addsitedir(site_packages)
sys.real_prefix = sys.prefix
sys.prefix = base

# Move the added items to the front of the path:
new_sys_path = []
for item in list(sys.path):
    if item not in prev_sys_path:
        new_sys_path.append(item)
        sys.path.remove(item)
sys.path[:0] = new_sys_path

from setuphelpers import *

pgsql_zip = wget('https://get.enterprisedb.com/postgresql/postgresql-9.4.14-1-windows-x64-binaries.zip',resume=True)
if os.path.isdir(makepath(wapt_base_dir,'waptserver','pgsql')):
    shutil.rmtree(makepath(wapt_base_dir,'waptserver','pgsql'))
pg_files = unzip(pgsql_zip,target=makepath(wapt_base_dir,'waptserver'),filenames=['pgsql/bin/*','pgsql/lib/*','pgsql/share/*'])

nginx_zip = wget('https://nginx.org/download/nginx-1.13.5.zip',resume=True)
if os.path.isdir(makepath(wapt_base_dir,'waptserver','nginx')):
    shutil.rmtree(makepath(wapt_base_dir,'waptserver','nginx'))
nginx_files = unzip(nginx_zip,target=makepath(wapt_base_dir,'waptserver'))
os.rename(makepath(wapt_base_dir,'waptserver','nginx-1.13.5'),makepath(wapt_base_dir,'waptserver','nginx'))



