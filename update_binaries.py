#-------------------------------------------------------------------------------
# Name:
# Purpose:     get ISCC, pgsql and nginx binaries
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

wapt_base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)))
print('WAPT base directory: %s' %wapt_base_dir)

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

print('Python PATH: %s' % sys.path)

from setuphelpers import *
import tempfile

print('Get Postgresql zip')
pgsql_zip = wget('https://get.enterprisedb.com/postgresql/postgresql-9.4.14-1-windows-x64-binaries.zip',resume=True)
if os.path.isdir(makepath(wapt_base_dir,'waptserver','pgsql')):
    shutil.rmtree(makepath(wapt_base_dir,'waptserver','pgsql'))
pg_files = unzip(pgsql_zip,target=makepath(wapt_base_dir,'waptserver'),filenames=['pgsql/bin/*','pgsql/lib/*','pgsql/share/*'])

print('Get NGINX zip')
nginx_zip = wget('https://nginx.org/download/nginx-1.13.5.zip',resume=True)
if os.path.isdir(makepath(wapt_base_dir,'waptserver','nginx')):
    shutil.rmtree(makepath(wapt_base_dir,'waptserver','nginx'))
nginx_files = unzip(nginx_zip,target=makepath(wapt_base_dir,'waptserver'))
os.rename(makepath(wapt_base_dir,'waptserver','nginx-1.13.5'),makepath(wapt_base_dir,'waptserver','nginx'))

print('Get innosetup compiler setup and extract files to waptsetup')
innosetup_install = wget('http://www.jrsoftware.org/download.php/is.exe',resume=True)
#run([innosetup_install,'/VERYSILENT'],timeout=60)

innoextract_zip = wget('http://constexpr.org/innoextract/files/innoextract-1.6-windows.zip',resume=True)
innoextract_files = unzip(innoextract_zip,filenames=['innoextract.exe'])
run([innoextract_files[0],'-e',innosetup_install,'-d',makepath(tempfile.gettempdir,'iscc')])

iscfiles_path = makepath(os.path.dirname(innosetup_install),'iscc','app')

for fn in ['Default.isl', 'isbunzip.dll', 'isbzip.dll', 'ISCC.exe', 'ISCmplr.dll', 'islzma.dll', 'islzma32.exe', 'islzma64.exe', 'ISPP.dll', 'ISPPBuiltins.iss', 'isscint.dll', 'isunzlib.dll', 'iszlib.dll', 'license.txt', 'Setup.e32', 'SetupLdr.e32', 'WizModernImage-IS.bmp', 'WizModernImage.bmp', 'WizModernSmallImage-IS.bmp', 'WizModernSmallImage.bmp']:
    filecopyto(makepath(iscfiles_path,fn),makepath(wapt_base_dir,'waptsetup','innosetup'))

print('Get OpenSSL binaries from Fulgan')
ssl_zip = wget('https://indy.fulgan.com/SSL/openssl-1.0.2l-i386-win32.zip',resume=True)
ssl_file = unzip(ssl_zip,target=makepath(wapt_base_dir),filenames=['ssleay32.dll','openssl.exe','libeay32.dll'])
