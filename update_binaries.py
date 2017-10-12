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
pgsql_zip = wget('https://get.enterprisedb.com/postgresql/postgresql-9.4.14-1-windows-x64-binaries.zip',resume=True,md5='b69d2e6135a0061dc5ecd968f3d0a31e')
if os.path.isdir(makepath(wapt_base_dir,'waptserver','pgsql')):
    shutil.rmtree(makepath(wapt_base_dir,'waptserver','pgsql'))
pg_files = unzip(pgsql_zip,target=makepath(wapt_base_dir,'waptserver'),filenames=['pgsql/bin/*','pgsql/lib/*','pgsql/share/*'])

print('Get NGINX zip')
nginx_zip = wget('https://nginx.org/download/nginx-1.13.5.zip',resume=True,md5='999bf2444d95771a72eb7fd3637c4f13')
if os.path.isdir(makepath(wapt_base_dir,'waptserver','nginx')):
    shutil.rmtree(makepath(wapt_base_dir,'waptserver','nginx'))
nginx_files = unzip(nginx_zip,target=makepath(wapt_base_dir,'waptserver'))
os.rename(makepath(wapt_base_dir,'waptserver','nginx-1.13.5'),makepath(wapt_base_dir,'waptserver','nginx'))

print('Get innosetup compiler setup and extract files to waptsetup')
innosetup_install = wget('http://www.jrsoftware.org/download.php/is-unicode.exe',resume=True,md5='42b9c2fcfdd96b79aeef49029ce776d4')

innoextract_zip = wget('http://constexpr.org/innoextract/files/innoextract-1.6-windows.zip',resume=True,md5='e3abf26e436c8f1858e2e06a67a37b60')
innoextract_files = unzip(innoextract_zip,filenames=['innoextract.exe'])
run([innoextract_files[0],'-e',innosetup_install,'-d',makepath(tempfile.gettempdir,'iscc')])

iscfiles_path = makepath(os.path.dirname(innosetup_install),'iscc','app')

for fn in ['Default.isl', 'isbunzip.dll', 'isbzip.dll', 'ISCC.exe', 'ISCmplr.dll', 'islzma.dll', 'islzma32.exe', 'islzma64.exe', 'ISPP.dll', 'ISPPBuiltins.iss', 'isscint.dll', 'isunzlib.dll', 'iszlib.dll', 'license.txt', 'Setup.e32', 'SetupLdr.e32', 'WizModernImage-IS.bmp', 'WizModernImage.bmp', 'WizModernSmallImage-IS.bmp', 'WizModernSmallImage.bmp']:
    filecopyto(makepath(iscfiles_path,fn),makepath(wapt_base_dir,'waptsetup','innosetup'))

print('Get OpenSSL binaries from Fulgan')
ssl_zip = wget('https://indy.fulgan.com/SSL/openssl-1.0.2l-i386-win32.zip',resume=True,md5='f1901d936f73d57a9efcef9b028e1621')
ssl_file = unzip(ssl_zip,target=makepath(wapt_base_dir),filenames=['ssleay32.dll','openssl.exe','libeay32.dll'])


print('Python ldap wheel windows')
python_ldap = wget('https://pypi.python.org/packages/55/8b/7e9b4f4f5c3b4c98416b10ba02f682e8e23d34c20fe8e56b9d09f4667e02/python_ldap-2.4.44-cp27-cp27m-win32.whl',resume=True,md5='21db70f804fe06d941a2e36f907358cf')
print('Install ldap wheel')
print(run(['pip','install',python_ldap,'--target',site_packages,'--upgrade']))

