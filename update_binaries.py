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

p7zip = makepath(programfiles,'7-Zip','7z.exe')

print('Get MS VC++ 2008 SP1 redist')
msvc = wget('https://download.microsoft.com/download/d/d/9/dd9a82d0-52ef-40db-8dab-795376989c03/vcredist_x86.exe',resume=True,md5='5689d43c3b201dd3810fa3bba4a6476a')
run([p7zip,'e',msvc,'-o'+makepath(tempfile.gettempdir,'vcredist'),'-y'])
run([p7zip,'e',makepath(tempfile.gettempdir,'vcredist','vc_red.cab'),'-o'+makepath(tempfile.gettempdir,'vcredist','dll'),'-y'])
for dll in ('msvcm90.dll.30729.01.Microsoft_VC90_CRT_x86.SP','msvcp90.dll.30729.01.Microsoft_VC90_CRT_x86.SP','msvcr90.dll.30729.01.Microsoft_VC90_CRT_x86.SP'):
    dest_path = makepath(wapt_base_dir,dll.replace('.30729.01.Microsoft_VC90_CRT_x86.SP',''))
    if os.path.exists(dest_path):
        os.unlink(dest_path)
    os.rename(makepath(tempfile.gettempdir,'vcredist','dll',dll),dest_path)

print('Get and unzip nssm')
nssm_zip = wget('https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip',resume=True,md5='63175d3830b8a5cfd254353c4f561e5c')
nssm_files = unzip(nssm_zip,filenames=['*/win*/nssm.exe'])
for f in nssm_files:
    new_name = makepath(wapt_base_dir,'waptservice',* f.split(os.path.sep)[-2:])
    if not os.path.isdir(os.path.dirname(new_name)):
        os.makedirs(os.path.dirname(new_name))
    if os.path.isfile(new_name):
        os.unlink(new_name)
    os.renames(f,new_name)
    # fix ACL extraction snafu in zipfile library. We reset acl after creation.
    # It is only need for dev time. Innosetup reset things properly when installing
    run('icacls %s /t /Q /C /RESET' % new_name)
print nssm_files


print('Get Postgresql zip')
pgsql_zip = wget('https://get.enterprisedb.com/postgresql/postgresql-9.4.14-1-windows-x64-binaries.zip',resume=True,md5='6dc704a32dacd6e151540a72bf81b252')

if os.path.isdir(makepath(wapt_base_dir,'waptserver','pgsql')):
    shutil.rmtree(makepath(wapt_base_dir,'waptserver','pgsql'))
pg_files = unzip(pgsql_zip,target=makepath(wapt_base_dir,'waptserver'),filenames=['pgsql/bin/*','pgsql/lib/*','pgsql/share/*'])


# msvc++2013 is required for postgres.exe. It cannot be unzipped easily like msvc2008, so for now we install it
print('Get MS VC++ 2013 redist')
msvc2013 = wget('https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x64.exe',resume=True,md5='96b61b8e069832e6b809f24ea74567ba')
msvc2013_dst_path = os.path.join(wapt_base_dir,'waptserver','pgsql','vcredist_x64.exe')
if os.path.exists(msvc2013_dst_path):
    os.unlink(msvc2013_dst_path)
os.rename(msvc2013, msvc2013_dst_path)

print('Get NGINX zip')
nginx_zip = wget('https://nginx.org/download/nginx-1.13.5.zip',resume=True,md5='999bf2444d95771a72eb7fd3637c4f13')
if os.path.isdir(makepath(wapt_base_dir,'waptserver','nginx')):
    shutil.rmtree(makepath(wapt_base_dir,'waptserver','nginx'))
nginx_files = unzip(nginx_zip,target=makepath(wapt_base_dir,'waptserver'))
os.renames(makepath(wapt_base_dir,'waptserver','nginx-1.13.5'),makepath(wapt_base_dir,'waptserver','nginx'))

print('Get innosetup compiler setup and extract files to waptsetup')
innosetup_install = wget('http://www.jrsoftware.org/download.php/is-unicode.exe',resume=True,md5='42b9c2fcfdd96b79aeef49029ce776d4')

innoextract_zip = wget('http://constexpr.org/innoextract/files/innoextract-1.6-windows.zip',resume=True,md5='e3abf26e436c8f1858e2e06a67a37b60')
innoextract_files = unzip(innoextract_zip,filenames=['innoextract.exe'])
run([innoextract_files[0],'-e',innosetup_install,'-d',makepath(tempfile.gettempdir,'iscc')])

iscfiles_path = makepath(os.path.dirname(innosetup_install),'iscc','app')

for fn in ['Default.isl', 'isbunzip.dll', 'isbzip.dll', 'ISCC.exe', 'ISCmplr.dll', 'islzma.dll', 'islzma32.exe', 'islzma64.exe', 'ISPP.dll', 'ISPPBuiltins.iss', 'isscint.dll', 'isunzlib.dll', 'iszlib.dll', 'license.txt', 'Setup.e32', 'SetupLdr.e32', 'WizModernImage-IS.bmp', 'WizModernImage.bmp', 'WizModernSmallImage-IS.bmp', 'WizModernSmallImage.bmp']:
    filecopyto(makepath(iscfiles_path,fn),makepath(wapt_base_dir,'waptsetup','innosetup'))


print('Get and unzip libzmq.dll')
zmq_exe = wget('http://miru.hk/archive/ZeroMQ-4.0.4~miru1.0-x86.exe',resume=True,md5='699b63085408cd7bfcde5d3d62077f4e')
run([p7zip,'e',zmq_exe,'*/libzmq-v90-mt-4_0_4.dll','-o'+wapt_base_dir,'-y'])
if os.path.isfile(makepath(wapt_base_dir,'libzmq.dll')):
    os.remove(makepath(wapt_base_dir,'libzmq.dll'))
os.renames(makepath(wapt_base_dir,'libzmq-v90-mt-4_0_4.dll'),makepath(wapt_base_dir,'libzmq.dll'))

print('Get DMIDecode')
dmidecode = wget('https://github.com/tabad/fusioninventory-agent-windows-installer/blob/master/Tools/dmidecode/x86/dmidecode.exe?raw=true',resume=True,md5='3945000726804e836cfff999e3b330ec')
if os.path.exists(makepath(wapt_base_dir,'dmidecode.exe')):
    os.remove(makepath(wapt_base_dir,'dmidecode.exe'))
os.renames(dmidecode,makepath(wapt_base_dir,'dmidecode.exe'))

print('Get OpenSSL binaries from Fulgan')
ssl_zip = wget('https://indy.fulgan.com/SSL/openssl-1.0.2l-i386-win32.zip',resume=True,md5='f1901d936f73d57a9efcef9b028e1621')
ssl_file = unzip(ssl_zip,target=makepath(wapt_base_dir),filenames=['ssleay32.dll','openssl.exe','libeay32.dll'])


print('Python ldap wheel windows')
python_ldap = wget('https://pypi.python.org/packages/55/8b/7e9b4f4f5c3b4c98416b10ba02f682e8e23d34c20fe8e56b9d09f4667e02/python_ldap-2.4.44-cp27-cp27m-win32.whl',resume=True,md5='21db70f804fe06d941a2e36f907358cf')
print('Install ldap wheel')
print(run([makepath(wapt_base_dir,'Scripts','pip.exe'),'install',python_ldap,'--target',site_packages,'--upgrade']))


