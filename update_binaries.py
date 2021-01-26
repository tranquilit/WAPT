# -*- coding: utf-8 -*-
from __future__ import absolute_import
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

from setuphelpers import *
import site
import sys
import os
import shutil
import tempfile

wapt_base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)))
print('WAPT base directory: %s' % wapt_base_dir)

binaries_cache = os.path.abspath(os.path.join(wapt_base_dir, '..', 'binaries_cache'))
base = wapt_base_dir
site_packages = os.path.join(base, 'Lib', 'site-packages')

proxies = None
proxies = {'http': 'http://srvproxy:8080', 'https': 'http://srvproxy:8080'}

p7zip = makepath(programfiles, '7-Zip', '7z.exe')

print('Get MS VC++ 2008 SP1 redist')
msvc = wget('https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe',resume=True,md5='35da2bf2befd998980a495b6f4f55e60',cache_dir=binaries_cache,proxies=proxies)
msvc_dst_path = os.path.join(wapt_base_dir,'vc_redist','vcredist_x86.exe')

run([p7zip,'e',msvc,'-o'+makepath(tempfile.gettempdir,'vcredist'),'-y'])
run([p7zip,'e',makepath(tempfile.gettempdir,'vcredist','vc_red.cab'),'-o'+makepath(tempfile.gettempdir,'vcredist','dll'),'-y'])
for dll in ('msvcm90.dll.30729.6161.Microsoft_VC90_CRT_x86.QFE','msvcp90.dll.30729.6161.Microsoft_VC90_CRT_x86.QFE','msvcr90.dll.30729.6161.Microsoft_VC90_CRT_x86.QFE'):
    dest_path = makepath(wapt_base_dir,dll.replace('.30729.6161.Microsoft_VC90_CRT_x86.QFE',''))
    if os.path.exists(dest_path):
        os.unlink(dest_path)
    os.rename(makepath(tempfile.gettempdir,'vcredist','dll',dll),dest_path)

ensure_dir(msvc_dst_path)
if os.path.exists(msvc_dst_path):
    os.unlink(msvc_dst_path)
os.rename(msvc, msvc_dst_path)

print('Get and unzip nssm')
nssm_zip = wget('https://nssm.cc/ci/nssm-2.24-103-gdee49fc.zip', resume=True, md5='1935c374b84b3ce7f068d87d366810b7', cache_dir=binaries_cache, connect_timeout=60, proxies=proxies)
nssm_files = unzip(nssm_zip, filenames=['*/win*/nssm.exe'])
for f in nssm_files:
    new_name = makepath(wapt_base_dir, 'waptservice', * f.split(os.path.sep)[-2:])
    if not os.path.isdir(os.path.dirname(new_name)):
        os.makedirs(os.path.dirname(new_name))
    if os.path.isfile(new_name):
        os.unlink(new_name)
    shutil.copyfile(f, new_name)
    # fix ACL extraction snafu in zipfile library. We reset acl after creation.
    # It is only need for dev time. Innosetup reset things properly when installing
    run('icacls %s /t /Q /C /RESET' % new_name)
print(nssm_files)


print('Get Postgresql zip')
pgsql_zip = wget('https://get.enterprisedb.com/postgresql/postgresql-9.6.10-2-windows-x64-binaries.zip', resume=True, md5='8ed95ad645eb852ec7709bf6665e3cfb', cache_dir=binaries_cache, proxies=proxies)

if os.path.isdir(makepath(wapt_base_dir, 'waptserver', 'pgsql-9.6')):
    shutil.rmtree(makepath(wapt_base_dir, 'waptserver', 'pgsql-9.6'))
if os.path.isdir(makepath(wapt_base_dir, 'waptserver', 'pgsql')):
    shutil.rmtree(makepath(wapt_base_dir, 'waptserver', 'pgsql'))
pg_files = unzip(pgsql_zip, target=makepath(wapt_base_dir, 'waptserver'), filenames=['pgsql/bin/*', 'pgsql/lib/*', 'pgsql/share/*'])
os.rename(makepath(wapt_base_dir, 'waptserver', 'pgsql'), makepath(wapt_base_dir, 'waptserver', 'pgsql-9.6'))

# msvc++2013 is required for postgres.exe. It cannot be unzipped easily like msvc2008, so for now we install it
print('Get MS VC++ 2013 redist')
msvc2013 = wget('https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x64.exe', resume=True, md5='96b61b8e069832e6b809f24ea74567ba', cache_dir=binaries_cache, proxies=proxies)
msvc2013_dst_path = os.path.join(wapt_base_dir, 'waptserver', 'pgsql-9.6', 'vcredist_x64.exe')
if os.path.exists(msvc2013_dst_path):
    os.unlink(msvc2013_dst_path)
filecopyto(msvc2013, msvc2013_dst_path)

print('Get NGINX zip')
nginx_zip = wget('https://nginx.org/download/nginx-1.13.5.zip', resume=True, md5='999bf2444d95771a72eb7fd3637c4f13', cache_dir=binaries_cache, proxies=proxies)
if os.path.isdir(makepath(wapt_base_dir, 'waptserver', 'nginx')):
    shutil.rmtree(makepath(wapt_base_dir, 'waptserver', 'nginx'))
nginx_files = unzip(nginx_zip, target=makepath(wapt_base_dir, 'waptserver'))
os.renames(makepath(wapt_base_dir, 'waptserver', 'nginx-1.13.5'), makepath(wapt_base_dir, 'waptserver', 'nginx'))

print('Get innosetup compiler setup and extract files to waptsetup')
innosetup_install = wget('http://files.jrsoftware.org/is/5/innosetup-5.6.0-unicode.exe', resume=True, md5='d8364b03587846b44cf00937d206d3e1', cache_dir=binaries_cache, proxies=proxies)

innoextract_zip = wget('https://constexpr.org/innoextract/files/innoextract-1.8/innoextract-1.8-windows.zip', resume=True, md5='01efb1f497f9afef630e32097d8a1e33', cache_dir=binaries_cache, proxies=proxies)
innoextract_files = unzip(innoextract_zip, filenames=['innoextract.exe'])
run([innoextract_files[0], '-e', innosetup_install, '-d', makepath(tempfile.gettempdir, 'iscc')])

iscfiles_path = makepath(os.path.dirname(innosetup_install), 'iscc', 'app')

for fn in ['Default.isl', 'isbunzip.dll', 'isbzip.dll', 'ISCC.exe', 'ISCmplr.dll', 'islzma.dll', 'islzma32.exe', 'islzma64.exe', 'ISPP.dll', 'ISPPBuiltins.iss', 'isscint.dll', 'isunzlib.dll', 'iszlib.dll', 'license.txt', 'Setup.e32', 'SetupLdr.e32', 'WizModernImage-IS.bmp', 'WizModernImage.bmp', 'WizModernSmallImage-IS.bmp', 'WizModernSmallImage.bmp']:
    filecopyto(makepath(iscfiles_path, fn), makepath(wapt_base_dir, 'waptsetup', 'innosetup'))

print('Get signtool from Microsot')
# https://docs.microsoft.com/en-us/dotnet/framework/tools/signtool-exe
mkdirs(makepath(binaries_cache,'winsdk_amd64'))
sdkcab1 = wget('https://download.microsoft.com/download/A/6/A/A6AC035D-DA3F-4F0C-ADA4-37C8E5D34E3D/setup/WinSDK_amd64/cab1.cab',resume=True,md5='8ba21a636cbc8749cd4ed1a98499c3e8',cache_dir=makepath(binaries_cache,'winsdk_amd64'),proxies=proxies)
sdkutils = wget('https://download.microsoft.com/download/A/6/A/A6AC035D-DA3F-4F0C-ADA4-37C8E5D34E3D/setup/WinSDK_amd64/WinSDK_amd64.msi',resume=True,md5='5f8dfd64e0c503c300ca23d306cdea5b',cache_dir=makepath(binaries_cache,'winsdk_amd64'),proxies=proxies)
install_msi_if_needed(sdkutils)

"""
print('Get and unzip libzmq.dll')
zmq_exe = wget('http://miru.hk/archive/ZeroMQ-4.0.4~miru1.0-x86.exe',resume=True,md5='699b63085408cd7bfcde5d3d62077f4e',cache_dir=binaries_cache,proxies=proxies)
run([p7zip,'e',zmq_exe,'*/libzmq-v90-mt-4_0_4.dll','-o'+wapt_base_dir,'-y'])
if os.path.isfile(makepath(wapt_base_dir,'libzmq.dll')):
    os.remove(makepath(wapt_base_dir,'libzmq.dll'))
os.renames(makepath(wapt_base_dir,'libzmq-v90-mt-4_0_4.dll'),makepath(wapt_base_dir,'libzmq.dll'))
"""

print('Get DMIDecode')
dmidecode = wget('https://github.com/tabad/fusioninventory-agent-windows-installer/blob/master/Tools/dmidecode/x86/dmidecode.exe?raw=true', resume=True, md5='3945000726804e836cfff999e3b330ec', cache_dir=binaries_cache, proxies=proxies)
if os.path.exists(makepath(wapt_base_dir, 'dmidecode.exe')):
    os.remove(makepath(wapt_base_dir, 'dmidecode.exe'))
filecopyto(dmidecode, makepath(wapt_base_dir, 'dmidecode.exe'))

print('Get OpenSSL binaries from Overbyte')
ssl_zip = wget('http://wiki.overbyte.eu/arch/openssl-1.0.2u-win32.zip', resume=True, sha256='01d17390bbe7077c240abda1d80e88f02ac02b17c8dd61633f316686e9cdd470'.lower(), cache_dir=binaries_cache, proxies=proxies)
ssl_file = unzip(ssl_zip, target=makepath(wapt_base_dir), filenames=['ssleay32.dll', 'openssl.exe', 'libeay32.dll'])

print('Get Cryptography 2.4.2 for Windows XP')
fn = wget('https://files.pythonhosted.org/packages/f2/fe/0877f63affd2ad8c3390d21f76342ef5229fd932f9f9e7388feaf705b040/cryptography-2.4.2-cp27-cp27m-win32.whl',sha256='5ecaf9e7db3ca582c6de6229525d35db8a4e59dc3e8a40a331674ed90e658cbf',resume=False,cache_dir=binaries_cache,proxies=proxies)
tmpdir = tempfile.mktemp('cryptographytmp')
try:
    unzip(fn,target=tmpdir)
    copytree2(makepath(tmpdir,'cryptography','hazmat','bindings'),makepath(site_packages,'cryptography','hazmat','bindings242'))
finally:
    if os.path.isdir(tmpdir):
        shutil.rmtree(tmpdir)


