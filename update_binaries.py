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
site_packages = os.path.join(base, 'lib', 'site-packages')

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

def _md5_for_file(fname, block_size=2**20):
    f = open(fname,'rb')
    md5 = hashlib.md5()
    while True:
        data = f.read(block_size)
        if not data:
            break
        md5.update(data)
    return md5.hexdigest()

ProgressBar = None

def wget(url,target=None,printhook=None,proxies=None,connect_timeout=10,download_timeout=None,verify_cert=False,referer=None,user_agent=None,cert=None,resume=False,md5=None):
    r"""Copy the contents of a file from a given URL to a local file.

    Args:
        url (str): URL to document
        target (str) : full file path of downloaded file. If None, put in a temporary dir with supplied url filename (final part of url)
        proxies (dict) : proxies to use. eg {'http':'http://wpad:3128','https':'http://wpad:3128'}
        timeout (int)  : seconds to wait for answer before giving up
        auth (list)    : (user,password) to authenticate wirh basic auth
        verify_cert (bool or str) : either False, True (verify with embedded CA list), or path to a directory or PEM encoded CA bundle file
                                    to check https certificate signature against.
        cert (list) : pair of (x509certfilename,pemkeyfilename) for authenticating the client

    Returns:
        str : path to downloaded file

    >>> respath = wget('http://wapt.tranquil.it/wapt/tis-firefox_28.0.0-1_all.wapt','c:\\tmp\\test.wapt',proxies={'http':'http://proxy:3128'})
    ???
    >>> os.stat(respath).st_size>10000
    True
    >>> respath = wget('http://localhost:8088/runstatus','c:\\tmp\\test.json')
    ???
    """
    start_time = time.time()
    last_time_display = 0.0
    last_downloaded = 0

    def reporthook(received,total):
        total = float(total)
        if total>1 and received>1:
            # print only every second or at end
            if (time.time()-start_time>1) and ((time.time()-last_time_display>=1) or (received>=total)):
                speed = received /(1024.0 * (time.time()-start_time))
                if printhook:
                    printhook(received,total,speed,url)
                elif sys.stdout is not None:
                    try:
                        if received == 0:
                            print(u"Downloading %s (%.1f Mb)" % (url,int(total)/1024/1024))
                        elif received>=total:
                            print(u"  -> download finished (%.0f Kb/s)" % (total /(1024.0*(time.time()+.001-start_time))))
                        else:
                            print(u'%i / %i (%.0f%%) (%.0f KB/s)\r' % (received,total,100.0*received/total,speed))
                    except:
                        return False
                return True
            else:
                return False

    if target is None:
        target = tempfile.gettempdir()

    if os.path.isdir(target):
        target = os.path.join(target,'')

    (dir,filename) = os.path.split(target)
    if not filename:
        url_parts = urlparse.urlparse(url)
        filename = url_parts.path.split('/')[-1]
    if not dir:
        dir = os.getcwd()

    if not os.path.isdir(dir):
        os.makedirs(dir)

    if verify_cert == False:
        requests.packages.urllib3.disable_warnings() # pylint: disable=no-member
    header=default_http_headers()
    if referer != None:
        header.update({'referer': '%s' % referer})
    if user_agent != None:
        header.update({'user-agent': '%s' % user_agent})

    target_fn = os.path.join(dir,filename)

    if os.path.isfile(target_fn) and resume:
        try:
            actual_size = os.stat(target_fn).st_size
            size_req = requests.head(url,
                proxies=proxies,
                timeout=connect_timeout,
                verify=verify_cert,
                headers=header,
                cert = cert,
                allow_redirects=True)

            target_size = int(size_req.headers['content-length'])
            file_date = size_req.headers.get('last-modified',None)

            if target_size > actual_size:
                header.update({'Range':'bytes=%s-' % (actual_size,)})
                write_mode = 'ab'
            elif target_size < actual_size:
                target_size = None
                write_mode = 'wb'
        except Exception as e:
            target_size = None
            write_mode = 'wb'

    else:
        file_date = None
        actual_size = 0
        target_size = None
        write_mode = 'wb'

    # check md5 if size equal
    if resume and md5 is not None and target_size is not None and (target_size == actual_size):
        actual_md5 = _md5_for_file(target_fn)
        if actual_md5 != md5:
            # restart download...
            target_size = None
            write_mode = 'wb'


    if not resume or target_size is None or (target_size - actual_size) > 0:
        httpreq = requests.get(url,stream=True,
            proxies=proxies,
            timeout=connect_timeout,
            verify=verify_cert,
            headers=header,
            cert = cert,
            allow_redirects=True)

        httpreq.raise_for_status()

        total_bytes = int(httpreq.headers['content-length'])
        target_free_bytes = get_disk_free_space(os.path.dirname(os.path.abspath(target)))
        if total_bytes > target_free_bytes:
            raise Exception('wget : not enough free space on target drive to get %s MB. Total size: %s MB. Free space: %s MB' % (url,total_bytes // (1024*1024),target_free_bytes // (1024*1024)))

        # 1Mb max, 1kb min
        chunk_size = min([1024*1024,max([total_bytes/100,2048])])

        cnt = 0
        if printhook is None and ProgressBar is not None:
            progress_bar = ProgressBar(label=filename,expected_size=target_size or total_bytes, filled_char='=')
            progress_bar.show(actual_size)

        with open(target_fn,write_mode) as output_file:
            last_time_display = time.time()
            last_downloaded = 0
            if httpreq.ok:
                for chunk in httpreq.iter_content(chunk_size=chunk_size):
                    output_file.write(chunk)
                    output_file.flush()
                    if download_timeout is not None and (time.time()-start_time>download_timeout):
                        raise requests.Timeout(r'Download of %s takes more than the requested %ss'%(url,download_timeout))
                    if printhook is None and ProgressBar is not None:
                        if (time.time()-start_time>0.2) and (time.time()-last_time_display>=0.2):
                            progress_bar.show(actual_size + cnt*len(chunk))
                            last_time_display = time.time()
                    else:
                        if reporthook(cnt*len(chunk),total_bytes):
                            last_time_display = time.time()
                    last_downloaded += len(chunk)
                    cnt +=1
                if printhook is None and ProgressBar is not None:
                    progress_bar.show(total_bytes)
                    progress_bar.done()
                    last_time_display = time.time()
                elif reporthook(last_downloaded,total_bytes):
                    last_time_display = time.time()

        # check md5
        if md5 is not None:
            actual_md5 = _md5_for_file(target_fn)
            if actual_md5 != md5:
                raise Exception(u'Downloaded file %s md5 %s does not match expected %s' % (url,actual_md5,md5))

        file_date = httpreq.headers.get('last-modified',None)

    if file_date:
        file_datetime = httpdatetime2time(file_date)
        os.utime(target_fn,(file_datetime,file_datetime))
    return target_fn


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


