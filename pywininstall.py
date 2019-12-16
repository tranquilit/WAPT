import os
import urllib
import urllib2
import hashlib

hash_current_version = 'd059126a23a6d55b5198b271bd29ddc1'
url_current_version = 'https://github.com/mhammond/pywin32/releases/download/b227/pywin32-227.win32-py2.7.exe'


wapt_base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)))
binaries_cache = os.path.abspath(os.path.join(wapt_base_dir,'..','binaries_cache'))

exe_location = os.path.join(binaries_cache,'pywin_install.exe')

proxy = urllib2.ProxyHandler(urllib.getproxies())

opener = urllib2.build_opener(proxy)

urllib2.install_opener(opener)

def download_file(url,location):
    with open(location,'wb') as f:
        f.write(urllib2.urlopen(url).read())
        f.close()

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def download_exe(url,hash,location):
    download_file(url,location)
    if md5(location) == hash:
        print('Good MD5 sum for %s' % (url))
        return location
    else:
        os.remove(location)
        raise Exception('Bad MD5 sum for %s' % (url))


if not(os.path.isdir(binaries_cache)):
    os.mkdir(binaries_cache)

if os.path.isfile(exe_location):
    if md5(exe_location) == hash_current_version:
        print('File already here with a good MD5 sum')
    else:
        print('File already here but with a bad MD5 sum delete the old file and download')
        os.remove(exe_location)
        download_exe(url_current_version,hash_current_version,exe_location)
else:
    download_exe(url_current_version,hash_current_version,exe_location)