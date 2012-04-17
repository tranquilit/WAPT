import os
import zipfile
import glob
import shutil
import hashlib
import tempfile
import common
def md5_for_file(fname, block_size=2**20):
    f = open(fname,'rb')
    md5 = hashlib.md5()
    while True:
        data = f.read(block_size)
        if not data:
            break
        md5.update(data)
    return md5.hexdigest()



waptlist = glob.glob('./*.wapt')
packagefilename = tempfile.mkstemp(prefix="/tmp/wapt-packages-")[1]
print packagefilename
packagefile = open(packagefilename,"wb")
for fname in waptlist:

    print fname
    entry = package_entry()
    entry.register_package(fname)
    packagefile.write(entry.printobj())

    packagefile.write('\n')

packagefile.close()
myzipfile = zipfile.ZipFile("Packages", "w")
myzipfile.write(filename=packagefilename,arcname= "Packages")
myzipfile.close()
os.remove(packagefilename)



