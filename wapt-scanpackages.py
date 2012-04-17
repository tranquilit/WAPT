import os
import zipfile
import glob
import shutil
import hashlib
import tempfile

def md5_for_file(fname, block_size=2**20):
    f = open(fname,'rb')
    md5 = hashlib.md5()
    while True:
        data = f.read(block_size)
        if not data:
            break
        md5.update(data)
    return md5.hexdigest()

class package_entry:
    Package=''
    Version=''
    Section=''
    Priority=''
    Architecture=''
    Maintainer=''
    Description=''
    Filename=''
    Size=0
    MD5sum=''
    
    def register_package(self,fname ):
        myzip = zipfile.ZipFile(fname,'r')
        tempdir = tempfile.mkdtemp(prefix='/tmp/wapt-')
        myzip.extract(path=tempdir,member='control')
        file = open(tempdir + "/control")
        self.Filename = fname
        self.MD5sum = md5_for_file(fname)
        self.Size = os.path.getsize(fname)
        keyvalue = {}
        while 1:
            line = file.readline()
            if not line:
                break
            if line.strip()=='':
                break
            splitline = line.split(':')
            #keyvalue[splitline[0]] = splitline[1]
            #print splitline[0] + " " + splitline[1]
            setattr(self,splitline[0].strip(),splitline[1].strip())

        shutil.rmtree(tempdir)

    def printobj(self):
        val=""
        val = val + "Package : " + self.Package + '\n'
        val = val + "Version : " + self.Version + '\n'
        val = val + "Section : " + self.Section + '\n'
        val = val +   "Priority : " + self.Priority + '\n'
        val = val +  "Architecture : " + self.Architecture + '\n'
        val = val +  "Maintainer : " + self.Maintainer + '\n'
        val = val + "Description : " + self.Description + '\n'
        val = val +  "Filename : " + self.Filename + '\n'
        val = val +  "size : " + str(self.Size) + '\n'
        val = val +  "MD5sum : " + self.MD5sum + '\n'
        return val 
        
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
myzipfile.write(packagefilename)
myzipfile.close()
os.remove(packagefilename)



