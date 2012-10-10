import os
import zipfile
import glob
import tempfile
import common
import codecs

from optparse import OptionParser
import logging

waptlist = glob.glob('./*.wapt')
packagefilename = tempfile.mkstemp(prefix="wapt-packages-")[1]
packagefile = codecs.open(packagefilename,"wb",encoding='UTF-8')
for fname in waptlist:
    print "Processing %s" % fname
    entry = common.Package_Entry()
    entry.register_package(fname)
    packagefile.write(entry.printobj())
    packagefile.write('\n')

packagefile.close()
myzipfile = zipfile.ZipFile("Packages", "w")
myzipfile.write(filename=packagefilename,arcname= "Packages")
myzipfile.close()
os.remove(packagefilename)



