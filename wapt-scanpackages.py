import os
import zipfile
import glob
import tempfile
import common
import codecs
import sys

from optparse import OptionParser
import logging

sys.path.append("/opt/wapt") 

def main():
    if len(sys.argv) < 2:
        sys.stderr.write('Usage: wapt-scanpackage <wapt_directory>\n')
        sys.exit(1)
    wapt_path = sys.argv[1]
    print wapt_path
    if os.path.exists(wapt_path)==False:
        print "Directory does not exists : %s " % wapt_path
        sys.exit(1)
    if os.path.isdir(wapt_path)==False:
        print "%s does not exists " % wapt_path
        sys.exit(1)

    waptlist = glob.glob(os.path.abspath(wapt_path) + '/*.wapt')


    packagefilename = tempfile.mkstemp(prefix="wapt-packages-")[1]
    packagefile = codecs.open(packagefilename,"wb",encoding='UTF-8')
    for fname in waptlist:
        print "Processing %s" % fname
        entry = common.Package_Entry()
        entry.load_control_from_wapt(fname)
        packagefile.write(entry.ascontrol())
        packagefile.write('\n')

    packagefile.close()
    myzipfile = zipfile.ZipFile(os.path.join(wapt_path,"Packages"), "w")
    myzipfile.write(filename=packagefilename,arcname= "Packages")
    myzipfile.close()
    os.remove(packagefilename)


if __name__ == "__main__":
    main()
