#!/usr/bin/python
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

    common.update_packages(wapt_path)

if __name__ == "__main__":
    main()
