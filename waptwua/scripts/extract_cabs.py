#!/usr/bin/env python
# -*- coding: utf-8 -*-

import errno
import os
import shutil
import subprocess
import sys

def die(message):
    print >> sys.stderr, message
    exit(1)

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError, exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: 
            raise

if len(sys.argv) != 2:
    die("Wrong number of args")

directory = sys.argv[1]

if not os.path.isdir(directory):
    die("%s is not a directory" % directory)

if not os.path.exists(os.path.join(directory, 'wsusscan2.cab')):
    die("%s does not contain a wsusscan2.cab file" % directory)

packages = os.path.join(directory, 'packages')

mkdir_p(packages)

subprocess.check_output(['cabextract', '-d', packages, os.path.join(directory, 'wsusscan2.cab')])

cab_list = filter(lambda f: f.endswith('.cab'), os.listdir(packages))

for cab in cab_list:
    cab_path = os.path.join(packages, cab)
    package_dir = cab_path[:-len('.cab')]
    shutil.rmtree(package_dir, ignore_errors=True)
    mkdir_p(package_dir)
    subprocess.check_output(['cabextract', '-d', package_dir, cab_path])

subprocess.check_output(['cabextract', '-d', packages, os.path.join(packages, 'package.cab')])
