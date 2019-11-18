#!/usr/bin/python

import os
import glob
import plistlib

list_installed_softwares=[]

app_dirs = [file for file in glob.glob("/Applications/*.app")]
plist_files = [dir + '/Contents/Info.plist' for dir in app_dirs]

for plist_file in plist_files:
    try:
        print(plist_file)
        plist_obj = plistlib.readPlist(plist_file)
        infodict = {'name': plist_obj['CFBundleName']}
        list_installed_softwares.append(infodict)
    except:
        pass


print(list_installed_softwares)
