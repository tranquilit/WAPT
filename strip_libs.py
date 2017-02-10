#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      htouvet
#
# Created:     09/02/2017
# Copyright:   (c) htouvet 2017
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import sys,os,glob,re,winshell

def keepit(fn,words=['fr_','de_','en_','us_','pt_','pl_','uk_']):
    result = False
    for k in words:
        if k.lower() in os.path.basename(fn).lower():
            result = True
            break
    return result

for fn in glob.glob(r'lib\site-packages\babel\locale-data\*'):
    if not keepit(fn):
        os.unlink(fn)

for fn in glob.glob(r'lib\site-packages\pytz\zoneinfo\*'):
    if not keepit(fn,['europe','etc','us','gb','portugal','france','cet','est','gmt','met','poland','utc','zone','universal','factory']):
        if os.path.isdir(os.path.abspath(fn)):
            print('delete %s' %fn)
            winshell.delete_file(os.path.abspath(fn),no_confirm=True)
        else:
            os.unlink(fn)

for dirfn in [
        ]:
    if os.path.isdir(os.path.abspath(dirfn)):
        winshell.delete_file(os.path.abspath(dirfn),no_confirm=True)

