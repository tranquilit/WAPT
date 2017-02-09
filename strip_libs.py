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

def keepit(fn,words=['fr','de','en','us','pt','pl','uk']):
    result = False
    for k in words:
        if k.lower() in os.path.basename(fn).lower():
            result = True
            break
    return result

for fn in glob.glob('c:/tranquilit/wapt/lib/site-packages/babel/locale-data/*'):
    if not keepit(fn):
        print('delete %s' %fn)
        os.unlink(fn)

for fn in glob.glob(r'C:\tranquilit\wapt\lib\site-packages\pytz\zoneinfo\*'):
    if not keepit(fn,['europe','etc','us','gb','portugal','france','cet','est','gmt','met','poland','utc','zone','universal','factory']):
        print('delete %s' %fn)
        if os.path.isdir(fn):
            winshell.delete_file(fn,no_confirm=True)
        else:
            os.unlink(fn)
