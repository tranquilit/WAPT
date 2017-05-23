#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      htouvet
#
# Created:     22/05/2017
# Copyright:   (c) htouvet 2017
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import os
import time

for client in range(0,50):
    p = os.spawnl(os.P_NOWAIT,r'c:\windows\system32\cmd.exe','/C',r'c:\tranquilit\wapt\waptpython.exe',r'c:\tranquilit\wapt\tests\sio_client.py')
    print client,p


while 1:
    time.sleep(10)


