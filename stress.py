#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      htouvet
#
# Created:     06/06/2013
# Copyright:   (c) htouvet 2013
# Licence:     <your licence>
#-------------------------------------------------------------------------------
import requests,os,threading

def task(*args,**kwargs):
    i = 0
    while True:
     r = requests.request('GET','http://localhost:8088/update',stream=False)
     i += 1
     print i,r.content

if __name__ == '__main__':
    try:
        for i in range(0,20):
            t = threading.Thread(target=task,args=[])
            t.start()
    except KeyboardInterrupt:
        print ("stopping")
        t.stop()



