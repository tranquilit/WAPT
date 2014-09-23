#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      Administrateur
#
# Created:     30/04/2014
# Copyright:   (c) Administrateur 2014
# Licence:     <your licence>
#-------------------------------------------------------------------------------

from setuphelpers import *
from pymongo import MongoClient
import os


mongodbIP = "127.0.0.1"
if os.name == 'nt':
    mongodbPort = 38999
    osType = 'Windows'
else:
    mongodbPort = 27017
    osType = 'Linux'


serverInfo = dmi_info()["System_Information"]['UUID']
client = MongoClient(mongodbIP,mongodbPort)
db = client['wapt']
print db['hosts'].find_one()['wapt']['common-version']
print db['hosts'].find_one()['uuid']
print serverInfo
print osType
