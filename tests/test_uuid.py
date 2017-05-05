#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      htouvet
#
# Created:     05/05/2017
# Copyright:   (c) htouvet 2017
# Licence:     <your licence>
#-------------------------------------------------------------------------------

from common import *

w = Wapt()
print(w.host_uuid)
print(w.read_param('uuid'))
w.register_computer()['result']['uuid']

w.generate_host_uuid()
print(w.host_uuid)
print w.register_computer()['result']['uuid']

w = Wapt()
print(w.host_uuid)
w.reset_host_uuid()
print(w.host_uuid)
w.register_computer()['result']['uuid']


