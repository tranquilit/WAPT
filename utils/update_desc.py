#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      htouvet
#
# Created:     18/06/2015
# Copyright:   (c) htouvet 2015
# Licence:     <your licence>
#-------------------------------------------------------------------------------
from setuphelpers import *
import active_directory

ad_admin = r'domaine\administrateur'
ad_passwd = 'xxxx'

for pc in active_directory.search (objectCategory='Computer', objectClass='Computer'):
  host = pc.dNShostname
  description = pc.description
  if host and description:
    print "Change %s description to %s" % (host,description)
    try:
        print('echo "" | wmic /USER:%s /PASSWORD:%s /NODE:"%s" os set description="%s"' % (ad_admin,ad_passwd,host,description))
    except Exception as e:
        print('Unable to change description for %s'%host)

