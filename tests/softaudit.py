#!/usr/bin/python
# -*- coding: utf-8 -*-
#------------------------------------------------
"""
    Sample script which check softwares installed recently on wapt registred computers
"""

import sys,os
from common import *
from getpass import getpass
from optparse import OptionParser

def compact_date(adatetime=None):
    if adatetime is None:
        adatetime = datetime.datetime.today()
    return adatetime.strftime('%Y%m%d')

if __name__ == '__main__':
    parser=OptionParser(usage=__doc__)
    parser.add_option("-c","--config", dest="config", default=os.path.join(os.path.dirname(sys.argv[0]),'wapt-get.ini') , help="Config file full path (default: %default)")
    parser.add_option("-d","--days", dest="days", default=1, type='int', help="Days back to look at (default: %default)")
    (options,args) = parser.parse_args()

    server_password = getpass('Please input wapt server admin password:')

    # initialise wapt api with local config file
    wapt = Wapt(config_filename = options.config)
    wapt.dbpath=':memory:'

    # get the collection of *all* hosts from waptserver inventory
    hosts =  wapt.waptserver.get('api/v1/hosts?limit=10000&columns=uuid,computer_fqdn,connected_ips,description',auth=('admin',server_password))

    print(u'Logiciels installés depuis %s jours sur les %s machines de wapt:\n'%(options.days,len(hosts['result'])))
    for h in hosts['result']:
        try:
            uuid = h['uuid']

            hostname = h['computer_fqdn']
            ip = ','.join(h['connected_ips'])
            description = h['description']

            softs = wapt.waptserver.get('api/v1/host_data?uuid=%s&field=installed_softwares'%(uuid,),auth=('admin',server_password)).get('result',[])
            softs = wapt.waptserver.get('api/v1/host_data?uuid=%s&field=installed_packages'%(uuid,),auth=('admin',server_password)).get('result',[])
            datemin = compact_date(datetime.datetime.now()-datetime.timedelta(days=options.days)) # forme YYYYMMDD 20161007
            recent_installs = [s['name'] for s in softs if s['install_date'] >= datemin]
            if recent_installs:
                print "%s (%s)  %s:\n    %s\n" %(hostname,ip,description,'\n    '.join(recent_installs))
        except Exception as e:
            print " error %s" % e
