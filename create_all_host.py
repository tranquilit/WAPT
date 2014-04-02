
import requests
import json
import common

hosts =  json.loads(requests.request('GET','http://srvwapt:8080/json/host_list').content)
import common
wapt = common.Wapt(config_filename='c://wapt//wapt-get.ini')
for h in hosts:
    fn = wapt.makehosttemplate(h['name'],'tis-base')
    wapt.build_upload(fn)
