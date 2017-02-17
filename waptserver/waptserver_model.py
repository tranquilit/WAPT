#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      htouvet
#
# Created:     27/01/2017
# Copyright:   (c) htouvet 2017
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import os
import sys
try:
    wapt_root_dir = os.path.abspath( os.path.join(  os.path.dirname(__file__),'..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0, os.path.join(wapt_root_dir))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib'))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib', 'site-packages'))



from peewee import *
from playhouse.postgres_ext import *
from playhouse.signals import Model, pre_save, post_save
from playhouse.shortcuts import dict_to_model,model_to_dict
from waptutils import ensure_unicode
import json
import codecs
import datetime
import os

# You must be sure your database is an instance of PostgresqlExtDatabase in order to use the JSONField.
wapt_db = PostgresqlExtDatabase('wapt', user='wapt',password='wapt')

class BaseModel(Model):
    """A base model that will use our Postgresql database"""
    class Meta:
        database = wapt_db

class WaptHosts(BaseModel):
    uuid = CharField(primary_key=True,unique=True)
    computer_fqdn = CharField(null=True,index=True)
    description = CharField(null=True,index=True)
    reachable = CharField(null=True)
    host_status = CharField(null=True)
    last_query_date = CharField(null=True)

    wapt = BinaryJSONField(null=True)
    update_status = BinaryJSONField(null=True)
    packages = BinaryJSONField(null=True)
    softwares = BinaryJSONField(null=True)
    host = BinaryJSONField(null=True)
    dmi = BinaryJSONField(null=True)
    wmi = BinaryJSONField(null=True)

    created_on = DateTimeField(null=True,default=datetime.datetime.now)
    created_by = DateTimeField(null=True)
    updated_on = DateTimeField(null=True,default=datetime.datetime.now)
    updated_by = DateTimeField(null=True)

    def __repr__(self):
        return "<Host fqdn=%s / uuid=%s>"% (self.computer_fqdn,self.uuid)

    @classmethod
    def fieldbyname(cls,fieldname):
        return cls._meta.fields[fieldname]

@pre_save(sender=WaptHosts)
def model_audit(model_class, instance, created):
    if WaptHosts.host in instance.dirty_fields:
        instance.computer_fqdn = instance.host.get('computer_fqdn',None)
        instance.description = instance.host.get('description',None)
    instance.updated_on = datetime.datetime.now()

def init_db(drop=False):
    wapt_db.get_conn()
    try:
        wapt_db.execute_sql('CREATE EXTENSION hstore;')
    except:
        wapt_db.rollback()
    if drop and 'WaptHosts'.lower() in wapt_db.get_tables():
        wapt_db.drop_table(WaptHosts)
    wapt_db.create_tables([WaptHosts],safe=True)

def mongo_data(ip='10.10.2.26',port=27017):
    """For raw import from mongo"""
    from pymongo import MongoClient
    mongo_client = MongoClient(ip,port)
    db = mongo_client.wapt
    hosts = db.hosts
    result = []
    for h in hosts.find():
        h.pop("_id")
        result.append(h)
    return result

def create_import_data(ip='10.10.2.26',fn=None):
    print('Read mongo data from %s ...'%ip)
    d = mongo_data(ip=ip)
    print('%s records read.'%len(d))
    if fn is None:
        fn = "%s.json"%ip

    #0000 is not accepted by postgresql
    open(fn,'wb').write(json.dumps(d).replace('\u0000',' '))
    print('File %s done.'%fn)

def load_json(filenames=r'c:\tmp\*.json'):
    import glob
    for fn in glob.glob(filenames):
        print('Loading %s'%fn)
        recs = json.load(codecs.open(fn,'rb',encoding='utf8'))

        for rec in recs:
            computer_fqdn = rec['host']['computer_fqdn']
            uuid = rec['uuid']
            try:
                try:
                    # wapt update_status packages softwares host
                    newhost = WaptHosts()
                    for k in rec.keys():
                        if hasattr(newhost,k):
                            setattr(newhost,k,rec[k])
                        else:
                            print 'unknown key %s' % k
                    newhost.save(force_insert=True)
                    print('%s Inserted (%s)'%(newhost.computer_fqdn,newhost.uuid))
                except IntegrityError as e:
                    wapt_db.rollback()
                    updates = {}
                    for k in rec.keys():
                        if hasattr(WaptHosts,k):
                            updates[k] = rec[k]
                    updates['updated_on'] = datetime.datetime.now()
                    WaptHosts.update(
                        **updates
                        ).where(WaptHosts.uuid == uuid)
                    print('%s Updated'%computer_fqdn)
            except Exception as e:
                print(u'Error for %s : %s'%(ensure_unicode(computer_fqdn),ensure_unicode(e)))
                wapt_db.rollback()

def import_shapers():
    for ip in ('wapt-shapers.intra.sermo.fr','wapt-polska.intra.sermo.fr','wapt-india.intra.sermo.fr','wapt-china.intra.sermo.fr'):
        fn = r'c:\tmp\shapers\%s.json' % ip
        if not os.path.isfile(fn):
            create_import_data(ip,fn)

    init_db(False)
    load_json(r'c:\tmp\shapers\*.json')

def tests():
    print WaptHosts.select().count()
    for h in WaptHosts.select(WaptHosts.uuid,WaptHosts.computer_fqdn,WaptHosts.host,WaptHosts.wapt).where(WaptHosts.wapt['waptserver']['dnsdomain'] == 'aspoland.lan' ):
        print h.computer_fqdn,h.host['windows_version'],h.wapt['wapt-exe-version']


if __name__ == '__main__':
    #import_shapers()
    init_db(True)
    #init_db(False)
    #load_json(r"c:\tmp\shapers\*.json")
    #print WaptHosts.get(Hosts.uuid == 'sd')
    #test_pg()
    #tests()


