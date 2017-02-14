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

from peewee import *
from playhouse.postgres_ext import *
from waptutils import ensure_unicode
import json
import codecs
import datetime
import os

wapt_db = PostgresqlExtDatabase('wapt', user='postgres')

class BaseModel(Model):
    """A base model that will use our Postgresql database"""
    class Meta:
        database = wapt_db

class WaptHosts(BaseModel):
    uuid = CharField(primary_key=True,unique=True)
    host_fqdn = CharField(null=True,index=True)
    host_data = BinaryJSONField(null=True)
    created_on = DateTimeField(null=True,default=datetime.datetime.now)
    created_by = DateTimeField(null=True)
    updated_on = DateTimeField(null=True,default=datetime.datetime.now)
    updated_by = DateTimeField(null=True)

    def __repr__(self):
        return "<Host fqdn=%s / uuid=%s>"% (self.host_fqdn,self.uuid)

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

def test_pg():
    init_db()

    r = WaptHosts.create(uuid=data['uuid'],host_fqdn=data['host']['computer_fqdn'],host_data=data)
    print r.uuid
    for h in WaptHosts.select().where(Hosts.uuid == r.uuid):
        print h.host_data['uuid']

    for h in WaptHosts.select().where(Hosts.host_data['uuid'] == r.uuid):
        print h.host_data['host']['computer_fqdn']

    print list(WaptHosts.select(WaptHosts.uuid,WaptHosts.host_fqdn).where(WaptHosts.host_data['host']['description'].regexp('.*Papin.*') ))
    for r in wapt_db.execute_sql("""select host_fqdn,
                                           jsonb_extract_path_text(host_data,'wapt','listening_address','address') as listening_address,
                                           jsonb_extract_path_text(host_data,'host_status') as host_status
                                        from wapthosts where jsonb_extract_path_text(host_data,'wapt','listening_address','address') ilike '10.10.12%%'
                                """):
        print r


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
        data = json.load(codecs.open(fn,'rb',encoding='utf8'))

        for host in data:
            computer_fqdn = host['host']['computer_fqdn']
            try:
                try:
                    WaptHosts.create(uuid=host['uuid'],host_fqdn=host['host']['computer_fqdn'],host_data=host)
                    print('%s Inserted'%computer_fqdn)
                except IntegrityError as e:
                    wapt_db.rollback()
                    WaptHosts.update(host_fqdn=host['host']['computer_fqdn'],host_data=host).where(WaptHosts.uuid == host['uuid'])
                    print('%s Inserted'%computer_fqdn)
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

#import_shapers()

#init_db(False)
#load_json(r"c:\tmp\*.json")
print WaptHosts.get(Hosts.uuid == 'sd')



