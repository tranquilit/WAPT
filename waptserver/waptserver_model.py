#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013  Tranquil IT Systems http://www.tranquil.it
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users PC.
#
#    WAPT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    WAPT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with WAPT.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------
__version__ = "1.4.0"

import os
import sys
import psutil
import datetime
import subprocess
import getpass
import traceback
import platform

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
    reachable = CharField(20,null=True)

    # netbios name
    computer_name = CharField(null=True)
    current_user = CharField(null=True)

    computer_type = CharField(null=True)  # tower, laptop,etc..
    computer_architecture = CharField(null=True)  # tower, laptop,etc..
    manufacturer = CharField(null=True)
    productname = CharField(null=True)
    serialnr = CharField(null=True)

    os_name = CharField(null=True)
    os_version = CharField(null=True)
    os_architecture = CharField(null=True)

    connected_ips = ArrayField(CharField,null=True)
    mac_addresses = ArrayField(CharField,null=True)
    gateways = ArrayField(CharField,null=True)
    networks = ArrayField(CharField,null=True)

    connected_users = CharField(null=True)

    listening_protocol = CharField(10,null=True)
    listening_address = CharField(null=True)
    listening_port = IntegerField(null=True)
    listening_timestamp = CharField(null=True)

    host_status = CharField(null=True)
    last_seen_on = CharField(null=True)

    # raw data from hosts
    wapt = BinaryJSONField(null=True)
    # running, pending, errors, finished
    # upgradable, errors,
    update_status = BinaryJSONField(null=True)

    # to do : moved to separate tables the json packages and softwares
    packages = BinaryJSONField(null=True)
    softwares = BinaryJSONField(null=True)

    # variable structures... so keep them as json
    host = BinaryJSONField(null=True)
    dmi = BinaryJSONField(null=True)
    wmi = BinaryJSONField(null=True)

    # audit data
    created_on = DateTimeField(null=True,default=datetime.datetime.now)
    created_by = DateTimeField(null=True)
    updated_on = DateTimeField(null=True,default=datetime.datetime.now)
    updated_by = DateTimeField(null=True)

    def __repr__(self):
        return "<Host fqdn=%s / uuid=%s>"% (self.computer_fqdn,self.uuid)

    @classmethod
    def fieldbyname(cls,fieldname):
        return cls._meta.fields[fieldname]

def dictgetpath(adict,pathstr):
    result = adict
    for k in pathstr.split('.'):
        if isinstance(k,(str,unicode)) and isinstance(result,dict):
            result = result.get(k)
        elif isinstance(k,int) and isinstance(result,list) and k<len(result):
            result = result[k]
        elif k == '*' and isinstance(result,list):
            continue
        elif isinstance(k,(str,unicode)) and isinstance(result,list):
            result = [item.get(k) for item in result if item.get(k)]
        else:
            result = None
            break
        if result is None:
            break
    return result

@pre_save(sender=WaptHosts)
def wapthosts_model_audit(model_class, instance, created):
    if (created or WaptHosts.host in instance.dirty_fields) and instance.host:
        extractmap = [
            ['computer_fqdn','computer_fqdn'],
            ['computer_name','computer_name'],
            ['description','description'],
            ['manufacturer','system_manufacturer'],
            ['productname','system_productname'],
            ['os_name','windows_product_infos.version'],
            ['os_version','windows_product_infos.windows_version'],
            ['connected_ips','connected_ips'],
            ['mac_addresses','mac'],
            ['current_user','current_user'],
            ]
        for field,attribute in extractmap:
            setattr(instance,field,dictgetpath(instance.host,attribute))

        instance.os_architecture = 'x64' and instance.host.get('win64','?') or 'x86'

    if (created or WaptHosts.dmi in instance.dirty_fields) and instance.dmi:
        extractmap = [
            ['serialnr','Chassis_Information.Serial_Number'],
            ['computer_type','Chassis_Information.Type'],
            ]
        for field,attribute in extractmap:
            setattr(instance,field,dictgetpath(instance.dmi,attribute))

    if not instance.connected_ips:
        instance.connected_ips = dictgetpath(instance.host,'networking.*.addr')

    if (created or WaptHosts.packages in instance.dirty_fields or WaptHosts.update_status in instance.dirty_fields):
        instance.host_status = None
        if instance.update_status:
            if instance.update_status.get('errors', []):
                instance.host_status = 'ERROR'
            elif instance.update_status.get('upgrades', []):
                instance.host_status = 'TO-UPGRADE'
        if not instance.host_status:
            for package in instance.packages:
                if package['install_status'] == 'ERROR':
                    instance.host_status = 'ERROR'
                    break
                if package['install_status'] == 'NEED-UPGRADE':
                    instance.host_status = 'TO-UPGRADE'
                    break
        instance.host_status = 'OK'

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

def mongo_data(ip='127.0.0.1',port=27017):
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

def create_import_data(ip='127.0.0.1',fn=None):
    """Connect to a mongo instance and write all wapt.hosts collection as json into a file"""
    print('Read mongo data from %s ...'%ip)
    d = mongo_data(ip=ip)
    print('%s records read.'%len(d))
    if fn is None:
        fn = "%s.json"%ip

    #0000 is not accepted by postgresql
    open(fn,'wb').write(json.dumps(d).replace('\u0000',' '))
    print('File %s done.'%fn)

def load_json(filenames=r'c:\tmp\*.json'):
    """Read a json host collection exported from wapt mongo and creates
            WaptHost DB instances"""
    import glob
    convert_map = {
        'last_query_date':'last_seen_on',
    }
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
                        if hasattr(newhost,convert_map.get(k,k)):
                            setattr(newhost,convert_map.get(k,k),rec[k])
                        else:
                            print '%s unknown key %s' % (computer_fqdn,k)
                    newhost.save(force_insert=True)
                    print('%s Inserted (%s)'%(newhost.computer_fqdn,newhost.uuid))
                except IntegrityError as e:
                    wapt_db.rollback()
                    updhost = WaptHosts.get(uuid=uuid)
                    for k in rec.keys():
                        if hasattr(updhost,convert_map.get(k,k)):
                            setattr(updhost,convert_map.get(k,k),rec[k])
                        else:
                            print '%s unknown key %s' % (computer_fqdn,k)
                    updhost.save()
                    print('%s Updated'%computer_fqdn)
            except Exception as e:
                print(u'Error for %s : %s'%(ensure_unicode(computer_fqdn),ensure_unicode(e)))
                wapt_db.rollback()
                raise e

def import_shapers():
    for ip in ('wapt-shapers.intra.sermo.fr','wapt-polska.intra.sermo.fr','wapt-india.intra.sermo.fr','wapt-china.intra.sermo.fr'):
        fn = r'c:\tmp\shapers\%s.json' % ip
        if not os.path.isfile(fn):
            create_import_data(ip,fn)

    init_db(False)
    load_json(r'c:\tmp\shapers\*.json')

def tests():
    print WaptHosts.select().count()
    print list(WaptHosts.select(WaptHosts.computer_fqdn,WaptHosts.wapt['wapt-exe-version']).tuples())
    print list(WaptHosts.select(WaptHosts.computer_fqdn,WaptHosts.wapt['wapt-exe-version'].alias('waptversion')).dicts())
    for h in WaptHosts.select(WaptHosts.uuid,WaptHosts.computer_fqdn,WaptHosts.host,WaptHosts.wapt).where(WaptHosts.wapt['waptserver']['dnsdomain'] == 'aspoland.lan' ):
        print h.computer_fqdn,h.host['windows_version'],h.wapt['wapt-exe-version']

def comment_mongodb_lines(conf_filename = '/opt/wapt/conf/waptserver.ini'):
    if not os.path.exists(conf_filename):
        print ("file %s does not exists!! Exiting " %  conf_filename)
        sys.exit(1)
    data = open(conf_filename)
    new_conf_file_data = ""
    modified = False
    for line in data.readlines():
        line = line.strip()
        if "mongodb_port" in line:
            line = '#%s' % line
            modified = True
        elif 'mongodb_ip' in line:
            line = '#%s' % line
            modified = True
        new_conf_file_data = new_conf_file_data + line + '\n'
    print new_conf_file_data
    if modified ==True:
        os.rename (conf_filename,"%s.%s" % (conf_filename,datetime.datetime.today().strftime('%Y%m%d-%H:%M:%S')))
        with open(conf_filename, "w") as text_file:
            text_file.write(new_conf_file_data)


def upgrade2postgres():
    # check if mongo is runnina
    print "upgrading data from mongodb to postgresql"
    mongo_running = False
    for proc in psutil.process_iter():
        if proc.name() == 'mongod':
            mongo_running=True
    if not mongo_running:
        print ("mongodb process not running, please check your configuration. Perhaps migration of data has already been done...")
        sys.exit(1)
    val = subprocess.check_output("""  psql wapt -c " SELECT datname FROM pg_database WHERE datname='wapt';   " """, shell=True)
    if 'wapt' not in val:
        print ("missing wapt database, please create database first")
        sys.exit(1)
    data_import_filename = "/tmp/waptupgrade_%s.json" % datetime.datetime.today().strftime('%Y%m%d-%h:%M:%s')
    print ("dumping mongodb data in %s " % data_import_filename)
    create_import_data(ip='127.0.0.1',fn=data_import_filename)
    try:
        load_json(filenames=data_import_filename)
        # TODO : check that data is properly imported
        subprocess.check_output('systemctl stop mongodb')
        subprocess.check_output('systemctl disable mongodb')

    except Exception as e:
        traceback.print_stack()
        print ('Exception while loading data, please check current configuration')
        sys.exit(1)


if __name__ == '__main__':
    #init_db(True)
    #import_shapers()

    if platform.system != 'Windows' and getpass.getuser()!='wapt':
        print """you should run this program as wapt:
                     sudo -u wapt python /opt/wapt/waptserver/waptserver_model.py  <action>"""
        sys.exit(1)
    print sys.argv
    if len(sys.argv)>1:
        print sys.argv[1]
        if sys.argv[1]=='init_db':
            print ("initializing wapt database")
            init_db(False)
            sys.exit(0)
        if sys.argv[1] == 'upgrade2postgres':
            print('upgrading from mongodb to postgres')
            comment_mongodb_lines()
            #upgrade2postgres()
    else:
        print ("""usage :
                python waptserver_model.py init_db
                python waptserver_model.py upgrade2postgres
                """)


