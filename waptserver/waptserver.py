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
__version__="0.9.0"

import os,sys
try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0,os.path.join(wapt_root_dir))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib'))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib','site-packages'))

from flask import request, Flask,Response, send_from_directory, session, g, redirect, url_for, abort, render_template, flash
import time
import json
import hashlib
from passlib.hash import sha512_crypt,bcrypt
import pymongo
from pymongo import MongoClient
from werkzeug import secure_filename
from functools import wraps
import logging
import ConfigParser
import logging
import codecs
import zipfile
import platform
import pprint
import socket
import requests
import subprocess
import tempfile
import traceback

from rocket import Rocket

import thread
import threading

from waptpackage import *
import pefile

import itsdangerous

from optparse import OptionParser
usage="""\
%prog -c configfile [action]

WAPTServer daemon.

action is either :
  <nothing> : run service in foreground
  install   : install as a Windows service managed by nssm

"""

parser=OptionParser(usage=usage,version='waptserver.py ' + __version__)
parser.add_option("-c","--config", dest="configfile", default=os.path.join(wapt_root_dir,'waptserver','waptserver.ini'), help="Config file full path (default: %default)")
parser.add_option("-l","--loglevel", dest="loglevel", default=None, type='choice',  choices=['debug','warning','info','error','critical'], metavar='LOGLEVEL',help="Loglevel (default: warning)")

(options,args)=parser.parse_args()

# setup logging
logger = logging.getLogger()
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')

def setloglevel(logger,loglevel):
    """set loglevel as string"""
    if loglevel in ('debug','warning','info','error','critical'):
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % loglevel)
        logger.setLevel(numeric_level)

# force loglevel
if options.loglevel is not None:
    setloglevel(logger,options.loglevel)

log_directory = os.path.join(wapt_root_dir,'log')
if not os.path.exists(log_directory):
    os.mkdir(log_directory)

hdlr = logging.StreamHandler(sys.stdout)
hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logger.addHandler(hdlr)

hdlr = logging.FileHandler(os.path.join(log_directory,'waptserver.log'))
hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logger.addHandler(hdlr)

# read configuration from waptserver.ini
config = ConfigParser.RawConfigParser()
if os.path.exists(options.configfile):
    config.read(options.configfile)
else:
    raise Exception("FATAL. Couldn't open config file : " + options.configfile)

#default mongodb configuration for wapt
mongodb_port = "38999"
mongodb_ip = "127.0.0.1"

wapt_folder = ""
wapt_user = ""
wapt_password = ""

waptserver_port = 8080
waptservice_port = 8088

if config.has_section('options'):
    if config.has_option('options', 'wapt_user'):
        wapt_user = config.get('options', 'wapt_user')
    else:
        wapt_user='admin'

    if config.has_option('options', 'waptserver_port'):
        waptserver_port = config.get('options', 'waptserver_port')

    if config.has_option('options', 'wapt_password'):
        wapt_password = config.get('options', 'wapt_password')
    else:
        raise Exception ('No waptserver admin password set in wapt-get.ini configuration file')

    if config.has_option('options', 'mongodb_port'):
        mongodb_port = config.get('options', 'mongodb_port')

    if config.has_option('options', 'mongodb_ip'):
        mongodb_ip = config.get('options', 'mongodb_ip')

    if config.has_option('options', 'wapt_folder'):
        wapt_folder = config.get('options', 'wapt_folder')
        if wapt_folder.endswith('/'):
            wapt_folder = wapt_folder[:-1]

    if options.loglevel is None and config.has_option('options', 'loglevel'):
        loglevel = config.get('options', 'loglevel')
        setloglevel(logger,loglevel)

else:
    raise Exception ("FATAL, configuration file " + options.configfile + " has no section [options]. Please check Waptserver documentation")

# XXX keep in sync with scripts/postconf.py
if not wapt_folder:
    wapt_folder = os.path.join(wapt_root_dir,'waptserver','repository','wapt')

waptsetup = os.path.join(wapt_folder, 'waptsetup.exe')

# Setup initial directories
if os.path.exists(wapt_folder)==False:
    try:
        os.makedirs(wapt_folder)
    except:
        raise Exception("Folder missing : %s" % wapt_folder)
if os.path.exists(wapt_folder + '-host')==False:
    try:
        os.makedirs(wapt_folder + '-host')
    except:
        raise Exception("Folder missing : %s-host" % wapt_folder )
if os.path.exists(wapt_folder + '-group')==False:
    try:
        os.makedirs(wapt_folder + '-group')
    except:
        raise Exception("Folder missing : %s-group" % wapt_folder )

ALLOWED_EXTENSIONS = set(['wapt'])

app = Flask(__name__,static_folder='./templates/static')
#app.secret_key = config.get('options','secret_key')

def hosts():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'client'):
        try:
            logger.debug('Connecting to mongo db %s:%s'%(mongodb_ip, int(mongodb_port)))
            g.client = MongoClient(mongodb_ip, int(mongodb_port))
            g.db = g.client.wapt
            g.hosts = g.db.hosts
            g.hosts.ensure_index('uuid',unique=True)
            g.hosts.ensure_index('computer_name',unique=False)
        except Exception as e:
            raise Exception(u"Could not connect do mongodb database: %s"%(repr(e),))
    return g.hosts

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'client'):
        logger.debug('Disconnected from mongodb')
        del g.hosts
        del g.db
        del g.client

def get_host_data(uuid, filter = {}, delete_id = True):
    if filter:
        data = hosts().find_one({ "uuid": uuid}, filter)
    else:
        data = hosts().find_one({ "uuid": uuid})
    if data and delete_id:
        data.pop("_id")
    return data


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/info')
def informations():
    informations = {}
    informations["server_version"] = __version__
    if os.path.exists(waptsetup):
        pe = pefile.PE(waptsetup)
        informations["client_version"] =  pe.FileInfo[0].StringTable[0].entries['ProductVersion'].strip()

    return Response(response=json.dumps(informations),
                     status=200,
                     mimetype="application/json")


@app.route('/wapt/')
def wapt_listing():
    return render_template('listing.html',data=data)


@app.route('/hosts')
@app.route('/json/host_list',methods=['GET'])
def get_host_list():
    list_hosts = []
    params = request.args
    query = {}
    search_filter = ""
    search = ""
    try:
        if "package_error" in params.keys() and params['package_error'] == "true":
            query["packages.install_status"] = "ERROR"
        if "need_upgrade" in params.keys() and params['need_upgrade'] == "true":
            query["update_status.upgrades"] = {"$exists": "true", "$ne" :[]}
        if "q" in params.keys():
            search = params['q'].lower()
        if "filter" in params.keys():
            search_filter = params['filter'].split(',')

        filters = []

        #{"host":1,"dmi":1,"uuid":1, "wapt":1, "update_status":1,"last_query_date":1}
        if search:
            if not search_filter or 'host' in search_filter:
                filters.append({'host.computer_fqdn':re.compile(search, re.IGNORECASE)})
                filters.append({'host.current_user':re.compile(search, re.IGNORECASE)})
                filters.append({'host.description':re.compile(search, re.IGNORECASE)})
                filters.append({'host.connected_ips':re.compile(search, re.IGNORECASE)})
                filters.append({'host.mac':re.compile(search, re.IGNORECASE)})
                filters.append({'dmi.Chassis_Information.Serial_Number':re.compile(search, re.IGNORECASE)})
            if not search_filter or 'dmi' in search_filter:
                filters.append({'dmi':re.compile(search, re.IGNORECASE)})
            if not search_filter or 'softwares' in search_filter:
                filters.append({'softwares.name':re.compile(search, re.IGNORECASE)})
            if not search_filter or 'packages' in search_filter:
                filters.append({'packages.package':re.compile(search, re.IGNORECASE)})

        if filters:
            if len(filters)>1:
                query['$or'] = filters
            else:
                query = filters[0]

        for host in hosts().find(query,fields={'softwares':0,'packages':0}):
            host.pop("_id")
            list_hosts.append(host)

        result = list_hosts
    except Exception as e:
        result = dict(status='ERROR',message='%s: %s'%('hosts',e),result=None)

    return Response(response=json.dumps(result),
                     status=200,
                     mimetype="application/json")


def update_data(data):
    data['last_query_date'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    host = get_host_data(data["uuid"],delete_id=False)
    if host:
        hosts().update({"_id" : host['_id'] }, {"$set": data})
    else:
        host_id = hosts().insert(data)
    return get_host_data(data["uuid"],filter={"uuid":1,"host":1})


@app.route('/add_host',methods=['POST'])
@app.route('/update_host',methods=['POST'])
def update_host():
    """Update localstatus of computer, and return known registration info"""
    try:
        data = json.loads(request.data)
        if data:
            uuid = data["uuid"]
            if uuid:
                logger.info('Update host %s status'%(uuid,))
                result = dict(status='OK',message="update_host: No data supplied",result=update_data(data))
            else:
                result = dict(status='ERROR',message="update_host: No uuid supplied")
        else:
            result = dict(status='ERROR',message="update_host: No data supplied")

    except Exception as e:
        result = dict(status='ERROR',message='%s: %s'%('update_host',e),result=None)

    # backward... to fix !
    if result['status'] == 'OK':
        return Response(response=json.dumps(result['result']),
                         status=200,
                         mimetype="application/json")
    else:
        return Response(response=json.dumps(result),
                         status=200,
                         mimetype="application/json")


@app.route('/delete_host/<string:uuid>')
def delete_host(uuid=""):
    try:
        hosts().remove({'uuid': uuid })
        data = get_host_data(uuid)
        result = dict(status='OK',message=json.dumps(data))
    except Exception as e:
        result = dict(status='ERROR',message=u"%s"%e)
    return Response(response=json.dumps(data),
                 status=200,
                 mimetype="application/json")


# to fix !
@app.route('/client_software_list/<string:uuid>')
def get_client_software_list(uuid=""):
    softwares = get_host_data(uuid, filter={"softwares":1})
    if 'softwares' in softwares:
        return  Response(response=json.dumps(softwares['softwares']),
                         status=200,
                         mimetype="application/json")
    else:
        return "{}"

def packagesFileToList(pathTofile):
    listPackages = codecs.decode(zipfile.ZipFile(pathTofile).read(name='Packages'),'utf-8')
    packages = []

    def add_package(lines):
        package = PackageEntry()
        package.load_control_from_wapt(lines)
        package.filename = package.make_package_filename()
        packages.append(package)

    lines = []
    for line in listPackages.splitlines():
        # new package
        if line.strip()=='':
            add_package(lines)
            lines = []
            # add ettribute to current package
        else:
            lines.append(line)

    if lines:
        add_package(lines)
        lines = []

    packages.sort()
    return packages


@app.route('/host_packages/<string:uuid>')
def host_packages(uuid=""):
    try:
        packages = get_host_data(uuid, {"packages":1})
        if not packages:
            raise Exception('No host with uuid %s'%uuid)
        repo_packages = packagesFileToList(os.path.join(wapt_folder, 'Packages'))
        if 'packages' in packages:
            for p in packages['packages']:
                package = PackageEntry()
                package.load_control_from_dict(p)
                matching = [ x for x in repo_packages if package.package == x.package ]
                if matching:
                    if package < matching[-1]:
                        p['install_status'] = 'NEED-UPGRADE'
        result = dict(status='OK',message='%i packages for host uuid: %s'%(len(packages['packages']),uuid),result = packages['packages'])
    except Exception as e:
        result = dict(status='ERROR',message='%s: %s'%('host_packages',e),result=None)

    return Response(response=json.dumps(result),
                     status=200,
                     mimetype="application/json")


@app.route('/client_package_list/<string:uuid>')
def get_client_package_list(uuid=""):
    try:
        packages = get_host_data(uuid, {"packages":1})
        if not packages:
            raise Exception('No host with uuid %s'%uuid)
        repo_packages = packagesFileToList(os.path.join(wapt_folder, 'Packages'))
        if 'packages' in packages:
            for p in packages['packages']:
                package = PackageEntry()
                package.load_control_from_dict(p)
                matching = [ x for x in repo_packages if package.package == x.package ]
                if matching:
                    if package < matching[-1]:
                        p['install_status'] = 'NEED-UPGRADE'
        result = dict(status='OK',message='%i packages for host uuid: %s'%(len(packages['packages']),uuid),result = packages['packages'])
        return Response(response=json.dumps(packages['packages']),
                         status=200,
                         mimetype="application/json")
    except Exception as e:
        result = dict(status='ERROR',message='%s: %s'%('get_client_package_list',e),result=None)

    return Response(response=json.dumps(packages['packages']),
                     status=200,
                     mimetype="application/json")


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization

        if not auth:
            logger.info('no credential given')
            return authenticate()

        logging.debug("authenticating : %s" % auth.username)
        if not check_auth(auth.username, auth.password):
            return authenticate()
        logger.info("user %s authenticated" % auth.username)
        return f(*args, **kwargs)
    return decorated

def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """

    def any_(l):
        """Check if any element in the list is true, in constant time.
        """
        ret = False
        for e in l:
            if e:
                ret = True
        return ret

    user_ok = False
    pass_sha1_ok = pass_sha512_ok = pass_sha512_crypt_ok = pass_bcrypt_crypt_ok = False

    user_ok = wapt_user == username

    pass_sha1_ok = wapt_password == hashlib.sha1(password).hexdigest()
    pass_sha512_ok = wapt_password == hashlib.sha512(password).hexdigest()

    if sha512_crypt.identify(wapt_password):
        pass_sha512_crypt_ok  = sha512_crypt.verify(password, wapt_password)
    elif bcrypt.identify(wapt_password):
        pass_bcrypt_crypt_ok = bcrypt.verify(password, wapt_password)

    #                                    sha512_crypt.encrypt('TIS', rounds=1000000)
    #ret = sha512_crypt.verify(password, '$6$rounds=100000$UyHraKoqY8Wm27eT$wsaNea6wq1ZHPeiJljLQRpuSHD3BaxPU9c8yacw5dy0z8TshCIMUjaVFCU93Lm2lJFMVIOwVIXozsw5kenxzh/')
    #pass_sha512_crypt_ok = False

    return any_([pass_sha1_ok, pass_sha512_ok, pass_sha512_crypt_ok, pass_bcrypt_crypt_ok]) and user_ok


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


@app.route('/upload_package/<string:filename>',methods=['POST'])
@requires_auth
def upload_package(filename=""):
    try:
        tmp_target = ''
        if request.method == 'POST':
            if filename and allowed_file(filename):
                tmp_target = os.path.join(wapt_folder, secure_filename(filename+'.tmp'))
                with open(tmp_target, 'wb') as f:
                    f.write(request.stream.read())
                if not os.path.isfile(tmp_target):
                    result = dict(status='ERROR',message='Problem during upload')
                else:
                    if PackageEntry().load_control_from_wapt(tmp_target):
                        target = os.path.join(wapt_folder, secure_filename(filename))
                        if os.path.isfile(target):
                            os.unlink(target)
                        os.rename(tmp_target,target)
                        data = update_packages(wapt_folder)
                        result = dict(status='OK',message='%s uploaded, %i packages analysed'%(filename,len(data['processed'])),result=data)
                    else:
                        result = dict(status='ERROR',message='Not a valid wapt package')
                        os.unlink(tmp_target)
            else:
                result = dict(status='ERROR',message='Wrong file type')
        else:
            result = dict(status='ERROR',message='Unsupported method')
    except:
        # remove temporary
        if os.path.isfile(tmp_target):
            os.unlink(tmp_target)
        e = sys.exc_info()
        logger.critical(repr(traceback.format_exc()))
        result = dict(status='ERROR',message='unexpected: %s'%(e,))
    return  Response(response=json.dumps(result),
                         status=200,
                         mimetype="application/json")


@app.route('/upload_host',methods=['POST'])
@requires_auth
def upload_host():
    try:
        file = request.files['file']
        if file:
            logger.debug('uploading host file : %s' % file)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                wapt_host_folder = os.path.join(wapt_folder+'-host')
                tmp_target = os.path.join(wapt_host_folder, filename+'.tmp')
                target = os.path.join(wapt_host_folder, filename)
                file.save(tmp_target)
                if os.path.isfile(tmp_target):
                    try:
                        # try to read attributes...
                        entry = PackageEntry().load_control_from_wapt(tmp_target)
                        if os.path.isfile(target):
                            os.unlink(target)
                        os.rename(tmp_target,target)
                        data = update_packages(wapt_host_folder)
                        result = dict(status='OK',message='File %s uploaded to %s'%(file.filename,target))
                    except:
                        if os.path.isfile(tmp_target):
                            os.unlink(tmp_target)
                        raise
                else:
                    result = dict(status='ERROR',message='No data received')
            else:
                result = dict(status='ERROR',message='Wrong file type')
        else:
            result = dict(status='ERROR',message='No package file provided in request')
    except:
        # remove temporary
        if os.path.isfile(tmp_target):
            os.unlink(tmp_target)
        e = sys.exc_info()
        logger.critical(repr(traceback.format_exc()))
        result = dict(status='ERROR',message='upload_host: %s'%(e,))
    return  Response(response=json.dumps(result),
                         status=200,
                         mimetype="application/json")


@app.route('/upload_waptsetup',methods=['POST'])
@requires_auth
def upload_waptsetup():
    logger.debug("Entering upload_waptsetup")
    tmp_target = None
    try:
        if request.method == 'POST':
            file = request.files['file']
            if file and "waptsetup.exe" in file.filename :
                filename = secure_filename(file.filename)
                tmp_target = os.path.join(wapt_folder, secure_filename('.'+filename))
                target = os.path.join(wapt_folder, secure_filename(filename))
                file.save(tmp_target)
                if not os.path.isfile(tmp_target):
                    result = dict(status='ERROR',message='Problem during upload')
                else:
                    os.rename(tmp_target,target)
                    result = dict(status='OK',message='%s uploaded'%(filename,))
            else:
                result = dict(status='ERROR',message='Wrong file name')
        else:
            result = dict(status='ERROR',message='Unsupported method')
    except:
        e = sys.exc_info()
        if tmp_target and os.path.isfile(tmp_target):
            os.unlink(tmp_target)
        result = dict(status='ERROR',message='unexpected: %s'%(e,))
    return  Response(response=json.dumps(result),
                         status=200,
                         mimetype="application/json")


@app.route('/waptupgrade_host/<string:ip>')
@requires_auth
def waptupgrade_host(ip):
    try:
        result = {}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip,waptservice_port))
            s.close
            if ip and waptservice_port:
                logger.info( "Upgrading %s..." % ip)
                try:
                    httpreq = requests.get("http://%s:%d/waptupgrade.json" % ( ip, waptservice_port),proxies=None)
                    httpreq.raise_for_status()
                    result = {'status' : 'OK', 'message': u"%s" % httpreq.text }
                except Exception as e:
                    logger.warning(u'%s'%e)
                    r = requests.get("http://%s:%d/waptupgrade" % ( ip, waptservice_port),proxies=None)
                    if "OK" in r.text.upper():
                        result = {  'status' : 'OK', 'message': u"%s" % r.text }
                    else:
                        result = {  'status' : 'ERROR', 'message': u"%s" % r.text }
            else:
                raise Exception(u"Le port de waptservice n'est pas défini")

        except Exception as e:
            raise Exception("Impossible de joindre le waptservice: %s" % e)

    except Exception, e:
            result = { 'status' : 'ERROR', 'message': u"%s" % e  }

    return  Response(response=json.dumps(result),
                         status=200,
                         mimetype="application/json")


@app.route('/install_package')
@app.route('/install_package.json')
@requires_auth
def install_package():
    try:
        result = {}
        try:
            package = request.args['package']
            ip = request.args['host']
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip,waptservice_port))
            s.close
            if ip and waptservice_port:
                logger.info( "installing %s on %s ..." % (package,ip))
                data = json.loads(requests.get("http://%s:%d/install.json?package=%s" % ( ip, waptservice_port,package),proxies=None).text)
                result = dict(message=data,status='OK')
            else:
                raise Exception(u"Le port de waptservice n'est pas défini")

        except Exception as e:
            raise Exception("Impossible de joindre le web service: %s" % e)

    except Exception, e:
            result = { 'status' : 'ERROR', 'message': u"%s" % e  }
    return  Response(response=json.dumps(result),
                         status=200,
                         mimetype="application/json")


@app.route('/remove_package')
@app.route('/remove_package.json')
@requires_auth
def remove_package():
    try:
        result = {}
        try:
            package = request.args['package']
            ip = request.args['host']
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip,waptservice_port))
            s.close
            if ip and waptservice_port:
                logger.info( "removing %s on %s ..." % (package,ip))
                httpreq = requests.get("http://%s:%d/remove.json?package=%s" % ( ip, waptservice_port,package),proxies=None)
                httpreq.raise_for_status()
                data = json.loads(httpreq.text)
                result = dict(message=data,status='OK')
            else:
                raise Exception(u"Le port de waptservice n'est pas défini")

        except Exception as e:
            raise Exception("Impossible de joindre le waptservice du poste: %s" % e)

    except Exception, e:
            result = { 'status' : 'ERROR', 'message': u"%s" % e  }
    return  Response(response=json.dumps(result),
                         status=200,
                         mimetype="application/json")


@app.route('/forget_packages')
@app.route('/forget_packages.json')
@requires_auth
def forget_packages():
    try:
        result = {}
        try:
            package = request.args['package']
            ip = request.args['host']
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip,waptservice_port))
            s.close
            if ip and waptservice_port:
                logger.info( "Forgetting %s on %s ..." % (package,ip))
                httpreq = requests.get("http://%s:%d/forget.json?package=%s" % ( ip, waptservice_port,package),proxies=None)
                httpreq.raise_for_status()
                data = json.loads(httpreq.text)
                result = dict(message=data,status='OK')
            else:
                raise Exception(u"Le port de waptservice n'est pas défini")

        except Exception as e:
            raise Exception("Impossible de joindre le waptservice du poste: %s" % e)

    except Exception, e:
            result = { 'status' : 'ERROR', 'message': u"%s" % e  }
    return  Response(response=json.dumps(result),
                         status=200,
                         mimetype="application/json")



@app.route('/host_tasks')
@app.route('/host_tasks.json')
@requires_auth
def host_tasks():
    try:
        result = {}
        try:
            ip = request.args['host']
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip,waptservice_port))
            s.close
            if ip and waptservice_port:
                data = json.loads(requests.get("http://%s:%d/tasks.json" % ( ip, waptservice_port),proxies=None).text)
                result = dict(message=data,status='OK')
            else:
                raise Exception(u"Le port de waptservice n'est pas défini")

        except Exception as e:
            raise Exception("Impossible de joindre le web service: %s" % e)

    except Exception, e:
            result = { 'status' : 'ERROR', 'message': u"%s" % e  }
    return  Response(response=json.dumps(result),
                         status=200,
                         mimetype="application/json")


@app.route('/host_taskkill')
@app.route('/host_taskkill.json')
@requires_auth
def host_taskkill():
    try:
        result = {}
        try:
            ip = request.args['host']
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip,waptservice_port))
            s.close
            if ip and waptservice_port:
                data = json.loads(requests.get("http://%s:%d/cancel_running_task.json" % ( ip, waptservice_port),proxies=None).text)
                result = dict(message=data,status='OK')
            else:
                raise Exception(u"Le port de waptservice n'est pas défini")

        except Exception as e:
            raise Exception("Impossible de joindre le web service: %s" % e)

    except Exception, e:
            result = { 'status' : 'ERROR', 'message': u"%s" % e  }
    return  Response(response=json.dumps(result),
                         status=200,
                         mimetype="application/json")


@app.route('/hosts_by_group/<string:name>')
@requires_auth
def get_hosts_by_group(name=""):
    try:
        list_hosts  =  []
        os.chdir(wapt_folder + '-host')
        hosts = [f for f in os.listdir('.') if os.path.isfile(f) and f.endswith('.wapt')]
        package = PackageEntry()
        for h in hosts:
            package.load_control_from_wapt(h)
            if name in package.depends.split(','):
                list_hosts.append({"computer_fqdn":package.package})

        return  Response(response=json.dumps(list_hosts),
                         status=200,
                         mimetype="application/json")
    except:
        e = sys.exc_info()
        return str(e)
    return "Unsupported method"


@app.route('/upgrade_host/<string:ip>')
@requires_auth
def upgrade_host(ip):
    """Proxy the wapt upgrade action to the client"""
    try:
        result = {}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip,waptservice_port))
            s.close
            if ip and waptservice_port:
                logger.info( "Upgrading %s..." % ip)
                try:
                    result = json.loads(requests.get("http://%s:%d/upgrade.json" % ( ip, waptservice_port),proxies=None).text)
                except Exception as e:
                    # try the old behaviour for wapt client < 0.8.10
                    logger.warning(u"%s"%e)
                    r = requests.get("http://%s:%d/upgrade" % ( ip, waptservice_port),proxies=None)
                    if "OK" in r.text.upper():
                        result = {  'status' : 'OK', 'message': u"%s" % r.text }
                    else:
                        result = {  'status' : 'ERROR', 'message': u"%s" % r.text }

            else:
                raise Exception(u"Le port de waptservice n'est pas défini")

        except Exception as e:
            raise  Exception("Impossible de joindre le web service: %s" % e)

    except Exception, e:
            result = { 'status' : 'ERROR', 'message': u"%s" % e  }
    return  Response(response=json.dumps(result),
                         status=200,
                         mimetype="application/json")


def install_wapt(computer_name,authentication_file):
    cmd = '/usr/bin/smbclient -G -E -A %s  //%s/IPC$ -c listconnect ' % (authentication_file, computer_name)
    try:
        subprocess.check_output(cmd,stderr=subprocess.STDOUT,shell=True)
    except subprocess.CalledProcessError as e:
        if "NT_STATUS_LOGON_FAILURE" in e.output:
            raise Exception("Mauvais identifiants")
        if "NT_STATUS_CONNECTION_REFUSED" in e.output:
            raise Exception("Partage IPC$ non accessible")

        raise Exception(u"%s" % e.output)

    cmd = '/usr/bin/smbclient -A "%s" //%s/c\\$ -c "put waptsetup.exe" ' % (authentication_file, computer_name)
    print subprocess.check_output(cmd,shell=True)

    cmd = '/usr/bin/winexe -A "%s"  //%s  "c:\\waptsetup.exe  /MERGETASKS=""useWaptServer,autorunTray"" /VERYSILENT"  ' % (authentication_file, computer_name)
    print subprocess.check_output(cmd,shell=True)

#    cmd = '/usr/bin/smbclient -A "%s" //%s/c\\$ -c "cd wapt ; put wapt-get.ini ; exit" ' % (authentication_file, computer_name)
#    print subprocess.check_output(cmd,shell=True)

    cmd = '/usr/bin/winexe -A "%s"  //%s  "c:\\wapt\\wapt-get.exe register"' % (authentication_file, computer_name)
    print subprocess.check_output(cmd,shell=True)

    cmd = '/usr/bin/winexe -A "%s"  //%s  "c:\\wapt\\wapt-get.exe --version"' % (authentication_file, computer_name)
    return subprocess.check_output(cmd,shell=True)


@app.route('/deploy_wapt',methods=['POST'])
@requires_auth
def deploy_wapt():
    try:
        result = {}
        if platform.system() != 'Linux':
            raise Exception(u'Le serveur wapt doit être executé sous Linux')
        if subprocess.call('which smbclient',shell=True) != 0:
            raise Exception(u"smbclient n'est pas installé sur le serveur wapt")
        if subprocess.call('which winexe',shell=True) != 0:
            raise Exception(u"winexe n'est pas installé sur le serveur wapt")

        if request.method == 'POST':
            d = json.loads(request.data)
            if 'auth' not in d:
                raise Exception("Les informations d'authentification sont manquantes")
            if 'computer_fqdn' not in d:
                raise Exception(u"Il n'y a aucuns ordinateurs de renseigné")

            auth_file = tempfile.mkstemp("wapt")[1]
            try:
                with open(auth_file, 'w') as f:
                    f.write('username = %s\npassword = %s\ndomain = %s\n'% (
                        d['auth']['username'],
                        d['auth']['password'],
                        d['auth']['domain']))

                os.chdir(wapt_folder)

                message = install_wapt(d['computer_fqdn'],auth_file)

                result = { 'status' : 'OK' , 'message': message}
            finally:
                os.unlink(auth_file)

        else:
            raise Exception(u"methode http non supportée")

    except Exception, e:
        result = { 'status' : 'ERROR', 'message': u"%s" % e  }

    return  Response(response=json.dumps(result),
                         status=200,
                         mimetype="application/json")


def rewrite_password(cfg_file, password):
    config = ConfigParser.RawConfigParser()
    config.read(cfg_file)
    config.set('options', 'wapt_password', password)
    with open(cfg_file, 'wb') as cfg:
        config.write(cfg)

@app.route('/login',methods=['POST'])
def login():
    try:
        if request.method == 'POST':
            d= json.loads(request.data)
            if "username" in d and "password" in d:
                if check_auth(d["username"], d["password"]):
                    if "newPass" in d:
                        global wapt_password
                        wapt_password = sha512_crypt.encrypt(d["newPass"], rounds=100000)
                        rewrite_password(options.configfile, wapt_password)
                        # Graceful reload pour prendre en compte le nouveau mot
                        # mot de passe dans tous les workers uwsgi
                        if os.name == "posix":
                            try:
                                import uwsgi
                                uwsgi.reload()
                            except ImportError:
                                pass
                    return "True"
            return "False"
        else:
            return "Unsupported method"
    except:
        e = sys.exc_info()
        return str(e)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/delete_package/<string:filename>')
@requires_auth
def delete_package(filename=""):
    fullpath = os.path.join(wapt_folder,filename)
    try:
        if os.path.isfile(fullpath):
            os.unlink(fullpath)
            data = update_packages(wapt_folder)
            if os.path.isfile("%s.zsync"%(fullpath,)):
                os.unlink("%s.zsync"%(fullpath,))
            result = dict(status='OK',message="Package deleted %s" % (fullpath,),result=data)
        else:
            result = dict(status='ERROR',message="The file %s doesn't exist in wapt folder (%s)" % (filename, wapt_folder))

    except Exception, e:
        result = { 'status' : 'ERROR', 'message': u"%s" % e  }

    return  Response(response=json.dumps(result),
                         status=200,
                         mimetype="application/json")


@app.route('/wapt/<string:input_package_name>')
def get_wapt_package(input_package_name):
    global wapt_folder
    package_name = secure_filename(input_package_name)
    r =  send_from_directory(wapt_folder, package_name)
    if 'content-length' not in r.headers:
        r.headers.add_header('content-length', int(os.path.getsize(os.path.join(wapt_folder,package_name))))
    return r

@app.route('/wapt/icons/<string:iconfilename>')
def serve_icons(iconfilename):
    """Serves a png icon file from /wapt/icons/ test waptserver"""
    global wapt_folder
    iconfilename = secure_filename(iconfilename)
    icons_folder = os.path.join(wapt_folder,'icons')
    r =  send_from_directory(icons_folder,iconfilename)
    if 'content-length' not in r.headers:
        r.headers.add_header('content-length', int(os.path.getsize(os.path.join(icons_folder,iconfilename))))
    return r


@app.route('/wapt-host/<string:input_package_name>')
def get_host_package(input_package_name):
    """Returns a host package (in case there is no apache static files server)"""
    global wapt_folder
    #TODO straighten this -host stuff
    host_folder = wapt_folder + '-host'
    package_name = secure_filename(input_package_name)
    r =  send_from_directory(host_folder, package_name)
    if 'Content-Length' not in r.headers:
        r.headers.add_header('Content-Length', int(os.path.getsize(os.path.join(host_folder,package_name))))
    return r


@app.route('/wapt-group/<string:input_package_name>')
def get_group_package(input_package_name):
    """Returns a group package (in case there is no apache static files server)"""
    global wapt_folder
    #TODO straighten this -group stuff
    group_folder = wapt_folder + '-group'
    package_name = secure_filename(input_package_name)
    r =  send_from_directory(group_folder, package_name)
    # on line content-length is not added to the header.
    if 'content-length' not in r.headers:
        r.headers.add_header('content-length', os.path.getsize(os.path.join(group_folder + '-group',package_name)))
    return r


class CheckHostsWaptService(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.mongoclient = MongoClient(mongodb_ip, int(mongodb_port))
        self.db = mongoclient.wapt
        self.polltimeout = 20

    def get_hosts_ip(self):
        list_hosts = []
        query = {"host.connected_ips":{"$exists": "true", "$ne" :[]}}
        fields = {'host.connected_ips':1,'uuid':1,'host.computer_fqdn':1}
        result = {}
        for host in self.db.hosts.find(query,fields=fields):
            result[host['uuid']] = host['host.connected_ips']
        return result

    def run(self):
        pass


def install_windows_nssm_service(service_name,service_binary,service_parameters,service_logfile,service_dependencies=None):
    """Setup a program as a windows Service managed by nssm
    >>> install_windows_nssm_service("WAPTServer",
        os.path.abspath(os.path.join(wapt_root_dir,'waptpython.exe')),
        os.path.abspath(__file__),
        os.path.join(log_directory,'nssm_waptserver.log'),
        service_logfile,
        'WAPTMongodb WAPTApache')
    """
    import setuphelpers
    from setuphelpers import registry_set,REG_DWORD,REG_EXPAND_SZ,REG_MULTI_SZ,REG_SZ
    datatypes = {
        'dword':REG_DWORD,
        'sz':REG_SZ,
        'expand_sz':REG_EXPAND_SZ,
        'multi_sz':REG_MULTI_SZ,
    }

    if setuphelpers.service_installed(service_name):
        if not setuphelpers.service_is_stopped(service_name):
            logger.info('Stop running "%s"' % service_name )
            setuphelpers.run('net stop "%s" /yes' % service_name)
            while not setuphelpers.service_is_stopped(service_name):
                logger.debug('Waiting for "%s" to terminate' % service_name)
                time.sleep(2)
        logger.info('Unregister existing "%s"'% service_name)
        setuphelpers.run('sc delete "%s"' % service_name)

    if setuphelpers.iswin64():
        nssm = os.path.join(wapt_root_dir,'waptservice','win64','nssm.exe')
    else:
        nssm = os.path.join(wapt_root_dir,'waptservice','win32','nssm.exe')

    logger.info('Register service "%s" with nssm' % service_name)
    cmd = '"{nssm}" install "{service_name}" "{service_binary}" {service_parameters}'.format(
        nssm = nssm,
        service_name = service_name,
        service_binary=service_binary,
        service_parameters=service_parameters
     )
    logger.info("running command : %s" % cmd)
    setuphelpers.run(cmd)

    # fix some parameters (quotes for path with spaces...
    params = {
        "Description": "sz:%s" % service_name,
        "DelayedAutostart": 1,
        "DisplayName" : "sz:%s" % service_name,
        "AppStdout" : r"expand_sz:{}".format(service_logfile),
        "Parameters\\AppStderr" : r"expand_sz:{}".format(service_logfile),
        "Parameters\\AppParameters" : r'expand_sz:{}'.format(service_parameters),
        }



    root = setuphelpers.HKEY_LOCAL_MACHINE
    base = r'SYSTEM\CurrentControlSet\services\%s' % service_name
    for key in params:
        if isinstance(params[key],int):
            (valuetype,value) = ('dword',params[key])
        elif ':' in params[key]:
            (valuetype,value) = params[key].split(':',1)
            if valuetype == 'dword':
                value = int(value)
        else:
            (valuetype,value) = ('sz',params[key])
        fullpath = base+'\\'+key
        (path,keyname) = fullpath.rsplit('\\',1)
        if keyname == '@' or keyname =='':
            keyname = None
        registry_set(root,path,keyname,value,type = datatypes[valuetype])

    if service_dependencies !=None:
        logger.info('Register dependencies for service "%s" with nssm : %s ' % (service_name,service_dependencies))
        cmd = '"{nssm}" set "{service_name}" DependOnService {service_dependencies}'.format(
                nssm = nssm,
                service_name = service_name,
                service_dependencies = service_dependencies
        )
        logger.info("running command : %s" % cmd)
        setuphelpers.run(cmd)

        #fullpath = base+'\\' + 'DependOnService'
        #(path,keyname) = fullpath.rsplit('\\',1)
        #registry_set(root,path,keyname,service_dependencies,REG_MULTI_SZ)

def make_httpd_config(wapt_root_dir, wapt_folder):
    import jinja2

    if wapt_folder.endswith('\\') or wapt_folder.endswith('/'):
        wapt_folder = wapt_folder[:-1]

    ap_conf_dir = os.path.join(wapt_root_dir,'waptserver','apache-win32','conf')
    ap_file_name = 'httpd.conf'
    ap_conf_file = os.path.join(ap_conf_dir ,ap_file_name)
    ap_ssl_dir = os.path.join(wapt_root_dir,'waptserver','apache-win32','conf')

    # write config file
    jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(ap_conf_dir))
    template = jinja_env.get_template(ap_file_name + '.j2')
    template_variables = {
        'wapt_repository_path': os.path.dirname(wapt_folder),
        'apache_root_folder':os.path.dirname(ap_conf_dir),
        'windows': True,
        'ssl': False,
        'wapt_ssl_key_file': os.path.join(ap_ssl_dir,'key.pem'),
        'wapt_ssl_cert_file': os.path.join(ap_ssl_dir,'cert.pem')
        }
    config_string = template.render(template_variables)
    dst_file = file(ap_conf_file, 'wt')
    dst_file.write(config_string)
    dst_file.close()


def make_mongod_config(wapt_root_dir):
    import jinja2

    conf_dir = os.path.join(wapt_root_dir,'waptserver','mongodb')
    file_name = 'mongod.cfg'
    conf_file = os.path.join(conf_dir ,file_name)
    jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(conf_dir))
    template = jinja_env.get_template(file_name + '.j2')
    template_variables = {'dbpath':os.path.join(conf_dir,'data'),'logpath':os.path.join(conf_dir,'log','mongodb.log')}
    config_string = template.render(template_variables)
    dst_file = file(conf_file, 'wt')
    dst_file.write(config_string)
    dst_file.close()

def install_windows_service():
    """Setup waptserver, waptmongodb et waptapache as a windows Service managed by nssm
    >>> install_windows_service()
    """

    # register mongodb server
    make_mongod_config(wapt_root_dir)

    service_binary =os.path.abspath(os.path.join(wapt_root_dir,'waptserver','mongodb','mongod.exe'))
    service_parameters = " --config %s " % os.path.join(wapt_root_dir,'waptserver','mongodb','mongod.cfg')
    service_logfile = os.path.join(log_directory,'nssm_waptmongodb.log')
    install_windows_nssm_service("WAPTMongodb",service_binary,service_parameters,service_logfile)

    # register apache frontend
    make_httpd_config(wapt_root_dir, wapt_folder)

    service_binary =os.path.abspath(os.path.join(wapt_root_dir,'waptserver','apache-win32','bin','httpd.exe'))
    service_parameters = ""
    service_logfile = os.path.join(log_directory,'nssm_apache.log')
    install_windows_nssm_service("WAPTApache",service_binary,service_parameters,service_logfile)

    # register waptserver
    service_binary = os.path.abspath(os.path.join(wapt_root_dir,'waptpython.exe'))
    service_parameters = os.path.abspath(__file__)
    service_logfile = os.path.join(log_directory,'nssm_waptserver.log')
    service_dependencies = 'WAPTMongodb WAPTApache'
    install_windows_nssm_service("WAPTServer",service_binary,service_parameters,service_logfile,service_dependencies)

if __name__ == "__main__":
    if len(sys.argv)>1 and sys.argv[1] == 'doctest':
        import doctest
        sys.exit(doctest.testmod())

    if len(sys.argv)>1 and sys.argv[1] == 'install':
        install_windows_service()
        sys.exit(0)

    debug=False
    if debug:
        app.run(host='0.0.0.0',port=30880,debug=False)
    else:
        port = 8080
        server = Rocket(('0.0.0.0', port), 'wsgi', {"wsgi_app":app})
        try:
            logger.info("starting waptserver")
            server.start()
        except KeyboardInterrupt:
            logger.info("stopping waptserver")
            server.stop()
