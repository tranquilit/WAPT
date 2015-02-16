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
__version__="1.0.2"

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
import socket
import requests
import subprocess
import tempfile
import traceback
import datetime

from rocket import Rocket

import thread
import threading
import Queue

from waptpackage import *
import pefile

import itsdangerous

# i18n
from flask.ext.babel import Babel
try:
    from flask.ext.babel import gettext
except ImportError:
    gettext = (lambda s:s)
_ = gettext


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
parser.add_option("-d","--devel", dest="devel", default=False,action='store_true', help="Enable debug mode (for development only)")

(options,args)=parser.parse_args()

app = Flask(__name__,static_folder='./templates/static')
babel = Babel(app)

# setup logging
logger = logging.getLogger()
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')

def setloglevel(logger,loglevel):
    """set loglevel as string"""
    if loglevel in ('debug','warning','info','error','critical'):
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(_('Invalid log level: {}'.format(loglevel)))
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
    raise Exception(_("FATAL : couldn't open configuration file : {}.".format(options.configfile)))

#default mongodb configuration for wapt
mongodb_port = "38999"
mongodb_ip = "127.0.0.1"

wapt_folder = ""
wapt_user = ""
wapt_password = ""

waptserver_port = 8080
waptservice_port = 8088

clients_connect_timeout = 1
clients_read_timeout = 1.5
clients_poll_interval = None

if config.has_section('options'):
    if config.has_option('options', 'wapt_user'):
        wapt_user = config.get('options', 'wapt_user')
    else:
        wapt_user='admin'

    if config.has_option('options', 'waptserver_port'):
        waptserver_port = config.get('options', 'waptserver_port')

    if config.has_option('options', 'waptservice_port'):
        waptservice_port = config.get('options', 'waptservice_port')

    if config.has_option('options', 'wapt_password'):
        wapt_password = config.get('options', 'wapt_password')
    else:
        raise Exception (_('No waptserver admin password set in wapt-get.ini configuration file.'))

    if config.has_option('options', 'mongodb_port'):
        mongodb_port = config.get('options', 'mongodb_port')

    if config.has_option('options', 'mongodb_ip'):
        mongodb_ip = config.get('options', 'mongodb_ip')

    if config.has_option('options', 'wapt_folder'):
        wapt_folder = config.get('options', 'wapt_folder')
        if wapt_folder.endswith('/'):
            wapt_folder = wapt_folder[:-1]

    if config.has_option('options', 'clients_poll_interval'):
        clients_poll_interval = int(config.get('options', 'clients_poll_interval'))
    else:
        clients_poll_interval = None

    if config.has_option('options', 'clients_connect_timeout'):
        clients_connect_timeout = int(config.get('options', 'clients_connect_timeout'))

    if config.has_option('options', 'clients_read_timeout'):
        clients_read_timeout = int(config.get('options', 'clients_read_timeout'))

    if config.has_option('options', 'secret_key'):
        app.secret_key = config.get('options','secret_key')
    else:
        app.secret_key = 'NOT DEFINED'

    if options.loglevel is None and config.has_option('options', 'loglevel'):
        loglevel = config.get('options', 'loglevel')
        setloglevel(logger,loglevel)



else:
    raise Exception (_("FATAL, configuration file {} has no section [options]. Please check Waptserver documentation").format(options.configfile))

# XXX keep in sync with scripts/postconf.py
if not wapt_folder:
    wapt_folder = os.path.join(wapt_root_dir,'waptserver','repository','wapt')

waptagent = os.path.join(wapt_folder, 'waptagent.exe')
waptsetup = os.path.join(wapt_folder, 'waptsetup.exe')

# Setup initial directories
if os.path.exists(wapt_folder)==False:
    try:
        os.makedirs(wapt_folder)
    except:
        raise Exception(_("Folder missing : {}.").format(wapt_folder))
if os.path.exists(wapt_folder + '-host')==False:
    try:
        os.makedirs(wapt_folder + '-host')
    except:
        raise Exception(_("Folder missing : {}-host.").format(wapt_folder))
if os.path.exists(wapt_folder + '-group')==False:
    try:
        os.makedirs(wapt_folder + '-group')
    except:
        raise Exception(_("Folder missing : {}-group.").format(wapt_folder))

ALLOWED_EXTENSIONS = set(['wapt'])


def datetime2isodate(adatetime = None):
    if not adatetime:
        adatetime = datetime.datetime.now()
    assert(isinstance(adatetime,datetime.datetime))
    return adatetime.isoformat()


def get_waptagent_version():
    present = False
    version = None
    if os.path.exists(waptagent):
        present = True
        try:
            pe = pefile.PE(waptagent)
            version = pe.FileInfo[0].StringTable[0].entries['ProductVersion'].strip()
        except:
            pass
    return (present, version)


def ensure_list(csv_or_list,ignore_empty_args=True):
    """if argument is not a list, return a list from a csv string"""
    if csv_or_list is None:
        return []
    if isinstance(csv_or_list,tuple):
        return list(csv_or_list)
    elif not isinstance(csv_or_list,list):
        if ignore_empty_args:
            return [s.strip() for s in csv_or_list.split(',') if s.strip() != '']
        else:
            return [s.strip() for s in csv_or_list.split(',')]
    else:
        return csv_or_list

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
            raise Exception(_("Could not connect to mongodb database: {}.").format((repr(e),)))
    return g.hosts

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'client'):
        logger.debug('Disconnected from mongodb')
        del g.hosts
        del g.db
        del g.client

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

    pass_sha1_ok = wapt_password == hashlib.sha1(password.encode('utf8')).hexdigest()
    pass_sha512_ok = wapt_password == hashlib.sha512(password.encode('utf8')).hexdigest()

    if sha512_crypt.identify(wapt_password):
        pass_sha512_crypt_ok  = sha512_crypt.verify(password, wapt_password)
    else:
        try:
            if bcrypt.identify(wapt_password):
                pass_bcrypt_crypt_ok = bcrypt.verify(password, wapt_password)
        except Exception:
            pass

    return any_([pass_sha1_ok, pass_sha512_ok, pass_sha512_crypt_ok, pass_bcrypt_crypt_ok]) and user_ok


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        _('You have to login with proper credentials'), 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def get_host_data(uuid, filter = {}, delete_id = True):
    if filter:
        data = hosts().find_one({ "uuid": uuid}, filter)
    else:
        data = hosts().find_one({ "uuid": uuid})
    if data and delete_id:
        data.pop("_id")
    return data


@babel.localeselector
def get_locale():
     browser_lang = request.accept_languages.best_match(['en', 'fr'])
     user_lang = session.get('lang',browser_lang)
     return user_lang

@app.route('/lang/<language>')
def lang(language=None):
     session['lang'] = language
     return redirect('/')

@babel.timezoneselector
def get_timezone():
    user = getattr(g, 'user', None)
    if user is not None:
        return user.timezone


@app.route('/')
def index():
    agent_present, agent_version = get_waptagent_version()
    if agent_present:
        if agent_version is not None:
            agent_status = agent_version
        else:
            agent_status = 'ERROR'
    else:
        agent_status = 'N/A'
    return render_template("index.html", wapt_server_version=__version__, wapt_agent_version=agent_status)


@app.route('/info')
def informations():
    informations = {}
    informations["server_version"] = __version__
    present, version = get_waptagent_version()
    if present and version is not None:
        informations["client_version"] = version

    return Response(response=json.dumps(informations),
                     status=200,
                     mimetype="application/json")


@app.route('/hosts')
@app.route('/json/host_list',methods=['GET'])
@requires_auth
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

        hosts_packages_repo = WaptLocalRepo(wapt_folder+'-host')
        hosts_packages_repo.load_packages()

        for host in hosts().find(query,fields={'softwares':0,'packages':0}):
            host.pop("_id")
            if 'host' in host and 'computer_fqdn' in host['host']:
                host_package = hosts_packages_repo.index.get(host['host']['computer_fqdn'],None)
                if host_package:
                    depends = ensure_list(host_package.depends.split(','))
                    host['depends'] = depends
            try:
                la = host['wapt']['listening_address']
                if la['address']  and (la['timestamp'] != ''):
                    reachable = 'OK'
                elif not la['address'] and (la['timestamp'] != ''):
                    reachable = 'UNREACHABLE'
                else:
                    reachable = 'UNKNOWN'
                host['reachable'] = reachable
            except KeyError:
                host['reachable'] = 'UNKNOWN'

            list_hosts.append(host)

        result = list_hosts
    except Exception as e:
        result = dict(status='ERROR',message='%s: %s'%('hosts',e),result=None)

    return Response(response=json.dumps(result),
                     status=200,
                     mimetype="application/json")


def update_data(data):
    """Helper function to update host data in mongodb
        data is a dict with at least 'uuid' key and other key to add/update
        - insert or update data based on uuid match
        - update last_query_date key to current datetime
        returns whole dict for the updated host data
    """
    data['last_query_date'] = datetime2isodate()
    host = get_host_data(data["uuid"],delete_id=False)
    if host:
        hosts().update({"_id" : host['_id'] }, {"$set": data})
    else:
        host_id = hosts().insert(data)
    return get_host_data(data["uuid"],filter={"uuid":1,"host":1})

def get_reachable_ip(ips=[],waptservice_port=waptservice_port,timeout=clients_connect_timeout):
    """Try to establish a TCP connection to each IP of ips list on waptservice_port
        return first successful IP
        return empty string if no ip is is successful
        ips is either a single IP, or a list of IP, or a CSV list of IP
    """
    ips = ensure_list(ips)
    for ip in ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip,waptservice_port))
            s.close()
            return ip
        except:
            pass
    return None

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
                # check if client is reachable
                if 'host' in data and 'connected_ips' in data['host']:
                    ips = data['host']['connected_ips']
                    ip = get_reachable_ip(ips,waptservice_port)
                    data['wapt']['listening_address'] = dict(protocol='http',address=ip,port=waptservice_port,timestamp=datetime2isodate())
                    logger.debug('Client {} is listening on IP {}:{}'.format(uuid,ip,waptservice_port))

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
@requires_auth
def delete_host(uuid=""):
    try:
        hosts().remove({'uuid': uuid })
        data = get_host_data(uuid)
        # todo : delete host package if present
        result = dict(status='OK',message=json.dumps(data))
    except Exception as e:
        result = dict(status='ERROR',message=u"%s"%e)
    return Response(response=json.dumps(data),
                 status=200,
                 mimetype="application/json")


# to fix !
@app.route('/client_software_list/<string:uuid>')
@requires_auth
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
@requires_auth
def host_packages(uuid=""):
    """Return a the status of all installed packages on a host given its UUID
        for each installed package, check if the package should be upgrades based on local
          package repository.
    """
    try:
        host_data = get_host_data(uuid, {"packages":1})
        if not host_data:
            raise Exception(_('No host with uuid {}.').format(uuid))
        # check packages on local repository
        localrepo = WaptLocalRepo(localpath=os.path.join(wapt_folder))
        localrepo.load_packages()

        # keep an index of installed packages for later check of depends.
        host_packages_index = {}

        packages = host_data.get('packages',[])
        # packages is a list of plain dict
        for package in packages:
            host_pe = PackageEntry().load_control_from_dict(package)
            # update index of installed packages for later check of depends.
            host_packages_index[host_pe.package] = host_pe

            # find if there are newer version packages in local repo matching those installed on the host
            newer = [ p for p in localrepo.packages if p.match(host_pe.package) and p > host_pe ]
            if newer:
                # if installed version is older than the newest available in local repo, overload status
                package['install_status'] = 'NEED-UPGRADE'

        result = dict(status='OK',message='%i packages for host uuid: %s' %(len(packages),uuid),result = packages)
    except Exception as e:
        result = dict(status='ERROR',message='%s: %s'%('host_packages',e),result=None)

    return Response(response=json.dumps(result),
                     status=200,
                     mimetype="application/json")


@app.route('/client_package_list/<string:uuid>')
@requires_auth
def get_client_package_list(uuid=""):
    try:
        packages = get_host_data(uuid, {"packages":1})
        if not packages:
            raise Exception(_('No host with uuid {}.').formatat(uuid))
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
                    result = dict(status='ERROR',message=_('Problem during upload'))
                else:
                    if PackageEntry().load_control_from_wapt(tmp_target):
                        target = os.path.join(wapt_folder, secure_filename(filename))
                        if os.path.isfile(target):
                            os.unlink(target)
                        os.rename(tmp_target,target)
                        data = update_packages(wapt_folder)
                        result = dict(status='OK',message='%s uploaded, %i packages analysed'%(filename,len(data['processed'])),result=data)
                    else:
                        result = dict(status='ERROR',message=_('Not a valid wapt package'))
                        os.unlink(tmp_target)
            else:
                result = dict(status='ERROR',message=_('Wrong file type'))
        else:
            result = dict(status='ERROR',message=_('Unsupported method'))
    except:
        # remove temporary
        if os.path.isfile(tmp_target):
            os.unlink(tmp_target)
        e = sys.exc_info()
        logger.critical(repr(traceback.format_exc()))
        result = dict(status='ERROR',message=_('unexpected: {}').format((e,)))
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
                        result = dict(status='OK',message=_('File {} uploaded to {}').format(file.filename,target))
                    except:
                        if os.path.isfile(tmp_target):
                            os.unlink(tmp_target)
                        raise
                else:
                    result = dict(status='ERROR',message=_('No data received'))
            else:
                result = dict(status='ERROR',message=_('Wrong file type'))
        else:
            result = dict(status='ERROR',message=_('No package file provided in request'))
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
            if file and "waptagent.exe" in file.filename:
                filename = secure_filename(file.filename)
                tmp_target = os.path.join(wapt_folder, secure_filename('.'+filename))
                target = os.path.join(wapt_folder, secure_filename(filename))
                file.save(tmp_target)
                if not os.path.isfile(tmp_target):
                    result = dict(status='ERROR',message=_('Problem during upload'))
                else:
                    os.rename(tmp_target,target)
                    result = dict(status='OK',message=_('{} uploaded').format((filename,)))

                # Compat with older clients: provide a waptsetup.exe -> waptagent.exe alias
                if os.path.exists(waptsetup):
                    if not os.path.exists(waptsetup + '.old'):
                        try:
                            os.rename(waptsetup, waptsetup + '.old')
                        except:
                            pass
                    try:
                        os.unlink(waptsetup)
                    except:
                        pass
                try:
                    os.symlink(waptagent, waptsetup)
                except:
                    import shutil
                    shutil.copyfile(waptagent, waptsetup)

            else:
                result = dict(status='ERROR',message=_('Wrong file name (version conflict?)'))
        else:
            result = dict(status='ERROR',message=_('Unsupported method'))
    except:
        e = sys.exc_info()
        if tmp_target and os.path.isfile(tmp_target):
            os.unlink(tmp_target)
        result = dict(status='ERROR',message=_('unexpected: {}').format((e,)))
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
                    httpreq = requests.get("http://%s:%d/waptupgrade.json" % ( ip, waptservice_port),proxies=None,timeout=clients_read_timeout)
                    httpreq.raise_for_status()
                    result = {'status' : 'OK', 'message': u"%s" % httpreq.text }
                except Exception as e:
                    logger.warning(u'%s'%e)
                    r = requests.get("http://%s:%d/waptupgrade" % ( ip, waptservice_port),proxies=None,timeout=clients_read_timeout)
                    if "OK" in r.text.upper():
                        result = {  'status' : 'OK', 'message': u"%s" % r.text }
                    else:
                        result = {  'status' : 'ERROR', 'message': u"%s" % r.text }
            else:
                raise Exception(_("The WAPT service port is not defined."))

        except Exception as e:
            raise Exception(_("Couldn't connect to web service : {}.").format(e))

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
                data = json.loads(requests.get("http://%s:%d/install.json?package=%s" % ( ip, waptservice_port,package),proxies=None).text,timeout=clients_read_timeout)
                result = dict(message=data,status='OK')
            else:
                raise Exception(_("The WAPT service port is not defined."))

        except Exception as e:
            raise Exception(_("Couldn't connect to web service : {}.").format(e))

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
                httpreq = requests.get("http://%s:%d/remove.json?package=%s" % ( ip, waptservice_port,package),proxies=None,timeout=clients_read_timeout)
                httpreq.raise_for_status()
                data = json.loads(httpreq.text)
                result = dict(message=data,status='OK')
            else:
                raise Exception(_("The WAPT service port is not defined."))

        except Exception as e:
            raise Exception(_("Couldn't connect to the host's WAPT service : {}.").format(e))

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
                httpreq = requests.get("http://%s:%d/forget.json?package=%s" % ( ip, waptservice_port,package),proxies=None,timeout=clients_read_timeout)
                httpreq.raise_for_status()
                data = json.loads(httpreq.text)
                result = dict(message=data,status='OK')
            else:
                raise Exception(_("The WAPT service port is not defined."))

        except Exception as e:
            raise Exception(_("Couldn't connect to the host's WAPT service : {}.").format(e))

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
            uuid = request.args['uuid']
            host_data = hosts().find_one({ "uuid": uuid},fields={'wapt':1,'host.connected_ips':1})
            listening_data = get_ip_port(host_data)

            if listening_data['address']:
                data = requests.get("%(protocol)s://%(address)s:%(port)d/tasks.json" % listening_data,proxies=None,timeout=clients_read_timeout).text
                result = dict(message=json.loads(data),status='OK')
            else:
                raise EWaptMissingHostData(_("The WAPT service port is not defined."))

        except Exception as e:
            raise EWaptHostUnreachable(_("Couldn't connect to web service : {}.").format(e))

    except Exception, e:
        # old behaviour
        if 'Restricted access.' in data:
            result = { 'status' : 'ERROR', 'message': u"%s" % (data)  }
        else:
            result = { 'status' : 'ERROR', 'message': u"%s, %s" % (e,data)  }
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
                data = json.loads(requests.get("http://%s:%d/cancel_running_task.json" % ( ip, waptservice_port),proxies=None,timeout=clients_read_timeout).text)
                result = dict(message=data,status='OK')
            else:
                raise Exception(_("The WAPT service port is not defined."))

        except Exception as e:
            raise Exception(_("Couldn't connect to web service : {}.").format(e))

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


# deprecated
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
                    result = json.loads(requests.get("http://%s:%d/upgrade.json" % ( ip, waptservice_port),proxies=None,timeout=clients_read_timeout).text)
                except Exception as e:
                    # try the old behaviour for wapt client < 0.8.10
                    logger.warning(u"%s"%e)
                    r = requests.get("http://%s:%d/upgrade" % ( ip, waptservice_port),proxies=None,timeout=clients_read_timeout)
                    if "OK" in r.text.upper():
                        result = {  'status' : 'OK', 'message': u"%s" % r.text }
                    else:
                        result = {  'status' : 'ERROR', 'message': u"%s" % r.text }

            else:
                raise Exception(_("The WAPT service port is not defined."))

        except Exception as e:
            raise  Exception(_("Couldn't connect to web service : {}.").format(e))

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
            raise Exception(_("Incorrect credentials."))
        if "NT_STATUS_CONNECTION_REFUSED" in e.output:
            raise Exception(_("Couldn't access IPC$ share."))

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
            raise Exception(_('WAPT server must be run on Linux.'))
        if subprocess.call('which smbclient',shell=True) != 0:
            raise Exception(_("smbclient installed on WAPT server."))
        if subprocess.call('which winexe',shell=True) != 0:
            raise Exception(_("winexe is not installed on WAPT server."))

        if request.method == 'POST':
            d = json.loads(request.data)
            if 'auth' not in d:
                raise Exception(_("Credentials are missing."))
            if 'computer_fqdn' not in d:
                raise Exception(_("There are no registered computers."))

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
            raise Exception(_("Unsupported HTTP method."))

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
                        wapt_password = hashlib.sha1(d["newPass"].encode('utf8')).hexdigest()
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

@app.route('/wapt/')
def wapt_listing():
    return render_template('listing.html', dir_listing=os.listdir(wapt_folder))

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


################ API V2 #########
def make_response(result = {},success=True,error_code='',msg='',status=200):
    data = dict(
            success = success,
            msg = msg,
            )
    if not success:
        data['error_code'] = error_code
    else:
        data['result'] = result
    return Response(
            response=json.dumps(data),
            status=status,
            mimetype="application/json")


def make_response_from_exception(exception,error_code='',status=200):
    """Return a error flask http response from an exception object
        success : False
        msg : message from exception
        error_code : classname of exception if not provided
        status: 200 if not provided
    """
    if not error_code:
        error_code = type(exception).__name__.lower()
    data = dict(
            success = False,
            error_code = error_code
            )
    if options.devel:
        data['msg'] = traceback.format_exc()
    else:
        data['msg'] = u"%s" % (exception,)
    return Response(
            response=json.dumps(data),
            status=status,
            mimetype="application/json")


class EWaptMissingHostData(Exception):
    pass

class EWaptUnknownHost(Exception):
    pass

class EWaptHostUnreachable(Exception):
    pass

class EWaptForbiddden(Exception):
    pass

def get_ip_port(host_data):
    """Return a dict proto,address,port for the supplied registered host
        - first check if wapt.listening_address is ok
        - if not present (old wapt client/server), check each of host.check connected_ips list
    """
    if not host_data:
        raise EWaptUnknownHost(_('Unknown uuid'))

    if 'wapt' in host_data:
        if 'listening_address' in host_data['wapt'] and \
                  'address' in host_data['wapt']['listening_address'] and \
                  host_data['wapt']['listening_address']['address']:
            return host_data['wapt']['listening_address']
        else:
            return dict(
                protocol='http',
                address=get_reachable_ip(ensure_list(host_data['host']['connected_ips'])),
                port=waptservice_port)
    else:
        raise EWaptHostUnreachable(_('No reachable IP for {}').format(host_data['uuid']))


@app.route('/ping')
def ping():
    return make_response(msg = _('WAPT Server running'), result = dict(version = __version__ ))


@app.route('/trigger_reachable_discovery')
@requires_auth
def trigger_reachable_discovery():
    """Launch a separate thread to check all reachable IP
    """
    try:
        check_listening = CheckHostsWaptService()
        check_listening.daemon = True
        check_listening.start()
        message = _(u'Hosts listening IP discovery launched')
        result = dict(thread_ident = check_listening.ident )

    except Exception, e:
            return make_response_from_exception(e)
    return make_response(result,msg = message)


@app.route('/host_reachable_ip')
@requires_auth
def host_reachable_ip():
    """Check if supplied host's waptservice can be reached
            param uuid : host uuid
    """
    try:
        try:
            uuid = request.args['uuid']
            host_data = hosts().find_one({ "uuid": uuid},fields={'softwares':0,'packages':0})
            result = get_ip_port(host_data)
        except Exception as e:
            raise EWaptHostUnreachable(_("Couldn't connect to web service : {}.").format(e))

    except Exception, e:
            return make_response_from_exception(e)
    return make_response(result)


@app.route('/trigger_upgrade')
@requires_auth
def trigger_upgrade():
    """Proxy the wapt upgrade action to the client"""
    try:
        uuid = request.args['uuid']
        host_data = hosts().find_one({ "uuid": uuid},fields={'uuid':1,'wapt':1,'host.connected_ips':1})
        listening_address = get_ip_port(host_data)
        msg = u''
        if listening_address and listening_address['address'] and listening_address['port']:
            logger.info( "Triggering upgrade for %s at address %s..." % (uuid,listening_address['address']))
            client_result = requests.get("%(protocol)s://%(address)s:%(port)d/upgrade.json" % listening_address,proxies=None,timeout=clients_read_timeout).text
            try:
                client_result = json.loads(client_result)
                result = client_result['content']
                if len(result)<=1:
                    msg = _(u"Nothing to upgrade.")
                else:
                    packages= [t['description'] for t in result if t['classname'] != 'WaptUpgrade']
                    msg = _(u"Triggered {} task(s):\n{}").format(len(packages),'\n'.join(packages))
            except ValueError:
                if 'Restricted access' in client_result:
                    raise EWaptForbiddden(client_result)
                else:
                    raise Exception(client_result)
        else:
            raise EWaptMissingHostData(_("The WAPT service is unreachable."))
        return make_response(result,
            msg = msg,
            success = client_result['result'] == 'OK',)
    except Exception, e:
        return make_response_from_exception(e)

@app.route('/trigger_update')
@requires_auth
def trigger_update():
    """Proxy the wapt update action to the client"""
    try:
        uuid = request.args['uuid']
        notify_user = request.args.get('notify_user',0)
        host_data = hosts().find_one({ "uuid": uuid},fields={'uuid':1,'wapt':1,'host.connected_ips':1})
        listening_address = get_ip_port(host_data)
        msg = u''
        if listening_address and listening_address['address'] and listening_address['port']:
            logger.info( "Triggering update for %s at address %s..." % (uuid,listening_address['address']))
            args = {}
            args.update(listening_address)
            args['notify_user'] = notify_user
            client_result = requests.get("%(protocol)s://%(address)s:%(port)d/update.json?notify_user=%(notify_user)s" % args,proxies=None,timeout=clients_read_timeout).text
            try:
                client_result = json.loads(client_result)
                msg = _(u"Triggered task: {}").format(client_result['description'])
            except ValueError:
                if 'Restricted access' in client_result:
                    raise EWaptForbiddden(client_result)
                else:
                    raise Exception(client_result)
        else:
            raise EWaptMissingHostData(_("The WAPT service is unreachable."))
        return make_response(client_result,
            msg = msg,
            success = True)
    except Exception, e:
        return make_response_from_exception(e)



@app.route('/host_tasks_status')
@requires_auth
def host_tasks_status():
    """Proxy the get tasks status action to the client"""
    try:
        uuid = request.args['uuid']
        host_data = hosts().find_one({ "uuid": uuid},fields={'wapt':1,'host.connected_ips':1})
        listening_address = get_ip_port(host_data)

        if listening_address and listening_address['address'] and listening_address['port']:
            logger.info( "Triggering upgrade for %s at address %s..." % (uuid,listening_address['address']))
            client_result = requests.get("%(protocol)s://%(address)s:%(port)d/tasks.json" % listening_address,proxies=None,timeout=clients_read_timeout).text
            try:
                client_result = json.loads(client_result)
            except ValueError:
                if 'Restricted access' in client_result:
                    raise EWaptForbiddden(client_result)
                else:
                    raise Exception(client_result)
        else:
            raise EWaptMissingHostData(_("The WAPT service port is not defined."))
        return make_response(client_result,
            msg = "Tasks status retrieved properly",
            success = isinstance(client_result,dict),)
    except Exception, e:
        return make_response_from_exception(e)


##################################################################
class CheckHostWorker(threading.Thread):
    """Worker which pull a host data from queue, checks reachability, and store result in db
    """
    def __init__(self,db,queue):
        threading.Thread.__init__(self)
        self.db = db
        self.queue = queue
        self.daemon = True
        self.start()


    def check_host(self,host_data):
        if 'host' in host_data:
            protocol = 'http'
            port = waptservice_port
            ip = ''
            # check with last known listening informations
            if 'wapt' in host_data['host'] and \
                    'listening_address' in  host_data['host']['wapt'] and \
                    host_data['host']['wapt'].get('address',''):
                la = host_data['host']['wapt']['listening_address']
                protocol = la['protocol']
                ip = la['address']
                port = la['port']
                logger.debug("Client checker %s is testing %s" % (self.ident,ip))
                ip = get_reachable_ip(ip,port)
            # check with other connected ips
            if not ip and 'connected_ips' in host_data['host']:
                ips = host_data['host']['connected_ips']
                logger.debug("Client checker %s is testing %s" % (self.ident,ips))
                ip = get_reachable_ip(ips,port)

            # stores result
            la = dict(protocol='http',address=ip,port=waptservice_port,timestamp=datetime2isodate())
            self.db.hosts.update({"_id" : host_data['_id'] }, {"$set": {'wapt.listening_address':la }})


    def run(self):
        while True:
            host_data = self.queue.get()
            self.check_host(host_data)
            self.queue.task_done()


class CheckHostsWaptService(threading.Thread):
    """Thread which check which IP is reachable for all registered hosts
        The result is stored in MongoDB database as wapt.listening_address
        {protocol
         address
         port}
       if poll_interval is not None, the thread runs indefinetely/
       if poll_interval is None, one check of all hosts is performed.
    """
    def __init__(self,poll_interval=None):
        threading.Thread.__init__(self)
        self.daemon = True
        self.mongoclient = MongoClient(mongodb_ip, int(mongodb_port))
        self.db = self.mongoclient.wapt
        self.poll_interval = poll_interval
        self.queue = Queue.PriorityQueue()
        self.workers = []
        self.workers_count = 20

    def update_listening_address(self):
        """create a queue with all hosts
        """
        self.db.hosts.update({'wapt.listening_address.timestamp':{'$ne':''}},{"$set": {'wapt.listening_address.timestamp':'' }},multi=True)
        query = {"host.connected_ips":{"$exists": "true", "$ne" :[]}}
        fields = {'wapt':1,'host.connected_ips':1,'uuid':1,'host.computer_fqdn':1}
        for data in self.db.hosts.find(query,fields=fields):
            self.queue.put(data)

        logger.debug('Create %i workers'%self.workers_count)
        for i in range(0,self.workers_count):
            self.workers.append(CheckHostWorker(self.db,self.queue))

        logger.debug('Waiting for hosts queue to be empty')
        self.queue.join()

    def run(self):
        logger.debug('Client-listening %s address checker thread started'%self.ident)
        while True:
            try:
                try:
                    self.update_listening_address()
                except Exception as e:
                    logger.critical('Unable to poll wapt client : %s' % e)
                if self.poll_interval:
                    logger.debug('Client-listening address checker %s sleeping...'%self.ident)
                    time.sleep(self.poll_interval)
                else:
                    break
            except KeyboardInterrupt:
                break
        logger.debug('Client-listening %s address checker thread stopped'%self.ident)




#################################################
## Helpers for installer
##

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
    ap_ssl_dir = os.path.join(wapt_root_dir,'waptserver','apache-win32','ssl')

    # generate ssl keys
    openssl = os.path.join(wapt_root_dir,'waptserver','apache-win32','bin','openssl.exe')
    openssl_config = os.path.join(wapt_root_dir,'waptserver','apache-win32','conf','openssl.cnf')
    fqdn = None
    try:
        import socket
        fqdn = socket.getfqdn()
    except:
        pass
    if not fqdn:
        fqdn = 'wapt'
    if '.' not in fqdn:
        fqdn += '.local'
    void = subprocess.check_output([
            openssl,
            'req',
            '-new',
            '-x509',
            '-newkey', 'rsa:2048',
            '-nodes',
            '-days', '3650',
            '-out', os.path.join(ap_ssl_dir,'cert.pem'),
            '-keyout', os.path.join(ap_ssl_dir,'key.pem'),
            '-config', openssl_config,
            '-subj', '/C=/ST=/L=/O=/CN=' + fqdn + '/'
            ], stderr=subprocess.STDOUT)

    # write config file
    jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(ap_conf_dir))
    template = jinja_env.get_template(ap_file_name + '.j2')
    template_variables = {
        'wapt_repository_path': os.path.dirname(wapt_folder),
        'apache_root_folder':os.path.dirname(ap_conf_dir),
        'windows': True,
        'ssl': True,
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

def install_windows_service(args):
    """Setup waptserver, waptmongodb et waptapache as a windows Service managed by nssm
    >>> install_windows_service([])
    """
    install_apache_service = '--without-apache' not in args

    # register mongodb server
    make_mongod_config(wapt_root_dir)

    service_binary =os.path.abspath(os.path.join(wapt_root_dir,'waptpython.exe'))
    service_parameters = "%s %s %s" % (
        os.path.join(wapt_root_dir,'waptserver','mongodb','mongod.py'),
        os.path.join(wapt_root_dir,'waptserver','mongodb','mongod.exe'),
        os.path.join(wapt_root_dir,'waptserver','mongodb','mongod.cfg')
    )
    service_logfile = os.path.join(log_directory,'nssm_waptmongodb.log')
    install_windows_nssm_service("WAPTMongodb",service_binary,service_parameters,service_logfile)

    # register apache frontend
    if install_apache_service:
        make_httpd_config(wapt_root_dir, wapt_folder)
        service_binary =os.path.abspath(os.path.join(wapt_root_dir,'waptserver','apache-win32','bin','httpd.exe'))
        service_parameters = ""
        service_logfile = os.path.join(log_directory,'nssm_apache.log')
        install_windows_nssm_service("WAPTApache",service_binary,service_parameters,service_logfile)

    # register waptserver
    service_binary = os.path.abspath(os.path.join(wapt_root_dir,'waptpython.exe'))
    service_parameters = os.path.abspath(__file__)
    service_logfile = os.path.join(log_directory,'nssm_waptserver.log')
    service_dependencies = 'WAPTMongodb'
    if install_apache_service:
        service_dependencies += ' WAPTApache'
    install_windows_nssm_service("WAPTServer",service_binary,service_parameters,service_logfile,service_dependencies)


##############
if __name__ == "__main__":
    if len(sys.argv)>1 and sys.argv[1] == 'doctest':
        import doctest
        sys.exit(doctest.testmod())

    if len(sys.argv)>1 and sys.argv[1] == 'install':
        # pass optional parameters along with the command
        install_windows_service(sys.argv[1:])
        sys.exit(0)


    # global thread to check listening ip of registred hosts periodically
    # use with caution as it generates noise on the network (tcp connection try on each host)
    check_listening = CheckHostsWaptService(poll_interval = clients_poll_interval)
    check_listening.daemon = True
    check_listening.start()

    if options.devel:
        app.run(host='0.0.0.0',port=30880,debug=False)
    else:
        port = waptserver_port
        server = Rocket(('0.0.0.0', port), 'wsgi', {"wsgi_app":app})
        try:
            logger.info("starting waptserver")
            server.start()
        except KeyboardInterrupt:
            logger.info("stopping waptserver")
            server.stop()
