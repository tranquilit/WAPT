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
__version__="1.2.4"

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
import shutil
import subprocess
import tempfile
import traceback
import datetime
import uuid
import email.utils
import collections
import urlparse
import stat
from bson.json_util import dumps

from rocket import Rocket

import thread
import threading
import Queue

from uwsgidecorators import *
from lxml import etree as ET


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
%prog [-c configfile] [--devel] [action]

WAPT daemon.

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

#hdlr = logging.StreamHandler(sys.stdout)
#hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
#logger.addHandler(hdlr)

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
waptwua_folder = ""
wapt_password = ""
server_uuid = ''

waptserver_port = 8080
waptservice_port = 8088

clients_connect_timeout = 5
clients_read_timeout = 5
client_tasks_timeout = 0.5

# Unique, constant UUIDs
WSUS_UPDATE_DOWNLOAD_LOCK = '420d1a1e-5f63-4afc-b055-2ce1538054aa'
WSUS_PARSE_WSUSSCN2_LOCK = 'b526e9da-ebf0-45c7-9d01-90218d110e61'


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

    if config.has_option('options', 'waptwua_folder'):
        waptwua_folder = config.get('options', 'waptwua_folder')
        if waptwua_folder.endswith('/'):
            waptwua_folder = waptwua_folder[:-1]

    if config.has_option('options', 'clients_connect_timeout'):
        clients_connect_timeout = int(config.get('options', 'clients_connect_timeout'))

    if config.has_option('options', 'clients_read_timeout'):
        clients_read_timeout = int(config.get('options', 'clients_read_timeout'))

    if config.has_option('options', 'client_tasks_timeout'):
        client_tasks_timeout = int(config.get('options', 'client_tasks_timeout'))

    if config.has_option('options', 'secret_key'):
        app.secret_key = config.get('options','secret_key')
    else:
        app.secret_key = 'NOT DEFINED'

    if options.loglevel is None and config.has_option('options', 'loglevel'):
        loglevel = config.get('options', 'loglevel')
        setloglevel(logger,loglevel)

    if config.has_option('options', 'server_uuid'):
        server_uuid = config.get('options', 'server_uuid')


else:
    raise Exception (_("FATAL, configuration file {} has no section [options]. Please check Waptserver documentation").format(options.configfile))

# XXX keep in sync with scripts/postconf.py
if not wapt_folder:
    wapt_folder = os.path.join(wapt_root_dir,'waptserver','repository','wapt')

if not waptwua_folder:
    waptwua_folder = wapt_folder+'wua'

waptagent = os.path.join(wapt_folder, 'waptagent.exe')
waptsetup = os.path.join(wapt_folder, 'waptsetup-tis.exe')
waptdeploy = os.path.join(wapt_folder, 'waptdeploy.exe')

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

def isodate2datetime(isodatestr):
    # we remove the microseconds part as it is not working for python2.5 strptime
    return datetime.datetime.strptime(isodatestr.split('.')[0] , "%Y-%m-%dT%H:%M:%S")

def httpdatetime2isodate(httpdate):
    """convert a date string as returned in http headers or mail headers to isodate
    >>> import requests
    >>> last_modified = requests.head('http://wapt/wapt/Packages',headers={'cache-control':'no-cache','pragma':'no-cache'}).headers['last-modified']
    >>> len(httpdatetime2isodate(last_modified)) == 19
    True
    """
    return datetime2isodate(datetime.datetime(*email.utils.parsedate(httpdate)[:6]))

def mkdir_p(path):
    import errno
    try:
        os.makedirs(path)
    except OSError, exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def get_wapt_exe_version(exe):
    present = False
    version = None
    if os.path.exists(exe):
        present = True
        pe = None
        try:
            pe = pefile.PE(exe)
            version = pe.FileInfo[0].StringTable[0].entries['FileVersion'].strip()
            if not version:
                version = pe.FileInfo[0].StringTable[0].entries['ProductVersion'].strip()
        except:
            pass
        if pe is not None:
            pe.close()
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

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'db'):
        try:
            logger.debug('Connecting to mongo db %s:%s'%(mongodb_ip, int(mongodb_port)))
            mongo_client = MongoClient(mongodb_ip, int(mongodb_port))
            g.mongo_client = mongo_client
            g.db = mongo_client.wapt
        except Exception as e:
            raise Exception(_("Could not connect to mongodb database: {}.").format((repr(e),)))
    return g.db

def hosts():
    """ Get hosts collection from db
    """
    if not hasattr(g, 'hosts'):
        try:
            logger.debug('Add hosts collection to current request context')
            g.hosts = get_db().hosts
            g.hosts.ensure_index('uuid',unique=True)
            g.hosts.ensure_index('computer_name',unique=False)
        except Exception as e:
            raise Exception(_("Could not get hosts collection from db: {}.").format((repr(e),)))
    return g.hosts

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'hosts'):
        logger.debug('Remove hosts from request context')
        del g.hosts
    if hasattr(g, 'db'):
        del g.db
    if hasattr(g, 'mongo_client'):
        logger.debug('del mongo_client instance')
        del g.mongo_client

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

    agent_status = setup_status = deploy_status = 'N/A'
    agent_style = setup_style = deploy_style = 'style="color: red;"'

    agent_present, agent_version = get_wapt_exe_version(waptagent)
    if agent_present:
        agent_style = ''
        if agent_version is not None:
            agent_status = agent_version
        else:
            agent_status = 'ERROR'

    setup_present, setup_version = get_wapt_exe_version(waptsetup)
    if setup_present:
        setup_style = ''
        if setup_version is not None:
            setup_status = setup_version
        else:
            setup_status = 'ERROR'

    deploy_present, deploy_version = get_wapt_exe_version(waptdeploy)
    if deploy_present:
        deploy_style = ''
        if deploy_version is not None:
            deploy_status = deploy_version
        else:
            deploy_status = 'ERROR'

    data = {
        'wapt': {
            'server': { 'status': __version__ },
            'agent': { 'status': agent_status, 'style': agent_style },
            'setup': { 'status': setup_status, 'style': setup_style },
            'deploy': { 'status': deploy_status, 'style': deploy_style },
        }
    }

    return render_template("index.html", data=data)


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
                result = dict(status='OK',message="update_host",result=update_data(data))

                # check if client is reachable
                if not 'check_hosts_thread' in g or not g.check_hosts_thread.is_alive():
                    logger.info('Creates check hosts thread for %s'%(uuid,))
                    g.check_hosts_thread = CheckHostsWaptService(timeout=clients_connect_timeout,uuids=[uuid])
                    g.check_hosts_thread.start()
                else:
                    logger.info('Reuses current check hosts thread for %s'%(uuid,))
                    g.check_hosts_thread.queue.append(data)

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


@app.route('/upload_package/<string:filename>',methods=['POST'])
@requires_auth
def upload_package(filename=""):
    try:
        tmp_target = ''
        if request.method == 'POST':
            if filename and allowed_file(filename):
                tmp_target = os.path.join(wapt_folder, secure_filename(filename+'.tmp'))
                with open(tmp_target, 'wb') as f:
                    data = request.stream.read(65535)
                    try:
                        while len(data) > 0:
                            f.write(data)
                            data = request.stream.read(65535)
                    except:
                        logger.debug('End of stream')
                        raise

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

    cmd = '/usr/bin/smbclient -A "%s" //%s/c\\$ -c "put waptagent.exe" ' % (authentication_file, computer_name)
    print subprocess.check_output(cmd,shell=True)

    cmd = '/usr/bin/winexe -A "%s"  //%s  "c:\\waptagent.exe  /MERGETASKS=""useWaptServer"" /VERYSILENT"  ' % (authentication_file, computer_name)
    print subprocess.check_output(cmd,shell=True)

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


def rewrite_config_item(cfg_file, *args):
    config = ConfigParser.RawConfigParser()
    config.read(cfg_file)
    config.set(*args)
    with open(cfg_file, 'wb') as cfg:
        config.write(cfg)

# Reload config file.
# On Rocket we rely on inter-threads synchronization,
# thus the variable you want to sync MUST be declared as a *global*
# On Unix we ask uwsgi to perform a graceful restart.
def reload_config():
    if os.name == "posix":
        try:
            import uwsgi
            uwsgi.reload()
        except ImportError:
            pass

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
                        rewrite_config_item(options.configfile, 'options', 'wapt_password', wapt_password)
                        reload_config()
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

@app.route('/waptwua/')
def waptwua():
    return render_template('listing.html', dir_listing=os.listdir(waptwua_folder))


@app.route('/waptwua/<path:wsuspackage>')
def get_wua_package(wsuspackage):
    fileparts = wsuspackage.split('/')
    full_path = os.path.join(waptwua_folder,*fileparts[:-1])
    package_name = secure_filename(fileparts[-1])
    r =  send_from_directory(full_path, package_name)
    if 'content-length' not in r.headers:
        r.headers.add_header('content-length', int(os.path.getsize(os.path.join(full_path,package_name))))
    return r

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
            response=dumps(data),
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

class EWaptMissingParameter(Exception):
    pass

def get_ip_port(host_data,recheck=False,timeout=None):
    """Return a dict proto,address,port for the supplied registered host
        - first check if wapt.listening_address is ok and recheck is False
        - if not present or recheck is True, check each of host.check connected_ips list with timeout
    """
    if not timeout:
        timeout = clients_connect_timeout
    if not host_data:
        raise EWaptUnknownHost(_('Unknown uuid'))

    if 'wapt' in host_data:
        if not recheck and host_data['wapt'].get('listening_address',None) and \
                  'address' in host_data['wapt']['listening_address'] and \
                  host_data['wapt']['listening_address']['address']:
            return host_data['wapt']['listening_address']
        else:
            port = host_data['wapt'].get('waptservice_port',waptservice_port)
            return dict(
                protocol=host_data['wapt'].get('waptservice_protocol','http'),
                address=get_reachable_ip(ensure_list(host_data['host']['connected_ips']),waptservice_port=port,timeout=timeout),
                port=port,
                timestamp=datetime2isodate())
    else:
        raise EWaptHostUnreachable(_('No reachable IP for {}').format(host_data['uuid']))


@app.route('/ping')
def ping():
    global server_uuid
    if server_uuid == '':
        server_uuid = str(uuid.uuid1())
        rewrite_config_item(options.configfile, 'options', 'server_uuid', server_uuid)
        reload_config()
    return make_response(
        msg = _('WAPT Server running'), result = dict(
            version = __version__,
            api_root='/api/',
            api_version='v1',
            uuid = server_uuid,
            date = datetime2isodate(),
            )
            )


@app.route('/api/v1/trigger_reachable_discovery')
@requires_auth
def trigger_reachable_discovery():
    """Launch a separate thread to check all reachable IP and update database with results.
    """
    try:
        # check if client is reachable
        if 'check_hosts_thread' in g:
            if not g.check_hosts_thread.is_alive():
                del(g.check_hosts_thread)
        g.check_hosts_thread = CheckHostsWaptService(timeout=clients_connect_timeout)
        g.check_hosts_thread.start()
        message = _(u'Hosts listening IP discovery launched')
        result = dict(thread_ident = g.check_hosts_thread.ident )

    except Exception, e:
            return make_response_from_exception(e)
    return make_response(result,msg = message)


@app.route('/api/v1/host_reachable_ip')
@requires_auth
def host_reachable_ip():
    """Check if supplied host's waptservice can be reached
            param uuid : host uuid
    """
    try:
        try:
            uuid = request.args['uuid']
            host_data = hosts().find_one({ "uuid": uuid},fields = {'uuid':1,'host.computer_fqdn':1,'wapt':1,'host.connected_ips':1})
            result = get_ip_port(host_data)
        except Exception as e:
            raise EWaptHostUnreachable(_("Couldn't connect to web service : {}.").format(e))

    except Exception, e:
            return make_response_from_exception(e)
    return make_response(result)


@app.route('/api/v1/trigger_upgrade')
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
            args = {}
            args.update(listening_address)
            args['uuid'] = uuid
            client_result = requests.get("%(protocol)s://%(address)s:%(port)d/upgrade.json?uuid=%(uuid)s" % args,proxies=None,verify=False, timeout=clients_read_timeout).text
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


@app.route('/api/v1/trigger_update')
@requires_auth
def trigger_update():
    """Proxy the wapt update action to the client"""
    try:
        uuid = request.args['uuid']
        notify_user = request.args.get('notify_user',0)
        notify_server = request.args.get('notify_server',1)


        host_data = hosts().find_one({ "uuid": uuid},fields={'uuid':1,'wapt':1,'host.connected_ips':1})
        listening_address = get_ip_port(host_data)
        msg = u''
        if listening_address and listening_address['address'] and listening_address['port']:
            logger.info( "Triggering update for %s at address %s..." % (uuid,listening_address['address']))
            args = {}
            args.update(listening_address)
            args['notify_user'] = notify_user
            args['uuid'] = uuid
            client_result = requests.get("%(protocol)s://%(address)s:%(port)d/update.json?notify_user=%(notify_user)s&notify_server=1&uuid=%(uuid)s" % args,proxies=None,verify=False, timeout=clients_read_timeout).text
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


@app.route('/api/v2/trigger_host_inventory')
@requires_auth
def trigger_host_inventory():
    """Proxy the wapt update action to the client"""
    try:
        uuid = request.args['uuid']
        notify_user = request.args.get('notify_user',0)
        notify_server = request.args.get('notify_server',1)


        host_data = hosts().find_one({ "uuid": uuid},fields={'uuid':1,'wapt':1,'host.connected_ips':1})
        listening_address = get_ip_port(host_data)
        msg = u''
        if listening_address and listening_address['address'] and listening_address['port']:
            logger.info( "Triggering inventory for %s at address %s..." % (uuid,listening_address['address']))
            args = {}
            args.update(listening_address)
            args['notify_user'] = notify_user
            args['uuid'] = uuid
            client_result = requests.get("%(protocol)s://%(address)s:%(port)d/register.json?notify_user=%(notify_user)s&notify_server=1&uuid=%(uuid)s" % args,proxies=None,verify=False, timeout=clients_read_timeout).text
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


@app.route('/api/v1/host_forget_packages')
@requires_auth
def host_forget_packages():
    """Proxy the wapt forget action to the client
            uuid
            packages
            notify_user
            notify_server
    """
    try:
        uuid = request.args['uuid']
        packages = ensure_list(request.args['packages'])
        notify_user = request.args.get('notify_user',0)

        host_data = hosts().find_one({ "uuid": uuid},fields={'uuid':1,'wapt':1,'host.connected_ips':1})
        listening_address = get_ip_port(host_data)
        msg = u''
        if listening_address and listening_address['address'] and listening_address['port']:
            logger.info( "Removing packages %s from %s at address %s..." % (','.join(packages),uuid,listening_address['address']))
            args = {}
            args.update(listening_address)
            args['notify_user'] = notify_user
            args['packages'] = ','.join(packages)
            args['uuid'] = uuid
            client_result = requests.get("%(protocol)s://%(address)s:%(port)d/forget.json?package=%(packages)s&notify_user=%(notify_user)s&notify_server=1&uuid=%(uuid)s" % args,proxies=None,verify=False, timeout=clients_read_timeout).text
            try:
                client_result = json.loads(client_result)
                if not isinstance(client_result,list):
                    client_result = [client_result]
                msg = _(u"Triggered tasks: {}").format(','.join(t['description'] for t in client_result))
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


@app.route('/api/v1/host_remove_packages')
@requires_auth
def host_remove_packages():
    """Proxy the wapt remove action to the client
            uuid
            packages
            notify_user
            notify_server
            force
    """
    try:
        uuid = request.args['uuid']
        packages = ensure_list(request.args['packages'])
        notify_user = request.args.get('notify_user',0)
        notify_server = request.args.get('notify_server',1)
        force = request.args.get('force',0)

        host_data = hosts().find_one({ "uuid": uuid},fields={'uuid':1,'wapt':1,'host.connected_ips':1})
        listening_address = get_ip_port(host_data)
        msg = u''
        if listening_address and listening_address['address'] and listening_address['port']:
            logger.info( "Removing packages %s from %s at address %s..." % (','.join(packages),uuid,listening_address['address']))
            args = {}
            args.update(listening_address)
            args['notify_user'] = notify_user
            args['notify_server'] = notify_server
            args['packages'] = ','.join(packages)
            args['force'] = force
            args['uuid'] = uuid
            client_result = requests.get("%(protocol)s://%(address)s:%(port)d/remove.json?package=%(packages)s&notify_user=%(notify_user)s&notify_server=%(notify_server)s&force=%(force)s&uuid=%(uuid)s" % args,proxies=None,verify=False, timeout=clients_read_timeout).text
            try:
                client_result = json.loads(client_result)
                if not isinstance(client_result,list):
                    client_result = [client_result]
                msg = _(u"Triggered tasks: {}").format(','.join(t['description'] for t in client_result))
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


@app.route('/api/v1/host_install_packages')
@requires_auth
def host_install_packages():
    """Proxy the wapt install action to the client
            uuid
            packages
            notify_user
            notify_server
    """
    try:
        uuid = request.args['uuid']
        packages = ensure_list(request.args['packages'])
        notify_user = request.args.get('notify_user',0)
        notify_server = request.args.get('notify_server',1)
        force = request.args.get('force',0)

        host_data = hosts().find_one({ "uuid": uuid},fields={'uuid':1,'wapt':1,'host.connected_ips':1})
        listening_address = get_ip_port(host_data)
        msg = u''
        if listening_address and listening_address['address'] and listening_address['port']:
            logger.info( "Trigger install packages %s for %s at address %s..." % (','.join(packages),uuid,listening_address['address']))
            args = {}
            args.update(listening_address)
            args['notify_user'] = notify_user
            args['notify_server'] = notify_server
            args['packages'] = ','.join(packages)
            args['force'] = force
            args['uuid'] = uuid
            client_result = requests.get("%(protocol)s://%(address)s:%(port)d/install.json?package=%(packages)s&notify_user=%(notify_user)s&notify_server=1&force=%(force)s&uuid=%(uuid)s" % args,proxies=None,verify=False, timeout=clients_read_timeout).text
            try:
                client_result = json.loads(client_result)
                if isinstance(client_result,list):
                    description = ','.join(t['description'] for t in client_result)
                else:
                    description = client_result['description']
                msg = _(u"Triggered tasks: {}").format(description)
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


@app.route('/api/v1/host_tasks_status')
@requires_auth
def host_tasks_status():
    """Proxy the get tasks status action to the client"""
    try:
        uuid = request.args['uuid']
        host_data = hosts().find_one({ "uuid": uuid},fields={'wapt':1,'host.connected_ips':1})
        #listening_address = get_ip_port(host_data)
        listening_address = host_data['wapt'].get('listening_address',None)

        if listening_address and listening_address['address'] and listening_address['port']:
            logger.info( "Get tasks status for %s at address %s..." % (uuid,listening_address['address']))
            args = {}
            args.update(listening_address)
            args['uuid'] = uuid
            client_result = requests.get("%(protocol)s://%(address)s:%(port)d/tasks.json?uuid=%(uuid)s" % args,proxies=None,verify=False,timeout=client_tasks_timeout).text
            try:
                client_result = json.loads(client_result)
            except ValueError:
                if 'Restricted access' in client_result:
                    raise EWaptForbiddden(client_result)
                else:
                    raise Exception(client_result)
        else:
            raise EWaptMissingHostData(_("The host reachability is not defined."))
        return make_response(client_result,
            msg = "Tasks status retrieved properly",
            success = isinstance(client_result,dict),)
    except Exception, e:
        return make_response_from_exception(e)

@app.route('/api/v1/groups')
@requires_auth
def get_groups():
    """List of packages having section == group
    """
    try:

        packages = WaptLocalRepo(wapt_folder)
        packages.load_packages()

        groups = [ p.as_dict() for p in packages.packages if p.section == 'group']
        msg = '{} Packages for section group'.format(len(groups))

    except Exception as e:
        return make_response_from_exception(e)

    return make_response(result=groups,msg=msg,status=200)


@app.route('/api/v1/hosts',methods=['DELETE'])
@app.route('/api/v1/hosts_delete',methods=['GET'])
@requires_auth
def hosts_delete():
    """
        query:
          uuid=<uuid1[,uuid2,...]>
        or
          filter=<csvlist of fields>:regular expression
    """
    try:
        # build filter
        if 'uuid' in request.args:
            query = {'uuid':{'$in':ensure_list(request.args['uuid'])}}
        elif 'filter' in request.args:
            (search_fields,search_expr) = request.args['filter'].split(':',1)
            if search_fields.strip() and search_expr.strip():
                query = {'$or':[ {fn:re.compile(search_expr, re.IGNORECASE)} for fn in ensure_list(search_fields)]}
            else:
                raise Exception('Neither uuid nor filter provided in query')
        else:
            raise Exception('Neither uuid nor filter provided in query')

        msg = []
        result = dict(files=[],records=[])

        hosts_packages_repo = WaptLocalRepo(wapt_folder+'-host')
        hosts_packages_repo.load_packages()

        packages_repo = WaptLocalRepo(wapt_folder)
        packages_repo.load_packages()

        if 'delete_packages' in request.args and request.args['delete_packages'] == '1':
            selected = hosts().find(query,fields={'uuid':1,'host.computer_fqdn':1})
            if selected:
                for host in selected:
                    result['records'].append(dict(uuid=host['uuid'],computer_fqdn=host['host']['computer_fqdn']))
                    if host['host']['computer_fqdn'] in hosts_packages_repo.index:
                        fn = hosts_packages_repo.index[host['host']['computer_fqdn']].wapt_fullpath()
                        logger.debug('Trying to remove %s' % fn)
                        if os.path.isfile(fn):
                            result['files'].append(fn)
                            os.remove(fn)
                msg.append('{} files removed from host repository'.format(len(result['files'])))
            else:
                msg.append('No host found in DB')

        remove_result = hosts().remove(query)
        if not remove_result['ok'] == 1:
            raise Exception('Error removing hosts from DB: %s'%(remove_result['err'],))

        nb = remove_result['n']
        msg.append('{} hosts removed from DB'.format(nb))

    except Exception as e:
        return make_response_from_exception(e)

    return make_response(result=result,msg='\n'.join(msg),status=200)



@app.route('/api/v1/hosts',methods=['GET'])
@requires_auth
def get_hosts():
    """
        query:
          uuid=<uuid>
        or
          filter=<csvlist of fields>:regular expression
        has_errors=1
        need_upgrade=1
        groups=<csvlist of packages>
        columns=<csvlist of columns>
    """
    try:
        default_columns = [u'host_status',
                         u'update_status',
                         u'reachable',
                         u'host.computer_fqdn',
                         u'host.description',
                         u'host.system_manufacturer',
                         u'host.system_productname',
                         u'dmi.Chassis_Information.Serial_Number',
                         u'last_query_date',
                         u'host.mac',
                         u'host.connected_ips',
                         u'wapt.*',
                         u'uuid',
                         u'md5sum',
                         u'purchase_order',
                         u'purchase_date',
                         u'groups',
                         u'attributes',
                         u'host.domain_controller',
                         u'host.domain_name',
                         u'host.domain_controller_address',
                         u'depends',
                         u'dmi.Chassis_Information.Type',
                         u'host.windows_product_infos.product_key',
                         u'host.windows_product_infos.version']

        # keep only top tree nodes (mongo doesn't want fields like {'wapt':1,'wapt.listening_address':1} !
        # minimum columns
        columns = ['uuid','host','wapt','update_status']
        other_columns = ensure_list(request.args.get('columns',default_columns))

        # add request columns
        for fn in other_columns:
            if not fn in columns:
                columns.append(fn)

        # remove children
        columns_tree =  [c.split('.') for c in columns]
        columns_tree.sort()
        last = None
        new_tree = []
        for col in columns_tree:
            if last is None or col[:len(last)] != last:
                new_tree.append(col)
                last = col

        columns = ['.'.join(c) for c in new_tree]

        # build filter
        if 'uuid' in request.args:
            query = dict(uuid=request.args['uuid'])
        elif 'filter' in request.args:
            (search_fields,search_expr) = request.args['filter'].split(':',1)
            if search_fields.strip() and search_expr.strip():
                query = {'$or':[ {fn:re.compile(search_expr, re.IGNORECASE)} for fn in ensure_list(search_fields)]}
            else:
                query = {}
        else:
            query = {}


        if 'has_errors' in request.args and request.args['has_errors']:
            query["packages.install_status"] = "ERROR"
        if "need_upgrade" in request.args and request.args['need_upgrade']:
            query["update_status.upgrades"] = {"$exists": "true", "$ne" :[]}

        hosts_packages_repo = WaptLocalRepo(wapt_folder+'-host')
        hosts_packages_repo.load_packages()

        packages_repo = WaptLocalRepo(wapt_folder)
        packages_repo.load_packages()

        groups = ensure_list(request.args.get('groups',''))

        result = []
        print { col:1 for col in columns }
        for host in hosts().find(query,fields={ col:1 for col in columns }):
            host.pop("_id")
            if ('depends' in columns or groups) and 'host' in host and 'computer_fqdn' in host['host']:
                host_package = hosts_packages_repo.index.get(host['host']['computer_fqdn'],None)
                if host_package:
                    depends = ensure_list(host_package.depends.split(','))
                    host['depends'] = [ d for d in depends
                            if (d in packages_repo.index and packages_repo.index[d].section == 'group')]
                else:
                    depends = []
            else:
                depends = []
            try:
                la = host['wapt']['listening_address']
                if la['address']  and la['timestamp']:
                    reachable = 'OK'
                elif not la['address'] and la['timestamp']:
                    reachable = 'UNREACHABLE'
                else:
                    reachable = 'UNKNOWN'
                host['reachable'] = reachable
            except (KeyError,TypeError):
                host['reachable'] = 'UNKNOWN'

            try:
                if 'update_status' in host:
                    us = host['update_status']
                    if us.get('errors',[]):
                        host['host_status'] = 'ERROR'
                    elif us.get('upgrades',[]):
                        host['host_status'] = 'TO-UPGRADE'
                    else:
                        host['host_status'] = 'OK'
                else:
                    host['host_status'] = '?'
            except:
                host['host_status'] = '?'

            if not groups or list(set(groups) & set(depends)):
                result.append(host)

        if  'uuid' in request.args:
            if len(result) == 0:
                msg = 'No data found for uuid {}'.format(request.args['uuid'])
            else:
                msg = 'host data fields {} returned for uuid {}'.format(','.join(columns),request.args['uuid'])
        elif 'filter' in request.args:
            if len(result) == 0:
                msg = 'No data found for filter {}'.format(request.args['filter'])
            else:
                msg = '{} hosts returned for filter {}'.format(len(result),request.args['filter'])
        else:
            if len(result) == 0:
                msg = 'No data found'
            else:
                msg = '{} hosts returned'.format(len(result))

    except Exception as e:
        return make_response_from_exception(e)

    return make_response(result=result,msg=msg,status=200)

@app.route('/api/v1/host_data')
@requires_auth
def host_data():
    """
        Get additional data for a host
        query:
          uuid=<uuid>
          field=packages, dmi or softwares
    """
    try:
        # build filter
        if 'uuid' in request.args:
            uuid = request.args['uuid']
        else:
            raise EWaptMissingParameter('Parameter uuid is missing')

        if 'field' in request.args:
            field = request.args['field']
        else:
            raise EWaptMissingParameter('Parameter field is missing')

        data = hosts().find_one({'uuid':uuid},fields={field:1})
        if data is None:
            raise EWaptUnknownHost('Host {} not found in database'.format(uuid) )
        else:
            msg = '{} data for host {}'.format(field,uuid)

    except Exception as e:
        return make_response_from_exception(e)

    result = data.get(field,None)
    if result is None:
        msg = 'No {} data for host {}'.format(field,uuid)
        success = False
        error_code = 'empty_data'
    else:
        success = True
        error_code = None

    return make_response(result=result,msg=msg,success=success,error_code=error_code,status=200)


@app.route('/api/v1/hosts',methods=['POST'])
@requires_auth
def update_hosts():
    """update one or several hosts
        post data is a json list of host data
        for each host, the key is the uuid
    """
    post_data = ensure_list(json.loads(request.data))
    msg = []
    result = []

    try:
        for data in post_data:
            # build filter
            if not 'uuid' in data:
                raise Exception('No uuid provided in post host data')
            uuid = data["uuid"]
            result.append(hosts().update({'uuid':uuid},{"$set": data},upsert=True))
            # check if client is reachable
            if not 'check_hosts_thread' in g or not g.check_hosts_thread.is_alive():
                logger.info('Creates check hosts thread for %s'%(uuid,))
                g.check_hosts_thread = CheckHostsWaptService(timeout=clients_connect_timeout,uuids=[uuid])
                g.check_hosts_thread.start()
            else:
                logger.info('Reuses current check hosts thread for %s'%(uuid,))
                g.check_hosts_thread.queue.append(data)

            msg.append('host {} updated in DB'.format(uuid))

    except Exception as e:
        return make_response_from_exception(e)

    return make_response(result=result,msg='\n'.join(msg),status=200)

@app.route('/api/v1/host_cancel_task')
@requires_auth
def host_cancel_task():
    try:
        uuid = request.args['uuid']
        host_data = hosts().find_one({ "uuid": uuid},fields={'wapt':1,'host.connected_ips':1})
        #listening_address = get_ip_port(host_data)
        listening_address = host_data['wapt'].get('listening_address',None)

        if listening_address and listening_address['address'] and listening_address['port']:
            logger.info( "Get tasks status for %s at address %s..." % (uuid,listening_address['address']))
            args = {}
            args.update(listening_address)
            args['uuid'] = uuid
            client_result = requests.get("%(protocol)s://%(address)s:%(port)d/cancel_running_task.json?uuid=%(uuid)s" % args,proxies=None,verify=False,timeout=client_tasks_timeout).text
            try:
                client_result = json.loads(client_result)
            except ValueError:
                if 'Restricted access' in client_result:
                    raise EWaptForbiddden(client_result)
                else:
                    raise Exception(client_result)
        else:
            raise EWaptMissingHostData(_("The host reachability is not defined."))
        return make_response(client_result,
            msg = "Task canceled",
            success = isinstance(client_result,dict),)
    except Exception, e:
        return make_response_from_exception(e)



@app.route('/api/v1/usage_statistics')
def usage_statistics():
    """returns some anonymous usage statistics to give an idea of depth of use"""
    hosts = get_db().hosts
    try:
        stats = hosts.aggregate([
            {'$unwind':'$packages'},
            {'$group':
                {'_id':'$uuid',
                    'last_query_date':{'$first':{'$substr':['$last_query_date',0,10]}},
                    'count':{'$sum':1},
                    'ok':{'$sum':{'$cond':[{'$eq': ['$packages.install_status', 'OK']},1,0]}},
                    'has_error':{'$first':{'$cond':[{'$ne':['$update_status.errors',[]]},1,0]}},
                    'need_upgrade':{'$first':{'$cond':[{'$ne':['$update_status.upgrades',[]]},1,0]}},
                }},
            {'$group':
                {'_id':1,
                    'hosts_count':{'$sum':1},
                    'oldest_query':{'$min':'$last_query_date'},
                    'newest_query':{'$max':'$last_query_date'},
                    'packages_count_max':{'$max':'$count'},
                    'packages_count_avg':{'$avg':'$count'},
                    'packages_count_ok':{'$sum':'$ok'},
                    'hosts_count_has_error':{'$sum':'$has_error'},
                    'hosts_count_need_upgrade':{'$sum':'$need_upgrade'},
                }},
            ])
        del(stats['result'][0]['_id'])
    except:
        # fallback for old mongo without aggregate framework
        stats = {}
        stats['result'] = [
            {
                'hosts_count':hosts.count(),
            }]

    result = dict(
        uuid = server_uuid,
        platform = platform.system(),
        architecture = platform.architecture(),
        version = __version__,
        date = datetime2isodate(),
        )
    result.update(stats['result'][0])
    return make_response(msg = _('Anomnymous usage statistics'), result = result)

def wget(url,target,proxies=None,connect_timeout=10,download_timeout=None):
    r"""Copy the contents of a file from a given URL to a local file.
    >>> respath = wget('http://wapt.tranquil.it/wapt/tis-firefox_28.0.0-1_all.wapt','c:\\tmp\\test.wapt',proxies={'http':'http://proxy:3128'})
    ???
    >>> os.stat(respath).st_size>10000
    True
    >>> respath = wget('http://localhost:8088/runstatus','c:\\tmp\\test.json')
    ???
    """
    if os.path.isdir(target):
        target = os.path.join(target,'')

    (dir,filename) = os.path.split(target)
    if not filename:
        filename = url.split('/')[-1]
    if not dir:
        dir = os.getcwd()

    if not os.path.isdir(dir):
        os.makedirs(dir)

    httpreq = requests.get(url,stream=True, proxies=proxies, timeout=connect_timeout, verify=False)

    total_bytes = int(httpreq.headers['content-length'])
    # 1MB max, 2KB min
    chunk_size = min([1024*1024,max([total_bytes/100,2048])])

    with open(os.path.join(dir,filename),'wb') as output_file:
        last_downloaded = 0
        if httpreq.ok:
            for chunk in httpreq.iter_content(chunk_size=chunk_size):
                output_file.write(chunk)
                if download_timeout is not None and (time.time()-start_time>download_timeout):
                    raise requests.Timeout(r'Download of %s takes more than the requested %ss'%(url,download_timeout))
                last_downloaded += len(chunk)
        else:
            httpreq.raise_for_status()

    # restore mtime of file if information is provided.
    if 'last-modified' in httpreq.headers:
        filedate = isodate2datetime(httpdatetime2isodate(httpreq.headers['last-modified']))
        unixtime = time.mktime(filedate.timetuple())
        os.utime(os.path.join(dir,filename),(unixtime,unixtime))
    return os.path.join(dir,filename)

SPOOL_OK = -2 # the task has been completed, the spool file will be removed
SPOOL_RETRY = -1 # something is temporarily wrong, the task will be retried at the next spooler iteration
SPOOL_IGNORE = 0 #  ignore this task, if multiple languages are loaded in the instance all of them will fight for managing the task. This return values allows you to skip a task in specific languages.

@spool
def download_wsusscan(force=False):
    """Launch a task to update current wsus offline cab file
        download in a temporary well known file
        abort if the temporary file is present (means another download is in progress

    """
    cab_url = 'http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab'
    wsus_filename = os.path.join(waptwua_folder,'wsusscn2.cab')
    tmp_filename = os.path.join(waptwua_folder,'wsusscn2.cab.tmp')

    wsusscan2_history = None
    stats = {
        'run_date': datetime2isodate()
    }

    if not force and os.path.isfile(tmp_filename):
        # check if not too old.... ?
        return SPOOL_OK
    try:

        wsusscan2_history = pymongo.MongoClient().wapt.wsusscan2_history
        new_cab_date =  httpdatetime2isodate(requests.head(cab_url).headers['last-modified'])
        if os.path.isfile(wsus_filename):
            current_cab_date = datetime2isodate(datetime.datetime.utcfromtimestamp(os.stat(wsus_filename).st_mtime))
        else:
            current_cab_date = ''
        logger.info('Current cab date: %s, New cab date: %s'%(current_cab_date,new_cab_date))

        if not os.path.isfile(wsus_filename) or ( new_cab_date > current_cab_date ) or force:
            #wget(cab_url,tmp_filename)
            os.link(wsus_filename, tmp_filename)

            file_stats = os.stat(tmp_filename)
            stats['file_timestamp'] = file_stats[stat.ST_MTIME]
            stats['file_size'] = file_stats[stat.ST_SIZE]

            # check integrity
            try:

                if sys.platform == 'win32':
                    cablist = subprocess.check_output('expand -D "%s"' % tmp_filename,shell = True).decode('cp850').splitlines()
                else:
                    cablist = subprocess.check_output('cabextract -t "%s"' % tmp_filename ,shell = True).splitlines()
                stats['cablist'] = cablist

            except Exception as e:
                if os.path.isfile(tmp_filename):
                    os.unlink(tmp_filename)

                stats['error'] = str(e)
                try:
                    wsusscan2_history.insert(stats)
                except Exception:
                    pass
                logger.error("Error in download_wsusscan: %s", str(e))
                logger.error('Trace:\n%s', traceback.format_exc())
                return SPOOL_OK

            if os.path.isfile(wsus_filename):
                os.unlink(wsus_filename)
            os.rename(tmp_filename, wsus_filename)

            try:
                wsusscan2_history.insert(stats)
            except Exception:
                pass

            parse_wsusscan2.spool(arg=None)

        else:
            stats['skipped'] = True
            try:
                wsusscan2_history.insert(stats)
            except Exception:
                pass

        return SPOOL_OK

    except Exception as e:
        stats.update({ 'error': str(e) })
        if wsusscan2_history:
            try:
                wsusscan2_history.insert(stats)
            except:
                pass
        logger.error("Error in download_wsusscan: %s", str(e))
        logger.error('Trace:\n%s', traceback.format_exc())
        return SPOOL_OK


def wsusscan2_extract_cabs(wsusscan2, tmpdir):

    if not os.path.exists(wsusscan2):
        logger.error("%s does not exist", wsusscan2)

    packages = os.path.join(tmpdir, 'packages')

    mkdir_p(packages)

    subprocess.check_output(['cabextract', '-d', packages, wsusscan2])

    cab_list = filter(lambda f: f.endswith('.cab'), os.listdir(packages))

    for cab in cab_list:
        cab_path = os.path.join(packages, cab)
        package_dir = cab_path[:-len('.cab')]
        mkdir_p(package_dir)
        subprocess.check_output(['cabextract', '-d', package_dir, cab_path])

    subprocess.check_output(['cabextract', '-d', packages, os.path.join(packages, 'package.cab')])

# end of cab extraction

# start of updates parsing

OFFLINE_SYNC_PFX = '{http://schemas.microsoft.com/msus/2004/02/OfflineSync}'

def off_sync_qualify(tag):
    return OFFLINE_SYNC_PFX + tag

UpdateCategories = [
    'Company',
    'Product',
    'ProductFamily',
    'UpdateClassification',
]

def wsusscan2_do_parse_update(update, db):

    superseded = update.findall(off_sync_qualify('SupersededBy'))
    if superseded:
        return

    upd = {}

    upd['update_id'] = update.get('UpdateId')

    if update.get('IsBundle', False):
        upd['is_bundle'] = True

    if update.get('IsLeaf', False):
        upd['is_leaf'] = True

    if update.get('RevisionId', False) != False:
        upd['revision_id'] = update.get('RevisionId')

    if update.get('RevisionNumber', False) != False:
        upd['revision_number'] = update.get('RevisionNumber')

    if db.wsus_updates.find(upd).count() != 0:
        return

    if update.get('DeploymentAction', False) != False:
        upd['deployment_action'] = update.get('DeploymentAction')

    if update.get('CreationDate', False) != False:
        upd['creation_date'] = update.get('CreationDate')

    categories = update.findall(off_sync_qualify('Categories'))
    if categories:
        upd['categories'] = {}
        for cat in categories:
            for subcat in cat.getchildren():
                type_ = subcat.get('Type')
                assert type_ in UpdateCategories
                upd['categories'][type_] = subcat.get('Id').lower()

    languages = update.findall(off_sync_qualify('Languages'))
    if languages:
        upd['languages'] = []
        assert len(languages) == 1
        for l in languages[0].findall(off_sync_qualify('Language')):
            upd['languages'].append(l.get('Name'))

    prereqs = update.findall(off_sync_qualify('Prerequisites'))
    if prereqs:
        upd['prereqs'] = []
        assert len(prereqs) == 1
        for update_ in prereqs[0].iterchildren(off_sync_qualify('UpdateId')):
                upd['prereqs'].append(update_.get('Id').lower())

    files = update.findall(off_sync_qualify('PayloadFiles'))
    if files:
        upd['payload_files'] = []
        for files_ in files:
            for f in files_.iter(off_sync_qualify('File')):
                upd['payload_files'].append(f.get('Id'))

    bundled_by = update.findall(off_sync_qualify('BundledBy'))
    if bundled_by:
        assert len(bundled_by) == 1
        revisions = bundled_by[0].findall(off_sync_qualify('Revision'))
        old_id = None
        for rev in revisions:
            if old_id is None:
                id_ = rev.get('Id')
            else:
                assert old_id == rev.get('Id')
        upd['bundled_by'] = id_

    db.wsus_updates.update(upd, upd, upsert=True)


def wsusscan2_do_parse_file_location(location, db):

    location_id = location.get('Id')
    location_url = location.get('Url')

    locations_collection = db.wsus_locations
    locations_collection.update(
        { 'id': location_id },
        {
            'id': location_id,
            'url': location_url,
        },
        upsert=True
    )


def wsusscan2_parse_updates(tmpdir, db):

    package_xml = os.path.join(tmpdir, 'package.xml')
    for _, elem in ET.iterparse(package_xml):
        if elem.tag == off_sync_qualify('Update'):
            wsusscan2_do_parse_update(elem, db)
        elif elem.tag == off_sync_qualify('FileLocation'):
            wsusscan2_do_parse_file_location(elem, db)

# end of updates parsing

# start of metadata parsing

UPDATE_SCHEMA_PFX = "{http://schemas.microsoft.com/msus/2002/12/Update}"

def update_qualify(tag):
    return UPDATE_SCHEMA_PFX + tag

def wsusscn2_parse_metadata(upd, descr_file):

    data = {}

    if not os.path.exists(descr_file):
        return
    if os.path.getsize(descr_file) == 0:
        return

    try:
        xml_str = file(descr_file, 'r').read()
        root = ET.fromstring(xml_str)

        logger.debug("")

        props = root.find(update_qualify('Properties'))

        creation_date = props.get('CreationDate')
        if creation_date is not None:
            data['creation_date2'] = creation_date

        msrc_severity = props.get('MsrcSeverity')
        if msrc_severity is not None:
            data['msrc_severity'] = msrc_severity
            logger.debug('MsrcSeverity: %s', data['msrc_severity'])

        elem = props.find(update_qualify('KBArticleID'))
        if elem is not None:
            data['kb_article_id'] = elem.text
            logger.debug('KBArticleID: %s', data['kb_article_id'])

        elem = props.find(update_qualify('SecurityBulletinID'))
        if elem is not None:
            data['security_bulletin_id'] = elem.text
            logger.debug('SecurityBulletinID: %s', data['security_bulletin_id'])

        localized_properties_collection = root.find(update_qualify('LocalizedPropertiesCollection'))
        for elem in localized_properties_collection.iter():
            if elem.tag.endswith('LocalizedProperties'):

                lang = elem.find(update_qualify('Language'))
                if lang is not None:
                    if lang.text != 'en':
                        break
                else:
                    continue

                title = elem.find(update_qualify('Title'))
                if title is not None and title.text != '':
                    data['title'] = title.text
                    logger.debug('Title: %s', data['title'])

                descr = elem.find(update_qualify('Description'))
                if descr is not None and descr.text != '':
                    data['description'] = descr.text
                    logger.debug('Description: %s', data['description'])

    except Exception, e:
        logger.warning("Error while using %s: %s", descr_file, str(e))

    return data


def amend_metadata(directory, db):

    def find_cab(rev, cabset):
        for start, cab in cabset.items():
            if int(rev) > int(start):
                return cab

    xmlindex = os.path.join(directory, 'index.xml')
    tree = ET.parse(xmlindex)
    root = tree.getroot()
    cablist = root.find('CABLIST').findall('CAB')

    cabs = {}
    for cab in cablist:
        cabname = cab.get('NAME')
        rangestart = cab.get('RANGESTART')
        # 'package.cab' has no rangestart attribute
        if rangestart is None:
            continue
        # strip the extension, keep the directory name
        cabs[rangestart] = cabname[:-len('.cab')]

    cabs = collections.OrderedDict(
        sorted(
            cabs.items(),
            key=lambda i: int(i[0]),
            reverse=True
        )
    )

    for update in db.wsus_updates.find():

        rev = update.get('revision_id')
        # no revision -> no metadata on disk
        if rev is None:
            continue

        cab_dir = find_cab(rev, cabs)

        descr_file = os.path.join(directory, cab_dir, 's', rev)
        metadata = wsusscn2_parse_metadata(update, descr_file)
        if metadata:
            db.wsus_updates.update(
                { "_id": update["_id"] },
                {
                    "$set": metadata,
                }
            )

# end of metadata parsing

def wsusscan_parse_entrypoint():
    wsusscan2 = os.path.join(waptwua_folder, 'wsusscn2.cab')

    client = pymongo.MongoClient()
    db = client.wapt

    tmpdir = tempfile.mkdtemp(prefix='wsusscn2', dir=waptwua_folder)
    #wsusscan2_extract_cabs(wsusscan2, tmpdir)

    packages = os.path.join(waptwua_folder, 'packages')
    #shutil.rmtree(packages)
    #shutil.move(tmpdir, packages)

    wsusscan2_parse_updates(packages, db)
    amend_metadata(packages, db)


@spool
def parse_wsusscan2(arg=None):

    runtime = pymongo.MongoClient().wapt.wsus_runtime
    try:
        runtime.insert({ '_id': WSUS_PARSE_WSUSSCN2_LOCK })
        parse_wsusscan_entry()
    except Exception as e:
        runtime.remove({'_id': WSUS_PARSE_WSUSSCN2_LOCK })
        logger.error('Exception in parse_wsusscan2: %s', str(e))


@app.route('/api/v2/download_wsusscan')
def trigger_wsusscan2_download():
    force = request.args.get('force', False)
    logger.info('Triggering download_wsusscan with parameter ' + str(force))
    download_wsusscan.spool(force=force)
    return make_response()


@app.route('/api/v2/wsusscan2_status')
def wsusscan2_status():
    wsus_filename = os.path.join(waptwua_folder,'wsusscn2.cab')
    tmp_filename = os.path.join(waptwua_folder,'wsusscn2.cab.tmp')

    success = False
    data = {}
    try:
        stats = os.stat(wsus_filename)
        success = True
        data.update({
            'wsus_timestamp': stats[stat.ST_MTIME],
            'wsus_size':      stats[stat.ST_SIZE],
        })
    except Exception:
        pass

    try:
        tmp_stats = os.stat(tmp_filename)
        data.update({
            'tmp_wsus_timestamp': tmp_stats[stat.ST_MTIME],
            'tmp_wsus_size':      tmp_stats[stat.ST_SIZE],
        })
    except Exception:
        pass

    return make_response(success=success, result=data)

@app.route('/api/v2/wsusscan2_history')
def wsusscan2_history():
    data = []
    wsusscan2_history = get_db().wsusscan2_history
    for log in wsusscan2_history.find():
        data.append(log)
    return make_response(result=data)


#https://msdn.microsoft.com/en-us/library/ff357803%28v=vs.85%29.aspx
update_classifications_id = {
 '28bc880e-0592-4cbf-8f95-c79b17911d5f': 'UpdateRollups',    # Ensemble de mises à jour
 'b54e7d24-7add-428f-8b75-90a396fa584f': 'FeaturePacks',     # feature packs
 'e6cf1350-c01b-414d-a61f-263d14d133b4': 'CriticalUpdates',  # Mises à jour critiques
 '0fa1201d-4330-4fa8-8ae9-b877473b6441': 'SecurityUpdates',  # Mises à jour de la sécurité
 'cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83': 'Updates',          # Mises à jour
 'e0789628-ce08-4437-be74-2495b842f43b': 'DefinitionUpdates',# Mises à jour de définitions
 'b4832bd8-e735-4761-8daf-37f882276dab': 'Tools',            # Outils
 'ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0': 'Drivers',          # Pilotes
 '68c5b0a3-d1a6-4553-ae49-01d3a7827828': 'ServicePacks',     # Services pack
 '434de588-ed14-48f5-8eed-a15e09a991f6': 'Connectors',       #
 '5c9376ab-8ce6-464a-b136-22113dd69801': 'Application',      #
 '9511d615-35b2-47bb-927f-f73d8e9260bb': 'Guidance',         #
 'e140075d-8433-45c3-ad87-e72345b36078': 'DeveloperKits',    #
 }

#https://msdn.microsoft.com/en-us/library/bb902472%28v=vs.85%29.aspx
detectoid_id = {
 '59653007-e2e9-4f71-8525-2ff588527978': 'x64-based systems',
 'aabd43ad-a183-4f0b-8eee-8dbbcd67687f': 'Itanium-based systems',
 '3e0afb10-a9fb-4c16-a60e-5790c3803437': 'x86-based systems',
}


products_id = {
    "fdcfda10-5b1f-4e57-8298-c744257e30db":"Active Directory Rights Management Services Client 2.0",
    "57742761-615a-4e06-90bb-008394eaea47":"Active Directory",
    "5d6a452a-55ba-4e11-adac-85e180bda3d6":"Antigen for Exchange/SMTP",
    "116a3557-3847-4858-9f03-38e94b977456":"Antigen",
    "b86cf33d-92ac-43d2-886b-be8a12f81ee1":"Bing Bar",
    "2b496c37-f722-4e7b-8467-a7ad1e29e7c1":"Bing",
    "34aae785-2ae3-446d-b305-aec3770edcef":"BizTalk Server 2002",
    "86b9f801-b8ec-4d16-b334-08fba8567c17":"BizTalk Server 2006R2",
    "b61793e6-3539-4dc8-8160-df71054ea826":"BizTalk Server 2009",
    "61487ade-9a4e-47c9-baa5-f1595bcdc5c5":"BizTalk Server 2013",
    "ed036c16-1bd6-43ab-b546-87c080dfd819":"BizTalk Server",
    "83aed513-c42d-4f94-b4dc-f2670973902d":"CAPICOM",
    "236c566b-aaa6-482c-89a6-1e6c5cac6ed8":"Category for System Center Online Client",
    "ac615cb5-1c12-44be-a262-fab9cd8bf523":"Compute Cluster Pack",
    "eb658c03-7d9f-4bfa-8ef3-c113b7466e73":"Data Protection Manager 2006",
    "48ce8c86-6850-4f68-8e9d-7dc8535ced60":"Developer Tools, Runtimes, and Redistributables",
    "f76b7f51-b762-4fd0-a35c-e04f582acf42":"Dictionary Updates for Microsoft IMEs",
    "83a83e29-7d55-44a0-afed-aea164bc35e6":"Exchange 2000 Server",
    "3cf32f7c-d8ee-43f8-a0da-8b88a6f8af1a":"Exchange Server 2003",
    "ab62c5bd-5539-49f6-8aea-5a114dd42314":"Exchange Server 2007 and Above Anti-spam",
    "26bb6be1-37d1-4ca6-baee-ec00b2f7d0f1":"Exchange Server 2007",
    "9b135dd5-fc75-4609-a6ae-fb5d22333ef0":"Exchange Server 2010",
    "d3d7c7a6-3e2f-4029-85bf-b59796b82ce7":"Exchange Server 2013",
    "352f9494-d516-4b40-a21a-cd2416098982":"Exchange",
    "fa9ff215-cfe0-4d57-8640-c65f24e6d8e0":"Expression Design 1",
    "f3b1d39b-6871-4b51-8b8c-6eb556c8eee1":"Expression Design 2",
    "18a2cff8-9fd2-487e-ac3b-f490e6a01b2d":"Expression Design 3",
    "9119fae9-3fdd-4c06-bde7-2cbbe2cf3964":"Expression Design 4",
    "5108d510-e169-420c-9a4d-618bdb33c480":"Expression Media 2",
    "d8584b2b-3ac5-4201-91cb-caf6d240dc0b":"Expression Media V1",
    "a33f42ac-b33f-4fd2-80a8-78b3bfa6a142":"Expression Web 3",
    "3b1e1746-d99b-42d4-91fd-71d794f97a4d":"Expression Web 4",
    "ca9e8c72-81c4-11dc-8284-f47156d89593":"Expression",
    "d72155f3-8aa8-4bf7-9972-0a696875b74e":"Firewall Client for ISA Server",
    "0a487050-8b0f-4f81-b401-be4ceacd61cd":"Forefront Client Security",
    "a38c835c-2950-4e87-86cc-6911a52c34a3":"Forefront Endpoint Protection 2010",
    "86134b1c-cf56-4884-87bf-5c9fe9eb526f":"Forefront Identity Manager 2010 R2",
    "d7d32245-1064-4edf-bd09-0218cfb6a2da":"Forefront Identity Manager 2010",
    "a6432e15-a446-44af-8f96-0475c472aef6":"Forefront Protection Category",
    "f54d8a80-c7e1-476c-9995-3d6aee4bfb58":"Forefront Server Security Category",
    "84a54ea9-e574-457a-a750-17164c1d1679":"Forefront Threat Management Gateway, Definition Updates for HTTP Malware Inspection",
    "06bdf56c-1360-4bb9-8997-6d67b318467c":"Forefront TMG MBE",
    "59f07fb7-a6a1-4444-a9a9-fb4b80138c6d":"Forefront TMG",
    "f8c3c9a9-10de-4f09-bc16-5eb1b861fb4c":"Forefront",
    "f0474daf-de38-4b6e-9ad6-74922f6f539d":"Fotogalerie-Installation und -Upgrades",
    "d84d138e-8423-4102-b317-91b1339aa9c9":"HealthVault Connection Center Upgrades",
    "2e068336-2ead-427a-b80d-5b0fffded7e7":"HealthVault Connection Center",
    "0c6af366-17fb-4125-a441-be87992b953a":"Host Integration Server 2000",
    "784c9f6d-959a-433f-b7a3-b2ace1489a18":"Host Integration Server 2004",
    "eac7e88b-d8d4-4158-a828-c8fc1325a816":"Host Integration Server 2006",
    "42b678ae-2b57-4251-ae57-efbd35e7ae96":"Host Integration Server 2009",
    "3f3b071e-c4a6-4bcc-b6c1-27122b235949":"Host Integration Server 2010",
    "5964c9f1-8e72-4891-a03a-2aed1c4115d2":"HPC Pack 2008",
    "4f93eb69-8b97-4677-8de4-d3fca7ed10e6":"HPC Pack",
    "d123907b-ba63-40cb-a954-9b8a4481dded":"Installation von OneCare Family Safety",
    "b627a8ff-19cd-45f5-a938-32879dd90123":"Internet Security and Acceleration Server 2004",
    "2cdbfa44-e2cb-4455-b334-fce74ded8eda":"Internet Security and Acceleration Server 2006",
    "0580151d-fd22-4401-aa2b-ce1e3ae62bc9":"Internet Security and Acceleration Server",
    "5cc25303-143f-40f3-a2ff-803a1db69955":"Lokal veröffentlichte Pakete",
    "7c40e8c2-01ae-47f5-9af2-6e75a0582518":"Lokaler Herausgeber",
    "00b2d754-4512-4278-b50b-d073efb27f37":"Microsoft Application Virtualization 4.5",
    "c755e211-dc2b-45a7-be72-0bdc9015a63b":"Microsoft Application Virtualization 4.6",
    "1406b1b4-5441-408f-babc-9dcb5501f46f":"Microsoft Application Virtualization 5.0",
    "523a2448-8b6c-458b-9336-307e1df6d6a6":"Microsoft Application Virtualization",
    "7e903438-3690-4cf0-bc89-2fc34c26422b":"Microsoft BitLocker Administration and Monitoring v1",
    "c8c19432-f207-4d9d-ab10-764f3d29744d":"Microsoft BitLocker Administration and Monitoring",
    "587f7961-187a-4419-8972-318be1c318af":"Microsoft Dynamics CRM 2011 SHS",
    "2f3d1aba-2192-47b4-9c8d-87b41f693af4":"Microsoft Dynamics CRM 2011",
    "0dbc842c-730f-4361-8811-1b048f11c09b":"Microsoft Dynamics CRM",
    "e7ba9d21-4c88-4f88-94cb-a23488e59ebd":"Microsoft HealthVault",
    "5e870422-bd8f-4fd2-96d3-9c5d9aafda22":"Microsoft Lync 2010",
    "04d85ac2-c29f-4414-9cb6-5bcd6c059070":"Microsoft Lync Server 2010",
    "01ce995b-6e10-404b-8511-08142e6b814e":"Microsoft Lync Server 2013",
    "2af51aa0-509a-4b1d-9218-7e7508f05ec3":"Microsoft Lync Server and Microsoft Lync",
    "935c5617-d17a-37cc-dbcf-423e5beab8ea":"Microsoft Online Services",
    "b0247430-6f8d-4409-b39b-30de02286c71":"Microsoft Online Services-Anmelde-Assistent",
    "a8f50393-2e42-43d1-aaf0-92bec8b60775":"Microsoft Research AutoCollage 2008",
    "0f3412f2-3405-4d86-a0ff-0ede802227a8":"Microsoft Research AutoCollage",
    "b567e54e-648b-4ac6-9171-149a19a73da8":"Microsoft Security Essentials",
    "e9ece729-676d-4b57-b4d1-7e0ab0589707":"Microsoft SQL Server 2008 R2 - PowerPivot for Microsoft Excel 2010",
    "56750722-19b4-4449-a547-5b68f19eee38":"Microsoft SQL Server 2012",
    "fe324c6a-dac1-aca8-9916-db718e48fa3a":"Microsoft SQL Server PowerPivot for Excel",
    "a73eeffa-5729-48d4-8bf4-275132338629":"Microsoft StreamInsight V1.0",
    "4c1a298e-8dbd-5d8b-a52f-6c176fdd5904":"Microsoft StreamInsight",
    "5ef2c723-3e0b-4f87-b719-78b027e38087":"Microsoft System Center Data Protection Manager",
    "bf6a6018-83f0-45a6-b9bf-074a78ec9c82":"Microsoft System Center DPM 2010",
    "29fd8922-db9e-4a97-aa00-ca980376b738":"Microsoft System Center Virtual Machine Manager 2007",
    "7e5d0309-78dd-4f52-a756-0259f88b634b":"Microsoft System Center Virtual Machine Manager 2008",
    "b790e43b-f4e4-48b4-9f0c-499194f00841":"Microsoft Works 8",
    "e9c87080-a759-475a-a8fa-55552c8cd3dc":"Microsoft Works 9",
    "56309036-4c77-4dd9-951a-99ee9c246a94":"Microsoft",
    "6b9e8b26-8f50-44b9-94c6-7846084383ec":"MS Security Essentials",
    "4217668b-66f0-42a0-911e-a334a5e4dbad":"Network Monitor 3",
    "35c4463b-35dc-42ac-b0ba-1d9b5c505de2":"Network Monitor",
    "8508af86-b85e-450f-a518-3b6f8f204eea":"New Dictionaries for Microsoft IMEs",
    "6248b8b1-ffeb-dbd9-887a-2acf53b09dfe":"Office 2002/XP",
    "1403f223-a63f-f572-82ba-c92391218055":"Office 2003",
    "041e4f9f-3a3d-4f58-8b2f-5e6fe95c4591":"Office 2007",
    "84f5f325-30d7-41c4-81d1-87a0e6535b66":"Office 2010",
    "704a0a4a-518f-4d69-9e03-10ba44198bd5":"Office 2013",
    "22bf57a8-4fe1-425f-bdaa-32b4f655284b":"Office Communications Server 2007 R2",
    "e164fc3d-96be-4811-8ad5-ebe692be33dd":"Office Communications Server 2007",
    "504ae250-57c5-484a-8a10-a2c35ea0689b":"Office Communications Server And Office Communicator",
    "8bc19572-a4b6-4910-b70d-716fecffc1eb":"Office Communicator 2007 R2",
    "03c7c488-f8ed-496c-b6e0-be608abb8a79":"Office Live",
    "ec231084-85c2-4daf-bfc4-50bbe4022257":"Office Live-Add-In",
    "477b856e-65c4-4473-b621-a8b230bb70d9":"Office",
    "dd78b8a1-0b20-45c1-add6-4da72e9364cf":"OOBE ZDP",
    "7cf56bdd-5b4e-4c04-a6a6-706a2199eff7":"Report Viewer 2005",
    "79adaa30-d83b-4d9c-8afd-e099cf34855f":"Report Viewer 2008",
    "f7f096c9-9293-422d-9be8-9f6e90c2e096":"Report Viewer 2010",
    "9f9b1ace-a810-11db-bad5-f7f555d89593":"SDK Components",
    "ce62f77a-28f3-4d4b-824f-0f9b53461d67":"Search Enhancement Pack",
    "6cf036b9-b546-4694-885a-938b93216b66":"Security Essentials",
    "9f3dd20a-1004-470e-ba65-3dc62d982958":"Silverlight",
    "fe729f7e-3945-11dc-8e0c-cd1356d89593":"Silverlight",
    "6750007f-c908-4f2c-8aff-48ca6d36add6":"Skype for Windows",
    "1e602215-b397-46ca-b1a8-7ea0059517bc":"Skype",
    "7145181b-9556-4b11-b659-0162fa9df11f":"SQL Server 2000",
    "60916385-7546-4e9b-836e-79d65e517bab":"SQL Server 2005",
    "bb7bc3a7-857b-49d4-8879-b639cf5e8c3c":"SQL Server 2008 R2",
    "c5f0b23c-e990-4b71-9808-718d353f533a":"SQL Server 2008",
    "7fe4630a-0330-4b01-a5e6-a77c7ad34eb0":"SQL Server 2012 Product Updates for Setup",
    "c96c35fc-a21f-481b-917c-10c4f64792cb":"SQL Server Feature Pack",
    "0a4c6c73-8887-4d7f-9cbe-d08fa8fa9d1e":"SQL Server",
    "daa70353-99b4-4e04-b776-03973d54d20f":"System Center 2012 - App Controller",
    "b0c3b58d-1997-4b68-8d73-ab77f721d099":"System Center 2012 - Data Protection Manager",
    "bf05abfb-6388-4908-824e-01565b05e43a":"System Center 2012 - Operations Manager",
    "ab8df9b9-8bff-4999-aee5-6e4054ead976":"System Center 2012 - Orchestrator",
    "6ed4a93e-e443-4965-b666-5bc7149f793c":"System Center 2012 - Virtual Machine Manager",
    "50d71efd-1e60-4898-9ef5-f31a77bde4b0":"System Center 2012 SP1 - App Controller",
    "dd6318d7-1cff-44ed-a0b1-9d410c196792":"System Center 2012 SP1 - Data Protection Manager",
    "80d30b43-f814-41fd-b7c5-85c91ea66c45":"System Center 2012 SP1 - Operation Manager",
    "ba649061-a2bd-42a9-b7c3-825ce12c3cd6":"System Center 2012 SP1 - Virtual Machine Manager",
    "ae4500e9-17b0-4a78-b088-5b056dbf452b":"System Center Advisor",
    "d22b3d16-bc75-418f-b648-e5f3d32490ee":"System Center Configuration Manager 2007",
    "23f5eb29-ddc6-4263-9958-cf032644deea":"System Center Online",
    "9476d3f6-a119-4d6e-9952-8ad28a55bba6":"System Center Virtual Machine Manager",
    "26a5d0a5-b108-46f1-93fa-f2a9cf10d029":"System Center",
    "5a456666-3ac5-4162-9f52-260885d6533a":"Systems Management Server 2003",
    "78f4e068-1609-4e7a-ac8e-174288fa70a1":"Systems Management Server",
    "ae4483f4-f3ce-4956-ae80-93c18d8886a6":"Threat Management Gateway Definition Updates for Network Inspection System",
    "cd8d80fe-5b55-48f1-b37a-96535dca6ae7":"TMG Firewall Client",
    "4ea8aeaf-1d28-463e-8179-af9829f81212":"Update zur Browserauswahl in Europa (nur Europa)",
    "c8a4436c-1043-4288-a065-0f37e9640d60":"Virtual PC",
    "6d992428-3b47-4957-bb1a-157bd8c73d38":"Virtual Server",
    "f61ce0bd-ba78-4399-bb1c-098da328f2cc":"Virtual Server",
    "a0dd7e72-90ec-41e3-b370-c86a245cd44f":"Visual Studio 2005",
    "e3fde9f8-14d6-4b5c-911c-fba9e0fc9887":"Visual Studio 2008",
    "cbfd1e71-9d9e-457e-a8c5-500c47cfe9f3":"Visual Studio 2010 Tools for Office Runtime",
    "c9834186-a976-472b-8384-6bb8f2aa43d9":"Visual Studio 2010",
    "abddd523-04f4-4f8e-b76f-a6c84286cc67":"Visual Studio 2012",
    "cf4aa0fc-119d-4408-bcba-181abb69ed33":"Visual Studio 2013",
    "3b4b8621-726e-43a6-b43b-37d07ec7019f":"Windows 2000",
    "bfe5b177-a086-47a0-b102-097e4fa1f807":"Windows 7",
    "3e5cc385-f312-4fff-bd5e-b88dcf29b476":"Windows 8 Language Interface Packs",
    "97c4cee8-b2ae-4c43-a5ee-08367dab8796":"Windows 8 Language Packs",
    "405706ed-f1d7-47ea-91e1-eb8860039715":"Windows 8.1 Drivers",
    "18e5ea77-e3d1-43b6-a0a8-fa3dbcd42e93":"Windows 8.1 Dynamic Update",
    "14a011c7-d17b-4b71-a2a4-051807f4f4c6":"Windows 8.1 Language Interface Packs",
    "01030579-66d2-446e-8c65-538df07e0e44":"Windows 8.1 Language Packs",
    "6407468e-edc7-4ecd-8c32-521f64cee65e":"Windows 8.1",
    "2ee2ad83-828c-4405-9479-544d767993fc":"Windows 8",
    "393789f5-61c1-4881-b5e7-c47bcca90f94":"Windows Consumer Preview Dynamic Update",
    "8c3fcc84-7410-4a95-8b89-a166a0190486":"Windows Defender",
    "50c04525-9b15-4f7c-bed4-87455bcd7ded":"Windows Dictionary Updates",
    "f14be400-6024-429b-9459-c438db2978d4":"Windows Embedded Developer Update",
    "f4b9c883-f4db-4fb5-b204-3343c11fa021":"Windows Embedded Standard 7",
    "a36724a5-da1a-47b2-b8be-95e7cd9bc909":"Windows Embedded",
    "6966a762-0c7c-4261-bd07-fb12b4673347":"Windows Essential Business Server 2008 Setup Updates",
    "e9b56b9a-0ca9-4b3e-91d4-bdcf1ac7d94d":"Windows Essential Business Server 2008",
    "649f3e94-ed2f-42e8-a4cd-e81489af357c":"Windows Essential Business Server Preinstallation Tools",
    "41dce4a6-71dd-4a02-bb36-76984107376d":"Windows Essential Business Server",
    "470bd53a-c36a-448f-b620-91feede01946":"Windows GDR-Dynamic Update",
    "5ea45628-0257-499b-9c23-a6988fc5ea85":"Windows Live Toolbar",
    "0ea196ba-7a32-4e76-afd8-46bd54ecd3c6":"Windows Live",
    "afd77d9e-f05a-431c-889a-34c23c9f9af5":"Windows Live",
    "b3d0af68-8a86-4bfc-b458-af702f35930e":"Windows Live",
    "e88a19fb-a847-4e3d-9ae2-13c2b84f58a6":"Windows Media Dynamic Installer",
    "8c27cdba-6a1c-455e-af20-46b7771bbb96":"Windows Next Graphics Driver Dynamic update",
    "2c62603e-7a60-4832-9a14-cfdfd2d71b9a":"Windows RT 8.1",
    "0a07aea1-9d09-4c1e-8dc7-7469228d8195":"Windows RT",
    "7f44c2a7-bc36-470b-be3b-c01b6dc5dd4e":"Windows Server 2003, Datacenter Edition",
    "dbf57a08-0d5a-46ff-b30c-7715eb9498e9":"Windows Server 2003",
    "fdfe8200-9d98-44ba-a12a-772282bf60ef":"Windows Server 2008 R2",
    "ec9aaca2-f868-4f06-b201-fb8eefd84cef":"Windows Server 2008 Server-Manager - Dynamic Installer",
    "ba0ae9cc-5f01-40b4-ac3f-50192b5d6aaf":"Windows Server 2008",
    "26cbba0f-45de-40d5-b94a-3cbe5b761c9d":"Windows Server 2012 Language Packs",
    "8b4e84f6-595f-41ed-854f-4ca886e317a5":"Windows Server 2012 R2 Language Packs",
    "d31bd4c3-d872-41c9-a2e7-231f372588cb":"Windows Server 2012 R2",
    "a105a108-7c9b-4518-bbbe-73f0fe30012b":"Windows Server 2012",
    "eef074e9-61d6-4dac-b102-3dbe15fff3ea":"Windows Server Solutions Best Practices Analyzer 1.0",
    "4e487029-f550-4c22-8b31-9173f3f95786":"Windows Server-Manager - Windows Server Updates Services (WSUS) Dynamic Installer",
    "032e3af5-1ac5-4205-9ae5-461b4e8cd26d":"Windows Small Business Server 2003",
    "7fff3336-2479-4623-a697-bcefcf1b9f92":"Windows Small Business Server 2008 Migration Preparation Tool",
    "575d68e2-7c94-48f9-a04f-4b68555d972d":"Windows Small Business Server 2008",
    "1556fc1d-f20e-4790-848e-90b7cdbedfda":"Windows Small Business Server 2011 Standard",
    "68623613-134c-4b18-bcec-7497ac1bfcb0":"Windows Small Business Server",
    "e7441a84-4561-465f-9e0e-7fc16fa25ea7":"Windows Ultimate Extras",
    "90e135fb-ef48-4ad0-afb5-10c4ceb4ed16":"Windows Vista Dynamic Installer",
    "a901c1bd-989c-45c6-8da0-8dde8dbb69e0":"Windows Vista Ultimate Language Packs",
    "26997d30-08ce-4f25-b2de-699c36a8033a":"Windows Vista",
    "a4bedb1d-a809-4f63-9b49-3fe31967b6d0":"Windows XP 64-Bit Edition Version 2003",
    "4cb6ebd5-e38a-4826-9f76-1416a6f563b0":"Windows XP x64 Edition",
    "558f4bc3-4827-49e1-accf-ea79fd72d4c9":"Windows XP",
    "6964aab4-c5b5-43bd-a17d-ffb4346a8e1d":"Windows",
    "81b8c03b-9743-44b1-8c78-25e750921e36":"Works 6-9 Converter",
    "2425de84-f071-4358-aac9-6bbd6e0bfaa7":"Works",
    "a13d331b-ce8f-40e4-8a18-227bf18f22f3":"Writer-Installation und -Upgrades",
}

def get_product_id(expr):
    """Find product ids matching expr"""
    result = []
    match = re.compile(expr,re.IGNORECASE)
    for key,value in products_id.iteritems():
        if match.match(value) or expr == key:
            result.append(key)
    return result


def simplematch(expr):
    words = expr.split()
    match = re.compile('[ \s.,:]*'.join(words) ,re.IGNORECASE)
    return match

@app.route('/api/v2/windows_products')
def windows_products():
    result = []
    if 'search' in request.args:
        match = simplematch(request.args['search'])
        result = [ dict(product=product,title=title) for (product,title) in products_id.iteritems()
                    if match.match(title) or product == request.args['search']]
    else:
        result = [ dict(product=product,title=title) for (product,title) in products_id.iteritems()]
    if 'selected' in request.args and request.args['selected']:
        selection = get_selected_products()
        result = [ r for r in result if r['product'] in selection]
    return make_response(msg = _('Windows Products'), result = result )


@app.route('/api/v2/windows_updates_options',methods=['GET','POST'])
def windows_updates_options():
    key = request.args.get('key','default')
    if request.method == 'POST':
        data = json.loads(request.data)
        result = get_db().wsus_options.update({'key':key},{'key':key,'value': data},upsert=True)
    else:
        result = get_db().wsus_options.find({'key':key})
    return make_response(msg = _('Win updates global option for key %(key)s',key=key),result = result)


def get_selected_products():
     result = get_db().wsus_options.find({'key':'products_selection'})
     if result:
         for r in result:
             return r['value']
         else:
             return []
     else:
         return []

@app.route('/api/v2/windows_updates')
def windows_updates():
    """
{
	"_id": ObjectId("555ca6dfe9cd567f6ee3308b"),
	"categories": {
		"ProductFamily": "6964aab4-c5b5-43bd-a17d-ffb4346a8e1d",
		"Company": "56309036-4c77-4dd9-951a-99ee9c246a94",
		"UpdateClassification": "0fa1201d-4330-4fa8-8ae9-b877473b6441",
		"Product": "558f4bc3-4827-49e1-accf-ea79fd72d4c9"
    	},
	"description": "A security issue has been identified in a Microsoft software product that could affect your system. You can help protect your system by installing this update from Microsoft. For a complete listing of the issues that are included in this update, see the associated Microsoft Knowledge Base article. After you install this update, you may have to restart your system.",
	"kb_article_id": "2929961",
	"msrc_severity": "Critical",
	"prereqs": ["824c2b95-8529-4939-956c-587f30b1a024",
    	"3e0afb10-a9fb-4c16-a60e-5790c3803437",
    	"0fa1201d-4330-4fa8-8ae9-b877473b6441",
    	"558f4bc3-4827-49e1-accf-ea79fd72d4c9"],
	"revision_id": "11542192",
	"security_bulletin_id": "MS14-013",
	"title": "Security Update for Windows XP (KB2929961)",
	"update_id": "fe81ecb6-6b64-450b-a2a6-f3bf4b124556"
}
{
	"_id": ObjectId("555cae69e9cd5606eb22aea0"),
	"revision_id": "11542192",
	"prereqs": ["824c2b95-8529-4939-956c-587f30b1a024",
    	"3e0afb10-a9fb-4c16-a60e-5790c3803437",
    	"0fa1201d-4330-4fa8-8ae9-b877473b6441",
    	"558f4bc3-4827-49e1-accf-ea79fd72d4c9"],
	"update_id": "fe81ecb6-6b64-450b-a2a6-f3bf4b124556",
	"categories": {
		"ProductFamily": "6964aab4-c5b5-43bd-a17d-ffb4346a8e1d",
		"Company": "56309036-4c77-4dd9-951a-99ee9c246a94",
		"UpdateClassification": "0fa1201d-4330-4fa8-8ae9-b877473b6441",
		"Product": "558f4bc3-4827-49e1-accf-ea79fd72d4c9"
	}
}
    """
    wsus_updates = get_db().wsus_updates
    query = {}

    if 'has_kb' in request.args and request.args['has_kb']:
        query["kb_article_id"]={'$exists':True}
    if 'kb' in request.args:
        kbs = []
        for kb in ensure_list(request.args['kb']):
            if kb.upper().startswith('KB'):
                kbs.append(kb[2:])
            else:
                kbs.append(kb)
        query["kb_article_id"]={'$in':kbs}
    if 'update_classifications' in request.args:
        update_classifications = []
        for update_classification in ensure_list(request.args['update_classifications']):
            update_classifications.append(update_classification)
        query["categories.UpdateClassification"]={'$in':update_classifications}
    if 'product' in request.args:
        query["categories.Product"] = {'$in':get_product_id(request.args['product'])}
    if 'products' in request.args:
        query["categories.Product"] = {'$in':ensure_list(request.args['products'])}
    if 'severity' in request.args and request.args['severity']:
        query["msrc_severity"] = {'$in':ensure_list(request.args['severity'])}
    if 'update_ids' in request.args:
        query["update_id"] = {'$in':ensure_list(request.args['update_ids'])}

    if 'selected_products'  in request.args and request.args['selected_products']:
        query["categories.Product"] = {'$in':get_selected_products()}

    result = wsus_updates.find(query)
    cnt = result.count()
    return make_response(msg = _('Windows Updates, filter: %(query)s, count: %(cnt)s',query=query,cnt=cnt),result = result)


@app.route('/api/v2/windows_updates_urls',methods=['GET','POST'])
def windows_updates_urls():
    wsus_updates = get_db().wsus_updates
    def get_payloads(id):
        result = []
        updates = [ u for u in wsus_updates.find({'update_id':id},{'prereqs':1,'payload_files':1})]
        if updates:
            for update in updates:
                result.extend(update.get('payload_files',[]))
                for req in update.get('prereqs',[]):
                    result.extend(get_payloads(req))
        return result

    update_id = request.args['update_id']
    files_id = get_payloads(update_id)
    result = get_db().wsus_locations.find({'id':files_id},{'url':1})
    cnt = result.count()
    return make_response(msg = _('Downloads for Windows Updates %(update_id)s, count: %(cnt)s',update_id=update_id,cnt=cnt),result = files_id)


def sha1_for_file(fname, block_size=2**20):
    f = open(fname,'rb')
    sha1 = hashlib.sha1()
    while True:
        data = f.read(block_size)
        if not data:
            break
        sha1.update(data)
    return sha1.hexdigest()



@app.route('/api/v2/download_windows_update')
def download_windows_updates():
    def check_sha1_filename(target):
        # check sha1 sum if possible...
        if os.path.isfile(target):
            sha1sum_parts = os.path.basename(target).rsplit('.')[0].rsplit('_',1)
            if sha1sum_parts:
                sha1sum = sha1sum_parts[1]
                #looks like hex sha1
                if len(sha1sum) == 40 and (sha1sum != sha1_for_file(target)):
                    return False
            return True

    try:
        try:
            kb_article_id = request.args.get('kb_article_id', None)
            if kb_article_id != None:
                requested_kb = get_db().requested_kb
                requested_kb.update({ 'kb_article_id': kb_article_id }, { 'kb_article_id': kb_article_id, '$inc': { 'request_count', int(1) } }, upsert=True)
        except Exception as e:
            logger.error('download_windows_updates: %s', str(e))

        url = request.args['url']
        url_parts = urlparse.urlparse(url)
        if url_parts.netloc not in ['download.windowsupdate.com','www.download.windowsupdate.com']:
            raise Exception('Unauthorized location')
        fileparts = urlparse.urlparse(url).path.split('/')
        target = os.path.join(waptwua_folder,*fileparts)

        # check sha1 sum if possible...
        if os.path.isfile(target) and not check_sha1_filename(target):
            os.remove(target)

        if not os.path.isfile(target):
            if not os.path.isdir(os.path.join(waptwua_folder,*fileparts[:-1])):
                os.makedirs(os.path.join(waptwua_folder,*fileparts[:-1]))
            os.system('wget -O "%s" "%s"'% (target,url))
            if not check_sha1_filename(target):
                os.remove(target)
                raise Exception('Error during download, sha1 mismatch')

        result = {'url':'/waptwua%s'% ('/'.join(fileparts),),'size':os.stat(target).st_size}
        return make_response(msg='Windows patch available',result=result)
    except Exception as e:
        return make_response_from_exception(e)


def do_resolve_update(update_map, update_id, recursion_level):

    update = update_map[update_id]

    status = update.get('done', False)
    if status:
        return

    recursion_level += 1

    if recursion_level > 30:
        raise Exception('Max recursion reached when resolving update.')

    wsus_locations = get_db().wsus_locations
    wsus_locations.ensure_index('id', unique=True)

    files = update.get('payload_files', [])
    if files:
        file_locations = []
        for f in files:
            for fl in wsus_locations.find({ 'id': f }):
                file_locations.append(fl)
        update_map[update_id]['file_locations'] = file_locations

    wsus_updates = get_db().wsus_updates
    wsus_updates.ensure_index([('update_id', pymongo.ASCENDING), ('revision_id', pymongo.DESCENDING)], unique=True)

    if update.get('is_bundle') or update.get('deployment_action') == 'Bundle':
        bundles = wsus_updates.find({ 'bundled_by': update['revision_id'] })
        for b in bundles:
            if b['update_id'] not in update_map:
                update_map[b['update_id']] = b
            do_resolve_update(update_map, b['update_id'], recursion_level)

    for p in update.get('prereqs', []):
        sub_updates = wsus_updates.find({ 'update_id': p })
        for s in sub_updates:
            if s['update_id'] not in update_map:
                update_map[s['update_id']] = s
            do_resolve_update(update_map, s['update_id'], recursion_level)

    update_map[update_id]['done'] = True


@app.route('/api/v2/select_windows_update', methods=['GET'])
def select_windows_update():
    try:
        try:
            update_id = request.args['update_id']
            forget = request.args.get('forget', False)
        except:
            raise Exception('Invalid or missing parameters')

        try:
            # normalize
            update = str(uuid.UUID(update_id))
        except:
            raise Exception('Invalid update_id format')

        wsus_updates = get_db().wsus_updates
        update_map = {}
        for update in wsus_updates.find({ 'update_id': update_id }):
            update_map[update['update_id']] = update
        if not update_map:
            raise Exception('No such update_id')

        # the real work
        do_resolve_update(update_map, update_id, 0)

        dl_info = []
        for u in update_map:
            for fl in update_map[u].get('file_locations', []):
                del fl['_id']
                dl_info.append(fl)

        # not needed any more, free resources
        del update_map

        wsus_fetch_info = get_db().wsus_fetch_info
        wsus_fetch_info.ensure_index('id', unique=True)

        ok = 0
        total = len(dl_info)
        for fl in dl_info:
            try:
                if forget:
                    wsus_fetch_info.remove({ 'id': fl['id'] })
                else:
                    wsus_fetch_info.insert(fl)
                ok += 1
            except:
                pass

        raise Exception('WARNING: method called with no auth ; forget=' + str(forget) + ', ok=' + str(ok) + '/' + str(total))

    except Exception as e:
        import traceback
        traceback.print_exc()
        return make_response_from_exception(e)


@app.route('/api/v2/windows_updates_rules',methods=['GET','POST'])
def windows_updates_rules():
    if request.method == 'POST':
        group = request.args.get('group','default')
        data = json.loads(request.data)
        if not 'group' in data:
            data['group'] = group
        result = get_db().wsus_rules.update({'group':group},{"$set": data},upsert=True)
    else:
        if 'group' in  request.args:
            group = request.args.get('group','default')
            result = get_db().wsus_rules.find({'group':group})
        else:
            result = get_db().wsus_rules.find()

    return make_response(msg = _('Win updates rules'),result = result)

def test():
    import flask
    app = flask.Flask(__name__)
    babel = Babel(app)
    with app.test_request_context():
        db = get_db()
        a =  usage_statistics()
        print a.data

##################################################################
class CheckHostWorker(threading.Thread):
    """Worker which pulls a host data from queue, checks reachability, and stores result in db
    """
    def __init__(self,queue,timeout):
        threading.Thread.__init__(self)
        self.queue = queue
        self.timeout = timeout
        self.daemon = True
        self.start()

    def check_host(self,host_data):
        try:
            listening_info = get_ip_port(host_data,recheck=True,timeout=self.timeout)
            #update timestamp
            listening_info['timestamp'] = datetime2isodate()
            return listening_info
        except:
            # return "not reachable" information
            return dict(protocol='',address='',port=waptservice_port,timestamp=datetime2isodate())

    def run(self):
        logger.debug('worker %s running'%self.ident)
        while True:
            try:
                host_data = self.queue.get(timeout=2)
                listening_infos = self.check_host(host_data)
                with MongoClient(mongodb_ip, int(mongodb_port)) as mongo_client:
                    # stores result
                    mongo_client.wapt.hosts.update({"_id" : host_data['_id'] }, {"$set": {'wapt.listening_address':listening_infos }})
                    logger.debug("Client check %s finished with %s" % (self.ident,listening_infos))
                self.queue.task_done()
            except Queue.Empty:
                break
        logger.debug('worker %s finished'%self.ident)


class CheckHostsWaptService(threading.Thread):
    """Thread which check which IP is reachable for all registered hosts
        The result is stored in MongoDB database as wapt.listening_address
        {protocol
         address
         port}
       if poll_interval is not None, the thread runs indefinetely/
       if poll_interval is None, one check of all hosts is performed.
    """
    def __init__(self,timeout=2,uuids=[]):
        threading.Thread.__init__(self)
        self.daemon = True
        self.timeout = timeout
        self.uuids = uuids
        if self.uuids:
            self.workers_count = min(len(uuids),20)
        else:
            self.workers_count = 20

    def run(self):
        logger.debug('Client-listening %s address checker thread started'%self.ident)
        with MongoClient(mongodb_ip, int(mongodb_port)) as mongoclient:
            fields = {'uuid':1,'host.computer_fqdn':1,'wapt':1,'host.connected_ips':1}
            if self.uuids:
                query = {"uuid":{"$in": self.uuids}}
            else:
                query = {"host.connected_ips":{"$exists": "true", "$ne" :[]}}

            logger.debug('Reset listening status timestamps of hosts')
            try:
                mongoclient.wapt.hosts.update(query,{"$set": {'wapt.listening_address.timestamp':''}},multi=True)
            except Exception as e:
                logger.debug('error resetting timestamp %s' % e)
                mongoclient.wapt.hosts.update(query,{"$unset": {'wapt.listening_address':1}},multi=True)

            queue = Queue.Queue()
            for data in mongoclient.wapt.hosts.find(query,fields=fields):
                logger.debug('Hosts %s pushed in check IP queue'%data['uuid'])
                queue.put(data)

            logger.debug('Create %i workers'%self.workers_count)
            for i in range(self.workers_count):
                CheckHostWorker(queue,self.timeout)

            logger.debug('%s CheckHostsWaptService waiting for check queue to be empty'%(self.ident))
            queue.join()
            logger.debug('%s CheckHostsWaptService workers all terminated'%(self.ident))


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

    if options.devel:
        app.run(host='0.0.0.0',port=30880,debug=True)
    else:
        port = waptserver_port
        server = Rocket(('127.0.0.1', port), 'wsgi', {"wsgi_app":app})
        try:
            logger.info("starting waptserver")
            server.start()
        except KeyboardInterrupt:
            logger.info("stopping waptserver")
            server.stop()
