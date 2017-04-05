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

import time
import sys
import os
import types

try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.append(os.path.join(wapt_root_dir))
sys.path.append(os.path.join(wapt_root_dir,'lib'))
sys.path.append(os.path.join(wapt_root_dir,'lib','site-packages'))

import ConfigParser
from optparse import OptionParser

import hashlib
import socket
import requests

from rocket import Rocket

# flask
from flask import request, Flask,Response, send_from_directory, send_file, session, g, redirect, url_for, abort, render_template, flash, stream_with_context
from flask_paginate import Pagination
import jinja2
from werkzeug.utils import secure_filename
from werkzeug.utils import html

from urlparse import urlparse
from functools import wraps

import logging
import sqlite3

import json
import StringIO

import thread
import threading
import zmq
from zmq.log.handlers import PUBHandler
import Queue
import traceback
import locale

import datetime
import copy

import ssl
from ssl import SSLError

import pythoncom
import ctypes
import win32security
import psutil

import tempfile

# wapt specific stuff
from waptutils import *

import common
from common import Wapt
import setuphelpers
from setuphelpers import Version
from waptpackage import PackageEntry

import windnsquery

from gettext import gettext

# i18n
from flask_babel import Babel
try:
    from flask_babel import gettext
except ImportError:
    gettext = (lambda s:s)
_ = gettext

import babel


v = (sys.version_info.major, sys.version_info.minor)
if v != (2, 7):
    raise Exception('waptservice supports only Python 2.7, not %d.%d' % v)

logger = logging.getLogger()

def get_authorized_callers_ip(waptserver_url=None):
    """Returns list of IP allowed to request actions with check_caller decorator"""
    ips = []
    if waptserver_url:
        waptserver_hostname = urlparse(waptserver_url).hostname
        try:
            ips.append(socket.gethostbyname(waptserver_hostname))
        except socket.gaierror as e:
            # no network connection to resolve hostname
            logger.info('Unable to resolve authorized caller for %s using socket : %s'%(waptserver_hostname,e))
        try:
            ips.extend(windnsquery.dnsquery_a(waptserver_hostname))
        except Exception as e:
            logger.warning('Unable to resolve authorized caller for %s using windns : %s'%(waptserver_hostname,e))
        logger.debug('Authorized callers found : %s' % (ips,))
    return ips

class WaptEvent(object):
    """Store single event with list of subscribers"""
    DEFAULT_TTL = 20 * 60

    def __init__(self,topic,subject,data=None,runstatus = ''):
        self.topic = topic
        self.subject = subject
        self.data = copy.deepcopy(data)
        self.runstatus = runstatus

        self.id = None
        self.ttl = self.DEFAULT_TTL
        self.date = time.time()
        # list of ids of subscribers which have not yet retrieved the event
        self.subscribers = []

class WaptEvents(object):
    """Thread safe central list of last events so that consumer can get list
        of latest events using http long poll requests"""

    def __init__(self,max_history=300):
        self.last = -1
        self.max_history = max_history
        self.get_lock = threading.RLock()
        self.events = []
        self.subscribers = []


    def get_missed(self,last_read=None):
        """returns events since last_read"""
        with self.get_lock:
            if last_read is None:
                return self.events[:]
            else:
                first = self.last-len(self.events)+1
                if last_read <= first:
                    return self.events[:]
                else:
                    return self.events[last_read-first:]

    def put(self, item):
        with self.get_lock:
            self.events.append(item)
            item.subscribers.extend(self.subscribers)
            # keep track of a global position for consumers
            self.last +=1
            item.id = self.last
            if len(self.events) > self.max_history:
                del self.events[:len(self.events) - self.max_history]

    def add_event(self,topic,subject,data=None,runstatus = ''):
        item = WaptEvent(topic,subject,data,runstatus)
        self.put(item)

    def cleanup(self):
        """Remove events with age>ttl"""
        with self.get_lock:
            for item in reversed(self.events):
                if item.date+item.ttl > time.time():
                    self.events.remove(item)


class WaptServiceConfig(object):
    """Configuration parameters from wapt-get.ini file
    >>> waptconfig = WaptServiceConfig('c:/wapt/wapt-get.ini')
    >>> waptconfig.load()
    """

    global_attributes = ['config_filename','waptservice_user','waptservice_password',
         'MAX_HISTORY','waptservice_port','waptservice_sslport',
         'dbpath','loglevel','log_directory','waptserver','authorized_callers_ip',
         'hiberboot_enabled','max_gpo_script_wait','pre_shutdown_timeout','log_to_windows_events']

    def __init__(self,config_filename=None):
        if not config_filename:
            self.config_filename = os.path.join(wapt_root_dir,'wapt-get.ini')
        else:
            self.config_filename = config_filename
        self.waptservice_user = None
        self.waptservice_password = None

        # maximum nb of tasks to keep in history wapt task manager
        self.MAX_HISTORY = 30

        # http localserver
        self.waptservice_port = 8088
        self.waptservice_sslport = None

        # zeroMQ publishing socket
        self.zmq_port = 5000

        # default language
        self.language = locale.getdefaultlocale()[0]

        # session key
        self.secret_key = '1234567890'

        self.dbpath = os.path.join(wapt_root_dir,'db','waptdb.sqlite')
        self.loglevel = "info"
        self.log_directory = os.path.join(wapt_root_dir,'log')
        if not os.path.exists(self.log_directory):
            os.mkdir(self.log_directory)

        self.log_to_windows_events = False

        self.waptserver = None
        self.authorized_callers_ip = []

        self.waptservice_poll_timeout = 10
        self.waptupdate_task_period = None
        self.waptupgrade_task_period = None

        self.config_filedate = None

        self.hiberboot_enabled = None
        self.max_gpo_script_wait = None
        self.pre_shutdown_timeout = None

    def load(self):
        """Load waptservice parameters from global wapt-get.ini file"""
        config = ConfigParser.RawConfigParser()
        if os.path.exists(self.config_filename):
            config.read(self.config_filename)
            self.config_filedate = os.stat(self.config_filename).st_mtime
        else:
            raise Exception(_("FATAL. Couldn't open config file : {}").format(self.config_filename))
        # lecture configuration
        if config.has_section('global'):
            if config.has_option('global', 'waptservice_user'):
                self.waptservice_user = config.get('global', 'waptservice_user')
            else:
                self.waptservice_user = None

            if config.has_option('global','waptservice_password'):
                self.waptservice_password = config.get('global', 'waptservice_password')
            else:
                logger.info(u"No password set for local waptservice, using local computer security")
                self.waptservice_password=None  # = password

            if config.has_option('global','waptservice_port'):
                port = config.get('global','waptservice_port')
                if port:
                    self.waptservice_port = int(port)
                else:
                    self.waptservice_port = None
            else:
                self.waptservice_port=8088

            if config.has_option('global','waptservice_sslport'):
                port = config.get('global','waptservice_sslport')
                if port:
                    self.waptservice_sslport = int(port)
                else:
                    self.waptservice_sslport = None
            else:
                self.waptservice_sslport=None

            if config.has_option('global','zmq_port'):
                self.zmq_port = int(config.get('global','zmq_port'))
            else:
                self.zmq_port=5000

            if config.has_option('global','language'):
                self.language = config.get('global','language')

            if config.has_option('global','secret_key'):
                self.secret_key = config.get('global','secret_key')

            if config.has_option('global','waptservice_poll_timeout'):
                self.waptservice_poll_timeout = int(config.get('global','waptservice_poll_timeout'))
            else:
                self.waptservice_poll_timeout = 10

            if config.has_option('global','waptupgrade_task_period'):
                self.waptupgrade_task_period = int(config.get('global','waptupgrade_task_period'))
            else:
                self.waptupgrade_task_period = None

            if config.has_option('global','waptupdate_task_period'):
                self.waptupdate_task_period = int(config.get('global','waptupdate_task_period'))
            else:
                self.waptupdate_task_period = None

            if config.has_option('global','dbpath'):
                self.dbpath =  config.get('global','dbpath')
            else:
                self.dbpath = os.path.join(wapt_root_dir,'db','waptdb.sqlite')

            if self.dbpath != ':memory:':
                self.dbdir = os.path.dirname(self.dbpath)
                if not os.path.isdir(self.dbdir):
                    os.makedirs(self.dbdir)
            else:
                self.dbdir = None

            if config.has_option('global','loglevel') and options.loglevel is None:
                self.loglevel = config.get('global','loglevel')
                setloglevel(logger,self.loglevel)
            elif options.loglevel is None:
                # default to warning
                setloglevel(logger,'warning')

            if config.has_option('global','log_to_windows_events'):
                self.log_to_windows_events = config.getboolean('global','log_to_windows_events')

            if config.has_option('global','wapt_server'):
                self.waptserver = common.WaptServer().load_config(config)
                self.authorized_callers_ip = get_authorized_callers_ip(self.waptserver.server_url)
            else:
                self.waptserver = None

            # settings for waptexit / shutdown policy
            #   recommended settings :
            #       hiberboot_enabled = 0
            #       max_gpo_script_wait = 180
            #       pre_shutdown_timeout = 180
            for param in ('hiberboot_enabled','max_gpo_script_wait','pre_shutdown_timeout'):
                if config.has_option('global',param):
                    setattr(self,param,config.getint('global',param))
                else:
                    setattr(self,param,None)


        else:
            raise Exception (_("FATAL, configuration file {} has no section [global]. Please check Waptserver documentation").format(self.config_filename))

    def reload_if_updated(self):
        """Check if config file has been updated,
        Return None if config has not changed or date of new config file if reloaded"""
        if os.path.exists(self.config_filename):
            new_config_filedate = os.stat(self.config_filename).st_mtime
            if new_config_filedate!=self.config_filedate:
                logger.info(u'Reloading configuration')
                self.load()
                return new_config_filedate
            else:
                return None
        else:
            return None

    def as_dict(self):
        result = {}
        for att in self.global_attributes:
            result[att] = getattr(self,att)
        return result

    def __unicode__(self):
        return u"{}".format(self.as_dict(),)


def format_isodate(isodate):
    """Pretty format iso date like : 2014-01-21T17:36:15.652000
        >>> format_isodate('2014-01-21T17:36:15.652000')
        '21/01/2014 17:36:15'
    """
    return isodate.replace('T',' ')[0:20]
    #dateutil.parser.parse(isodate).strftime("%d/%m/%Y %H:%M:%S")

def beautify(c):
    """return pretty html"""
    join = u"".join
    if c is None:
        return ""
    elif isinstance(c,(datetime.datetime,datetime.date)):
        return c.isoformat()
    elif isinstance(c,int):
        return '{}'.format(c)
    elif isinstance(c,float):
        return '{:.3}'.format(c)
    elif isinstance(c,unicode):
        return jinja2.Markup(c.replace('\r\n','<br>').replace('\n','<br>'))
    elif isinstance(c,str):
        return jinja2.Markup(ensure_unicode(c).replace('\r\n','<br>').replace('\n','<br>'))
    elif isinstance(c,PackageEntry):
        return jinja2.Markup('<a href="%s">%s</a>'%(url_for('package_details',package=c.asrequirement()),c.asrequirement()))
    elif isinstance(c,dict) or (hasattr(c,'keys') and callable(c.keys)):
        rows = []
        try:
            for key in c.keys():
                rows.append(u'<li><b>{}</b>: {}</li>'.format(beautify(key),beautify(c[key])))
            return jinja2.Markup(u'<ul>{}</ul>'.format(join(rows)))
        except:
            pass
    elif isinstance(c, (list, tuple)):
        if c:
            rows = [u'<li>{}</li>'.format(beautify(item)) for item in c]
            return jinja2.Markup(u'<ul>{}</ul>'.format(join(rows)))
        else:
            return ''
    else:
        return jinja2.Markup(u"<pre>{}</pre>".format(ensure_unicode(c)))


def ssl_required(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        if app.config.get("SSL"):
            if request.is_secure:
                return fn(*args, **kwargs)
            else:
                return redirect(request.url.replace("http://", "https://"))

        return fn(*args, **kwargs)
    return decorated_view


def check_open_port(portnumber=8088):
    """Configure local firewall to accept incoming request to specified tcp port
    >>> check_open_port(8088)
    """
    import win32serviceutil
    import platform
    import win32service
    win_major_version = int(platform.win32_ver()[1].split('.')[0])
    try:
        if win_major_version<6:
            #check if firewall is running
            if win32serviceutil.QueryServiceStatus( 'SharedAccess', None)[1]==win32service.SERVICE_RUNNING:
                logger.info(u"Firewall started, checking for port openning...")
                #WinXP 2003
                if 'waptservice' not in setuphelpers.run_notfatal('netsh firewall show portopening'):
                    logger.info(u"Adding a firewall rule to open port %s"%portnumber)
                    setuphelpers.run_notfatal("""netsh.exe firewall add portopening name="waptservice %s" port=%s protocol=TCP profile=ALL"""%(portnumber,portnumber))
                else:
                    logger.info(u"port %s already opened, skipping firewall configuration"%(portnumber,))
        else:
            if win32serviceutil.QueryServiceStatus('MpsSvc', None)[1]==win32service.SERVICE_RUNNING:
                logger.info(u"Firewall started, checking for port openning...")
                if 'waptservice' not in setuphelpers.run_notfatal('netsh advfirewall firewall show rule name="waptservice %s"'%(portnumber,)):
                    logger.info(u"No port opened for waptservice, opening port %s"%portnumber)
                    #win Vista and higher
                    setuphelpers.run_notfatal("""netsh advfirewall firewall add rule name="waptservice %s" dir=in action=allow protocol=TCP localport=%s remoteip=%s """%(portnumber,portnumber,','.join(waptconfig.authorized_callers_ip)))
                else:
                    logger.info(u"port %s already opened, skipping firewall configuration"%(portnumber,))
    except Exception as e:
        logger.info('Unable to check if port %s is opened : %s' % (portnumber,e))

waptconfig = WaptServiceConfig()

app = Flask(__name__)
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['SECRET_KEY'] = waptconfig.secret_key

try:
    from waptwua import WaptWUA
    app.register_blueprint(waptwua.waptwua)
except Exception as e:
    pass

app.jinja_env.filters['beautify'] = beautify
app.waptconfig = waptconfig

app_babel = Babel(app)

def apply_host_settings(waptconfig):
    #apply waptservice / waptexit specific settings
    wapt = Wapt(config_filename = waptconfig.config_filename)
    try:
        if waptconfig.max_gpo_script_wait is not None and wapt.max_gpo_script_wait != waptconfig.max_gpo_script_wait:
            logger.info('Setting max_gpo_script_wait to %s'%waptconfig.max_gpo_script_wait)
            wapt.max_gpo_script_wait = waptconfig.max_gpo_script_wait
        if waptconfig.pre_shutdown_timeout is not None and wapt.pre_shutdown_timeout != waptconfig.pre_shutdown_timeout:
            logger.info('Setting pre_shutdown_timeout to %s'%waptconfig.pre_shutdown_timeout)
            wapt.pre_shutdown_timeout = waptconfig.pre_shutdown_timeout
        if waptconfig.hiberboot_enabled is not None and wapt.hiberboot_enabled != waptconfig.hiberboot_enabled:
            logger.info('Setting hiberboot_enabled to %s'%waptconfig.hiberboot_enabled)
            wapt.hiberboot_enabled = waptconfig.hiberboot_enabled
    except Exception as e:
        logger.critical('Unable to set shutdown policies : %s' % e)


def wapt():
    if not hasattr(g,'wapt'):
        g.wapt = Wapt(config_filename = waptconfig.config_filename)
        apply_host_settings(waptconfig)
    # apply settings
    elif g.wapt.reload_config_if_updated():
        #apply waptservice / waptexit specific settings
        apply_host_settings(waptconfig)
    return g.wapt

@app.before_first_request
def before_first_request():
    pythoncom.CoInitializeEx(pythoncom.COINIT_MULTITHREADED)

@app.teardown_appcontext
def close_connection(exception):
    try:
        local_wapt = getattr(g, 'wapt', None)
        if local_wapt is not None and local_wapt._waptdb:
            try:
                local_wapt._waptdb.commit()
                local_wapt._waptdb = None
            except:
                try:
                    local_wapt._waptdb.rollback()
                    local_wapt._waptdb = None
                except:
                    local_wapt._waptdb = None

    except Exception as e:
        logger.debug('Error in teardown, please consider upgrading Flask if <0.10. %s' % e)

def forbidden():
    """Sends a 403 response that enables basic auth"""
    return Response(
        'Restricted access.\n',
         403)

def badtarget():
    """Sends a 400 response if uuid mismatch"""
    return Response(
        'Host target UUID is not matching your request.\n',
         400)

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def check_auth(logon_name, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    if app.waptconfig.waptservice_password != 'NOPASSWORD':
        if len(logon_name) ==0 or len(password)==0:
            return False
        domain = ''
        if logon_name.count('\\') > 1 or logon_name.count('@') > 1  or (logon_name.count('\\') == 1 and logon_name.count('@')==1)  :
            logger.debug("malformed logon credential : %s "% logon_name)
            return False

        if '\\' in logon_name:
            domain = logon_name.split('\\')[0]
            username = logon_name.split('\\')[1]
        elif '@' in logon_name:
            username = logon_name.split('@')[0]
            domain = logon_name.split('@')[1]
        else:
            username = logon_name
        logger.debug("Checking authentification for domain: %s user: %s" % (domain,username))

        try:
            huser = win32security.LogonUser (
                username,
                domain,
                password,
            win32security.LOGON32_LOGON_NETWORK,
            win32security.LOGON32_PROVIDER_DEFAULT
            )
            #check if user is domain admins ou member of waptselfservice admin
            try:
                domain_admins_group_name = common.get_domain_admins_group_name()
                if common.check_is_member_of(huser,domain_admins_group_name):
                    return True
                if common.check_is_member_of(huser,'waptselfservice'):
                    return True
            except:
                pass
            local_admins_group_name = common.get_local_admins_group_name()
            if common.check_is_member_of(huser,local_admins_group_name):
                return True

        except win32security.error:
            if app.waptconfig.waptservice_password:
                logger.debug('auth using wapt local account')
                return app.waptconfig.waptservice_user == username and app.waptconfig.waptservice_password == hashlib.sha256(password).hexdigest()
        else:
            return False
    else:
        return True

def allow_waptserver_or_local_auth(f):
    """Restrict access to localhost authenticated or waptserver IP"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            if not app.waptconfig.authorized_callers_ip and app.waptconfig.waptserver:
                app.waptconfig.authorized_callers_ip = get_authorized_callers_ip(app.waptconfig.waptserver.server_url)
        except Exception as e:
            logger.debug('Unable to acquire IP of waptserver : %s' % e)
        if request.remote_addr in app.waptconfig.authorized_callers_ip:
            uuid = wapt().host_uuid
            if not 'uuid' in request.args or request.args['uuid'] != uuid:
                return badtarget()
            return f(*args, **kwargs)
        elif request.remote_addr == '127.0.0.1':
            auth = request.authorization
            if not auth:
                logging.info('no credential given')
                return authenticate()

            logging.info("authenticating : %s" % auth.username)
            if not check_auth(auth.username, auth.password):
                return authenticate()
            logging.info("user %s authentication success" % auth.username)
        else:
            logger.info(u'Forbidden: caller src address {} is not in authorized list {}'.format(request.remote_addr,app.waptconfig.authorized_callers_ip))
            # try to reacquire IP of waptserver
            try:
                if app.waptconfig.waptserver:
                    app.waptconfig.authorized_callers_ip = get_authorized_callers_ip(app.waptconfig.waptserver.server_url)
            except Exception as e:
                logger.debug('Unable to acquire IP of waptserver : %s' % e)

            return forbidden()
        return f(*args, **kwargs)
    return decorated


def allow_waptserver_or_local_unauth(f):
    """Restrict access to localhost unauthenticated or waptserver IP"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            if not app.waptconfig.authorized_callers_ip and app.waptconfig.waptserver:
                app.waptconfig.authorized_callers_ip = get_authorized_callers_ip(app.waptconfig.waptserver.server_url)
        except Exception as e:
            logger.debug('Unable to acquire IP of waptserver : %s' % e)
        if not request.remote_addr in (app.waptconfig.authorized_callers_ip + ['127.0.0.1']):
            logger.info(u'Forbidden: caller src address {} is not in authorized list {}'.format(request.remote_addr,app.waptconfig.authorized_callers_ip))
            # try to reacquire IP of waptserver
            try:
                if app.waptconfig.waptserver:
                    app.waptconfig.authorized_callers_ip = get_authorized_callers_ip(app.waptconfig.waptserver.server_url)
            except Exception as e:
                logger.debug('Unable to acquire IP of waptserver : %s' % e)
            return forbidden()
        if request.remote_addr != '127.0.0.1':
            uuid = wapt().host_uuid
            if not 'uuid' in request.args or request.args['uuid'] != uuid:
                return badtarget()
        return f(*args, **kwargs)
    return decorated

def allow_local(f):
    """Restrict access to localhost authenticated or waptserver IP"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.remote_addr in ['127.0.0.1']:
            return f(*args, **kwargs)
        else:
            return forbidden()
    return decorated

def allow_local_auth(f):
    """Restrict access to localhost authenticated or waptserver IP"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.remote_addr in ['127.0.0.1']:
            auth = request.authorization
            if not auth:
                logging.info('no credential given')
                return authenticate()

            logging.info("authenticating : %s" % auth.username)
            if not check_auth(auth.username, auth.password):
                return authenticate()
            logging.info("user %s authenticated" % auth.username)
        else:
            return forbidden()
        return f(*args, **kwargs)
    return decorated



@app_babel.localeselector
def get_locale():
     browser_lang = request.accept_languages.best_match(['en', 'fr'])
     user_lang = session.get('lang',browser_lang)
     return user_lang

@app.route('/lang/<language>')
def lang(language=None):
     session['lang'] = language
     return redirect('/')

@app_babel.timezoneselector
def get_timezone():
    user = getattr(g, 'user', None)
    if user is not None:
        return user.timezone


@app.route('/ping')
@allow_waptserver_or_local_unauth
def ping():
    if 'uuid' in request.args:
        w = wapt()
        data = dict(
            hostname = setuphelpers.get_hostname(),
            version=__version__,
            uuid = w.host_uuid,
            waptserver = w.waptserver,
            )
    else:
        data = dict(
            version=__version__,
            )
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/status')
@app.route('/status.json')
@allow_local
def status():
    rows = []
    with sqlite3.connect(app.waptconfig.dbpath) as con:
        try:
            con.row_factory=sqlite3.Row
            query = '''select s.package,s.version,s.install_date,
                                 s.install_status,s.install_output,r.description,
                                 (select GROUP_CONCAT(p.version,"|") from wapt_package p where p.package=s.package) as repo_versions,
                                 explicit_by as install_par
                                 from wapt_localstatus s
                                 left join wapt_package r on r.package=s.package and r.version=s.version
                                 order by s.package'''
            cur = con.cursor()
            cur.execute(query)
            rows = []
            search = request.args.get('q','')

            for row in cur.fetchall():
                pe = PackageEntry()
                rec_dict = dict((cur.description[idx][0], value) for idx, value in enumerate(row))
                for k in rec_dict:
                    setattr(pe,k,rec_dict[k])
                    # add joined field to calculated attributes list
                    if not k in pe.all_attributes:
                        pe._calculated_attributes.append(k)
                # hack to enable proper version comparison in templates
                pe.version = Version(pe.version)
                # calc most up to date repo version
                if pe.get('repo_versions',None) is not None:
                    pe.repo_version = max(Version(v) for v in pe.get('repo_versions','').split('|'))
                else:
                    pe.repo_version = None

                if not search or pe.match_search(search):
                    rows.append(pe)

            #rows = [ waptpackage.PackageEntry().load_control_from_dict(dict(x)) for x in cur.fetchall() ]
        except sqlite3.Error as e:
            logger.critical(u"*********** Error %s:" % e.args[0])
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(rows), mimetype='application/json')
    else:
        return render_template('status.html',packages=rows,format_isodate=format_isodate,Version=setuphelpers.Version)


def latest_only(packages):
    index = {}
    for p in sorted(packages, reverse=True):
        if not p.package in index:
            p.previous = []
            index[p.package] = p
        else:
            index[p.package].previous.append(p)

    return index.values()


@app.route('/list/pg<int:page>')
@app.route('/packages.json')
@app.route('/packages')
@app.route('/list')
@allow_local
def all_packages(page=1):
    with sqlite3.connect(app.waptconfig.dbpath) as con:
        try:
            con.row_factory=sqlite3.Row
            query = '''\
                select
                    r.*,
                    s.version as install_version,s.install_status,s.install_date,s.explicit_by
                from wapt_package r
                left join wapt_localstatus s on s.package=r.package
                where r.section<>"host"
                order by r.package,r.version'''
            cur = con.cursor()
            cur.execute(query)
            rows = []

            search = request.args.get('q','').encode('utf8').replace('\\', '')
            for row in cur.fetchall():
                pe = PackageEntry().load_control_from_dict(
                    dict((cur.description[idx][0], value) for idx, value in enumerate(row)))
                if not search or pe.match_search(search):
                    rows.append(pe)

            if request.args.get('latest','0') == '1':
                filtered = []
                last_package_name = None
                for package in sorted(rows,reverse=True):
                    if package.package != last_package_name:
                        filtered.append(package)
                    last_package_name = package.package
                rows = list(reversed(filtered))

            if not request.args.get('all_versions',''):
                rows = sorted(latest_only(rows))
            for pe in rows:
                # hack to enable proper version comparison in templates
                pe.install_version = Version(pe.install_version)
                pe.version = Version(pe.version)


        except sqlite3.Error as e:
            logger.critical(u"*********** Error %s:" % e.args[0])
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(rows), mimetype='application/json')
    else:
        total = len(rows)
        per_page = 30

        try:
            search = search
        except NameError:
            search = False

        _min = per_page * (page - 1)
        _max = _min + per_page
        pagination = Pagination(css_framework='foundation', page=page, total=total, search=search, per_page=per_page)
        return render_template(
            'list.html',
            packages=rows[_min:_max],
            format_isodate=format_isodate,
            Version=setuphelpers.Version,
            pagination=pagination,
        )

@app.route('/package_icon')
@allow_local
def package_icon():
    """Return png icon for the required 'package' parameter
        get it from local cache if or from package's remote repositiory
    """
    package = request.args.get('package')
    icon_local_cache = os.path.join(wapt_root_dir,'cache','icons')
    if not os.path.isdir(icon_local_cache):
        os.makedirs(icon_local_cache)
    #wapt=[]

    def get_icon(package):
        """Get icon from local cache or remote wapt directory, returns local filename"""
        icon_local_filename = os.path.join(icon_local_cache,package+'.png')
        if (not os.path.isfile(icon_local_filename) or os.path.getsize(icon_local_filename)<10):
            if wapt().repositories[0].repo_url:
                proxies = wapt().repositories[0].proxies
                repo_url = wapt().repositories[0].repo_url
                timeout = wapt().repositories[0].timeout

                remote_icon_path = "{repo}/icons/{package}.png".format(repo=repo_url,package=package)
                icon = requests.get(remote_icon_path,proxies=proxies,timeout=timeout,verify=False)
                icon.raise_for_status()
                open(icon_local_filename,'wb').write(icon.content)
                return StringIO.StringIO(icon.content)
            else:
                raise requests.HTTPError('Unavailable icon')
        else:
            return open(icon_local_filename,'rb')

    try:
        icon = get_icon(package)
        return send_file(icon,'image/png',as_attachment=True,attachment_filename='{}.png'.format(package),cache_timeout=43200)
    except requests.RequestException as e:
        return send_from_directory(app.static_folder+'/images','unknown.png',mimetype='image/png',as_attachment=True,attachment_filename='{}.png'.format(package),cache_timeout=43200)

@app.route('/package_details')
@app.route('/package_details.json')
@allow_local
def package_details():
    #wapt=Wapt(config_filename=app.waptconfig.config_filename)
    package = request.args.get('package')
    try:
        data = wapt().is_available(package)
    except Exception as e:
        data = {'errors':[ ensure_unicode(e) ]}

    # take the newest...
    data = data and data[-1].as_dict()
    if request.args.get('format','html')=='json':
        return Response(common.jsondump(dict(result=data,errors=[])), mimetype='application/json')
    else:
        return render_template('package_details.html',data=data)


@app.route('/runstatus')
@allow_waptserver_or_local_unauth
def get_runstatus():
    data = []
    with sqlite3.connect(app.waptconfig.dbpath) as con:
        con.row_factory=sqlite3.Row
        try:
            query ="""select value,create_date from wapt_params where name='runstatus' limit 1"""
            cur = con.cursor()
            cur.execute(query)
            rows = cur.fetchall()
            data = [dict(ix) for ix in rows]
        except Exception as e:
            logger.critical(u"*********** error " + ensure_unicode(e))
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/check_ssl')
@allow_waptserver_or_local_unauth
def check_ssk():
    data = common.jsondump(request.input_stream._sock.getpeercert(binary_form=False))
    return Response(data, mimetype='application/json')


@app.route('/checkupgrades')
@app.route('/checkupgrades.json')
@allow_waptserver_or_local_unauth
def get_checkupgrades():
    with sqlite3.connect(app.waptconfig.dbpath) as con:
        con.row_factory=sqlite3.Row
        data = ""
        try:
            query ="""select * from wapt_params where name="last_update_status" limit 1"""
            cur = con.cursor()
            cur.execute(query)
            data = json.loads(cur.fetchone()['value'])
        except Exception as e :
            logger.critical(u"*********** error %s"  % (ensure_unicode(e)))
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title=_(u'Update status'))


@app.route('/waptupgrade')
@app.route('/waptupgrade.json')
@allow_waptserver_or_local_unauth
def waptclientupgrade():
    """Launch an external 'wapt-get waptupgrade' process to upgrade local copy of wapt client"""
    data = task_manager.add_task(WaptClientUpgrade()).as_dict()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title='Upgrade')


@app.route('/waptservicerestart')
@app.route('/waptservicerestart.json')
@allow_waptserver_or_local_unauth
def waptservicerestart():
    """Restart local waptservice using a spawned batch file"""
    data = task_manager.add_task(WaptServiceRestart()).as_dict()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title='Upgrade')


@app.route('/reload_config')
@app.route('/reload_config.json')
@allow_waptserver_or_local_unauth
def reload_config():
    """trigger reload of wapt-get.ini file for the service"""
    force = int(request.args.get('force','0')) == 1
    notify_user = int(request.args.get('notify_user','0')) == 1
    data = task_manager.add_task(WaptNetworkReconfig(),notify_user=notify_user).as_dict()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title=_('Reload configuration'))



@app.route('/upgrade')
@app.route('/upgrade.json')
@allow_waptserver_or_local_unauth
def upgrade():
    force = int(request.args.get('force','0')) != 0
    notify_user = int(request.args.get('notify_user','1')) != 0
    all_tasks = []
    wapt().update()
    actions = wapt().list_upgrade()
    to_install = actions['upgrade']+actions['additional']+actions['install']
    for req in to_install:
        all_tasks.append(task_manager.add_task(WaptPackageInstall(req,force=force),notify_user=notify_user).as_dict())
    all_tasks.append(task_manager.add_task(WaptUpgrade(),notify_user=notify_user).as_dict())
    all_tasks.append(task_manager.add_task(WaptCleanup(),notify_user=False))
    data = {'result':'OK','content':all_tasks}
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title='Upgrade')


@app.route('/download_upgrades')
@app.route('/download_upgrades.json')
@allow_waptserver_or_local_unauth
def download_upgrades():
    force = int(request.args.get('force','0')) != 0
    notify_user = int(request.args.get('notify_user','0')) != 0
    all_tasks = []
    wapt().update()
    reqs = wapt().check_downloads()
    for req in reqs:
        all_tasks.append(task_manager.add_task(WaptDownloadPackage(req.asrequirement(),usecache=not force),notify_user=notify_user).as_dict())
    data = {'result':'OK','content':all_tasks}
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title=_(u'Download upgrades'))


@app.route('/upgrade2')
@app.route('/upgrade2.json')
@allow_waptserver_or_local_unauth
def upgrade2():
    notify_user = request.args.get('notify_user',None)
    if notify_user is not None:
        notify_user=int(notify_user)
    data1 = task_manager.add_task(WaptUpdate(),notify_user=notify_user).as_dict()
    data2 = task_manager.add_task(WaptUpgrade(),notify_user=notify_user).as_dict()
    data = {'result':'OK','content':[data1,data2]}
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title='Upgrade')


@app.route('/update')
@app.route('/update.json')
@allow_waptserver_or_local_unauth
def update():
    task = WaptUpdate()
    task.force = int(request.args.get('force','0')) != 0
    task.notify_user = int(request.args.get('notify_user','1')) != 0
    task.notify_server_on_finish = int(request.args.get('notify_server','0')) != 0
    data = task_manager.add_task(task).as_dict()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title=_(u'Installed software update'))


@app.route('/update_status')
@app.route('/update_status.json')
@allow_waptserver_or_local_unauth
def update_status():
    task = WaptUpdateServerStatus()
    data = task_manager.add_task(task).as_dict()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title=task)


@app.route('/longtask')
@app.route('/longtask.json')
@allow_waptserver_or_local_unauth
def longtask():
    notify_user = request.args.get('notify_user',None)
    if notify_user is not None:
        notify_user=int(notify_user)
    data = task_manager.add_task(
        WaptLongTask(
            duration=int(request.args.get('duration','60')),
            raise_error=int(request.args.get('raise_error',0))),
        notify_user=notify_user)
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title=_('LongTask'))


@app.route('/cleanup')
@app.route('/cleanup.json')
@app.route('/clean')
@allow_waptserver_or_local_unauth
def cleanup():
    task = WaptCleanup()
    task.force = int(request.args.get('force','0')) == 1
    notify_user = int(request.args.get('notify_user','0')) == 1
    data = task_manager.add_task(task,notify_user=notify_user)
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data.as_dict(),title=_('Cleanup'))


@app.route('/install_log')
@app.route('/install_log.json')
@allow_waptserver_or_local_auth
def install_log():
    logger.info(u"show install log")
    try:
        packagename = request.args.get('package')
        data = wapt().last_install_log(packagename)
    except Exception as e:
        data = {'result':'ERROR','message': u'{}'.format(ensure_unicode(e))}
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title=_('Trace of the installation of {}').format(packagename))


@app.route('/enable')
@allow_local_auth
def enable():
    logger.info(u"enable tasks scheduling")
    data = wapt().enable_tasks()
    return Response(common.jsondump(data), mimetype='application/json')


@app.route('/disable')
@allow_local_auth
def disable():
    logger.info(u"disable tasks scheduling")
    data = wapt().disable_tasks()
    return Response(common.jsondump(data), mimetype='application/json')


@app.route('/register')
@app.route('/register.json')
@allow_waptserver_or_local_auth
def register():
    logger.info(u"register computer")
    notify_user = int(request.args.get('notify_user','0')) == 1
    data = task_manager.add_task(WaptRegisterComputer(),notify_user=notify_user).as_dict()

    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title=_('Saving host to the WAPT server'))


@app.route('/inventory')
@app.route('/inventory.json')
@allow_waptserver_or_local_auth
def inventory():
    logger.info(u"Inventory")
    #wapt=Wapt(config_filename=app.waptconfig.config_filename)
    data = wapt().inventory()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title=_('Inventory of the host'))


@app.route('/install', methods=['GET'])
@app.route('/install.json', methods=['GET'])
@app.route('/install.html', methods=['GET'])
@allow_waptserver_or_local_auth
def install():
    package = request.args.get('package')
    force = int(request.args.get('force','0')) == 1
    notify_user = int(request.args.get('notify_user','0')) == 1
    data = task_manager.add_task(WaptPackageInstall(package,force=force),notify_user=notify_user).as_dict()

    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('install.html',data=data)


@app.route('/package_download')
@app.route('/package_download.json')
@allow_waptserver_or_local_auth
def package_download():
    package = request.args.get('package')
    logger.info(u"download package %s" % package)
    notify_user = int(request.args.get('notify_user','0')) == 1
    usecache = int(request.args.get('usecache','1')) == 1
    data = task_manager.add_task(WaptDownloadPackage(package,usecache=usecache),notify_user=notify_user).as_dict()

    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data)


@app.route('/remove', methods=['GET'])
@app.route('/remove.json', methods=['GET'])
@allow_waptserver_or_local_auth
def remove():
    package = request.args.get('package')
    packages = package.split(',')
    logger.info(u"Remove package(s) %s" % packages)
    force=int(request.args.get('force','0')) == 1
    notify_user = int(request.args.get('notify_user','0')) == 1
    data = []
    for package in packages:
        data.append(task_manager.add_task(WaptPackageRemove(package,force = force),notify_user=notify_user).as_dict())
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('install.html',data=data)


@app.route('/forget', methods=['GET'])
@app.route('/forget.json', methods=['GET'])
@allow_waptserver_or_local_auth
def forget():
    package = request.args.get('package')
    packages = package.split(',')
    logger.info(u"Forget package(s) %s" % packages)
    notify_user = int(request.args.get('notify_user','0')) == 1
    data = task_manager.add_task(WaptPackageForget(packages),notify_user=notify_user).as_dict()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('install.html',data=data)

@app.route('/favicon.ico', methods=['GET'])
def wapticon():
    return send_from_directory(app.static_folder+'/images','wapt.png',mimetype='image/png')

@app.route('/', methods=['GET'])
@allow_local
def index():
    host_info = setuphelpers.host_info()
    data = dict(html=html,
            host_info=host_info,
            wapt=wapt(),
            wapt_info=wapt().wapt_status(),
            update_status=wapt().get_last_update_status(),)
    if request.args.get('format','html')=='json'  or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('index.html',**data)


@app.route('/tasks')
@app.route('/tasks.json')
@allow_waptserver_or_local_unauth
def tasks():
    data = task_manager.tasks_status()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('tasks.html',data=data)


@app.route('/tasks_status')
@app.route('/tasks_status.json')
@allow_waptserver_or_local_unauth
def tasks_status():
    all = task_manager.tasks_status()
    data = []
    data.extend(all['pending'])
    if all['running']:
        data.append(all['running'])
    data.extend(all['done'])
    data.extend(all['errors'])

    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('tasks.html',data=data)


@app.route('/task')
@app.route('/task.json')
@app.route('/task.html')
@allow_waptserver_or_local_unauth
def task():
    id = int(request.args['id'])
    tasks = task_manager.tasks_status()
    all_tasks = tasks['done']+tasks['pending']+tasks['errors']
    if tasks['running']:
        all_tasks.append(tasks['running'])
    all_tasks = [task for task in all_tasks if task and task['id'] == id]
    if all_tasks:
        task = all_tasks[0]
    else:
        task = {}
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(task), mimetype='application/json')
    else:
        return render_template('task.html',task=task)


@app.route('/cancel_all_tasks')
@app.route('/cancel_all_tasks.html')
@app.route('/cancel_all_tasks.json')
@allow_waptserver_or_local_unauth
def cancel_all_tasks():
    data = task_manager.cancel_all_tasks()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data)


@app.route('/cancel_running_task')
@app.route('/cancel_running_task.json')
@allow_waptserver_or_local_unauth
def cancel_running_task():
    data = task_manager.cancel_running_task()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data)

@app.route('/cancel_task')
@app.route('/cancel_task.json')
@allow_waptserver_or_local_unauth
def cancel_task():
    id = int(request.args['id'])
    data = task_manager.cancel_task(id)
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data)


class EventsPrinter:
    '''EventsPrinter class which serves to emulates a file object and logs
       whatever it gets sent to a broadcast object at the INFO level.'''
    def __init__(self,events,logs):
        '''Grabs the specific brodcaster to use for printing.'''
        self.events = events
        self.logs = logs

    def write(self, text):
        '''Logs written output to listeners'''
        if text and text != '\n':
            if self.events:
                self.events.send_multipart([str('PRINT'),(ensure_unicode(text)).encode('utf8')])
            self.logs.append(ensure_unicode(text))


def eventprintinfo(func):
    '''Wraps a method so that any calls made to print get logged instead'''
    def pwrapper(*arg, **kwargs):
        stdobak = sys.stdout
        lpinstance = EventsPrinter(arg[0].wapt.events,arg[0].logs)
        sys.stdout = lpinstance
        try:
            return func(*arg, **kwargs)
        finally:
            sys.stdout = stdobak
    return pwrapper

new_wapt_event = threading.Event()

class WaptTask(object):
    """Base object class for all wapt task : download, install, remove, upgrade..."""
    def __init__(self,**args):
        self.id = -1
        self.wapt = None
        self.priority = 100
        self.order = 0
        self.external_pids = []
        self.create_date = datetime.datetime.now()
        self.start_date = None
        self.finish_date = None
        self.logs = []
        self.result = None
        self.runstatus = ""
        self.summary = u""
        # from 0 to 100%
        self.progress = 0
        self.notify_server_on_start = True
        self.notify_server_on_finish = True
        self.notify_user = True
        for k in args:
            setattr(self,k,args[k])
        self.lang = None

    def update_status(self,status):
        """Update runstatus in database and send PROGRESS event"""
        if self.wapt:
            self.runstatus = status
            self.wapt.runstatus = status
            if self.wapt.events:
                self.wapt.events.send_multipart(["TASKS",'PROGRESS',common.jsondump(self.as_dict())])

    def can_run(self,explain=False):
        """Return True if all the requirements for the task are met
        (ex. install can start if package+depencies are downloaded)"""
        return True

    def _run(self):
        """method to override in descendant to do the actual work"""
        pass

    @eventprintinfo
    def run(self):
        """register start and finish time, call _run, redirect stdout and stderr to events broadcaster
            result of task should be stored in self.result
            human readable summary of work done should be stored in self.summary
        """
        self.start_date = datetime.datetime.now()
        try:
            if self.wapt:
                self.wapt.task_is_cancelled.clear()
            # to keep track of external processes launched by Wapt.run()
            self.wapt.pidlist = self.external_pids
            self._run()
            self.progress=100
        finally:
            self.finish_date = datetime.datetime.now()

    def kill(self):
        """if task has been started, kill the task (ex: kill the external processes"""
        self.summary = u'Canceled'
        self.logs.append(u'Canceled')

        if self.wapt:
            self.wapt.task_is_cancelled.set()
        if self.external_pids:
            for pid in self.external_pids:
                logger.debug(u'Killing process with pid {}'.format(pid))
                setuphelpers.killtree(pid)
            del(self.external_pids[:])

    def run_external(self,*args,**kwargs):
        """Run an external process, register pid in current task to be able to kill it"""
        result = setuphelpers.run(*args,pidlist=self.external_pids,**kwargs)

    def __unicode__(self):
        return __(u"{classname} {id} created {create_date} started:{start_date} finished:{finish_date} ").format(**self.as_dict())

    def as_dict(self):
        return copy.deepcopy(dict(
            id=self.id,
            classname=self.__class__.__name__,
            priority = self.priority,
            order=self.order,
            create_date = self.create_date and self.create_date.isoformat(),
            start_date = self.start_date and self.start_date.isoformat(),
            finish_date = self.finish_date and self.finish_date.isoformat(),
            logs = u'\n'.join(self.logs),
            result = common.jsondump(self.result),
            summary = self.summary,
            progress = self.progress,
            runstatus = self.runstatus,
            description = u"{}".format(self),
            pidlist = u"{0}".format(self.external_pids),
            notify_user = self.notify_user,
            notify_server_on_start = self.notify_server_on_start,
            notify_server_on_finish = self.notify_server_on_finish,
            ))

    def as_json(self):
        return json.dumps(self.as_dict(),indent=True)

    def __repr__(self):
        return u"<{}>".format(self)

    def __cmp__(self,other):
        return cmp((self.priority,self.order),(other.priority,other.order))

    def same_action(self,other):
        return self.__class__ == other.__class__


class WaptNetworkReconfig(WaptTask):
    def __init__(self,**args):
        super(WaptNetworkReconfig,self).__init__()
        self.priority = 0
        self.notify_server_on_start = False
        self.notify_server_on_finish = False
        self.notify_user = False
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        logger.debug(u'Reloading config file')
        self.wapt.load_config(waptconfig.config_filename)
        self.wapt.network_reconfigure()
        waptconfig.load()
        self.result = waptconfig.as_dict()
        self.notify_server_on_finish = self.wapt.waptserver_available()

    def __unicode__(self):
        return __(u"Reconfiguring network access")


class WaptClientUpgrade(WaptTask):
    def __init__(self,**args):
        super(WaptClientUpgrade,self).__init__()
        self.priority = 10
        self.notify_server_on_start = True
        self.notify_server_on_finish = False
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        """Launch an external 'wapt-get waptupgrade' process to upgrade local copy of wapt client"""
        from setuphelpers import run
        output = run('"%s" %s' % (os.path.join(wapt_root_dir,'wapt-get.exe'),'waptupgrade'))
        self.result = {'result':'OK','message':output}

    def __unicode__(self):
        return __(u"Upgrading WAPT client")


class WaptServiceRestart(WaptTask):
    """A task to restart the waptservice using a spawned cmd process"""
    def __init__(self,**args):
        super(WaptServiceRestart,self).__init__()
        self.priority = 10000
        self.notify_server_on_start = False
        self.notify_server_on_finish = False
        self.notify_user = False
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        """Launch an external 'wapt-get waptupgrade' process to upgrade local copy of wapt client"""
        """
        tmp_bat = tempfile.NamedTemporaryFile(prefix='waptrestart',suffix='.cmd',mode='wt',delete=False)
        tmp_bat.write('ping -n 2 127.0.0.1 >nul\n')
        tmp_bat.write('net stop waptservice\n')
        tmp_bat.write('net start waptservice\n')
        tmp_bat.write('del "%s"\n'%tmp_bat.name)
        tmp_bat.close()
        setuphelpers.create_onetime_task('waptservicerestart',tmp_bat.name,'')
        """
        setuphelpers.create_onetime_task('waptservicerestart','cmd.exe','/C net stop waptservice & net start waptservice')
        output = __(u'WaptService restart planned')
        self.result = {'result':'OK','message':output}

    def __unicode__(self):
        return __(u"Restarting local WAPT service")


class WaptUpdate(WaptTask):
    def __init__(self,**args):
        super(WaptUpdate,self).__init__()
        self.priority = 10
        self.notify_server_on_start = False
        self.notify_server_on_finish = True
        self.force = False
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        self.wapt.check_install_running()
        self.result = self.wapt.update(force=self.force,register=self.notify_server_on_finish)
        """result: {
            count: 176,
            added: [ ],
            repos: [
            "http://srvwapt.tranquilit.local/wapt",
            "http://srvwapt.tranquilit.local/wapt-host"
            ],
            upgrades: ['install': 'additional': 'upgrade': ],
            date: "2014-02-28T19:30:35.829000",
            removed: [ ]
        },"""
        s = []
        if len(self.result['added'])>0:
            s.append(__(u'{} new package(s)').format(len(self.result['added'])))
        if len(self.result['removed'])>0:
            s.append(__(u'{} removed package(s)').format(len(self.result['removed'])))
        s.append(__(u'{} package(s) in the repository').format(self.result['count']))
        all_install =  self.result['upgrades']['install']+\
                        self.result['upgrades']['additional']+\
                        self.result['upgrades']['upgrade']
        installs = u','.join(all_install)
        errors = u','.join([p.asrequirement() for p in  self.wapt.error_packages()])
        if installs:
            s.append(__(u'Packages to be updated : {}').format(installs))
        if errors:
            s.append(__(u'Packages with errors : {}').format(errors))
        if not installs and not errors:
            s.append(__(u'System up-to-date'))
        self.summary = u'\n'.join(s)

    def __unicode__(self):
        return __(u"Updating available packages")


class WaptUpgrade(WaptTask):
    def __init__(self,**args):
        super(WaptUpgrade,self).__init__()
        #self.priority = 10
        self.notify_server_on_start = False
        self.notify_server_on_finish = True
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        def cjoin(l):
            return u','.join([u"%s" % (p[1].asrequirement(),) for p in l])

        # TODO : create parent/child tasks
        # currently, only a place holder for report
        self.result = self.wapt.check_install(force=True,forceupgrade=True)
        #self.result = self.wapt.upgrade()
        """result: {
            unavailable: [ ],
            skipped: [ ],
            errors: [ ],
            downloads: {
                downloaded: [ ],
                skipped: [ ],
                errors: [ ]
            },
            upgrade: [ ],
            install: [ ],
            additional: [ ]
            }"""
        all_install = self.result.get('install',[])
        if self.result.get('additional',[]):
            all_install.extend(self.result['additional'])
        install = cjoin(all_install)
        upgrade = cjoin(self.result.get('upgrade',[]))
        #skipped = cjoin(self.result['skipped'])
        errors = ','.join([p.asrequirement() for p in  self.wapt.error_packages()])
        unavailable = u','.join([p[0] for p in self.result.get('unavailable',[])])
        s = []
        if install:
            s.append(__(u'Installed : {}').format(install))
        if upgrade:
            s.append(__(u'Updated : {}').format(upgrade))
        if errors:
            s.append(__(u'Errors : {}').format(errors))
        if unavailable:
            s.append(__(u'Unavailable : {}').format(unavailable))
        if not errors and not unavailable and not install and not upgrade:
            s.append(__(u'System up-to-date'))

        self.summary = u"\n".join(s)

    def __unicode__(self):
        return __(u'Update packages installed on host')


class WaptUpdateServerStatus(WaptTask):
    """Send workstation status to server"""
    def __init__(self,**args):
        super(WaptUpdateServerStatus,self).__init__()
        self.priority = 10
        self.notify_server_on_start = False
        self.notify_server_on_finish = False
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        if self.wapt.waptserver_available():
            try:
                self.result = self.wapt.update_server_status()
                self.summary = __(u'WAPT Server has been notified')
            except Exception as e:
                self.result = {}
                self.summary = __(u"Error while sending to the server : {}").format(ensure_unicode(e))
        else:
            self.result = {}
            self.summary = __(u'WAPT Server is not available')

    def __unicode__(self):
        return __(u"Update server with this host's status")


class WaptRegisterComputer(WaptTask):
    """Send workstation status to server"""
    def __init__(self,**args):
        super(WaptRegisterComputer,self).__init__(**args)
        self.priority = 10
        self.notify_server_on_start = False
        self.notify_server_on_finish = False
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        if self.wapt.waptserver_available():
            try:
                self.result = self.wapt.register_computer()
                self.summary = __(u"Inventory has been sent to the WAPT server")
            except Exception as e:
                self.result = {}
                self.summary = __(u"Error while sending inventory to the server : {}").format(ensure_unicode(e))
                raise
        else:
            self.result = {}
            self.summary = __(u'WAPT Server is not avalable')
            raise Exception(self.summary)

    def __unicode__(self):
        return __(u"Update server with this host's inventory")


class WaptCleanup(WaptTask):
    """Cleanup local packages cache"""
    def __init__(self,**args):
        super(WaptCleanup,self).__init__()
        self.priority = 1000
        self.notify_server_on_start = False
        self.notify_server_on_finish = False
        self.notify_user = False
        self.force = False
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        def cjoin(l):
            return u','.join([u'%s'%p for p in l])
        try:
            self.result = self.wapt.cleanup(obsolete_only=not self.force)
            self.summary = __(u"Packages erased : {}").format(cjoin(self.result))
        except Exception as e:
            self.result = {}
            self.summary = __(u"Error while clearing local cache : {}").format(ensure_unicode(e))
            raise Exception(self.summary)

    def __unicode__(self):
        return __(u"Clear local package cache")

class WaptLongTask(WaptTask):
    """Test action for debug purpose"""
    def __init__(self,**args):
        super(WaptLongTask,self).__init__()
        self.duration = 60
        self.raise_error = False
        self.notify_server_on_start = False
        self.notify_server_on_finish = False
        for k in args:
            setattr(self,k,args[k])


    def _run(self):
        self.progress = 0
        for i in range(self.duration):
            if self.wapt:
                self.wapt.check_cancelled()
            #print u"Step {}".format(i)
            self.update_status(u"Step {}".format(i))
            self.progress = 100.0 /self.duration * i
            #print "test {:.0f}%".format(self.progress)
            time.sleep(1)
        if self.raise_error:
            raise Exception(__('raising an error for Test WaptLongTask'))

    def same_action(self,other):
        return False

    def __unicode__(self):
        return __(u"Test long running task of {}s").format(self.duration)


class WaptDownloadPackage(WaptTask):
    def __init__(self,packagename,usecache=True):
        super(WaptDownloadPackage,self).__init__()
        self.packagename = packagename
        self.usecache = usecache
        self.size = 0

    def printhook(self,received,total,speed,url):
        self.wapt.check_cancelled()
        if total>1.0:
            stat = u'%i / %i (%.0f%%) (%.0f KB/s)\r' % (received,total,100.0*received/total, speed)
            self.progress = 100.0*received/total
            if not self.size:
                self.size = total
        else:
            stat = u''
        self.update_status(__(u'Downloading %s : %s' % (url,stat)))

    def _run(self):
        start = time.time()
        self.result = self.wapt.download_packages(self.packagename,usecache=self.usecache,printhook=self.printhook)
        end = time.time()
        if self.result['errors']:
            self.summary = __(u"Error while downloading {packagename}: {error}").format(packagename=self.packagename,error=self.result['errors'][0][1])
        else:
            if end-start> 0.01:
                self.summary = __(u"Done downloading {packagename}. {speed} kB/s").format(packagename=self.packagename,speed=self.size/1024/(end-start))
            else:
                self.summary = __(u"Done downloading {packagename}.").format(packagename=self.packagename)

    def as_dict(self):
        d = WaptTask.as_dict(self)
        d.update(
            dict(
                packagename = self.packagename,
                usecache = self.usecache,
                )
            )
        return d

    def __unicode__(self):
        return __(u"Download of {packagename} (tâche #{id})").format(classname=self.__class__.__name__,id=self.id,packagename=self.packagename)

    def same_action(self,other):
        return (self.__class__ == other.__class__) and (self.packagename == other.packagename)


class WaptPackageInstall(WaptTask):
    def __init__(self,packagename,force=False):
        super(WaptPackageInstall,self).__init__()
        self.packagename = packagename
        self.force = force
        self.package = None

    def _run(self):
        def cjoin(l):
            return u','.join([u"%s" % (p[1].asrequirement() if p[1] else p[0],) for p in l])
        self.result = self.wapt.install(self.packagename,force = self.force)
        all_install = self.result.get('install',[])
        if self.result.get('additional',[]):
            all_install.extend(self.result['additional'])
        install = cjoin(all_install)
        upgrade = cjoin(self.result.get('upgrade',[]))
        #skipped = cjoin(self.result['skipped'])
        errors = cjoin(self.result.get('errors',[]))
        unavailable = cjoin(self.result.get('unavailable',[]))
        s = []
        if install:
            s.append(__(u'Installed : {}').format(install))
        if upgrade:
            s.append(__(u'Updated : {}').format(upgrade))
        if errors:
            s.append(__(u'Errors : {}').format(errors))
        if unavailable:
            s.append(__(u'Unavailable : {}').format(unavailable))
        self.summary = u"\n".join(s)
        if self.result.get('errors',[]):
            raise Exception(__('Error during install of {}: errors in packages {}').format(
                    self.packagename,
                    self.result.get('errors',[])))

    def as_dict(self):
        d = WaptTask.as_dict(self)
        d.update(
            dict(
                packagename = self.packagename,
                force = self.force)
            )
        return d

    def __unicode__(self):
        return __(u"Installation of {packagename} (task #{id})").format(classname=self.__class__.__name__,id=self.id,packagename=self.packagename)

    def same_action(self,other):
        return (self.__class__ == other.__class__) and (self.packagename == other.packagename)


class WaptPackageRemove(WaptPackageInstall):
    def __init__(self,packagename,force=False):
        super(WaptPackageRemove,self).__init__(packagename=packagename,force=force)

    def _run(self):
        def cjoin(l):
            return u','.join([u'%s'%p for p in l])

        self.result = self.wapt.remove(self.packagename,force=self.force)
        s = []
        if self.result['removed']:
            s.append(__(u'Removed : {}').format(cjoin(self.result['removed'])))
        if self.result['errors']:
            s.append(__(u'Errors : {}').format(cjoin(self.result['errors'])))
        self.summary = u"\n".join(s)

    def __unicode__(self):
        return __(u"Uninstall of {packagename} (task #{id})").format(classname=self.__class__.__name__,id=self.id,packagename=self.packagename)


class WaptPackageForget(WaptTask):
    def __init__(self,packagenames):
        super(WaptPackageForget,self).__init__()
        self.packagenames = packagenames

    def _run(self):
        self.result = self.wapt.forget_packages(self.packagenames)
        if self.result:
            self.summary = __(u"Packages removed from database : %s") % (u"\n".join(self.result),)
        else:
            self.summary = __(u"No package removed from database.")

    def __unicode__(self):
        return __(u"Forget {packagenames} (task #{id})").format(classname=self.__class__.__name__,id=self.id,packagenames=self.packagenames)


    def same_action(self,other):
        return (self.__class__ == other.__class__) and (self.packagenames == other.packagenames)


def is_firewall_running():
    if setuphelpers.service_installed('MpsSvc'):
        return setuphelpers.service_is_running('MpsSvc')
    else:
        return setuphelpers.service_installed('sharedaccess') and setuphelpers.isrunning('sharedaccess')


def babel_translations(lang = ''):
    dirname = os.path.join(app.root_path, 'translations')
    return babel.support.Translations.load(dirname, [lang])

tr = babel_translations(waptconfig.language)
__ = tr.ugettext

class WaptTaskManager(threading.Thread):
    _ = __


    def __init__(self,config_filename = 'c:/wapt/wapt-get.ini'):
        threading.Thread.__init__(self)
        self.status_lock = threading.RLock()

        self.wapt=None
        self.tasks = []

        self.tasks_queue = Queue.PriorityQueue()
        self.tasks_counter = 0

        self.tasks_done = []
        self.tasks_error = []
        self.tasks_cancelled = []
        self.events = None

        self.running_task = None
        self.config_filename = config_filename

        self.last_upgrade = None
        self.last_update = None

        self.firewall_running = None

    def setup_event_queue(self):
        if waptconfig.zmq_port:
            # init zeromq events broadcast
            try:
                zmq_context = zmq.Context()
                event_queue = zmq_context.socket(zmq.PUB)
                event_queue.hwm = 10000;

                logger.debug('Starting ZMQ on port %i' % waptconfig.zmq_port)
                # start event broadcasting
                event_queue.bind("tcp://127.0.0.1:{}".format(waptconfig.zmq_port))

                # add logger through zmq events
                handler = PUBHandler(event_queue)
                logger.addHandler(handler)

                self.events = event_queue
            except Exception as e:
                logger.warning('Unable to start Event queue : %s'%e)
                self.events = None
        else:
            self.events = None
            logger.info('zmq_port not set, no Event queue setup.')
        self.wapt.events = self.events
        return self.events

    def update_runstatus(self,status):
        # update database with new runstatus
        self.wapt.runstatus = status
        if self.events:
            # dispatch event to listening parties
            msg = common.jsondump(self.wapt.get_last_update_status())
            self.wapt.events.send_multipart([str("STATUS"),msg])

    def update_server_status(self):
        if self.wapt.waptserver_available():
            try:
                result = self.wapt.update_server_status()
                if result['uuid']:
                    self.last_update_server_date = datetime.datetime.now()
            except Exception as e:
                logger.debug(u'Unable to update server status: %s' % ensure_unicode(e))

    def broadcast_tasks_status(self,topic,task):
        """topic : ADD START FINISH CANCEL ERROR
        """
        # ignore broadcast for this..
        if isinstance(task,WaptUpdateServerStatus):
            return
        if self.events and task:
            self.wapt.events.send_multipart([str("TASKS"),topic,common.jsondump(task)])

    def add_task(self,task,notify_user=None):
        """Adds a new WaptTask for processing"""
        with self.status_lock:
            same = [ pending for pending in self.tasks_queue.queue if pending.same_action(task)]
            if self.running_task and self.running_task.same_action(task):
                same.append(self.running_task)

            # keep track of last update/upgrade add date to avoid relaunching
            if isinstance(task,WaptUpdate):
                self.last_update = time.time()
            if isinstance(task,WaptUpgrade):
                self.last_upgrade = time.time()

            # not already in pending  actions...
            if not same:
                task.wapt = self.wapt

                self.tasks_counter += 1
                task.id = self.tasks_counter
                # default order is task id
                task.order = self.tasks_counter
                if notify_user is not None:
                    task.notify_user = notify_user
                self.tasks_queue.put(task)
                self.tasks.append(task)
                self.broadcast_tasks_status(str('ADD'),task)
                return task
            else:
                return same[0]

    def check_configuration(self):
        """Check wapt configuration, reload ini file if changed"""
        try:
            logger.debug(u"Checking if config file has changed")
            if waptconfig.reload_if_updated():
                logger.info(u"Wapt config file has changed, reloading")
                self.wapt.reload_config_if_updated()

        except:
            pass

    def check_scheduled_tasks(self):
        """Add update/upgrade tasks if elapsed time since last update/upgrade is over"""
        logger.debug(u'Check scheduled tasks')

        if datetime.datetime.now() - self.start_time >= datetime.timedelta(days=1):
            self.start_time = datetime.datetime.now()
            self.add_task(WaptServiceRestart())

        if waptconfig.waptupgrade_task_period is not None and common.running_on_ac():
            if self.last_upgrade is None or (time.time()-self.last_upgrade)/60>waptconfig.waptupgrade_task_period:
                try:
                    actions = self.wapt.list_upgrade()
                    to_install = actions['upgrade']+actions['additional']+actions['install']
                    for req in to_install:
                        self.add_task(WaptPackageInstall(req),notify_user=True)
                    self.add_task(WaptUpgrade(notifyuser=False))
                except Exception as e:
                    logger.debug(u'Error for upgrade in check_scheduled_tasks: %s'%e)
                self.add_task(WaptCleanup(notifyuser=False))

        if waptconfig.waptupdate_task_period is not None:
            if self.last_update is None or (time.time()-self.last_update)/60>waptconfig.waptupdate_task_period:
                try:
                    self.wapt.update()
                    reqs = self.wapt.check_downloads()
                    for req in reqs:
                        self.add_task(WaptDownloadPackage(req.asrequirement()),notify_user=True)
                    self.add_task(WaptUpdate(notify_user=False))
                except Exception as e:
                    logger.debug(u'Error for update in check_scheduled_tasks: %s'%e)

    def run(self):
        """Queue management, event processing"""
        try:
            pythoncom.CoInitializeEx(pythoncom.COINIT_MULTITHREADED)
        except pythoncom.com_error:
            # already initialized.
            pass

        self.start_time = datetime.datetime.now()
        self.wapt = Wapt(config_filename=self.config_filename)
        self.events = self.setup_event_queue()
        self.firewall_running = is_firewall_running()
        logger.info(u'Wapt tasks management initialized with {} configuration, thread ID {}'.format(self.config_filename,threading.current_thread().ident))

        self.start_network_monitoring()
        self.start_ipaddr_monitoring()

        logger.debug(u"Wapt tasks queue started")
        while True:
            try:
                # check wapt configuration, reload ini file if changed
                # reload wapt config
                self.check_configuration()

                # check tasks queue
                self.running_task = self.tasks_queue.get(timeout=waptconfig.waptservice_poll_timeout)
                try:
                    # don't send update_run status for updatestatus itself...
                    self.broadcast_tasks_status(str('START'),self.running_task)
                    if self.running_task.notify_server_on_start:
                        self.update_runstatus(__(u'Running: {description}').format(description=self.running_task) )
                        self.update_server_status()
                    try:
                        self.running_task.run()
                        if self.running_task:
                            self.tasks_done.append(self.running_task)
                            self.broadcast_tasks_status(str('FINISH'),self.running_task)
                            if self.running_task.notify_server_on_finish:
                                self.update_runstatus(__(u'Done: {description}\n{summary}').format(description=self.running_task,summary=self.running_task.summary) )
                                self.update_server_status()

                    except common.EWaptCancelled as e:
                        if self.running_task:
                            self.running_task.logs.append(u"{}".format(ensure_unicode(e)))
                            self.running_task.summary = __(u"Canceled")
                            self.tasks_cancelled.append(self.running_task)
                            self.broadcast_tasks_status(str('CANCEL'),self.running_task)
                    except Exception as e:
                        if self.running_task:
                            self.running_task.logs.append(u"{}".format(ensure_unicode(e)))
                            self.running_task.logs.append(ensure_unicode(traceback.format_exc()))
                            self.running_task.summary = u"{}".format(ensure_unicode(e))
                            self.tasks_error.append(self.running_task)
                            self.broadcast_tasks_status(str('ERROR'),self.running_task)
                        logger.critical(ensure_unicode(e))
                        try:
                            logger.debug(ensure_unicode(traceback.format_exc()))
                        except:
                            print("Traceback error")
                finally:
                    self.tasks_queue.task_done()
                    self.update_runstatus('')

                    self.running_task = None
                    # trim history lists
                    if len(self.tasks_cancelled)>waptconfig.MAX_HISTORY:
                        del self.tasks_cancelled[:len(self.tasks_cancelled)-waptconfig.MAX_HISTORY]
                    if len(self.tasks_done)>waptconfig.MAX_HISTORY:
                        del self.tasks_done[:len(self.tasks_done)-waptconfig.MAX_HISTORY]
                    if len(self.tasks_error)>waptconfig.MAX_HISTORY:
                        del self.tasks_error[:len(self.tasks_error)-waptconfig.MAX_HISTORY]

            except Queue.Empty:
                self.update_runstatus('')
                try:
                    self.check_scheduled_tasks()
                except Exception as e:
                    logger.warning(u'Error checking scheduled tasks : %s' % ensure_unicode(traceback.format_exc()))
                logger.debug(u"{} i'm still alive... but nothing to do".format(datetime.datetime.now()))

    def tasks_status(self):
        """Returns list of pending, error, done tasks, and current running one"""
        with self.status_lock:
            return dict(
                running=self.running_task and self.running_task.as_dict(),
                pending=[task.as_dict() for task in sorted(self.tasks_queue.queue)],
                done = [task.as_dict() for task in self.tasks_done],
                cancelled = [ task.as_dict() for task in self.tasks_cancelled],
                errors = [ task.as_dict() for task in self.tasks_error],
                )

    def cancel_running_task(self):
        """Cancel running task. Returns cancelled task"""
        with self.status_lock:
            if self.running_task:
                try:
                    cancelled = self.running_task
                    self.tasks_error.append(self.running_task)
                    try:
                        self.running_task.kill()
                    except:
                        pass
                finally:
                    self.running_task = None
                if cancelled:
                    self.tasks_cancelled.append(cancelled)
                    self.broadcast_tasks_status('CANCEL',cancelled)
                return cancelled
            else:
                return None

    def cancel_task(self,id):
        """Cancel running or pending task with supplied id.
            return cancelled task"""
        with self.status_lock:
            cancelled = None
            if self.running_task and self.running_task.id == id:
                cancelled = self.running_task
                try:
                    self.running_task.kill()
                except:
                    pass
                finally:
                    self.running_task = None
            else:
                for task in self.tasks_queue.queue:
                    if task.id == id:
                        cancelled = task
                        self.tasks_queue.queue.remove(task)
                        break
                if cancelled:
                    try:
                        cancelled.kill()
                    except:
                        pass
            if cancelled:
                self.broadcast_tasks_status('CANCEL',cancelled)
            return cancelled

    def cancel_all_tasks(self):
        """Cancel running and pending tasks. Returns list of cancelled tasks"""
        with self.status_lock:
            cancelled = []
            while not self.tasks_queue.empty():
                 cancelled.append(self.tasks_queue.get())
            if self.running_task:
                try:
                    cancelled.append(self.running_task)
                    self.tasks_error.append(self.running_task)
                    try:
                        self.running_task.kill()
                    except:
                        pass
                finally:
                    self.running_task = None
            for task in cancelled:
                self.tasks_cancelled.append(task)
                self.broadcast_tasks_status('CANCEL',task)
            return cancelled

    def start_ipaddr_monitoring(self):
        nac = ctypes.windll.iphlpapi.NotifyAddrChange
        def addr_change(wapt):
            while True:
                nac(0, 0)
                wapt.add_task(WaptNetworkReconfig())

        nm = threading.Thread(target=addr_change,args=(self,))
        nm.daemon = True
        nm.start()
        logger.debug(u"Wapt network address monitoring started")

    def start_network_monitoring(self):
        nrc = ctypes.windll.iphlpapi.NotifyRouteChange
        def connected_change(taskman):
            while True:
                nrc(0, 0)
                taskman.add_task(WaptNetworkReconfig())

        nm = threading.Thread(target=connected_change,args=(self,))
        nm.daemon = True
        nm.start()
        logger.debug(u"Wapt connection monitor started")

    def __unicode__(self):
        return "\n".join(self.tasks_status())

def install_service():
    """Setup waptservice as a windows Service managed by nssm
    >>> install_service()
    """
    logger.info(u'Open port on firewall')
    # http
    if waptconfig.waptserver is not None:
        if waptconfig.waptservice_port is not None:
            check_open_port(waptconfig.waptservice_port)
        # https
        if waptconfig.waptservice_sslport is not None:
            check_open_port(waptconfig.waptservice_sslport)

    from setuphelpers import registry_set,REG_DWORD,REG_EXPAND_SZ,REG_MULTI_SZ,REG_SZ
    datatypes = {
        'dword':REG_DWORD,
        'sz':REG_SZ,
        'expand_sz':REG_EXPAND_SZ,
        'multi_sz':REG_MULTI_SZ,
    }

    if setuphelpers.service_installed('waptservice'):
        if not setuphelpers.service_is_stopped('waptservice'):
            logger.info(u'Stop running waptservice')
            setuphelpers.service_stop('waptservice')
            while not setuphelpers.service_is_stopped('waptservice'):
                logger.debug(u'Waiting for waptservice to terminate')
                time.sleep(2)
        logger.info(u'Unregister existing waptservice')
        setuphelpers.service_delete('waptservice')

    if setuphelpers.iswin64():
        nssm = os.path.join(wapt_root_dir,'waptservice','win64','nssm.exe')
    else:
        nssm = os.path.join(wapt_root_dir,'waptservice','win32','nssm.exe')

    logger.info(u'Register new waptservice with nssm')
    setuphelpers.run('"{nssm}" install WAPTService "{waptpython}" -E ""{waptservicepy}""'.format(
        waptpython = os.path.abspath(os.path.join(wapt_root_dir,'waptpython.exe')),
        nssm = nssm,
        waptservicepy = os.path.abspath(__file__),
     ))

    #logger.info('Delayed startup')
    #setuphelpers.run('"{nssm}" set WAPTService Start SERVICE_DELAYED_START'.format(
    #    nssm = nssm))

    # fix some parameters (quotes for path with spaces...
    params = {
        "Description": "sz:Local helper managing WAPT install/remove/update/upgrade",
        "DisplayName" : "sz:WAPTService",
        "AppStdout" : r"expand_sz:{}".format(os.path.join(waptconfig.log_directory,'waptservice.log')),
        "Parameters\\AppStderr" : r"expand_sz:{}".format(os.path.join(waptconfig.log_directory,'waptservice.log')),
        "Parameters\\AppStdout" : r"expand_sz:{}".format(os.path.join(waptconfig.log_directory,'waptservice.log')),
        "Parameters\\AppParameters" : r'expand_sz:"{}"'.format(os.path.abspath(__file__)),
        "Parameters\\AppRotateFiles": 1,
        "Parameters\\AppRotateBytes": 10*1024*1024,
        }

    root = setuphelpers.HKEY_LOCAL_MACHINE
    base = r'SYSTEM\CurrentControlSet\services\WAPTService'
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

    logger.info(u'Allow authenticated users to start/stop waptservice')
    setuphelpers.run('sc sdset waptservice D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;S-1-5-11)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)');

if __name__ == "__main__":
    usage="""\
    %prog -c configfile [action]

    WAPT Service.

    action is either :
      <nothing> : run service in foreground
      install   : install as a Windows service managed by nssm

    """

    parser=OptionParser(usage=usage,version='waptservice.py ' + __version__+' common.py '+common.__version__+' setuphelpers.py '+setuphelpers.__version__)
    parser.add_option("-c","--config", dest="config", default=os.path.join(wapt_root_dir,'wapt-get.ini') , help="Config file full path (default: %default)")
    parser.add_option("-l","--loglevel", dest="loglevel", default=None, type='choice',  choices=['debug','warning','info','error','critical'], metavar='LOGLEVEL',help="Loglevel (default: warning)")
    parser.add_option("-d","--devel", dest="devel", default=False,action='store_true', help="Enable debug mode (for development only)")

    (options,args)=parser.parse_args()

    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')

    def setloglevel(logger,loglevel):
        """set loglevel as string"""
        if loglevel in ('debug','warning','info','error','critical'):
            numeric_level = getattr(logging, loglevel.upper(), None)
            if not isinstance(numeric_level, int):
                raise ValueError(_('Invalid log level: {}').format(loglevel))
            logger.setLevel(numeric_level)

    if args  and args[0] == 'doctest':
        import doctest
        sys.exit(doctest.testmod())

    if args and args[0] == 'install':
        install_service()
        sys.exit(0)

    waptconfig.config_filename = options.config
    waptconfig.load()

    # force loglevel
    if waptconfig.loglevel is not None:
        setloglevel(logger,waptconfig.loglevel)

    if waptconfig.log_to_windows_events:
        try:
            from logging.handlers import NTEventLogHandler
            hdlr = NTEventLogHandler('waptservice')
            logger.addHandler(hdlr)
        except Exception as e:
            print('Unable to initialize windows log Event handler: %s' % e)

    # setup basic settings
    apply_host_settings(waptconfig)

    # starts one WaptTasksManager
    task_manager = WaptTaskManager(config_filename = waptconfig.config_filename)
    task_manager.daemon = True
    task_manager.start()
    if options.devel:
        app.run(host='0.0.0.0',port=8088,debug=False)
    else:
        #logger.setLevel(logging.DEBUG)

        # hack to authenticate clients using client ssl certificates
        import rocket.listener
        # copy from rocket/listener.py
        def wrap_socket(self, sock):
            try:
                sock = ssl.wrap_socket(sock,
                                       keyfile = self.interface[2],
                                       certfile = self.interface[3],
                                       server_side = True,
                                       ssl_version = ssl.PROTOCOL_SSLv23,
                                       ca_certs = os.path.join(wapt_root_dir,r'waptservice','ssl','caserver.pem'),
                                       cert_reqs = ssl.CERT_REQUIRED )
            except SSLError:
                pass

            return sock

        #rocket.listener.Listener.wrap_socket = wrap_socket
        port_config = []
        if waptconfig.waptservice_port:
            port_config.append(('0.0.0.0', waptconfig.waptservice_port))
        if waptconfig.waptservice_sslport:
            port_config.append(('0.0.0.0', waptconfig.waptservice_sslport,
                            os.path.join(wapt_root_dir,r'waptservice','ssl','waptservice.pem'),
                            os.path.join(wapt_root_dir,r'waptservice','ssl','waptservice.crt')))
        server = Rocket(port_config,'wsgi', {"wsgi_app":app})

        try:
            logger.info(u"starting waptservice")
            # http
            if waptconfig.waptserver is not None:
                if waptconfig.waptservice_port is not None:
                    check_open_port(waptconfig.waptservice_port)
                # https
                if waptconfig.waptservice_sslport is not None:
                    check_open_port(waptconfig.waptservice_sslport)
            server.start()
        except KeyboardInterrupt:
            logger.info(u"stopping waptservice")
            server.stop()
