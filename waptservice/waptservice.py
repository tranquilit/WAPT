# -*- coding: UTF-8 -*-
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
__version__ = "0.8.13"

import time
import sys
import os
import hashlib
from werkzeug import secure_filename
from urlparse import urlparse
from functools import wraps
import logging
import ConfigParser
import logging
import sqlite3
import socket
import thread
import threading
import json
from rocket import Rocket
from flask import request, Flask,Response, send_from_directory, send_file, session, g, redirect, url_for, abort, render_template, flash
import requests
import StringIO
import zmq
from zmq.log.handlers import PUBHandler
import Queue
import jinja2
import pythoncom
import ctypes

from network_manager import NetworkManager
from werkzeug.utils import html

import gc
import datetime
import dateutil.parser

import winsys.security
import winsys.accounts

try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.append(os.path.join(wapt_root_dir))
sys.path.append(os.path.join(wapt_root_dir,'lib'))
sys.path.append(os.path.join(wapt_root_dir,'waptservice'))
sys.path.append(os.path.join(wapt_root_dir,'lib','site-packages'))

import ssl
from ssl import SSLError

import common
import setuphelpers
from common import Wapt


logger = logging.getLogger()
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
logger.setLevel(logging.INFO)

def setloglevel(logger,loglevel):
    """set loglevel as string"""
    if loglevel in ('debug','warning','info','error','critical'):
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % loglevel)
        logger.setLevel(numeric_level)

def get_authorized_callers_ip(waptserver_url):
    """Returns list of IP allowed to request actions with check_caller decorator"""
    ips = ['127.0.0.1']
    if waptserver_url:
        try:
            ips.append(socket.gethostbyname( urlparse(waptserver_url).hostname))
        except socket.gaierror as e:
            # no network connection to resolve hostname
            pass
    return ips

class WaptServiceConfig(object):
    """Configuration parameters from wapt-get.ini file
    >>> waptconfig = WaptServiceConfig('c:/wapt/wapt-get.ini')
    >>> waptconfig.load()
    """
    def __init__(self,config_filename=None):
        if not config_filename:
            self.config_filename = os.path.join(wapt_root_dir,'wapt-get.ini')
        else:
            self.config_filename = config_filename
        self.wapt_user = "admin"
        self.wapt_password = None

        # maximum nb of tasks in wapt task manager
        self.MAX_HISTORY = 30

        self.waptservice_port = 8088
        self.dbpath = os.path.join(wapt_root_dir,'db','waptdb.sqlite')
        self.loglevel = "info"
        self.log_directory = os.path.join(wapt_root_dir,'log')
        if not os.path.exists(self.log_directory):
            os.mkdir(self.log_directory)

        self.wapt_server = ""
        self.authorized_callers_ip = get_authorized_callers_ip(self.wapt_server)

    def load(self):
        """Load waptservice parameters from global wapt-get.ini file"""
        config = ConfigParser.RawConfigParser()
        if os.path.exists(self.config_filename):
            config.read(self.config_filename)
        else:
            raise Exception("FATAL. Couldn't open config file : " + self.config_filename)
        # lecture configuration
        if config.has_section('global'):
            if config.has_option('global', 'waptservice_user'):
                self.wapt_user = config.get('global', 'waptservice_user')
            else:
                self.wapt_user = 'admin'

            if config.has_option('global','waptservice_password'):
                self.wapt_password = config.get('global', 'waptservice_password')
            else:
                logger.warning("WARNING : no password set, using default password")
                self.wapt_password='5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8' # = password

            if config.has_option('global','waptservice_port'):
                self.waptservice_port = int(config.get('global','waptservice_port'))
            else:
                self.waptservice_port=8088

            if config.has_option('global','dbdir'):
                self.dbpath = os.path.join(config.get('global','dbdir'),'waptdb.sqlite')
            else:
                self.dbpath = os.path.join(wapt_root_dir,'db','waptdb.sqlite')

            if config.has_option('global','loglevel'):
                self.loglevel = config.get('global','loglevel')
                setloglevel(logger,self.loglevel)
            else:
                setloglevel(logger,'warning')

            if config.has_option('global','wapt_server'):
                self.wapt_server = config.get('global','wapt_server')
            else:
                self.wapt_server = ''
            self.authorized_callers_ip = get_authorized_callers_ip(self.wapt_server)

        else:
            raise Exception ("FATAL, configuration file " + self.config_filename + " has no section [global]. Please check Waptserver documentation")

        def __str__(self):
            return ""

def format_isodate(isodate):
    """Pretty format iso date like : 2014-01-21T17:36:15.652000
        >>> format_isodate('2014-01-21T17:36:15.652000')
        '21/01/2014 17:36:15'
    """
    return dateutil.parser.parse(isodate).strftime("%d/%m/%Y %H:%M:%S")


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
        return jinja2.Markup(setuphelpers.ensure_unicode(c).replace('\r\n','<br>').replace('\n','<br>'))
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
        return jinja2.Markup(u"<pre>{}</pre>".format(setuphelpers.ensure_unicode(c)))

def ssl_required(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        if current_app.config.get("SSL"):
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
    if win_major_version<6:
        #check if firewall is running
        print "Running on NT5 "
        if  win32serviceutil.QueryServiceStatus( 'SharedAccess', None)[1]==win32service.SERVICE_RUNNING:
            logger.info("Firewall started, checking for port openning...")
            #winXP 2003
            if 'waptservice' not in setuphelpers.run_notfatal('netsh firewall show portopening'):
                logger.info("Adding a firewall rule to open port %s"%portnumber)
                setuphelpers.run_notfatal("""netsh.exe firewall add portopening name="waptservice %s" port=%s protocol=TCP"""%(portnumber,portnumber))
            else:
                logger.info("port %s already opened, skipping firewall configuration"%(portnumber,))
    else:

        if  win32serviceutil.QueryServiceStatus( 'MpsSvc', None)[1]==win32service.SERVICE_RUNNING:
            logger.info("Firewall started, checking for port openning...")
            if 'waptservice' not in setuphelpers.run_notfatal('netsh advfirewall firewall show rule name="waptservice %s"'%(portnumber,)):
                logger.info("No port opened for waptservice, opening port %s"%portnumber)
                #win Vista and higher
                setuphelpers.run_notfatal("""netsh advfirewall firewall add rule name="waptservice %s" dir=in action=allow protocol=TCP localport=%s"""%(portnumber,portnumber))
            else:
                logger.info("port %s already opened, skipping firewall configuration"%(portnumber,))


waptconfig = WaptServiceConfig()
waptconfig.load()

app = Flask(__name__)
app.config['PROPAGATE_EXCEPTIONS'] = True
app.jinja_env.filters['beautify'] = beautify
app.waptconfig = waptconfig

def wapt():
    if not hasattr(g,'wapt'):
        g.wapt = Wapt(config_filename = waptconfig.config_filename)
    return g.wapt


def requires_auth(f):
    """Restrict access to localhost (authenticated) or waptserver IP"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth:
            logging.info('no credential given')
            return authenticate()

        logging.info("authenticating : %s" % auth.username)
        if not check_auth(auth.username, auth.password):
            return authenticate()

        if not request.remote_addr in app.waptconfig.authorized_callers_ip:
            return authenticate()

        logging.info("user %s authenticated" % auth.username)
        return f(*args, **kwargs)

    return decorated

def check_ip_source(f):
    """Restrict access to localhost or waptserver IP"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not request.remote_addr in app.waptconfig.authorized_callers_ip:
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route('/status')
@app.route('/status.json')
@check_ip_source
def status():
    rows = []
    with sqlite3.connect(app.waptconfig.dbpath) as con:
        try:
            con.row_factory=sqlite3.Row
            query = '''select s.package,s.version,s.install_date,s.install_status,s.install_output,r.description,
                                 (select GROUP_CONCAT(p.version," | ") from wapt_package p where p.package=s.package) as repo_version,explicit_by as install_par
                                 from wapt_localstatus s
                                 left join wapt_package r on r.package=s.package and r.version=s.version
                                 order by s.package'''
            cur = con.cursor()
            cur.execute(query)
            rows = [ dict(x) for x in cur.fetchall() ]
        except lite.Error, e:
            logger.critical("*********** Error %s:" % e.args[0])
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(rows), mimetype='application/json')
    else:
        return render_template('status.html',packages=rows,format_isodate=format_isodate,Version=setuphelpers.Version)

@app.route('/list')
@app.route('/packages')
@app.route('/packages.json')
@check_ip_source
def all_packages():
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
            rows = [ dict(x) for x in cur.fetchall() ]
        except sqlite3.Error, e:
            logger.critical("*********** Error %s:" % e.args[0])
    if request.args.get('format','html')=='json' or request.url.endswith('.json'):
        return Response(common.jsondump(rows), mimetype='application/json')
    else:
        return render_template('list.html',packages=rows,format_isodate=format_isodate,Version=setuphelpers.Version)

@app.route('/package_icon')
@check_ip_source
def package_icon():
    package = request.args.get('package')
    icon_local_cache = os.path.join(wapt_root_dir,'cache','icons')
    if not os.path.isdir(icon_local_cache):
        os.makedirs(icon_local_cache)
    #wapt=[]

    def get_icon(package):
        """Get icon from local cache or remote wapt directory, returns local filename"""
        icon_local_filename = os.path.join(icon_local_cache,package+'.png')
        if not os.path.isfile(icon_local_filename) or os.path.getsize(icon_local_filename)<10:
            #if not wapt:
            #    wapt.append(Wapt(config_filename=app.waptconfig.config_filename))
            proxies = wapt().proxies
            repo_url = wapt().repositories[0].repo_url

            remote_icon_path = "{repo}/icons/{package}.png".format(repo=repo_url,package=package)
            icon = requests.get(remote_icon_path,proxies=proxies)
            icon.raise_for_status()
            open(icon_local_filename,'wb').write(icon.content)
            return StringIO.StringIO(icon.content)
        else:
            return open(icon_local_filename,'rb')

    try:
        icon = get_icon(package)
        return send_file(icon,'image/png',as_attachment=True,attachment_filename='{}.png'.format(package),cache_timeout=43200)
    except requests.HTTPError as e:
        icon = get_icon('unknown')
        return send_file(icon,'image/png',as_attachment=True,attachment_filename='{}.png'.format('unknown'),cache_timeout=43200)

@app.route('/package_details')
@app.route('/package_details.json')
@check_ip_source
def package_details():
    #wapt=Wapt(config_filename=app.waptconfig.config_filename)
    package = request.args.get('package')
    try:
        data = wapt().is_available(package)
    except Exception as e:
        data = {'errors':[ str(e) ]}

    # take the newest...
    data = data and data[-1].as_dict()
    if request.args.get('format','html')=='json':
        return Response(common.jsondump(dict(result=data,errors=[])), mimetype='application/json')
    else:
        return render_template('package_details.html',data=data)


@app.route('/runstatus')
@check_ip_source
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
            logger.critical("*********** error " + str (e))
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/checkupgrades')
@app.route('/checkupgrades.json')
@check_ip_source
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
            logger.critical("*********** error %s"  % (e,))
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title=u'Status des mises à jour')

@app.route('/waptupgrade')
@app.route('/waptupgrade.json')
@check_ip_source
def waptupgrade():
    """Launch an external 'wapt-get waptupgrade' process to upgrade local copy of wapt client"""
    from setuphelpers import run
    output = run('"%s" %s' % (os.path.join(wapt_root_dir,'wapt-get.exe'),'waptupgrade'))
    data = {'result':'OK','message':output}
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title=u'Upgrade du client WAPT')

@app.route('/upgrade')
@app.route('/upgrade.json')
@check_ip_source
def upgrade():
    data1 = task_manager.add_task(WaptUpdate()).as_dict()
    data2 = task_manager.add_task(WaptUpgrade()).as_dict()
    data = {'result':'OK','content':[data1,data2]}
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title='Upgrade')

@app.route('/update')
@app.route('/update.json')
@check_ip_source
def update():
    data = task_manager.add_task(WaptUpdate()).as_dict()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title=u'Mise à jour des logiciels installés')

@app.route('/update_status')
@app.route('/update_status.json')
@check_ip_source
def update_status():
    task = WaptUpdateServerStatus()
    data = task_manager.add_task(task).as_dict()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title=task)

@app.route('/longtask')
@app.route('/longtask.json')
@check_ip_source
def longtask():
    data = task_manager.add_task(WaptLongTask(duration=int(request.args.get('duration','60')),raise_error=int(request.args.get('raise_error',0))))
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title='LongTask')

@app.route('/cleanup')
@app.route('/cleanup.json')
@app.route('/clean')
@check_ip_source
def cleanup():
    logger.info("run cleanup")
    #wapt=Wapt(config_filename=app.waptconfig.config_filename)
    data = wapt().cleanup()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title='Cleanup')

@app.route('/install_log')
@app.route('/install_log.json')
@check_ip_source
def install_log():
    logger.info("show install log")
    #wapt=Wapt(config_filename=app.waptconfig.config_filename)
    try:
        packagename = request.args.get('package')
        data = wapt().last_install_log(packagename)
    except Exception as e:
        data = {'result':'ERROR','message': u'{}'.format(e)}
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title='Traces de l''installation de {}'.format(packagename))

@app.route('/enable')
@check_ip_source
def enable():
    logger.info("enable tasks scheduling")
    #wapt=Wapt(config_filename=app.waptconfig.config_filename)
    data = wapt().enable_tasks()
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/disable')
@check_ip_source
def disable():
    logger.info("disable tasks scheduling")
    #wapt=Wapt(config_filename=app.waptconfig.config_filename)
    data = wapt().disable_tasks()
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/register')
@app.route('/register.json')
@check_ip_source
def register():
    logger.info("register computer")
    data = task_manager.add_task(WaptRegisterComputer()).as_dict()

    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title='Enregistrement du poste de travail sur le serveur WAPT')



@app.route('/inventory')
@app.route('/inventory.json')
@check_ip_source
def disable():
    logger.info("Inventory")
    #wapt=Wapt(config_filename=app.waptconfig.config_filename)
    data = wapt().inventory()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title='Inventaire du poste de travail')


@app.route('/install', methods=['GET'])
@app.route('/install.json', methods=['GET'])
@app.route('/install.html', methods=['GET'])
@requires_auth
def install():
    package = request.args.get('package')
    force = int(request.args.get('force','0')) == 1
    data = task_manager.add_task(WaptPackageInstall(package,force=force)).as_dict()

    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('install.html',data=data)

@app.route('/package_download')
@app.route('/package_download.json')
@check_ip_source
def package_download():
    package = request.args.get('package')
    logger.info("download package %s" % package)
    data = task_manager.add_task(WaptDownloadPackage(package)).as_dict()

    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data)

@app.route('/remove.json', methods=['GET'])
@app.route('/remove', methods=['GET'])
@requires_auth
def remove():
    package = request.args.get('package')
    logger.info("remove package %s" % package)
    force=int(request.args.get('force','0'))
    data = task_manager.add_task(WaptPackageRemove(package,force = force)).as_dict()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('install.html',data=data)

"""
@app.route('/static/<path:filename>', methods=['GET'])
def static(filename):
    return send_file(open(os.path.join(wapt_root_dir,'static',filename),'rb'),as_attachment=False)
"""

@app.route('/', methods=['GET'])
def index():
    host_info = setuphelpers.host_info()
    data = dict(html=html,
            host_info=host_info,
            wapt=wapt(),
            wapt_info=wapt().wapt_status(),
            update_status=wapt().get_last_update_status())
    if request.args.get('format','html')=='json'  or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('index.html',**data)


@app.route('/login', methods=['GET', 'POST'])
@check_ip_source
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != 'admin' or \
                request.form['password'] != 'secret':
            error = 'Invalid credentials'
        else:
            flash('You were successfully logged in')
            return redirect(url_for('index'))
    return render_template('login.html', error=error)

@app.route('/tasks')
@app.route('/tasks.json')
@check_ip_source
def tasks():
    data = task_manager.tasks_status()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('tasks.html',data=data)

@app.route('/task')
@app.route('/task.json')
@app.route('/task.html')
@check_ip_source
def task():
    id = int(request.args['id'])
    tasks = task_manager.tasks_status()
    all_tasks = tasks['done']+tasks['pending']+tasks['errors']
    if tasks['running']:
        all_tasks.append(tasks['running'])
    task = [task for task in all_tasks if task and task['order'] == id]
    if task:
        task = task[0]
    else:
        task = {}
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(task), mimetype='application/json')
    else:
        return render_template('task.html',task=task)

@app.route('/cancel_all_tasks')
@app.route('/cancel_all_tasks.html')
@app.route('/cancel_all_tasks.json')
@check_ip_source
def cancel_all_tasks():
    data = task_manager.cancel_all_tasks()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data)

@app.route('/cancel_running_task')
@app.route('/cancel_running_task.json')
@check_ip_source
def cancel_all_tasks():
    data = task_manager.cancel_running_task()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data)


def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    return app.waptconfig.wapt_user == username and app.waptconfig.wapt_password == hashlib.sha256(password).hexdigest()

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})


class EventsPrinter:
    '''EventsPrinter class which serves to emulates a file object and logs
       whatever it gets sent to a briadcast object at the INFO level.'''
    def __init__(self,events,logs):
        '''Grabs the specific brodcaster to use for printing.'''
        self.events = events
        self.logs = logs

    def write(self, text):
        '''Logs written output to listeners'''
        if text and text <> '\n':
            if self.events:
                self.events.send_multipart(['PRINT',u'{}'.format(text).encode('utf8')])
            self.logs.append(text)

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
    def __init__(self):
        self.wapt = None
        self.priority = 100
        self.order = 0
        self.external_pids = []
        self.create_date = datetime.datetime.now()
        self.start_date = None
        self.finish_date = None
        self.logs = []
        self.result = None
        self.summary = ""
        # from 0 to 100%
        self.progress = None
        self.notify_server_on_start = True
        self.notify_server_on_finish = True

    def update_status(self,status):
        """Update runstatus in database and send PROGRESS event"""
        if self.wapt:
            self.wapt.runstatus = status
            msg = {}
            msg['description'] = u'{}'.format(self)
            msg['runstatus'] = status
            if self.progress is not None:
                msg['progress'] = self.progress
            self.wapt.events.send_multipart(["TASKS",'PROGRESS',common.jsondump(msg)])

    def can_run(self,explain=False):
        """Return True if all the requirements for the task are met
        (ex. install can start if package+depencies are downloaded)"""
        return True

    def _run(self):
        """method to override in descendant to do the catual work"""
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
            self._run()
        finally:
            self.finish_date = datetime.datetime.now()

    def kill(self):
        """if task has been started, kill the task (ex: kill the external processes"""
        if self.external_pids:
            for pid in self.external_pids:
                logger.debug('Killing process with pid {}'.format(pid))
        if self.wapt:
            self.wapt.task_is_cancelled.set()

    def run_external(self,*args,**kwargs):
        """Run an external process, register pid in current task to be able to kill it"""
        result = setuphelpers.run(*args,**kwargs)

    def __str__(self):
        return u"{classname} {order} created {create_date} started:{start_date} finished:{finish_date} ".format(**self.as_dict())

    def as_dict(self):
        return dict(
            classname=self.__class__.__name__,
            priority = self.priority,
            order=self.order,
            create_date = self.create_date and self.create_date.isoformat(),
            start_date = self.start_date and self.start_date.isoformat(),
            finish_date = self.finish_date and self.finish_date.isoformat(),
            logs = self.logs,
            result = self.result,
            summary = self.summary,
            progress = self.progress,
            description = u"{}".format(self),
            )

    def as_json(self):
        return json.dumps(self.as_dict(),indent=True)

    def __repr__(self):
        return u"<{}>".format(self)

    def __cmp__(self,other):
        return cmp((self.priority,self.order),(other.priority,other.order))

    def same_action(self,other):
        return self.__class__ == other.__class__

class WaptNetworkReconfig(WaptTask):
    def __init__(self):
        super(WaptNetworkReconfig,self).__init__()
        self.priority = 0
        self.notify_server_on_start = False
        self.notify_server_on_finish = True

    def _run(self):
        self.wapt.network_reconfigure()
        logger.info('Reloading confg file')
        waptconfig.load()

    def __str__(self):
        return u"Reconfiguration accès réseau"

class WaptUpdate(WaptTask):
    def __init__(self):
        super(WaptUpdate,self).__init__()
        self.priority = 10
        self.notify_server_on_start = False
        self.notify_server_on_finish = True

    def _run(self):
        self.result = self.wapt.update()
        """result: {
            count: 176,
            added: [ ],
            repos: [
            "http://srvwapt.tranquilit.local/wapt",
            "http://srvwapt.tranquilit.local/wapt-host"
            ],
            upgrades: [ ],
            date: "2014-02-28T19:30:35.829000",
            removed: [ ]
        },"""
        s = []
        if len(self.result['added'])>0:
            s.append(u'{} nouveaux paquets'.format(len(self.result['added'])))
        if len(self.result['removed'])>0:
            s.append(u'{} paquets enlevés'.format(len(self.result['added'])))
        s.append(u'{} paquets dans les dépôts'.format(self.result['count']))
        s.append(u'')
        if len(self.result['upgrades'])>0:
            s.append(u'Paquets à mettre à jour : {}'.format(self.result['upgrades']))

        self.summary = u'\n'.join(s)

    def __str__(self):
        return u"Mise à jour des paquets disponibles"

class WaptUpgrade(WaptTask):
    def __init__(self):
        super(WaptUpgrade,self).__init__()

    def _run(self):
        def cjoin(l):
            return u','.join([u"%s" % (p[1].asrequirement(),) for p in l])

        self.result = self.wapt.upgrade()
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
        all_install = self.result['install']
        if self.result['additional']:
            all_install.extend(self.result['additional'])
        self.summary = u"""\
            Installés : {install}
            Mis à jour : {upgrade}
            Déjà à jour :{skipped}
            Erreurs : {errors}""".format(
            install = cjoin(all_install),
            upgrade = cjoin(self.result['upgrade']),
            skipped = cjoin(self.result['skipped']),
            errors = cjoin(self.result['errors']),
        )


    def __str__(self):
        return u'Mise à jour des paquets installés sur la machine'

class WaptUpdateServerStatus(WaptTask):
    """Send workstation status to server"""
    def __init__(self):
        super(WaptUpdateServerStatus,self).__init__()
        self.priority = 10
        self.notify_server_on_start = False
        self.notify_server_on_finish = False

    def _run(self):
        if self.wapt.wapt_server:
            try:
                self.result = self.wapt.update_server_status()
                self.summary = u'Le WAPT Server a été informé'
            except Exception as e:
                self.result = {}
                self.summary = u"Erreur lors de l'envoi vers le serveur : {}".format(e)
        else:
            self.result = {}
            self.summary = u'WAPT Server is not defined'

    def __str__(self):
        return u"Informer le serveur de l'état du poste de travail"

class WaptRegisterComputer(WaptTask):
    """Send workstation status to server"""
    def __init__(self):
        super(WaptRegisterComputer,self).__init__()
        self.priority = 10
        self.notify_server_on_start = False
        self.notify_server_on_finish = False

    def _run(self):
        if self.wapt.wapt_server:
            try:
                self.result = self.wapt.register_computer()
                self.summary = u"L'inventaire a été envoyé au serveur WAPT"
            except Exception as e:
                self.result = {}
                self.summary = u"Erreur lors de l'envoi de l'inventaire vers le serveur : {}".format(e)
        else:
            self.result = {}
            self.summary = u'WAPT Server is not defined'

    def __str__(self):
        return u"Informer le serveur de l'inventaire du poste de travail"

class WaptLongTask(WaptTask):
    """Test action for debug purpose"""
    def __init__(self,duration=60,raise_error=False):
        super(WaptLongTask,self).__init__()
        self.duration = duration
        self.raise_error = raise_error

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
            raise Exception('raising an error for Test WaptLongTask')

    def same_action(self,other):
        return False

    def __str__(self):
        return u"Test long running task of {}s".format(self.duration)

class WaptDownloadPackage(WaptTask):
    def __init__(self,packagename,usecache=False):
        super(WaptDownloadPackage,self).__init__()
        self.packagename = packagename
        self.usecache = usecache

    def printhook(self,received,total,speed,url):
        self.wapt.check_cancelled()
        stat = u'%i / %i (%.0f%%) (%.0f KB/s)\r' % (received,total,100.0*received/total, speed)
        self.progress = 100.0*received/total
        self.update_status('Downloading %s : %s' % (url,stat))

    def _run(self):
        self.result = self.wapt.download_packages(self.packagename,usecache=self.usecache,printhook=self.printhook)

    def as_dict(self):
        d = WaptTask.as_dict(self)
        d.update(
            dict(
                packagename = self.packagename,
                usecache = self.usecache,
                )
            )
        return d

    def __str__(self):
        return u"Téléchargement de {packagename} (tâche #{order})".format(classname=self.__class__.__name__,order=self.order,packagename=self.packagename)

    def same_action(self,other):
        return (self.__class__ == other.__class__) and (self.packagename == other.packagename)


class WaptPackageInstall(WaptTask):
    def __init__(self,packagename,force=False):
        super(WaptPackageInstall,self).__init__()
        self.packagename = packagename
        self.force = force
        self.package = None

    def _run(self):
        self.result = self.wapt.install(self.packagename,force = self.force)
        if self.result['errors']:
            raise Exception('Error during install of {}'.format(self.result['errors']))

    def as_dict(self):
        d = WaptTask.as_dict(self)
        d.update(
            dict(
                packagename = self.packagename,
                force = self.force)
            )
        return d

    def __str__(self):
        return u"Installation de {packagename} (tâche #{order})".format(classname=self.__class__.__name__,order=self.order,packagename=self.packagename)

    def same_action(self,other):
        return (self.__class__ == other.__class__) and (self.packagename == other.packagename)

class WaptPackageRemove(WaptPackageInstall):
    def __init__(self,packagename,force=False):
        super(WaptPackageRemove,self).__init__(packagename=packagename,force=force)

    def _run(self):
        def cjoin(l):
            return u','.join([u'%s'%p for p in l])

        self.result = self.wapt.remove(self.packagename,force=self.force)
        self.summary = u"""\
            Enlevés : {removed}
            Erreurs : {errors}""".format(
                removed = cjoin(self.result['removed']),
                errors = cjoin(self.result['errors']),
                )

    def __str__(self):
        return u"Désinstallation de {packagename} (tâche #{order})".format(classname=self.__class__.__name__,order=self.order,packagename=self.packagename)

class WaptTaskManager(threading.Thread):
    def __init__(self,config_filename = 'c:/wapt/wapt-get.ini'):
        threading.Thread.__init__(self)

        self.status_lock = threading.RLock()

        self.wapt=Wapt(config_filename=config_filename)

        self.tasks = []

        self.tasks_queue = Queue.PriorityQueue()
        self.tasks_counter = 0

        self.tasks_done = []
        self.tasks_error = []
        self.tasks_cancelled = []

        # init zeromq events broadcast
        zmq_context = zmq.Context()
        event_queue = zmq_context.socket(zmq.PUB)

        # start event broadcasting
        event_queue.bind("tcp://127.0.0.1:5000")

        # add logger through zmq events
        handler = PUBHandler(event_queue)
        logger.addHandler(handler)

        self.events = event_queue
        self.wapt.events = self.events

        self.running_task = None
        logger.info(u'Wapt tasks management initialized with {} configuration'.format(config_filename))

    def update_runstatus(self,status):
        # update database with new runstatus
        self.wapt.runstatus = status
        # dispatch event to listening parties
        msg = json.dumps(self.wapt.get_last_update_status())
        if self.events:
            self.wapt.events.send_multipart(["STATUS",msg])

    def update_server_status(self):
        if self.wapt.wapt_server:
            try:
                result = self.wapt.update_server_status()
                if result['uuid']:
                    self.last_update_server_date = datetime.datetime.now()
            except Exception as e:
                logger.warning('Unable to update server status: %s' % e)

    def broadcast_tasks_status(self,topic,content):
        """topic : ADD START FINISH CANCEL ERROR """
        # ignorr brodcast for this..
        if isinstance(content,WaptUpdateServerStatus):
            return
        if self.events:
            if not isinstance(content,str):
                if isinstance(content,unicode):
                    content = content.encode('utf8')
                else:
                    content = common.jsondump(content)
            if content:
                self.wapt.events.send_multipart(["TASKS",topic,content])

    def add_task(self,task):
        """Adds a new WaptTask for processing"""
        with self.status_lock:
            same = [ pending for pending in self.tasks_queue.queue if pending.same_action(task)]
            # not already in pending  actions...
            if not same:
                self.broadcast_tasks_status('ADD',task)
                task.wapt = self.wapt

                self.tasks_counter += 1
                task.order = self.tasks_counter

                self.tasks_queue.put(task)
                self.tasks.append(task)
                return task
            else:
                return same[0]

    def run(self):
        """Queue management, event processing"""
        pythoncom.CoInitialize()
        self.start_network_monitoring()
        logger.debug("Wapt tasks queue started")
        while True:
            try:
                # check tasks queue
                self.running_task = self.tasks_queue.get(timeout=10)
                try:
                    # don't send update_run status fir udapstatus itself...
                    self.broadcast_tasks_status('START',self.running_task)
                    if self.running_task.notify_server_on_start:
                        self.update_runstatus(u'En cours: {description}'.format(description=self.running_task) )
                        self.update_server_status()
                    try:
                        self.running_task.run()
                        if self.running_task:
                            self.tasks_done.append(self.running_task)
                            self.broadcast_tasks_status('FINISH',self.running_task)
                            if self.running_task.notify_server_on_finish:
                                self.update_runstatus(u'Terminé: {description}'.format(description=self.running_task) )
                                self.update_server_status()

                    except common.EWaptCancelled as e:
                        if self.running_task:
                            self.running_task.logs.append(u"{}".format(e))
                            self.tasks_cancelled.append(self.running_task)
                            self.broadcast_tasks_status('CANCEL',self.running_task.as_dict())
                    except Exception as e:
                        if self.running_task:
                            self.running_task.logs.append(u"{}".format(e))
                            self.tasks_error.append(self.running_task)
                            self.broadcast_tasks_status('ERROR',self.running_task.as_dict())
                        logger.critical(u"%s"%e)
                finally:
                    self.tasks_queue.task_done()
                    # send workstation status
                    #if not isinstance(self.running_task,WaptUpdateServerStatus) and self.wapt.wapt_server:
                    #    self.add_task(WaptUpdateServerStatus())

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
                logger.debug(u"{} i'm still alive... but nothing to do".format(datetime.datetime.now()))

    def tasks_status(self):
        """Returns list of pending, error, done tasks, and current running one"""
        try:
            with self.status_lock:
                return dict(
                    running=self.running_task and self.running_task.as_dict(),
                    pending=[task.as_dict() for task in sorted(self.tasks_queue.queue)],
                    done = [task.as_dict() for task in self.tasks_done],
                    cancelled = [ task.as_dict() for task in self.tasks_cancelled],
                    errors = [ task.as_dict() for task in self.tasks_error],
                    )
        except Exception as e:
            return u"Error : tasks list locked : {}".format(e)


    def cancel_running_task(self):
        """Cancel running task. Returns cancelled task"""
        try:
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
                        self.broadcast_tasks_status('CANCEL',[cancelled])
                    return cancelled
                else:
                    return None

        except Exception as e:
            return u"Error : tasks list locked : {}".format(e)

    def cancel_all_tasks(self):
        """Cancel running and pending tasks. Returns list of cancelled tasks"""
        try:
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
                self.tasks_cancelled.extend(cancelled)
                self.broadcast_tasks_status('CANCEL',cancelled)
                return cancelled

        except Exception as e:
            return u"Error : tasks list locked : {}".format(e)

    def start_network_monitoring(self):
        def addr_change(wapt):
            while True:
                print('waiting for addr change')
                #ctypes.windll.iphlpapi.NotifyRouteChange(0, 0)
                ctypes.windll.iphlpapi.NotifyAddrChange(0, 0)
                print('addr changed !')
                wapt.add_task(WaptNetworkReconfig())

        logger.debug("Wapt network address monitoring started")
        nm = threading.Thread(target=addr_change,args=(self,))
        nm.daemon = True
        nm.start()
        logger.debug("Wapt network address monitoring stopped")


    def network_up(self):
        with self.status_lock:
            logger.warning('Network is UP')
            try:
                #self.wapt.update_server_status()
                pass
            except Exception as e:
                logger.warning(u'Mise à jour du status sur le serveur impossible : %s'%e)

    def network_down(self):
        with self.status_lock:
            logger.warning('Network is DOWN')

    def __str__(self):
        return "\n".join(self.tasks_status())

def install_service():
    """Setup waptservice as a windows Service managed by nssm
    >>> install_service()
    """

    # http
    check_open_port(waptconfig.waptservice_port)
    # https
    check_open_port(waptconfig.waptservice_port+1)

    from setuphelpers import registry_set,REG_DWORD,REG_EXPAND_SZ,REG_MULTI_SZ,REG_SZ
    datatypes = {
        'dword':REG_DWORD,
        'sz':REG_SZ,
        'expand_sz':REG_EXPAND_SZ,
        'multi_sz':REG_MULTI_SZ,
    }

    if setuphelpers.service_installed('waptservice'):
        if setuphelpers.service_is_running('waptservice'):
            setuphelpers.run('sc stop waptservice')
        setuphelpers.run('sc delete waptservice')

    if setuphelpers.iswin64():
        nssm = os.path.join(wapt_root_dir,'waptservice','win64','nssm.exe')
    else:
        nssm = os.path.join(wapt_root_dir,'waptservice','win32','nssm.exe')

    setuphelpers.run('"{nssm}" install WAPTService "{waptpython}" "{waptservicepy}"'.format(
        waptpython = os.path.abspath(os.path.join(wapt_root_dir,'waptpython.exe')),
        nssm = nssm,
        waptservicepy = os.path.abspath(__file__),
     ))

    params = {
        "DisplayName":"sz:WAPT Service",
        "AppStdout":r"expand_sz:{}".format(os.path.join(waptconfig.log_directory,'waptservice.log')),
        "Parameters\\AppStderr":r"expand_sz:{}".format(os.path.join(waptconfig.log_directory,'waptservice.log')),
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


if __name__ == "__main__":
    if len(sys.argv)>1 and sys.argv[1] == 'doctest':
        import doctest
        sys.exit(doctest.testmod())

    if len(sys.argv)>1 and sys.argv[1] == 'install':
        install_service()
        sys.exit(0)

    # starts one WaptTasksManager
    task_manager = WaptTaskManager(config_filename = waptconfig.config_filename)
    task_manager.daemon = True
    task_manager.start()

    #network_monitor = NetworkManager(connected_cb = task_manager.network_up,disconnected_cb=task_manager.network_down)
    #network_monitor_thread = threading.Thread(target=network_monitor.run)
    #network_monitor_thread.start()

    debug=False
    if debug==True:
        app.run(host='0.0.0.0',port=waptconfig.waptservice_port ,debug=False)
        logger.info("exiting")
    else:
        #logger.setLevel(logging.DEBUG)
        server = Rocket(
            [('0.0.0.0', waptconfig.waptservice_port),
             ('0.0.0.0', waptconfig.waptservice_port+1, r'waptservice\ssl\waptservice.pem', r'waptservice\ssl\waptservice.crt')],
             'wsgi', {"wsgi_app":app})

        try:
            logger.info("starting waptservice")
            server.start()
        except KeyboardInterrupt:
            logger.info("stopping waptservice")
            server.stop()
