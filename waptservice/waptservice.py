# -*- coding: UTF-8 -*-

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

from network_manager import NetworkManager

from werkzeug.utils import html

import gc
import datetime
import dateutil.parser



try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.append(os.path.join(wapt_root_dir))
sys.path.append(os.path.join(wapt_root_dir,'lib'))
sys.path.append(os.path.join(wapt_root_dir,'waptservice'))
sys.path.append(os.path.join(wapt_root_dir,'lib','site-packages'))

import common
import setuphelpers
from common import Wapt

__version__ = "0.8.8"

config = ConfigParser.RawConfigParser()

# log
log_directory = os.path.join(wapt_root_dir,'log')
if not os.path.exists(log_directory):
    os.mkdir(log_directory)

logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

config_filename = os.path.join(wapt_root_dir,'wapt-get.ini')

if os.path.exists(config_filename):
    config.read(config_filename)
else:
    raise Exception("FATAL. Couldn't open config file : " + config_filename)

wapt_user = ""
wapt_password = ""

# maximum nb of tasks in wapt task manager
MAX_HISTORY = 30

def format_isodate(isodate):
    """Pretty format iso date like : 2014-01-21T17:36:15.652000
        >>> format_isodate('2014-01-21T17:36:15.652000')
        '21/01/2014 17:36:15'
    """
    return dateutil.parser.parse(isodate).strftime("%d/%m/%Y %H:%M:%S")

def setloglevel(logger,loglevel):
    """set loglevel as string"""
    if loglevel in ('debug','warning','info','error','critical'):
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % loglevel)
        logger.setLevel(numeric_level)

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

# lecture configuration
if config.has_section('global'):
    if config.has_option('global', 'wapt_user'):
        wapt_user = config.get('global', 'wapt_user')
    else:
        wapt_user='admin'

    if config.has_option('global','waptservice_password'):
        wapt_password = config.get('global', 'waptservice_password')
    else:
        logger.warning("WARNING : no password set, using default password")
        wapt_password='5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8' # = password

    if config.has_option('global','waptservice_port'):
        waptservice_port = int(config.get('global','waptservice_port'))
    else:
        waptservice_port=8088

    if config.has_option('global','dbdir'):
        dbpath = os.path.join(config.get('global','dbdir'),'waptdb.sqlite')
    else:
        dbpath = os.path.join(wapt_root_dir,'db','waptdb.sqlite')

    if config.has_option('global','loglevel'):
        loglevel = config.get('global','loglevel')
        setloglevel(logger,loglevel)
    else:
        setloglevel(logger,'warning')

else:
    raise Exception ("FATAL, configuration file " + config_filename + " has no section [global]. Please check Waptserver documentation")

def check_open_port():
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
                logger.info("Port not opening, opening port")
                setuphelpers.run_notfatal("""netsh.exe firewall add portopening name="waptservice 8088" port=8088 protocol=TCP""")
            else:
                logger.info("port already opened, skipping firewall configuration")
    else:

        if  win32serviceutil.QueryServiceStatus( 'MpsSvc', None)[1]==win32service.SERVICE_RUNNING:
            logger.info("Firewall started, checking for port openning...")
            if 'waptservice' not in setuphelpers.run_notfatal('netsh advfirewall firewall show rule name="waptservice 8088"'):
                logger.info("No port opened for waptservice, opening port")
                #win Vista and higher
                setuphelpers.run_notfatal("""netsh advfirewall firewall add rule name="waptservice 8088" dir=in action=allow protocol=TCP localport=8088""")
            else:
                logger.info("port already opened, skipping firewall configuration")

check_open_port()

def get_authorized_callers_ip():
    ips = ['127.0.0.1']
    wapt = Wapt(config_filename=config_filename)
    #ips.append(socket.gethostbyname( urlparse(wapt.find_wapt_server()).hostname))
    if wapt.wapt_server:
        try:
            ips.append(socket.gethostbyname( urlparse(wapt.wapt_server).hostname))
        except socket.gaierror as e:
            # no network connection to resolve hostname
            pass
    return ips

authorized_callers_ip = get_authorized_callers_ip()
app = Flask(__name__)
app.config['PROPAGATE_EXCEPTIONS'] = True

app.jinja_env.filters['beautify'] = beautify


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth:
            logging.info('no credential given')
            return authenticate()

        logging.info("authenticating : %s" % auth.username)

        if not check_auth(auth.username, auth.password):
            return authenticate()

        if not  request.remote_addr == '127.0.0.1':
            return authenticate()

        logging.info("user %s authenticated" % auth.username)

        return f(*args, **kwargs)

    return decorated

def check_ip_source(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not request.remote_addr in authorized_callers_ip:
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route('/status')
@check_ip_source
def status():
    rows = []
    with sqlite3.connect(dbpath) as con:
        try:
            con.row_factory=sqlite3.Row
            query = '''select s.package,s.version,s.install_date,s.install_status,s.install_output,
                                 (select GROUP_CONCAT(p.version," | ") from wapt_package p where p.package=s.package) as repo_version,explicit_by as install_par
                                 from wapt_localstatus s
                                 order by s.package'''
            cur = con.cursor()
            cur.execute(query)
            rows = [ dict(x) for x in cur.fetchall() ]
        except lite.Error, e:
            logger.critical("*********** Error %s:" % e.args[0])
    if request.args.get('format','html')=='json':
        return Response(common.jsondump(rows), mimetype='application/json')
    else:
        return render_template('status.html',packages=rows,format_isodate=format_isodate,Version=setuphelpers.Version)

@app.route('/list')
@app.route('/packages')
@app.route('/packages.json')
@check_ip_source
def all_packages():
    with sqlite3.connect(dbpath) as con:
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
def package_icon():
    package = request.args.get('package')
    icon_local_cache = os.path.join(wapt_root_dir,'cache','icons')
    if not os.path.isdir(icon_local_cache):
        os.makedirs(icon_local_cache)
    wapt=[]
    #repo_url='http://wapt/wapt'
    #proxies = []

    def get_icon(package):
        """Get icon from local cache or remote wapt directory, returns local filename"""
        icon_local_filename = os.path.join(icon_local_cache,package+'.png')
        if not os.path.isfile(icon_local_filename) or os.path.getsize(icon_local_filename)<10:
            if not wapt:
                wapt.append(Wapt(config_filename=config_filename))
            proxies = wapt[0].proxies
            repo_url = wapt[0].repositories[0].repo_url

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
def package_details():
    wapt=Wapt(config_filename=config_filename)
    package = request.args.get('package')
    wapt=Wapt(config_filename=config_filename)
    try:
        data = wapt.is_available(package)
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
    with sqlite3.connect(dbpath) as con:
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
@check_ip_source
def get_checkupgrades():
    with sqlite3.connect(dbpath) as con:
        con.row_factory=sqlite3.Row
        data = ""
        try:
            query ="""select * from wapt_params where name="last_update_status" limit 1"""
            cur = con.cursor()
            cur.execute(query)
            data = json.loads(cur.fetchone()['value'])
        except Exception as e :
            logger.critical("*********** error %s"  % (e,))
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/waptupgrade')
@check_ip_source
def waptupgrade():
    from setuphelpers import run
    output = run('"%s" %s' % (os.path.join(wapt_root_dir,'wapt-get.exe'),'waptupgrade'))
    return Response(common.jsondump({'result':'OK','message':output}), mimetype='application/json')

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
@app.route('/updatebg')
@check_ip_source
def update():
    data = task_manager.add_task(WaptUpdate()).as_dict()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title='Update')

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
@requires_auth
def cleanup():
    logger.info("run cleanup")
    wapt=Wapt(config_filename=config_filename)
    data = wapt.cleanup()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data,title='Cleanup')

@app.route('/enable')
@requires_auth
def enable():
    logger.info("enable tasks scheduling")
    wapt=Wapt(config_filename=config_filename)
    data = wapt.enable_tasks()
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/disable')
@requires_auth
def disable():
    logger.info("disable tasks scheduling")
    wapt=Wapt(config_filename=config_filename)
    data = wapt.disable_tasks()
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
        return render_template('register.html',data=data)


@app.route('/install', methods=['GET'])
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
def package_download():
    package = request.args.get('package')
    logger.info("download package %s" % package)
    data = task_manager.add_task(WaptDownloadPackage(package)).as_dict()

    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('default.html',data=data)

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
        return render_template('install.html',**data)

"""
@app.route('/static/<path:filename>', methods=['GET'])
def static(filename):
    return send_file(open(os.path.join(wapt_root_dir,'static',filename),'rb'),as_attachment=False)
"""

@app.route('/', methods=['GET'])
def index():
    wapt = Wapt(config_filename=config_filename)
    host_info = setuphelpers.host_info()
    data = dict(html=html,
            host_info=host_info,
            wapt=wapt,
            wapt_info=wapt.wapt_status(),
            update_status=wapt.get_last_update_status())
    if request.args.get('format','html')=='json'  or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('index.html',**data)


@app.route('/login', methods=['GET', 'POST'])
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
def tasks():
    data = task_manager.tasks_status()
    if request.args.get('format','html')=='json' or request.path.endswith('.json'):
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('tasks.html',data=data)

@app.route('/task')
@app.route('/task.json')
@app.route('/task.html')
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
def cancel_all_tasks():
    return Response(common.jsondump(task_manager.cancel_all_tasks()), mimetype='application/json')

def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    return wapt_user == username and wapt_password == hashlib.sha256(password).hexdigest()

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

    def update_status(self,status):
        self.wapt.runstatus = status
        msg = json.dumps(self.wapt.get_last_update_status())
        if self.progress is not None:
            msg['progress'] = self.progress
        self.wapt.events.send(msg)

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

class WaptUpdate(WaptTask):
    def __init__(self):
        super(WaptUpdate,self).__init__()
        self.priority = 10

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
        cjoin = u','.join
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
        """
        if self.result['additional']:
            all_install.extend(self.result['additional'])
        """
        self.summary = u"""\
            Installés : {install}
            Mis à jour : {upgrade}
            Déjà à jour :{skipped}
            Erreurs : {errors}""".format(**self.result)
        """
            install = cjoin(all_install),
            upgrade = cjoin(self.result['upgrade']),
            skipped = cjoin(self.result['skipped']),
            errors = cjoin(self.result['errors']),
        )
        """

    def __str__(self):
        return u'Mise à jour des paquets installés sur la machine'

class WaptUpdateServerStatus(WaptTask):
    """Send workstation status to server"""
    def __init__(self):
        super(WaptUpdateServerStatus,self).__init__()
        self.priority = 10

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
        for i in range(self.duration):
            if self.wapt:
                self.wapt.check_cancelled()
            print u"Step {}".format(i)
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
        #print stat,
        self.runstatus='Downloading %s : %s' % (url,stat)
        self.progress = 100.0*received/total

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
        self.result = self.wapt.remove(self.packagename,force=self.force)

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

        import pythoncom
        pythoncom.CoInitialize()

        logger.debug("Wapt tasks queue started")
        while True:
            try:
                self.running_task = self.tasks_queue.get(timeout=10)
                try:
                    self.update_runstatus(u'Processing {description}'.format(description=self.running_task) )
                    self.broadcast_tasks_status('START',self.running_task)
                    try:
                        self.running_task.run()
                        self.tasks_done.append(self.running_task)
                        self.broadcast_tasks_status('FINISH',self.running_task)

                    except common.EWaptCancelled as e:
                        if self.running_task:
                            self.running_task.logs.append(u"{}".format(e))
                            self.tasks_cancelled.append(self.running_task)
                            self.broadcast_tasks_status('CANCEL',self.running_task)
                    except Exception as e:
                        if self.running_task:
                            self.running_task.logs.append(u"{}".format(e))
                            self.tasks_error.append(self.running_task)
                            self.broadcast_tasks_status('ERROR',self.running_task)
                        logger.critical(e)
                finally:
                    self.tasks_queue.task_done()
                    # send workstation status
                    if not isinstance(self.running_task,WaptUpdateServerStatus) and self.wapt.wapt_server:
                        self.add_task(WaptUpdateServerStatus())

                    self.running_task = None
                    # trim history lists
                    if len(self.tasks_cancelled)>MAX_HISTORY:
                        del self.tasks_cancelled[:len(self.tasks_cancelled)-MAX_HISTORY]
                    if len(self.tasks_done)>MAX_HISTORY:
                        del self.tasks_done[:len(self.tasks_done)-MAX_HISTORY]
                    if len(self.tasks_error)>MAX_HISTORY:
                        del self.tasks_error[:len(self.tasks_error)-MAX_HISTORY]


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

    def cancel_all_tasks(self):
        """Returns list of pending, error, done tasks, and current running one"""
        try:
            with self.status_lock:
                cancelled = []
                while not self.tasks_queue.empty():
                     cancelled.append(self.tasks_queue.get())
                self.tasks_cancelled.extend(cancelled)
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
                self.broadcast_tasks_status('CANCEL',cancelled)
                return dict(
                    running=self.running_task and self.running_task.as_dict(),
                    pending=[task for task in sorted(self.tasks_queue.queue)],
                    done = self.tasks_done[:],
                    cancelled = self.tasks_cancelled[:],
                    errors = self.tasks_error[:],
                    )
        except Exception as e:
            return u"Error : tasks list locked : {}".format(e)

    def network_up(self):
        with self.status_lock:
            logger.info('Network is UP')

    def network_down(self):
        with self.status_lock:
            logger.warning('Network is DOWN')

    def __str__(self):
        return "\n".join(self.tasks_status())

def install_service():
    import setuphelpers
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

    basedir = os.path.abspath(os.path.dirname(__file__))
    if setuphelpers.iswin64():
        nssm = os.path.join(basedir,'win64','nssm.exe')
    else:
        nssm = os.path.join(basedir,'win32','nssm.exe')

    setuphelpers.run('"{nssm}" install WAPTService "{waptpython}" "{waptservicepy}"'.format(
        waptpython = os.path.abspath(os.path.join(basedir,'..','waptpython.exe')),
        nssm = nssm,
        waptservicepy = os.path.abspath(__file__),
     ))

    params = {
        "DisplayName":"sz:WAPT Service",
        "AppStdout":r"expand_sz:{}".format(os.path.join(log_directory,'waptservice.log')),
        "Parameters\\AppStderr":r"expand_sz:{}".format(os.path.join(log_directory,'waptservice.log')),
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
    task_manager = WaptTaskManager(config_filename = config_filename)
    task_manager.daemon = True
    task_manager.start()

    network_monitor = NetworkManager(connected_cb = task_manager.network_up,disconnected_cb=task_manager.network_down)
    network_monitor_thread = threading.Thread(target=network_monitor.register)
    network_monitor_thread.start()

    debug=False
    if debug==True:
        app.run(host='0.0.0.0',port=waptservice_port,debug=False)
        logger.info("exiting")
    else:
        server = Rocket(
            [('0.0.0.0', waptservice_port),
             ('0.0.0.0', waptservice_port+1, r'ssl\waptservice.pem', r'ssl\waptservice.crt')],
             'wsgi', {"wsgi_app":app})

        try:
            logger.info("starting waptserver")
            server.start()
        except KeyboardInterrupt:
            logger.info("stopping waptserver")
            server.stop()

