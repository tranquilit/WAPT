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
import json
from rocket import Rocket
from flask import request, Flask,Response, send_from_directory, send_file, session, g, redirect, url_for, abort, render_template, flash
import requests
import StringIO

from werkzeug.utils import html

import gc
import datetime
import dateutil.parser

wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
sys.path.append(os.path.join(wapt_root_dir))
sys.path.append(os.path.join(wapt_root_dir,'lib'))
sys.path.append(os.path.join(wapt_root_dir,'waptservice'))
sys.path.append(os.path.join(wapt_root_dir,'lib','site-packages'))

import common
import setuphelpers
from common import Wapt

__version__ = "0.8.7"

config = ConfigParser.RawConfigParser()

# log
log_directory = os.path.join(wapt_root_dir,'log')
if not os.path.exists(log_directory):
    os.mkdir(log_directory)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

config_file = os.path.join(wapt_root_dir,'wapt-get.ini')

if os.path.exists(config_file):
    config.read(config_file)
else:
    raise Exception("FATAL. Couldn't open config file : " + config_file)

wapt_user = ""
wapt_password = ""

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
    raise Exception ("FATAL, configuration file " + config_file + " has no section [global]. Please check Waptserver documentation")

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
    wapt = Wapt(config_filename=config_file)
    #ips.append(socket.gethostbyname( urlparse(wapt.find_wapt_server()).hostname))
    if wapt.wapt_server:
        ips.append(socket.gethostbyname( urlparse(wapt.wapt_server).hostname))
    return ips

authorized_callers_ip = get_authorized_callers_ip()

app = Flask(__name__)
app.config['PROPAGATE_EXCEPTIONS'] = True

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
@check_ip_source
def list():
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
    if request.args.get('format','html')=='json':
        return Response(common.jsondump(rows), mimetype='application/json')
    else:
        return render_template('list.html',packages=rows,format_isodate=format_isodate,Version=setuphelpers.Version)

@app.route('/package_icon')
def package_icon():
    package = request.args.get('package')
    icon_local_cache = os.path.join(wapt_root_dir,'cache','icons')
    wapt=[]
    #repo_url='http://wapt/wapt'
    #proxies = []

    def get_icon(package):
        """Get icon from local cache or remote wapt directory, returns local filename"""
        icon_local_filename = os.path.join(icon_local_cache,package+'.png')
        if not os.path.isfile(icon_local_filename) or os.path.getsize(icon_local_filename)<10:
            if not wapt:
                wapt.append(Wapt(config_filename=config_file))
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
    wapt=Wapt(config_filename=config_file)
    package = request.args.get('package')
    wapt=Wapt(config_filename=config_file)
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
    print "run waptupgrade"
    output = run('"%s" %s' % (os.path.join(wapt_root_dir,'wapt-get.exe'),'waptupgrade'))
    return Response(common.jsondump({'result':'OK','message':output}), mimetype='application/json')

@app.route('/upgrade')
@check_ip_source
def upgrade():
    print "run upgrade"
    def background_upgrade(config_file):
        logger.info("************** Launch upgrade***********************")
        wapt=Wapt(config_filename=config_file)
        wapt.update()
        wapt.upgrade()
        wapt.update_server_status()
        logger.info("************** End upgrade *************************")
        del wapt
        gc.collect()

    thread.start_new_thread(background_upgrade,(config_file,))
    return Response(common.jsondump({'result':'OK'}), mimetype='application/json')

@app.route('/update')
@app.route('/updatebg')
@check_ip_source
def update():
    print "run update"
    def background_update(config_file):
        wapt=Wapt(config_filename=config_file)
        wapt.update()
        del wapt
        gc.collect()

    thread.start_new_thread(background_update,(config_file,))
    return Response(common.jsondump({'result':'OK'}), mimetype='application/json')

@app.route('/cleanup')
@app.route('/clean')
@requires_auth
def cleanup():
    logger.info("run cleanup")
    wapt=Wapt(config_filename=config_file)
    data = wapt.cleanup()
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/enable')
@requires_auth
def enable():
    logger.info("enable tasks scheduling")
    wapt=Wapt(config_filename=config_file)
    data = wapt.enable_tasks()
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/disable')
@requires_auth
def disable():
    logger.info("disable tasks scheduling")
    wapt=Wapt(config_filename=config_file)
    data = wapt.disable_tasks()
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/register')
@check_ip_source
def register():
    logger.info("register computer")
    wapt=Wapt(config_filename=config_file)
    data = wapt.register_computer()
    return Response(common.jsondump(data), mimetype='application/json')


@app.route('/install', methods=['GET'])
@requires_auth
def install():
    package = request.args.get('package')
    logger.info("install package %s" % package)
    wapt=Wapt(config_filename=config_file)
    try:
        data = wapt.install(package)
    except Exception as e:
        data = {'errors':[ str(e) ]}

    if request.args.get('format','html')=='json':
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('install.html',**data)

@app.route('/package_download', methods=['GET'])
def package_download():
    package = request.args.get('package')
    logger.info("download package %s" % package)
    wapt=Wapt(config_filename=config_file)
    try:
        data = wapt.install(package,download_only=True,force=True)
    except Exception as e:
        data = {'errors':[ str(e) ]}

    if request.args.get('format','html')=='json':
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('download.html',**data)

@app.route('/remove', methods=['GET'])
@requires_auth
def remove():
    package = request.args.get('package')
    logger.info("remove package %s" % package)
    wapt=Wapt(config_filename=config_file)
    try:
        data = wapt.remove(package)
    except Exception as e:
        data = {'removed' :[ package ], 'errors':[ str(e) ]}
    if request.args.get('format','html')=='json':
        return Response(common.jsondump(data), mimetype='application/json')
    else:
        return render_template('remove.html',**data)

"""
@app.route('/static/<path:filename>', methods=['GET'])
def static(filename):
    return send_file(open(os.path.join(wapt_root_dir,'static',filename),'rb'),as_attachment=False)
"""

@app.route('/', methods=['GET'])
def index():
    wapt = Wapt(config_filename=config_file)
    host_info = setuphelpers.host_info()
    data = dict(html=html,
            host_info=host_info,
            wapt=wapt,
            wapt_info=wapt.wapt_status(),
            update_status=wapt.get_last_update_status())
    if request.args.get('format','html')=='json':
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

if __name__ == "__main__":
    if len(sys.argv)>1 and sys.argv[1] == 'doctest':
        import doctest
        sys.exit(doctest.testmod())

    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
    #hdlr = logging.StreamHandler(sys.stdout)
    #hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    #logger.addHandler(hdlr)

    debug=True
    if debug==True:
        app.run(host='0.0.0.0',port=waptservice_port,debug=True)
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

