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
import gc

wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
sys.path.append(os.path.join(wapt_root_dir))
sys.path.append(os.path.join(wapt_root_dir,'lib'))
sys.path.append(os.path.join(wapt_root_dir,'waptservice'))
sys.path.append(os.path.join(wapt_root_dir,'lib','site-packages'))



__version__ = "0.7.6"

config = ConfigParser.RawConfigParser()

log_directory = os.path.join(wapt_root_dir,'log')
if not os.path.exists(log_directory):
    os.mkdir(log_directory)

logging.basicConfig(filename=os.path.join(log_directory,'waptservice.log'),format='%(asctime)s %(message)s')
logging.info('waptservice starting')

config_file = os.path.join(wapt_root_dir,'wapt-get.ini')

if os.path.exists(config_file):
    config.read(config_file)
else:
    raise Exception("FATAL. Couldn't open config file : " + config_file)

#default mongodb configuration for wapt
mongodb_port = "38999"
mongodb_ip = "127.0.0.1"

wapt_user = ""
wapt_password = ""

if config.has_section('global'):
    if config.has_option('global', 'wapt_user'):
        wapt_user = config.get('global', 'wapt_user')
    else:
        wapt_user='admin'

    if config.has_option('global','waptservice_password'):
        wapt_password = config.get('global', 'waptservice_password')
    else:
        print "WARNING : no password set, using default password"
        wapt_password='5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8' # = password

    if config.has_option('global','waptservice_port'):
        waptservice_port = config.get('global','waptservice_port')
    else:
        waptservice_port=8088
else:
    raise Exception ("FATAL, configuration file " + config_file + " has no section [global]. Please check Waptserver documentation")

logger = logging.getLogger()
hdlr = logging.StreamHandler(sys.stdout)
hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

import common
from common import Wapt


ALLOWED_EXTENSIONS = set(['wapt'])


dbpath = 'c:\\wapt\\db\\waptdb.sqlite'

wapt_ip = socket.gethostbyname( urlparse(Wapt(config_filename=config_file).find_wapt_server()).hostname)

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
        print wapt_ip
        if not  request.remote_addr in ['127.0.0.1', wapt_ip]:
            return authenticate()
        return f(*args, **kwargs)

    return decorated

def get_con():
    con = sqlite3.connect(dbpath)
    return con

@app.route('/status')
def status():
    rows = []
    with sqlite3.connect(dbpath) as con:
        try:
            con.row_factory=sqlite3.Row
            query = '''select s.package,s.version,s.install_date,s.install_status,
                                 (select max(p.version) from wapt_package p where p.package=s.package) as repo_version,explicit_by as install_par
                                 from wapt_localstatus s
                                 order by s.package'''
            cur = con.cursor()
            cur.execute(query)
            rows = [ dict(x) for x in cur.fetchall() ]
        except lite.Error, e:
            print "*********** Error %s:" % e.args[0]
    return Response(common.jsondump(rows), mimetype='application/json')

@app.route('/list')
def status():
    with sqlite3.connect(dbpath) as con:
        try:
            con.row_factory=sqlite3.Row
            query = '''select * from wapt_package where section<>"host" order by package,version'''
            cur = con.cursor()
            cur.execute(query)
            rows = [ dict(x) for x in cur.fetchall() ]
        except lite.Error, e:
            print "*********** Error %s:" % e.args[0]
    return Response(common.jsondump(rows), mimetype='application/json')

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
            print data
        except Exception as e:
            print "*********** error " + str (e)
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
            print data
        except Exception as e :
            print "*********** error"  + str(e)
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/waptupgrade')
@check_ip_source
def waptupgrade():
    from setuphelpers import run
    print "run waptupgrade"
    run('c:\\wapt\\wapt-get waptupgrade')
    return "200 OK"

@app.route('/upgrade')
@check_ip_source
def upgrade():
    print "run upgrade"
    def background_upgrade(config_file):
        print "************** Launch upgrade***********************"
        wapt=Wapt(config_filename=config_file)
        wapt.update()
        wapt.upgrade()
        wapt.update_server_status()
        print "************** End upgrade *************************"
        del wapt
        gc.collect()

    thread.start_new_thread(background_upgrade,(config_file,))
    return Response(common.jsondump({'result':'ok'}), mimetype='application/json')

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
    return Response(common.jsondump({'result':'ok'}), mimetype='application/json')

@app.route('/clean')
@requires_auth
def clean():
    print "run cleanup"
    wapt=Wapt(config_filename=config_file)
    data = wapt.cleanup()
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/enable')
@requires_auth
def enable():
    print "run cleanup"
    wapt=Wapt(config_filename=config_file)
    data = wapt.enable_tasks()
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/disable')
@requires_auth
def disable():
    print "run cleanup"
    wapt=Wapt(config_filename=config_file)
    data = wapt.disable_tasks()
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/register')
@check_ip_source
def register():
    print "run cleanup"
    wapt=Wapt(config_filename=config_file)
    data = wapt.register_computer()
    return Response(common.jsondump(data), mimetype='application/json')


@app.route('/install', methods=['GET'])
@requires_auth
def install():
    package = request.args.get('package')
    print "run cleanup"
    wapt=Wapt(config_filename=config_file)
    data = wapt.install(package)
    return Response(common.jsondump(data),status=200, mimetype='application/json')


@app.route('/remove', methods=['GET'])
@requires_auth
def remove():
    package = request.args.get('package')
    print "run cleanup"
    wapt=Wapt(config_filename=config_file)
    data = wapt.remove(package)
    return Response(common.jsondump(data), mimetype='application/json')

"""
@app.route('/static/<path:filename>', methods=['GET'])
def static(filename):
    return send_file(open(os.path.join(wapt_root_dir,'static',filename),'rb'),as_attachment=False)
"""

@app.route('/', methods=['GET'])
def index():
    return render_template('layout.html')

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
    debug=False
    if debug==True:
        #TODO : recuperer le port du .ini
        app.run(host='0.0.0.0',port=8088,debug=False)
        print "exiting"
    else:
        #TODO : recuperer le port depuis le .ini
        port = 8088
        server = Rocket(('0.0.0.0', port), 'wsgi', {"wsgi_app":app})
        try:
            print ("starting waptserver")
            server.start()
        except KeyboardInterrupt:
            print ("stopping waptserver")
            server.stop()

