import time
import sys
import json
import hashlib

import os
from werkzeug import secure_filename
from waptpackage import update_packages,PackageEntry
from functools import wraps
import logging
import ConfigParser
import  cheroot.wsgi, cheroot.ssllib.ssl_builtin
import logging
import codecs
import zipfile
import pprint
import sqlite3
from flask import request, Flask,Response, send_from_directory, session, g, redirect, url_for, abort, render_template, flash
import common

__version__ = "0.7.4"

config = ConfigParser.RawConfigParser()
wapt_root_dir = ''

if os.name=='nt':
    import _winreg
    try:
        key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\\TranquilIT\\WAPT")
        (wapt_root_dir,atype) = _winreg.QueryValueEx(key,'install_dir')
    except:
        wapt_root_dir = 'c:\\\\wapt\\'
else:
    wapt_root_dir = '/opt/wapt/'

import logging



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

sys.path.append(os.path.join(wapt_root_dir))
sys.path.append(os.path.join(wapt_root_dir,'lib'))
sys.path.append(os.path.join(wapt_root_dir,'waptservice'))
sys.path.append(os.path.join(wapt_root_dir,'lib','site-packages'))

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
        raise Exception ('No waptservice admin password set in wapt-get.ini configuration file')

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

ALLOWED_EXTENSIONS = set(['wapt'])

app = Flask(__name__,static_folder='./templates/static')
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
        logging.info("user %s authenticated" % auth.username)
        return f(*args, **kwargs)
    return decorated


def get_con():
    con  = None
    con = sqlite3.connect('c:\\wapt\\db\\waptdb.sqlite')
    return con

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/status')
def status():
    con = None
    try:
        query = '''select s.package,s.version,s.install_date,s.install_status,"Remove" as Remove,
                             (select max(p.version) from wapt_package p where p.package=s.package) as repo_version,explicit_by as install_par
                             from wapt_localstatus s
                             order by s.package'''
        con = get_con()
        cur = con.cursor()
        cur.execute(query)
        data = cur.fetchall()
    except lite.Error, e:
        print "Error %s:" % e.args[0]
    finally:
        if con:
            con.close()
    return data
    #return render_template('listing.html')

@app.route('/runstatus')
def get_runstatus():
    print "from runstatus"
    con = sqlite3.connect('c:\\wapt\\db\\waptdb.sqlite')
    con.row_factory=sqlite3.Row
    data = ""
    try:
        query ="""select value,create_date from wapt_params where name='runstatus' limit 1"""
        cur = con.cursor()
        cur.execute(query)
        rows = cur.fetchall()
        data = json.dumps([dict(ix) for ix in rows])
    except Exception as e:
        print "error" + str (e)
    finally:
        if con:  con.close()
    return Response(data, mimetype='application/json')

@app.route('/checkupgrades')
def get_checkupgrades():
    global config_file
    con = sqlite3.connect('c:\\wapt\\db\\waptdb.sqlite')
    con.row_factory=sqlite3.Row
    data = ""
    try:
        query ="""select * from wapt_params where name="last_update_status" limit 1"""
        cur = con.cursor()
        cur.execute(query)
        rows = cur.fetchone()['value']
        data = json.dumps(rows)
    except Exception as e :
        print "error"  + str(e)
    finally:
        if con:  con.close()
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/waptupgrade')
def waptupgrade():
    from setuphelpers import run
    print "run waptupgrade"
    run('c:\\wapt\\wapt-get waptupgrade')
    return "200 OK"

@app.route('/upgrade')
def upgrade():
    global config_file
    from common import Wapt
    wapt=Wapt(config_filename=config_file)
    print "run upgrade"
    data =  wapt.upgrade()
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/update')
def update():
    global config_file
    from common import Wapt
    wapt=Wapt(config_filename=config_file)
    print "run upgrade"
    data = wapt.update()
    print data
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/updatebg')
def update():
    global config_file
    from common import Wapt
    wapt=Wapt(config_filename=config_file)
    print "run upgrade"
    data = wapt.update()
    print data
    return Response('OK : Process c:\\wapt\\wapt-get.exe launched in background')

@app.route('/clean')
def clean():
    global config_file
    from common import Wapt
    wapt=Wapt(config_filename=config_file)
    print "run cleanup"
    data = wapt.cleanup()
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/enable')
def enable():
    global config_file
    from common import Wapt
    wapt=Wapt(config_filename=config_file)
    print "run cleanup"
    data = wapt.enable_tasks()
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/disable')
def disable():
    from common import Wapt
    global config_file
    wapt=Wapt(config_filename=config_file)
    print "run cleanup"
    data = wapt.disable_tasks()
    return Response(common.jsondump(data), mimetype='application/json')

@app.route('/register')
def register():
    from common import Wapt
    global config_file
    wapt=Wapt(config_filename=config_file)
    print "run cleanup"
    data = wapt.register_computer()
    return Response(common.jsondump(data), mimetype='application/json')


@app.route('/install', methods=['GET'])
@requires_auth
def install():
    from common import Wapt
    global config_file
    wapt=Wapt(config_filename=config_file)
    package = request.args.get('package')
    print "run cleanup"
    data = wapt.install(package)
    return Response(common.jsondump(data),status=200, mimetype='application/json')

@requires_auth
@app.route('/remove', methods=['GET'])
def remove():
    from common import Wapt
    global config_file
    wapt=Wapt(config_filename=config_file)
    package = request.args.get('package')
    print "run cleanup"
    data = wapt.remove(package)
    return Response(data, mimetype='application/json')

@app.route('/login',methods=['POST'])
def login():
    try:
        if request.method == 'POST':
            d= json.loads(request.data)
            if "username" in d and "password" in d:
                if check_auth(d["username"], d["password"]):
                    if "newPass" in d:
                        global wapt_password
                        wapt_password = hashlib.sha256(d["newPass"]).hexdigest()
                        config.set('options', 'wapt_password', wapt_password)
                        with open(os.path.join(wapt_root_dir,'waptserver','waptserver.ini'), 'wb') as configfile:
                            config.write(configfile)
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


def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    return wapt_user == username and wapt_password == hashlib.sha512(password).hexdigest()

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

if __name__ == "__main__":
    # SSL Support
    #port = 8443
    #ssl_a = cheroot.ssllib.ssl_builtin.BuiltinSSLAdapter("srvlts1.crt", "srvlts1.key", "ca.crt")
    #wsgi_d = cheroot.wsgi.WSGIPathInfoDispatcher({'/': app})
    #server = cheroot.wsgi.WSGIServer(('0.0.0.0', port),wsgi_app=wsgi_d,ssl_adapter=ssl_a)
    debug=True
    if debug==True:
        #TODO : recuperer le port du .ini
        app.run(host='0.0.0.0',port=8088,debug=False)
        print "exiting"
    else:
        #TODO : recuperer le port depuis le .ini
        port = 8080
        wsgi_d = cheroot.wsgi.WSGIPathInfoDispatcher({'/': app})
        server = cheroot.wsgi.WSGIServer(('0.0.0.0', port),wsgi_app=wsgi_d)
        try:
            print ("starting waptserver")
            server.start()
        except KeyboardInterrupt:
            print ("stopping waptserver")
            server.stop()

