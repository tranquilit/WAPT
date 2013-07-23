from flask import request, Flask,Response
import time
import sys
import json
import pymongo
import os
from pymongo import MongoClient
from werkzeug import secure_filename
from waptpackage import update_packages
import logging
import ConfigParser
config = ConfigParser.RawConfigParser()
config.read('waptserver.ini')

mongodb_port = ""
mongodb_ip = ""
wapt_folder = ""

if config.has_section('options'):
    if config.has_option('options', 'mongodb_port'):
        mongodb_port = config.get('options', 'mongodb_port')
    if config.has_option('options', 'mongodb_ip'):
        mongodb_ip = config.get('options', 'mongodb_ip')
    if config.has_option('options', 'wapt_folder'):
        wapt_folder = config.get('options', 'wapt_folder')
        if wapt_folder.endswith('/'):
            wapt_folder = wapt_folder[:-1]
    

logger = logging.getLogger()
hdlr = logging.StreamHandler(sys.stdout)
hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

if mongodb_port and mongodb_ip:
    client = MongoClient(mongodb_ip, int(mongodb_port))
else :
    client = MongoClient()

db = client.wapt
hosts = db.hosts

if not wapt_folder:
    wapt_folder = '/var/www/wapt'

    
ALLOWED_EXTENSIONS = set(['wapt'])


app = Flask(__name__)
app.config['PROPAGATE_EXCEPTIONS'] = True

def get_host_data(uuid, filter = {}, delete_id = True):
    if filter:
        data = hosts.find_one({ "uuid": uuid}, filter)
    else:
        data = hosts.find_one({ "uuid": uuid})
    if data and delete_id:
        data.pop("_id")
    return data


@app.route('/json/host_list',methods=['GET'])
def get_host_list():

    list_hosts = []
    data = request.args
    query = {}
    search_filter = ""
    search = ""

    if "package_error" in data.keys() and data['package_error'] == "true":
        query["packages.install_status"] = "ERROR"
    if "need_upgrade" in data.keys() and data['need_upgrade'] == "true":
        query["update_status.upgrades"] = {"$exists": "true", "$ne" :[]}
    if "q" in data.keys():
        search = data['q'].lower()
    if "filter" in data.keys():
        search_filter = data['filter'].split(',')
            
    #{"host":1,"dmi":1,"uuid":1, "wapt":1, "update_status":1,"last_query_date":1}

    for host in hosts.find( query):
        host.pop("_id")
        if search_filter:
            for key in search_filter:
                if host.has_key(key) and search in json.dumps(host[key]).lower():
                    host["softwares"] = ""
                    host["packages"] = ""
                    list_hosts.append(host)  
                    continue
        elif search and search in json.dumps(host).lower():
            host["softwares"] = ""
            host["packages"] = ""           
            list_hosts.append(host)  
        elif search == "":
            host["softwares"] = ""
            host["packages"] = ""            
            list_hosts.append(host)  

    return  Response(response=json.dumps(list_hosts),
                    status=200,
                    mimetype="application/json")

@app.route('/update_host',methods=['POST'])
def update_host():
    data = json.loads(request.data)
    if data:
        return json.dumps(update_data(data))
    else:
        raise Exception("No data retrieved")


@app.route('/delete_host/<string:uuid>')
def delete_host(uuid=""):
    hosts.remove({'uuid': uuid })
    if get_host_data(uuid):
        return "error"
    else:
        return "ok"
@app.route('/add_host',methods=['POST'])
def add_host():
    data = json.loads(request.data)
    if data:
        return json.dumps(update_data(data))
    else:
        raise Exception("No data retrieved")
def update_data(data):
    data['last_query_date'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    host = get_host_data(data["uuid"],delete_id=False)
    if host:
        hosts.update({"_id" : host['_id'] }, {"$set": data})
    else:
        host_id = hosts.insert(data)

    return get_host_data(data["uuid"],filter={"uuid":1,"host":1})


@app.route('/client_software_list/<string:uuid>')
def get_client_software_list(uuid=""):
    softwares = get_host_data(uuid, filter={"softwares":1})
    return  Response(response=json.dumps(softwares['softwares']),
                    status=200,
                    mimetype="application/json")

@app.route('/client_package_list/<string:uuid>')
def get_client_package_list(uuid=""):
    packages = get_host_data(uuid, {"packages":1})
    return  Response(response=json.dumps(packages['packages']),
                    status=200,
                    mimetype="application/json")


@app.route('/upload_package',methods=['POST'])
def upload_package():
    try:
        if request.method == 'POST':
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(wapt_folder, filename))
                update_packages(wapt_folder)
                return "ok"
            else:
                return "wrong file type"
        else:
            return "Unsupported method"
    except:
        e = sys.exc_info()
        return str(e)
    
@app.route('/upload_host',methods=['POST'])
def upload_host():
    try:
        if request.method == 'POST':
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(wapt_folder+'-host', filename))
                return "ok"
            else:
                return "wrong file type"
        else:
            return "Unsupported method"
    except:
        e = sys.exc_info()
        return str(e)
    
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/delete_package/<string:filename>')
def delete_package(filename=""):
    file = os.path.join(wapt_folder,filename)
    if os.path.exists(file):
        try:
            os.unlink(file)
            update_packages(wapt_folder)
            return json.dumps({'result':'ok'})
        except Exception,e:
            return json.dumps({'error': "%s" % e })
    else:
        return json.dumps({'error': "The file %s doesn't exist in wapt folder (%s)" % (filename, wapt_folder)})
if __name__ == "__main__":
    app.run(host='0.0.0.0',port=8080, debug=False)

