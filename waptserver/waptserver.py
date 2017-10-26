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
__version__ = '1.5.0.12'

import os
import sys
try:
    wapt_root_dir = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            '..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0, os.path.join(wapt_root_dir))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib'))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib', 'site-packages'))

# monkeypatching for eventlet greenthreads
from eventlet import monkey_patch

# os=False for windows see https://mail.python.org/pipermail/python-bugs-list/2012-November/186579.html
monkey_patch(os=False)

from flask import request, Flask, Response, send_from_directory, session, g, redirect, url_for, abort, render_template, flash
from flask_socketio import SocketIO, disconnect, send, emit
# from flask_login import LoginManager,login_required,current_user,UserMixin

import time
import json
import hashlib
from passlib.hash import sha512_crypt, bcrypt
from passlib.hash import pbkdf2_sha256

from peewee import *
from playhouse.postgres_ext import *

from waptserver_model import Hosts, HostSoftwares, HostPackagesStatus, ServerAttribs, HostGroups
from waptserver_model import get_db_version, init_db, wapt_db, model_to_dict, dict_to_model, update_host_data
from waptserver_model import upgrade_db_structure

from werkzeug.utils import secure_filename
from functools import wraps

import logging
import logging.handlers
import ConfigParser
import codecs
import base64
import zlib

import zipfile
import platform
import socket
import requests
import shutil
import subprocess
import tempfile
import traceback
import datetime
import uuid as uuid_
import email.utils
import collections
from collections import OrderedDict
import urlparse
import stat
import pefile
import itsdangerous
import thread
import threading
import Queue
import re

from waptpackage import *
from waptcrypto import *

from waptserver_utils import *
import waptserver_config

import wakeonlan.wol

# i18n
from flask_babel import Babel
try:
    from flask_babel import gettext
except ImportError:
    gettext = (lambda s: s)
_ = gettext


from optparse import OptionParser

# Ensure that any created files have sane permissions.
# uWSGI implicitely sets umask(0).
try:
    os.umask(0o022)
except Exception:
    pass

ALLOWED_EXTENSIONS = set(['wapt'])
DEFAULT_CONFIG_FILE = os.path.join(wapt_root_dir, 'conf', 'waptserver.ini')
config_file = DEFAULT_CONFIG_FILE

# setup logging
logger = logging.getLogger()

#
app = Flask(__name__, static_folder='./templates/static')
app.config['CONFIG_FILE'] = config_file

babel = Babel(app)

conf = waptserver_config.load_config(config_file)
app.config['SECRET_KEY'] = conf.get('secret_key')

# chain SocketIO server
socketio = SocketIO(app, logger=logger, max_size=conf['max_clients'])

try:
    import wsus
    app.register_blueprint(wsus.wsus)
except Exception as e:
    logger.info(str(e))
    wsus = False


app.config['HAS_AD_MODULE_AUTH'] = False
if conf.get('dc_auth_enabled'):
    try:
        import auth_module_ad
        app.config['HAS_AD_MODULE_AUTH'] = True
    except Exception as e:
        logger.debug(traceback.print_exc())
        logger.info(str(e))
        logger.fatal("Couldn't configure AD authentification, missing module")
        sys.exit(1)

def get_wapt_exe_version(exe):
    present = False
    version = None
    if os.path.exists(exe):
        present = True
        pe = None
        try:
            pe = pefile.PE(exe)
            version = pe.FileInfo[0].StringTable[
                0].entries['FileVersion'].strip()
            if not version:
                version = pe.FileInfo[0].StringTable[
                    0].entries['ProductVersion'].strip()
        except:
            pass
        if pe is not None:
            pe.close()
    return (present, version)


@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    try:
        wapt_db.commit()
    except:
        wapt_db.rollback()
    if not wapt_db.is_closed():
        wapt_db.close()


def sio_authenticated_only(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            disconnect()
        else:
            return f(*args, **kwargs)
    return wrapped


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization

        if session.get('user',None):
            logger.debug('connection from user %s ' % session.get('user'))
            return f(*args, **kwargs)

        if not auth:
            logger.info('no credential given')
            return authenticate()

        logging.debug('authenticating : %s' % auth.username)
        if not check_auth(auth.username, auth.password):
            return authenticate()
        logger.info('user %s authenticated' % auth.username)
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

    try:
        logger.debug('has ad module: %s ' % app.config['HAS_AD_MODULE_AUTH'])
        if app.config['HAS_AD_MODULE_AUTH']:
            if auth_module_ad.check_credentials_ad(username,password):
                return True
    except:
        print "error while checking ad auth"
        logger.warning('error while checking ad auth')
        logger.debug(traceback.print_exc())




    user_ok = False
    pass_sha1_ok = pbkdf2_sha256_ok = pass_sha512_ok = pass_sha512_crypt_ok = pass_bcrypt_crypt_ok = False

    user_ok = conf['wapt_user'] == username

    pass_sha1_ok = conf['wapt_password'] == hashlib.sha1(
        password.encode('utf8')).hexdigest()
    pass_sha512_ok = conf['wapt_password'] == hashlib.sha512(
        password.encode('utf8')).hexdigest()

    if '$pbkdf2-sha256$' in conf['wapt_password']:
        pbkdf2_sha256_ok = pbkdf2_sha256.verify(password, conf['wapt_password'])
    elif sha512_crypt.identify(conf['wapt_password']):
        pass_sha512_crypt_ok = sha512_crypt.verify(
            password,
            conf['wapt_password'])
    else:
        try:
            if bcrypt.identify(conf['wapt_password']):
                pass_bcrypt_crypt_ok = bcrypt.verify(
                    password,
                    conf['wapt_password'])
        except Exception:
            pass

    return any_([pbkdf2_sha256_ok, pass_sha1_ok, pass_sha512_ok,
                 pass_sha512_crypt_ok, pass_bcrypt_crypt_ok]) and user_ok


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        _('You have to login with proper credentials'), 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


@babel.localeselector
def get_locale():
    browser_lang = request.accept_languages.best_match(['en', 'fr'])
    user_lang = session.get('lang', browser_lang)
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


def get_server_uuid():
    """Create and/or returns this server UUID"""
    server_uuid = conf.get('server_uuid', None)
    return server_uuid


@app.route('/')
def index():
    waptagent = os.path.join(conf['wapt_folder'], 'waptagent.exe')
    waptsetup = os.path.join(conf['wapt_folder'], 'waptsetup-tis.exe')
    waptdeploy = os.path.join(conf['wapt_folder'], 'waptdeploy.exe')

    agent_status = setup_status = deploy_status = db_status = 'N/A'
    agent_style = setup_style = deploy_style = disk_space_style = 'style="color: red;"'

    setup_present, setup_version = get_wapt_exe_version(waptsetup)
    if setup_present:
        setup_style = ''
        if setup_version is not None:
            setup_status = setup_version
        else:
            setup_status = 'ERROR'

    agent_present, agent_version = get_wapt_exe_version(waptagent)
    agent_sha256 = None
    if agent_present:
        if agent_version is not None:
            agent_status = agent_version
            agent_sha256 = sha256_for_file(waptagent)
            if Version(agent_version) >= Version(setup_version):
                agent_style = ''
        else:
            agent_status = 'ERROR'

    deploy_present, deploy_version = get_wapt_exe_version(waptdeploy)
    if deploy_present:
        deploy_style = ''
        if deploy_version is not None:
            deploy_status = deploy_version
        else:
            deploy_status = 'ERROR'

    try:
        db_status = 'OK (%s)' % get_db_version()
    except Exception as e:
        db_status = 'ERROR'

    try:
        space = get_disk_space(conf['wapt_folder'])
        if not space:
            raise Exception('Disk info not found')
        percent_free = (space[0] * 100) / space[1]
        if percent_free >= 20:
            disk_space_style = ''
        disk_space_str = str(percent_free) + '% free'
    except Exception as e:
        disk_space_str = 'error, %s' % str(e)

    data = {
        'wapt': {
            'server': {'status': __version__},
            'agent': {'status': agent_status, 'style': agent_style, 'sha256': agent_sha256},
            'setup': {'status': setup_status, 'style': setup_style},
            'deploy': {'status': deploy_status, 'style': deploy_style},
            'db': {'status': db_status},
            'disk_space': {'status': disk_space_str, 'style': disk_space_style},
        }
    }

    return render_template('index.html', data=data)


@app.route('/add_host', methods=['POST'])
@app.route('/add_host', methods=['GET'])
@app.route('/update_host', methods=['POST'])
def update_host():
    """Update localstatus of computer, and return known registration info
    """
    try:
        starttime = time.time()

        if request.headers.get('Content-Encoding') == 'gzip':
            raw_data = zlib.decompress(request.data)
        else:
            raw_data = request.data

        data = json.loads(raw_data)

        if data:
            uuid = data['uuid']
            if uuid:
                logger.info('Update host %s status' % (uuid,))
                data['last_seen_on'] = datetime2isodate()
                signature_b64 = request.headers.get('X-Signature', None)
                signer = request.headers.get('X-Signer', None)

                # with nginx kerberos module, auth user name is stored as Basic auth in the
                # 'Authorisation' header with password 'bogus_auth_gss_passwd'
                authenticated_user = request.headers.get('Authorization', None)

                if authenticated_user:
                    if authenticated_user.startswith('Basic'):
                        logger.debug('#####################################')
                        logger.debug(authenticated_user)
                        authenticated_user = base64.b64decode(authenticated_user.replace('Basic', '').strip())
                        logger.debug(authenticated_user)
                    authenticated_user = authenticated_user.lower().replace('$', '')
                    if authenticated_user.endswith(':bogus_auth_gss_passwd'):
                        authenticated_user = authenticated_user.replace(':bogus_auth_gss_passwd', '')

                    dns_domain = '.'.join(socket.getfqdn().split('.')[1:])
                    authenticated_user = '%s.%s' % (authenticated_user, dns_domain)
                    logger.debug(request.headers)
                    logger.debug('authenticated computer : %s ' % (authenticated_user,))

                if signature_b64:
                    signature = signature_b64.decode('base64')
                else:
                    signature = None

                if signature:
                    # when registering, mutual authentication is assumed by kerberos
                    # on nginx reverse proxy level
                    if request.path in ['/add_host']:
                        host_cert = SSLCertificate(crt_string=data['host_certificate'])
                        if conf['use_kerberos']:
                            if not authenticated_user:
                                raise EWaptAuthenticationFailure('add_host : Missing authentication header')
                            if authenticated_user.lower().replace('@', '.') != host_cert.cn.lower():
                                raise EWaptAuthenticationFailure(
                                    'add_host : Mismatch between authendtication header %s and Certificate commonName %s' % (authenticated_user, host_cert.cn))
                    else:
                        # get certificate from DB to check/authenticate submitted data.
                        existing_host = Hosts.select(Hosts.host_certificate, Hosts.computer_fqdn).where(Hosts.uuid == uuid).first()
                        if existing_host:
                            if existing_host.host_certificate:
                                host_cert = SSLCertificate(crt_string=existing_host.host_certificate)
                            else:
                                raise EWaptMissingCertificate(
                                    'Host certificate of %s (%s) is not in database, please register first.' % (uuid, existing_host.computer_fqdn))
                        else:
                            raise EWaptMissingCertificate(
                                'You try to update status of an unknown host %s (%s). Please register first.' % (uuid, data.get('computer_fqdn', 'unknown')))

                    if host_cert:
                        logger.debug('About to check supplied data signature with certificate %s' % host_cert.cn)
                        host_dn = host_cert.verify_content(sha256_for_data(raw_data), signature)
                        logger.info('Data successfully checked with certificate CN %s for %s' % (host_dn, uuid))
                    else:
                        raise EWaptMissingCertificate('There is no public certificate for checking signed data from %s' % (uuid))
                else:
                    raise EWaptBadSignature('No signature for supplied data for %s' % (uuid))

                db_data = update_host_data(data)

                result = db_data
                message = 'update_host'

            else:
                raise Exception('update_host: No uuid supplied')
        else:
            raise Exception('update_host: No data supplied')

        return make_response(result=result, msg=message, request_time=time.time() - starttime)

    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('update_host failed %s' % (repr(e)))
        return make_response_from_exception(e)


@app.route('/upload_package/<string:filename>', methods=['POST'])
@requires_auth
def upload_package(filename=''):
    try:
        tmp_target = ''
        if request.method == 'POST':
            if filename and allowed_file(filename):
                tmp_target = os.path.join(conf['wapt_folder'], secure_filename(filename + '.tmp'))
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
                    result = dict(status='ERROR', message=_('Problem during upload'))
                else:
                    if PackageEntry().load_control_from_wapt(tmp_target):
                        target = os.path.join(conf['wapt_folder'], secure_filename(filename))
                        if os.path.isfile(target):
                            os.unlink(target)
                        os.rename(tmp_target, target)
                        data = update_packages(conf['wapt_folder'])
                        result = dict(status='OK', message='%s uploaded, %i packages analysed' % (filename, len(data['processed'])), result=data)
                    else:
                        result = dict(status='ERROR', message=_('Not a valid wapt package'))
                        os.unlink(tmp_target)
            else:
                result = dict(status='ERROR', message=_('Wrong file type'))
        else:
            result = dict(status='ERROR', message=_('Unsupported method'))
    except:
        # remove temporary
        if os.path.isfile(tmp_target):
            os.unlink(tmp_target)
        e = sys.exc_info()
        logger.critical(repr(traceback.format_exc()))
        result = dict(status='ERROR', message=_('unexpected: {}').format((e,)))
    return Response(response=json.dumps(result),
                    status=200,
                    mimetype='application/json')


@app.route('/api/v3/upload_packages', methods=['POST'])
@requires_auth
def upload_packages():
    try:
        starttime = time.time()
        done = []
        errors = []
        files = request.files
        logger.info('Upload of %s packages' % len(files))
        for fkey in files:
            packagefile = request.files[fkey]
            logger.debug('uploading file : %s' % fkey)
            if packagefile and allowed_file(packagefile.filename):
                filename = secure_filename(packagefile.filename)
                wapt_folder = conf['wapt_folder']
                target = os.path.join(wapt_folder, filename)
                tmp_target = tempfile.mktemp(dir=wapt_folder,prefix='wapt')
                try:
                    packagefile.save(tmp_target)
                    # test if package is OK.
                    entry = PackageEntry(waptfile=tmp_target)
                    logger.debug('Saved package %s into %s' % (entry.asrequirement(),tmp_target))
                    # TODO check if certificate is allowed on thi server ?

                    if os.path.isfile(target):
                        os.unlink(target)
                    logger.debug('Renaming package %s into %s' % (tmp_target,target))
                    os.rename(tmp_target, target)
                    # fix context on target file (otherwith tmp context is carried over)
                    #logger.debug(subprocess.check_output('chcon -R -t httpd_sys_content_t %s' % target,shell=True))

                    done.append(filename)

                except Exception as e:
                    logger.debug('traceback')
                    logger.debug(traceback.print_exc())
                    logger.critical('Error uploading package %s: %s' % (filename, e))
                    errors.append(filename)
                    if os.path.isfile(tmp_target):
                        os.unlink(tmp_target)
                    raise

        logger.debug('Update package index')
        packages_index_result = update_packages(conf['wapt_folder'])

        spenttime = time.time() - starttime
        return make_response(success=len(errors) == 0,
                             result=dict(done=done, errors=errors, packages_index_result = packages_index_result),
                             msg=_('{} Packages uploaded, {} errors').format(len(done), len(errors)),
                             request_time=spenttime)

    except Exception as e:
        raise
        return make_response_from_exception(e, status='201')


@app.route('/upload_host', methods=['POST'])
@app.route('/api/v3/upload_hosts', methods=['POST'])
@requires_auth
def upload_host():
    try:
        starttime = time.time()
        done = []
        errors = []
        files = request.files.keys()
        logger.info('Upload of %s host packages' % len(files))
        for fkey in files:
            hostpackagefile = request.files[fkey]
            logger.debug('uploading host file : %s' % fkey)
            if hostpackagefile and allowed_file(hostpackagefile.filename):
                filename = secure_filename(hostpackagefile.filename)
                wapt_host_folder = os.path.join(conf['wapt_folder'] + '-host')
                target = os.path.join(wapt_host_folder, filename)
                tmp_target = tempfile.mktemp(dir=wapt_host_folder,prefix='wapt')
                with wapt_db.atomic():
                    try:

                        # if encrypted host packages, store the clear copy in a protected area for further edit...
                        if conf['encrypt_host_packages']:
                            ref_target = os.path.join(conf['wapt_folder'] + '-hostref', filename)
                            hostpackagefile.save(ref_target)
                            entry = PackageEntry(waptfile=ref_target)
                        else:
                            # write directly clear zip to tmp_targert
                            hostpackagefile.save(tmp_target)
                            entry = PackageEntry(waptfile=tmp_target)

                        host_id = entry.package

                        # insert /delete depends as groups
                        depends = [s.strip() for s in entry.depends.split(',')]
                        old_groups = [h['group_name'] for h in HostGroups.select(HostGroups.group_name).where(HostGroups.host == host_id).dicts()]
                        to_delete = [g for g in old_groups if not g in depends]
                        to_add = [g for g in depends if not g in old_groups]
                        if to_delete:
                            HostGroups.delete().where((HostGroups.host == host_id) & (HostGroups.group_name.in_(to_delete))).execute()
                        if to_add:
                            HostGroups.insert_many([dict(host=host_id, group_name=group) for group in to_add]).execute()

                        # get host cert to encrypt package with public key
                        if conf['encrypt_host_packages']:
                            host = Hosts.select(Hosts.uuid, Hosts.computer_fqdn, Hosts.host_certificate) \
                                .where((Hosts.uuid == host_id) | (Hosts.computer_fqdn == host_id)) \
                                .dicts().first()

                            # write encrypted package content
                            with open(tmp_target, 'wb') as encrypted_package:
                                package_data = open(ref_target, 'rb').read()
                                if host and host['host_certificate'] is not None:
                                    host_cert = SSLCertificate(crt_string=host['host_certificate'])
                                    encrypted_package.write(host_cert.encrypt_fernet(package_data))
                                else:
                                    encrypted_package.write(package_data)

                        if os.path.isfile(target):
                            os.unlink(target)
                        os.rename(tmp_target, target)
                        # fix context on target file (otherwith tmp context is carried over)
                        #logger.debug(subprocess.check_output('chcon -R -t httpd_sys_content_t %s' % target,shell=True))

                        done.append(filename)
                        wapt_db.commit()

                    except Exception as e:
                        wapt_db.rollback()
                        logger.debug('traceback')
                        logger.debug(traceback.print_exc())
                        logger.critical('Error uploading package %s: %s' % (filename, e))
                        errors.append(filename)
                        if os.path.isfile(tmp_target):
                            os.unlink(tmp_target)

        spenttime = time.time() - starttime
        return make_response(success=len(errors) == 0,
                             result=dict(done=done, errors=errors),
                             msg=_('{} Host packages uploaded, {} errors').format(len(done), len(errors)),
                             request_time=spenttime)

    except Exception as e:
        return make_response_from_exception(e, status='201')


@app.route('/upload_waptsetup', methods=['POST'])
@requires_auth
def upload_waptsetup():
    waptagent = os.path.join(conf['wapt_folder'], 'waptagent.exe')
    waptsetup = os.path.join(conf['wapt_folder'], 'waptsetup-tis.exe')

    logger.debug('Entering upload_waptsetup')
    tmp_target = None
    try:
        if request.method == 'POST':
            file = request.files['file']
            if file and 'waptagent.exe' in file.filename:
                filename = secure_filename(file.filename)
                tmp_target = os.path.join(conf['wapt_folder'], secure_filename('.' + filename))
                target = os.path.join(conf['wapt_folder'], secure_filename(filename))
                file.save(tmp_target)
                if not os.path.isfile(tmp_target):
                    result = dict(status='ERROR', message=_('Problem during upload'))
                else:
                    os.rename(tmp_target, target)
                    result = dict(status='OK', message=_('{} uploaded').format((filename,)))

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
                result = dict(status='ERROR', message=_('Wrong file name (version conflict?)'))
        else:
            result = dict(status='ERROR', message=_('Unsupported method'))
    except:
        e = sys.exc_info()
        if tmp_target and os.path.isfile(tmp_target):
            os.unlink(tmp_target)
        result = dict(status='ERROR', message=_('unexpected: {}').format((e,)))
    return Response(response=json.dumps(result),
                    status=200,
                    mimetype='application/json')


def rewrite_config_item(cfg_file, *args):
    config = ConfigParser.RawConfigParser()
    config.read(cfg_file)
    config.set(*args)
    with open(cfg_file, 'wb') as cfg:
        config.write(cfg)

# Reload config file.


def reload_config():
    try:
        global conf
        conf = waptserver_config.load_config(app.config['CONFIG_FILE'])
    except Exception as e:
        logger.critical('Unable to reload server config : %s' % repr(e))


@app.route('/api/v3/change_password', methods=['POST'])
@requires_auth
def change_passsword():
    try:
        config_file = app.config['CONFIG_FILE']
        post_data = request.get_json()
        if 'user' in post_data and 'password' in post_data:
            if check_auth(post_data['user'], post_data['password']):
                # change master password
                if 'new_password' in post_data and post_data['user'] == 'admin':
                    new_hash = pbkdf2_sha256.hash(post_data['new_password'].encode('utf8'))
                    rewrite_config_item(config_file, 'options', 'wapt_password', new_hash)
                    conf['wapt_password'] = new_hash
                    reload_config()
                    msg = 'Password for %s updated successfully' % post_data['user']
                else:
                    raise EWaptMissingParameter('Bad or missing parameter')
            else:
                raise EWaptAuthenticationFailure('Bad user or password')
        else:
            raise EWaptMissingParameter('Missing parameter')
        return make_response(result=msg, msg=msg, status=200)
    except Exception as e:
        return make_response_from_exception(e)


@app.route('/login', methods=['POST'])
@app.route('/api/v3/login', methods=['POST'])
def login():
    error = ''
    try:
        # TODO use session...
        post_data = request.get_json()
        if post_data is not None:
            # json auth from waptconsole
            user = post_data['user']
            password = post_data['password']

        # TODO : sanity check on username
        if not re.match('[a-z0-9]+[a-z0-9-_\.]+[a-z0-9]+$', user, re.IGNORECASE):
            msg = 'login must be alphanumeric with a dash'
            raise EWaptAuthenticationFailure(msg)

        if user is not None and password is not None:
            if check_auth(user, password):
                result = dict(
                    server_uuid=get_server_uuid(),
                    version=__version__,
                )
                session['user'] = user
        else:
            raise EWaptMissingParameter('Missing parameter for authentication')

        msg = 'Authentication OK'
        return make_response(result=result, msg=msg, status=200)
    except Exception as e:
        if 'auth_token' in session:
            del session['auth_token']
        logger.debug(traceback.print_exc())
        return make_response_from_exception(e)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/delete_package/<string:filename>')
@requires_auth
def delete_package(filename=''):
    fullpath = os.path.join(conf['wapt_folder'], filename)
    try:
        if os.path.isfile(fullpath):
            os.unlink(fullpath)
            data = update_packages(conf['wapt_folder'])
            result = dict(status='OK', message='Package deleted %s' % (fullpath,), result=data)
        else:
            result = dict(status='ERROR', message="The file %s doesn't exist in wapt folder (%s)" % (filename, conf['wapt_folder']))

    except Exception as e:
        result = {'status': 'ERROR', 'message': u'%s' % e}

    return Response(response=json.dumps(result),
                    status=200,
                    mimetype='application/json')


@app.route('/wapt/')
def wapt_listing():
    return render_template(
        'listing.html', dir_listing=os.listdir(conf['wapt_folder']))


@app.route('/waptwua/')
def waptwua():
    return render_template(
        'listingwua.html', dir_listing=os.listdir(waptwua_folder))


@app.route('/wapt/<string:input_package_name>')
def get_wapt_package(input_package_name):
    package_name = secure_filename(input_package_name)
    r = send_from_directory(conf['wapt_folder'], package_name)
    if 'content-length' not in r.headers:
        r.headers.add_header(
            'content-length', int(os.path.getsize(os.path.join(conf['wapt_folder'], package_name))))
    return r


@app.route('/wapt/icons/<string:iconfilename>')
def serve_icons(iconfilename):
    """Serves a png icon file from /wapt/icons/ test waptserver"""
    iconfilename = secure_filename(iconfilename)
    icons_folder = os.path.join(conf['wapt_folder'], 'icons')
    r = send_from_directory(icons_folder, iconfilename)
    if 'content-length' not in r.headers:
        r.headers.add_header(
            'content-length', int(os.path.getsize(os.path.join(icons_folder, iconfilename))))
    return r


@app.route('/css/<string:fn>')
@app.route('/fonts/<string:fn>')
@app.route('/img/<string:fn>')
@app.route('/js/<string:fn>')
def serve_static(fn):
    """Serve"""
    rootdir = os.path.join(app.template_folder, request.path.split('/')[1])
    if fn is not None:
        fn = secure_filename(fn)
        r = send_from_directory(rootdir, fn)
        if 'content-length' not in r.headers:
            r.headers.add_header(
                'content-length', int(os.path.getsize(os.path.join(rootdir, fn))))
        return r


@app.route('/wapt-host/<string:input_package_name>')
def get_host_package(input_package_name):
    """Returns a host package (in case there is no apache static files server)"""
    # TODO straighten this -host stuff
    host_folder = conf['wapt_folder'] + '-host'
    package_name = secure_filename(input_package_name)
    r = send_from_directory(host_folder, package_name)
    if 'Content-Length' not in r.headers:
        r.headers.add_header(
            'Content-Length', int(os.path.getsize(os.path.join(host_folder, package_name))))
    return r


@app.route('/wapt-group/<string:input_package_name>')
def get_group_package(input_package_name):
    """Returns a group package (in case there is no apache static files server)"""
    # TODO straighten this -group stuff
    group_folder = conf['wapt_folder'] + '-group'
    package_name = secure_filename(input_package_name)
    r = send_from_directory(group_folder, package_name)
    # on line content-length is not added to the header.
    if 'content-length' not in r.headers:
        r.headers.add_header(
            'content-length',
            os.path.getsize(
                os.path.join(
                    group_folder +
                    '-group',
                    package_name)))
    return r


@app.route('/ping')
def ping():
    return make_response(
        msg=_('WAPT Server running'), result=dict(
            version=__version__,
            api_root='/api/',
            api_version='v3',
            uuid=get_server_uuid(),
            date=datetime2isodate(),
        )
    )


@app.route('/api/v3/reset_hosts_sid', methods=['GET', 'POST'])
@requires_auth
def reset_hosts_sid():
    """Launch a separate thread to check all reachable IP and update database with results.
    """
    try:
        # in case a POST is issued with a selection of uuids to scan.
        uuids = request.json.get('uuids', None) or None
        if uuids is not None:
            message = _(u'Hosts connection reset launched for %s host(s)' % len(uuids))
        else:
            message = _(u'Hosts connection reset launched for all hosts')

        def target(uuids):
            logger.debug('Reset wsocket.io SID and timestamps of hosts')
            if uuids:
                where_clause = Hosts.uuid.in_(uuids)
            else:
                where_clause = None
            Hosts.update(listening_timestamp=None, listening_protocol=None).where(where_clause).execute()
            socketio.emit('wapt_ping')

        socketio.start_background_task(target=target, uuids=uuids)

    except Exception as e:
        return make_response_from_exception(e)
    return make_response(msg=message)


def proxy_host_request(request, action):
    """Proxy a waptconsole action to wapt clients using websockets
            uuid: can be a list or a single uuid
            notify_user: 0/1
            notify_server: 0/1
    Returns:
        dict:
            'success':
            'errors':
    """
    try:
        start_time = time.time()
        all_args = {k: v for k, v in request.args.iteritems()}
        if request.json:
            all_args.update(request.json)

        uuids = ensure_list(all_args['uuid'])
        del(all_args['uuid'])
        timeout = float(request.args.get('timeout', conf.get('clients_read_timeout', 5)))

        result = dict(success=[], errors=[])
        tasks = []
        for uuid in uuids:
            try:
                host_data = Hosts\
                    .select(Hosts.uuid, Hosts.computer_fqdn,
                            Hosts.server_uuid,
                            Hosts.listening_address,
                            Hosts.listening_port,
                            Hosts.listening_protocol,
                            Hosts.listening_timestamp,
                            )\
                    .where((Hosts.server_uuid == get_server_uuid()) & (Hosts.uuid == uuid) & (~Hosts.listening_address.is_null()) & (Hosts.listening_protocol == 'websockets'))\
                    .dicts()\
                    .first(1)

                if host_data and host_data.get('listening_address', None):
                    msg = u''
                    logger.info(
                        'Launching %s with args %s for %s at address %s...' %
                        (action, all_args, uuid, host_data['listening_address']))

                    args = dict(all_args)
                    sid = host_data['listening_address']
                    computer_fqdn = host_data['computer_fqdn']

                    def emit_action(sid, uuid, action, action_args, computer_fqdn, timeout=5):
                        try:
                            got_result = []

                            def result_callback(data):
                                got_result.append(data)

                            logger.debug('Emit %s to %s (%s)' % (action, uuid, computer_fqdn))
                            socketio.emit(action, action_args, room=sid, callback=result_callback)
                            # with for asynchronous answer...
                            wait_loop = timeout * 20
                            while not got_result:
                                wait_loop -= 1
                                if wait_loop < 0:
                                    raise EWaptTimeoutWaitingForResult('Timeout, client did not send result within %s s' % timeout)
                                socketio.sleep(0.05)

                            # action succedded
                            result['success'].append(
                                dict(
                                    uuid=uuid,
                                    msg=msg,
                                    computer_fqdn=computer_fqdn,
                                    result=got_result[0],
                                ))
                        except Exception as e:
                            result['errors'].append(
                                dict(
                                    uuid=uuid,
                                    msg='%s' % repr(e),
                                    computer_fqdn='',
                                ))
                    if sid:
                        tasks.append(socketio.start_background_task(
                            emit_action, sid=sid, uuid=uuid, action=action, action_args=args, computer_fqdn=computer_fqdn))

                else:
                    result['errors'].append(
                        dict(
                            uuid=uuid,
                            msg='Host %s is not registered or not connected wia websockets' % uuid,
                            computer_fqdn='',
                        ))
            except Exception as e:
                result['errors'].append(
                    dict(
                        uuid=uuid,
                        msg='Host %s error %s' % (uuid, repr(e)),
                        computer_fqdn='',
                    ))

        # wait for all background tasks to terminate or timeout...
        # assume the timeout should be longer if more hosts to perform
        wait_loop = timeout * len(tasks)
        while True:
            running = [t for t in tasks if t.is_alive()]
            if not running:
                break
            wait_loop -= 1
            if wait_loop < 0:
                break
            socketio.sleep(0.05)

        msg = ['Success : %s, Errors: %s' % (len(result['success']), len(result['errors']))]
        if result['errors']:
            msg.extend(['%s: %s' % (e['computer_fqdn'], e['msg'])
                        for e in result['errors']])

        return make_response(result,
                             msg='\n- '.join(msg),
                             success=len(result['success']) > 0,
                             request_time=time.time() - start_time)
    except Exception as e:
        return make_response_from_exception(e)


@app.route('/api/v3/trigger_wakeonlan', methods=['POST'])
@requires_auth
def trigger_wakeonlan():
    try:
        uuids = request.get_json()['uuids']
        hosts_data = Hosts\
            .select(Hosts.uuid, Hosts.computer_fqdn, Hosts.mac_addresses, Hosts.wapt_status, Hosts.host_info)\
            .where(Hosts.uuid.in_(uuids))\
            .dicts()
        result = []
        for host in hosts_data:
            macs = host['mac_addresses']
            msg = u''
            if macs:
                logger.debug(
                    _('Sending magic wakeonlan packets to {} for machine {}').format(
                        macs,
                        host['computer_fqdn']
                    ))
                wakeonlan.wol.send_magic_packet(*macs)
                for line in host['host_info']['networking']:
                    if 'broadcast' in line:
                        broadcast = line['broadcast']
                        wakeonlan.wol.send_magic_packet(
                            *
                            macs,
                            ip_address='%s' %
                            broadcast)
                result.append(dict(uuid=host['uuid'], computer_fqdn=host['computer_fqdn'], mac_addresses=host['mac_addresses']))
        msg = _(u'Wakeonlan packets sent to {} machines.').format(len(result))
        result = result
        return make_response(result,
                             msg=msg,
                             success=True)
    except Exception as e:
        return make_response_from_exception(e)


@app.route('/api/v3/trigger_waptwua_scan', methods=['GET', 'POST'])
@requires_auth
def trigger_waptwua_scan():
    """Proxy the wapt update action to the client"""
    return proxy_host_request(request, 'trigger_waptwua_scan')


@app.route('/api/v3/trigger_waptwua_download', methods=['GET', 'POST'])
@requires_auth
def trigger_waptwua_download():
    """Proxy the wapt download action to the client"""
    return proxy_host_request(request, 'trigger_waptwua_download')


@app.route('/api/v3/trigger_waptwua_install', methods=['GET', 'POST'])
@requires_auth
def trigger_waptwua_install():
    """Proxy the wapt scan action to the client"""
    return proxy_host_request(request, 'trigger_waptwua_install')


@app.route('/api/v2/waptagent_version')
@requires_auth
def waptagent_version():
    try:
        start = time.time()
        waptagent = os.path.join(conf['wapt_folder'], 'waptagent.exe')
        agent_present, agent_version = get_wapt_exe_version(waptagent)
        waptagent_timestamp = None
        agent_sha256 = None
        if agent_present and agent_version is not None:
            agent_sha256 = sha256_for_file(waptagent)
            waptagent_timestamp = datetime2isodate(
                datetime.datetime.fromtimestamp(
                    os.path.getmtime(waptagent)))

        waptsetup = os.path.join(conf['wapt_folder'], 'waptsetup-tis.exe')
        setup_present, setup_version = get_wapt_exe_version(waptsetup)
        waptsetup_timestamp = None
        if setup_present and setup_version is not None:
            waptsetup_timestamp = datetime2isodate(
                datetime.datetime.fromtimestamp(
                    os.path.getmtime(waptsetup)))

        if agent_present and setup_present and Version(
                agent_version) >= Version(setup_version):
            msg = 'OK : waptagent.exe %s >= waptsetup %s' % (
                agent_version, setup_version)
        elif agent_present and setup_present and Version(agent_version) < Version(setup_version):
            msg = 'Problem : waptagent.exe %s is older than waptsetup %s, and must be regenerated.' % (
                agent_version, setup_version)
        elif not agent_present and setup_present:
            msg = 'Problem : waptagent.exe not found. It should be compiled from waptconsole.'
        elif not setup_present:
            msg = 'Problem : waptsetup-tis.exe not found on repository.'

        result = dict(
            waptagent_version=agent_version,
            waptagent_sha256=agent_sha256,
            waptagent_timestamp=waptagent_timestamp,
            waptsetup_version=setup_version,
            waptsetup_timestamp=waptsetup_timestamp,
            request_time=time.time() - start,
        )
    except Exception as e:
        return make_response_from_exception(e)

    return make_response(result=result, msg=msg, status=200)


@app.route('/api/v3/trigger_cancel_task')
@requires_auth
def host_cancel_task():
    return proxy_host_request(request, 'trigger_cancel_task')


@app.route('/api/v1/groups')
@requires_auth
def get_groups():
    """List of packages having section == group
    """
    try:
        packages = WaptLocalRepo(conf['wapt_folder'])
        groups = [p.as_dict()
                  for p in packages.packages if p.section == 'group']
        msg = '{} Packages for section group'.format(len(groups))

    except Exception as e:
        return make_response_from_exception(e)

    return make_response(result=groups, msg=msg, status=200)


def build_hosts_filter(model, filter_expr):
    """Legacy helper function to translate waptconsole <=1.3.11 hosts filter
        into peewee model where clause.
    Args:
        filter_expr (str) : field1,field4,field5:search_regexp
    """
    (search_fields, search_expr) = filter_expr.split(':', 1)
    if search_expr.startswith('not ') or search_expr.startswith('!'):
        not_filter = 1
        if search_expr.startswith('not '):
            search_expr = search_expr.split(' ', 1)[1]
        else:
            search_expr = search_expr[1:]
    else:
        not_filter = 0

    if search_fields.strip() and search_expr.strip():
        result = None
        for fn in ensure_list(search_fields):
            members = fn.split('.')
            rootfield = members[0]
            # external collections...
            if rootfield == 'installed_softwares':
                clause = Hosts.uuid.in_(HostSoftwares.select(HostSoftwares.host).where(
                    HostSoftwares.key.regexp(ur'(?i)%s' % search_expr) | HostSoftwares.name.regexp(ur'(?i)%s' % search_expr)))
            elif rootfield == 'installed_packages':
                clause = Hosts.uuid.in_(HostPackagesStatus.select(HostPackagesStatus.host).where(HostPackagesStatus.package.regexp(ur'(?i)%s' % search_expr)))
            elif rootfield in model._meta.fields:
                if isinstance(model._meta.fields[rootfield], (JSONField, BinaryJSONField)):
                    if len(members) == 1:
                        clause = SQL("%s::text ~* '%s'" % (fn, search_expr))
                    else:
                        # (wapt->'waptserver'->'dnsdomain')::text ~* 'asfrance.lan'
                        clause = SQL("(%s->%s)::text ~* '%s'" % (rootfield, '->'.join(["'%s'" % f for f in members[1:]]), search_expr))
                        # model._meta.fields[members[0]].path(members[1:]).regexp(ur'(?i)%s' % search_expr)
                elif isinstance(model._meta.fields[rootfield], ArrayField):
                    clause = SQL("%s::text ~* '%s'" % (fn, search_expr))
                else:
                    clause = model._meta.fields[fn].regexp(ur'(?i)%s' % search_expr)
            # else ignored...
            else:
                clause = None

            if result is None:
                result = clause
            else:
                if clause is not None:
                    result = result | clause
        if not_filter:
            result = ~result
        return result
    else:
        raise Exception('Invalid filter provided in query. Should be f1,f2,f3:regexp ')


@app.route('/api/v3/hosts_delete', methods=['POST'])
@requires_auth
def hosts_delete():
    """Remove one or several hosts from Server DB and optionnally the host packages

    Args:
        uuids (list) : list of uuids to delete
        filter (csvlist of field:regular expression): filter based on attributes
        delete_packages (bool) : delete host's packages
        delete_inventory (bool) : delete host's inventory

    Returns:
        result (dict):

    """
    try:
        # build filter
        post_data = request.get_json()

        if 'uuids' in post_data:
            query = Hosts.uuid.in_(ensure_list(post_data['uuids']))
        elif 'filter' in post_data:
            query = build_hosts_filter(Hosts, post_data['filter'])
        else:
            raise Exception('Neither uuid nor filter provided in query')

        msg = []
        result = dict(files=[], records=[])

        if 'delete_packages' in post_data and post_data['delete_packages']:
            selected = Hosts.select(Hosts.uuid, Hosts.computer_fqdn).where(query)
            for host in selected:
                result['records'].append(
                    dict(
                        uuid=host.uuid,
                        computer_fqdn=host.computer_fqdn))
                uuid_hostpackage = os.path.join(conf['wapt_folder'] + '-host',host.uuid+'.wapt')
                fqdn_hostpackage = os.path.join(conf['wapt_folder'] + '-host',host.computer_fqdn+'.wapt')

                if os.path.isfile(uuid_hostpackage):
                    logger.debug('Trying to remove %s' % uuid_hostpackage)
                    if os.path.isfile(uuid_hostpackage):
                        os.remove(uuid_hostpackage)
                        result['files'].append(uuid_hostpackage)

                if os.path.isfile(fqdn_hostpackage):
                    logger.debug('Trying to remove %s' % fqdn_hostpackage)
                    if os.path.isfile(fqdn_hostpackage):
                        os.remove(fqdn_hostpackage)
                        result['files'].append(fqdn_hostpackage)

            msg.append(
                '{} files removed from host repository'.format(len(result['files'])))

        if 'delete_inventory' in post_data and post_data['delete_inventory']:
            remove_result = Hosts.delete().where(query).execute()
            msg.append('{} hosts removed from DB'.format(remove_result))

        return make_response(result=result, msg='\n'.join(msg), status=200)

    except Exception as e:
        wapt_db.rollback()
        return make_response_from_exception(e)


def build_fields_list(model, mongoproj):
    """Returns a list of peewee fields based on a mongo style projection
            For compatibility with waptconsole <= 1.3.11
    """
    result = []
    for fn in mongoproj.keys():
        if fn in model._meta.fields:
            result.append(model._meta.fields[fn])
        else:
            # jsonb sub fields.
            parts = fn.split('/')
            root = parts[0]
            if root in model._meta.fields:
                path = ','.join(parts[1:])
                result.append(SQL("%s #>>'{%s}' as \"%s\" " % (root, path, fn)))
    return result


@app.route('/api/v1/hosts', methods=['GET'])
@requires_auth
def get_hosts():
    """Get registration data of one or several hosts

    Args:
        has_errors (0/1): filter out hosts with packages errors
        need_upgrade (0/1): filter out hosts with outdated packages
        groups (csvlist of packages) : hosts with packages
        columns (csvlist of columns) :
        uuid (csvlist of uuid): <uuid1[,uuid2,...]>): filter based on uuid
        filter (csvlist of field):regular expression: filter based on attributes
        not_filter (0,1):
        limit (int) : 1000

    Returns:
        result (dict): {'records':[],'files':[]}

        query:
          uuid=<uuid>
        or
          filter=<csvlist of fields>:regular expression
    """
    try:
        start_time = time.time()
        default_columns = ['host_status',
                           'last_update_status',
                           'reachable',
                           'computer_fqdn',
                           'dnsdomain',
                           'description',
                           'connected_users',
                           'listening_protocol',
                           'listening_address',
                           'listening_port',
                           'listening_timestamp',
                           'manufacturer',
                           'productname',
                           'serialnr',
                           'last_seen_on',
                           'mac_addresses',
                           'connected_ips',
                           'wapt_status',
                           'uuid',
                           'md5sum',
                           'purchase_order',
                           'purchase_date',
                           'groups',
                           'attributes',
                           'host_info.domain_controller',
                           'host_info.domain_name',
                           'host_info.domain_controller_address',
                           'depends',
                           'computer_type',
                           'os_name',
                           'os_version', ]

        # keep only top tree nodes (mongo doesn't want fields like {'wapt':1,'wapt.listening_address':1} !
        # minimum columns
        columns = ['uuid',
                   'host_status',
                   'last_seen_on',
                   'last_update_status',
                   'computer_fqdn',
                   'computer_name',
                   'description',
                   'wapt_status',
                   'dnsdomain',
                   'server_uuid',
                   'listening_protocol',
                   'listening_address',
                   'listening_port',
                   'listening_timestamp',
                   'connected_users']
        other_columns = ensure_list(
            request.args.get(
                'columns',
                default_columns))

        # add request columns
        for fn in other_columns:
            if not fn in columns:
                columns.append(fn)

        not_filter = request.args.get('not_filter', 0)

        query = None

        # build filter
        if 'uuid' in request.args:
            query = Hosts.uuid.in_(ensure_list(request.args['uuid']))
        elif 'filter' in request.args:
            query = build_hosts_filter(Hosts, request.args['filter'])
        else:
            query = ~(Hosts.uuid.is_null())

        if 'has_errors' in request.args and request.args['has_errors']:
            query = query & (Hosts.host_status == 'ERROR')
        if 'need_upgrade' in request.args and request.args['need_upgrade']:
            query = query & (Hosts.host_status.in_(['ERROR', 'TO-UPGRADE']))
        if 'reachable' in request.args and (request.args['reachable'] == '1'):
            query = query & (Hosts.reachable == 'OK')

        if 'groups' in request.args:
            groups = ensure_list(request.args.get('groups', ''))
            in_group = HostGroups.select(HostGroups.host).where(HostGroups.group_name == groups)
            query = query & (Hosts.uuid << in_group )

        if not_filter:
            query = ~ query

        limit = int(request.args.get('limit', 1000))


        result = []
        req = Hosts.select(*build_fields_list(Hosts, {col: 1 for col in columns})).limit(limit).order_by(SQL('last_seen_on desc NULLS LAST')).dicts().dicts()
        if query:
            req = req.where(query)

        result = list(req)

        if 'uuid' in request.args:
            if len(result) == 0:
                msg = u'No data found for uuid {}'.format(request.args['uuid'])
            else:
                msg = u'host data fields {} returned for uuid {}'.format(
                    u','.join(columns),
                    request.args['uuid'])
        elif 'filter' in request.args:
            if len(result) == 0:
                msg = u'No data found for filter {}'.format(
                    request.args['filter'])
            else:
                msg = u'{} hosts returned for filter {}'.format(
                    len(result),
                    request.args['filter'])
        else:
            if len(result) == 0:
                msg = u'No data found'
            else:
                msg = u'{} hosts returned'.format(len(result))

    except Exception as e:
        return make_response_from_exception(e)

    return make_response(
        result=result, msg=msg, status=200, request_time=time.time() - start_time)


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
        start_time = time.time()
        # build filter
        if 'uuid' in request.args:
            uuid = request.args['uuid']
        else:
            raise EWaptMissingParameter('Parameter uuid is missing')

        if 'field' in request.args:
            field = request.args['field']
            if not field in Hosts._meta.fields.keys() + ['installed_softwares', 'installed_packages', 'waptwua']:
                raise EWaptMissingParameter('Parameter field %s is unknown' % field)
        else:
            raise EWaptMissingParameter('Parameter field is missing')

        if field == 'installed_softwares':
            result = list(HostSoftwares.select().where(HostSoftwares.host == uuid).dicts())
        elif field == 'installed_packages':
            result = list(HostPackagesStatus.select().where(HostPackagesStatus.host == uuid).dicts())
        else:
            data = Hosts\
                .select(Hosts.uuid, Hosts.computer_fqdn, Hosts.fieldbyname(field))\
                .where(Hosts.uuid == uuid)\
                .dicts()\
                .first(1)

            if data is None:
                raise EWaptUnknownHost(
                    'Host {} not found in database'.format(uuid))
            result = data.get(field, None)
        msg = '{} data for host {}'.format(field, uuid)

    except Exception as e:
        if utils_devel_mode:
            raise
        return make_response_from_exception(e)

    if result is None:
        msg = 'No {} data for host {}'.format(field, uuid)
        success = False
        error_code = 'empty_data'
    else:
        success = True
        error_code = None

    return make_response(result=result, msg=msg, success=success,
                         error_code=error_code, status=200, request_time=time.time() - start_time)


@app.route('/api/v1/usage_statistics')
@requires_auth
def usage_statistics():
    """returns some anonymous usage statistics to give an idea of depth of use"""
    try:
        host_data = Hosts.select(
            fn.count(Hosts.uuid).alias('hosts_count'),
            fn.min(Hosts.last_seen_on).alias('oldest_query'),
            fn.max(Hosts.last_seen_on).alias('newest_query'),
        ).dicts().first()

        installed_packages = HostPackagesStatus.select(
            HostPackagesStatus.install_status,
            fn.count(HostPackagesStatus.id),
        )\
            .group_by(HostPackagesStatus.install_status)\
            .dicts()

        stats = {
            'hosts_count': host_data['hosts_count'],
            'oldest_query': host_data['oldest_query'],
            'newest_query': host_data['newest_query'],
            'packages_count_max': None,
            'packages_count_avg': None,
            'packages_count_ok': None,
            'hosts_count_has_error': None,
            'hosts_count_need_upgrade': None,
        }

    except:
        pass

    result = dict(
        uuid=conf['server_uuid'],
        platform=platform.system(),
        architecture=platform.architecture(),
        version=__version__,
        date=datetime2isodate(),
    )
    result.update(stats)
    return make_response(msg=_('Anomnymous usage statistics'), result=result)


@app.route('/api/v3/host_tasks_status')
@requires_auth
def host_tasks_status():
    """Proxy the get tasks status action to the client"""
    try:
        uuid = request.args['uuid']
        timeout = float(request.args.get('timeout', conf['client_tasks_timeout']))
        start_time = time.time()
        host_data = Hosts\
            .select(Hosts.uuid, Hosts.computer_fqdn, Hosts.wapt_status,
                    Hosts.listening_address,
                    Hosts.listening_port,
                    Hosts.listening_protocol,
                    Hosts.listening_timestamp,
                    )\
            .where(Hosts.uuid == uuid)\
            .dicts()\
            .first(1)
        if host_data and host_data.get('listening_address', None):
            result = []

            def result_callback(data):
                result.append(data)

            socketio.emit('get_tasks_status', request.args, room=host_data['listening_address'], callback=result_callback)

            #print('waiting...')
            wait_loop = timeout * 20
            while not result:
                wait_loop -= 1
                if wait_loop < 0:
                    raise EWaptTimeoutWaitingForResult('Timeout, client did not send result within %s s' % timeout)
                socketio.sleep(0.05)

            msg = 'Tasks status for %s' % host_data['computer_fqdn']
            return make_response(result[0]['result'],
                                 msg=msg,
                                 success=True,
                                 request_time=time.time() - start_time,
                                 )
        else:
            raise EWaptHostUnreachable('Host not connected, Websocket sid not in database')

    except Exception as e:
        return make_response_from_exception(e)


@app.route('/api/v3/trigger_host_action', methods=['POST'])
@requires_auth
def trigger_host_action():
    """Proxy some single shot actions to the client using websockets"""
    try:
        timeout = float(request.args.get('timeout', conf['client_tasks_timeout']))
        action_data = request.get_json()
        if action_data:
            if isinstance(action_data, list):
                for action in action_data:
                    if not action.get('signature', None):
                        raise EWaptBadSignature('One or some actions not signed, not relayed')
            else:
                if not action_data.get('signature', None):
                    raise EWaptBadSignature('Action is not signed, not relayed')
        else:
            raise EWaptForbiddden('Invalid action')
        # TODO : check signer before proxying ?
        last_uuid = None
        host = None

        if not isinstance(action_data, list):
            action_data = [action_data]

        result = []
        errors = []
        expected_result_count = len(action_data)
        #print 'expected %s' % expected_result_count

        def result_callback(data):
            #print data
            result.append(data)
            if not data.get('success',False):
                errors.append(data['msg'])
            #print 'now expected %s' % expected_result_count

        last_uuid = None
        hostnames = []

        for action in action_data:
            uuid = action['uuid']
            if last_uuid != uuid:
                host = Hosts.select(Hosts.computer_fqdn, Hosts.listening_address).where(
                    (Hosts.uuid == uuid) & (Hosts.listening_protocol == 'websockets')).first()
            if host:
                if not host.computer_fqdn in hostnames:
                    hostnames.append(host.computer_fqdn)
                socketio.emit('trigger_host_action', action, room=host.listening_address, callback=result_callback)
            else:
                expected_result_count -= 1
                errors.append('Host %s not connected, Websocket sid not in database' % uuid)
            last_uuid = uuid

        wait_loop = timeout * expected_result_count * 20
        while len(result) < expected_result_count:
            #print len(result)
            wait_loop -= 1
            if wait_loop < 0:
                raise EWaptTimeoutWaitingForResult('Timeout, client did not send result within %s s' % timeout)
            socketio.sleep(0.05)

        if errors and not result:
            raise EWaptHostUnreachable('Targeted host(s) is/are not connected')

        msg = []
        if errors:
            msg.extend(errors)
        msg.append('%s actions launched on %s' % (len(result), ','.join(hostnames),))

        #print result
        return make_response([r.get('result', None) for r in result],
                             msg=' '.join(msg),
                             success=len(errors) == 0)
    except Exception as e:
        return make_response_from_exception(e)


# SocketIO Callbacks / handlers

@socketio.on('trigger_update_result')
def on_trigger_update_result(result):
    """Return from update on client"""
    logger.debug('Trigger Update result : %s (uuid:%s)' % (result, request.args['uuid']))
    # send to all waptconsole warching this host.
    socketio.emit('trigger_update_result', result, room=request.args['uuid'], include_self=False)


@socketio.on('trigger_upgrade_result')
def on_trigger_upgrade_result(result):
    """Return from the launch of upgrade on a client"""
    logger.debug('Trigger Upgrade result : %s (uuid:%s)' % (result, request.args['uuid']))
    socketio.emit('trigger_upgrade_result', result, room=request.args['uuid'], include_self=False)


@socketio.on('trigger_install_packages_result')
def on_trigger_install_packages_result(result):
    logger.debug('Trigger install result : %s (uuid:%s)' % (result, request.args['uuid']))
    socketio.emit('trigger_install_packages_result', result, room=request.args['uuid'], include_self=False)


@socketio.on('trigger_remove_packages_result')
def on_trigger_remove_packages_result(result):
    logger.debug('Trigger remove result : %s (uuid:%s)' % (result, request.args['uuid']))
    socketio.emit('trigger_remove_packages_result', result, room=request.args['uuid'], include_self=False)


@socketio.on('reconnect')
@socketio.on('connect')
def on_waptclient_connect():
    try:
        uuid = request.args.get('uuid', None)
        if not uuid:
            raise EWaptForbiddden('Missing source host uuid')
        host_cert = Hosts.select(Hosts.host_certificate).where(Hosts.uuid == uuid).first()

        if host_cert and host_cert.host_certificate:
            host_certificate = SSLCertificate(crt_string=host_cert.host_certificate)
            host_cert_issuer = host_certificate.verify_claim(json.loads(request.args['login']), max_age_secs=60,required_attributes=['uuid'])
            logger.debug(u'Socket IO %s connect checked. issuer : %s' % ( request.sid,host_cert_issuer))
            pass
        else:
            raise EWaptForbiddden('Host is not registered or no host certificate found in database.')

        logger.info('Socket.IO connection from wapt client sid %s (uuid: %s)' % (request.sid, uuid))
        # stores sid in database
        hostcount = Hosts.update(
            server_uuid=get_server_uuid(),
            listening_timestamp=datetime2isodate(),
            listening_protocol='websockets',
            listening_address=request.sid,
            reachable='OK',
        ).where(Hosts.uuid == uuid).execute()
        wapt_db.commit()
        wapt_db.close()

        # if not known, reject the connection
        if hostcount == 0:
            raise EWaptForbiddden('Host is not registered')

    except Exception as e:
        logger.debug(u'Connect refused: %s' % e)
        wapt_db.rollback()
        wapt_db.close()
        return False


@socketio.on('wapt_pong')
def on_wapt_pong():
    try:
        print('wapt_pong')
        uuid = request.args.get('uuid', None)
        logger.info('Socket.IO pong from wapt client sid %s (uuid: %s)' % (request.sid, uuid))
        # stores sid in database
        hostcount = Hosts.update(
            server_uuid=get_server_uuid(),
            listening_timestamp=datetime2isodate(),
            listening_protocol='websockets',
            listening_address=request.sid,
            reachable='OK',
        ).where(Hosts.uuid == uuid).execute()
        print('sio pong: commit')
        wapt_db.commit()
        # if not known, reject the connection
        if hostcount == 0:
            # socketio.disconnect()
            return False
    except:
        wapt_db.rollback()


@socketio.on('disconnect')
def on_waptclient_disconnect():
    try:
        uuid = request.args.get('uuid', None)
        logger.info('Socket.IO disconnection from wapt client sid %s (uuid: %s)' % (request.sid, uuid))
        # clear sid in database
        Hosts.update(
            server_uuid=None,
            listening_timestamp=datetime2isodate(),
            listening_protocol=None,
            listening_address=None,
            reachable='UNREACHABLE',
        ).where((Hosts.uuid == uuid) & (Hosts.listening_address == request.sid)).execute()
        wapt_db.commit()
    except:
        wapt_db.rollback()


@socketio.on('join')
def on_join(data):
    room = request.args.get('uuid', None)
    if room:
        socketio.join_room(room)


@socketio.on('leave')
def on_leave(data):
    room = request.args.get('uuid', None)
    if room:
        socketio.leave_room(room)


@socketio.on_error()
def on_wapt_socketio_error(e):
    logger.critical('Socket IO : An error has occurred for sid %s, uuid:%s : %s' % (request.sid, request.args.get('uuid', None), repr(e)))


# end websockets

if __name__ == '__main__':
    usage = """\
    %prog [-c configfile] [--devel] [action]

    WAPT Server daemon.

    action is either :
      <nothing> : run service in foreground
      install   : install as a Windows service managed by nssm

    """

    parser = OptionParser(usage=usage, version='waptserver.py ' + __version__)
    parser.add_option(
        '-c',
        '--config',
        dest='configfile',
        default=DEFAULT_CONFIG_FILE,
        help='Config file full path (default: %default)')
    parser.add_option(
        '-l',
        '--loglevel',
        dest='loglevel',
        default=None,
        type='choice',
        choices=[
            'debug',
            'warning',
            'info',
            'error',
            'critical'],
        metavar='LOGLEVEL',
        help='Loglevel (default: warning)')
    parser.add_option(
        '-d',
        '--devel',
        dest='devel',
        default=False,
        action='store_true',
        help='Enable debug mode (for development only)')
    parser.add_option(
        '-w',
        '--without-apache',
        dest='without_apache',
        default=False,
        action='store_true',
        help="Don't install Apache http server for wapt (service WAPTApache)")

    (options, args) = parser.parse_args()
    app.config['CONFIG_FILE'] = options.configfile

    utils_set_devel_mode(options.devel)

    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
    setloglevel(logger, conf['loglevel'])

    if options.loglevel is not None:
        setloglevel(logger, options.loglevel)
    else:
        setloglevel(logger, conf['loglevel'])

    log_directory = os.path.join(wapt_root_dir, 'log')
    if not os.path.exists(log_directory):
        os.mkdir(log_directory)

    if platform.system() == 'Linux':
        hdlr = logging.handlers.SysLogHandler('/dev/log')
    else:
        hdlr = logging.FileHandler(os.path.join(log_directory, 'waptserver.log'))

    hdlr.setFormatter(
        logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(hdlr)

    # check wapt directories
    if not os.path.exists(conf['wapt_folder']):
        raise Exception('Folder missing : %s.' % conf['wapt_folder'])
    if not os.path.exists(conf['wapt_folder'] + '-host'):
        raise Exception('Folder missing : %s-host.' % conf['wapt_folder'])
    if not os.path.exists('%s-hostref' % conf['wapt_folder']):
        raise Exception('Folder missing : %s-hostref.' % conf['wapt_folder'])

    if args and args[0] == 'doctest':
        import doctest
        sys.exit(doctest.testmod())

    if args and args[0] == 'install':
        # pass optional parameters along with the command
        raise Exception('Wapt 1.5 serie does not currently support install on Windows')
        # install_windows_service()
        # sys.exit(0)

    if args and args[0] == 'test':
        # pass optional parameters along with the command
        test()
        sys.exit(0)

    logger.info('Waptserver starting...')
    port = conf['waptserver_port']
    while True:
        try:
            logger.info('Reset connections SID for former hosts on this server')
            hosts_count = Hosts.update(
                reachable='UNKNOWN',
                server_uuid=None,
                listening_protocol=None,
                listening_address=None,
            ).where(
                (Hosts.listening_protocol == 'websockets') & (Hosts.server_uuid == get_server_uuid())
            ).execute()
            wapt_db.commit()
            break
        except Exception as e:
            wapt_db.rollback()
            logger.critical('Trying to upgrade database structure, error was : %s' % repr(e))
            upgrade_db_structure()

    if not wapt_db.is_closed():
        wapt_db.close()

    if options.devel:
        socketio.run(app, host='0.0.0.0', port=port, debug=options.devel, use_reloader=options.devel)
    else:
        socketio.run(app, host='127.0.0.1', port=port, debug=options.devel, use_reloader=options.devel)
    logger.info('Waptserver stopped')
