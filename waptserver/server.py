#!/opt/wapt/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2020  Tranquil IT Systems http://www.tranquil.it
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
from __future__ import absolute_import
import sys
if __name__ == '__main__':
    # as soon as possible, we must monkey patch the library...
    # monkeypatching for eventlet greenthreads
    from eventlet import monkey_patch
    # os=False for windows see https://mail.python.org/pipermail/python-bugs-list/2012-November/186579.html
    if hasattr(sys,'getwindowsversion'):
        # interactive debug mode on PyScripter hang if tread is patched.
        if 'rpyc' in sys.modules:
            monkey_patch(os=False,thread=False)
        else:
            monkey_patch(os=False)
    else:
        monkey_patch()

import platform
import os

if platform.system() != 'Windows':
    import setproctitle
    setproctitle.setproctitle('waptserver')

from waptserver.config import __version__

import time
import json
import ujson
import logging
import logging.handlers
import ipaddress
import fnmatch
import zlib
import platform
import socket
import shutil
import tempfile
import traceback
import datetime
import re
import glob
import base64
import ldap3.utils

from optparse import OptionParser

from werkzeug.utils import secure_filename

from flask import request, Response, send_from_directory, session, g, redirect, render_template

from peewee import *
from playhouse.postgres_ext import *

from waptserver.model import Hosts, HostSoftwares, HostPackagesStatus, HostGroups, HostWsus, WsusUpdates, Packages
from waptserver.model import WaptUsers,WaptUserAcls
from waptserver.model import get_db_version, init_db, wapt_db, model_to_dict, update_host_data
from waptserver.model import upgrade_db_structure
from waptserver.model import load_db_config,wapt_db_connect,wapt_db_close,WaptDB
from waptserver.config import get_http_proxies,WAPTLOGGERS

from waptpackage import PackageEntry,WaptLocalRepo,EWaptBadSignature,EWaptMissingCertificate
from waptcrypto import SSLCertificate,SSLVerifyException,SSLCertificateSigningRequest,InvalidSignature,SSLPrivateKey,EWaptCryptoException
from waptcrypto import sha256_for_file,sha256_for_data
from waptcrypto import SSLCABundle,SSLCRL

from waptutils import datetime2isodate,ensure_list,Version,setloglevel

from waptserver.utils import EWaptAuthenticationFailure,EWaptForbiddden,EWaptHostUnreachable
from waptserver.utils import EWaptMissingParameter,EWaptTimeoutWaitingForResult,EWaptUnknownHost
from waptserver.utils import get_disk_space,jsondump
from waptserver.utils import get_dns_domain,get_wapt_edition,get_wapt_exe_version,wapt_root_dir

from waptserver.common import get_secured_token_generator,get_server_uuid
from waptserver.common import make_response,make_response_from_exception

from waptserver.app import app
from waptserver.auth import check_auth,change_admin_password,get_user_acls
from waptserver.decorators import requires_auth,authenticate,gzipped,require_wapt_db,wapt_db_readonly

import waptserver.config

import wakeonlan.wol

# socketio is loaded conditionally if iwe are running in app mode, not uwsgi mode
socketio = None
git_hash = ''
wapt_edition = ''

logger = logging.getLogger('waptserver')

try:
    from waptenterprise import auth_module_ad
except ImportError as e:
    logger.debug(u'LDAP Auth disabled: %s' % e)
    auth_module_ad = None

# Ensure that any created files have sane permissions.
# uWSGI implicitely sets umask(0).
try:
    os.umask(0o022)
except Exception:
    pass

ALLOWED_EXTENSIONS = set(['.wapt'])

# i18n
try:
    from flask_babel import Babel
    from flask_babel import gettext

    babel = Babel(app)

    @babel.localeselector
    def get_locale():
        browser_lang = request.accept_languages.best_match(['en', 'fr'])
        user_lang = session.get('lang', browser_lang)
        return user_lang

except ImportError:
    gettext = (lambda s: s)
    Babel = None
_ = gettext


try:
    from waptenterprise.waptserver import wsus,enterprise,repositories,repositories_socketio
    app.register_blueprint(wsus.wsus)
    app.register_blueprint(enterprise.enterprise)
    app.register_blueprint(repositories.repositories)
    app.register_blueprint(repositories_socketio.repositories_socketio)
    app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations;../waptenterprise/waptserver/translations'
except Exception as e:
    logger.info(str(e))
    wsus = False
    repositories = False
if app.conf['enable_store']:
    from waptenterprise.waptserver import store
    app.register_blueprint(store.store)

@app.teardown_request
def _db_close(error):
    """Closes the database again at the end of the request."""
    if wapt_db and not wapt_db.is_closed():
        logger.warning('waptdb was not closed after request. Used DB connections Count: %s' % len(wapt_db._in_use))
        # perhaps we should not cloe DB as request are runnong in background with same db connection ?
        #wapt_db_close()

@app.route('/lang/<language>')
def lang(language=None):
    session['lang'] = language
    return redirect('/')


@app.route('/')
def index():
    waptagent = os.path.join(app.conf['wapt_folder'], 'waptagent.exe')
    waptsetup = os.path.join(app.conf['wapt_folder'], 'waptsetup-tis.exe')
    waptdeploy = os.path.join(app.conf['wapt_folder'], 'waptdeploy.exe')

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
        space = get_disk_space(app.conf['wapt_folder'])
        if not space:
            raise Exception('Disk info not found')
        percent_free = (space[0] * 100) / space[1]
        if percent_free >= 20:
            disk_space_style = ''
        disk_space_str = str(percent_free) + '% free'
    except Exception as e:
        disk_space_str = 'error, %s' % str(e)


    if os.path.isfile(waptsetup):
        waptsetup_tis_url = 'wapt/waptsetup-tis.exe'
    else:
        waptsetup_tis_url = 'https://wapt.tranquil.it/wapt/releases/wapt-%s/waptsetup.exe' %  __version__

    if os.path.isfile(waptdeploy):
        waptdeploy_url = 'wapt/waptdeploy.exe'
    else:
        waptdeploy_url = 'https://wapt.tranquil.it/wapt/releases/wapt-%s/waptdeploy.exe' %  __version__

    data = {
        'wapt': {
            'server': {'status': __version__},
            'agent': {'status': agent_status, 'style': agent_style, 'sha256': agent_sha256},
            'setup': {'status': setup_status, 'style': setup_style, 'url':waptsetup_tis_url},
            'deploy': {'status': deploy_status, 'style': deploy_style, 'url':waptdeploy_url},
            'db': {'status': db_status},
            'disk_space': {'status': disk_space_str, 'style': disk_space_style},
        }
    }
    return render_template('index.html', data=data)

def sign_host_csr(host_certificate_csr):
    """Sign the CSR with server key and return a certificate for further host auth on nginx server

    Args:
        host_certificate_csr ()

    Returns:

    """
    host_cert = None
    if (app.conf['clients_signing_key'] and app.conf['clients_signing_certificate'] and
            os.path.isfile(app.conf['clients_signing_key']) and os.path.isfile(app.conf['clients_signing_certificate'])):
        signing_key = SSLPrivateKey(app.conf['clients_signing_key'])
        signing_cert = SSLCertificate(app.conf['clients_signing_certificate'])
        host_cert_lifetime = app.conf['client_certificate_lifetime']
        if app.conf['clients_signing_crl_url']:
            crl_urls = ensure_list(app.conf['clients_signing_crl_url'])
        else:
            crl_urls = None
        host_cert = signing_cert.build_certificate_from_csr(host_certificate_csr,signing_key,host_cert_lifetime,crl_urls=crl_urls)
    return host_cert

def check_host_cert(host_certificate):
    """Check if host_certificate is trusted by the server own CA,
    ie it has been signed by the server key

    Args:
        host_certificate (SSLCertificate): host certificate to check.

    Returns
        list: cert chain if OK. Raise exception if not approved. None if no certificate is defined on the server.

    """
    if app.conf['clients_signing_certificate'] and os.path.isfile(app.conf['clients_signing_certificate']):
        server_ca = SSLCABundle(app.conf['clients_signing_certificate'])
        return server_ca.check_certificates_chain(host_certificate)
    return None

def revoke_cert(host_certificate):
    if (app.conf['clients_signing_key'] and app.conf['clients_signing_certificate'] and app.conf['clients_signing_crl'] and \
            os.path.isfile(app.conf['clients_signing_key']) and os.path.isfile(app.conf['clients_signing_certificate'])):
        signing_key = SSLPrivateKey(app.conf['clients_signing_key'])
        signing_cert = SSLCertificate(app.conf['clients_signing_certificate'])
        server_ca = SSLCABundle(app.conf['clients_signing_certificate'])
        if server_ca.check_certificates_chain(host_certificate):
            crl = SSLCRL(app.conf['clients_signing_crl'],cakey=signing_key,cacert=signing_cert)
            crl.revoke_cert(host_certificate,crl_ttl_days = app.conf['clients_signing_crl_days'])
            crl.save_as_pem()
        else:
            logger.warning('certificate can not be revoked by this CA')


    return None

@app.route('/add_host_kerberos',methods=['HEAD','POST'])
@app.route('/add_host',methods=['HEAD','POST'])
def register_host():
    """Add a new host into database, and return registration info
    If path is add_host_kerberos, assume there is (already validated by NGINX) computer kerberos SPN in the user part of Authorization http header else
    if path is add_host, requires a valid user/password combination in Authorization http header
    If data contains a host_certificate_csr, sign it a returns it to the caller.


    Specific headers:
        'X-Signature':  base64 encoded signature of payload. Can be checked with public key in host_certificate_csr
                        required if 'allow_unsigned_status_data' conf is False
        'X-Signer': indication of signer (not authoritative)
        'Content-Encoding' : if == 'gzip', payload in decompressed before process
        'authorization' : basic auth
        'X-Forwarded-For' :


    Args:
        posted body (json encoded dict):
            uuid
            host_info.computer_fqdn
            host_certificate_csr
            host_certificate

    Returns:

    """

    # we have to be sure that nginx has filtered out the bogus authorization header set by nginx kerberos module
    if session.get('auth_method') == 'kerb' and not request.path in ('/add_host_kerberos'):
        return authenticate()

    if request.method == 'HEAD':
        return ''

    try:
        starttime = time.time()

        # unzip if post data is gzipped
        if request.headers.get('Content-Encoding') == 'gzip':
            raw_data = zlib.decompress(request.data)
        else:
            raw_data = request.data

        data = ujson.loads(raw_data)
        if not data:
            raise Exception('register_host: No data supplied')

        uuid = data['uuid']
        if not uuid:
            raise Exception('register_host: No uuid supplied')
        logger.info(u'Trying to register host %s' % (uuid,))

        # get request signature
        signature_b64 = request.headers.get('X-Signature', None)
        if signature_b64:
            signature = signature_b64.decode('base64')
        else:
            signature = None
        if not signature and not app.conf['allow_unsigned_status_data']:
            raise Exception('register_host: Missing signature')
        signer = request.headers.get('X-Signer', None)

        # Registering a host requires authentication; Either signatue is Ok or Kerberos or basic
        authenticated_user = None
        registration_auth_user = None

        # 'host' is for pre wapt pre 1.4
        computer_fqdn =  (data.get('host_info',None) or data.get('host',{})).get('computer_fqdn',None)

        auth_result = None
        host_cert = None

        # with nginx kerberos module, auth user name is stored as Basic auth in the
        # 'Authorisation' header with password 'bogus_auth_gss_passwd'
        if request.path=='/add_host_kerberos' and (app.conf['use_kerberos'] or not app.conf['allow_unauthenticated_registration']):
            auth = request.authorization
            if auth and auth.password == 'bogus_auth_gss_passwd' and auth.username:
                    authenticated_user = auth.username.lower().replace('$', '')
                    dns_domain = '.'.join(socket.getfqdn().split('.')[1:])
                    authenticated_user = '%s.%s' % (authenticated_user, dns_domain)
                    logger.debug(u'Kerberos authenticated user %s for %s' % (authenticated_user,computer_fqdn))
                    registration_auth_user = u'kerb:%s' % authenticated_user
                    auth_date = datetime.datetime.utcnow().isoformat()
                    logger.debug(u'User %s authenticated using kerberos' % (authenticated_user,))
                    auth_result = dict(auth_method = 'kerb',user=authenticated_user,auth_date=auth_date)
            else:
                authenticated_user = None

        # kerberos has failed or kerberos is not enabled
        if not authenticated_user:
            # get authentication from basic auth. Check against waptserver admins
            auth_result = check_auth(request = request, session=session, methods=['admin','passwd','ldap'])
            if auth_result:
                # assume authenticated user is the fqdn provided in the data
                logger.debug(u'Authenticated registration for %s with user %s' % (computer_fqdn,auth_result['user']))
                authenticated_user = computer_fqdn
                session.update(**auth_result)
                registration_auth_user = u'%s:%s' % (auth_result['auth_method'],auth_result['user'])


            # if certificate is properly signed, we can trust it without using database
            if 'host_certificate' in data:
                try:
                    untrusted_host_cert = SSLCertificate(crt_string=data['host_certificate'])
                    if (untrusted_host_cert.issuer_subject_hash != untrusted_host_cert.subject_hash and
                            (untrusted_host_cert.cn.lower() == computer_fqdn.lower() or untrusted_host_cert.cn.lower() == uuid.lower())):
                        # we can check if issuer is myself...
                        cert_chain = check_host_cert(untrusted_host_cert)
                        if cert_chain:
                            host_cert = untrusted_host_cert
                            authenticated_user = computer_fqdn
                            registration_auth_user = u'Cert:%s' % host_cert.cn

                except Exception as e:
                    logger.warning(u'Unable to trust supplied host certificate: %s' % (repr(e),))
                    host_cert = None

        # db stuff
        with WaptDB():
            with wapt_db.atomic() as trans:
                if not host_cert and not authenticated_user:
                    existing_host = Hosts.select(Hosts.host_certificate, Hosts.computer_fqdn).where(Hosts.uuid == uuid).first()
                    if existing_host and existing_host.host_certificate:
                        # check if existing record, and in this case, check signature with existing certificate
                        host_cert = SSLCertificate(crt_string=existing_host.host_certificate)

                # if data is properly signed by a trusted certificate, consider we are authenticated.
                if host_cert and not authenticated_user:
                    try:
                        authenticated_user = host_cert.verify_content(sha256_for_data(raw_data), signature)
                    except (InvalidSignature,SSLVerifyException) as e:
                        authenticated_user = None

                if not authenticated_user and app.conf['allow_unauthenticated_registration']:
                    logger.warning(u'Unauthenticated registration for %s' % computer_fqdn)
                    # assume authenticated user is the fqdn provided in the data
                    authenticated_user = computer_fqdn #request.headers.get('X-Forwarded-For',None)
                    registration_auth_user = 'None:%s' % request.headers.get('X-Forwarded-For',None)

                if not authenticated_user:
                    # use basic auth
                    return authenticate()

            if not authenticated_user:
                raise EWaptAuthenticationFailure('register_host : Missing authentication header')

            if not app.conf['allow_unauthenticated_registration']:
                logger.debug(u'Authenticated computer %s with user %s ' % (computer_fqdn,authenticated_user,))
                # check that authenticated user matches the CN of the certificate supplied in post data
                supplied_host_cert = SSLCertificate(crt_string=data['host_certificate'])
                if not (supplied_host_cert.cn.lower() == computer_fqdn.lower() or supplied_host_cert.cn.lower() == uuid.lower()):
                    raise EWaptAuthenticationFailure('register_host : Mismatch between certificate Certificate commonName %s and supplied fqdn or uuid %s / %s' % (supplied_host_cert.cn,computer_fqdn,uuid))
            else:
                supplied_host_cert = None

            data['last_seen_on'] = datetime2isodate()

            # sign the CSR if present
            valid_auth = authenticated_user is not None # auth_result and auth_result['auth_method'] in ['admin','passwd','ldap','kerb']
            if 'host_certificate_signing_request' in data and valid_auth:
                host_certificate_csr = SSLCertificateSigningRequest(csr_pem_string=data['host_certificate_signing_request'])
                if host_certificate_csr.cn.lower() == computer_fqdn.lower() or host_certificate_csr.cn.lower() == uuid.lower():
                    logger.info(u'Authenticated user: %s , Registration auth user: %s Issuing a signed certificate for %s' % (authenticated_user,registration_auth_user,host_certificate_csr.cn))
                    signed_host_cert = sign_host_csr(host_certificate_csr)
                    if signed_host_cert:
                        data['host_certificate'] = signed_host_cert.as_pem()
                else:
                    logger.warning(u'Authenticated user: %s , Registration auth user %s asking a signed certificate for %s but registering as %s or %s. Refused.' % (authenticated_user,registration_auth_user,host_certificate_csr.cn,computer_fqdn,uuid))

                if registration_auth_user:
                    data['registration_auth_user'] = registration_auth_user

            db_data = update_host_data(data,app.conf)
            # return back signed host certificate
            if 'host_certificate_signing_request' in data and valid_auth:
                db_data['host_certificate'] = data['host_certificate']

            result = db_data
            message = 'register_host'
            return make_response(result=result, msg=message, request_time=time.time() - starttime)

    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('add_host failed %s' % (repr(e)))
        return make_response_from_exception(e)


@app.route('/update_host',methods=['HEAD','POST'])
@require_wapt_db
def update_host():
    """Update localstatus of computer, and return known registration info
    Requires a base64 encoded signature in X-Signature http header (unless allow_unsigned_status_data config is True)
    This signature is checked using the host certificate stored in Hosts.host_certificate field in database.
    Data is supplied as a JSon (optionnaly gzipped) POST data.
    Required keys are:
        uuid
        host_info.computer_fqdn

    """
    if request.method == 'HEAD':
        return ''

    try:
        starttime = time.time()

        # unzip if post data is gzipped
        if request.headers.get('Content-Encoding') == 'gzip':
            raw_data = zlib.decompress(request.data)
        else:
            raw_data = request.data

        data = ujson.loads(raw_data)
        if not data:
            raise Exception('register_host: No data supplied')

        uuid = data['uuid']
        if not uuid:
            raise Exception('register_host: No uuid supplied')

        # 'host' is for pre wapt pre 1.4
        computer_fqdn =  (data.get('host_info',None) or data.get('host',{})).get('computer_fqdn',None)

        logger.info(u'updating host status %s (%s), data:%s' % (uuid,computer_fqdn,list(data.keys())))

        # get request signature
        signature_b64 = request.headers.get('X-Signature', None)
        if signature_b64:
            signature = signature_b64.decode('base64')
        else:
            signature = None

        if not signature and not app.conf['allow_unsigned_status_data']:
            raise Exception('register_host: Missing signature')
        signer = request.headers.get('X-Signer', None)

        # check if data is for the registered host
        existing_host = Hosts.select(Hosts.uuid, Hosts.host_certificate, Hosts.computer_fqdn).where(Hosts.uuid == uuid).first()

        if not existing_host or not existing_host.host_certificate:
            raise EWaptMissingCertificate(
                'You try to update status of an unknown host %s (%s). Please register first.' % (uuid, computer_fqdn))

        host_cert = SSLCertificate(crt_string=existing_host.host_certificate)
        if 'computer_fqdn' in data and not (host_cert.cn.lower() == computer_fqdn.lower() or  host_cert.cn.lower() == uuid.lower()):
            raise EWaptUnknownHost('Supplied hostname or uuid does not match known certificate CN, aborting')

        if signature:
            logger.debug(u'About to check supplied data signature with certificate %s' % host_cert.cn)
            try:
                host_cert_cn = host_cert.verify_content(sha256_for_data(raw_data), signature)
            except Exception as e:
                # for pre 1.5 wapt clients
                host_cert_cn = 'unknown'
                if not app.conf['allow_unsigned_status_data']:
                    raise
            logger.info(u'Data successfully checked with certificate CN %s for %s' % (host_cert_cn, uuid))
            if existing_host and not (host_cert_cn.lower() == existing_host.computer_fqdn.lower() or host_cert_cn.lower() == existing_host.uuid.lower()):
                raise Exception('update_host: mismatch between host certificate DN %s and existing host hostname %s' % (host_cert_cn,existing_host.computer_fqdn))
        elif app.conf['allow_unsigned_status_data']:
            logger.warning(u'No signature for supplied data for %s,%s upgrade the wapt client.' % (uuid,computer_fqdn))
        else:
            raise Exception(u'update_host: Invalid request')

        # be sure to not update host certificate
        if 'host_certificate' in data and not app.conf['allow_unsigned_status_data']:
            del data['host_certificate']

        data['last_seen_on'] = datetime2isodate()
        db_data = update_host_data(data,app.conf)

        result = db_data
        message = 'update_host'

        return make_response(result=result, msg=message, request_time=time.time() - starttime)

    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('update_host failed %s' % (repr(e)))
        return make_response_from_exception(e)

@app.route('/get_websocket_auth_token',methods=['HEAD','POST'])
def get_websocket_auth_token():
    """Returns a token for the authentication of websocket

    Http headers:
        Content-Encoding : can be gzip
        X-Signature :

    Args:
       None

    Post data (json):
        uuid (str) : host requesting a token
        purpose (str): must be websocket

    Returns:
        "success": bool
        "msg": str
        "result": dict
            "authorization_token": str
        "error": str
    """
    if request.method == 'HEAD':
        return ''
    try:
        starttime = time.time()
        # unzip if post data is gzipped
        if request.headers.get('Content-Encoding') == 'gzip':
            raw_data = zlib.decompress(request.data)
        else:
            raw_data = request.data

        data = ujson.loads(raw_data)
        if not data:
            raise EWaptAuthenticationFailure('No data supplied')

        uuid = data['uuid']
        if not uuid:
            raise EWaptAuthenticationFailure('No uuid supplied')

        if data.get('purpose') != 'websocket':
            raise EWaptAuthenticationFailure('Bad purpose')

        with WaptDB():
            existing_host = Hosts.select(Hosts.uuid, Hosts.host_certificate, Hosts.computer_fqdn).where(Hosts.uuid == uuid).first()
            if not existing_host or not existing_host.host_certificate:
                raise EWaptAuthenticationFailure('Unknown host UUID %s. Please register first.' % (uuid, ))

            auth_result = check_auth(request=request,session=session,methods=['ssl','token'])
            if not auth_result:
            # get request signature
                signature_b64 = request.headers.get('X-Signature', None)
                if signature_b64:
                    signature = signature_b64.decode('base64')
                else:
                    raise EWaptAuthenticationFailure('No signature in request')
                host_cert = SSLCertificate(crt_string=existing_host.host_certificate)
                try:
                    host_cert_cn = host_cert.verify_content(sha256_for_data(raw_data), signature)
                except Exception as e:
                    raise EWaptAuthenticationFailure(u'Request signature verification failed: %s' % e)
            else:
                user = auth_result['user']
                if user != uuid:
                    raise EWaptAuthenticationFailure(u'Authentication does not match required uuid %s' % uuid)

            token_gen = get_secured_token_generator()
            result = {
                'authorization_token': token_gen.dumps({'uuid':uuid,'server_uuid':get_server_uuid()}),
                }

            with wapt_db.atomic() as trans:
                # stores sid in database
                Hosts.update(
                    server_uuid=get_server_uuid(),
                    listening_timestamp=datetime2isodate(),
                    last_seen_on=datetime2isodate()
                ).where(Hosts.uuid == uuid).execute()

            message = 'Authorization token'
            return make_response(result=result, msg=message, request_time=time.time() - starttime)

    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('Get_websocket_auth_token failed %s' % (repr(e)))
        return make_response_from_exception(e)


def get_repo_packages():
    """Returns list of package entries for this server main packages repository

    Returns:
        list: of PackageEntry
    """
    if not hasattr(g,'packages') or g.packages is None:
        try:
            g.packages = WaptLocalRepo(app.conf['wapt_folder'])
        except Exception as e:
            g.packages = None
    return g.packages


def allowed_file(filename):
    """Ensure filename is safe and ascii only
    """
    try:
        as_ascii = filename.decode('ascii')
        return filename == secure_filename(filename) and os.path.splitext(filename)[1] in ALLOWED_EXTENSIONS
    except:
        return False


@app.route('/api/v3/packages')
@requires_auth(['admin','view'])
def localrepo_packages():
    try:
        start_time = time.time()
        query = ensure_list(request.args.get('q',None),allow_none=True)
        local_repo = WaptLocalRepo(app.conf['wapt_folder'])
        packages = local_repo.search(searchwords=query,newest_only=True,exclude_sections=['group','unit','host','restricted','profile'])
        return make_response(packages,
                             msg = '%s packages in local repository matching the keywords %s' % (len(packages),query),
                             request_time=time.time() - start_time)
    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('localrepo_packages %s' % (repr(e)))
        return make_response_from_exception(e)

@app.route('/api/v3/known_packages')
@requires_auth(['admin','view'])
@require_wapt_db
def known_packages():
    """Returns list of known packages metadata from database

    Args:
        exclude_sections (csv str): packages section to exclude from result.
                                    default 'unit,host,profile' are excluded

    Returns:
        dict : result

    """
    try:
        start_time = time.time()
        exclude_sections = ensure_list(request.args.get('exclude_sections','unit,host,profile'))
        if exclude_sections:
            where = ~ Packages.section.in_(exclude_sections)
        else:
            where = None

        packages = Packages.select(Packages.package,fn.MAX(Packages.signature_date).alias('last_signature_date'))
        if where:
            packages = packages.where(where)
        packages = list(packages.group_by(Packages.package).dicts())
        return make_response(packages,
                             msg = '%s known packages' % (len(packages),),
                             request_time=time.time() - start_time)
    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('known_packages failed %s' % (repr(e)))
        return make_response_from_exception(e)

def read_trusted_certificates(trusted_certificates_folder=None):
    """Loads the certificates files from trusted_certificates_folder.
    Trusted certificate is the first certificate of each PEM file in trusted_certificates_folder
    Other certificates in PEM files can be used to build certificate chain

    Returns:
        SSLCABundle : trusted certs are in trusted dict attribute (indexed by fingerprint)
    """
    if not trusted_certificates_folder:
        return None
    if not os.path.isdir(trusted_certificates_folder):
        raise Exception(u'Trusted certificates folder %s does not exists' % trusted_certificates_folder)

    cabundle = SSLCABundle()
    cabundle.add_pems(trusted_certificates_folder,trust_first=True)
    return cabundle

def check_valid_signer(package,cabundle):
    """Check if the signer of package is in the trusted list of certificates in cabundle.

    Args:
        package (PackageEntry): package to check signer
        cabundle (SSLCABundle) : buncle of CA trusted certificate.

    Returns:
        list of SSLCertificate : trusted certificate chain.
    """
    with WaptDB():
        signer_certs = package.package_certificates()
        if package.has_file('setup.py'):
            # check if certificate has code_signing extended attribute
            if not signer_certs or not signer_certs[0].is_code_signing:
                raise EWaptForbiddden(u'The package %s contains setup.py code but has not been signed with a proper code_signing certificate' % package.package)
        if cabundle is not None:
            trusted_chain = cabundle.check_certificates_chain(signer_certs,check_is_trusted=True)
        else:
            trusted_chain = signer_certs

        # If it's host package, check if host is known to trust one of the signer cert in cert chain.
        if package.section == 'host':
            host = Hosts.select(Hosts.host_capabilities).where(Hosts.uuid==package.package)
            # get the list of trusted packages signers for this host
            packages_trusted_ca_fingerprints = Hosts.host_capabilities['packages_trusted_ca_fingerprints']
            if packages_trusted_ca_fingerprints:
                trusted_cert = None
                for signer_cert in trusted_chain:
                    #SSLCertificate.get_fingerprint('sha256').hexdigest()
                    if signer_cert.fingerprint in packages_trusted_ca_fingerprints:
                        trusted_cert = signer_cert
                        logger.info('Package %s trusted for signer %s issued by %s' % (package.package,signer_cert.cn,signer_cert.issuer_dn))
                        break
                if not trusted_cert:
                    raise EWaptForbiddden('Host matching package %s does not trusted signer certificate %s' % (package.package,trusted_chain[0].fingerprint))

        return trusted_chain

@app.route('/api/v3/upload_packages',methods=['HEAD','POST'])
@requires_auth(['admin','edit_host_package','edit_base_package','edit_group_package',
    'edit_unit_package','edit_wua_package','edit_profile_package','edit_self_service_package'])
@require_wapt_db
def upload_packages():
    """Handle the streamed upload of multiple packages

    Args:
        scanpackages : if 1, rescan packages, else only append new packages to packages index
        POST body are packages file handles

    Returns:
        Response: json message with keys:
                    'success' (bool)
                    'error_code' if success is False
                    'msg' (str)
                    'result' (data)
                    'request_time' (float)
    """
    class PackageStream(object):
        def __init__(self,stream,chunk_size=10*1024*1024):
            self.stream = stream
            self.chunk_size = chunk_size

        def save(self,target):
            with open(target, "wb") as f:
                chunk = self.stream.read(self.chunk_size)
                while len(chunk) > 0:
                    f.write(chunk)
                    chunk = self.stream.read(self.chunk_size)

    def read_package(packagefile,trusted_signers):
        """Reads the stream of a zipped package file and return the entry

        Args:
            packagefile (file): opened file like object seeked to the start of a wapt package (Zip file stream)

        Returns:
            PackageEntry

        """
        target = None
        try:
            wapt_folder = app.conf['wapt_folder']
            tmp_target = tempfile.mktemp(dir=wapt_folder,prefix='wapt')
            packagefile.save(tmp_target)
            # test if package is OK.
            entry = PackageEntry(waptfile=tmp_target)
            target_filename = entry.make_package_filename(with_md5sum=True)
            if not allowed_file(target_filename):
                raise EWaptForbiddden(u'Package filename / name is forbidden : %s' % target_filename)

            # check if package signer is authorized
            trusted_chain = check_valid_signer(entry,trusted_signers)
            if not trusted_chain:
                raise EWaptForbiddden(u'Package %s is not signed properly' % target_filename)

            logger.info(u'Package is trusted: %s' % trusted_chain)

            logger.debug(u'Saved package %s into %s' % (entry.asrequirement(),tmp_target))

            entry.filename = target_filename

            if entry.section == 'host':
                target = os.path.join(wapt_folder+'-host', target_filename)
            else:
                target = os.path.join(wapt_folder, target_filename)

            if os.path.isfile(target):
                os.unlink(target)
            logger.debug(u'Renaming package %s into %s' % (tmp_target,target))

            shutil.move(tmp_target, target)

            # for caller to get completed PackageEntry.
            entry.localpath = target

            # fix context on target file (otherwith tmp context is carried over)
            #logger.debug(subprocess.check_output('chcon -R -t httpd_sys_content_t %s' % target,shell=True))
            if entry.section == 'host':
                (added,removed) = HostGroups.sync_from_host_package(entry)
                if added or removed:
                    # immediate feedback in waptconsole
                    Hosts.update(host_status='TO-UPGRADE').where(Hosts.uuid == entry.package).execute()
            else:
                (rec,_isnew) = Packages.update_from_control(entry)

            return entry

        except Exception as e:
            logger.debug(traceback.format_exc())
            logger.critical(u'Error uploading package %s: %s' % (target,e,))
            errors.append(target)
            if os.path.isfile(tmp_target):
                os.unlink(tmp_target)
            raise

    if request.method == 'HEAD':
        return ''

    try:
        starttime = time.time()
        done = []
        errors = []
        errors_msg = []
        packages_index_result = None

        # load trusted signers
        trusted_signers = read_trusted_certificates(app.conf.get('trusted_signers_certificates_folder'))
        if request.method == 'POST':
            if request.files:
                files = request.files
                # multipart upload
                logger.info(u'Upload of %s packages' % len(files))
                for fkey in files:
                    try:
                        packagefile = request.files[fkey]
                        logger.info(u'Uploading package file : %s' % fkey)
                        if packagefile and allowed_file(packagefile.filename):
                            new_package = read_package(packagefile,trusted_signers)
                            # check if package signer is auhtorized for the hos
                            done.append(new_package)
                    except Exception as e:
                        logger.critical(u'Error uploading %s : %s' % (fkey,e))
                        errors.append(fkey)
                        errors_msg.append('%s : %s' % (fkey,e))
            else:
                # streamed upload
                packagefile = PackageStream(request.stream)
                # check if package signer is auhtorized for the hos
                new_package = read_package(packagefile,trusted_signers)
                done.append(new_package)


            if [e for e in done if e.section != 'host']:
                logger.debug(u'Update package index')
                if request.args.get('scanpackages','1') == '1':
                    repo = WaptLocalRepo(localpath=app.conf['wapt_folder'])
                    packages_index_result = repo.update_packages_index(proxies=get_http_proxies(app.conf))
                    if packages_index_result['errors']:
                        errors_msg.extend(packages_index_result['errors'])
                else:
                    packages_index_result = {'processed':[],'kept':None,'errors':None,'packages_filename':None}
                    repo = WaptLocalRepo(localpath=app.conf['wapt_folder'])
                    for pe in done:
                        packages_index_result['processed'].append(repo._append_package_to_index(pe))
            else:
                packages_index_result = None

        else:
            pass

        g.packages = None


        if repositories and app.conf.get('remote_repo_support'):
            repositories.update_file_tree_of_files(username=request.authorization.username)

        spenttime = time.time() - starttime
        return make_response(success=len(errors) == 0 and len(done)>0,
                             result=dict(done=done, errors=errors, packages_index_result = packages_index_result),
                             msg=_(u'{} Packages uploaded, {} errors.{}').format(len(done), len(errors),u'\n'.join(errors_msg)),
                             request_time=spenttime)

    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('upload_packages failed %s' % (repr(e)))
        return make_response_from_exception(e, status='500')


@app.route('/upload_host',methods=['HEAD','POST'])
@app.route('/api/v3/upload_hosts',methods=['HEAD','POST'])
@requires_auth(['admin','edit_host_package'])
@require_wapt_db
def upload_host():
    """Handle the upload of multiple host packages

    Args:

    Returns:
        Response: json message with keys:
                    'success' (bool)
                    'error_code' if success is False
                    'msg' (str)
                    'result' (data)
                    'request_time' (float)
    """
    if request.method == 'HEAD':
        return ''
    try:
        starttime = time.time()
        done = []
        errors = []
        if request.method == 'POST':
            # load trusted signers
            trusted_signers = read_trusted_certificates(app.conf.get('trusted_signers_certificates_folder'))

            #
            files = list(request.files.keys())
            logger.info(u'Upload of %s host packages' % len(files))
            for fkey in files:
                hostpackagefile = request.files[fkey]
                logger.debug(u'uploading host file : %s' % fkey)
                if hostpackagefile and allowed_file(hostpackagefile.filename):
                    filename = secure_filename(hostpackagefile.filename)
                    wapt_host_folder = os.path.join(app.conf['wapt_folder'] + '-host')
                    target = os.path.join(wapt_host_folder, filename)
                    tmp_target = tempfile.mktemp(dir=wapt_host_folder,prefix='wapt')
                    with wapt_db.atomic() as trans:
                        try:

                            # if encrypted host packages, store the clear copy in a protected area for further edit...
                            if app.conf['encrypt_host_packages']:
                                ref_target = os.path.join(app.conf['wapt_folder'] + '-hostref', filename)
                                hostpackagefile.save(ref_target)
                                entry = PackageEntry(waptfile=ref_target)
                            else:
                                # write directly clear zip to tmp_targert
                                hostpackagefile.save(tmp_target)
                                entry = PackageEntry(waptfile=tmp_target)

                            check_valid_signer(entry,trusted_signers)

                            # update database for filtering on direct dependencies of a host
                            HostGroups.sync_from_host_package(entry)

                            # get host cert to encrypt package with public key
                            if app.conf['encrypt_host_packages']:
                                host_id = entry.package
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
                            shutil.move(tmp_target, target)
                            # fix context on target file (otherwith tmp context is carried over)
                            #logger.debug(subprocess.check_output('chcon -R -t httpd_sys_content_t %s' % target,shell=True))

                            done.append(filename)

                        except Exception as e:
                            logger.debug(traceback.format_exc())
                            logger.critical(u'Error uploading package %s: %s' % (filename, e))
                            errors.append(filename)
                            trans.rollback()
                            if os.path.isfile(tmp_target):
                                os.unlink(tmp_target)
        else:
            pass

        spenttime = time.time() - starttime
        return make_response(success=len(errors) == 0,
                             result=dict(done=done, errors=errors),
                             msg=_('{} Host packages uploaded, {} errors').format(len(done), len(errors)),
                             request_time=spenttime)

    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('upload_host failed %s' % (repr(e)))
        return make_response_from_exception(e, status='201')


@app.route('/upload_waptsetup',methods=['HEAD','POST'])
@requires_auth(['admin'])
def upload_waptsetup():
    """Handle the upload of customized waptagent.exe into wapt repository
    """
    if request.method == 'HEAD':
        return ''
    waptagent = os.path.join(app.conf['wapt_folder'], 'waptagent.exe')
    logger.debug(u'Entering upload_waptsetup')
    tmp_target = None
    try:
        if request.method == 'POST':
            file = request.files['file']
            if file and 'waptagent.exe' in file.filename:
                filename = secure_filename(file.filename)
                tmp_target = os.path.join(app.conf['wapt_folder'], secure_filename('.' + filename))
                target = os.path.join(app.conf['wapt_folder'], secure_filename(filename))
                file.save(tmp_target)
                if not os.path.isfile(tmp_target):
                    result = dict(status='ERROR', message=_('Problem during upload'))
                else:
                    shutil.move(tmp_target, target)
                    result = dict(status='OK', message=_('{} uploaded').format((filename,)))

                    if repositories and app.conf.get('remote_repo_support'):
                        repositories.update_file_tree_of_files(username=request.authorization.username)
            else:
                result = dict(status='ERROR', message=_('Wrong file name (version conflict?)'))
        else:
            result = dict(status='ERROR', message=_('Unsupported method'))
    except:
        e = sys.exc_info()
        if tmp_target and os.path.isfile(tmp_target):
            os.unlink(tmp_target)
        result = dict(status='ERROR', message=_('unexpected: {}').format((e,)))
    return Response(response=ujson.dumps(result),
                    status=200,
                    mimetype='application/json')


@app.route('/api/v3/change_password',methods=['HEAD','POST'])
@requires_auth(['admin'])
def change_password():
    """Handle change of admin master password"""
    if request.method == 'POST':
        try:
            post_data = request.get_json()
            if 'user' in post_data and 'password' in post_data:
                if check_auth(username = post_data['user'], password = post_data['password'], session=session, methods=['admin']):
                    # change master password
                    if 'new_password' in post_data and post_data['user'] == 'admin':
                        if len(post_data['new_password']) < app.conf.get('min_password_length',10):
                            raise EWaptForbiddden('The password must be at least %s characters' % app.conf.get('min_password_length',10))
                        change_admin_password(post_data['new_password'])
                        msg = 'Password for %s updated successfully' % post_data['user']
                    else:
                        raise EWaptMissingParameter('Bad or missing parameter')
                else:
                    raise EWaptAuthenticationFailure('Bad user or password')
            else:
                raise EWaptMissingParameter('Missing parameter')
            return make_response(result=msg, msg=msg, status=200)
        except Exception as e:
            logger.debug(traceback.format_exc())
            logger.critical('change_password failed %s' % (repr(e)))
            return make_response_from_exception(e)


@app.route('/api/v3/login', methods=['HEAD', 'POST', 'GET'])
@app.route('/login', methods=['HEAD', 'POST', 'GET'])
def login():
    if request.method == 'HEAD':
        return ''
    error = ''
    result = None
    starttime = time.time()
    try:
        user = None,
        password = None

        # legacy
        if request.method == 'POST' :
            post_data = request.get_json()
            if request.headers.get('Content-Encoding') == 'gzip':
                raw_data = zlib.decompress(request.data)
            else:
                raw_data = request.data
            post_data = ujson.loads(raw_data)
            if post_data is not None:
                # json auth from waptconsole
                user = post_data.get('user')
                password = post_data.get('password')
        else:
            # html form auth
            user = request.args.get('user')
            password = request.args.get('password')

        session.clear()
        auth_result = check_auth(username = user, password = password, session=session, request = request, methods=['admin','ldap'])
        if not auth_result:
            return authenticate()

        # if basic auth, user was in authorization header
        user = auth_result['user']
        token_gen = get_secured_token_generator()

        with WaptDB():
            if auth_result['auth_method'] in ('ldap') and app.conf['auto_create_ldap_users']:
                # add ACL
                (user_data,_created) = WaptUsers.get_or_create(name=user)
                if _created or user_data.user_fingerprint_sha1 is None:
                    user_data.user_fingerprint_sha1 = user
                    user_data.save()
                (user_acls_rec,_created) = WaptUserAcls.get_or_create(user_fingerprint_sha1=user,perimeter_fingerprint='*')
                if _created:
                    user_acls_rec.acls=['admin']
                    user_acls_rec.save()
            else:
                user_data = WaptUsers.get(name=user)

            user_acls = get_user_acls(user_data.user_fingerprint_sha1)
            auth_result['user_acls'] = user_acls
            session.update(** auth_result)

            token_content = dict(
                user = auth_result['user'],
                auth_method = auth_result['auth_method'],
                auth_date = auth_result['auth_date'],
                server_uuid = get_server_uuid(),
                user_acls = user_acls,
                user_fingerprint_sha1 = user_data.user_fingerprint_sha1,
                )

            try:
                hosts_count = Hosts.select(fn.COUNT(Hosts.uuid)).tuples().first()[0] # pylint: disable=no-value-for-parameter
            except:
                hosts_count = None

        result = dict(
            auth_result = auth_result,
            user_acls = user_acls,
            token = token_gen.dumps(token_content),
            server_uuid = get_server_uuid(),
            version=__version__,
            hosts_count = hosts_count,
            server_domain = get_dns_domain(),
            edition = get_wapt_edition(),
            #client_headers = request.headers,
        )
        session.update(**auth_result)
        msg = 'Authentication OK'
        spenttime = time.time() - starttime

        return make_response(result=result, msg=msg, status=200,request_time=spenttime)
    except Exception as e:
        if 'auth_token' in session:
            del session['auth_token']
        logger.debug(traceback.format_exc())
        logger.critical('login failed %s' % (repr(e)))
        return make_response_from_exception(e)

@app.route('/api/v3/logout',methods=['HEAD','POST','GET'])
def logout():
    if request.method == 'HEAD':
        return ''
    session.clear()
    return make_response(result=None, msg='logout', status=200)


@app.route('/api/v3/login_self_service', methods=['POST'])
@app.route('/login_self_service', methods=['POST'])
def login_self_service():
    """ Logs user in and returns the groups they belong to. For the option use_server_auth. """

    try:
        starttime = time.time()
        post_data = request.get_json()
        if request.headers.get('Content-Encoding') == 'gzip':
            raw_data = zlib.decompress(request.data)
        else:
            raw_data = request.data

        post_data = ujson.loads(raw_data)

        user = post_data.get('user')
        password = post_data.get('password')
        groups = post_data.get('groups')

        if user and password and groups :
            result = auth_module_ad.check_credentials_ad(app.conf, user, password, [], groups)
            msg = 'Self service authentication'
            spenttime = time.time() - starttime
            return make_response(result=result, msg=msg, status=200,request_time=spenttime)
        else:
            msg = 'Missing arguments'
            spenttime = time.time() - starttime
            return make_response(result={"success":False,'groups':[],'error':True,'msg':msg},msg=msg, status=200,request_time=spenttime)


    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('login self-service failed %s' % (repr(e)))
        return make_response_from_exception(e)


@app.route('/api/v3/packages_delete',methods=['HEAD','POST'])
@requires_auth(['admin','edit_host_package','edit_base_package','edit_group_package'])
@require_wapt_db
def packages_delete():
    """Removes a list of packages by filenames
    After removal, the repository package index "Packages" is updated.

    Args:
        POST body is a json list of packages filenames

    """
    if request.method == 'HEAD':
        return ''
    errors = []
    deleted = []

    if request.method == 'POST':
        filenames = request.get_json()
        listpackage=[]
        for filename in filenames:
            try:
                if not allowed_file(filename):
                    raise EWaptForbiddden(u'Bad filename: %s' % filename)
                package_path = os.path.join(app.conf['wapt_folder'], secure_filename(filename))
                if os.path.isfile(package_path):
                    package = PackageEntry(waptfile=package_path)
                    listpackage.append(package)
                    #package_uuid = package.package_uuid
                    os.unlink(package_path)
                    deleted.append(filename)

                    #if package_uuid:
                    #    Packages.update(Packages.available == False).where(Packages.package_uuid == package_uuid).execute()
                    #else:
                    #    Packages.update(Packages.available == False).where(
                    #        (Packages.package == package.package) &
                    #        (Packages.version == package.version) &
                    #        (Packages.architecture == package.architecture) &
                    #        (Packages.locale == package.locale) &
                    #        (Packages.maturity == package.maturity)
                    #        ).execute()
                else:
                    errors.append(filename)
            except Exception as e:
                errors.append(filename)
        repo = WaptLocalRepo(localpath=app.conf['wapt_folder'])
        result = repo.update_packages_index(proxies=get_http_proxies(app.conf))
        for package in listpackage:
            icons_path = os.path.abspath(os.path.join(repo.localpath,'icons'))
            icon_fn = os.path.join(icons_path,u"%s.png" % package.package)
            if os.path.isfile(icon_fn):
                remicon = True
                for c in result['kept']:
                    if package.package in c:
                        remicon = False
                        pass
                if remicon:
                    try:
                        os.unlink(icon_fn)
                    except:
                        pass
    else:
        pass
    msg = ['%s packages deleted' % len(deleted)]

    if repositories and app.conf.get('remote_repo_support'):
        repositories.update_file_tree_of_files(username=request.authorization.username)

    if errors:
        msg.append('ERROR : %s packages could not be deleted' % len(errors))
    return make_response(result=result, msg='\n'.join(msg), status=200)


@app.route('/wapt/')
def wapt_listing():
    return render_template(
        'listing.html', dir_listing=os.listdir(app.conf['wapt_folder']))


@app.route('/wapt/<string:input_package_name>')
def get_wapt_package(input_package_name):
    package_name = secure_filename(input_package_name)
    r = send_from_directory(app.conf['wapt_folder'], package_name)
    if 'content-length' not in r.headers:
        r.headers.add_header(
            'content-length', int(os.path.getsize(os.path.join(app.conf['wapt_folder'], package_name))))
    return r


@app.route('/wapt/icons/<string:iconfilename>')
def serve_icons(iconfilename):
    """Serves a png icon file from /wapt/icons/ test waptserver"""
    iconfilename = secure_filename(iconfilename)
    icons_folder = os.path.join(app.conf['wapt_folder'], 'icons')
    r = send_from_directory(icons_folder, iconfilename)
    if 'content-length' not in r.headers:
        r.headers.add_header(
            'content-length', int(os.path.getsize(os.path.join(icons_folder, iconfilename))))
    return r

@app.route('/static/css/<string:fn>')
@app.route('/static/fonts/<string:fn>')
@app.route('/static/img/<string:fn>')
@app.route('/static/js/<string:fn>')
def serve_static(fn):
    """Serve"""
    rootdir = os.path.join(wapt_root_dir,'waptserver','static')
    if fn is not None:
        fn = request.path.split('/')[2:]
        r = send_from_directory(os.path.join(rootdir,secure_filename(fn[0])),secure_filename(fn[-1]))
        if 'content-length' not in r.headers:
            r.headers.add_header(
                'content-length', int(os.path.getsize(os.path.join(rootdir, fn))))
        return r


@app.route('/wapt-host/<string:input_package_name>')
def get_host_package(input_package_name):
    """Returns a host package (in case there is no apache static files server)"""
    # TODO straighten this -host stuff
    host_folder = app.conf['wapt_folder'] + '-host'
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
    group_folder = app.conf['wapt_folder'] + '-group'
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
    if request.method == 'HEAD':
        return ''
    return make_response(
        msg=_('WAPT Server running'), result=dict(
            version=__version__,
            api_root='/api/',
            api_version='v3',
            uuid=get_server_uuid(),
            date=datetime2isodate(),
            application_root=app.conf['application_root'],
            edition=wapt_edition,
            git_hash=git_hash,
            platform=platform.system(),
            architecture=platform.architecture()),
    )

@app.route('/api/v3/reset_hosts_sid', methods=['GET','HEAD','POST'])
@requires_auth(['admin','view'])
def reset_hosts_sid():
    """Launch a separate thread to check all reachable IP and update database with results.
    """
    if request.method == 'HEAD':
        return ''
    try:
        if not socketio:
            raise Exception('socketio unavailable')

        # in case a POST is issued with a selection of uuids to scan.
        if request.json is not None:
            uuids = request.json.get('uuids', None) or None
        else:
            uuids = None

        if uuids is not None:
            message = _(u'Hosts connection reset launched for %s host(s)' % len(uuids))
        else:
            message = _(u'Hosts connection reset launched for all hosts')

        def target(uuids):
            with wapt_db:
                logger.debug(u'Reset wsocket.io SID and timestamps of hosts')
                if uuids:
                    where_clause = Hosts.uuid.in_(uuids)
                    sids = [ s[0] for s in Hosts.select(Hosts.listening_address).where(where_clause).tuples()]
                    Hosts.update(reachable=None,listening_timestamp=None, listening_protocol=None).where(where_clause).execute()
                    for sid in sids:
                        socketio.emit('wapt_ping',room=sid)
                else:
                    Hosts.update(reachable=None,listening_timestamp=None, listening_protocol=None).where(Hosts.server_uuid == get_server_uuid()).execute()
                    socketio.emit('wapt_ping')

        socketio.start_background_task(target=target, uuids=uuids)

    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('reset_hosts_sid failed %s' % (repr(e)))
        return make_response_from_exception(e)
    return make_response(msg=message)

@app.route('/api/v3/trigger_wakeonlan', methods=['HEAD','POST'])
@requires_auth(['admin','trigger_host_action'])
@require_wapt_db
def trigger_wakeonlan():
    if request.method == 'HEAD':
        return ''
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
                for port in app.conf['wol_port'].split(','):
                    logger.debug(
                        _('Sending magic wakeonlan packets to {} for machine {} on port {} 255.255.255.255').format(
                            macs,
                            host['computer_fqdn'],
                            str(port.strip())
                        ))
                    wakeonlan.wol.send_magic_packet(*macs, port=int(port))
                    for line in host['host_info']['networking']:
                        if 'addr' in line:
                            for i in line['addr']:
                                if not 'broadcast' in i:
                                    continue
                                broadcast = i['broadcast']
                                if not '.' in broadcast:
                                    continue
                                logger.debug(
                                    _('Sending magic wakeonlan packets to {} for machine {} on port {} {}').format(
                                        macs,
                                        host['computer_fqdn'],
                                        str(port.strip()),
                                        broadcast
                                    ))

                                wakeonlan.wol.send_magic_packet(
                                    *
                                    macs,
                                    ip_address='%s' %
                                    broadcast,
                                    port=int(port.strip()))
                result.append(dict(uuid=host['uuid'], computer_fqdn=host['computer_fqdn'], mac_addresses=host['mac_addresses']))
        msg = _(u'Wakeonlan packets sent to {} machines.').format(len(result))
        result = result
        return make_response(result,
                             msg=msg,
                             success=True)
    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('trigger_wakeonlan failed %s' % (repr(e)))
        return make_response_from_exception(e)


@app.route('/api/v2/waptagent_version')
@requires_auth(['admin','view'])
def waptagent_version():
    try:
        start = time.time()
        waptagent = os.path.join(app.conf['wapt_folder'], 'waptagent.exe')
        agent_present, agent_version = get_wapt_exe_version(waptagent)
        waptagent_timestamp = None
        agent_sha256 = None
        if agent_present and agent_version is not None:
            agent_sha256 = sha256_for_file(waptagent)
            waptagent_timestamp = datetime2isodate(
                datetime.datetime.fromtimestamp(
                    os.path.getmtime(waptagent)))

        waptsetup = os.path.join(app.conf['wapt_folder'], 'waptsetup-tis.exe')
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
@requires_auth(['admin','trigger_host_action'])
def host_cancel_task():
    if not socketio:
        raise Exception('socketio not available')
    return proxy_host_request(request, 'trigger_cancel_task')


@app.route('/api/v1/groups')
@requires_auth(['admin','view'])
@require_wapt_db
def get_groups():
    """List of packages having section == group
    """
    try:
        groups = list(HostGroups.select(fn.DISTINCT(HostGroups.group_name).alias('package')).order_by(1).dicts())
        msg = '{} Packages for section group'.format(len(groups))

    except Exception as e:
        return make_response_from_exception(e)

    return make_response(result=groups, msg=msg, status=200)

@app.route('/api/v3/get_ad_groups')
@requires_auth()
@require_wapt_db
def get_ad_groups():
    """list of active directory computers groups

    Result:
        Response {"msg": "4 active directory computers groups", "result": ["xxx", "yyy", "ttt"], "success": true, "request_time": null}
    """
    starttime = time.time()
    try:
        adgroups = Hosts.select(fn.unnest(Hosts.computer_ad_groups).alias('groups')).where(~Hosts.computer_ad_groups.is_null()).distinct()
        groups = [r[0] for r in list(Select(columns=[adgroups.c.groups]).from_(adgroups).distinct().tuples().bind(wapt_db))]
        msg = '{} active directory computers groups'.format(len(groups))

    except Exception as e:
        return make_response_from_exception(e)

    return make_response(result=groups, msg=msg, status=200,request_time=time.time() - starttime)

@app.route('/api/v3/get_ad_ou')
@requires_auth(['admin','view'])
@require_wapt_db
def get_ad_ou():
    """List all the OU registered by hosts
    """
    try:
        starttime = time.time()
        result = [r[0] for r in Hosts.select(
            Hosts.computer_ad_ou,
            fn.COUNT(Hosts.uuid))
            .where(
            ~Hosts.computer_ad_ou.is_null())
            .group_by(Hosts.computer_ad_ou)
            .tuples()
            ]

        message = 'AD OU DN List'
        return make_response(result=result, msg=message, request_time=time.time() - starttime)

    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('get_ad_ou failed %s' % (repr(e)))
        return make_response_from_exception(e)

@app.route('/api/v3/get_ad_ou_split')
@requires_auth(['admin','view'])
@require_wapt_db
def get_ad_ou_split():
    """List all the OU registered by hosts
    """
    try:
        starttime = time.time()
        req = [r[0] for r in Hosts.select(
            Hosts.computer_ad_ou,
            fn.COUNT(Hosts.uuid))
            .where(
            ~Hosts.computer_ad_ou.is_null())
            .group_by(Hosts.computer_ad_ou)
            .tuples()
            ]
        result = [ldap3.utils.dn.parse_dn(elem) for elem in req if elem]

        message = 'AD OU DN List'
        return make_response(result=result, msg=message, request_time=time.time() - starttime)

    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('get_ad_ou failed %s' % (repr(e)))
        return make_response_from_exception(e)

@app.route('/api/v3/get_ad_sites')
@requires_auth(['admin','view'])
@require_wapt_db
def get_ad_sites():
    """List all the AD Sites registered by hosts
    """
    try:
        starttime = time.time()
        result = [r[0] for r in Hosts.select(fn.DISTINCT(Hosts.computer_ad_site)).where(~Hosts.computer_ad_site.is_null()).tuples()] #pylint: disable=too-many-function-args

        message = 'AD Sites List'
        return make_response(result=result, msg=message, request_time=time.time() - starttime)

    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('get_ad_sites failed %s' % (repr(e)))
        return make_response_from_exception(e)

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
                    HostSoftwares.key.regexp(ur'(?i)%s' % search_expr) | (HostSoftwares.name+' ('+HostSoftwares.version+')').regexp(ur'(?i)%s' % search_expr)))
            elif rootfield == 'installed_packages':
                clause = Hosts.uuid.in_(HostPackagesStatus.select(HostPackagesStatus.host).where(HostPackagesStatus.package.regexp(ur'(?i)%s' % search_expr)))
            elif rootfield in model._meta.fields: #
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
        if result is not None and not_filter:
            result = ~result # pylint: disable=invalid-unary-operand-type
        return result
    else:
        raise Exception('Invalid filter provided in query. Should be f1,f2,f3:regexp ')


@app.route('/api/v3/hosts_delete',methods=['HEAD','POST'])
@requires_auth(['admin','unregister_host'])
@require_wapt_db
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
    msg = []
    result = dict(files=[], records=[])

    if request.method == 'HEAD':
        return ''

    if request.method == 'POST':
        with wapt_db.atomic() as trans:
            try:
                # unzip if post data is gzipped
                if request.headers.get('Content-Encoding') == 'gzip':
                    raw_data = zlib.decompress(request.data)
                else:
                    raw_data = request.data

                post_data = ujson.loads(raw_data)
                if not post_data:
                    raise Exception('unregister_host: No data supplied')

                if 'uuids' in post_data:
                    query = Hosts.uuid.in_(ensure_list(post_data['uuids']))
                elif 'filter' in post_data:
                    query = build_hosts_filter(Hosts, post_data['filter'])
                else:
                    raise Exception('Neither uuid nor filter provided in query')


                if 'delete_packages' in post_data and post_data['delete_packages']:
                    selected = Hosts.select(Hosts.uuid, Hosts.computer_fqdn).where(query)
                    for host in selected:
                        result['records'].append(
                            dict(
                                uuid=host.uuid,
                                computer_fqdn=host.computer_fqdn))
                        uuid_hostpackage = os.path.join(app.conf['wapt_folder'] + '-host',host.uuid+'.wapt')
                        fqdn_hostpackage = os.path.join(app.conf['wapt_folder'] + '-host',host.computer_fqdn+'.wapt')

                        if os.path.isfile(uuid_hostpackage):
                            logger.debug(u'Trying to remove %s' % uuid_hostpackage)
                            if os.path.isfile(uuid_hostpackage):
                                os.remove(uuid_hostpackage)
                                result['files'].append(uuid_hostpackage)

                        if os.path.isfile(fqdn_hostpackage):
                            logger.debug(u'Trying to remove %s' % fqdn_hostpackage)
                            if os.path.isfile(fqdn_hostpackage):
                                os.remove(fqdn_hostpackage)
                                result['files'].append(fqdn_hostpackage)

                    msg.append(
                        '{} files removed from host repository'.format(len(result['files'])))

                if 'delete_inventory' in post_data and post_data['delete_inventory']:
                    if app.conf['clients_signing_crl']:
                        host_certs = Hosts.select(Hosts.host_certificate).where(query)
                        for host in host_certs:
                            if host.host_certificate:
                                cert = SSLCertificate(crt_string=host.host_certificate)
                                revoke_cert(cert)

                    remove_result = Hosts.delete().where(query).execute()
                    msg.append('{} hosts removed from DB'.format(remove_result))

            except Exception as e:
                logger.debug(traceback.format_exc())
                logger.critical('hosts_delete failed %s' % (repr(e)))
                trans.rollback()
                return make_response_from_exception(e)

        return make_response(result=result, msg='\n'.join(msg), status=200)



def build_fields_list(model, columns):
    """Returns a list of peewee fields
    """
    result = []
    for fname in columns:
        if fname in model._meta.fields:
            result.append(model._meta.fields[fname])
        elif fname == 'depends':
            # subquery with result aggregation.
            result.append(HostGroups.select(fn.STRING_AGG(HostGroups.group_name,',')).where(
                (HostGroups.host_id==Hosts.uuid)
                ).alias('depends'))
        else:
            # jsonb sub fields.
            parts = fname.split('/')
            root = parts[0]
            if root in model._meta.fields:
                path = ','.join(parts[1:])
                result.append(SQL("%s #>>'{%s}' as \"%s\" " % (root, path, fname)))
    return result


@app.route('/api/v3/hosts', methods=['HEAD','GET'])
@app.route('/api/v1/hosts', methods=['HEAD','GET'])
@requires_auth(['admin','view'])
@require_wapt_db
@gzipped
def get_hosts():
    """Get registration data of one or several hosts

    Args:
        has_errors (0/1): filter out hosts with packages errors
        need_upgrade (0/1): filter out hosts with outdated packages
        groups (csvlist of packages) : hosts with packages
        ad_groups (csvlist of ad group names) : hosts which belong to these AD groups
        ad_site (ad site name) : hosts which belong to these AD site
        columns (csvlist of columns) :
        uuid (csvlist of uuid): <uuid1[,uuid2,...]>): filter based on uuid
        filter (csvlist of field):regular expression: filter based on attributes
        not_filter (0,1):
        limit (int) : 1000
        trusted_certs_sha256 (csvlist): filter out machines based on their trusted package certs

    Returns:
        result (dict): {'records':[],'files':[]}

        query:
          uuid=<uuid>
        or
          filter=<csvlist of fields>:regular expression
    """
    if request.method == 'HEAD':
        return ''
    try:
        result = []
        msg = ''
        start_time = time.time()
        if request.method == 'GET':
            default_columns = ['host_status',
                               'last_update_status',
                               'reachable',
                               'wapt_version',
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
                               'os_version',
                               'registration_auth_user',
                               'platform',
                               'repositories',
                               'host_capabilities'
                               ]

            # keep only top tree nodes (mongo doesn't want fields like {'wapt':1,'wapt.listening_address':1} !
            # minimum columns
            columns = ['uuid',
                       'host_status',
                       'last_seen_on',
                       'last_update_status',
                       'computer_fqdn',
                       'computer_name',
                       'description',
                       'dnsdomain',
                       'server_uuid',
                       'listening_protocol',
                       'listening_address',
                       'listening_port',
                       'listening_timestamp',
                       'connected_users',
                       'registration_auth_user',
                       'wapt_version',
                       'host_capabilities'
                       ]
            other_columns = ensure_list(
                request.args.get(
                    'columns',
                    default_columns))

            # add request columns
            for fn in other_columns:
                if not fn in columns:
                    columns.append(fn)

            not_filter = request.args.get('not_filter', '0') == '1'

            query = None

            def and_query(q,not_filter=False):
                if query is None:
                    if not_filter:
                        return ~(q)
                    else:
                        return q
                else:
                    if not_filter:
                        return query & ~(q)
                    else:
                        return query & q

            # build filter
            if 'uuid' in request.args:
                query = and_query(Hosts.uuid.in_(ensure_list(request.args['uuid'])))
            elif 'filter' in request.args:
                query = and_query(build_hosts_filter(Hosts, request.args['filter']),not_filter)

            ## TODO : pylint does not like this block... raises 'Uninferable' object is not iterable
            if 'groups' in request.args:
                groups = ensure_list(request.args.get('groups', ''))
                in_group = HostGroups.select(HostGroups.host).where(HostGroups.group_name << groups)
                query = and_query(Hosts.uuid << in_group,not_filter)

            if 'trusted_certs_sha256' in request.args:
                trusted_certs_sha256 = ensure_list(request.args.get('trusted_certs_sha256', ''))
                certs_sub = None
                for cert_fingerprint in trusted_certs_sha256:
                    if certs_sub is None:
                        certs_sub = Hosts.authorized_certificates_sha256.contains(cert_fingerprint)
                    else:
                        certs_sub = certs_sub | Hosts.authorized_certificates_sha256.contains(cert_fingerprint)
                query = and_query(certs_sub,not_filter)

            if 'ad_site' in request.args:
                query = and_query(Hosts.computer_ad_site  == request.args.get('ad_site'),not_filter)

            if 'ad_groups' in request.args and request.args.get('ad_groups'):
                groups = request.args.get('ad_groups').split('||')
                or_list = Hosts.computer_ad_groups.contains(groups[0])
                for group in groups[1:]:
                   or_list = or_list | Hosts.computer_ad_groups.contains(group)
                query = and_query(or_list,not_filter)

            if 'organizational_unit' in request.args:
                ou_list = request.args.get('organizational_unit').split('||')
                if request.args.get('include_childs_ou','1') == '1':
                    or_list = Hosts.computer_ad_ou.endswith(ou_list[0])
                    for ou in ou_list[1:]:
                       or_list = or_list | Hosts.computer_ad_ou.endswith(ou)
                    query = and_query(or_list)
                else:
                    query = and_query(Hosts.computer_ad_ou.in_(ou_list))

            if 'has_errors' in request.args and request.args['has_errors']:
                query = and_query(Hosts.host_status == 'ERROR')
            if 'need_upgrade' in request.args and request.args['need_upgrade']:
                query = and_query(Hosts.host_status.in_(['ERROR', 'TO-UPGRADE']))
            if 'reachable' in request.args and (request.args['reachable'] == '1'):
                query = and_query(Hosts.reachable == 'OK')

            limit = int(request.args.get('limit', 1000))

            fields = build_fields_list(Hosts, columns)
            req = Hosts.select(*fields)
            req = req.limit(limit)

            req = req.order_by(SQL('last_seen_on desc NULLS LAST'))
            if query:
                req = req.where(query)

            result = list(req.dicts())

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

        return make_response(
            result=result, msg=msg, status=200, request_time=time.time() - start_time)
    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('get_hosts failed %s' % (repr(e)))
        return make_response_from_exception(e)


@app.route('/api/v1/host_data')
@requires_auth(['admin','view'])
@require_wapt_db
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
            if not field in list(Hosts._meta.fields.keys()) + ['installed_softwares', 'installed_packages', 'wsusupdates']: # pylint: disable=no-member
                raise EWaptMissingParameter('Parameter field %s is unknown' % field)
        else:
            raise EWaptMissingParameter('Parameter field is missing')

        if field == 'installed_softwares':
            result = list(HostSoftwares.select().where(HostSoftwares.host == uuid).order_by(HostSoftwares.created_on.desc()).dicts())
        elif field == 'installed_packages':
            result = list(HostPackagesStatus.select().where(HostPackagesStatus.host == uuid).order_by(HostPackagesStatus.created_on.desc()).dicts())
        elif field == 'wsusupdates':
            local_status = HostWsus.alias('local_status')
            fields = [
                local_status.id.alias('local_status_id'),
                local_status.status.alias('local_status_status'),
                local_status.allowed.alias('local_status_allowed'),
                local_status.installed.alias('local_status_installed'),
                local_status.install_date.alias('local_status_install_date'),
                local_status.present.alias('local_status_present'),
                local_status.hidden.alias('local_status_hidden'),
                local_status.downloaded.alias('local_status_downloaded'),
                local_status.history.alias('local_status_history'),
                WsusUpdates.update_id,
                WsusUpdates.title,
                WsusUpdates.update_type,
                WsusUpdates.kbids,
                WsusUpdates.severity,
                WsusUpdates.changetime,
                WsusUpdates.product,
                WsusUpdates.classification,
                WsusUpdates.download_urls,
                WsusUpdates.min_download_size,
                WsusUpdates.max_download_size,
                WsusUpdates.superseded_update_ids,
                WsusUpdates.security_bulletin_ids,
                WsusUpdates.is_mandatory,
                WsusUpdates.reboot_behaviour,
                WsusUpdates.can_request_user_input,
                WsusUpdates.requires_network_connectivity,
                WsusUpdates.languages,
                WsusUpdates.created_on,
                WsusUpdates.updated_on,
                WsusUpdates.downloaded_on,
                WsusUpdates.is_beta,
                WsusUpdates.release_notes,
                WsusUpdates.is_uninstallable,
                WsusUpdates.update_type,
                WsusUpdates.installation_impact,
                WsusUpdates.uninstallation_impact,
                ]
            result = list(local_status.select(*fields).join(WsusUpdates,'RIGHT OUTER').where(local_status.host == uuid).order_by(WsusUpdates.changetime).dicts()) # pylint: disable=no-member
        else:
            data = Hosts\
                .select(Hosts.uuid, Hosts.computer_fqdn, Hosts.fieldbyname(field))\
                .where(Hosts.uuid == uuid)\
                .dicts()\
                .first()

            if data is None:
                raise EWaptUnknownHost(
                    'Host {} not found in database'.format(uuid))
            result = data.get(field, None)
        msg = '{} data for host {}'.format(field, uuid)

    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('host_data failed %s' % (repr(e)))
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


@app.route('/api/v3/hosts_for_package',methods=['GET','POST'])
@requires_auth(['admin','view'])
@require_wapt_db
def hosts_for_package():
    """Returns list of hosts having the supplied package names

    Args:
        package (str) : (can be a csv list of package names)
        limit (int)

    Returns:
        list of Hosts

    """
    if request.method=='GET':
        limit = int(request.args.get('limit','1000'))
        packages = ensure_list(request.args.get('package'))
    else:
        # unzip if post data is gzipped
        if request.headers.get('Content-Encoding') == 'gzip':
            raw_data = zlib.decompress(request.data)
        else:
            raw_data = request.data

        post_data = ujson.loads(raw_data)
        limit = post_data.get('limit','1000')
        packages = post_data.get('package')

    result = list(
            HostPackagesStatus.select(
                HostPackagesStatus,
                Hosts.computer_name.alias('host_computer_name'),
                Hosts.computer_fqdn.alias('host_computer_fqdn'),
                Hosts.description.alias('host_description'),
                Hosts.connected_ips.alias('host_connected_ips'),
                Hosts.reachable,
                Hosts.connected_users.alias('host_connected_users'),
            )
            .where(
                HostPackagesStatus.package.in_(packages))
                .join(Hosts,'RIGHT OUTER')
                .limit(limit)
                .dicts())

    return make_response(msg = _('Hosts for packages %s, limit %s') % (packages,limit), result = result)


@app.route('/api/v3/packages_for_hosts',methods=['GET','POST'])
@requires_auth()
@require_wapt_db
def packages_for_hosts():
    """Returns list of aggregated packages status

    Args:
        host_uuids (str) : (can be a csv list of hosts uuid)
        install_status (str): csv list of install_status to return
        sections (str): csv list of packages section to return. If empty, all sections
        reachable : if set and =1, returns only reachable hosts status

        limit (int)

    Returns:
        list of Hosts

    """
    if request.method=='GET':
        limit = int(request.args.get('limit','1000'))
        host_uuids = ensure_list(request.args.get('host_uuids'))
        reachable = request.args.get('reachable','') == '1'
        install_status = ensure_list(request.args.get('install_status'))
        sections = ensure_list(request.args.get('sections'))
    else:
        # unzip if post data is gzipped
        if request.headers.get('Content-Encoding') == 'gzip':
            raw_data = zlib.decompress(request.data)
        else:
            raw_data = request.data

        post_data = ujson.loads(raw_data)
        limit = post_data.get('limit','1000')
        host_uuids = post_data.get('host_uuids')
        reachable = str(post_data.get('reachable','')) == '1'
        install_status = ensure_list(post_data.get('install_status'))
        sections = ensure_list(post_data.get('sections'))

    fields = []
    fields.extend([
                    HostPackagesStatus.package,
                    HostPackagesStatus.version,
                    HostPackagesStatus.section,
                    HostPackagesStatus.priority,
                    HostPackagesStatus.install_status,
        ])
    if not reachable:
        fields.append(Hosts.reachable)
    fields.append(SQL('json_agg(uuid) as host_uuids'))
    fields.append(fn.COUNT(Hosts.uuid))
    query = HostPackagesStatus.select(*fields)
    where = HostPackagesStatus.host.in_(host_uuids)
    if reachable:
        where = where & (Hosts.reachable =='OK')
    if install_status:
        where = where & HostPackagesStatus.install_status.in_(install_status)
    if sections:
        where = where & HostPackagesStatus.section.in_(sections)

    result = list(
            query.where(where)
            .join(Hosts,'RIGHT OUTER')
            .group_by(SQL(','.join([str(i) for i in range(1,len(fields)-1)])))  # 1,2,3,4
            .limit(limit)
            .dicts())

    return make_response(msg = _('Packages status for %s hosts, limit %s') % (len(host_uuids),limit), result = result)


def packages_install_stats():
    SQL = """select * from crosstab(
                'select package||'' (=''||version||'')'',install_status,count(*) as value from hostpackagesstatus where section <>''host'' group by 1,2 order by 1,2',
                'select status from (VALUES (''ERROR''),(''MISSING''),(''NEED-UPGRADE''),(''OK''),(''TO-UPDATE'')) t (status)')
            AS ct(computer_ad_ou varchar(255), "ERROR" integer,"MISSING" integer, "NEED-UPGRADE" integer, "OK" integer, "TO-UPGRADE" integer);
            """
    cur = wapt_db.execute_sql(SQL)


@app.route('/api/v3/trusted_signers_certificates',methods=['GET','DELETE','POST'])
@requires_auth(['admin'])
def trusted_signers_certificates():
    if request.method == 'GET':
        try:
            start_time = time.time()
            # load trusted signers
            trusted = read_trusted_certificates(app.conf.get('trusted_signers_certificates_folder'))
            # add other known certificates
            known_ssl_path = app.conf.get('known_certificates_folder')
            if os.path.isdir(known_ssl_path):
                trusted.add_pems(known_ssl_path)
            trusted_certs =  [{'cn':c.cn,
                        'issuer_cn':c.issuer_cn,
                        'subject_key_identifier':(c.subject_key_identifier or '').encode('hex'),
                        'authority_key_identifier': (c.authority_key_identifier or '').encode('hex'),
                        'fingerprint_sha1':c.get_fingerprint('sha1').encode('hex'),
                        'fingerprint':c.get_fingerprint('sha256').encode('hex'),
                        'pem':c.as_pem()} for c in trusted.trusted.values()]
            known_certificates =  [{'cn':c.cn,
                        'issuer_cn':c.issuer_cn,
                        'subject_key_identifier':(c.subject_key_identifier or '').encode('hex'),
                        'authority_key_identifier': (c.authority_key_identifier or '').encode('hex'),
                        'fingerprint_sha1':c.get_fingerprint('sha1').encode('hex'),
                        'fingerprint':c.get_fingerprint('sha256').encode('hex'),
                        'pem':c.as_pem()} for c in trusted.certificates()]

            msg = u'Trusted: %s, Known: %s' % (','.join([c.cn for c in trusted.trusted.values()]), ','.join([c.cn for c in trusted.certificates()]))
            result = {'trusted':trusted_certs,'certificates':known_certificates}
            return make_response(result=result, msg=msg, status=200, request_time=time.time() - start_time)

        except Exception as e:
            logger.debug(traceback.format_exc())
            logger.critical('trusted_signers_certificates %s' % (repr(e)))
            return make_response_from_exception(e)
    elif request.method == 'POST':
        # one new trusted certificate in payload
        try:
            start_time = time.time()

            if request.headers.get('Content-Encoding') == 'gzip':
                raw_data = zlib.decompress(request.data)
            else:
                raw_data = request.data
            # try to read it to check consistency
            trusted = SSLCABundle()
            new_certs = trusted.add_certificates_from_pem(raw_data)
            cert_fn = os.path.join(app.conf.get('trusted_signers_certificates_folder'),new_certs[0].get_fingerprint('sha1').encode('hex')+'.crt')
            open(cert_fn,'w').write(raw_data)
            msg = u'Added %s as trusted certificate (cn %s)'% (cert_fn,new_certs[0].cn)
            return make_response(result=trusted, msg=msg, status=200, request_time=time.time() - start_time)

        except Exception as e:
            logger.debug(traceback.format_exc())
            logger.critical('trusted_signers_certificates %s' % (repr(e)))
            return make_response_from_exception(e)
    elif request.method == 'DELETE':
        try:
            start_time = time.time()
            if request.headers.get('Content-Encoding') == 'gzip':
                raw_data = zlib.decompress(request.data)
            else:
                raw_data = request.data

            # payload is a list of sha1 fingerprints of trusted certificates to remove from  trusted_signers_certificates_folder
            fingerprints = ujson.loads(raw_data)
            if not isinstance(fingerprints,list):
                raise Exception('Bad argument')
            result = []
            for cert_fn in glob.glob(os.path.join(app.conf.get('trusted_signers_certificates_folder'),'*.crt')):
                cert = SSLCertificate(cert_fn)
                if cert.get_fingerprint('sha1').encode('hex') in fingerprints:
                    os.unlink(cert_fn)
                    result.append(cert_fn)

            msg = u'Removed trusted certificates %s'% (', '.join(result),)
            return make_response(result=result, msg=msg, status=200, request_time=time.time() - start_time)

        except Exception as e:
            logger.debug(traceback.format_exc())
            logger.critical('trusted_signers_certificates %s' % (repr(e)))
            return make_response_from_exception(e)


@app.route('/api/v1/usage_statistics')
@requires_auth(['admin','view'])
@require_wapt_db
def usage_statistics():
    """returns some anonymous usage statistics to give an idea of depth of use"""
    try:
        host_data = Hosts.select(
            fn.COUNT(Hosts.uuid).alias('hosts_count'),
            fn.MIN(Hosts.last_seen_on).alias('oldest_query'),
            fn.MAX(Hosts.last_seen_on).alias('newest_query'),
        ).where(Hosts.server_uuid == get_server_uuid()).dicts().first()

        installed_packages = HostPackagesStatus.select(
            HostPackagesStatus.install_status,
            fn.COUNT(HostPackagesStatus.id),  # pylint: disable=no-member
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
        uuid=app.conf['server_uuid'],
        platform=platform.system(),
        architecture=platform.architecture(),
        version=__version__,
        date=datetime2isodate(),
        edition=get_wapt_edition(),
        git_hash=git_hash,
    )
    result.update(stats)
    return make_response(msg=_('Anomnymous usage statistics'), result=result)


@app.route('/api/v3/host_tasks_status')
@requires_auth(['admin','view'])
@require_wapt_db
def host_tasks_status():
    """Proxy the get tasks status action to the client"""
    try:
        if not socketio:
            raise Exception('socketio unavailable')

        uuid = request.args['uuid']
        client_tasks_timeout = float(request.args.get('client_tasks_timeout', app.conf['client_tasks_timeout']))
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
            .first()
        if host_data and host_data.get('listening_address', None):
            result = []

            def result_callback(data):
                result.append(data)

            request.sid=host_data['listening_address']
            socketio.emit('get_tasks_status', request.args, room=request.sid, callback=result_callback)

            start_waiting = time.time()
            while not result:
                if time.time() - start_waiting > client_tasks_timeout:
                    raise EWaptTimeoutWaitingForResult('Timeout, client did not send result within %s s' % client_tasks_timeout)
                socketio.sleep(0.1)
            # be sure to not eat cpu in case host return empty result
            if not 'running' in result:
                time.sleep(0.1)
            msg = 'Tasks status for %s' % host_data['computer_fqdn']
            return make_response(result[0]['result'],
                                 msg=msg,
                                 success=True,
                                 request_time=time.time() - start_time,
                                 )
        else:
            raise EWaptHostUnreachable('Host not connected, Websocket sid not in database')

    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('host_tasks_status failed %s' % (repr(e)))
        return make_response_from_exception(e)



@app.route('/api/v3/trigger_host_action', methods=['HEAD','POST'])
@requires_auth(['admin','trigger_host_action','trigger_host_upgrade'])
@require_wapt_db
def trigger_host_action():
    """Proxy some single shot actions to the client using websockets"""
    try:
        if not socketio:
            raise Exception('socketio unavailable')

        timeout = float(request.args.get('timeout', app.conf['client_tasks_timeout']))
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

        ok = []
        client_errors = []
        server_errors = []
        other_server = []
        expected_result_count = 0

        def result_callback(data):
            if data.get('success',False):
                ok.append(data)
            else:
                client_errors.append(data)

        last_uuid = None
        notified_uuids = []

        for action in action_data:
            if 'uuid' in action:
                where = Hosts.uuid == action['uuid']
            elif 'uuids' in action:
                where = Hosts.uuid.in_(action['uuids'])
            elif 'organizational_units' in action:
                ou_list = action['organizational_units']
                if action.get('include_childs_ou','1') == '1':
                    or_list = Hosts.computer_ad_ou.endswith(ou_list[0])
                    for ou in ou_list[1:]:
                       or_list = or_list | Hosts.computer_ad_ou.endswith(ou)
                    where = (or_list)
                else:
                    where = (Hosts.computer_ad_ou.in_(ou_list))

            for host in Hosts.select(Hosts.uuid,Hosts.computer_fqdn, Hosts.listening_address, Hosts.server_uuid).where(
                    (where) & (Hosts.listening_protocol == 'websockets')).dicts():
                uuid = host['uuid']
                if host['server_uuid'] != app.conf['server_uuid']:
                    other_server.append(uuid)
                else:
                    notify_server = action.get('notify_server',False)
                    if notify_server:
                        socket_callback = result_callback
                    else:
                        socket_callback = None
                    try:
                        request.sid = host['listening_address']
                        socketio.emit('trigger_host_action', action, room=request.sid) #, callback = socket_callback)
                        if notify_server:
                            expected_result_count += 1
                        # notify console that action is in progress until client send it updated status.
                        #if notify_server and not uuid in notified_uuids:
                        #    notified_uuids.append(uuid)
                        #    Hosts.update(host_status='RUNNING').where(Hosts.uuid == uuid).execute()
                    except Exception as e:
                        server_errors.append('Error for %s: %s' % (uuid,e))
                last_uuid= uuid

        #wait_until = time.time() + timeout + expected_result_count * timeout / 100
        #while len(ok) + len(client_errors) + len(server_errors) < expected_result_count:
        #    if time.time() >= wait_until:
        #        break
        #    socketio.sleep(0.05)

        msg = '%s actions launched, %s errors, %s skipped, %s server errors' % (expected_result_count, len(client_errors), len(other_server),len(server_errors))

        return make_response([r.get('result', None) for r in (ok + client_errors)],
                             msg=msg,
                             success=len(client_errors) == 0 and len(server_errors) == 0)
    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.critical('trigger_host_action failed %s' % (repr(e)))
        return make_response_from_exception(e)

def setup_logging(config=None):
    loglevel = config['loglevel']
    for log in WAPTLOGGERS:
        sublogger = logging.getLogger(log)
        if sublogger:
            if 'loglevel_%s' % log in config:
                setloglevel(sublogger,config['loglevel_%s' % log])
            else:
                setloglevel(sublogger,loglevel)

            #if platform.system() == 'Linux':
            #    hdlr = logging.handlers.SysLogHandler('/dev/log')
            #else:
                #log_directory = os.path.join(wapt_root_dir, 'log')
                #if not os.path.exists(log_directory):
                #    os.mkdir(log_directory)
            #    hdlr = logging.FileHandler(os.path.join(log_directory, 'waptserver.log'))

            #hdlr = logging.StreamHandler()
            #hdlr.setFormatter(
            #    logging.Formatter('%(asctime)s [%(name)-15s] %(levelname)s %(message)s'))
            #sublogger.addHandler(hdlr)

    hdlr = logging.StreamHandler()
    hdlr.setFormatter(
        logging.Formatter('%(asctime)s [%(name)-15s] %(levelname)s %(message)s'))
    rootlogger = logging.getLogger()
    rootlogger.addHandler(hdlr)
    setloglevel(rootlogger,loglevel)

@app.route('/api/v3/user_infos')
#@requires_auth(['admin','view'],methods=['session','admin','passwd','ldap','ssl','token','kerb'])
def user_infos():
    user_info = dict(
        user=session.get('user'),
        user_fingerprint_sha1=session.get('user_fingerprint_sha1'),
        user_acls=session.get('user_acls'),
        auth_method=session.get('auth_method'),
        auth_date=session.get('auth_date'),
        )
    msg = 'Info on logged in user'
    return make_response(result=user_info,msg=msg)

def get_revision_hash():
    fn = os.path.join(wapt_root_dir,'revision.txt')
    if os.path.isfile(fn):
        return open(fn,'r').read()
    else:
        fn = os.path.join(wapt_root_dir,'waptserver','VERSION')
        if os.path.isfile(fn):
            return open(fn,'r').read()
        else:
            return ''

# app mode
if __name__ == '__main__':
    usage = """\
    %prog [-c configfile] [--devel] [action]

    WAPT Server daemon.

    action is either :
      <nothing> : run service in foreground
      install   : install as a Windows service managed by nssm

    """
    git_hash = get_revision_hash()
    wapt_edition = get_wapt_edition()

    parser = OptionParser(usage=usage, version='waptserver.py ' + __version__)
    parser.add_option(
        '-c',
        '--config',
        dest='configfile',
        default=waptserver.config.DEFAULT_CONFIG_FILE,
        help='Config file full path (default: %default)')
    parser.add_option('-l','--loglevel',dest='loglevel',default=None,type='choice',
            choices=['debug',   'warning','info','error','critical'],
            metavar='LOGLEVEL',help='Loglevel (default: warning)')
    parser.add_option('-d','--devel',dest='devel',default=False,action='store_true',
            help='Enable debug mode (for development only)')

    for log in WAPTLOGGERS:
        parser.add_option('--loglevel_%s' % log,dest='loglevel_%s' % log,default=None,type='choice',
                choices=['debug','warning','info','error','critical'],
                metavar='LOGLEVEL',help='Loglevel %s (default: warning)' % log)

    (options, args) = parser.parse_args()

    app.config['CONFIG_FILE'] = options.configfile
    app.conf.update(**waptserver.config.load_config(options.configfile))
    for att in options.__dict__:
        if att in app.conf and getattr(options,att) is not None:
            app.conf[att] = getattr(options,att)

    app.config['SECRET_KEY'] = app.conf.get('secret_key')
    app.config['APPLICATION_ROOT'] = app.conf.get('application_root','')
    setup_logging(app.conf)
    logger.info(u'Using config file %s' % options.configfile)

    # monkey patch for greenlet and define a socketio on top of app
    from waptserver.server_socketio import socketio,proxy_host_request

    if wsus:
        # add socketio targets to trigger wsus actions on hosts
        from waptenterprise.waptserver import wsus_socketio
        app.register_blueprint(wsus_socketio.wsus_socketio)

    logger.info(u'Load database configuration')
    load_db_config(app.conf)
    try:
        with WaptDB():
            upgrade_db_structure()
    except Exception as e:
        logger.critical('Unable to upgrade DB structure, init instead: %s' % (repr(e)))
        init_db()

    # check wapt directories
    if not os.path.exists(app.conf['wapt_folder']):
        raise Exception('Folder missing : %s.' % app.conf['wapt_folder'])
    if not os.path.exists(app.conf['wapt_folder'] + '-host'):
        raise Exception('Folder missing : %s-host.' % app.conf['wapt_folder'])

    logger.info(u'Waptserver starting...')
    port = app.conf['waptserver_port']
    with WaptDB():
        with wapt_db.atomic() as trans:
            while True:
                try:
                    logger.info(u'Reset connections SID for former hosts on this server')
                    hosts_count = Hosts.update(
                        reachable='DISCONNECTED',
                        listening_protocol=None,
                        listening_address=None,
                    ).where(
                        (Hosts.listening_protocol == 'websockets') & (Hosts.server_uuid == get_server_uuid())
                    ).execute()
                    break
                except Exception as e:
                    trans.rollback()
                    logger.critical('Trying to upgrade database structure, error was : %s' % repr(e))
                    upgrade_db_structure()

    # initialize socketio layer
    if socketio:
        logger.info(u'Starting socketio/wsgi server on port %s' % (port,))
        socketio.run(app, host=app.conf['wapt_bind_interface'], log=logger,  port=port, debug=options.devel, log_output = True, use_reloader=options.devel, max_size=app.conf['max_clients'])
    else:
        # debug wsgi mode mode
        logger.info(u'Starting wsgi debug server...')
        app.run(host=app.conf['wapt_bind_interface'],port=port,debug=options.devel)

    logger.info(u'Waptserver stopped')
else:
    # initialize WSGI app only
    # config filename is defined in  uwsgi config file (so refer to himself...)
    git_hash = get_revision_hash()
    wapt_edition = get_wapt_edition()
    app.config['CONFIG_FILE'] = os.environ['CONFIG_FILE']
    app.conf.update(**waptserver.config.load_config(app.config['CONFIG_FILE']))
    setup_logging(app.conf)
    app.config['SECRET_KEY'] = app.conf.get('secret_key')
    app.config['APPLICATION_ROOT'] = app.conf.get('application_root','')
    load_db_config(app.conf)

