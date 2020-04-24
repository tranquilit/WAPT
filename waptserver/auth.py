#!/opt/wapt/bin/python
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
from __future__ import absolute_import
import os
import sys
import platform
import functools
import logging
import time
import json
import hashlib
from passlib.hash import sha512_crypt, bcrypt
from passlib.hash import pbkdf2_sha256
from passlib.apache import HtpasswdFile
import datetime

from waptserver.config import __version__

# from flask_login import LoginManager,login_required,current_user,UserMixin

from waptutils import datetime2isodate,ensure_list,ensure_unicode,Version,setloglevel

from waptserver.common import make_response,make_response_from_exception
from waptserver.common import get_secured_token_generator,get_server_uuid
from waptserver.utils import EWaptAuthenticationFailure

from waptserver.app import app

from waptserver.config import DEFAULT_CONFIG_FILE,rewrite_config_item
from waptserver.model import wapt_db,WaptUsers,WaptUserAcls,WaptDB

from itsdangerous import TimedJSONWebSignatureSerializer

logger = logging.getLogger('waptserver')

try:
    from waptenterprise.waptserver import auth_module_ad
except ImportError as e:
    logger.debug(u'LDAP Auth disabled: %s' % e)
    auth_module_ad = None

"""
def get_token_secret_key(self):
    private_dir = app.conf['private_dir']
    kfn = os.path.join(private_dir,'secret_key')
    if not os.path.isfile(kfn):
        if not os.path.isdir(private_dir):
            os.makedirs(private_dir)
        result = ''.join(random.SystemRandom().choice(string.letters + string.digits) for _ in range(64))
        open(kfn,'w').write(result)
        return result
    else:
        return open(kfn,'r').read()
"""

ACLS = [
    'admin',
    'view',
    'register_host',
    'unregister_host',
    'edit_host_package',
    'edit_base_package',
    'edit_group_package',
    'edit_unit_package',
    'edit_profile_package',
    'edit_wua_package',
    'edit_self_service_package',
    'edit_repo_rules',
    'trigger_host_upgrade',
    'trigger_host_action',
    'edit_report',
    'run_report',
    ]

def valid_username(username):
    return username is not None and username != '' and len(username)<255

def check_auth( username=None, password = None, request = None,
                session=None, methods=['session','admin','ldap']):
    """This function is called to check if a username /
    password combination is valid or to get already authenticated username
    from session argument.

    If no username or password, use session.authorization header if available.

    Args:
        username (str):
        password (str):
        request (Flask.Request) : request where to lookup authrization basic header
        session (Flask.Session) where to lookup session user
        methods (list of str) : list of auth method to try until one is successfull
                               'session': use current session user if it matches username
                               'admin':
                               'ldap':
                               'kerb':
                               'ssl':
                               'passwd':



    Returns:
        dict (auth_method = auth_method,user=auth_user,auth_date=auth_date)
             None if auth is not successfull

    """
    if username is None and password is None and request is not None and request.authorization:
        username = request.authorization.username
        password = request.authorization.password

    auth_method = None
    auth_user = None
    auth_date = None

    assert(isinstance(methods,list))

    for method in methods:
        if method == 'session' and session:
            session_user = session.get('user',None)
            if session_user and (username is None or username == session_user):
                auth_user = session_user
                auth_date = session.get('auth_date',None)
                auth_method = method
                logger.debug(u'User %s authenticated using session cookie' % (username,))

        elif method == 'passwd' and valid_username(username) and username != app.conf['wapt_user'] and password is not None:
                # local htpasswd user/passwd file for add_host registration action
                if app.conf.get('htpasswd_path'):
                    htpasswd_users = HtpasswdFile(app.conf.get('htpasswd_path'))
                    if htpasswd_users.verify(username,password):
                        auth_method = method
                        auth_user = username
                        auth_date = datetime.datetime.utcnow().isoformat()
                        logger.debug(u'User %s authenticated using htpasswd %s' % (username,htpasswd_users))
                    else:
                        logger.debug(u'user %s htpasswd %s verification failed' % (username,htpasswd_users))

        elif method == 'admin' and valid_username(username) and app.conf['wapt_user'] == username and password is not None:
                pbkdf2_sha256_ok = False
                pass_sha512_crypt_ok = False
                pass_bcrypt_crypt_ok = False

                if '$pbkdf2-sha256$' in app.conf['wapt_password']:
                    pbkdf2_sha256_ok = pbkdf2_sha256.verify(password, app.conf['wapt_password'])
                elif sha512_crypt.identify(app.conf['wapt_password']):
                    pass_sha512_crypt_ok = sha512_crypt.verify(
                        password,
                        app.conf['wapt_password'])
                else:
                    try:
                        if bcrypt.identify(app.conf['wapt_password']):
                            pass_bcrypt_crypt_ok = bcrypt.verify(
                                password,
                                app.conf['wapt_password'])
                    except Exception:
                        pass

                if pbkdf2_sha256_ok or pass_sha512_crypt_ok or pass_bcrypt_crypt_ok:
                    auth_method = method
                    auth_user = username
                    auth_date = datetime.datetime.utcnow().isoformat()
                else:
                    logger.debug(u'wapt admin passwd verification failed')

        elif method == 'token':
            # token auth
            token_secret_key = app.conf['secret_key']
            if token_secret_key:
                # check if there is a valid token in the password
                try:
                    token_gen = get_secured_token_generator(token_secret_key)
                    # check if there is a Bearer, else use Basic / password
                    authorization = request.headers.get('Authorization')
                    if authorization and authorization.startswith('Bearer '):
                        token_data = token_gen.loads(authorization.split(' ',1)[1])
                    elif password is not None:
                        token_data = token_gen.loads(password)
                    else:
                        raise EWaptAuthenticationFailure('No token')

                    uuid = token_data.get('uuid', token_data.get('user',None))
                    if not uuid:
                        raise EWaptAuthenticationFailure('Bad token UUID')
                    if token_data['server_uuid'] != get_server_uuid():
                        raise EWaptAuthenticationFailure('Bad server UUID')
                    auth_method = method
                    auth_user = uuid
                    auth_date =  datetime.datetime.fromtimestamp(token_data['iat']).isoformat()
                    logger.debug(u'User %s authenticated using token' % (uuid,))
                except Exception as e:
                    logger.debug(u'Token verification failed : %s' % repr(e))
                    pass

        elif method == 'kerb' and app.conf['use_kerberos']:
            # with nginx kerberos module, auth user name is stored as Basic auth in the
            # 'Authorisation' header with password 'bogus_auth_gss_passwd'

            # Kerberos auth negociated by nginx
            if username != '' and password == 'bogus_auth_gss_passwd':
                authenticated_user = username.lower().replace('$', '')
                auth_method = method
                auth_user = authenticated_user
                auth_date = datetime.datetime.utcnow().isoformat()
                logger.debug(u'User %s authenticated using kerberos' % (authenticated_user,))

        elif method == 'ldap' and valid_username(username) and password is not None:
            if auth_module_ad is not None and (app.conf['wapt_user'] != username and
                    auth_module_ad.check_credentials_ad(app.conf, username, password,list_dn=app.conf.get('wapt_admin_group_dn'),group_name=app.conf.get('wapt_admin_group'))['groups']):
                auth_method = method
                auth_user = username
                auth_date = datetime.datetime.utcnow().isoformat()
                logger.debug(u'User %s authenticated using LDAP' % (username,))

        # nginx ssl auth.
        elif method == 'ssl' and request and app.conf['use_ssl_client_auth'] and request.headers.get('X-Ssl-Authenticated', None) == 'SUCCESS':
            dn = request.headers.get('X-Ssl-Client-Dn', None)
            if dn:
                auth_method = method
                # strip CN= if no other suffix.
                if dn.upper().startswith('CN='):
                    auth_user = dn.split('=',1)[1]
                else:
                    auth_user = dn
                auth_date = datetime.datetime.utcnow().isoformat()
                logger.debug(u'User %s authenticated using SSL client certificate' % (dn,))

        if auth_method and auth_user:
            break

    #only session and admin methods are ok for the embedded wapt admin password based account.
    if auth_method and auth_user and (auth_user != app.conf['wapt_user'] or auth_method in ('session','admin')):
        return dict(auth_method = auth_method,user=auth_user,auth_date=auth_date)
    else:
        return None

def change_admin_password(newpassword):
    """Computes and stores the hash of newpassword for the embedded wapt admin account
    in waptserver.ini config file.

    """
    new_hash = pbkdf2_sha256.hash(newpassword.encode('utf8'))
    rewrite_config_item(app.config['CONFIG_FILE'],'options', 'wapt_password', new_hash)
    app.conf['wapt_password'] = new_hash
    return new_hash

def get_user_acls(user_fingerprint_sha1):
    """Returns a dict of not expired {perimeter -> list of acls} for a user

    Args:
        username (str): username to check rights about

    Returns:
        dict: {perimeter: list of acl (str)}
    """
    if user_fingerprint_sha1:
        result = {}
        with WaptDB():
            perimeters = WaptUserAcls.select(WaptUserAcls.perimeter_fingerprint,WaptUserAcls.acls).where(
                (WaptUserAcls.user_fingerprint_sha1 == user_fingerprint_sha1) &
                ((WaptUserAcls.expiration_date.is_null()) | (WaptUserAcls.expiration_date <= datetime2isodate()))).dicts()
            for perimeter in perimeters:
                result[perimeter['perimeter_fingerprint']] = perimeter['acls']
        return result
    else:
        return None

def has_any_right(user_acls,acls=['admin'],perimeters=None):
    """Return the list of perimeters for which the user
    has any of the rights listed in acls.

    Args:
        user_acls (dict) : acls of the user. {'perimeter':['list of acl']}
        acls (list of str) : any of the acls will match
        perimeters (list of str): check the right in these perimters only.
                                 If None, returns all matches

    Returns:
        list of str: list of perimeters fingerprint (list of CA fingerprint)
                     if no right on any perimeter, return empty list.

    >>> user_acls = {'perimeter1_hash':['admin','view'],'perimeter2_hash':['view','edit_hosts']}
    >>> has_any_right(user_acls, acls = ['view'])
    ['perimeter2_hash', 'perimeter1_hash']

    >>> has_any_right(user_acls, acls = ['admin','edit_hosts'])
    ['perimeter2_hash', 'perimeter1_hash']

    >>> has_any_right(user_acls, acls = ['edit_hosts'])
    ['perimeter2_hash']

    >>> has_any_right(user_acls, acls = ['edit_hosts'],perimeters=['perimeter1_hash'])
    ['perimeter2_hash']

    >>> has_any_right(user_acls, acls = ['edit_hosts'],perimeters=['perimeter1_hash'])
    []
    >>> has_any_right(user_acls, acls = ['edit_hosts'],perimeters=['perimeter2_hash'])
    ['perimeter2_hash']

    """

    result = []
    if user_acls:
        for perimeter,perimeter_acls in user_acls.iteritems():
            if (perimeters is None or perimeter in perimeters) and [acl for acl in acls if acl in perimeter_acls]:
                result.append(perimeter)
    return result


