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

from itsdangerous import TimedJSONWebSignatureSerializer

logger = logging.getLogger()

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

def check_auth( username=None, password = None, request = None,
                session=None, methods=['admin','passwd','ldap','session','ssl','token']):
    """This function is called to check if a username /
    password combination is valid.

    Args:
        username (str):
        password (str):
        request (Flask.Request) : request where to looup authrization basic header
        session (Flask.Session) where to lookup session user

    Returns:
        list of (str,str): list of (Auth method,username) or None if bad auth

    """
    if not username and not password and request.authorization:
        username = request.authorization.username
        password = request.authorization.password

    auth_method = None
    auth_user = None
    auth_date = None

    for method in methods:
        if method == 'session' and session:
            session_user = session.get('user',None)
            if session_user:
                auth_user = session_user
                auth_date = session.get('auth_date',None)
                auth_method = method
                logger.debug(u'User %s authenticated using session cookie' % (username,))

        elif method == 'password' and username != app.conf['wapt_user']:
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


        elif method == 'admin' and app.conf['wapt_user'] == username:
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
                    token_data = token_gen.loads(password)
                    uuid = token_data.get('uuid', None)
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

        elif method == 'kerb':
            # with nginx kerberos module, auth user name is stored as Basic auth in the
            # 'Authorisation' header with password 'bogus_auth_gss_passwd'

            # Kerberos auth negociated by nginx
            if username != '' and password == 'bogus_auth_gss_passwd':
                authenticated_user = username.lower().replace('$', '')
                auth_method = method
                auth_user = authenticated_user
                auth_date = datetime.datetime.utcnow().isoformat()
                logger.debug(u'User %s authenticated using kerberos' % (authenticated_user,))

        elif method == 'ldap':
            if auth_module_ad is not None and (app.conf['wapt_user'] != username and
                    auth_module_ad.check_credentials_ad(app.conf, username, password)):
                auth_method = method
                auth_user = username
                auth_date = datetime.datetime.utcnow().isoformat()
                logger.debug(u'User %s authenticated using LDAP' % (username,))

        # nginx ssl auth.
        elif request and request.headers.get('X-Ssl-Authenticated', None) == 'SUCCESS':
            dn = request.headers.get('X-Ssl-Client-Dn', None)
            if dn:
                auth_method = method
                auth_user = dn
                auth_date = datetime.datetime.utcnow().isoformat()
                logger.debug(u'User %s authenticated using SSL client certificate' % (dn,))

        if auth_method and auth_user:
            break

    if auth_method and auth_user:
        return dict(auth_method = auth_method,user=auth_user,auth_date=auth_date)
    else:
        return None

def change_admin_password(newpassword):
    new_hash = pbkdf2_sha256.hash(newpassword.encode('utf8'))
    rewrite_config_item(app.config['CONFIG_FILE'],'options', 'wapt_password', new_hash)
    app.conf['wapt_password'] = new_hash


def get_authorized_actions(user):
    """

    Args:
        user (str): username

    Returns:
        dict : 'action': ['scopes']
    """
    return []
