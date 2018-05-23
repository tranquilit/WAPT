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

from waptserver.config import __version__

# from flask_login import LoginManager,login_required,current_user,UserMixin

from waptutils import datetime2isodate,ensure_list,ensure_unicode,Version,setloglevel

from waptserver.utils import make_response,make_response_from_exception
from waptserver.utils import EWaptAuthenticationFailure

from waptserver.app import app

import waptserver.config

logger = logging.getLogger()

try:
    from waptenterprise.waptserver import auth_module_ad
except ImportError as e:
    logger.debug(u'LDAP Auth disabled: %s' % e)
    auth_module_ad = None


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

    user_ok = False
    pass_sha1_ok = pbkdf2_sha256_ok = pass_sha512_ok = pass_sha512_crypt_ok = pass_bcrypt_crypt_ok = False

    user_ok = app.conf['wapt_user'] == username

    pass_sha1_ok = app.conf['wapt_password'] == hashlib.sha1(
        password.encode('utf8')).hexdigest()
    pass_sha512_ok = app.conf['wapt_password'] == hashlib.sha512(
        password.encode('utf8')).hexdigest()

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

    basic_auth = any_([pbkdf2_sha256_ok, pass_sha1_ok, pass_sha512_ok,
                 pass_sha512_crypt_ok, pass_bcrypt_crypt_ok]) and user_ok

    return basic_auth or (auth_module_ad is not None and auth_module_ad.check_credentials_ad(app.conf, username, password))

def change_admin_password(newpassword):
    new_hash = pbkdf2_sha256.hash(newpassword.encode('utf8'))
    rewrite_config_item(config_file, 'options', 'wapt_password', new_hash)
    app.conf['wapt_password'] = new_hash

