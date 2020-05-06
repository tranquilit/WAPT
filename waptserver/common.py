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
import time
import logging
import traceback

from flask import request, Flask, Response, send_from_directory, session, g, redirect, url_for, abort, render_template, flash
from itsdangerous import TimedJSONWebSignatureSerializer

from waptserver.config import __version__
from waptserver.app import app
from waptserver.model import Hosts
from waptutils import jsondump,ensure_list,ensure_unicode
from waptserver.utils import EWaptMissingParameter,EWaptSignalReceived,EWaptTimeoutWaitingForResult,EWaptUnknownHost

logger = logging.getLogger()

__all__ = [
    'make_response',
    'make_response_from_exception',
    'get_server_uuid',
    'get_secured_token_generator',
    ]

# API V2 #####
def make_response(result={}, success=True, error_code='', msg='', status=200, request_time=None):
    data = dict(
        success=success,
        msg=msg,
    )
    if not success:
        data['error_code'] = error_code
    else:
        data['result'] = result
    data['request_time'] = request_time
    return Response(
        response=jsondump(data),
        status=status,
        mimetype='application/json')


def make_response_from_exception(exception, error_code='', status=200):
    """Return a error flask http response from an exception object
        success : False
        msg : message from exception
        error_code : classname of exception if not provided
        status: 200 if not provided
    """
    if not error_code:
        error_code = type(exception).__name__.lower()
    data = dict(
        success=False,
        error_code=error_code
    )

    logger.info(traceback.format_exc())

    data['msg'] = u'Error on server:\n%s' % (repr(exception))
    return Response(
        response=jsondump(data),
        status=status,
        mimetype='application/json')


def get_server_uuid():
    """Returns this server UUID as configured in configuration file waptserver.ini
    """
    server_uuid = app.conf.get('server_uuid', None)
    return server_uuid

def get_secured_token_generator(secret_key=None):
    if not secret_key:
        secret_key = app.conf['secret_key']
    return TimedJSONWebSignatureSerializer(secret_key, expires_in = app.conf['token_lifetime'])

def get_user_groups(conf,username, password):
    return ["waptservice"] #TODO change

    '''
    wapt_admin_group_dn = conf.get('wapt_admin_group_dn','')
    if not wapt_admin_group_dn:
        return False

    dns_suffix = conf.get('wapt_admin_group_dn','')
    dns_suffix = '.'.join(socket.getfqdn().split('.')[1:])
    dc_name = conf.get('ldap_auth_server')
    if not dc_name:
        dc_name = str(socket.gethostbyname(dns_suffix))
    logger.debug('Using %s as authentication ldap server' % dc_name)

    dc_base_dn =  conf.get('ldap_auth_base_dn')
    if not dc_base_dn:
        dc_base_dn = ','.join(['dc=%s' % x for x in dns_suffix.split('.')])
    logger.debug('Using %s as base DN' % dc_base_dn)

    default_user_kerberos_realm = dc_base_dn.lower().split('dc=',1)[-1].replace('dc=','.').replace(',','')
    dc_ssl_enabled = conf['ldap_auth_ssl_enabled']

    if ':' in dc_name:
        logger.error("DC_NAME must be a DNS server name or ip, not a ldap url")
        raise Exception("DC_NAME must be a DNS server name or ip, not a ldap url")

    auth_ok = False

    # append a REALM if not provided.
    if not '@' in username:
        bind_username = '%s@%s' % (username, default_user_kerberos_realm)
    else:
        (username,user_kerberos_readm) = username.split('@')
        if user_kerberos_readm != default_user_kerberos_realm:
            auth_ok = False
            logger.error("AUTH FAILED : User kerberos realm %s not matching default one %s" % (user_kerberos_readm,default_user_kerberos_realm))
            return auth_ok


    logger.debug('using dc %s for authentication, with base DN %s and bind username %s ' % (dc_name, dc_base_dn, bind_username))

    ldap_filter = '(&(sAMAccountName=%s)(memberof:1.2.840.113556.1.4.1941:=%s))' % (username,wapt_admin_group_dn)
'''

