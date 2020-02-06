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
from waptserver.config import __version__
import functools
import logging

from flask import request, Flask, Response, session, g, redirect, url_for, abort, render_template, flash,after_this_request

from cStringIO import StringIO as IO
import gzip

from waptserver.app import app
from waptserver.auth import check_auth
from waptserver.model import wapt_db
# i18n
from flask_babel import Babel
try:
    from flask_babel import gettext
except ImportError:
    gettext = (lambda s: s)
_ = gettext

logger = logging.getLogger('waptserver')

def authenticate(method='Basic'):
    """Sends a 401 response that enables basic auth"""
    return Response(
        _('You have to login with proper credentials'), 401,
        {'WWW-Authenticate': '%s realm="Login Required"' % method})

def requires_auth(methods=['session','admin','ldap']):
    """Flask route decorator which requires Basic Auth http header
    If not header, returns a 401 http status.
    """
    def decorator(f):
        @functools.wraps(f)
        def _auth_wrapper(*args,**kwargs):
            auth_result = check_auth(request = request, session=session, methods=methods)
            if not auth_result:
                return authenticate()
            logger.info(u'user %s authenticated' % auth_result )
            session.update(**auth_result)
            result = f(*args,**kwargs)
            return result
        return _auth_wrapper
    return decorator

def allow_local(f):
    """Restrict access to localhost"""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if request.remote_addr in ['127.0.0.1','[::1]','[::ffff:127.0.0.1]']:
            return f(*args, **kwargs)
        else:
            return forbidden()
    return decorated

def forbidden():
    """Sends a 403 response that enables basic auth"""
    return Response(
        'Restricted access.\n',
         403)

def gzipped(f):
    @functools.wraps(f)
    def view_func(*args, **kwargs):
        @after_this_request
        def zipper(response):
            accept_encoding = request.headers.get('Accept-Encoding', '')

            if 'gzip' not in accept_encoding.lower():
                return response

            response.direct_passthrough = False

            if (response.status_code < 200 or
                response.status_code >= 300 or
                'Content-Encoding' in response.headers):
                return response
            gzip_buffer = IO()
            gzip_file = gzip.GzipFile(mode='wb',
                                      fileobj=gzip_buffer)
            gzip_file.write(response.data)
            gzip_file.close()

            response.data = gzip_buffer.getvalue()
            response.headers['Content-Encoding'] = 'gzip'
            response.headers['Vary'] = 'Accept-Encoding'
            response.headers['Content-Length'] = len(response.data)

            return response

        return f(*args, **kwargs)

    return view_func

def wapt_db_readonly(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if wapt_db and wapt_db.is_closed():
            wapt_db.connect()
        cnx = wapt_db.connection();
        b = cnx.readonly;
        if not b:
            cnx.set_session( readonly=True );
        try:
            r = f(*args,**kwargs);
            return r;
        finally:
            if not b:
                cnx.set_session( readonly=False );
            if wapt_db and not wapt_db.is_closed():
                wapt_db.close()
    return decorated;

def require_wapt_db(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if wapt_db and wapt_db.is_closed():
            logger.info('connecting to waptdb before request')
            wapt_db.connect()
        try:
            r = f(*args,**kwargs);
            return r;
        finally:
            if wapt_db and not wapt_db.is_closed():
                wapt_db.close()
    return decorated;
