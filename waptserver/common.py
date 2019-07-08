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

    logger.debug(traceback.format_exc())

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

def get_secured_token_generator():
    return TimedJSONWebSignatureSerializer(app.conf['secret_key'], expires_in = app.conf['token_lifetime'])


