#!/usr/bin/env python
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
__version__ = '1.5.0.17'

import sys
import errno
import flask
import logging
import os
import requests
import traceback
import time
from waptutils import jsondump

__all__ = [
    'mkdir_p',
    'utils_set_devel_mode',
    'utils_devel_mode',
    'get_disk_space',
    'logger',
    'setloglevel',
    'make_response',
    'make_response_from_exception',
    'EWaptMissingHostData',
    'EWaptUnknownHost',
    'EWaptHostUnreachable',
    'EWaptForbiddden',
    'EWaptMissingParameter',
    'EWaptSignalReceived',
    'EWaptDatabaseError',
    'EWaptAuthenticationFailure',
    'EWaptTimeoutWaitingForResult',
]

utils_devel_mode = False

logger = logging.getLogger('waptserver')

def utils_set_devel_mode(devel):
    global utils_devel_mode
    utils_devel_mode = devel


def mkdir_p(path):
    import errno
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def get_disk_space(directory):

    ret = None

    if os.name == 'posix':
        stats = os.statvfs(directory)
        ret = (stats.f_bavail * stats.f_bsize, stats.f_blocks * stats.f_bsize)
    else:
        import pythoncom
        pythoncom.CoInitializeEx(pythoncom.COINIT_MULTITHREADED)
        import wmi

        drive = os.path.splitdrive(os.path.abspath(directory))[0].lower()

        for d in wmi.WMI().Win32_LogicalDisk():
            if str(d.Name).lower() == drive:
                ret = (int(d.FreeSpace), int(d.Size))

    return ret



def setloglevel(logger, loglevel):
    """set loglevel as string"""
    if loglevel in ('debug', 'warning', 'info', 'error', 'critical'):
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: {}'.format(loglevel))
        logger.setLevel(numeric_level)


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
    return flask.Response(
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
    if utils_devel_mode:
        raise exception
    else:
        data['msg'] = u'Error on server: %s' % (exception,)
    return flask.Response(
        response=jsondump(data),
        status=status,
        mimetype='application/json')


# Custom exceptions #####
class EWaptMissingHostData(Exception):
    pass


class EWaptUnknownHost(Exception):
    pass


class EWaptHostUnreachable(Exception):
    pass


class EWaptForbiddden(Exception):
    pass


class EWaptMissingParameter(Exception):
    pass


class EWaptSignalReceived(Exception):
    pass


class EWaptDatabaseError(Exception):
    pass


class EWaptAuthenticationFailure(Exception):
    pass


class EWaptTimeoutWaitingForResult(Exception):
    pass
