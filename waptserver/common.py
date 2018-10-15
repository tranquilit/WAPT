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
from waptserver.app import app,socketio
from waptserver.model import Hosts
from waptutils import jsondump,ensure_list,ensure_unicode
from waptserver.utils import EWaptMissingParameter,EWaptSignalReceived,EWaptTimeoutWaitingForResult,EWaptUnknownHost

logger = logging.getLogger()

__all__ = [
    'make_response',
    'make_response_from_exception',
    'get_server_uuid',
    'get_secured_token_generator',
    'proxy_host_request',
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
    return TimedJSONWebSignatureSerializer(app.conf['secret_key'], expires_in = app.conf['signature_clockskew'])


def proxy_host_request(request, action):
    """Proxy a waptconsole action to wapt clients using websockets

    Args:
        uuid: can be a list or a single uuid
        notify_user: 0/1
        notify_server: 0/1

    Returns:
        dict:
            'result':
                'success' (list)
                'errors' (list)
            'msg' (str)
            'success'(bool)
            'request_time' (float)
            'error_code'
    """
    try:
        start_time = time.time()
        all_args = {k: v for k, v in request.args.iteritems()}
        if request.json:
            all_args.update(request.json)

        uuids = ensure_list(all_args['uuid'])
        del(all_args['uuid'])
        timeout = float(request.args.get('timeout', app.conf.get('clients_read_timeout', 5)))

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

                            logger.debug(u'Emit %s to %s (%s)' % (action, uuid, computer_fqdn))
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

