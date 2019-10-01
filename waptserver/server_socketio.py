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
import traceback


from waptserver.config import __version__
from waptserver.config import DEFAULT_CONFIG_FILE,rewrite_config_item

from waptserver.app import app

from waptutils import datetime2isodate,ensure_list,ensure_unicode,Version,setloglevel

from waptserver.utils import EWaptAuthenticationFailure,EWaptForbiddden,EWaptHostUnreachable,EWaptMissingHostData
from waptserver.utils import EWaptMissingParameter,EWaptSignalReceived,EWaptTimeoutWaitingForResult,EWaptUnknownHost
from waptserver.common import get_secured_token_generator,get_server_uuid
from waptserver.common import make_response,make_response_from_exception

from waptserver.model import wapt_db,Hosts,SyncStatus,fn

from flask import request, session
from flask_socketio import SocketIO
from flask_socketio import disconnect, send, emit


logger = logging.getLogger()

# chain SocketIO server
socketio = SocketIO(app, logger = logger, engineio_logger = logger, cors_allowed_origins = '*')


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
                            # wait for asynchronous answer...
                            wait_loop = timeout * 20
                            while not got_result:
                                wait_loop -= 1
                                if wait_loop < 0:
                                    raise EWaptTimeoutWaitingForResult(u'Timeout, client did not send result within %s s' % timeout)
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
                            msg=u'Host %s is not registered or not connected wia websockets' % uuid,
                            computer_fqdn='',
                        ))
            except Exception as e:
                result['errors'].append(
                    dict(
                        uuid=uuid,
                        msg=u'Host %s error %s' % (uuid, repr(e)),
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


# SocketIO Callbacks / handlers
@socketio.on('trigger_update_result')
def on_trigger_update_result(result):
    """Return from update on client"""
    logger.debug(u'Trigger Update result : %s (uuid:%s)' % (result, request.args['uuid']))
    # send to all waptconsole warching this host.
    socketio.emit(u'trigger_update_result', result, room=request.args['uuid'], include_self=False)


@socketio.on('trigger_upgrade_result')
def on_trigger_upgrade_result(result):
    """Return from the launch of upgrade on a client"""
    logger.debug(u'Trigger Upgrade result : %s (uuid:%s)' % (result, request.args['uuid']))
    socketio.emit(u'trigger_upgrade_result', result, room=request.args['uuid'], include_self=False)


@socketio.on('trigger_install_packages_result')
def on_trigger_install_packages_result(result):
    logger.debug(u'Trigger install result : %s (uuid:%s)' % (result, request.args['uuid']))
    socketio.emit(u'trigger_install_packages_result', result, room=request.args['uuid'], include_self=False)


@socketio.on('trigger_remove_packages_result')
def on_trigger_remove_packages_result(result):
    logger.debug(u'Trigger remove result : %s (uuid:%s)' % (result, request.args['uuid']))
    socketio.emit(u'trigger_remove_packages_result', result, room=request.args['uuid'], include_self=False)


@socketio.on('reconnect')
@socketio.on('connect')
def on_waptclient_connect():
    try:
        uuid = request.args.get('uuid', None)
        if not uuid:
            raise EWaptForbiddden('Missing source host uuid')
        allow_unauthenticated_connect = app.conf.get('allow_unauthenticated_connect',False)
        if not allow_unauthenticated_connect:
            try:
                token_gen = get_secured_token_generator()
                token_data = token_gen.loads(request.args['token'])
                uuid = token_data.get('uuid', None)
                if not uuid:
                    raise EWaptAuthenticationFailure('Bad host UUID')
                if token_data['server_uuid'] != get_server_uuid():
                    raise EWaptAuthenticationFailure('Bad server UUID')
            except Exception as e:
                raise EWaptAuthenticationFailure(u'SocketIO connection not authorized, invalid token: %s' % e)
            logger.info(u'Socket.IO connection from wapt client sid %s (uuid: %s fqdn:%s)' % (request.sid,uuid,token_data.get('computer_fqdn')))
        else:
            logger.info(u'Unauthenticated Socket.IO connection from wapt client sid %s (uuid: %s)' % (request.sid,uuid))

        # update the db
        with wapt_db.atomic() as trans:
            # stores sid in database
            hostcount = Hosts.update(
                server_uuid=get_server_uuid(),
                listening_protocol='websockets',
                listening_address=request.sid,
                listening_timestamp=datetime2isodate(),
                last_seen_on=datetime2isodate()
            ).where(Hosts.uuid == uuid).execute()
            # if not known, reject the connection
            if hostcount == 0:
                raise EWaptForbiddden('Host is not registered')

        session['uuid'] = uuid
        return True

    except Exception as e:
        if 'uuid' in session:
            session.pop('uuid')
        logger.warning(u'SocketIO connection refused for uuid %s, sid %s: %s, instance %s' % (uuid,request.sid,e,app.conf.get('application_root')))
        disconnect()
        return False


@socketio.on('wapt_pong')
def on_wapt_pong():
    uuid = None
    try:
        uuid = session.get('uuid')
        if not uuid:
            logger.critical(u'SocketIO %s connected but no host uuid in session: asking connected host to reconnect' % (request.sid))
            emit('wapt_force_reconnect')
            return False
        else:
            logger.debug(u'Socket.IO pong from wapt client sid %s (uuid: %s)' % (request.sid, session.get('uuid',None)))
            # stores sid in database
            with wapt_db.atomic() as trans:
                hostcount = Hosts.update(
                    server_uuid=get_server_uuid(),
                    listening_timestamp=datetime2isodate(),
                    listening_protocol='websockets',
                    listening_address=request.sid,
                    reachable='OK',
                ).where(Hosts.uuid == uuid).execute()
                # if not known, reject the connection
                if hostcount == 0:
                    logger.warning(u'SocketIO sid %s connected but no match in database for uuid %s : asking to reconnect' % (request.sid,uuid))
                    emit('wapt_force_reconnect')
                    return False
            return True
    except Exception as e:
        logger.critical(u'SocketIO pong error for uuid %s and sid %s : %s, instance: %s' % (uuid,request.sid,traceback.format_exc(),app.conf.get('application_root')))
        return False

@socketio.on('disconnect')
def on_waptclient_disconnect():
    uuid = session.get('uuid', None)
    logger.info(u'Socket.IO disconnection from wapt client sid %s (uuid: %s)' % (request.sid, uuid))
    # clear sid in database
    with wapt_db.atomic() as trans:
        Hosts.update(
            listening_timestamp=datetime2isodate(),
            listening_protocol=None,
            listening_address=None,
            reachable='DISCONNECTED',
        ).where((Hosts.uuid == uuid) & (Hosts.listening_address == request.sid)).execute()
    return True

@socketio.on_error()
def on_wapt_socketio_error(e):
    logger.critical(u'Socket IO : An error has occurred for sid %s, uuid:%s : %s' % (request.sid, request.args.get('uuid', None), repr(e)))

# end websockets
