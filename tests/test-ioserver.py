#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      htouvet
#
# Created:     22/05/2017
# Copyright:   (c) htouvet 2017
# Licence:     <your licence>
#-------------------------------------------------------------------------------

from eventlet import monkey_patch
monkey_patch()

import os
import sys
try:
    wapt_root_dir = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            '..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0, os.path.join(wapt_root_dir))
sys.path.insert(0, os.path.join(wapt_root_dir,'waptserver'))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib'))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib', 'site-packages'))

from flask import request, Flask, Response, send_from_directory, session, g, redirect, url_for, abort, render_template, flash
from flask_socketio import SocketIO
from flask_socketio import send, emit,rooms,join_room, close_room,disconnect
from flask_login import current_user

from waptserver_utils import *
import waptserver_config

import logging
import logging.handlers

from optparse import OptionParser

DEFAULT_CONFIG_FILE = os.path.join(wapt_root_dir, 'conf', 'waptserver.ini')
config_file = DEFAULT_CONFIG_FILE

app = Flask(__name__, static_folder='./templates/static')
app.config['CONFIG_FILE'] = config_file

conf = waptserver_config.load_config(config_file)
app.config['SECRET_KEY'] = conf.get('secret_key','secretkey!!')

ALLOWED_EXTENSIONS = set(['wapt'])

# setup logging
logger = logging.getLogger("waptserver")

# chain SocketIO server
socketio = SocketIO(app,logger=logger)

client_count = None

@app.route('/api/v3/trigger_update')
#@requires_auth
def trigger_sio_update():
    """Proxy the wapt update action to the client using websockets"""
    try:
        uuid = request.args['uuid']
        notify_user = request.args.get('notify_user', 0)
        notify_server = request.args.get('notify_server', 1)

        print('send update to all')
        # how to find SID ??
        socketio.emit('update',args)

        result = request.args
        msg = request.path

        return make_response(result,
                             msg=msg,
                             success=True)
    except Exception as e:
        return make_response_from_exception(e)


@app.route('/testsio')
def testsio():
    return render_template('testsio.html', async_mode=socketio.async_mode)


def background_thread():
    """Example of how to send server generated events to clients."""
    count = 0
    while True:
        socketio.sleep(10)
        count += 1
        socketio.emit('my_response',
                      {'data': 'Server generated event', 'count': count})

@socketio.on('my_event')
def test_message(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': message['data'], 'count': session['receive_count']})


@socketio.on('my_broadcast_event')
def test_broadcast_message(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': message['data'], 'count': session['receive_count']},
         broadcast=True)


@socketio.on('join')
def join(message):
    join_room(message['room'])
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': 'In rooms: ' + ', '.join(rooms()),
          'count': session['receive_count']})


@socketio.on('leave')
def leave(message):
    leave_room(message['room'])
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': 'In rooms: ' + ', '.join(rooms()),
          'count': session['receive_count']})


@socketio.on('close_room')
def close(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response', {'data': 'Room ' + message['room'] + ' is closing.',
                         'count': session['receive_count']},
         room=message['room'])
    close_room(message['room'])


@socketio.on('my_room_event')
def send_room_message(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': message['data'], 'count': session['receive_count']},
         room=message['room'])


@socketio.on('disconnect_request')
def disconnect_request():
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': 'Disconnected!', 'count': session['receive_count']})
    disconnect()


@socketio.on('my_ping')
def ping_pong():
    print(request.sid,rooms())
    emit('my_pong')


@socketio.on('connect')
def test_connect():
    global client_count
    if client_count is None:
        client_count = 0
    client_count +=1
    #emit('my_response', {'data': 'Connected', 'count': 0})

    print('connected... %s (count = %s)' % (request.sid,client_count))

@socketio.on('disconnect')
def test_disconnect():
    global client_count
    if client_count is None:
        client_count = 0
    client_count -=1
    print('Client disconnected (count=%s)', (request.sid,client_count))


if __name__ == '__main__':
    usage = """\
    """
    import win32file
    win32file._setmaxstdio(2048)


    parser = OptionParser(usage=usage)
    parser.add_option(
        "-l",
        "--loglevel",
        dest="loglevel",
        default=None,
        type='choice',
        choices=[
            'debug',
            'warning',
            'info',
            'error',
            'critical'],
        metavar='LOGLEVEL',
        help="Loglevel (default: warning)")
    parser.add_option(
        "-d",
        "--devel",
        dest="devel",
        default=False,
        action='store_true',
        help="Enable debug mode (for development only)")

    (options, args) = parser.parse_args()

    socketio.run(app,host='0.0.0.0', port=8080, debug=options.devel)

