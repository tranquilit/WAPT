#
from eventlet import monkey_patch
monkey_patch()

import time
import sys
import os
import types

try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.append(os.path.join(wapt_root_dir))
sys.path.append(os.path.join(wapt_root_dir,'lib'))
sys.path.append(os.path.join(wapt_root_dir,'lib','site-packages'))

from socketIO_client import SocketIO, LoggingNamespace,SocketIONamespace,BaseNamespace

import logging
logging.basicConfig(level=logging.DEBUG)

class TestNamespace(BaseNamespace):
    def on_my_event(self,message):
        print('my event:%s'%message)

    def on_my_broadcast_event(self,message):
        print('my_broadcast_event %s'%message)

    def on_join(self,message):
        join_room(message['room'])

    def on_leave(self,message):
        print('message %s'%message)

    def on_update(self,message):
        print('UPDATE %s for sid %s'%(message,self._io._engineIO_session.id))

    def on_my_pong(self,message):
        print('pong %s'%message)

    def on_my_response(self,message):
        print('myresponse: %s' % message)

    def on_connect(self):
        print('connected %s !'%dir(self))

    def on_disconnect(self):
        print('Client disconnected!')

#def on_update(message):
#    print('update : %s'%message)

clients = []

print('Starting socketio...')
socketIO = SocketIO('192.168.149.139',8080,transports=['websocket'])
test_namespace = socketIO.define(TestNamespace)

#socketIO.wait(seconds=1)
test_namespace.emit('new connection %s' % socketIO._engineIO_session.id)

socketIO.wait()

