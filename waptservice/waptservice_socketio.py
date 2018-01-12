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
import time
import sys
import os
import datetime
import logging
import threading

try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

from waptutils import __version__

from socketIO_client import SocketIO, LoggingSocketIONamespace,SocketIONamespace

import urlparse

import logging
import sqlite3

import json
import StringIO

import thread
import threading

import Queue
import traceback
import locale

import datetime
import copy

import tempfile

import setuphelpers

# wapt specific stuff
from waptutils import ensure_unicode,ensure_list,jsondump

from waptpackage import PackageEntry,WaptLocalRepo,WaptPackage,EWaptException
from waptcrypto import SSLVerifyException,SSLCABundle,SSLCertificate,SSLPrivateKey

from common import Wapt

from waptservice_common import waptservice_remote_actions,waptconfig,WaptServiceConfig
from waptservice_common import WaptUpdate,WaptUpgrade,WaptUpdateServerStatus,WaptRegisterComputer
from waptservice_common import WaptCleanup,WaptPackageInstall,WaptPackageRemove,WaptPackageForget,WaptLongTask

from plugins import *

logger = logging.getLogger()

# Websocket stuff
##### API V2 #####
def make_response(result = {},success=True,error_code='',msg='',uuid=None,request_time=None):
    data = dict(
            uuid = uuid,
            success = success,
            msg = msg,
            error_code = error_code,
            result = result,
            request_time = request_time,
            )
    return data

def make_response_from_exception(exception,error_code='',uuid=None,request_time=None):
    """Create a standard answer for websocket callback exception

    Returns:
        dict: {success : False,msg : message from exceptionerror_code : classname of exception if not provided}
   """
    if not error_code:
        error_code = type(exception).__name__.lower()

    data = dict(
            uuid = uuid,
            success = False,
            msg = "Error on client: %s" % repr(exception),
            error_code = error_code,
            request_time = request_time,
            )
    return data


class WaptSocketIORemoteCalls(SocketIONamespace):

    def initialize(self):
        """Initialize custom variables here.
        You can override this method."""
        logger.debug('New waptremotecall instance created...')
        self.task_manager = None
        self.wapt = None

    def on_trigger_host_action(self,args,result_callback=None):
        try:
            start_time = time.time()
            actions = args
            if not isinstance(actions,list):
                actions =[actions]
            logger.debug('Host actions "%s" triggered by SocketIO' % ",".join([action['action'] for action in actions]))
            # check signatures
            if not self.wapt:
                raise Exception('Wapt not available')
            verified_by = None
            for action in actions:
                name = action['action']
                verified_by = None
                signer_cert_chain = SSLCABundle().add_pem(action['signer_certificate']).certificates()
                chain = self.wapt.cabundle.check_certificates_chain(signer_cert_chain)
                if chain:
                    required_attributes = ['uuid','action']
                    if name in ['trigger_install_packages','trigger_remove_packages','trigger_forget_packages']:
                        required_attributes.append('packages')
                    if name in ['trigger_change_description']:
                        required_attributes.append('computer_description')
                    if name in waptservice_remote_actions:
                        required_attributes.extend(waptservice_remote_actions[name].required_attributes)

                    verified_by = chain[0].verify_claim(action,max_age_secs=waptconfig.signature_clockskew,
                        required_attributes=required_attributes)
                if not verified_by:
                    raise SSLVerifyException('Bad signature for action %s, aborting' % action)

            if verified_by:
                verified_by = verified_by.get('verified_by',None)

            result = []
            for action in actions:
                uuid = action['uuid']
                if uuid != self.wapt.host_uuid:
                    raise Exception('Task is not targeted to this host. task''s uuid does not match host''uuid')
                name = action['action']
                if name in ['trigger_cancel_all_tasks']:
                    data = [t.as_dict() for t in self.task_manager.cancel_all_tasks()]
                    result.append(data)

                elif name in ['trigger_host_update','trigger_host_register']:
                    if name == 'trigger_host_update':
                        task = WaptUpdate()
                    elif name == 'trigger_host_register':
                        task = WaptRegisterComputer(computer_description = action.get('computer_description',None))
                    task.force = action.get('force',False)
                    task.notify_user = action.get('notify_user',False)
                    task.notify_server_on_finish = action.get('notify_server',False)
                    task.created_by = verified_by
                    data = self.task_manager.add_task(task).as_dict()
                    result.append(data)

                elif name in ['trigger_change_description']:
                    desc = action.get('computer_description',None)
                    if desc is not None:
                        setuphelpers.set_computer_description(desc)
                        msg = u'Computer description of %s changed to %s' % (setuphelpers.get_hostname(),setuphelpers.get_computer_description())
                        if not setuphelpers.get_computer_description() == desc:
                            raise Exception(u'Computer description has not been changed')
                        result.append(dict(success=True,
                            msg = msg,
                            result = msg,
                            ))
                        if action.get('notify_server',False):
                            task = WaptUpdate(created_by=verified_by)
                            task.notify_server_on_finish = True
                            self.task_manager.add_task(task)
                            result.append(task.as_dict())

                elif name == 'trigger_host_upgrade':
                    notify_user = action.get('notify_user',False)
                    notify_server_on_finish = action.get('notify_server',False)
                    force = action.get('force',False)
                    self.wapt.update(force=force)
                    upgrades = self.wapt.list_upgrade()
                    to_install = upgrades['upgrade']+upgrades['additional']+upgrades['install']
                    for req in to_install:
                        result.append(self.task_manager.add_task(WaptPackageInstall(req,force=force,notify_user=notify_user,created_by=verified_by)).as_dict())

                    result.append(self.task_manager.add_task(WaptUpgrade(notify_user=notify_user,created_by=verified_by)).as_dict())
                    result.append(self.task_manager.add_task(WaptCleanup(notify_user=False,created_by=verified_by)).as_dict())

                elif name in  ['trigger_install_packages','trigger_remove_packages','trigger_forget_packages']:
                    packagenames = ensure_list(action['packages'])
                    for packagename in packagenames:
                        if name == 'trigger_install_packages':
                            task = WaptPackageInstall(packagename=packagename)
                        elif name == 'trigger_remove_packages':
                            task = WaptPackageRemove(packagename=packagename)
                        elif name == 'trigger_forget_packages':
                            task = WaptPackageForget(packagenames=packagename)
                        task.force = action.get('force',False)
                        task.notify_user = action.get('notify_user',False)
                        task.notify_server_on_finish = action.get('notify_server',False)
                        task.created_by=verified_by

                        result.append(self.task_manager.add_task(task).as_dict())
                elif name in waptservice_remote_actions:
                    waptservice_remote_actions[name].trigger_action(self,action,verified_by)
                else:
                    raise EWaptException('Unhandled remote action %s' % name)

            #self.emit('trigger_update_result',{'result':data})
            if result_callback:
                result_callback(make_response(result,uuid=self.wapt.host_uuid,request_time=time.time()-start_time))
        except BaseException as e:
            logger.info('Exception for actions %s: %s' % (repr(args),repr(e)))
            if result_callback:
                result_callback(make_response_from_exception(e,uuid=self.wapt.host_uuid,request_time=time.time()-start_time))

    def on_get_tasks_status(self,args,result_callback=None):
        # check signatures
        try:
            if not self.wapt:
                raise Exception('Wapt not available')

            uuid = args.get('uuid','')
            if uuid != self.wapt.host_uuid:
                raise Exception('Task is not targeted to this host. task''s uuid does not match host''uuid')

            data = self.task_manager.tasks_status()
            if result_callback:
                result_callback(make_response(data,uuid=self.wapt.host_uuid,))

        except BaseException as e:
            logger.info('Exception for actions %s: %s' % (repr(args),repr(e)))
            if result_callback:
                result_callback(make_response_from_exception(e,uuid=self.wapt.host_uuid))

    def on_trigger_longtask(self,args,result_callback=None):
        task = WaptLongTask()
        task.force = args.get('force',False)
        task.notify_user = args.get('notify_user',False)
        task.notify_server_on_finish = args.get('notify_server',False)
        data = self.task_manager.add_task(task).as_dict()
        if result_callback:
            result_callback(make_response(data,uuid=self.wapt.host_uuid))

    def on_wapt_ping(self,args):
        logger.debug('wapt_ping... %s'% (args,))
        self.emit('wapt_pong')

    def on_message(self,message):
        logger.debug(u'socket.io message : %s' % message)

    def on_wapt_trigger_update_status(self,message):
        logger.info(u'trigger update status from server: %s' % message)
        task = WaptUpdate()
        task.force = False
        task.notify_user = False
        task.notify_server_on_finish = True
        task.created_by = 'waptservice'
        self.task_manager.add_task(task).as_dict()

    def on_event(self,event,*args):
        logger.debug(u'socket.io event : %s, args: %s' % (event,args))


class WaptSocketIOClient(threading.Thread):
    def __init__(self,config_filename = 'c:/wapt/wapt-get.ini',task_manager=None):
        threading.Thread.__init__(self)
        self.config_filename = config_filename
        self.task_manager = task_manager
        self.config = WaptServiceConfig(config_filename)
        self.socketio_client = None
        self.wapt_remote_calls = None


    def run(self):
        self.config.reload_if_updated()
        with Wapt(config_filename = self.config.config_filename) as tmp_wapt:
            logger.info('Starting socketio on "%s://%s:%s" ...' % (self.config.websockets_proto,self.config.websockets_host,self.config.websockets_port))
            logger.debug('Certificate checking : %s' %  self.config.websockets_verify_cert)
            while True:
                try:
                    connect_params = dict(
                        uuid = tmp_wapt.host_uuid,
                    )
                    host_key = tmp_wapt.get_host_key()
                    host_cert = tmp_wapt.get_host_certificate()

                    if not self.socketio_client and self.config.websockets_host:
                        logger.debug('Creating socketio client')
                        logger.debug('Proxies : %s'%self.config.waptserver.proxies)
                        # bug in socketio... ? we must not pass proxies at all (even None) if we don"t want to switch to polling mode...
                        kwargs = {}
                        if self.config.waptserver.proxies and self.config.waptserver.proxies.get(self.config.websockets_proto,None) is not None:
                            kwargs['proxies'] = self.config.waptserver.proxies


                        signed_connect_params = host_key.sign_claim(connect_params,certificate = host_cert)

                        self.socketio_client = SocketIO(
                                host="%s://%s" % (self.config.websockets_proto,self.config.websockets_host),
                                port=self.config.websockets_port,
                                Namespace = WaptSocketIORemoteCalls,
                                resource=self.config.websockets_root,
                                verify=self.config.websockets_verify_cert,
                                wait_for_connection = False,
                                transport = ['websocket'],
                                ping_interval = self.config.websockets_ping,
                                hurry_interval_in_seconds = self.config.websockets_hurry_interval,
                                params = {'uuid': tmp_wapt.host_uuid, 'login':jsondump(signed_connect_params)},
                                **kwargs)
                        self.socketio_client.get_namespace().wapt = tmp_wapt
                        self.socketio_client.get_namespace().task_manager = self.task_manager

                    if self.socketio_client and self.config.websockets_host:
                        if not self.socketio_client.connected:
                            signed_connect_params = host_key.sign_claim(connect_params,certificate = host_cert)

                            self.socketio_client._http_session.params.update({'uuid': tmp_wapt.host_uuid,'login':jsondump(signed_connect_params)})
                            self.socketio_client.define(WaptSocketIORemoteCalls)
                            self.socketio_client.get_namespace().wapt = tmp_wapt
                            self.socketio_client.get_namespace().task_manager = self.task_manager
                            self.socketio_client.connect('')
                        else:
                            self.socketio_client.emit('wapt_pong')

                        if self.socketio_client.connected:
                            logger.info('Socket IO listening for %ss' % self.config.websockets_check_config_interval )
                            startwait = time.time()
                            self.socketio_client.wait(self.config.websockets_check_config_interval)
                            # QAD workaround for cases where server disconnect but client is between 2 states.
                            # In this case; wait() immediately returns, leading to an indefinite loop eating 1 core.
                            if time.time() - startwait < self.config.websockets_check_config_interval-2:
                                raise Exception('Websocket client seems disconnected. Force Websocket connection to be recreated')
                    elif not self.config.websockets_host:
                        self.socketio_client = None

                    if self.config.reload_if_updated():
                        if self.socketio_client:
                            self.socketio_client.disconnect()
                        raise EWaptException('Configuration changed, force Websocket connection to be recreated')


                except Exception as e:
                    logger.info('Error in socket io connection %s' % repr(e))
                    self.config.reload_if_updated()
                    if self.socketio_client:
                        logger.debug('stop sio client')
                        self.socketio_client = None
                    logger.debug('Socket IO Stopped, waiting %ss before retrying' %
                        self.config.websockets_retry_delay)
                    time.sleep(self.config.websockets_retry_delay)

if __name__ == "__main__":
    pass