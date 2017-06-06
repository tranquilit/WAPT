#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      htouvet
#
# Created:     06/06/2017
# Copyright:   (c) htouvet 2017
# Licence:     <your licence>
#-------------------------------------------------------------------------------
__version__ = "1.5.0.5"
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

import ConfigParser
from optparse import OptionParser

import hashlib
import requests

# flask
from flask import request, Flask,Response, send_from_directory, send_file, session, g, redirect, url_for, abort, render_template, flash, stream_with_context
from flask_paginate import Pagination

import jinja2
from werkzeug.utils import secure_filename
from werkzeug.utils import html

from socketIO_client import SocketIO, LoggingSocketIONamespace,SocketIONamespace

from urlparse import urlparse
from functools import wraps

import logging
logger = logging.getLogger('waptservice')
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')


import json
import StringIO

import Queue
import traceback
import locale

import datetime
import copy

import tempfile

# wapt specific stuff
from waptutils import *

import common
from common import Wapt
import setuphelpers
from waptpackage import PackageEntry,WaptLocalRepo,WaptPackage

class WaptServiceConfig(object):
    """Configuration parameters from wapt-get.ini file
    >>> waptconfig = WaptServiceConfig('c:/wapt/wapt-get.ini')
    >>> waptconfig.load()
    """

    global_attributes = ['config_filename','waptservice_user','waptservice_password',
         'MAX_HISTORY','waptservice_port',
         'dbpath','loglevel','log_directory','waptserver','authorized_callers_ip',
         'hiberboot_enabled','max_gpo_script_wait','pre_shutdown_timeout','log_to_windows_events']

    def __init__(self,config_filename=None):
        if not config_filename:
            self.config_filename = os.path.join(wapt_root_dir,'wapt-get.ini')
        else:
            self.config_filename = config_filename
        self.waptservice_user = None
        self.waptservice_password = None

        # maximum nb of tasks to keep in history wapt task manager
        self.MAX_HISTORY = 30

        # http localserver
        self.waptservice_port = 8088

        # zeroMQ publishing socket
        self.zmq_port = None

        # default language
        self.language = locale.getdefaultlocale()[0]

        # session key
        self.secret_key = '1234567890'

        self.dbpath = os.path.join(wapt_root_dir,'db','waptdb.sqlite')
        self.loglevel = "warning"
        self.log_directory = os.path.join(wapt_root_dir,'log')
        if not os.path.exists(self.log_directory):
            os.mkdir(self.log_directory)

        self.log_to_windows_events = False

        self.waptserver = None
        self.authorized_callers_ip = []

        self.waptservice_poll_timeout = 10
        self.waptupdate_task_period = None
        self.waptupgrade_task_period = None

        self.config_filedate = None

        self.hiberboot_enabled = None
        self.max_gpo_script_wait = None
        self.pre_shutdown_timeout = None

        self.websockets_proto = None
        self.websockets_host = None
        self.websockets_port = None
        self.websockets_verify_cert = False
        self.websockets_ping = 10
        self.websockets_retry_delay = 60
        self.websockets_check_config_interval = 120
        self.websockets_hurry_interval = 1


    def load(self):
        """Load waptservice parameters from global wapt-get.ini file"""
        config = ConfigParser.RawConfigParser()
        if os.path.exists(self.config_filename):
            config.read(self.config_filename)
            self.config_filedate = os.stat(self.config_filename).st_mtime
        else:
            raise Exception(_("FATAL. Couldn't open config file : {}").format(self.config_filename))
        # lecture configuration
        if config.has_section('global'):
            if config.has_option('global', 'waptservice_user'):
                self.waptservice_user = config.get('global', 'waptservice_user')
            else:
                self.waptservice_user = None

            if config.has_option('global','waptservice_password'):
                self.waptservice_password = config.get('global', 'waptservice_password')
            else:
                logger.info(u"No password set for local waptservice, using local computer security")
                self.waptservice_password=None  # = password

            if config.has_option('global','waptservice_port'):
                port = config.get('global','waptservice_port')
                if port:
                    self.waptservice_port = int(port)
                else:
                    self.waptservice_port = None
            else:
                self.waptservice_port=8088

            if config.has_option('global','zmq_port'):
                self.zmq_port = int(config.get('global','zmq_port'))
            else:
                self.zmq_port=5000

            if config.has_option('global','language'):
                self.language = config.get('global','language')

            if config.has_option('global','secret_key'):
                self.secret_key = config.get('global','secret_key')

            if config.has_option('global','waptservice_poll_timeout'):
                self.waptservice_poll_timeout = int(config.get('global','waptservice_poll_timeout'))
            else:
                self.waptservice_poll_timeout = 10

            if config.has_option('global','waptupgrade_task_period'):
                self.waptupgrade_task_period = int(config.get('global','waptupgrade_task_period'))
            else:
                self.waptupgrade_task_period = None

            if config.has_option('global','waptupdate_task_period'):
                self.waptupdate_task_period = int(config.get('global','waptupdate_task_period'))
            else:
                self.waptupdate_task_period = None

            if config.has_option('global','dbpath'):
                self.dbpath =  config.get('global','dbpath')
            else:
                self.dbpath = os.path.join(wapt_root_dir,'db','waptdb.sqlite')

            if self.dbpath != ':memory:':
                self.dbdir = os.path.dirname(self.dbpath)
                if not os.path.isdir(self.dbdir):
                    os.makedirs(self.dbdir)
            else:
                self.dbdir = None

            if config.has_option('global','loglevel') and options.loglevel is None:
                self.loglevel = config.get('global','loglevel')
                setloglevel(logger,self.loglevel)
            elif options.loglevel is None:
                # default to warning
                setloglevel(logger,'warning')

            if config.has_option('global','log_to_windows_events'):
                self.log_to_windows_events = config.getboolean('global','log_to_windows_events')

            if config.has_option('global','wapt_server'):
                self.waptserver = common.WaptServer().load_config(config)
                waptserver_url = urlparse(self.waptserver.server_url)
                if waptserver_url.port is None:
                    if waptserver_url.scheme == 'https':
                        self.websockets_port = 443
                        self.websockets_host = waptserver_url.hostname
                        self.websockets_proto = 'https'
                    else:
                        self.websockets_port = 80
                        self.websockets_host = waptserver_url.hostname
                        self.websockets_proto = 'http'
                else:
                    self.websockets_port = waptserver_url.port
                    self.websockets_host = waptserver_url.hostname
                    self.websockets_proto = 'http'
            else:
                self.waptserver = None
                self.websockets_host = None
                self.websockets_proto = None
                self.websockets_port = None
                self.websockets_verify_cert = False


            if config.has_option('global','websockets_verify_cert'):
                try:
                    self.websockets_verify_cert = config.getboolean('global','websockets_verify_cert')
                except:
                    self.websockets_verify_cert = config.get('global','websockets_verify_cert')
                    if not os.path.isfile(self.websockets_verify_cert):
                        logger.warning(u'websockets_verify_cert certificate %s declared in configuration file can not be found. Waptserver websockets communication will fail' % self.websockets_verify_cert)
            else:
                self.websockets_verify_cert = self.waptserver.verify_cert

            if config.has_option('global','websockets_ping'):
                self.websockets_ping = config.getint('global','websockets_ping')

            if config.has_option('global','websockets_retry_delay'):
                self.websockets_retry_delay = config.getint('global','websockets_retry_delay')

            if config.has_option('global','websockets_check_config_interval'):
                self.websockets_check_config_interval = config.getint('global','websockets_check_config_interval')

            if config.has_option('global','websockets_hurry_interval'):
                self.websockets_hurry_interval = config.getint('global','websockets_hurry_interval')


            # settings for waptexit / shutdown policy
            #   recommended settings :
            #       hiberboot_enabled = 0
            #       max_gpo_script_wait = 180
            #       pre_shutdown_timeout = 180
            for param in ('hiberboot_enabled','max_gpo_script_wait','pre_shutdown_timeout'):
                if config.has_option('global',param):
                    setattr(self,param,config.getint('global',param))
                else:
                    setattr(self,param,None)

        else:
            raise Exception (_("FATAL, configuration file {} has no section [global]. Please check Waptserver documentation").format(self.config_filename))

    def reload_if_updated(self):
        """Check if config file has been updated,
        Return None if config has not changed or date of new config file if reloaded"""
        if os.path.exists(self.config_filename):
            new_config_filedate = os.stat(self.config_filename).st_mtime
            if new_config_filedate!=self.config_filedate:
                logger.info(u'Reloading configuration')
                self.load()
                return new_config_filedate
            else:
                return None
        else:
            return None

    def as_dict(self):
        result = {}
        for att in self.global_attributes:
            result[att] = getattr(self,att)
        return result

    def __unicode__(self):
        return u"{}".format(self.as_dict(),)


def make_response(result = {},success=True,error_code='',msg='',request_time=None):
    data = dict(
            success = success,
            msg = msg,
            )
    if not success:
        data['error_code'] = error_code
    else:
        data['result'] = result
    data['request_time'] = request_time
    return data

def make_response_from_exception(exception,error_code=''):
    """Return a dict for websocket result callback from exception
        success : False
        msg : message from exception
        error_code : classname of exception if not provided
   """
    if not error_code:
        error_code = type(exception).__name__.lower()
    data = dict(
            success = False,
            error_code = error_code
            )
    data['msg'] = "%s" % repr(exception)
    return data

class WaptSocketIORemoteCalls(SocketIONamespace):

    def initialize(self):
        """Initialize custom variables here.
        You can override this method."""
        logger.debug('New waptremotecall instance created...')
        self.actions = []
        self._id = 0

    def add_action(self,action,args):
        self._id +=1
        action = dict(
            id = self._id,
            description=action,
            summary = jsondump(args)
        )
        self.actions.append(action)
        return action

    def on_trigger_update(self,args,result_callback=None):
        print('Update triggered by SocketIO')
        data = self.add_action('update',args)
        if result_callback:
            print('callback...')
            result_callback(make_response(data))


    def on_trigger_upgrade(self,args,result_callback=None):
        print('Upgrade triggered by SocketIO')
        data = self.add_action('upgrade',args)
        if result_callback:
            print('callback...')
            result_callback(make_response(data))

    def on_trigger_register(self,args,result_callback=None):
        print('register triggered by SocketIO')

    def on_get_tasks_status(self,args,result_callback=None):
        print('task_status triggered by SocketIO')
        data = dict(
            done=self.actions,
            pending=[],
            errors=[],
            running=dict(description='Testing...'))
        if result_callback:
            print('callback...')
            result_callback(make_response(data))


    def on_trigger_install_packages(self,args,result_callback=None):
        print('install triggered by SocketIO')
        data = self.add_action('install',args)
        if result_callback:
            print('callback...')
            result_callback(make_response(data))

    def on_trigger_remove_packages(self,args,result_callback=None):
        print('remove triggered by SocketIO')
        data = self.add_action('remove',args)
        if result_callback:
            print('callback...')
            result_callback(make_response(data))

    def on_trigger_forget_packages(self,args,result_callback=None):
        print('forget triggered by SocketIO')
        data = self.add_action('forget',args)
        if result_callback:
            print('callback...')
            result_callback(make_response(data))


    def on_wapt_ping(self,args):
        print('wapt_ping... %s'% (args,))
        self.emit('wapt_pong')

    def on_message(self,message):
        logger.debug(u'socket.io message : %s' % message)

    def on_event(self,event,*args):
        logger.debug(u'socket.io event : %s, args: %s' % (event,args))


class WaptTestHost(object):
    def __init__(self,config_filename = 'c:/wapt/wapt-get.ini'):
        self.config_filename = config_filename
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
                    if not self.socketio_client and self.config.websockets_host:
                        logger.debug('Creating socketio client')
                        logger.debug('Proxies : %s'%self.config.waptserver.proxies)
                        # bug in socketio... ? we must not pass proxies at all (even None) if we don"t want to switch to polling mode...
                        kwargs = {}
                        if self.config.waptserver.proxies and self.config.waptserver.proxies.get(self.config.websockets_proto,None) is not None:
                            kwargs['proxies'] = self.config.waptserver.proxies

                        self.socketio_client = SocketIO(
                                host="%s://%s" % (self.config.websockets_proto,self.config.websockets_host),
                                port=self.config.websockets_port,
                                verify=self.config.websockets_verify_cert,
                                #cert=self.config.websockets_verify_cert,
                                wait_for_connection = False,
                                transport = ['websocket'],
                                ping_interval = self.config.websockets_ping,
                                hurry_interval_in_seconds = self.config.websockets_hurry_interval,
                                params = {'uuid':tmp_wapt.host_uuid},
                                **kwargs)
                        #logger.debug(self.socketio_client._engineIO_session.ping_interval)
                        self.wapt_remote_calls = self.socketio_client.define(WaptSocketIORemoteCalls)

                    if self.socketio_client and self.config.websockets_host:
                        if not self.socketio_client.connected:
                            self.socketio_client.connect('/')
                        if self.socketio_client.connected:
                            logger.info('Socket IO listening for %ss' % self.config.websockets_check_config_interval )
                            self.socketio_client.wait(self.config.websockets_check_config_interval)
                    self.config.reload_if_updated()
                except AssertionError:
                    pass

                except Exception as e:
                    logger.debug('Error in socket io connection %s' % repr(e))
                    if self.socketio_client and self.config.websockets_host:
                        try:
                            logger.debug('Creating socketio client')
                            self.socketio_client.disconnect()
                            self.socketio_client.connect('/')
                        except:
                            pass
                    logger.info('Socket IO Stopped, waiting %ss before retrying' % self.config.websockets_retry_delay)
                    time.sleep(self.config.websockets_retry_delay)

if __name__ == "__main__":
    usage="""\
    %prog -c configfile [action]

    WAPT Service.

    action is either :
      <nothing> : run service in foreground
      install   : install as a Windows service managed by nssm

    """

    parser=OptionParser(usage='test')
    parser.add_option("-c","--config", dest="config", default=os.path.join(wapt_root_dir,'wapt-get.ini') , help="Config file full path (default: %default)")
    parser.add_option("-l","--loglevel", dest="loglevel", default=None, type='choice',  choices=['debug','warning','info','error','critical'], metavar='LOGLEVEL',help="Loglevel (default: warning)")
    parser.add_option("-d","--devel", dest="devel", default=False,action='store_true', help="Enable debug mode (for development only)")

    (options,args)=parser.parse_args()

    def setloglevel(logger,loglevel):
        """set loglevel as string"""
        if loglevel in ('debug','warning','info','error','critical'):
            numeric_level = getattr(logging, loglevel.upper(), None)
            if not isinstance(numeric_level, int):
                raise ValueError(_('Invalid log level: {}').format(loglevel))
            logger.setLevel(numeric_level)

    client = WaptTestHost(options.config)
    client.run()

