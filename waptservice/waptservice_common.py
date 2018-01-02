# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2017  Tranquil IT Systems http://www.tranquil.it
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

import locale
import json
import urlparse
import copy

import ConfigParser
from optparse import OptionParser

# wapt specific stuff
from waptutils import *
import common
from common import Wapt
import setuphelpers
from setuphelpers import Version

logger = logging.getLogger()

import babel

from gettext import gettext
_ = gettext

class WaptServiceRemoteAction(object):
    def __init__(self,name,action,required_attributes=[]):
        self.name = name
        self.action = action
        self.required_attributes = required_attributes

    def trigger_action(self,*args,**argv):
        self.action(*args,**argv)

waptservice_remote_actions = {}

def register_remote_action(name,action,required_attributes=[]):
    waptservice_remote_actions[name] = WaptServiceRemoteAction(name,action,required_attributes)

class WaptEvent(object):
    """Store single event with list of subscribers"""
    DEFAULT_TTL = 20 * 60

    def __init__(self,topic,subject,data=None,runstatus = ''):
        self.topic = topic
        self.subject = subject
        self.data = copy.deepcopy(data)
        self.runstatus = runstatus

        self.id = None
        self.ttl = self.DEFAULT_TTL
        self.date = time.time()
        # list of ids of subscribers which have not yet retrieved the event
        self.subscribers = []

class WaptEvents(object):
    """Thread safe central list of last events so that consumer can get list
        of latest events using http long poll requests"""

    def __init__(self,max_history=300):
        self.last = -1
        self.max_history = max_history
        self.get_lock = threading.RLock()
        self.events = []
        self.subscribers = []


    def get_missed(self,last_read=None):
        """returns events since last_read"""
        with self.get_lock:
            if last_read is None:
                return self.events[:]
            else:
                first = self.last-len(self.events)+1
                if last_read <= first:
                    return self.events[:]
                else:
                    return self.events[last_read-first:]

    def put(self, item):
        with self.get_lock:
            self.events.append(item)
            item.subscribers.extend(self.subscribers)
            # keep track of a global position for consumers
            self.last +=1
            item.id = self.last
            if len(self.events) > self.max_history:
                del self.events[:len(self.events) - self.max_history]

    def add_event(self,topic,subject,data=None,runstatus = ''):
        item = WaptEvent(topic,subject,data,runstatus)
        self.put(item)

    def cleanup(self):
        """Remove events with age>ttl"""
        with self.get_lock:
            for item in reversed(self.events):
                if item.date+item.ttl > time.time():
                    self.events.remove(item)


class WaptServiceConfig(object):
    """Configuration parameters from wapt-get.ini file
    >>> waptconfig = WaptServiceConfig('c:/wapt/wapt-get.ini')
    >>> waptconfig.load()
    """

    global_attributes = ['config_filename','waptservice_user','waptservice_password',
         'MAX_HISTORY','waptservice_port',
         'dbpath','loglevel','log_directory','waptserver','authorized_callers_ip',
         'hiberboot_enabled','max_gpo_script_wait','pre_shutdown_timeout','log_to_windows_events',
         'allow_user_service_restart','signature_clockskew']

    def __init__(self,config_filename=None):
        if not config_filename:
            self.config_filename = os.path.join(wapt_root_dir,'wapt-get.ini')
        else:
            self.config_filename = config_filename
        self.waptservice_user = None
        self.waptservice_password = None

        # maximum nb of tasks to keep in history wapt task manager
        self.MAX_HISTORY = 30

        # add logged on user right to stop / start the service
        self.allow_user_service_restart = False

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
        self.waptupdate_task_period = 120
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
        self.websockets_root = 'socket.io'

        # tolerance time replay limit for signed actions from server
        self.signature_clockskew = 5*60


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
                if config.get('global','zmq_port'):
                    self.zmq_port = int(config.get('global','zmq_port'))
                else:
                    self.zmq_port = None
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
                self.waptupdate_task_period = 120

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

            if config.has_option('global','loglevel'):
                self.loglevel = config.get('global','loglevel')

            if config.has_option('global','log_to_windows_events'):
                self.log_to_windows_events = config.getboolean('global','log_to_windows_events')

            if config.has_option('global','allow_user_service_restart'):
                self.allow_user_service_restart = config.getboolean('global','allow_user_service_restart')

            if config.has_option('global','wapt_server'):
                self.waptserver = common.WaptServer().load_config(config)
                if self.waptserver.server_url:
                    waptserver_url = urlparse.urlparse(self.waptserver.server_url)
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

                    if waptserver_url.path in ('','/'):
                        self.websockets_root = 'socket.io'
                    else:
                        self.websockets_root = '%s/socket.io' % waptserver_url.path[1:]
                else:
                    self.waptserver = None
                    self.websockets_host = None
                    self.websockets_proto = None
                    self.websockets_port = None
                    self.websockets_verify_cert = False
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
                self.websockets_verify_cert = False

            if config.has_option('global','websockets_ping'):
                self.websockets_ping = config.getint('global','websockets_ping')

            if config.has_option('global','websockets_retry_delay'):
                self.websockets_retry_delay = config.getint('global','websockets_retry_delay')

            if config.has_option('global','websockets_check_config_interval'):
                self.websockets_check_config_interval = config.getint('global','websockets_check_config_interval')

            if config.has_option('global','websockets_hurry_interval'):
                self.websockets_hurry_interval = config.getint('global','websockets_hurry_interval')

            if config.has_option('global','signature_clockskew'):
                self.signature_clockskew = config.getint('global','signature_clockskew')

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

class EventsPrinter:
    '''EventsPrinter class which serves to emulates a file object and logs
       whatever it gets sent to a broadcast object at the INFO level.'''
    def __init__(self,events,logs):
        '''Grabs the specific brodcaster to use for printing.'''
        self.events = events
        self.logs = logs

    def write(self, text):
        '''Logs written output to listeners'''
        if text and text != '\n':
            if self.events:
                self.events.send_multipart([str('PRINT'),(ensure_unicode(text)).encode('utf8')])
            self.logs.append(ensure_unicode(text))


def eventprintinfo(func):
    '''Wraps a method so that any calls made to print get logged instead'''
    def pwrapper(*arg, **kwargs):
        stdobak = sys.stdout
        if arg[0].wapt is not None:
            lpinstance = EventsPrinter(arg[0].wapt.events,arg[0].logs)
            sys.stdout = lpinstance
        try:
            return func(*arg, **kwargs)
        finally:
            sys.stdout = stdobak
    return pwrapper

class WaptTask(object):
    """Base object class for all wapt task : download, install, remove, upgrade..."""
    def __init__(self,**args):
        self.id = -1
        self.wapt = None
        self.priority = 100
        self.order = 0
        self.external_pids = []
        self.create_date = datetime.datetime.now()
        self.start_date = None
        self.finish_date = None
        self.logs = []
        self.result = None
        self.runstatus = ""
        self.summary = u""
        # from 0 to 100%
        self.progress = 0
        self.notify_server_on_start = True
        self.notify_server_on_finish = True
        self.notify_user = True
        self.created_by = None
        for k in args:
            setattr(self,k,args[k])
        self.lang = None

    def update_status(self,status):
        """Update runstatus in database and send PROGRESS event"""
        if self.wapt:
            self.runstatus = status
            self.wapt.runstatus = status
            if self.wapt.events:
                self.wapt.events.send_multipart(["TASKS",'PROGRESS',common.jsondump(self.as_dict())])

    def can_run(self,explain=False):
        """Return True if all the requirements for the task are met
        (ex. install can start if package+depencies are downloaded)"""
        return True

    def _run(self):
        """method to override in descendant to do the actual work"""
        pass

    @eventprintinfo
    def run(self):
        """register start and finish time, call _run, redirect stdout and stderr to events broadcaster
            result of task should be stored in self.result
            human readable summary of work done should be stored in self.summary
        """
        self.start_date = datetime.datetime.now()
        try:
            if self.wapt:
                self.wapt.task_is_cancelled.clear()
            # to keep track of external processes launched by Wapt.run()
            self.wapt.pidlist = self.external_pids
            self._run()
            self.progress=100
        finally:
            self.finish_date = datetime.datetime.now()

    def kill(self):
        """if task has been started, kill the task (ex: kill the external processes"""
        self.summary = u'Canceled'
        self.logs.append(u'Canceled')

        if self.wapt:
            self.wapt.task_is_cancelled.set()
        if self.external_pids:
            for pid in self.external_pids:
                logger.debug(u'Killing process with pid {}'.format(pid))
                setuphelpers.killtree(pid)
            del(self.external_pids[:])

    def run_external(self,*args,**kwargs):
        """Run an external process, register pid in current task to be able to kill it"""
        result = setuphelpers.run(*args,pidlist=self.external_pids,**kwargs)

    def __unicode__(self):
        return _(u"{classname} {id} created {create_date} started:{start_date} finished:{finish_date} ").format(**self.as_dict())

    def as_dict(self):
        return copy.deepcopy(dict(
            id=self.id,
            classname=self.__class__.__name__,
            priority = self.priority,
            order=self.order,
            create_date = self.create_date and self.create_date.isoformat(),
            start_date = self.start_date and self.start_date.isoformat(),
            finish_date = self.finish_date and self.finish_date.isoformat(),
            logs = u'\n'.join(self.logs),
            result = common.jsondump(self.result),
            summary = self.summary,
            progress = self.progress,
            runstatus = self.runstatus,
            description = u"{}".format(self),
            pidlist = u"{0}".format(self.external_pids),
            notify_user = self.notify_user,
            notify_server_on_start = self.notify_server_on_start,
            notify_server_on_finish = self.notify_server_on_finish,
            created_by = self.created_by,
            ))

    def as_json(self):
        return json.dumps(self.as_dict(),indent=True)

    def __repr__(self):
        return u"<{}>".format(self)

    def __cmp__(self,other):
        return cmp((self.priority,self.order),(other.priority,other.order))

    def same_action(self,other):
        return self.__class__ == other.__class__

class WaptNetworkReconfig(WaptTask):
    def __init__(self,**args):
        super(WaptNetworkReconfig,self).__init__()
        self.priority = 0
        self.notify_server_on_start = False
        self.notify_server_on_finish = False
        self.notify_user = False
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        logger.debug(u'Reloading config file')
        self.wapt.load_config(waptconfig.config_filename)
        self.wapt.network_reconfigure()
        waptconfig.load()
        self.result = waptconfig.as_dict()
        self.notify_server_on_finish = self.wapt.waptserver_available()

    def __unicode__(self):
        return _(u"Reconfiguring network access")


class WaptClientUpgrade(WaptTask):
    def __init__(self,**args):
        super(WaptClientUpgrade,self).__init__()
        self.priority = 10
        self.notify_server_on_start = True
        self.notify_server_on_finish = False
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        """Launch an external 'wapt-get waptupgrade' process to upgrade local copy of wapt client"""
        from setuphelpers import run
        output = ensure_unicode(run('"%s" %s' % (os.path.join(wapt_root_dir,'wapt-get.exe'),'waptupgrade')))
        self.result = {'result':'OK','message':output}

    def __unicode__(self):
        return _(u"Upgrading WAPT client")


class WaptServiceRestart(WaptTask):
    """A task to restart the waptservice using a spawned cmd process"""
    def __init__(self,**args):
        super(WaptServiceRestart,self).__init__()
        self.priority = 10000
        self.notify_server_on_start = False
        self.notify_server_on_finish = False
        self.notify_user = False
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        """Launch an external 'wapt-get waptupgrade' process to upgrade local copy of wapt client"""
        output = _(u'WaptService restart planned: %s' % setuphelpers.create_onetime_task('waptservicerestart','cmd.exe','/C net stop waptservice & net start waptservice'))
        self.result = {'result':'OK','message':output}

    def __unicode__(self):
        return _(u"Restarting local WAPT service")


class WaptUpdate(WaptTask):
    def __init__(self,**args):
        super(WaptUpdate,self).__init__()
        self.priority = 10
        self.notify_server_on_start = False
        self.notify_server_on_finish = True
        self.force = False
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        self.wapt.check_install_running()
        self.result = self.wapt.update(force=self.force,register=self.notify_server_on_finish)
        """result: {
            count: 176,
            added: [ ],
            repos: [
            "http://srvwapt.tranquilit.local/wapt",
            "http://srvwapt.tranquilit.local/wapt-host"
            ],
            upgrades: ['install': 'additional': 'upgrade': ],
            date: "2014-02-28T19:30:35.829000",
            removed: [ ]
        },"""
        s = []
        if len(self.result['added'])>0:
            s.append(_(u'{} new package(s)').format(len(self.result['added'])))
        if len(self.result['removed'])>0:
            s.append(_(u'{} removed package(s)').format(len(self.result['removed'])))
        s.append(_(u'{} package(s) in the repository').format(self.result['count']))
        all_install =  self.result['upgrades']['install']+\
                        self.result['upgrades']['additional']+\
                        self.result['upgrades']['upgrade']
        installs = u','.join(all_install)
        errors = u','.join([p.asrequirement() for p in  self.wapt.error_packages()])
        if installs:
            s.append(_(u'Packages to be updated : {}').format(installs))
        if errors:
            s.append(_(u'Packages with errors : {}').format(errors))
        if not installs and not errors:
            s.append(_(u'System up-to-date'))
        self.summary = u'\n'.join(s)

    def __unicode__(self):
        return _(u"Updating available packages")


class WaptUpgrade(WaptTask):
    def __init__(self,**args):
        super(WaptUpgrade,self).__init__()
        #self.priority = 10
        self.notify_server_on_start = False
        self.notify_server_on_finish = True
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        def cjoin(l):
            return u','.join([u"%s" % (p[1].asrequirement(),) for p in l])

        # TODO : create parent/child tasks
        # currently, only a place holder for report
        self.result = self.wapt.check_install(force=True,forceupgrade=True)
        #self.result = self.wapt.upgrade()
        """result: {
            unavailable: [ ],
            skipped: [ ],
            errors: [ ],
            downloads: {
                downloaded: [ ],
                skipped: [ ],
                errors: [ ]
            },
            upgrade: [ ],
            install: [ ],
            additional: [ ]
            }"""
        all_install = self.result.get('install',[])
        if self.result.get('additional',[]):
            all_install.extend(self.result['additional'])
        install = cjoin(all_install)
        upgrade = cjoin(self.result.get('upgrade',[]))
        #skipped = cjoin(self.result['skipped'])
        errors = ','.join([p.asrequirement() for p in  self.wapt.error_packages()])
        unavailable = u','.join([p[0] for p in self.result.get('unavailable',[])])
        s = []
        if install:
            s.append(_(u'Installed : {}').format(install))
        if upgrade:
            s.append(_(u'Updated : {}').format(upgrade))
        if errors:
            s.append(_(u'Errors : {}').format(errors))
        if unavailable:
            s.append(_(u'Unavailable : {}').format(unavailable))
        if not errors and not unavailable and not install and not upgrade:
            s.append(_(u'System up-to-date'))

        self.summary = u"\n".join(s)

    def __unicode__(self):
        return _(u'Upgrade packages installed on host')


class WaptUpdateServerStatus(WaptTask):
    """Send workstation status to server"""
    def __init__(self,**args):
        super(WaptUpdateServerStatus,self).__init__()
        self.priority = 10
        self.notify_server_on_start = False
        self.notify_server_on_finish = False
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        if self.wapt.waptserver_available():
            try:
                self.result = self.wapt.update_server_status()
                self.summary = _(u'WAPT Server has been notified')
            except Exception as e:
                self.result = {}
                self.summary = _(u"Error while sending to the server : {}").format(ensure_unicode(e))
        else:
            self.result = {}
            self.summary = _(u'WAPT Server is not available')

    def __unicode__(self):
        return _(u"Update server with this host's status")


class WaptRegisterComputer(WaptTask):
    """Send workstation status to server"""
    def __init__(self,computer_description = None,**args):
        super(WaptRegisterComputer,self).__init__(**args)
        self.priority = 10
        self.notify_server_on_start = False
        self.notify_server_on_finish = False
        self.computer_description = computer_description
        for k in args:
            setattr(self,k,args[k])


    def _run(self):
        if self.wapt.waptserver_available():
            try:
                self.result = self.wapt.register_computer(description = self.computer_description)
                self.summary = _(u"Inventory has been sent to the WAPT server")
            except Exception as e:
                self.result = {}
                self.summary = _(u"Error while sending inventory to the server : {}").format(ensure_unicode(e))
                raise
        else:
            self.result = {}
            self.summary = _(u'WAPT Server is not available')
            raise Exception(self.summary)

    def __unicode__(self):
        return _(u"Update server with this host's inventory")


class WaptCleanup(WaptTask):
    """Cleanup local packages cache"""
    def __init__(self,**args):
        super(WaptCleanup,self).__init__()
        self.priority = 1000
        self.notify_server_on_start = False
        self.notify_server_on_finish = False
        self.notify_user = False
        self.force = False
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        def cjoin(l):
            return u','.join([u'%s'%p for p in l])
        try:
            self.result = self.wapt.cleanup(obsolete_only=not self.force)
            self.summary = _(u"Packages erased : {}").format(cjoin(self.result))
        except Exception as e:
            self.result = {}
            self.summary = _(u"Error while clearing local cache : {}").format(ensure_unicode(e))
            raise Exception(self.summary)

    def __unicode__(self):
        return _(u"Clear local package cache")

class WaptLongTask(WaptTask):
    """Test action for debug purpose"""
    def __init__(self,**args):
        super(WaptLongTask,self).__init__()
        self.duration = 60
        self.raise_error = False
        self.notify_server_on_start = False
        self.notify_server_on_finish = False
        for k in args:
            setattr(self,k,args[k])


    def _run(self):
        self.progress = 0
        for i in range(self.duration):
            if self.wapt:
                self.wapt.check_cancelled()
            #print u"Step {}".format(i)
            self.update_status(u"Step {}".format(i))
            self.progress = 100.0 /self.duration * i
            #print "test {:.0f}%".format(self.progress)
            time.sleep(1)
        if self.raise_error:
            raise Exception(_('raising an error for Test WaptLongTask'))

    def same_action(self,other):
        return False

    def __unicode__(self):
        return _(u"Test long running task of {}s").format(self.duration)


class WaptDownloadPackage(WaptTask):
    def __init__(self,packagename,usecache=True,**args):
        super(WaptDownloadPackage,self).__init__()
        self.packagename = packagename
        self.usecache = usecache
        self.size = 0
        for k in args:
            setattr(self,k,args[k])

    def printhook(self,received,total,speed,url):
        self.wapt.check_cancelled()
        if total>1.0:
            stat = u'%i / %i (%.0f%%) (%.0f KB/s)\r' % (received,total,100.0*received/total, speed)
            self.progress = 100.0*received/total
            if not self.size:
                self.size = total
        else:
            stat = u''
        self.update_status(_(u'Downloading %s : %s' % (url,stat)))

    def _run(self):
        start = time.time()
        self.result = self.wapt.download_packages(self.packagename,usecache=self.usecache,printhook=self.printhook)
        end = time.time()
        if self.result['errors']:
            self.summary = _(u"Error while downloading {packagename}: {error}").format(packagename=self.packagename,error=self.result['errors'][0][1])
        else:
            if end-start> 0.01:
                self.summary = _(u"Done downloading {packagename}. {speed} kB/s").format(packagename=self.packagename,speed=self.size/1024/(end-start))
            else:
                self.summary = _(u"Done downloading {packagename}.").format(packagename=self.packagename)

    def as_dict(self):
        d = WaptTask.as_dict(self)
        d.update(
            dict(
                packagename = self.packagename,
                usecache = self.usecache,
                )
            )
        return d

    def __unicode__(self):
        return _(u"Download of {packagename} (tâche #{id})").format(classname=self.__class__.__name__,id=self.id,packagename=self.packagename)

    def same_action(self,other):
        return (self.__class__ == other.__class__) and (self.packagename == other.packagename)


class WaptPackageInstall(WaptTask):
    def __init__(self,packagename,force=False,**args):
        super(WaptPackageInstall,self).__init__()
        self.packagename = packagename
        self.force = force
        self.package = None
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        def cjoin(l):
            return u','.join([u"%s" % (p[1].asrequirement() if p[1] else p[0],) for p in l])
        self.result = self.wapt.install(self.packagename,force = self.force)
        all_install = self.result.get('install',[])
        if self.result.get('additional',[]):
            all_install.extend(self.result['additional'])
        install = cjoin(all_install)
        upgrade = cjoin(self.result.get('upgrade',[]))
        #skipped = cjoin(self.result['skipped'])
        errors = cjoin(self.result.get('errors',[]))
        unavailable = cjoin(self.result.get('unavailable',[]))
        s = []
        if install:
            s.append(_(u'Installed : {}').format(install))
        if upgrade:
            s.append(_(u'Updated : {}').format(upgrade))
        if errors:
            s.append(_(u'Errors : {}').format(errors))
        if unavailable:
            s.append(_(u'Unavailable : {}').format(unavailable))
        self.summary = u"\n".join(s)
        if self.result.get('errors',[]):
            raise Exception(_('Error during install of {}: errors in packages {}').format(
                    self.packagename,
                    self.result.get('errors',[])))

    def as_dict(self):
        d = WaptTask.as_dict(self)
        d.update(
            dict(
                packagename = self.packagename,
                force = self.force)
            )
        return d

    def __unicode__(self):
        return _(u"Installation of {packagename} (task #{id})").format(classname=self.__class__.__name__,id=self.id,packagename=self.packagename)

    def same_action(self,other):
        return (self.__class__ == other.__class__) and (self.packagename == other.packagename)


class WaptPackageRemove(WaptPackageInstall):
    def __init__(self,packagename,force=False,**args):
        super(WaptPackageRemove,self).__init__(packagename=packagename,force=force)
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        def cjoin(l):
            return u','.join([u'%s'%p for p in l])

        self.result = self.wapt.remove(self.packagename,force=self.force)
        s = []
        if self.result['removed']:
            s.append(_(u'Removed : {}').format(cjoin(self.result['removed'])))
        if self.result['errors']:
            s.append(_(u'Errors : {}').format(cjoin(self.result['errors'])))
        self.summary = u"\n".join(s)

    def __unicode__(self):
        return _(u"Uninstall of {packagename} (task #{id})").format(classname=self.__class__.__name__,id=self.id,packagename=self.packagename)


class WaptPackageForget(WaptTask):
    def __init__(self,packagenames,**args):
        super(WaptPackageForget,self).__init__()
        self.packagenames = packagenames
        for k in args:
            setattr(self,k,args[k])

    def _run(self):
        self.result = self.wapt.forget_packages(self.packagenames)
        if self.result:
            self.summary = _(u"Packages removed from database : %s") % (u"\n".join(self.result),)
        else:
            self.summary = _(u"No package removed from database.")

    def __unicode__(self):
        return _(u"Forget {packagenames} (task #{id})").format(classname=self.__class__.__name__,id=self.id,packagenames=self.packagenames)


    def same_action(self,other):
        return (self.__class__ == other.__class__) and (self.packagenames == other.packagenames)

def babel_translations(lang = ''):
    dirname = os.path.join(os.path.dirname(__file__), 'translations')
    return babel.support.Translations.load(dirname, [lang])

# init translations
waptconfig = WaptServiceConfig()
tr = babel_translations(waptconfig.language)
_ = tr.ugettext

