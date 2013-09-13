# -*- coding: utf-8 -*-

# This file is part of the Rocket Web Server
# Copyright (c) 2010 Timothy Farrell

# Import System Modules
import sys
import time
import socket
import logging
import traceback
from threading import Lock
try:
    from queue import Queue
except ImportError:
    from Queue import Queue

# Import Package Modules
from . import DEFAULTS, SERVER_SOFTWARE, NullHandler, THREAD_STOP_CHECK_INTERVAL
from .monitor import Monitor
from .threadpool import ThreadPool
from .worker import get_method
from .listener import Listener

# Setup Logging
log = logging.getLogger('Rocket')
log.addHandler(NullHandler())

class Rocket(object):
    """The Rocket class is responsible for handling threads and accepting and
    dispatching connections."""

    def __init__(self,
                 interfaces = ('127.0.0.1', 8000),
                 method = 'wsgi',
                 app_info = None,
                 min_threads = None,
                 max_threads = None,
                 queue_size = None,
                 timeout = 600,
                 handle_signals = True):

        self.handle_signals = handle_signals
        self.startstop_lock = Lock()
        self.timeout = timeout

        if not isinstance(interfaces, list):
            self.interfaces = [interfaces]
        else:
            self.interfaces = interfaces

        if min_threads is None:
            min_threads = DEFAULTS['MIN_THREADS']

        if max_threads is None:
            max_threads = DEFAULTS['MAX_THREADS']

        if not queue_size:
            if hasattr(socket, 'SOMAXCONN'):
                queue_size = socket.SOMAXCONN
            else:
                queue_size = DEFAULTS['LISTEN_QUEUE_SIZE']

        if max_threads and queue_size > max_threads:
            queue_size = max_threads

        if isinstance(app_info, dict):
            app_info['server_software'] = SERVER_SOFTWARE

        self.monitor_queue = Queue()
        self.active_queue = Queue()

        self._threadpool = ThreadPool(get_method(method),
                                      app_info = app_info,
                                      active_queue = self.active_queue,
                                      monitor_queue = self.monitor_queue,
                                      min_threads = min_threads,
                                      max_threads = max_threads)

        # Build our socket listeners
        self.listeners = [Listener(i, queue_size, self.active_queue) for i in self.interfaces]
        for ndx in range(len(self.listeners)-1, 0, -1):
            if not self.listeners[ndx].ready:
                del self.listeners[ndx]

        if not self.listeners:
            log.critical("No interfaces to listen on...closing.")
            sys.exit(1)

    def _sigterm(self, signum, frame):
        log.info('Received SIGTERM')
        self.stop()

    def _sighup(self, signum, frame):
        log.info('Received SIGHUP')
        self.restart()

    def start(self, background=False):
        log.info('Starting %s' % SERVER_SOFTWARE)

        self.startstop_lock.acquire()

        try:
            # Set up our shutdown signals
            if self.handle_signals:
                try:
                    import signal
                    signal.signal(signal.SIGTERM, self._sigterm)
                    signal.signal(signal.SIGUSR1, self._sighup)
                except:
                    log.debug('This platform does not support signals.')

            # Start our worker threads
            self._threadpool.start()

            # Start our monitor thread
            self._monitor = Monitor(self.monitor_queue,
                                    self.active_queue,
                                    self.timeout,
                                    self._threadpool)
            self._monitor.setDaemon(True)
            self._monitor.start()

            # I know that EXPR and A or B is bad but I'm keeping it for Py2.4
            # compatibility.
            str_extract = lambda l: (l.addr, l.port, l.secure and '*' or '')

            msg = 'Listening on sockets: '
            msg += ', '.join(['%s:%i%s' % str_extract(l) for l in self.listeners])
            log.info(msg)

            for l in self.listeners:
                l.start()

        finally:
            self.startstop_lock.release()

        if background:
            return

        while self._monitor.isAlive():
            try:
                time.sleep(THREAD_STOP_CHECK_INTERVAL)
            except KeyboardInterrupt:
                # Capture a keyboard interrupt when running from a console
                break
            except:
                if self._monitor.isAlive():
                    log.error(str(traceback.format_exc()))
                    continue

        return self.stop()

    def stop(self, stoplogging = False):
        log.info('Stopping %s' % SERVER_SOFTWARE)

        self.startstop_lock.acquire()
        
        try:
            # Stop listeners
            for l in self.listeners:
                l.ready = False

            # Encourage a context switch
            time.sleep(0.01)

            for l in self.listeners:
                if l.isAlive():
                    l.join()

            # Stop Monitor
            self._monitor.stop()
            if self._monitor.isAlive():
                self._monitor.join()

            # Stop Worker threads
            self._threadpool.stop()

            if stoplogging:
                logging.shutdown()
                msg = "Calling logging.shutdown() is now the responsibility of \
                       the application developer.  Please update your \
                       applications to no longer call rocket.stop(True)"
                try:
                    import warnings
                    raise warnings.DeprecationWarning(msg)
                except ImportError:
                    raise RuntimeError(msg)

        finally:
            self.startstop_lock.release()

    def restart(self):
        self.stop()
        self.start()

def CherryPyWSGIServer(bind_addr,
                       wsgi_app,
                       numthreads = 10,
                       server_name = None,
                       max = -1,
                       request_queue_size = 5,
                       timeout = 10,
                       shutdown_timeout = 5):
    """ A Cherrypy wsgiserver-compatible wrapper. """
    max_threads = max
    if max_threads < 0:
        max_threads = 0
    return Rocket(bind_addr, 'wsgi', {'wsgi_app': wsgi_app},
                  min_threads = numthreads,
                  max_threads = max_threads,
                  queue_size = request_queue_size,
                  timeout = timeout)
