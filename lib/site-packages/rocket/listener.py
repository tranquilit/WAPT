# -*- coding: utf-8 -*-

# This file is part of the Rocket Web Server
# Copyright (c) 2010 Timothy Farrell

# Import System Modules
import os
import socket
import logging
import traceback
from threading import Thread

try:
    import ssl
    from ssl import SSLError
    has_ssl = True
except ImportError:
    has_ssl = False
    class SSLError(socket.error):
        pass
# Import Package Modules
from . import IS_JYTHON, NullHandler, THREAD_STOP_CHECK_INTERVAL

class Listener(Thread):
    """The Listener class is a class responsible for accepting connections
    and queuing them to be processed by a worker thread."""

    def __init__(self, interface, queue_size, active_queue, *args, **kwargs):
        Thread.__init__(self, *args, **kwargs)

        # Instance variables
        self.active_queue = active_queue
        self.interface = interface
        self.addr = interface[0]
        self.port = interface[1]
        self.secure = len(interface) == 4 and \
                      os.path.exists(interface[2]) and \
                      os.path.exists(interface[3])
        self.thread = None
        self.ready = False

        # Error Log
        self.err_log = logging.getLogger('Rocket.Errors.Port%i' % self.port)
        self.err_log.addHandler(NullHandler())

        # Build the socket
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if not listener:
            self.err_log.error("Failed to get socket.")
            return

        if self.secure:
            if not has_ssl:
                self.err_log.error("ssl module required to serve HTTPS.")
                return
            elif not os.path.exists(interface[2]):
                data = (interface[2], interface[0], interface[1])
                self.err_log.error("Cannot find key file "
                          "'%s'.  Cannot bind to %s:%s" % data)
                return
            elif not os.path.exists(interface[3]):
                data = (interface[3], interface[0], interface[1])
                self.err_log.error("Cannot find certificate file "
                          "'%s'.  Cannot bind to %s:%s" % data)
                return

        # Set socket options
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except:
            msg = "Cannot share socket.  Using %s:%i exclusively."
            self.err_log.warning(msg % (self.addr, self.port))

        try:
            if not IS_JYTHON:
                listener.setsockopt(socket.IPPROTO_TCP,
                                    socket.TCP_NODELAY,
                                    1)
        except:
            msg = "Cannot set TCP_NODELAY, things might run a little slower"
            self.err_log.warning(msg)

        try:
            listener.bind((self.addr, self.port))
        except:
            msg = "Socket %s:%i in use by other process and it won't share."
            self.err_log.error(msg % (self.addr, self.port))
        else:
            # We want socket operations to timeout periodically so we can
            # check if the server is shutting down
            listener.settimeout(THREAD_STOP_CHECK_INTERVAL)
            # Listen for new connections allowing queue_size number of
            # connections to wait before rejecting a connection.
            listener.listen(queue_size)

            self.listener = listener

            self.ready = True

    def wrap_socket(self, sock):
        try:
            sock = ssl.wrap_socket(sock,
                                   keyfile = self.interface[2],
                                   certfile = self.interface[3],
                                   server_side = True,
                                   ssl_version = ssl.PROTOCOL_SSLv23)
        except SSLError:
            # Generally this happens when an HTTP request is received on a
            # secure socket. We don't do anything because it will be detected
            # by Worker and dealt with appropriately.
            pass
        
        return sock

    def start(self):
        if not self.ready:
            self.err_log.warning('Listener started when not ready.')
            return
            
        if self.thread is not None and self.thread.isAlive():
            self.err_log.warning('Listener already running.')
            return
            
        self.thread = Thread(target=self.listen, name="Port" + str(self.port))
        
        self.thread.start()
    
    def isAlive(self):
        if self.thread is None:
            return False
        
        return self.thread.isAlive()

    def join(self):
        if self.thread is None:
            return
            
        self.ready = False
        
        self.thread.join()
        
        del self.thread
        self.thread = None
        self.ready = True
    
    def listen(self):
        if __debug__:
            self.err_log.debug('Entering main loop.')
        while True:
            try:
                sock, addr = self.listener.accept()

                if self.secure:
                    sock = self.wrap_socket(sock)

                self.active_queue.put(((sock, addr),
                                       self.interface[1],
                                       self.secure))

            except socket.timeout:
                # socket.timeout will be raised every THREAD_STOP_CHECK_INTERVAL
                # seconds.  When that happens, we check if it's time to die.

                if not self.ready:
                    if __debug__:
                        self.err_log.debug('Listener exiting.')
                    return
                else:
                    continue
            except:
                self.err_log.error(str(traceback.format_exc()))
