# -*- coding: utf-8 -*-

# This file is part of the Rocket Web Server
# Copyright (c) 2010 Timothy Farrell

# Import System Modules
import re
import sys
import socket
import logging
import traceback
from wsgiref.headers import Headers
from threading import Thread
from datetime import datetime

try:
    from urllib import unquote
except ImportError:
    from urllib.parse import unquote

try:
    from io import StringIO
except ImportError:
    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO

try:
    from ssl import SSLError
except ImportError:
    class SSLError(socket.error):
        pass
# Import Package Modules
from . import IGNORE_ERRORS_ON_CLOSE, b, PY3K, NullHandler, IS_JYTHON
from .connection import Connection

# Define Constants
re_SLASH = re.compile('%2F', re.IGNORECASE)
re_REQUEST_LINE = re.compile(r"""^
(?P<method>OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT)   # Request Method
\                                                            # (single space)
(
    (?P<scheme>[^:/]+)                                       # Scheme
    (://)  #
    (?P<host>[^/]+)                                          # Host
)? #
(?P<path>(\*|/[^ \?]*))                                      # Path
(\? (?P<query_string>[^ ]+))?                                # Query String
\                                                            # (single space)
(?P<protocol>HTTPS?/1\.[01])                                 # Protocol
$
""", re.X)
LOG_LINE = '%(client_ip)s - "%(request_line)s" - %(status)s %(size)s'
RESPONSE = '''\
HTTP/1.1 %s
Content-Length: %i
Content-Type: %s

%s
'''
if IS_JYTHON:
    HTTP_METHODS = set(['OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE', 'CONNECT'])

class Worker(Thread):
    """The Worker class is a base class responsible for receiving connections
    and (a subclass) will run an application to process the the connection """

    def __init__(self,
                 app_info,
                 active_queue,
                 monitor_queue,
                 *args,
                 **kwargs):

        Thread.__init__(self, *args, **kwargs)

        # Instance Variables
        self.app_info = app_info
        self.active_queue = active_queue
        self.monitor_queue = monitor_queue

        self.size = 0
        self.status = "200 OK"
        self.closeConnection = True
        self.request_line = ""

        # Request Log
        self.req_log = logging.getLogger('Rocket.Requests')
        self.req_log.addHandler(NullHandler())

        # Error Log
        self.err_log = logging.getLogger('Rocket.Errors.'+self.getName())
        self.err_log.addHandler(NullHandler())

    def _handleError(self, typ, val, tb):
        if typ == SSLError:
            if 'timed out' in val.args[0]:
                typ = SocketTimeout
        if typ == SocketTimeout:
            if __debug__:
                self.err_log.debug('Socket timed out')
            self.monitor_queue.put(self.conn)
            return True
        if typ == SocketClosed:
            self.closeConnection = True
            if __debug__:
                self.err_log.debug('Client closed socket')
            return False
        if typ == BadRequest:
            self.closeConnection = True
            if __debug__:
                self.err_log.debug('Client sent a bad request')
            return True
        if typ == socket.error:
            self.closeConnection = True
            if val.args[0] in IGNORE_ERRORS_ON_CLOSE:
                if __debug__:
                    self.err_log.debug('Ignorable socket Error received...'
                                       'closing connection.')
                return False
            else:
                self.status = "999 Utter Server Failure"
                tb_fmt = traceback.format_exception(typ, val, tb)
                self.err_log.error('Unhandled Error when serving '
                                   'connection:\n' + '\n'.join(tb_fmt))
                return False

        self.closeConnection = True
        tb_fmt = traceback.format_exception(typ, val, tb)
        self.err_log.error('\n'.join(tb_fmt))
        self.send_response('500 Server Error')
        return False

    def run(self):
        if __debug__:
            self.err_log.debug('Entering main loop.')

        # Enter thread main loop
        while True:
            conn = self.active_queue.get()

            if not conn:
                # A non-client is a signal to die
                if __debug__:
                    self.err_log.debug('Received a death threat.')
                return conn

            if isinstance(conn, tuple):
                conn = Connection(*conn)

            self.conn = conn

            if conn.ssl != conn.secure:
                self.err_log.info('Received HTTP connection on HTTPS port.')
                self.send_response('400 Bad Request')
                self.closeConnection = True
                conn.close()
                continue
            else:
                if __debug__:
                    self.err_log.debug('Received a connection.')
                self.closeConnection = False

            # Enter connection serve loop
            while True:
                if __debug__:
                    self.err_log.debug('Serving a request')
                try:
                    self.run_app(conn)
                    log_info = dict(client_ip = conn.client_addr,
                                    time = datetime.now().strftime('%c'),
                                    status = self.status.split(' ')[0],
                                    size = self.size,
                                    request_line = self.request_line)
                    self.req_log.info(LOG_LINE % log_info)
                except:
                    exc = sys.exc_info()
                    handled = self._handleError(*exc)
                    if handled:
                        break
                    else:
                        if self.request_line:
                            log_info = dict(client_ip = conn.client_addr,
                                            time = datetime.now().strftime('%c'),
                                            status = self.status.split(' ')[0],
                                            size = self.size,
                                            request_line = self.request_line + ' - not stopping')
                            self.req_log.info(LOG_LINE % log_info)

                if self.closeConnection:
                    try:
                        conn.close()
                    except:
                        self.err_log.error(str(traceback.format_exc()))

                    break

    def run_app(self, conn):
        # Must be overridden with a method reads the request from the socket
        # and sends a response.
        self.closeConnection = True
        raise NotImplementedError('Overload this method!')

    def send_response(self, status):
        stat_msg = status.split(' ', 1)[1]
        msg = RESPONSE % (status,
                          len(stat_msg),
                          'text/plain',
                          stat_msg)
        try:
            self.conn.sendall(b(msg))
        except socket.error:
            self.closeConnection = True
            self.err_log.error('Tried to send "%s" to client but received socket'
                           ' error' % status)

    #def kill(self):
    #    if self.isAlive() and hasattr(self, 'conn'):
    #        try:
    #            self.conn.shutdown(socket.SHUT_RDWR)
    #        except socket.error:
    #            info = sys.exc_info()
    #            if info[1].args[0] != socket.EBADF:
    #                self.err_log.debug('Error on shutdown: '+str(info))

    def read_request_line(self, sock_file):
        self.request_line = ''
        try:
            # Grab the request line
            d = sock_file.readline()
            if PY3K:
                d = d.decode('ISO-8859-1')

            if d == '\r\n':
                # Allow an extra NEWLINE at the beginning per HTTP 1.1 spec
                if __debug__:
                    self.err_log.debug('Client sent newline')

                d = sock_file.readline()
                if PY3K:
                    d = d.decode('ISO-8859-1')
        except socket.timeout:
            raise SocketTimeout("Socket timed out before request.")

        d = d.strip()

        if not d:
            if __debug__:
                self.err_log.debug('Client did not send a recognizable request.')
            raise SocketClosed('Client closed socket.')

        self.request_line = d

        # NOTE: I've replaced the traditional method of procedurally breaking
        # apart the request line with a (rather unsightly) regular expression.
        # However, Java's regexp support sucks so bad that it actually takes
        # longer in Jython to process the regexp than procedurally. So I've
        # left the old code here for Jython's sake...for now.
        if IS_JYTHON:
            return self._read_request_line_jython(d)

        match = re_REQUEST_LINE.match(d)

        if not match:
            self.send_response('400 Bad Request')
            raise BadRequest

        req = match.groupdict()
        for k,v in req.items():
            if not v:
                req[k] = ""
            if k == 'path':
                req['path'] = r'%2F'.join([unquote(x) for x in re_SLASH.split(v)])

        return req

    def _read_request_line_jython(self, d):
        d = d.strip()
        try:
            method, uri, proto = d.split(' ')
            if not proto.startswith('HTTP') or \
               proto[-3:] not in ('1.0', '1.1') or \
               method not in HTTP_METHODS:
                self.send_response('400 Bad Request')
                raise BadRequest
        except ValueError:
            self.send_response('400 Bad Request')
            raise BadRequest

        req = dict(method=method, protocol = proto)
        scheme = ''
        host = ''
        if uri == '*' or uri.startswith('/'):
            path = uri
        elif '://' in uri:
            scheme, rest = uri.split('://')
            host, path = rest.split('/', 1)
            path = '/' + path
        else:
            self.send_response('400 Bad Request')
            raise BadRequest

        query_string = ''
        if '?' in path:
            path, query_string = path.split('?', 1)

        path = r'%2F'.join([unquote(x) for x in re_SLASH.split(path)])

        req.update(path=path,
                   query_string=query_string,
                   scheme=scheme.lower(),
                   host=host)
        return req


    def read_headers(self, sock_file):
        try:
            headers = dict()
            l = sock_file.readline()
    
            lname = None
            lval = None
            while True:
                if PY3K:
                    try:
                        l = str(l, 'ISO-8859-1')
                    except UnicodeDecodeError:
                        self.err_log.warning('Client sent invalid header: ' + repr(l))
    
                if l == '\r\n':
                    break
    
                if l[0] in ' \t' and lname:
                    # Some headers take more than one line
                    lval += ',' + l.strip()
                else:
                    # HTTP header values are latin-1 encoded
                    l = l.split(':', 1)
                    # HTTP header names are us-ascii encoded
    
                    lname = l[0].strip().upper().replace('-', '_')
                    lval = l[-1].strip()
                headers[str(lname)] = str(lval)
    
                l = sock_file.readline()
        except socket.timeout:
            raise SocketTimeout("Socket timed out before request.")

        return headers

class SocketTimeout(Exception):
    "Exception for when a socket times out between requests."
    pass

class BadRequest(Exception):
    "Exception for when a client sends an incomprehensible request."
    pass

class SocketClosed(Exception):
    "Exception for when a socket is closed by the client."
    pass

class ChunkedReader(object):
    def __init__(self, sock_file):
        self.stream = sock_file
        self.chunk_size = 0

    def _read_header(self):
        chunk_len = ""
        try:
            while "" == chunk_len:
                chunk_len = self.stream.readline().strip()
            return int(chunk_len, 16)
        except ValueError:
            return 0

    def read(self, size):
        data = b('')
        chunk_size = self.chunk_size
        while size:
            if not chunk_size:
                chunk_size = self._read_header()

            if size < chunk_size:
                data += self.stream.read(size)
                chunk_size -= size
                break
            else:
                if not chunk_size:
                    break
                data += self.stream.read(chunk_size)
                size -= chunk_size
                chunk_size = 0

        self.chunk_size = chunk_size
        return data

    def readline(self):
        data = b('')
        c = self.read(1)
        while c and c != b('\n'):
            data += c
            c = self.read(1)
        data += c
        return data

    def readlines(self):
        yield self.readline()

def get_method(method):
    from .methods.wsgi import WSGIWorker
    from .methods.fs import FileSystemWorker
    methods = dict(wsgi=WSGIWorker,
                   fs=FileSystemWorker)
    return methods[method.lower()]
