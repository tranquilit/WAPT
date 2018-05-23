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
from waptserver.config import __version__
from flask import Flask
from flask_socketio import SocketIO

from waptserver.config import load_config
import logging

logger = logging.getLogger()

# allow chunked uploads when no nginx reverse proxy server server (see https://github.com/pallets/flask/issues/367)
class FlaskApp(Flask):
    def __init__(self,*args,**kwargs):
        super(FlaskApp,self).__init__(*args,**kwargs)
        self.conf = load_config()

    def request_context(self, environ):
        # it's the only way I've found to handle chunked encoding request (otherwise flask.request.stream is empty)
        environ['wsgi.input_terminated'] = 1
        return super(FlaskApp, self).request_context(environ)

app = FlaskApp(__name__, static_folder='./templates/static')
# chain SocketIO server
socketio = SocketIO(app, logger = logger, engineio_logger = logger)

