#!/usr/bin/python
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

import sys
import os

try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..','..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

from waptserver.config import __version__
from waptserver.config import DEFAULT_CONFIG_FILE,load_config
from waptserver.utils import *
from waptserver.model import *
from waptcrypto import SSLCABundle,SSLPrivateKey,SSLCRL,SSLCertificate

from huey.contrib.sqlitedb import SqliteHuey,SqliteStorage
from huey.api import Huey, create_task
from huey import crontab

# hack to get a config filename from end of command line arguments without rewriting the huey consumer.
if len(sys.argv)>2 and os.path.isfile(sys.argv[-1]) and os.path.splitext(sys.argv[-1])[1]=='.ini':
    conf = load_config(sys.argv[-1])
else:
    conf = load_config()

tasks_db_dir = os.path.join(wapt_root_dir,'db')
if not os.path.isdir(tasks_db_dir):
    os.makedirs(tasks_db_dir)
tasks_db = os.path.join(tasks_db_dir,'waptservertasks.sqlite')

huey = SqliteHuey('wapt',filename=tasks_db)
huey.flush_locks()

logger.info('tasks db : %s'% tasks_db)

load_db_config(conf)

@huey.task(include_task=True,name='resign_crl')
@huey.periodic_task(crontab(minute='0',hour='*/1'))
def resign_crl():
    """Check validity of CRL and resign it if it will expire before next round.
    """
    if (conf['clients_signing_key'] and conf['clients_signing_certificate'] and conf['clients_signing_crl'] and \
            os.path.isfile(conf['clients_signing_key']) and os.path.isfile(conf['clients_signing_certificate'])):
        signing_key = SSLPrivateKey(conf['clients_signing_key'])
        signing_cert = SSLCertificate(conf['clients_signing_certificate'])
        server_ca = SSLCABundle(conf['clients_signing_certificate'])
        logger.info('Resigning CRL %s' % conf['clients_signing_crl'])
        try:
            crl = SSLCRL(conf['clients_signing_crl'],cakey=signing_key,cacert=signing_cert)
            if not crl.crl or crl.next_update <= datetime.datetime.utcnow() + datetime.timedelta(hours=1):
                crl.revoke_cert(crl_ttl_days = conf['clients_signing_crl_days'])
            crl.save_as_pem()
        except Exception as e:
            logger.warning('Unable to sign CRL %s: %s' % (conf['clients_signing_crl'],repr(e)))

