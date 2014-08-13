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
import os,sys
try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'../..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0,os.path.join(wapt_root_dir))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib'))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib','site-packages'))

from iniparse import RawConfigParser
import shutil
import fileinput
import glob
import hashlib
import dialog
import subprocess

postconf = dialog.Dialog(dialog="dialog")

if postconf.yesno("Do you want to launch post configuration tool ?") == postconf.DIALOG_OK:
    shutil.copyfile('/opt/wapt/waptserver/waptserver.ini.template','/opt/wapt/waptserver/waptserver.ini')
    waptserver_ini = RawConfigParser()

    waptserver_ini.read('/opt/wapt/waptserver/waptserver.ini')

    if os.path.isdir('/var/www/wapt'):
        waptserver_ini.set('options','wapt_folder','/var/www/wapt')

    code, tag = postconf.menu("Mongodb server location",
                              choices=[("1", "localhost (default)"),
                                    ("2", "other server")])
    if code == postconf.DIALOG_OK:
        if tag == "1":
            waptserver_ini.set('options','mongodb_ip','127.0.0.1')
        elif tag == "2":
            (code,mongodb_ip) = postconf.inputbox("IP address of the mongodb server:")
            if code != postconf.DIALOG_OK:
                exit(1)
            else:
                waptserver_ini.set('options','mongodb_ip',mongodb_ip)
        elif code != postconf.DIALOG_OK:
            exit(1)

    code, tag = postconf.menu("Mongodb server port: ",
                                  choices=[("1", "27017 (default)"),
                                        ("2", "other")])
    if code == postconf.DIALOG_OK:
        if tag == "1":
            waptserver_ini.set('options','mongodb_port','27017')
        elif tag == "2":
            (code,mongodb_port) = postconf.inputbox("mongodb server port: ")
            if code != postconf.DIALOG_OK:
                exit(1)
            else:
                waptserver_ini.set('options','mongodb_port',mongodb_port)
        elif code != postconf.DIALOG_OK:
            exit(0)

    while 1:
        (code,wapt_password) = postconf.passwordbox("wapt server password:  ")
        if code != postconf.DIALOG_OK:
            exit(0)
        else:
            password = hashlib.sha1(wapt_password).hexdigest()
            waptserver_ini.set('options','wapt_password',password)
        if wapt_password != '':
            break

    with open('/opt/wapt/waptserver/waptserver.ini','w') as inifile:
        waptserver_ini.write(inifile)
        subprocess.check_output("/bin/chmod 640 /opt/wapt/waptserver/waptserver.ini",shell=True) 
        subprocess.check_output("/bin/chown wapt /opt/wapt/waptserver/waptserver.ini",shell=True)
    postconf.msgbox("postconf script completed !! \n Please start wapt server with /etc/init.d/waptserver start")
