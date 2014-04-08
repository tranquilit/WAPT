import dialog
from iniparse import RawConfigParser
import shutil
import fileinput
import os,glob,sys
import hashlib

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

    (code,wapt_password) = postconf.passwordbox("wapt server password:  ")
    if code != postconf.DIALOG_OK:
        exit(0)
    else:
        password = hashlib.sha512(wapt_password).hexdigest()
        waptserver_ini.set('options','wapt_password',password)

    with open('/opt/wapt/waptserver/waptserver.ini','w') as inifile:
        waptserver_ini.write(inifile)
    postconf.msgbox("postconf script completed !! \n Please start wapt server with /etc/init.d/waptserver start")
