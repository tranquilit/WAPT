import dialog
from iniparse import RawConfigParser
import shutil
import fileinput
import os,glob,sys
import hashlib


def replaceAll(file,searchExp,replaceExp):
    for line in fileinput.input(file, inplace=1):
        if searchExp in line:
            line = line.replace(searchExp,replaceExp)
        sys.stdout.write(line)

postconf = dialog.Dialog(dialog="dialog")

if postconf.yesno("Do you wan't to launch post configuration tool ?") == postconf.DIALOG_OK:
    shutil.copyfile('/opt/wapt/waptserver/waptserver.ini.template','/opt/wapt/waptserver/waptserver.ini')
    waptserver_ini = RawConfigParser()

    replaceAll('/opt/wapt/waptserver/waptserver.ini','#','')
    waptserver_ini.read('/opt/wapt/waptserver/waptserver.ini')

    code, tag = postconf.menu("Where mongodb is install ?",
                              choices=[("1", "Localhost (default)"),
                                    ("2", "other serveur")])
    if code == postconf.DIALOG_OK:
        if tag == "1":
            waptserver_ini.set('options','mongodb_ip','127.0.0.1')
        elif tag == "2":
            (code,mongodb_ip) = postconf.inputbox("IP address of the mongodb serveur:")
            if code<>postconf.DIALOG_OK:
                exit(0)
            else:
                waptserver_ini.set('options','mongodb_ip',mongodb_ip)
        elif code<>postconf.DIALOG_OK:
            exit(0)

    code, tag = postconf.menu("Mongodb serveur port: ",
                                  choices=[("1", "27017 (default)"),
                                        ("2", "other")])
    if code == postconf.DIALOG_OK:
        if tag == "1":
            waptserver_ini.set('options','mongodb_port','27017')
        elif tag == "2":
            (code,mongodb_port) = postconf.inputbox("mongodb serveur port: ")
            if code<>postconf.DIALOG_OK:
                exit(0)
            else:
                waptserver_ini.set('options','mongodb_port',mongodb_port)
        elif code<>postconf.DIALOG_OK:
            exit(0)

    (code,wapt_password) = postconf.inputbox("wapt serveur password:  ")
    if code<>postconf.DIALOG_OK:
        exit(0)
    else:
        password = hashlib.sha512(wapt_password).hexdigest()
        waptserver_ini.set('options','wapt_password',password)

    with open('/opt/wapt/waptserver/waptserver.ini','w') as inifile:
        waptserver_ini.write(inifile)
    postconf.msgbox("Postconf is finished !! \n please start wapt server with /etc/init.d/waptserver start")
else:
    exit(0)
os.system('chown -R wapt:www-data /opt/wapt/')
