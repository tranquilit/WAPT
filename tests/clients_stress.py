#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      htouvet
#
# Created:     25/09/2018
# Copyright:   (c) htouvet 2018
# Licence:     <your licence>
#-------------------------------------------------------------------------------

from setuphelpers import *
from jinja2 import Template
import subprocess
import time
import os
from win32process import *


clients_dir = makepath(r'c:\wapttests')

wapt_ini_template = Template("""\
[global]
dbpath={{ basedir }}\db\waptdb.sqlite

fake_hostname={{hostname}}
host_organizational_unit_dn=DC=stresstest,DC=lan

use_fqdn_as_uuid=True

waptservice_port = {{waptservice_port}}

repo_url=https://srvwapt.ad.tranquil.it/wapt
wapt_server=https://srvwapt.ad.tranquil.it

public_certs_dir=c:\wapt\ssl
send_usage_report=0
use_hostpackages=1
use_kerberos=0
check_certificates_validity=0
waptwua_enabled=False
waptaudit_task_period=
notify_user=0
loglevel=critical
verify_cert=0

[store]
repo_url=http://wapt.tranquil.it/wapt

[wapt-templates]
repo_url=https://store.wapt.fr/wapt
verify_cert=1
""")

clients_processes = []

waptservice_dir = makepath(r'c:\tranquilit\wapt')
waptpython = makepath(waptservice_dir,'Scripts','python.exe')
waptservice_py = makepath(waptservice_dir,'waptservice','service.py')
#waptservice_py = makepath(waptservice_dir,'wapt-get.py')

waptservice_env = {
    'VIRTUAL_ENV': waptservice_dir,
    'PYTHONHOME': waptservice_dir,
    }

try:
    for client in range(0,100):
        hostname = 'pc%05i.stresstest.lan' % client
        print(hostname)
        waptservice_port = 18000+client

        basedir = makepath(clients_dir,hostname)
        mkdirs(makepath(basedir,'db'))
        waptini_fn = makepath(basedir,'wapt-get.ini')
        open(waptini_fn,'w').write(wapt_ini_template.render(locals()))

        env = os.environ
        env.update(waptservice_env)

        wapt_service = subprocess.Popen(
            args = '"%s" "%s" --config=%s' % (waptpython,waptservice_py,waptini_fn),
            cwd = waptservice_dir,
            env = env,
            shell=False,
            #stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            #creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
            )

        clients_processes.append((hostname,wapt_service))

    raw_input('Enter to stop...')
finally:
    for (hostname,process) in clients_processes:
        process.terminate()

