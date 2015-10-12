
import common
import waptpackage
import waptdevutils
import logging
logger = logging.getLogger()
logging.basicConfig(level=logging.WARNING)
mywapt = common.Wapt(config_filename=r"C:\Users\%(user)s\AppData\Local\waptconsole\waptconsole.ini".decode('utf8'),disable_update_server_status=True)
mywapt.dbpath=':memory:'
mywapt.use_hostpackages = False
mywapt.search()
mywapt.repositories[0]
mywapt.repositories[0].repo_url
mywapt.repositories[0].is_available()
