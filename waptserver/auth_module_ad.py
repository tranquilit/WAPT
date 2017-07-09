# copyright Tranquil IT Systems, all right reserved 2017


import os
import sys
try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'
sys.path.insert(0, os.path.join(wapt_root_dir))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib'))
sys.path.insert(0, os.path.join(wapt_root_dir, 'lib', 'site-packages'))

import re
import logging
import socket
import ldap
import traceback
import waptserver_config
import ConfigParser
import getpass

logger = logging.getLogger('waptserver')

DEFAULT_CONFIG_FILE = os.path.join(wapt_root_dir, 'conf', 'waptserver.ini')
conf = waptserver_config.load_config(DEFAULT_CONFIG_FILE)

def check_credentials_ad(username, password):

    dns_suffix = '.'.join(socket.getfqdn().split('.')[1:])
    dc_name = str(socket.gethostbyname(dns_suffix))
#    dc_name = 'newad.ad.tranquil.it'
    dc_kerberos_realm = dns_suffix.upper()
    dc_base_dn = ','.join(['dc=%s' % x for x in dns_suffix.split('.')])
    dc_ssl_enabled = conf['dc_ssl_enabled']
    wapt_admin_group = 'waptadmins'

    logger.debug('using dc %s for authentication, with base DN %s and kerberos realm %s ' % (dc_name, dc_base_dn, dc_kerberos_realm))

    if ':' in dc_name:
        logger.error("DC_NAME must be a DNS server name or ip, not a ldap url")
        raise

    auth_ok = False

    bind_username = '%s@%s' % (username, dc_kerberos_realm)

    ldap_filter = 'sAMAccountName=%s' % username
    attrs = ['memberOf']
    try:
        #ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        if dc_ssl_enabled==True:         
            ldap_client = ldap.initialize('ldaps://%s:636' % dc_name)
        else:
            ldap_client = ldap.initialize('ldap://%s:389' % dc_name)

        ldap_client.set_option(ldap.OPT_NETWORK_TIMEOUT, 5.0)
        ldap_client.set_option(ldap.OPT_REFERRALS, 0)
        ldap_client.simple_bind_s(bind_username, password)
        ldap_search_groups = ldap_client.search_s(dc_base_dn,
                                                  ldap.SCOPE_SUBTREE, ldap_filter, attrs)[0][1]['memberOf']
        logger.debug('user groups : %s ' % str(ldap_search_groups))

        for group in ldap_search_groups:
            if group.lower().startswith('cn=%s' % wapt_admin_group):
                print('AUTH OK : %s is members of group %s ' % (username, wapt_admin_group))
                auth_ok = True
        if auth_ok == False:
            print "AUTH FAILED : Credentials OK but user is not member of the group WaptAdmins"
    except ldap.INVALID_CREDENTIALS:
        logger.error('Wrong username %s password' % bind_username)
        auth_ok = False
    except ldap.SERVER_DOWN:
        logger.error(traceback.print_exc())
        logger.error("AD server is here but we couldn't open a connection, please check ssl / starttls parameters")
        auth_ok = False
    finally:
        try:
            ldap_client.unbind()
        except:
            pass

    return auth_ok

def enable_ssl(enabled):
    waptserver_ini = ConfigParser.RawConfigParser()
    config_file = '%s/conf/waptserver.ini' % wapt_root_dir
    waptserver_ini.readfp(file('/opt/wapt/conf/waptserver.ini', 'rU'))
    waptserver_ini.set('options','dc_ssl_enabled',enabled)
    with open('/opt/wapt/conf/waptserver.ini','w') as inifile:
        waptserver_ini.write(inifile)

def enable_ad_auth(enabled):
    waptserver_ini = ConfigParser.RawConfigParser()
    config_file = '%s/conf/waptserver.ini' % wapt_root_dir
    waptserver_ini.readfp(file('/opt/wapt/conf/waptserver.ini', 'rU'))
    waptserver_ini.set('options','dc_auth_enabled',enabled)
    with open('/opt/wapt/conf/waptserver.ini','w') as inifile:
        waptserver_ini.write(inifile)




if __name__ == "__main__":
    logger = logging.getLogger('waptserver')
#    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    logger.addHandler(ch)

    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')

    if len(sys.argv) > 1:
        print sys.argv[1]
        if sys.argv[1] == 'configure':
            print ('Configuring SSl module')
            # to switch to optionparser
            enable_value = sys.argv[2].split('--enable-ssl=')[1]
            print enable_value


            if enable_value.lower() in ('1','true'):
                enable_ssl(True)
            elif enable_value.lower() in ('0','false'):
                enable_ssl(False)
            else:
                print('error, wrong parameter, was expecting True or False')
            sys.exit(0)

        if sys.argv[1] == 'activate':
            print ('Configuring SSl module')
            # to switch to optionparser
            enable_value = sys.argv[2].split('--enable=')[1]
            print enable_value
            if enable_value.lower() in ('1','true'):
                enable_ad_auth(True)
            elif enable_value.lower() in ('0','false'):
                enable_ad_auth(False)
            else:
                print('error, wrong parameter, was expecting True or False')
            sys.exit(0)

        if sys.argv[1] == 'check_auth':
            username = sys.argv[2]
            try:
                password = sys.argv[3]
            except:
                password =  getpass.getpass('Password:')
            print ("checking for authentication of user %s "% username)
            check_credentials_ad(username,password) 
            sys.exit(0)
    else:
        print ("""usage :

        To enable/disable AD authentication (default : False)
                python auth_module_ad.py activate --enable=<True|False>

        To enable/disable ssl (default : True)
                python auth_module_ad.py configure --enable-ssl=<True|False>

        To check if authentication is working (password can be entered interactively)
                python auth_module_ad.py check_auth <username> [<password>]

                """)

