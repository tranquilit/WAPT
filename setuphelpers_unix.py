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
import os
import socket
import struct
import getpass
import platform
import configparser
import platform
import psutil
import netifaces
import json
import cpuinfo
import sys
import subprocess
import logging
import glob
import datetime
import platform
import grp
import pwd
from waptutils import (ensure_unicode, makepath, ensure_dir,currentdate,currentdatetime,_lower,ini2winstr,error,get_main_ip,TimeoutExpired,RunReader,RunOutput,killtree,run_notfatal)
import threading
import psutil
from subprocess import PIPE
import logging
import ipaddress
from ldap3 import Server, Connection, Tls, SASL, KERBEROS
import ssl
import dns.resolver


logger = logging.getLogger('waptcore')

def get_kernel_version():
    return os.uname()[2]

def user_home_directory():
    return os.path.expanduser('~')

def get_computer_groups():
    """Try to finc the computer in the Active Directory
    and return the list of groups
    """
    return get_groups_unix(get_computername.split('.')[0] + '$')

def get_groups_unix(user):
    gids = [g.gr_gid for g in grp.getgrall() if user.lower() in g.gr_mem]
    gid = pwd.getpwnam(user.lower()).pw_gid
    gids.append(grp.getgrgid(gid).gr_gid)
    return [grp.getgrgid(gid).gr_name for gid in gids]

def get_domain_info_unix():
    """Return ad site and ou
    Warning : Please note that the search for gssapi does not work if the reverse dns recording is not available for ad
    """
    result = {'ou':'','site':''}
    try:
        if platform.system() == 'Darwin':
            cmd = 'ktutil -k /etc/krb5.keytab list'
        else:
            cmd = 'klist -k'
        splitlist = subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT).split('$@',1)
        hostname = str(splitlist[0].rsplit(' ',1)[-1] + '$').split('/')[-1]
        domain = splitlist[1].split('\n')[0].strip()
        try:
            subprocess.check_output(r'kinit -k %s\@%s' % (hostname,domain),shell=True, stderr=subprocess.STDOUT)
        except:
            pass

        #TODO Get ldap_auth_server in wapt-get.ini
        ldap_auth_server = None

        list_controleur=[]
        if not ldap_auth_server:
            for entry in dns.resolver.query('_ldap._tcp.dc._msdcs.%s' % domain.lower(), 'SRV'):
                list_controleur.append(entry.to_text().split(' ')[-1].strip('.'))
        else:
            list_controleur.append(ldap_auth_server)

        for controleur in list_controleur:
            try:
                tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
                server = Server(controleur, use_ssl=True, tls=tls)
                c = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS)
                c.bind()

                # get ou with ldap
                c.search('dc=' + domain.lower().replace('.',',dc='),search_filter='(samaccountname=%s)' % hostname.lower(),attributes=['distinguishedName'])
                result['ou'] = c.response[0]['dn']

                # get site with ldap
                c.search('CN=Subnets,CN=Sites,CN=Configuration,dc=' + domain.lower().replace('.',',dc='),search_filter='(siteObject=*)',attributes=['siteObject','cn'])
                dict_ip_site = {}

                for i in c.response:
                    dict_ip_site[i['attributes']['cn']] = i['attributes']['siteObject'].split('=',1)[1].split(',',1)[0]

                for value in dict_ip_site:
                    if ipaddress.ip_address(get_main_ip().decode('utf-8')) in ipaddress.ip_network(value.decode('utf-8')) :
                        result['site'] = dict_ip_site[value]
            except :
                try:
                    c.unbind()
                except:
                    pass
                continue
            try:
                c.unbind()
            except:
                pass
            return result

    except:
        pass
    return result


def get_default_gateways():
    if platform.system() == 'Linux':
        """Read the default gateway directly from /proc."""
        with open("/proc/net/route") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue
                return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    elif platform.system() == 'Darwin':
        route_output = run('route get default').rstrip().split('\n')
        route_output = [line.strip() for line in route_output]
        route_dict = {}

        for line in route_output:
            split_l = line.split(':')
            try:
                route_dict[split_l[0]] = split_l[1].strip()
            except:
                pass
        gateway_ip = route_dict['gateway']
        gateway_hex = '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, gateway_ip.split('.')))
        return socket.inet_ntoa(struct.pack("<L", int(gateway_hex, 16)))


def user_local_appdata():
    r"""Return the local appdata profile of current user

    Returns:
        str: path like u'C:\\Users\\user\\AppData\\Local'
    """
    if 'HOME' in os.environ:
        return ensure_unicode(makepath(os.environ['HOME'],'.config/'))
    else:
        return ''


def local_drives():
    partitions = psutil.disk_partitions()
    result = {}
    for elem in partitions:
        result[elem.mountpoint]=dict(elem._asdict())
        result[elem.mountpoint]=result[elem.mountpoint].update(dict(psutil.disk_usage(elem.mountpoint)._asdict()))
    return result


def host_metrics():
    """Frequently updated host data
    """
    result = {}
    # volatile...
    result['physical_memory'] = psutil.virtual_memory().total
    result['virtual_memory'] = psutil.swap_memory().total
    result['local_drives'] = local_drives()
    result['logged_in_users'] = get_loggedinusers()
    result['last_logged_on_user'] = get_last_logged_on_user()

    # memory usage
    current_process = psutil.Process()
    result['wapt-memory-usage'] = dir(current_process.memory_info())

    return result


def default_gateway():
    """Returns default ipv4 current gateway"""
    gateways = netifaces.gateways()
    if gateways:
        default_gw = gateways.get('default',None)
        if default_gw:
            default_inet_gw = default_gw.get(netifaces.AF_INET,None)
        else:
            default_inet_gw = None
    if default_gateway:
        return default_inet_gw[0]
    else:
        return None


def networking():
    """return a list of (iface,mac,{addr,broadcast,netmask})
    """
    ifaces = netifaces.interfaces()
    local_ips = socket.gethostbyname_ex(socket.gethostname())[2]

    res = []
    for i in ifaces:
        params = netifaces.ifaddresses(i)
        if netifaces.AF_LINK in params and params[netifaces.AF_LINK][0]['addr'] and not params[netifaces.AF_LINK][0]['addr'].startswith('00:00:00'):
            iface = {'iface':i,'mac':params
            [netifaces.AF_LINK][0]['addr']}
            if netifaces.AF_INET in params:
                iface.update(params[netifaces.AF_INET][0])
                iface['connected'] = 'addr' in iface and iface['addr'] in local_ips
            res.append( iface )
    return res


def get_hostname():
    try:
        return socket.getfqdn().lower()
    except:
        return ""


def get_current_user():
    r"""Get the login name for the current user.
    >>> get_current_user()
    u'htouvet'
    """
    return ensure_unicode(getpass.getuser())

def application_data():
    return os.path.join(os.environ['HOME'],'.config')

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False
    return True


def get_dns_servers():
    dns_ips = []
    with open('/etc/resolv.conf') as fp:
        for cnt, line in enumerate(fp):
            columns = line.split()
            if len(columns) == 0 :
                continue
            if columns[0] == 'nameserver':
                ip = columns[1:][0]
                if is_valid_ipv4_address(ip):
                    dns_ips.append(ip)
    return dns_ips


def get_loggedinusers():
    suser = psutil.users()
    result = []
    for elem in suser:
        result.append(elem.name)
    return result


def get_last_logged_on_user():
    suser = psutil.users()
    res = ''
    for elem in suser:
        if res == '':
            res = elem
        elif res.started < elem.started:
            res = elem
    return res


def get_domain_batch():
    """Return main DNS domain of the computer

    Returns:
        str: domain name

    >>> get_domain_batch()
    u'tranquilit.local'
    """

    try:
        return socket.getfqdn().split('.', 1)[1]
    except:
        return ""


def host_info_common_unix():
    """Read main workstation informations, returned as a dict

    Returns:
        dict: main properties of host, networking and windows system

    .. versionchanged:: 1.4.1
         returned keys changed :
           dns_domain -> dnsdomain

    >>> hi = host_info()
    >>> 'computer_fqdn' in hi and 'connected_ips' in hi and 'computer_name' in hi and 'mac' in hi
    True
    """
    info = {}
    try:
        dmi = dmi_info()
        info['system_manufacturer'] = dmi['System_Information']['Manufacturer']
        info['system_productname'] = dmi['System_Information']['Product_Name']
    except:
        logger.warning('Error while running dmidecode, dmidecode needs root privileges')
        pass

    domain_info = get_domain_info_unix()
    info['computer_ad_dn'] =  domain_info['ou']
    info['computer_ad_site'] =  domain_info['site']

    info['computer_name'] = socket.gethostname()
    info['computer_fqdn'] = socket.getfqdn()
    info['dnsdomain'] = get_domain_batch()

    info['local_groups'] = {g.gr_name:g.gr_mem for g in grp.getgrall()}
    info['local_users'] = []
    for u in pwd.getpwall():
        info['local_users'].append(u.pw_name)
        try:
            gr_struct=grp.getgrgid(u.pw_gid)
            if info['local_groups'].has_key(gr_struct.gr_name):
                if u.pw_name not in info['local_groups'][gr_struct.gr_name]:
                    info['local_groups'][gr_struct.gr_name].append(u.pw_name)
            else:
                info['local_groups'][gr_struct.gr_name]=[u.pw_name]
        except:
            pass

    try:
        if os.path.isfile('/etc/samba/smb.conf'):
            config = configparser.RawConfigParser(strict=False)
            config.read('/etc/samba/smb.conf')
            if config.has_option('global','workgroup'):
                info['workgroup_name'] = config.get('global','workgroup')
    except:
        info['workgroup_name'] = ''

    info['networking'] = networking()
    info['gateways'] = [get_default_gateways()]
    info['dns_servers'] = get_dns_servers()
    info['connected_ips'] = [get_main_ip()]
    info['mac'] = [ c['mac'] for c in networking() if 'mac' in c and 'addr' in c and c['addr'] in info['connected_ips']]
    info['kernel_version'] = get_kernel_version()
    #Fix for vscode don't know why it doesn't work : KeyError: 'brand'
    try:
        info['cpu_name'] = cpuinfo.get_cpu_info()['brand']
    except:
        pass
    info['environ'] = {k:ensure_unicode(v) for k,v in os.environ.items()}
    info['main_ip'] = get_main_ip()

    return info

def get_computername():
    """Return host name (without domain part)"""
    return socket.gethostname()


def run(cmd,shell=True,timeout=600,accept_returncodes=[0,3010],on_write=None,pidlist=None,return_stderr=True,**kwargs):
    r"""Run the command cmd in a shell and return the output and error text as string

    Args:
        cmd : command and arguments, either as a string or as a list of arguments
        shell (boolean) : True is assumed
        timeout (int) : maximum time to wait for cmd completion is second (default = 600)
                        a TimeoutExpired exception is raised if tiemout is reached.
        on_write : callback when a new line is printed on stdout or stderr by the subprocess
                        func(unicode_line). arg is enforced to unicode
        accept_returncodes (list) : list of return code which are considered OK default = (0,1601)
        pidlist (list): external list where to append the pid of the launched process.
        return_stderr (bool or list) : if True, the error lines are returned to caller in result.
                                       if a list is provided, the error lines are appended to this list

        all other parameters from the psutil.Popen constructor are accepted

    Returns:
        RunOutput : bytes like output of stdout and optionnaly stderr streams.
                    returncode attribute

    Raises:
        CalledProcessError: if return code of cmd is not in accept_returncodes list
        TimeoutExpired:  if process is running for more than timeout time.

    .. versionchanged:: 1.3.9
            return_stderr parameters to disable stderr or get it in a separate list
            return value has a returncode attribute to

    .. versionchanged:: 1.4.0
            output is not forced to unicode

    .. versionchanged:: 1.4.1
          error code 1603 is no longer accepted by default.

    .. versionchanged:: 1.5.1
          If cmd is unicode, encode it to default filesystem encoding before
            running it.

    >>> run(r'dir /B c:\windows\explorer.exe')
    'explorer.exe\r\n'

    >>> out = []
    >>> pids = []
    >>> def getlines(line):
    ...    out.append(line)
    >>> run(r'dir /B c:\windows\explorer.exe',pidlist=pids,on_write=getlines)
    u'explorer.exe\r\n'

    >>> print out
    ['explorer.exe\r\n']
    >>> try:
    ...     run(r'ping /t 127.0.0.1',timeout=3)
    ... except TimeoutExpired:
    ...     print('timeout')
    timeout
    """
    logger.info(u'Run "%s"' % (ensure_unicode(cmd),))
    output = []

    if return_stderr is None or return_stderr == False:
        return_stderr = []
    elif not isinstance(return_stderr,list):
        return_stderr = output

    if pidlist is None:
        pidlist = []

    # unicode cmd is not understood by shell system anyway...
    if isinstance(cmd,unicode):
        cmd = cmd.encode(sys.getfilesystemencoding())

    try:
        proc = psutil.Popen(cmd, shell = shell, bufsize=1, stdin=PIPE, stdout=PIPE, stderr=PIPE,**kwargs)
    except RuntimeError as e:
        # be sure to not trigger encoding errors.
        raise RuntimeError(e[0],repr(e[1]))
    # keep track of launched pid if required by providing a pidlist argument to run
    if not proc.pid in pidlist:
        pidlist.append(proc.pid)

    def worker(pipe,on_write=None):
        while True:
            line = pipe.readline()
            if not line:
                break
            else:
                if on_write:
                    on_write(ensure_unicode(line))
                if pipe == proc.stderr:
                    return_stderr.append(line)
                else:
                    output.append(line)

    stdout_worker = RunReader(worker, proc.stdout,on_write)
    stderr_worker = RunReader(worker, proc.stderr,on_write)
    stdout_worker.start()
    stderr_worker.start()
    stdout_worker.join(timeout)
    if stdout_worker.is_alive():
        # kill the task and all subtasks
        if proc.pid in pidlist:
            pidlist.remove(proc.pid)
            killtree(proc.pid)
        raise TimeoutExpired(cmd,''.join(output),timeout)
    stderr_worker.join(timeout)
    if stderr_worker.is_alive():
        if proc.pid in pidlist:
            pidlist.remove(proc.pid)
            killtree(proc.pid)
        raise TimeoutExpired(cmd,''.join(output),timeout)
    proc.returncode = proc.wait()
    if proc.pid in pidlist:
        pidlist.remove(proc.pid)
        killtree(proc.pid)
    if accept_returncodes is not None and not proc.returncode in accept_returncodes:
        if return_stderr != output:
            raise CalledProcessErrorOutput(proc.returncode,cmd,''.join(output+return_stderr))
        else:
            raise CalledProcessErrorOutput(proc.returncode,cmd,''.join(output))
    else:
        if proc.returncode == 0:
            logger.info(u'%s command returns code %s' % (ensure_unicode(cmd),proc.returncode))
        else:
            logger.warning(u'%s command returns code %s' % (ensure_unicode(cmd),proc.returncode))
    result = RunOutput(output)
    result.returncode = proc.returncode
    return result



def dmi_info():
    """Hardware System information from BIOS estracted with dmidecode
    Convert dmidecode -q output to python dict

    Returns:
        dict

    >>> dmi = dmi_info()
    >>> 'UUID' in dmi['System_Information']
    True
    >>> 'Product_Name' in dmi['System_Information']
    True
    """

    result = {}
    # dmidecode don't show errors
    dmiout = ensure_unicode(run('dmidecode -q 2>/dev/null'))

    new_section = True
    for l in dmiout.splitlines():
        if not l.strip() or l.startswith('#'):
            new_section = True
            continue

        if not l.startswith('\t') or new_section:
            currobject={}
            key = l.strip().replace(' ','_')
            # already here... so add as array...
            if (key in result):
                if not isinstance(result[key],list):
                    result[key] = [result[key]]
                result[key].append(currobject)
            else:
                result[key]  = currobject
            if l.startswith('\t'):
                logger.debug(l)
        else:
            if not l.startswith('\t\t'):
                currarray = []
                if ':' in l:
                    (name,value)=l.split(':',1)
                    currobject[name.strip().replace(' ','_')]=value.strip()
                else:
                    logger.warning("Error in line : %s" % l)
            else:
                # first line of array
                if not currarray:
                    currobject[name.strip().replace(' ','_')]=currarray
                currarray.append(l.strip())
        new_section = False
    return result

def killalltasks(process_names,include_children=True):
    """Kill the task by their process_names

    >>> killalltasks('firefox')
    """
    logger.debug('Kill tasks %s' % (process_names,))
    if not process_names:
        return []
    if not isinstance(process_names,list):
        process_names = [process_names]

    result = []
    process_names = [process.lower() for process in process_names]
    for p in psutil.process_iter():
        try:
            if p.name().lower() in process_names:
                logger.debug('Kill process %i' % (p.pid,))
                result.append((p.pid,p.name()))
                if include_children:
                    killtree(p.pid)
                else:
                    p.kill()
        except (psutil.AccessDenied,psutil.NoSuchProcess):
            pass
    return result

