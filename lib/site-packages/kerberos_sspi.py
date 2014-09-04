#-*- coding:utf-8 -*-
##
# Copyright (c) 2012 Norman Krämer. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##

import win32security
import sys
import sspicon
import sspi
from base64 import encodestring, decodestring
import logging

logger = logging.getLogger(__name__)

class KrbError(Exception):
    pass

class BasicAuthError(KrbError):
    pass

class GSSError(KrbError):
    pass

def _sspi_spn_from_nt_service_name(nt_service_name, realm=None):
    """
    create a service name consumable by sspi from the nt_service_name fromat used by krb,
    e.g. from http@somehost -> http/somehost[@REALM]
    
    """
    global hostname, defaultrealm
    if "/" not in nt_service_name and "@" in nt_service_name:
        service = nt_service_name.replace("@", "/", 1)
    elif "/" not in nt_service_name and "@" not in nt_service_name: # e.g. http, and the service name would be http/hostname
        if hostname is None:
            import socket
            hostname = socket.getfqdn()
        service = "%s/%s" % (nt_service_name,hostname)
    else:
        service = nt_service_name
    if realm or defaultrealm:
        service = "%s@%s" (service, (realm or defaultrealm).upper())
    return service


def checkPassword(user, pswd, service, default_realm):
    """
    This function provides a simple way to verify that a user name and password match
    those normally used for Kerberos authentication. It does this by checking that the
    supplied user name and password can be used to get a ticket for the supplied service.
    If the user name does not contain a realm, then the default realm supplied is used.
    
    NB For this to work properly the Kerberos must be configured properly on this machine.
    That will likely mean ensuring that the edu.mit.Kerberos preference file has the correct
    realms and KDCs listed.
    
    @param user:          a string containing the Kerberos user name. A realm may be
        included by appending an '@' followed by the realm string to the actual user id.
        If no realm is supplied, then the realm set in the default_realm argument will
        be used.
    @param pswd:          a string containing the password for the user.
    @param service:       a string containging the Kerberos service to check access for.
        This will be of the form 'sss/xx.yy.zz', where 'sss' is the service identifier
        (e.g., 'http', 'krbtgt'), and 'xx.yy.zz' is the hostname of the server.
    @param default_realm: a string containing the default realm to use if one is not
        supplied in the user argument. Note that Kerberos realms are normally all
        uppercase (e.g., 'EXAMPLE.COM').
    @return:              True if authentication succeeds, False otherwise.
    """

    service=_sspi_spn_from_nt_service_name(service)

    if "@" in user:
        user, default_realm = user.rsplit("@", 1)
    auth_info = user, default_realm, pswd
    ca = ClientAuth("Kerberos", auth_info = auth_info, targetspn=service)
    result = False
    try:
        err, data = ca.authorize(None)
        result = True
    except:
        pass

    return result


def changePassword(user, oldpswd, newpswd):
    """
    This function allows to change the user password on the KDC.

    @param user:          a string containing the Kerberos user name. A realm may be
        included by appending an '@' followed by the realm string to the actual user id.
        If no realm is supplied, then the realm set in the default_realm argument will
        be used.
    @param oldpswd:       a string containing the old (current) password for the user.
    @param newpswd:       a string containging the new password for the user.
    @return:              True if password changing succeeds, False otherwise.
    """

    raise NotImplementedError

def getServerPrincipalDetails(service, hostname):
    """
    This function returns the service principal for the server given a service type
    and hostname. Details are looked up via the /etc/keytab file.
    
    @param service:       a string containing the Kerberos service type for the server.
    @param hostname:      a string containing the hostname of the server.
    @return:              a string containing the service principal.
    """

    raise NotImplementedError

"""
GSSAPI Function Result Codes:
    
    -1 : Error
    0  : GSSAPI step continuation (only returned by 'Step' function)
    1  : GSSAPI step complete, or function return OK

"""

# Some useful result codes
AUTH_GSS_CONTINUE     = 0 
AUTH_GSS_COMPLETE     = 1 
     
# Some useful gss flags 
GSS_C_DELEG_FLAG      = sspicon.ISC_REQ_DELEGATE 
GSS_C_MUTUAL_FLAG     = sspicon.ISC_REQ_MUTUAL_AUTH
GSS_C_REPLAY_FLAG     = sspicon.ISC_REQ_REPLAY_DETECT
GSS_C_SEQUENCE_FLAG   = sspicon.ISC_REQ_SEQUENCE_DETECT
GSS_C_CONF_FLAG       = sspicon.ISC_REQ_CONFIDENTIALITY 
GSS_C_INTEG_FLAG      = sspicon.ISC_REQ_INTEGRITY 

# leave the following undefined, so if someone relies on them they know that this package
# is not for them
#GSS_C_ANON_FLAG       = 0 
#GSS_C_PROT_READY_FLAG = 0 
#GSS_C_TRANS_FLAG      = 0 

GSS_AUTH_P_NONE = 1
GSS_AUTH_P_INTEGRITY = 2
GSS_AUTH_P_PRIVACY = 4

hostname=None
defaultrealm=None

def authGSSClientInit(service, gssflags=GSS_C_MUTUAL_FLAG|GSS_C_SEQUENCE_FLAG):
    """
    Initializes a context for GSSAPI client-side authentication with the given service principal.
    authGSSClientClean must be called after this function returns an OK result to dispose of
    the context once all GSSAPI operations are complete.

    @param service: a string containing the service principal in the form 'type@fqdn'
        (e.g. 'imap@mail.apple.com').
    @param gssflags: optional integer used to set GSS flags.
        (e.g.  GSS_C_DELEG_FLAG|GSS_C_MUTUAL_FLAG|GSS_C_SEQUENCE_FLAG will allow 
        for forwarding credentials to the remote host)
    @return: a tuple of (result, context) where result is the result code (see above) and
        context is an opaque value that will need to be passed to subsequent functions.
    """

    spn=_sspi_spn_from_nt_service_name(service)
    ctx={"csa":sspi.ClientAuth("Kerberos", scflags=gssflags, targetspn=spn), 
         "service":service, 
         "gssflags":gssflags,
         "response":None
         }
    return AUTH_GSS_COMPLETE, ctx


def authGSSClientClean(context):
    """
    Destroys the context for GSSAPI client-side authentication. After this call the context
    object is invalid and should not be used again.

    @param context: the context object returned from authGSSClientInit.
    @return: a result code (see above).
    """
    context["csa"].reset()
    context["response"] = None

    return AUTH_GSS_COMPLETE

def authGSSClientStep(context, challenge):
    """
    Processes a single GSSAPI client-side step using the supplied server data.

    @param context: the context object returned from authGSSClientInit.
    @param challenge: a string containing the base64-encoded server data (which may be empty
        for the first step).
    @return: a result code (see above).
    """
    data = decodestring(challenge) if challenge else None

    err, sec_buffer = context["csa"].authorize(data)
    context["response"] = sec_buffer[0].Buffer
    return AUTH_GSS_COMPLETE if err == 0 else AUTH_GSS_CONTINUE

def authGSSClientResponse(context):
    """
    Get the client response from the last successful GSSAPI client-side step.

    @param context: the context object returned from authGSSClientInit.
    @return: a string containing the base64-encoded client data to be sent to the server.
    """
    data = context["response"]
    auth = encodestring(data).replace("\012", "")

    return auth

def authGSSClientUserName(context):
    """
    Get the user name of the principal authenticated via the now complete GSSAPI client-side operations.
    This method must only be called after authGSSClientStep returns a complete response code.

    @param context:   the context object returned from authGSSClientInit.
    @return: a string containing the user name.
    """

    return context["csa"].ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_NAMES)

def authGSSClientUnwrap(context, challenge): 
    """ 
    Perform the client side GSSAPI unwrap step 
    
    @param challenge: a string containing the base64-encoded server data. 
    @return: a result code (see above) 
    """
    data = decodestring(challenge) if challenge else None

    ca = context["csa"]
    encbuf=win32security.PySecBufferDescType()

    encbuf.append(win32security.PySecBufferType(0, sspicon.SECBUFFER_DATA))
    encbuf.append(win32security.PySecBufferType(len(data), sspicon.SECBUFFER_STREAM))
    encbuf[1].Buffer=data
    ca.ctxt.DecryptMessage(encbuf,ca._get_next_seq_num())
    context["response"]= encbuf[0].Buffer
    
    return AUTH_GSS_COMPLETE

def authGSSClientWrap(context, data, user=None): 
    """ 
    Perform the client side GSSAPI wrap step.  
    
    @param data:the result of the authGSSClientResponse after the authGSSClientUnwrap 
    @param user: the user to authorize 
    @return: a result code (see above) 
    """ 
    
    ca = context["csa"]

    data = decodestring(data) if data else None
    if user and data:
        import struct
        conf_and_size = data[:struct.calcsize("!L")] # network unsigned long
        conf = struct.unpack("B", conf_and_size[0])[0] # B .. unsigned char
        size = struct.unpack("!L", conf_and_size)[0] & 0x00ffffff
        logger.info("N" if conf & GSS_AUTH_P_NONE else "-")
        logger.info("I" if conf & GSS_AUTH_P_INTEGRITY else "-")
        logger.info("P" if conf & GSS_AUTH_P_PRIVACY else "-")
        logger.info("Maximum GSS token size is %d", size)
        conf_and_size=chr(GSS_AUTH_P_NONE) + conf_and_size[1:]
        data = conf_and_size + user

    pkg_size_info=ca.ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_SIZES)
    trailersize=pkg_size_info['SecurityTrailer']
    blocksize=pkg_size_info['BlockSize']

    encbuf=win32security.PySecBufferDescType()
    encbuf.append(win32security.PySecBufferType(trailersize, sspicon.SECBUFFER_TOKEN))
    encbuf.append(win32security.PySecBufferType(len(data), sspicon.SECBUFFER_DATA))
    encbuf.append(win32security.PySecBufferType(blocksize, sspicon.SECBUFFER_PADDING))
    encbuf[1].Buffer=data
    ca.ctxt.EncryptMessage(0,encbuf, ca._get_next_seq_num())
    #ca.ctxt.EncryptMessage(0,encbuf, 0)

    
    context["response"] = encbuf[0].Buffer+encbuf[1].Buffer+encbuf[2].Buffer

    return AUTH_GSS_COMPLETE

def authGSSServerInit(service):
    """
    Initializes a context for GSSAPI server-side authentication with the given service principal.
    authGSSServerClean must be called after this function returns an OK result to dispose of
    the context once all GSSAPI operations are complete.

    @param service: a string containing the service principal in the form 'type@fqdn'
        (e.g. 'imap@mail.apple.com').
    @return: a tuple of (result, context) where result is the result code (see above) and
        context is an opaque value that will need to be passed to subsequent functions.
    """
    spn=_sspi_spn_from_nt_service_name(service)
    ctx={"csa":sspi.ServerAuth("Kerberos", spn=spn), 
         "service":service, 
         "response":None,
         }
    return AUTH_GSS_COMPLETE, ctx

def authGSSServerClean(context):
    """
    Destroys the context for GSSAPI server-side authentication. After this call the context
    object is invalid and should not be used again.

    @param context: the context object returned from authGSSServerInit.
    @return: a result code (see above).
    """
    context["csa"].reset()
    context["response"] = ""
    return AUTH_GSS_COMPLETE

def authGSSServerStep(context, challenge):
    """
    Processes a single GSSAPI server-side step using the supplied client data.

    @param context: the context object returned from authGSSServerInit.
    @param challenge: a string containing the base64-encoded client data.
    @return: a result code (see above).
    """
    data = decodestring(challenge) if challenge else None

    err, sec_buffer = context["csa"].authorize(data)
    context["response"] = sec_buffer[0].Buffer
    return AUTH_GSS_COMPLETE if err == 0 else AUTH_GSS_CONTINUE

def authGSSServerResponse(context):
    """
    Get the server response from the last successful GSSAPI server-side step.

    @param context: the context object returned from authGSSServerInit.
    @return: a string containing the base64-encoded server data to be sent to the client.
    """
    data = context["response"]
    auth = encodestring(data).replace("\012", "")

    return auth

def authGSSServerUserName(context):
    """
    Get the user name of the principal trying to authenticate to the server.
    This method must only be called after authGSSServerStep returns a complete or continue response code.

    @param context: the context object returned from authGSSServerInit.
    @return: a string containing the user name.
    """

    #return context["csa"].ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_NATIVE_NAMES)[0]
    return context["csa"].ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_NAMES)

def authGSSServerTargetName(context):
    """
    Get the target name if the server did not supply its own credentials.
    This method must only be called after authGSSServerStep returns a complete or continue response code.

    @param context: the context object returned from authGSSServerInit.
    @return: a string containing the target name.
    """

    return context["csa"].ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_NATIVE_NAMES)[1]
