#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013  Tranquil IT Systems http://www.tranquil.it
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users PC.
#
#    inspired and adapted from
#     from  http://pastebin.com/f39d8b997 and
#     http://stackoverflow.com/questions/1812564/help-ctypes-windll-dnsapi-dnsquery-a
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

__version__ = "1.2.2"

import ctypes
from ctypes import wintypes
from ctypes import *

from ctypes.wintypes import LPSTR
from ctypes.wintypes import WORD
from ctypes.wintypes import DWORD
from ctypes.wintypes import BYTE
from ctypes.wintypes import BOOL

class IP4_ARRAY(Structure):
    _fields_ = [('AddrCount', DWORD),
                ('AddrArray', DWORD*1),
    ]

class _DnsRecord(Structure):
    pass
DNS_RECORD = _DnsRecord
CHAR = c_char
LPTSTR = LPSTR
class N10_DnsRecord5DOLLAR_226E(Union):
    pass
class _DnsRecordFlags(Structure):
    pass
_DnsRecordFlags._fields_ = [
    ('Section', DWORD, 2),
    ('Delete', DWORD, 1),
    ('CharSet', DWORD, 2),
    ('Unused', DWORD, 3),
    ('Reserved', DWORD, 24),
]
DNS_RECORD_FLAGS = _DnsRecordFlags
N10_DnsRecord5DOLLAR_226E._fields_ = [
    ('DW', DWORD),
    ('S', DNS_RECORD_FLAGS),
]
class N10_DnsRecord5DOLLAR_227E(Union):
    pass
class DNS_A_DATA(Structure):
    pass
IP4_ADDRESS = DWORD
DNS_A_DATA._fields_ = [
    ('IpAddress', IP4_ADDRESS),
]
class DNS_SOA_DATA(Structure):
    pass
DNS_SOA_DATA._fields_ = [
    ('pNamePrimaryServer', LPTSTR),
    ('pNameAdministrator', LPTSTR),
    ('dwSerialNo', DWORD),
    ('dwRefresh', DWORD),
    ('dwRetry', DWORD),
    ('dwExpire', DWORD),
    ('dwDefaultTtl', DWORD),
]
class DNS_PTR_DATA(Structure):
    pass
DNS_PTR_DATA._fields_ = [
    ('pNameHost', LPTSTR),
]
class DNS_MINFO_DATA(Structure):
    pass
DNS_MINFO_DATA._fields_ = [
    ('pNameMailbox', LPTSTR),
    ('pNameErrorsMailbox', LPTSTR),
]
class DNS_MX_DATA(Structure):
    pass
DNS_MX_DATA._fields_ = [
    ('pNameExchange', LPTSTR),
    ('wPreference', WORD),
    ('Pad', WORD),
]
class DNS_TXT_DATA(Structure):
    pass
DNS_TXT_DATA._fields_ = [
    ('dwStringCount', DWORD),
    ('pStringArray', LPTSTR * 1),
]
class DNS_NULL_DATA(Structure):
    pass
DNS_NULL_DATA._fields_ = [
    ('dwByteCount', DWORD),
    ('Data', BYTE * 1),
]
class DNS_WKS_DATA(Structure):
    pass
DNS_WKS_DATA._fields_ = [
    ('IpAddress', IP4_ADDRESS),
    ('chProtocol', BYTE),
    ('BitMask', BYTE * 1),
]
class DNS_AAAA_DATA(Structure):
    pass
class IP6_ADDRESS(Union):
    pass
IP6_ADDRESS._fields_ = [
    ('IP6Dword', DWORD * 4),
    ('IP6Word', WORD * 8),
    ('IP6Byte', BYTE * 16),
]
DNS_IP6_ADDRESS = IP6_ADDRESS
DNS_AAAA_DATA._fields_ = [
    ('Ip6Address', DNS_IP6_ADDRESS),
]
class DNS_KEY_DATA(Structure):
    pass
DNS_KEY_DATA._fields_ = [
    ('wFlags', WORD),
    ('chProtocol', BYTE),
    ('chAlgorithm', BYTE),
    ('Key', BYTE * 1),
]
class DNS_SIG_DATA(Structure):
    pass
DNS_SIG_DATA._fields_ = [
    ('pNameSigner', LPTSTR),
    ('wTypeCovered', WORD),
    ('chAlgorithm', BYTE),
    ('chLabelCount', BYTE),
    ('dwOriginalTtl', DWORD),
    ('dwExpiration', DWORD),
    ('dwTimeSigned', DWORD),
    ('wKeyTag', WORD),
    ('Pad', WORD),
    ('Signature', BYTE * 1),
]
class DNS_ATMA_DATA(Structure):
    pass
DNS_ATMA_DATA._fields_ = [
    ('AddressType', BYTE),
    ('Address', BYTE * 20),
]
class DNS_NXT_DATA(Structure):
    pass
DNS_NXT_DATA._fields_ = [
    ('pNameNext', LPTSTR),
    ('wNumTypes', WORD),
    ('wTypes', WORD * 1),
]
class DNS_SRV_DATA(Structure):
    pass
DNS_SRV_DATA._fields_ = [
    ('pNameTarget', LPTSTR),
    ('wPriority', WORD),
    ('wWeight', WORD),
    ('wPort', WORD),
    ('Pad', WORD),
]
class DNS_TKEY_DATA(Structure):
    pass
PBYTE = POINTER(BYTE)
DNS_TKEY_DATA._fields_ = [
    ('pNameAlgorithm', LPTSTR),
    ('pAlgorithmPacket', PBYTE),
    ('pKey', PBYTE),
    ('pOtherData', PBYTE),
    ('dwCreateTime', DWORD),
    ('dwExpireTime', DWORD),
    ('wMode', WORD),
    ('wError', WORD),
    ('wKeyLength', WORD),
    ('wOtherLength', WORD),
    ('cAlgNameLength', BYTE),
    ('bPacketPointers', BOOL),
]
class DNS_TSIG_DATA(Structure):
    pass
LONGLONG = c_longlong
DNS_TSIG_DATA._fields_ = [
    ('pNameAlgorithm', LPTSTR),
    ('pAlgorithmPacket', PBYTE),
    ('pSignature', PBYTE),
    ('pOtherData', PBYTE),
    ('i64CreateTime', LONGLONG),
    ('wFudgeTime', WORD),
    ('wOriginalXid', WORD),
    ('wError', WORD),
    ('wSigLength', WORD),
    ('wOtherLength', WORD),
    ('cAlgNameLength', BYTE),
    ('bPacketPointers', BOOL),
]
class DNS_WINS_DATA(Structure):
    pass
DNS_WINS_DATA._fields_ = [
    ('dwMappingFlag', DWORD),
    ('dwLookupTimeout', DWORD),
    ('dwCacheTimeout', DWORD),
    ('cWinsServerCount', DWORD),
    ('WinsServers', IP4_ADDRESS * 1),
]
class DNS_WINSR_DATA(Structure):
    pass
DNS_WINSR_DATA._fields_ = [
    ('dwMappingFlag', DWORD),
    ('dwLookupTimeout', DWORD),
    ('dwCacheTimeout', DWORD),
    ('pNameResultDomain', LPTSTR),
]
N10_DnsRecord5DOLLAR_227E._fields_ = [
    ('A', DNS_A_DATA),
    ('SOA', DNS_SOA_DATA),
    ('Soa', DNS_SOA_DATA),
    ('PTR', DNS_PTR_DATA),
    ('Ptr', DNS_PTR_DATA),
    ('NS', DNS_PTR_DATA),
    ('Ns', DNS_PTR_DATA),
    ('CNAME', DNS_PTR_DATA),
    ('Cname', DNS_PTR_DATA),
    ('MB', DNS_PTR_DATA),
    ('Mb', DNS_PTR_DATA),
    ('MD', DNS_PTR_DATA),
    ('Md', DNS_PTR_DATA),
    ('MF', DNS_PTR_DATA),
    ('Mf', DNS_PTR_DATA),
    ('MG', DNS_PTR_DATA),
    ('Mg', DNS_PTR_DATA),
    ('MR', DNS_PTR_DATA),
    ('Mr', DNS_PTR_DATA),
    ('MINFO', DNS_MINFO_DATA),
    ('Minfo', DNS_MINFO_DATA),
    ('RP', DNS_MINFO_DATA),
    ('Rp', DNS_MINFO_DATA),
    ('MX', DNS_MX_DATA),
    ('Mx', DNS_MX_DATA),
    ('AFSDB', DNS_MX_DATA),
    ('Afsdb', DNS_MX_DATA),
    ('RT', DNS_MX_DATA),
    ('Rt', DNS_MX_DATA),
    ('HINFO', DNS_TXT_DATA),
    ('Hinfo', DNS_TXT_DATA),
    ('ISDN', DNS_TXT_DATA),
    ('Isdn', DNS_TXT_DATA),
    ('TXT', DNS_TXT_DATA),
    ('Txt', DNS_TXT_DATA),
    ('X25', DNS_TXT_DATA),
    ('Null', DNS_NULL_DATA),
    ('WKS', DNS_WKS_DATA),
    ('Wks', DNS_WKS_DATA),
    ('AAAA', DNS_AAAA_DATA),
    ('KEY', DNS_KEY_DATA),
    ('Key', DNS_KEY_DATA),
    ('SIG', DNS_SIG_DATA),
    ('Sig', DNS_SIG_DATA),
    ('ATMA', DNS_ATMA_DATA),
    ('Atma', DNS_ATMA_DATA),
    ('NXT', DNS_NXT_DATA),
    ('Nxt', DNS_NXT_DATA),
    ('SRV', DNS_SRV_DATA),
    ('Srv', DNS_SRV_DATA),
    ('TKEY', DNS_TKEY_DATA),
    ('Tkey', DNS_TKEY_DATA),
    ('TSIG', DNS_TSIG_DATA),
    ('Tsig', DNS_TSIG_DATA),
    ('WINS', DNS_WINS_DATA),
    ('Wins', DNS_WINS_DATA),
    ('WINSR', DNS_WINSR_DATA),
    ('WinsR', DNS_WINSR_DATA),
    ('NBSTAT', DNS_WINSR_DATA),
    ('Nbstat', DNS_WINSR_DATA),
]
_DnsRecord._fields_ = [
    ('pNext', POINTER(_DnsRecord)),
    ('pName', LPTSTR),
    ('wType', WORD),
    ('wDataLength', WORD),
    ('Flags', N10_DnsRecord5DOLLAR_226E),
    ('dwTtl', DWORD),
    ('dwReserved', DWORD),
    ('Data', N10_DnsRecord5DOLLAR_227E),
]

# options
DNS_QUERY_STANDARD                  = 0x00000000
DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE = 0x00000001
DNS_QUERY_USE_TCP_ONLY              = 0x00000002
DNS_QUERY_NO_RECURSION              = 0x00000004
DNS_QUERY_BYPASS_CACHE              = 0x00000008

DNS_QUERY_NO_WIRE_QUERY = 0x00000010
DNS_QUERY_NO_LOCAL_NAME = 0x00000020
DNS_QUERY_NO_HOSTS_FILE = 0x00000040
DNS_QUERY_NO_NETBT      = 0x00000080

DNS_QUERY_WIRE_ONLY      = 0x00000100
DNS_QUERY_RETURN_MESSAGE = 0x00000200

DNS_QUERY_TREAT_AS_FQDN         = 0x00001000
DNS_QUERY_DONT_RESET_TTL_VALUES = 0x00100000
DNS_QUERY_RESERVED              = 0xff000000

DNS_QUERY_CACHE_ONLY = DNS_QUERY_NO_WIRE_QUERY

# types
DNS_TYPE_ZERO = 0x0000
DNS_TYPE_A     = 0x0001
DNS_TYPE_NS    = 0x0002
DNS_TYPE_MD    = 0x0003
DNS_TYPE_MF    = 0x0004
DNS_TYPE_CNAME = 0x0005
DNS_TYPE_SOA   = 0x0006
DNS_TYPE_MB    = 0x0007
DNS_TYPE_MG    = 0x0008
DNS_TYPE_MR    = 0x0009

DNS_TYPE_NULL  = 0x000a
DNS_TYPE_WKS   = 0x000b
DNS_TYPE_PTR   = 0x000c
DNS_TYPE_HINFO = 0x000d
DNS_TYPE_MINFO = 0x000e
DNS_TYPE_MX    = 0x000f
DNS_TYPE_TEXT  = 0x0010


DNS_TYPE_RP    = 0x0011
DNS_TYPE_AFSDB = 0x0012
DNS_TYPE_X25   = 0x0013

DNS_TYPE_ISDN  = 0x0014
DNS_TYPE_RT    = 0x0015

DNS_TYPE_NSAP    = 0x0016
DNS_TYPE_NSAPPTR = 0x0017


#  RFC 2065    (DNS security)
DNS_TYPE_SIG = 0x0018
DNS_TYPE_KEY = 0x0019

#  RFC 1664    (X.400 mail)
DNS_TYPE_PX = 0x001a

#  RFC 1712    (Geographic position)
DNS_TYPE_GPOS = 0x001b

#  RFC 1886    (IPv6 Address)
DNS_TYPE_AAAA = 0x001c

#  RFC 1876    (Geographic location)
DNS_TYPE_LOC = 0x001d

#  RFC 2065    (Secure negative response)
DNS_TYPE_NXT = 0x001e

#  Patton      (Endpoint Identifier)
DNS_TYPE_EID = 0x001f

#  Patton      (Nimrod Locator)
DNS_TYPE_NIMLOC = 0x0020

#  RFC 2052    (Service location)
DNS_TYPE_SRV = 0x0021

#  ATM Standard something-or-another (ATM Address)
DNS_TYPE_ATMA = 0x0022

#  RFC 2168    (Naming Authority Pointer)
DNS_TYPE_NAPTR = 0x0023

#  RFC 2230    (Key Exchanger)
DNS_TYPE_KX = 0x0024

#  RFC 2538    (CERT)
DNS_TYPE_CERT = 0x0025

#  A6 Draft    (A6)
DNS_TYPE_A6 = 0x0026

#  DNAME Draft (DNAME)
DNS_TYPE_DNAME = 0x0027

#  Eastlake    (Kitchen Sink)
DNS_TYPE_SINK = 0x0028

#  RFC 2671    (EDNS OPT)
DNS_TYPE_OPT = 0x0029

#
#  IANA Reserved
#

DNS_TYPE_UINFO  = 0x0064
DNS_TYPE_UID    = 0x0065
DNS_TYPE_GID    = 0x0066
DNS_TYPE_UNSPEC = 0x0067


#
#  Query only types (1035, 1995)
#      - Crawford      (ADDRS)
#      - TKEY draft    (TKEY)
#      - TSIG draft    (TSIG)
#      - RFC 1995      (IXFR)
#      - RFC 1035      (AXFR up)
#
DNS_TYPE_ADDRS = 0x00f8
DNS_TYPE_TKEY  = 0x00f9
DNS_TYPE_TSIG  = 0x00fa
DNS_TYPE_IXFR  = 0x00fb
DNS_TYPE_AXFR  = 0x00fc
DNS_TYPE_MAILB = 0x00fd
DNS_TYPE_MAILA = 0x00fe
DNS_TYPE_ALL   = 0x00ff
DNS_TYPE_ANY   = 0x00ff


#
#  Temp Microsoft types -- use until get IANA approval for real type
#
DNS_TYPE_WINS   = 0xff01
DNS_TYPE_WINSR  = 0xff02
DNS_TYPE_NBSTAT = DNS_TYPE_WINSR

#
#  DNS Record Types -- Net Byte Order
#
DNS_RTYPE_A       = 0x0100
DNS_RTYPE_NS      = 0x0200
DNS_RTYPE_MD      = 0x0300
DNS_RTYPE_MF      = 0x0400
DNS_RTYPE_CNAME   = 0x0500
DNS_RTYPE_SOA     = 0x0600
DNS_RTYPE_MB      = 0x0700
DNS_RTYPE_MG      = 0x0800
DNS_RTYPE_MR      = 0x0900
DNS_RTYPE_NULL    = 0x0a00
DNS_RTYPE_WKS     = 0x0b00
DNS_RTYPE_PTR     = 0x0c00
DNS_RTYPE_HINFO   = 0x0d00
DNS_RTYPE_MINFO   = 0x0e00
DNS_RTYPE_MX      = 0x0f00
DNS_RTYPE_TEXT    = 0x1000
DNS_RTYPE_RP      = 0x1100
DNS_RTYPE_AFSDB   = 0x1200
DNS_RTYPE_X25     = 0x1300
DNS_RTYPE_ISDN    = 0x1400
DNS_RTYPE_RT      = 0x1500
DNS_RTYPE_NSAP    = 0x1600
DNS_RTYPE_NSAPPTR = 0x1700
DNS_RTYPE_SIG     = 0x1800
DNS_RTYPE_KEY     = 0x1900
DNS_RTYPE_PX      = 0x1a00
DNS_RTYPE_GPOS    = 0x1b00
DNS_RTYPE_AAAA    = 0x1c00
DNS_RTYPE_LOC     = 0x1d00
DNS_RTYPE_NXT     = 0x1e00
DNS_RTYPE_EID     = 0x1f00
DNS_RTYPE_NIMLOC  = 0x2000
DNS_RTYPE_SRV     = 0x2100
DNS_RTYPE_ATMA    = 0x2200
DNS_RTYPE_NAPTR   = 0x2300
DNS_RTYPE_KX      = 0x2400
DNS_RTYPE_CERT    = 0x2500
DNS_RTYPE_A6      = 0x2600
DNS_RTYPE_DNAME   = 0x2700
DNS_RTYPE_SINK    = 0x2800
DNS_RTYPE_OPT     = 0x2900

#
#  IANA Reserved
#
DNS_RTYPE_UINFO  = 0x6400
DNS_RTYPE_UID    = 0x6500
DNS_RTYPE_GID    = 0x6600
DNS_RTYPE_UNSPEC = 0x6700


#
#  Query only types
#
DNS_RTYPE_TKEY  = 0xf900
DNS_RTYPE_TSIG  = 0xfa00
DNS_RTYPE_IXFR  = 0xfb00
DNS_RTYPE_AXFR  = 0xfc00
DNS_RTYPE_MAILB = 0xfd00
DNS_RTYPE_MAILA = 0xfe00
DNS_RTYPE_ALL   = 0xff00
DNS_RTYPE_ANY   = 0xff00

#
#  Temp Microsoft types -- use until get IANA approval for real type
#
DNS_RTYPE_WINS  = 0x01ff
DNS_RTYPE_WINSR = 0x02ff

def ipv4_to_str(ipv4):
    # convert 32bit int style ipv4 into dotted representation
    return '%s.%s.%s.%s' % (ipv4 & 0xff, (ipv4 >> 8) & 0xff,  (ipv4  >> 16) & 0xFF, (ipv4  >> 24) & 0xFF)

def dnsquery_raw(host, type, server=0, opt=0):
    rr = ctypes.pointer(DNS_RECORD())
    if server:
        server_arr = IP4_ARRAY()
        server_arr.AddrCount=1
        server_arr.AddrArray[0] = ctypes.windll.Ws2_32.inet_addr(server)
        psrv = ctypes.byref(server_arr)
    else:
        psrv = 0
    retval = ctypes.windll.dnsapi.DnsQuery_A(str(host), type, opt, psrv, ctypes.byref(rr), 0)
    if retval == 0:
        return rr
    else:
        return None

def dnsquery(name, type, server=0, opt=0):
    """Query DNS registred on specific or connected network interfaces

    Args:
        name (str) : name to lookup
        type (int) : type of query like DNS_TYPE_A, DNS_TYPE_CNAME etc...
        server : server to query, or 0 to use default on connected interfaces
        opt : or'ed list of options for the query like DNS_QUERY_BYPASS_CACHE

    Returns:
        list : list of windows dns records. Use type property
                 data.A.* or data.CNAME.* etc... to access fields

    >>> [ ipv4_to_str(r.Data.A.IpAddress) for r in dnsquery('srvwapt.tranquilit.local',DNS_TYPE_A) if r.wType == DNS_TYPE_A]
    ['192.168.149.37']

    """
    res =  dnsquery_raw(name, type , server = server, opt=opt)
    r = res
    result = []
    while r:
        result.append(r.contents)
        r = r.contents.pNext
    return result


def dnsquery_a(name,opt=DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_LOCAL_NAME | DNS_QUERY_NO_HOSTS_FILE):
    """Recursively resolve the IP matching a hostname <name> (A)

    Args:
        name (str) : name of IP to lookup in dns
        opt  (str) : windows DNS or'ed options

    Returns:
        list : list of str, IP matching the <name>

    >>> dnsquery_a('srvwapt.tranquilit.local')
    ['192.168.149.37']

    >>> dnsquery_a('www.google.com')
    ['216.58.208.228',
     '216.239.32.10',
     '216.239.34.10',
     '216.239.36.10',
     '216.239.38.10']

    """
    result = []
    res = dnsquery(name, DNS_TYPE_A , opt=opt)
    for r in res:
        if r.wType == DNS_TYPE_CNAME:
            ips = dnsquery_a(r.Data.CNAME.pNameHost)
            if ips:
                result.extend(ips)
        elif (r.wType == DNS_TYPE_A) and (r.pName.lower() == name.lower()) :
            result.append(ipv4_to_str(r.Data.A.IpAddress))
    return result


def dnsquery_cname(name,opt=DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_LOCAL_NAME | DNS_QUERY_NO_HOSTS_FILE):
    """Returns the name matching a cname

    Args:
        name : cname to lookup in dns

    Returns:
        list : list of str, matching targets for the <name>

    >>> dnsquery_cname('wapt.tranquilit.local')
    ['srvwapt.tranquilit.local']

    """

    result = []
    res = dnsquery(name, DNS_TYPE_CNAME , opt=opt)
    for r in res:
        if r.wType == DNS_TYPE_CNAME:
            result.append(r.Data.CNAME.pNameHost)
    return result


def dnsquery_srv(name,opt=DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_LOCAL_NAME | DNS_QUERY_NO_HOSTS_FILE):
    """Returns the mains fields for SRV records for <name> service.

    Args:
        name (str) : servic ename like _ldap._tcp.mondomain.local
        opt (int) : windows DNS options : default to no cache query.

    Returns:
        list : list of (prio,weight,dnsname,port)

    >>> dnsquery_srv('_wapt._tcp.tranquilit.local')
    [(30, 0, 'waptwifi.tranquilit.local', 80),
     (20, 0, 'nexiste2pas.tranquil.it', 80),
     (20, 0, 'srvinstallation.tranquil.it', 80),
     (20, 0, 'nexistepas.tranquilit.local', 80),
     (20, 0, 'wapt.tranquilit.local', 80)]
    >>> dnsquery_srv('_ldap._tcp.tranquilit.local')
    [(0, 100, 'srvads.tranquilit.local', 389)]

    """
    result = []
    res = dnsquery_raw(name, DNS_TYPE_SRV , opt=opt)
    while res:
        if res.contents.wType == DNS_TYPE_SRV:
            result.append((res.contents.Data.SRV.wPriority,res.contents.Data.SRV.wWeight,res.contents.Data.SRV.pNameTarget,res.contents.Data.SRV.wPort))
        res = res.contents.pNext
    return result


if __name__ == "__main__":
    print dnsquery_a('wapt.tranquilit.local')

    res =  dnsquery_raw("www.google.com", DNS_TYPE_A , opt=DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_LOCAL_NAME | DNS_QUERY_NO_HOSTS_FILE)
    print  ipv4_to_str(res.contents.Data.A.IpAddress)

    res =  dnsquery_raw("_wapt._tcp.tranquilit.local", DNS_TYPE_SRV , opt=DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_LOCAL_NAME | DNS_QUERY_NO_HOSTS_FILE)
    r = res
    while r:
        if r.contents.wType == DNS_TYPE_SRV:
            print r.contents.pName,r.contents.Data.SRV.pNameTarget,r.contents.Data.SRV.wPort
        elif r.contents.wType == DNS_TYPE_A:
            print r.contents.pName,ipv4_to_str(r.contents.Data.A.IpAddress)
        else:
            print r.contents.pName,r.contents.wType
        r = r.contents.pNext
    print dnsquery_a('wapt')

