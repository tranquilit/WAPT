#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
#    This file is part of WAPT
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users PC.
#
#    This is based on the work from ...

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

import sys,time
from ctypes import *
from ctypes.wintypes import DWORD
import threading

sleepTime = 0

class WinInet:

    def __init__(self, callback = None):
        self.hInternet = None
        self.hRequest  = None
        self.hConnect  = None
        self.callback = callback
        self.lock = threading.Lock()

        #global gErr, gDbg
        #gDbg = Loggers.CreateLogger('debug.wininet')
        #gErr = Loggers.CreateLogger('error.wininet')

    def getStageCount(self):
        return 3

    def stop(self):
        wininet = windll.wininet

        self.lock.acquire()

        if self.hConnect:
            wininet.InternetCloseHandle(self.hConnect)
            self.hConnect = None

        if self.hRequest:
            wininet.InternetCloseHandle(self.hRequest)
            self.hRequest = None

        if self.hInternet:
            wininet.InternetCloseHandle(self.hInternet)
            self.hInternet = None

        self.lock.release()


    def doUrlStatus(self, url, host, headers={}, user=0, password=0,port=80):
        wininet = windll.wininet
        flags = DWORD()

        self.lock.acquire()
        self.hInternet = wininet.InternetOpenA('wapt-get/1.0', 0, 0, 0, 0);
        self.lock.release()
        if not self.hInternet:
            #gErr.log("couldn't open")
            self.stop()
            return 0

        #print hInternet

        #print "Doing Connect"
        #gDbg.log('Connecting...')
        if self.callback: self.callback('Connecting...', 1)
        time.sleep(sleepTime)

        INTERNET_SERVICE_HTTP = 3
        self.hConnect = wininet.InternetConnectA(self.hInternet, host, port, user, password, 3, 0, 0)
        if not self.hConnect:
            #gErr.log("couldn't connect")
            self.stop()
            return 0


        #print hConnect

        #gDbg.log('Opening Request...')
        if self.callback: self.callback('Sending...', 2)
        time.sleep(sleepTime)

        INTERNET_FLAG_NO_CACHE_WRITE = 0x04000000
        #hRequest = wininet.InternetOpenUrlA(hInternet, "http://rpc.bloglines.com/listsubs", 0, 0, 0x80000200L, 0)
        self.hRequest = wininet.HttpOpenRequestA(self.hConnect, "GET", url, 0, 0, 0, INTERNET_FLAG_NO_CACHE_WRITE, 0)
        if not self.hRequest:
            #gErr.log("couldn't open request")
            self.stop()
            return 0


        HTTP_ADDREQ_FLAG_ADD_IF_NEW  = 0x10000000
        HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA     =  0x40000000
        HTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON =  0x01000000
        HTTP_ADDREQ_FLAG_COALESCE = HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA
        HTTP_ADDREQ_FLAG_ADD     =   0x20000000
        HTTP_ADDREQ_FLAG_REPLACE = 0x80000000
        for k in headers.keys():
            res = wininet.HttpAddRequestHeadersA(self.hRequest, "%s: %s\r\n" %(k, headers[k]), -1, HTTP_ADDREQ_FLAG_REPLACE | HTTP_ADDREQ_FLAG_ADD)
            if not res:
                code = GetLastError()
                #gErr.log("couldn't add header: %d - %s" %(code, FormatError(code)))
                self.stop()
                return retVal


        gDbg.log('Sending Request...')
        res = wininet.HttpSendRequestA(self.hRequest, 0,0,0,0)
        if not res:
            #gErr.log("couldn't send request")
            self.stop()
            return 0
        #print "Request Sent: %d", res

        HTTP_QUERY_FLAG_NUMBER = 0x20000000
        HTTP_QUERY_CONTENT_LENGTH = 5
        HTTP_QUERY_STATUS_CODE    = 19

        #gDbg.log('Getting Result...')
        if self.callback: self.callback('Getting Result...', 3)
        time.sleep(sleepTime)

        dwStatus = DWORD()
        dwBufLen = DWORD(4)
        res =wininet.HttpQueryInfoA(self.hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
            byref(dwStatus), byref(dwBufLen), 0)

        if res == 0:
            #gErr.log("Bad HttpQueryInfo")
            #print "HttpQueryInfo failed"
            dwStatus.value = 0

        status = dwStatus.value
        #gDbg.log("Status = %d" %status)

        self.stop()

        return status


    # Returns status and data
    def doUrlGet(self, url, host, headers={}, user=0, password=0, port=80):
        wininet = windll.wininet
        flags = DWORD()
        data = ''
        retVal = (0, data)

        # Use the Registry settings for Proxy (nice!)
        INTERNET_OPEN_TYPE_PRECONFIG = 0
        self.lock.acquire()
        self.hInternet = wininet.InternetOpenA('WAPT)', INTERNET_OPEN_TYPE_PRECONFIG, 0, 0, 0);
        self.lock.release()
        if not self.hInternet:
            code = GetLastError()
            #gErr.log("couldn't open: %d - %s" %(code, FormatError(code)))
            self.stop()
            return retVal

        #print hInternet

        #print "Doing Connect"
        #gDbg.log('Connecting...')
        if self.callback: self.callback('Connecting...', 1)
        time.sleep(sleepTime)

        INTERNET_SERVICE_HTTP = 3
        INTERNET_INVALID_PORT_NUMBER = 0
        self.hConnect = wininet.InternetConnectA(self.hInternet, host, port,
                                                 user, password, INTERNET_SERVICE_HTTP, 0, 0)
        if not self.hConnect:
            code = GetLastError()
            #gErr.log("couldn't connect: %d - %s" %(code, FormatError(code)))
            self.stop()
            return retVal


        #print hConnect

        #gDbg.log('Opening Request...')
        if self.callback: self.callback('Sending...', 2)
        time.sleep(sleepTime)

        INTERNET_FLAG_NO_CACHE_WRITE = 0x04000000
        self.hRequest = wininet.HttpOpenRequestA(self.hConnect, "GET", url, 0, 0, 0, INTERNET_FLAG_NO_CACHE_WRITE, 0)
        if not self.hRequest:
            code = GetLastError()
            #gErr.log("couldn't open request: %d - %s" %(code, FormatError(code)))
            self.stop()
            return retVal

        #print hRequest


        #gDbg.log('Sending Request...')
        res = wininet.HttpSendRequestA(self.hRequest, 0,0,0,0)
        if not res:
            code = GetLastError()
            gErr.log("couldn't send request: %d - %s" %(code, FormatError(code)))
            self.stop()
            return retVal
        #print "Request Sent: %d", res

        HTTP_QUERY_FLAG_NUMBER = 0x20000000
        HTTP_QUERY_CONTENT_LENGTH = 5
        HTTP_QUERY_STATUS_CODE    = 19

        #gDbg.log('Getting Result...')
        if self.callback: self.callback('Getting Result...', 3)
        time.sleep(sleepTime)

        dwStatus = DWORD()
        dwBufLen = DWORD(4)
        res =wininet.HttpQueryInfoA(self.hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
            byref(dwStatus), byref(dwBufLen), 0)

        if res == 0:
            code = GetLastError()
            #gErr.log("couldn't query info: %d - %s" %(code, FormatError(code)))
            dwStatus.value = 0

        status = dwStatus.value
        #gDbg.log("Status = %d" %status)

        data = ''
        if status == 200:
            while 1:
                buff = c_buffer(8192)
                bytesRead = DWORD()
                bResult = wininet.InternetReadFile(self.hRequest, buff, 8192, byref(bytesRead))
                #print "bResult: ", bResult
                if bytesRead.value == 0:
                    break
                data = data + buff.raw[:bytesRead.value]

        self.stop()
        return (status, data)


    # Returns status and data
    def doUrlPost(self, url, host, postData, headers = {}, user=0, password=0):
        wininet = windll.wininet
        flags = DWORD()
        data = ''
        retVal = (0, data)

        # Use the Registry settings for Proxy (nice!)
        INTERNET_OPEN_TYPE_PRECONFIG = 0
        self.lock.acquire()
        self.hInternet = wininet.InternetOpenA('Blogbot/1.0 (http://blogbot.com/)', INTERNET_OPEN_TYPE_PRECONFIG, 0, 0, 0);
        self.lock.release()
        if not self.hInternet:
            code = GetLastError()
            gErr.log("couldn't open: %d - %s" %(code, FormatError(code)))
            self.stop()
            return retVal

        #print hInternet

        #print "Doing Connect"
        gDbg.log('Connecting...')
        if self.callback: self.callback('Conecting...', 1)
        time.sleep(sleepTime)

        INTERNET_SERVICE_HTTP = 3
        INTERNET_INVALID_PORT_NUMBER = 0
        self.hConnect = wininet.InternetConnectA(self.hInternet, host, INTERNET_INVALID_PORT_NUMBER,
                                                 user, password, INTERNET_SERVICE_HTTP, 0, 0)
        if not self.hConnect:
            code = GetLastError()
            gErr.log("couldn't connect: %d - %s" %(code, FormatError(code)))
            self.stop()
            return retVal


        #print hConnect

        gDbg.log('Opening Request...')
        if self.callback: self.callback('Sending...', 2)
        time.sleep(sleepTime)

        INTERNET_FLAG_NO_CACHE_WRITE = 0x04000000
        #hRequest = wininet.InternetOpenUrlA(hInternet, "http://rpc.bloglines.com/listsubs", 0, 0, 0x80000200L, 0)
        self.hRequest = wininet.HttpOpenRequestA(self.hConnect, "POST", url, 0, 0, 0, INTERNET_FLAG_NO_CACHE_WRITE, 0)
        if not self.hRequest:
            code = GetLastError()
            gErr.log("couldn't open request: %d - %s" %(code, FormatError(code)))
            self.stop()
            return retVal

        #print hRequest


        HTTP_ADDREQ_FLAG_ADD_IF_NEW  = 0x10000000
        HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA     =  0x40000000
        HTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON =  0x01000000
        HTTP_ADDREQ_FLAG_COALESCE = HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA
        HTTP_ADDREQ_FLAG_ADD     =   0x20000000
        HTTP_ADDREQ_FLAG_REPLACE = 0x80000000
        for k in headers.keys():
            res = wininet.HttpAddRequestHeadersA(self.hRequest, "%s: %s\r\n" %(k, headers[k]), -1, HTTP_ADDREQ_FLAG_REPLACE | HTTP_ADDREQ_FLAG_ADD)
            if not res:
                code = GetLastError()
                gErr.log("couldn't add header: %d - %s" %(code, FormatError(code)))
                self.stop()
                return retVal


        gDbg.log('Sending Request...')
        res = wininet.HttpSendRequestA(self.hRequest, 0,0,postData,len(postData))
        if not res:
            code = GetLastError()
            gErr.log("couldn't send request: %d - %s" %(code, FormatError(code)))
            self.stop()
            return retVal
        #print "Request Sent: %d", res

        HTTP_QUERY_FLAG_NUMBER = 0x20000000
        HTTP_QUERY_CONTENT_LENGTH = 5
        HTTP_QUERY_STATUS_CODE    = 19

        gDbg.log('Getting Result...')
        if self.callback: self.callback('Getting Result...', 3)
        time.sleep(sleepTime)

        dwStatus = DWORD()
        dwBufLen = DWORD(4)
        res =wininet.HttpQueryInfoA(self.hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
            byref(dwStatus), byref(dwBufLen), 0)

        if res == 0:
            code = GetLastError()
            gErr.log("couldn't query info: %d - %s" %(code, FormatError(code)))
            dwStatus.value = 0

        status = dwStatus.value
        gDbg.log("Status = %d" %status)

        data = ''
        if (status / 100) == 2:
            while 1:
                buff = c_buffer(8192)
                bytesRead = DWORD()
                bResult = wininet.InternetReadFile(self.hRequest, buff, 8192, byref(bytesRead))
                #print "bResult: ", bResult
                if bytesRead.value == 0:
                    break
                data = data + buff.raw[:bytesRead.value]

        self.stop()
        return (status, data)




if __name__ == '__main__':
    inet = WinInet()
    status, data = inet.doUrlGet("login?openerp_login=admin&openerp_password=xxx", "srvwapt", {}, "", "",port=8000)
    print "s", status
    print "d", data
