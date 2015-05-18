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
from setuphelpers import *

import os
import win32com.client

# https://support.microsoft.com/en-us/kb/927745
# download updated version of  wsus index cab file
#wget('http://go.microsoft.com/fwlink/?LinkID=74689','wsusscn2.cab')

class WaptWUA(object):
    def __init__(self,wapt):
        self.wapt = wapt
        self.cache_path = makepath(wapt.wapt_base_dir,'waptwua','cache')
        self.update_session = win32com.client.Dispatch("Microsoft.Update.Session")
        self.update_service_manager = win32com.client.Dispatch("Microsoft.Update.ServiceManager")
        self._update_searcher = None
        self._update_service = None

    def update_wsusscan_cab(self):
        if len(self.wapt.repositories)>0:
            wget('%swua/wsusscn2.cab' % self.wapt.repositories[0].repo_url,makepath(self.cache_path,'wsusscn2.cab'))

    def scan_updates(self,filter="IsInstalled=0 and Type='Software'"):
        print 'Looking for updates with filter: %s'%filter
        search_result = self.update_searcher.Search(filter)
        updates_to_install = win32com.client.Dispatch("Microsoft.Update.UpdateColl")

        for update in search_result.Updates:
            if update.MsrcSeverity == 'Critical':
                # IUpdate : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386099(v=vs.85).aspx
                # IUpdate2 : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386100(v=vs.85).aspx

                #update.AcceptEula()
                updates_to_install.add(update)
                print update.Identity.UpdateID,update.Title,
                """for dc in update.DownloadContents:
                    #https://msdn.microsoft.com/en-us/library/windows/desktop/aa386120(v=vs.85).aspx
                    print dc.DownloadUrl
                    target = makepath(r'C:\tranquilit\tis-mbsa-wapt',os.path.split(dc.DownloadUrl)[1])
                    files = win32com.client.Dispatch('Microsoft.Update.StringColl')
                    if not isfile(target):
                        wget(dc.DownloadUrl,target)
                    if isfile(target):
                        files.add(target)

                    update.CopyToCache(files)
                    for fn in files:
                        print"%s put to local WUA cache for update %s" % (fn,update.Title)

                for bu in update.BundledUpdates:
                    files = win32com.client.Dispatch('Microsoft.Update.StringColl')
                    for dc in bu.DownloadContents:
                        #https://msdn.microsoft.com/en-us/library/windows/desktop/aa386120(v=vs.85).aspx
                        print dc.DownloadUrl
                        target = makepath(self.cache_path,os.path.split(dc.DownloadUrl)[1])
                        if not isfile(target):
                            wget(dc.DownloadUrl,target,proxies={'http':'http://wapt.tranquilit.local:8123'})
                        if isfile(target):
                            files.add(target)

                    bu.CopyToCache(files)
                    for fn in files:
                        print"%s put to local WUA cache for update %s" % (fn,update.Title)
                        if isfile(fn):
                            remove_file(fn)
                """
        return updates_to_install

    @property
    def update_searcher(self):
        if not self._update_searcher:
            print('   Connecting to local update searcher using offline wsusscn2 file...')
            wsusscn2_path = makepath(self.cache_path,'wsusscn2.cab')
            if not isfile(wsusscn2_path):
                self.update_wsusscan_cab()
            # use wsus offline updates index cab
            self._update_service = self.update_service_manager.AddScanPackageService("Offline Sync Service",wsusscn2_path)
            self._update_searcher = self.update_session.CreateupdateSearcher()
            # use offline only
            self._update_searcher.ServerSelection = 3 # other
            self._update_searcher.ServiceID = self._update_service.ServiceID
            print('   Update searcher ready...')
        return self._update_searcher


    def download_patches(self):
        search_result = self.update_searcher.Search("IsInstalled=0 and Type='Software' and IsDownloaded=0")
        updates_to_install = win32com.client.Dispatch("Microsoft.Update.UpdateColl")

        for update in search_result.Updates:
            if update.MsrcSeverity == 'Critical':
                # IUpdate : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386099(v=vs.85).aspx
                # IUpdate2 : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386100(v=vs.85).aspx

                #update.AcceptEula()
                updates_to_install.add(update)
                print update.Identity.UpdateID,update.Title,
                """for dc in update.DownloadContents:
                    #https://msdn.microsoft.com/en-us/library/windows/desktop/aa386120(v=vs.85).aspx
                    print dc.DownloadUrl
                    target = makepath(r'C:\tranquilit\tis-mbsa-wapt',os.path.split(dc.DownloadUrl)[1])
                    files = win32com.client.Dispatch('Microsoft.Update.StringColl')
                    if not isfile(target):
                        wget(dc.DownloadUrl,target)
                    if isfile(target):
                        files.add(target)

                    update.CopyToCache(files)
                    for fn in files:
                        print"%s put to local WUA cache for update %s" % (fn,update.Title)

                for bu in update.BundledUpdates:
                    files = win32com.client.Dispatch('Microsoft.Update.StringColl')
                    for dc in bu.DownloadContents:
                        #https://msdn.microsoft.com/en-us/library/windows/desktop/aa386120(v=vs.85).aspx
                        print dc.DownloadUrl
                        target = makepath(self.cache_path,os.path.split(dc.DownloadUrl)[1])
                        if not isfile(target):
                            wget(dc.DownloadUrl,target,proxies={'http':'http://wapt.tranquilit.local:8123'})
                        if isfile(target):
                            files.add(target)

                    bu.CopyToCache(files)
                    for fn in files:
                        print"%s put to local WUA cache for update %s" % (fn,update.Title)
                        if isfile(fn):
                            remove_file(fn)
                """

        def install_patches(self):
            #apply the updates
            for update in self.scan_updates():
                update.AcceptEula()
            installer = self.update_session.CreateUpdateInstaller()
            installer.Updates = updates_to_install
            installation_result = installer.Install()
            print "Result %s" % installation_result.ResultCode
            print "Reboot required %s" % installation_result.RebootRequired



# list of properties : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386099(v=vs.85).aspx
if __name__ == '__main__':
    from common import *
    w = Wapt()
    wua = WaptWUA(w)
    #us = wua.update_searcher
    print wua.scan_updates()
    print wua

