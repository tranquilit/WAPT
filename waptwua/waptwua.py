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

def update_as_dict(update):
    return dict(
        uuid = update.Identity.UpdateID,
        title = update.Title,
        type = update.Type,
        description = update.Description,
        kbids = [ "%s" % kb for kb in update.KBArticleIDs ],
        severity = update.MsrcSeverity,
        installed = update.IsInstalled,
        downloaded = update.IsDownloaded,
        )

InstallResult = {
  0: 'NotStarted',
  1: 'InProgress',
  2: 'Succeeded',
  3: 'SucceededWithErrors',
  4: 'Failed',
  5: 'Aborted',
 }

class WaptWUA(object):
    def __init__(self,wapt,allowed_updates=[], filter="Type='Software'"):
        self.wapt = wapt
        self.cache_path = makepath(wapt.wapt_base_dir,'waptwua','cache')
        self.update_session = win32com.client.Dispatch("Microsoft.Update.Session")
        self.update_service_manager = win32com.client.Dispatch("Microsoft.Update.ServiceManager")
        self._update_searcher = None
        self._update_service = None
        self.filter = filter
        self.allowed_updates = allowed_updates

        self._installed_updates = None
        self._pending_updates = None
        self._discarded_updates = None

    def update_wsusscan_cab(self):
        if len(self.wapt.repositories)>0:
            wget('%swua/wsusscn2.cab' % self.wapt.repositories[0].repo_url,makepath(self.cache_path,'wsusscn2.cab'))

    def scan_updates(self):
        filter = self.filter
        print 'Looking for updates with filter: %s'%filter
        search_result = self.update_searcher.Search(filter)
        updates_to_install = win32com.client.Dispatch("Microsoft.Update.UpdateColl")

        self._installed_updates = []
        self._pending_updates = []
        self._discarded_updates = []

        for update in search_result.Updates:
            if update.IsInstalled:
                self._installed_updates.append(update)
            elif update.Identity.UpdateID in self.allowed_updates:
                # IUpdate : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386099(v=vs.85).aspx
                # IUpdate2 : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386100(v=vs.85).aspx
                print('Adding %s : %s' % (update.Identity.UpdateID,update.Title ))
                self._pending_updates.append(update)
            else:
                print('Skipping %s : %s' % (update.Identity.UpdateID,update.Title ))
                self._discarded_updates.append(update)

        self.wapt.write_param('waptwua.installed',jsondump([ update_as_dict(u) for u in self._installed_updates]))
        self.wapt.write_param('waptwua.pending',jsondump([ update_as_dict(u) for u in self._pending_updates]))
        self.wapt.write_param('waptwua.discarded',jsondump([ update_as_dict(u) for u in self._discarded_updates]))
        self.wapt.write_param('waptwua.last_scan_date',datetime2isodate())

        return self._pending_updates

    @property
    def update_searcher(self):
        """Instantiate a updateSearcher instance
        """
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
            print('   Offline Update searcher ready...')
        return self._update_searcher

    def download_updates(self):
        """Download all pending updates and put them in Windows Update cache

        """
        updates_to_download = win32com.client.Dispatch("Microsoft.Update.UpdateColl")
        for update in self._pending_updates:
            if update.IsDownloaded == 0:
                # IUpdate : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386099(v=vs.85).aspx
                # IUpdate2 : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386100(v=vs.85).aspx
                updates_to_download.add(update)
                for dc in update.DownloadContents:
                    #https://msdn.microsoft.com/en-us/library/windows/desktop/aa386120(v=vs.85).aspx
                    print dc.DownloadUrl
                    target = makepath(self.cache_path,os.path.split(dc.DownloadUrl)[1])
                    files = win32com.client.Dispatch('Microsoft.Update.StringColl')
                    if not isfile(target):
                        wget(dc.DownloadUrl,target)
                    if isfile(target):
                        files.add(target)

                    update.CopyToCache(files)
                    for fn in files:
                        print"%s put to local WUA cache for update %s" % (fn,update.Title)
                        if isfile(fn):
                            remove_file(fn)

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


    def install_updates(self):
        """Install all pending downloaded updates"""
        result = []
        if self._pending_updates is None:
            self.scan_updates()
        updates_to_install = win32com.client.Dispatch("Microsoft.Update.UpdateColl")
        #apply the updates
        for update in self._pending_updates:
            if update.IsDownloaded:
                update.AcceptEula()
                updates_to_install.add(update)
                result.append(update.Identity.UpdateID)

        if result:
            installer = self.update_session.CreateUpdateInstaller()
            installer.Updates = updates_to_install
            installation_result = installer.Install()
            print "Result: %s" % installation_result.ResultCode
            print "Reboot required: %s" % installation_result.RebootRequired
            self.wapt.write_param('waptwua.rebootrequired',jsondump(installation_result.RebootRequired))
            self.wapt.write_param('waptwua.last_install_result',InstallResult[installation_result.ResultCode])
        else:
            self.wapt.write_param('waptwua.rebootrequired',jsondump(False))
            self.wapt.write_param('waptwua.last_install_result','None')

        self.wapt.write_param('waptwua.last_install_batch',jsondump(result))
        self.wapt.write_param('waptwua.last_install_date',datetime2isodate())
        return result


# list of properties : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386099(v=vs.85).aspx
if __name__ == '__main__':
    from common import *
    w = Wapt()
    wua = WaptWUA(w,allowed_updates=['1072c136-fabd-435a-a032-10996626e444'])
    #us = wua.update_searcher
    print wua.scan_updates()
    print 'Pending : '+wua.wapt.read_param('waptwua.pending')
    print 'Discarded : '+wua.wapt.read_param('waptwua.discarded')
    print wua.download_updates()
    print wua.install_updates()
    print "Finished"



