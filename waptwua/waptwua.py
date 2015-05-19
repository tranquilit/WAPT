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
"""
    waptpython waptwua.py <action>

    Script which scans the computer for Windows Update based on wsusscn2 cab
    Stores the result of scan in waptdb
    Can download and apply Windows Updates from wapt server
    based on allowed_updates list

    <action> can be :
        scan : updates wsusscn2.cab, and checks current computer againt allowed KB
        download : download necessary updates from wapt server and push them in cache
        install : install allowed cached updates
"""

from setuphelpers import *
from common import *

import os
import win32com.client
import json

from optparse import OptionParser
from urlparse import urlparse

from common import httpdatetime2isodate,isodate2datetime
import datetime

def ensure_list(csv_or_list,ignore_empty_args=True):
    """if argument is not a list, return a list from a csv string"""
    if csv_or_list is None:
        return []
    if isinstance(csv_or_list,tuple):
        return list(csv_or_list)
    elif not isinstance(csv_or_list,list):
        if ignore_empty_args:
            return [s.strip() for s in csv_or_list.split(',') if s.strip() != '']
        else:
            return [s.strip() for s in csv_or_list.split(',')]
    else:
        return csv_or_list

# https://support.microsoft.com/en-us/kb/927745
# download updated version of  wsus index cab file
#wget('http://go.microsoft.com/fwlink/?LinkID=74689','wsusscn2.cab')

def update_as_dict(update):
    """Convert a IUpdate instance into a dict
    """
    return dict(
        uuid = update.Identity.UpdateID,
        title = update.Title,
        type = update.Type,
        kbids = [ "%s" % kb for kb in update.KBArticleIDs ],
        severity = update.MsrcSeverity,
        installed = update.IsInstalled,
        downloaded = update.IsDownloaded,
        changetime = datetime2isodate(datetime.datetime.fromtimestamp(int(update.LastDeploymentChangeTime)))
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
    def __init__(self,wapt,allowed_updates=None, filter="Type='Software'", allow_critical=False):
        self.wapt = wapt
        self.cache_path = makepath(wapt.wapt_base_dir,'waptwua','cache')
        self.update_session = win32com.client.Dispatch("Microsoft.Update.Session")
        self.update_service_manager = win32com.client.Dispatch("Microsoft.Update.ServiceManager")
        self._update_searcher = None
        self._update_service = None
        self.filter = filter
        self.allow_critical = allow_critical
        if allowed_updates is not None:
            self.allowed_updates = allowed_updates
        else:
            au = self.wapt.read_param('waptwua.allowed_updates')
            if au:
                self.allowed_updates = json.loads(au)
            else:
                self.allowed_updates = []

        self._installed_updates = None
        self._pending_updates = None
        self._discarded_updates = None

    def update_wsusscan_cab(self):
        if len(self.wapt.repositories)>0:
            try:
                cab_location = '%swua/wsusscn2.cab' % self.wapt.repositories[0].repo_url
                cab_target = makepath(self.cache_path,'wsusscn2.cab')
                cab_current_date = self.wapt.read_param('waptwua.wsusscn2cab_date')
                cab_new_date = httpdatetime2isodate(requests.head(
                    cab_location,
                    timeout=self.wapt.repositories[0].timeout,
                    proxies=self.wapt.repositories[0].proxies,
                    verify=False,
                    ).headers['last-modified'])
                if not isfile(cab_target) or (cab_new_date > cab_current_date ):
                    wget(cab_location,cab_target,proxies=self.wapt.repositories[0].proxies,connect_timeout=self.wapt.repositories[0].timeout)
                    self.wapt.write_param('waptwua.wsusscn2cab_date',cab_new_date)

                return cab_new_date
            except requests.RequestException as e:
                return None

    def scan_updates(self):
        filter = self.filter
        print 'Looking for updates with filter: %s'%filter
        search_result = self.update_searcher.Search(filter)
        updates_to_install = win32com.client.Dispatch("Microsoft.Update.UpdateColl")

        self._installed_updates = []
        self._pending_updates = []
        self._discarded_updates = []

        for update in search_result.Updates:
            kbs = [ "KB%s" % kb for kb in update.KBArticleIDs ]
            match_kb = False
            for kb in kbs:
                if kb in self.allowed_updates:
                    match_kb = True
                    break
            if update.IsInstalled:
                self._installed_updates.append(update)
            elif update.Identity.UpdateID in self.allowed_updates or match_kb or (self.allow_critical and update.MsrcSeverity == 'Critical'):
                # IUpdate : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386099(v=vs.85).aspx
                # IUpdate2 : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386100(v=vs.85).aspx
                print('Adding %s : %s' % (update.Identity.UpdateID,update.Title ))
                update.IsHidden = False
                self._pending_updates.append(update)
            else:
                print('Skipping %s : %s' % (update.Identity.UpdateID,update.Title ))
                update.IsHidden = True
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
            try:
                cab_sourcedate = self.update_wsusscan_cab()
            except Exception as e:
                if isfile(wsusscn2_path):
                    print('Unable to refresh wsusscan cab, using old one. (error: %s)'%e)
                else:
                    print('Unable to get wsusscan cab, aborting.')
                    raise
            # use wsus offline updates index cab
            self._update_service = self.update_service_manager.AddScanPackageService("Offline Sync Service",wsusscn2_path)
            self._update_searcher = self.update_session.CreateupdateSearcher()
            # use offline only
            self._update_searcher.ServerSelection = 3 # other
            self._update_searcher.ServiceID = self._update_service.ServiceID
            print('   Offline Update searcher ready...')
        return self._update_searcher

    def wget_update(self,url,target):
        # try using specialized proxy
        if len(self.wapt.repositories)>0:
            wua_proxy = {'http':'http://%s:8123' % (urlparse(self.wapt.repositories[0].repo_url).netloc,)}
        else:
            wua_proxy = None
        wget(url,target,proxies=wua_proxy)

    def download_single(self,update):
        result = []
        for dc in update.DownloadContents:
            #https://msdn.microsoft.com/en-us/library/windows/desktop/aa386120(v=vs.85).aspx
            print dc.DownloadUrl
            target = makepath(self.cache_path,os.path.split(dc.DownloadUrl)[1])
            files = win32com.client.Dispatch('Microsoft.Update.StringColl')
            if not isfile(target):
                self.wget_update(dc.DownloadUrl,target)
                result.append(dc.DownloadUrl)
            if isfile(target):
                files.add(target)

            update.CopyToCache(files)
            for fn in files:
                print"%s put to local WUA cache for update" % (fn,)
                if isfile(fn):
                    remove_file(fn)

        for bu in update.BundledUpdates:
            files = win32com.client.Dispatch('Microsoft.Update.StringColl')
            for dc in bu.DownloadContents:
                #https://msdn.microsoft.com/en-us/library/windows/desktop/aa386120(v=vs.85).aspx
                print dc.DownloadUrl
                target = makepath(self.cache_path,os.path.split(dc.DownloadUrl)[1])
                if not isfile(target):
                    self.wget_update(dc.DownloadUrl,target)
                    result.append(dc.DownloadUrl)
                if isfile(target):
                    files.add(target)

            bu.CopyToCache(files)
            for fn in files:
                print"%s put to local WUA cache for update %s" % (fn,update.Title)
                if isfile(fn):
                    remove_file(fn)

        return result

    def download_updates(self):
        """Download all pending updates and put them in Windows Update cache

        """
        result = []
        if self._pending_updates is None:
            self.scan_updates()
        for update in self._pending_updates:
            if update.IsDownloaded == 0:
                # IUpdate : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386099(v=vs.85).aspx
                # IUpdate2 : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386100(v=vs.85).aspx
                result.extend(self.download_single(update))
        return result

    def install_updates(self):
        """Install all pending downloaded updates"""
        result = []
        if self._pending_updates is None:
            self.scan_updates()
        updates_to_install = win32com.client.Dispatch("Microsoft.Update.UpdateColl")
        #apply the updates
        for update in self._pending_updates:
            if not update.IsDownloaded:
                self.download_single(update)
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

    def store_status(self):
        pass

    def status(self):
        return {
            'last_scan_date':self.wapt.read_param('waptwua.last_scan_date'),
            'last_install_batch':self.wapt.read_param('waptwua.last_install_batch'),
            'last_install_date':self.wapt.read_param('waptwua.last_install_date'),
            'last_install_result':self.wapt.read_param('waptwua.last_install_result'),
            'wsusscn2cab_date':self.wapt.read_param('waptwua.wsusscn2cab_date'),
            'installed':json.loads(self.wapt.read_param('waptwua.installed') or '[]'),
            'pending':json.loads(self.wapt.read_param('waptwua.pending') or '[]'),
            'discarded':json.loads(self.wapt.read_param('waptwua.discarded') or '[]'),
            }


if __name__ == '__main__':
    parser=OptionParser(usage=__doc__)
    parser.add_option("-a","--allowed", dest="allowed", default='', help="List of updates uuid or KB to apply (default: %default)")
    parser.add_option("-c","--config", dest="config", default=None, help="Config file full path (default: %default)")
    parser.add_option("-C","--critical", dest="allow_critical", default=False, action='store_true', help="Allows all 'Critical' updates too (default: %default)")
    #parser.add_option("-d","--dry-run", dest="dry_run",    default=False, action='store_true', help="Dry run (default: %default)")
    (options,args) = parser.parse_args()

    wapt = Wapt(config_filename=options.config)

    allowed_updates = ensure_list(options.allowed) or None
    wua = WaptWUA(wapt,allowed_updates=allowed_updates,allow_critical=options.allow_critical)
    if len(args) <1:
        print parser.usage
        sys.exit(1)

    action = args[0]
    if action == 'scan':
        pending = wua.scan_updates()
        print "%s pending updates" % (len(pending),)
    elif action == 'download':
        print wua.download_updates()
    elif action == 'install':
        print wua.install_updates()
    else:
        print parser.usage

