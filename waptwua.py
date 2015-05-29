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

import sys
import os
import win32com.client
import json

from optparse import OptionParser
from urlparse import urlparse

import datetime
import requests
import logging

InstallResult = {
  0: 'NotStarted',
  1: 'InProgress',
  2: 'Succeeded',
  3: 'SucceededWithErrors',
  4: 'Failed',
  5: 'Aborted',
 }

class WaptWUA(object):
    def __init__(self,wapt,allowed_updates=None, forbidden_updates= None, allowed_severities=None, filter="Type='Software'"):
        self.wapt = wapt
        self.cache_path = os.path.abspath(makepath(wapt.wapt_base_dir,'waptwua','cache'))
        self._update_session = None
        self._update_service_manager = None
        self._update_searcher = None
        self._update_service = None
        self.filter = filter
        if allowed_updates is not None:
            self.allowed_updates = allowed_updates
        else:
            au = self.wapt.read_param('waptwua.allowed_updates')
            if au:
                self.allowed_updates = json.loads(au) or '[]'
            else:
                self.allowed_updates = []

        if forbidden_updates is not None:
            self.forbidden_updates = forbidden_updates
        else:
            fu = self.wapt.read_param('waptwua.forbidden_updates') or '[]'
            if au:
                self.forbidden_updates = json.loads(fu)
            else:
                self.forbidden_updates = []

        if allowed_severities is not None:
            self.allowed_severities = allowed_severities
        else:
            au = self.wapt.read_param('waptwua.allowed_severities') or '[]'
            if au:
                self.allowed_severities = json.loads(au)
            else:
                self.allowed_severities = []

        self._updates = None
        # to store successful changes in read only properties of _updates after initial scan
        self._cached_updates = {}
        logger.info('Forbidden updates:%s'%self.forbidden_updates or 'None')
        logger.info('Allowed severities:%s'%(self.allowed_severities or 'All'))
        logger.info('Allowed additional specific updates:%s'%self.allowed_updates or 'None')


    def cached_update_property(self,update,key):
        update_id = update.Identity.UpdateID
        if update_id in self._cached_updates and key in self._cached_updates[update_id]:
            return self._cached_updates[update_id][key]
        else:
            return getattr(update,key)

    def store_cached_update_property(self,update,key,value):
        update_id = update.Identity.UpdateID
        if not update_id in self._cached_updates:
            self._cached_updates[update_id] = {}
        cached = self._cached_updates[update_id]
        cached[key] = value

    def update_as_dict(self,update):
        """Convert a IUpdate instance into a dict
        """
        if self.cached_update_property(update,'IsInstalled'):
            status = 'OK'
        elif not self.cached_update_property(update,'IsInstalled') and not update.IsHidden:
            status = 'PENDING'
        else:
            status = 'DISCARDED'

        return dict(
            uuid = update.Identity.UpdateID,
            title = update.Title,
            type = update.Type,
            status = status,
            kbids = [ "%s" % kb for kb in update.KBArticleIDs ],
            severity = update.MsrcSeverity,
            installed = self.cached_update_property(update,'IsInstalled'),
            hidden = update.IsHidden,
            downloaded = update.IsDownloaded,
            changetime = datetime2isodate(datetime.datetime.fromtimestamp(int(update.LastDeploymentChangeTime)))
            )

    @property
    def update_session(self):
        if self._update_session is None:
            self._update_session = win32com.client.Dispatch("Microsoft.Update.Session")
        return self._update_session

    @property
    def update_service_manager(self):
        if self._update_service_manager is None:
            self._update_service_manager = win32com.client.Dispatch("Microsoft.Update.ServiceManager")
        return self._update_service_manager

    def update_wsusscan_cab(self):
        """Download deom wapt server the last version of wsuscn2.cab database for offline update scan

        """
        if len(self.wapt.repositories)>0:
            try:
                self.wapt.write_param('waptwua.status','UPDATING')
                cab_location = '%swua/wsusscn2.cab' % self.wapt.repositories[0].repo_url
                cab_target = makepath(self.cache_path,'wsusscn2.cab')
                cab_current_date = self.wapt.read_param('waptwua.wsusscn2cab_date')
                cab_new_date = httpdatetime2isodate(requests.head(
                    cab_location,
                    timeout=self.wapt.repositories[0].timeout,
                    proxies=self.wapt.repositories[0].proxies,
                    verify=self.wapt.repositories[0].verify_cert,
                    ).headers['last-modified'])
                if not isfile(cab_target) or (cab_new_date > cab_current_date ):
                    wget(cab_location,cab_target,proxies=self.wapt.repositories[0].proxies,connect_timeout=self.wapt.repositories[0].timeout)
                    self.wapt.write_param('waptwua.wsusscn2cab_date',cab_new_date)
                    logger.debug('New wusscn2.cab date : %s'%cab_new_date)
                self.wapt.write_param('waptwua.status','DBREADY')
                return cab_new_date
            except requests.RequestException as e:
                self.wapt.write_param('waptwua.status','ERROR')
                return None

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

    @property
    def updates(self):
        """List of current updates scanned againts wsusscn2 cab and computer"""
        if self._updates is None:
            filter = self.filter
            self.wapt.write_param('waptwua.status','SCANNING')
            try:
                print 'Looking for updates with filter: %s'%filter
                search_result = self.update_searcher.Search(filter)
                updates_to_install = win32com.client.Dispatch("Microsoft.Update.UpdateColl")
                self._updates = []
                self._cached_updates = {}
                for update in search_result.Updates:
                    self._updates.append(update)
            finally:
                self.wapt.write_param('waptwua.status','READY')
        return self._updates


    def is_allowed(self,update):
        """Check if an update is allowed
            allowed if
        """
        kbs = [ "KB%s" % kb for kb in update.KBArticleIDs ]
        allowed_kb = False
        forbidden_kb = False
        for kb in kbs:
            if kb in self.allowed_updates:
                allowed_kb = True
                break
        for kb in kbs:
            if kb in self.forbidden_updates:
                forbidden_kb = True
                break
        return not forbidden_kb and not update.Identity.UpdateID in self.forbidden_updates and \
            (update.Identity.UpdateID in self.allowed_updates or allowed_kb or update.MsrcSeverity in self.allowed_severities or (not update.MsrcSeverity and self.allowed_severities is None))

    def scan_updates_status(self):
        """Check all updates and filter out which one should be installed"""
        installed,pending,discarded = 0,0,0
        logger.debug('Scanning installed / not installed Updates')
        for update in self.updates:
            if not self.cached_update_property(update,'IsInstalled'):
                if self.is_allowed(update):
                    # IUpdate : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386099(v=vs.85).aspx
                    # IUpdate2 : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386100(v=vs.85).aspx
                    logger.info('Adding %s : %s' % (update.Identity.UpdateID,update.Title ))
                    update.IsHidden = False
                    pending += 1
                else:
                    logger.info('Skipping %s : %s' % (update.Identity.UpdateID,update.Title ))
                    update.IsHidden = True
                    discarded += 1
            else:
                logger.debug('Already installed %s : %s' % (update.Identity.UpdateID,update.Title ))
                installed += 1

        logger.debug('Writing status in local wapt DB')
        self.wapt.write_param('waptwua.updates',json.dumps([ self.update_as_dict(u) for u in self.updates]))
        self.wapt.write_param('waptwua.last_scan_date',datetime2isodate())
        if not pending:
            self.wapt.write_param('waptwua.status','OK')
        else:
            self.wapt.write_param('waptwua.status','PENDING_UPDATES')
        # send status to wapt server
        logger.debug('Updating workstation status on remote wapt server')
        self.wapt.update_server_status()
        return (installed,pending,discarded)

    def wget_update(self,url,target):
        # try using specialized proxy
        if len(self.wapt.repositories)>0:
            wua_proxy = {'http':'http://%s:8123' % (urlparse(self.wapt.repositories[0].repo_url).netloc,)}
        else:
            wua_proxy = None
        wget(url,target,proxies=wua_proxy)

    def download_single(self,update):
        result = []
        try:
            self.wapt.write_param('waptwua.status','DOWNLOADING')

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

            self.wapt.write_param('waptwua.status','READY')
        except:
            self.wapt.write_param('waptwua.status','ERROR')
            raise
        return result

    def download_updates(self):
        """Download all pending updates and put them in Windows Update cache

        """
        result = []
        for update in self.updates:
            if not update.IsInstalled and self.is_allowed(update) and not update.IsDownloaded:
                # IUpdate : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386099(v=vs.85).aspx
                # IUpdate2 : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386100(v=vs.85).aspx
                result.extend(self.download_single(update))
        self.scan_updates_status()
        return result

    def install_updates(self):
        """Install all pending downloaded updates"""
        result = []
        try:
            self.wapt.write_param('waptwua.status','INSTALL')
            updates_to_install = win32com.client.Dispatch("Microsoft.Update.UpdateColl")
            #apply the updates
            for update in self.updates:
                if self.is_allowed(update):
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
                self.wapt.write_param('waptwua.rebootrequired',json.dumps(installation_result.RebootRequired))
                self.wapt.write_param('waptwua.last_install_result',InstallResult[installation_result.ResultCode])
                if installation_result.ResultCode in [3,4,5]:
                    self.wapt.write_param('waptwua.status','ERROR')
                else:
                    # assume all is installed for the next report...
                    for update in self.updates:
                        self.store_cached_update_property(update,'IsInstalled',True)

            else:
                self.wapt.write_param('waptwua.rebootrequired',json.dumps(False))
                self.wapt.write_param('waptwua.last_install_result','None')

            self.wapt.write_param('waptwua.last_install_batch',json.dumps(result))
            self.wapt.write_param('waptwua.last_install_date',datetime2isodate())
        except:
            self.wapt.write_param('waptwua.status','ERROR')
        finally:
            self.scan_updates_status()
        return result


    def stored_status(self):
        return {
            'last_scan_date':self.wapt.read_param('waptwua.last_scan_date'),
            'last_install_batch':self.wapt.read_param('waptwua.last_install_batch'),
            'last_install_date':self.wapt.read_param('waptwua.last_install_date'),
            'last_install_result':self.wapt.read_param('waptwua.last_install_result'),
            'wsusscn2cab_date':self.wapt.read_param('waptwua.wsusscn2cab_date'),
            'rebootrequired':self.wapt.read_param('waptwua.rebootrequired'),
            'updates':json.loads(self.wapt.read_param('waptwua.updates') or '[]'),
            'status':self.wapt.read_param('waptwua.status'),
            'allowed_updates':json.loads(self.wapt.read_param('waptwua.allowed_updates') or '[]'),
            }

if __name__ == '__main__':
    parser=OptionParser(usage=__doc__)
    parser.add_option("-S","--severity", dest="severity", default='All', help="Allow updates by severity. csv list of  Critical,Important,Moderate,Low (default: %default)")
    parser.add_option("-a","--allowed", dest="allowed", default=None, help="Allow updates by update-id or KB. csv list of id to allow (default: %default)")
    parser.add_option("-b","--forbidden", dest="forbidden", default=None, help="Forbid updates by update-id or KB. csv list (default: %default)")
    parser.add_option("-c","--config", dest="config", default=None, help="Config file full path (default: %default)")
    parser.add_option("-l","--loglevel", dest="loglevel", default=None, type='choice',  choices=['debug','warning','info','error','critical'], metavar='LOGLEVEL',help="Loglevel (default: warning)")
    #parser.add_option("-d","--dry-run", dest="dry_run",    default=False, action='store_true', help="Dry run (default: %default)")

    (options,args) = parser.parse_args()

    logger = logging.getLogger()
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')

    def setloglevel(logger,loglevel):
        """set loglevel as string"""
        if loglevel in ('debug','warning','info','error','critical'):
            numeric_level = getattr(logging, loglevel.upper(), None)
            if not isinstance(numeric_level, int):
                raise ValueError(_('Invalid log level: {}').format(loglevel))
            logger.setLevel(numeric_level)

    # force loglevel
    if options.loglevel is not None:
        setloglevel(logger,options.loglevel)


    from common import Wapt
    wapt = Wapt(config_filename=options.config)

    if options.allowed is not None:
        allowed_updates = ensure_list(options.allowed)
    else:
        allowed_updates = None

    if options.forbidden is not None:
        forbidden_updates = ensure_list(options.forbidden)
    else:
        forbidden_updates = None

    if options.severity is not None:
        allowed_severities = ensure_list(options.severity)
    else:
        allowed_severities = None

    wua = WaptWUA(wapt,allowed_updates=allowed_updates,forbidden_updates=forbidden_updates,allowed_severities=allowed_severities)
    if len(args) <1:
        print parser.usage
        sys.exit(1)

    action = args[0]
    if action == 'scan':
        installed,pending,discarded = wua.scan_updates_status()
        print "%s installed updates" % installed
        print "%s pending updates" % pending
        print "%s discarded updates" % discarded
    elif action == 'download':
        print wua.download_updates()
    elif action == 'install':
        print wua.install_updates()
    else:
        print parser.usage

