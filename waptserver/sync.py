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
from future.utils import python_2_unicode_compatible
from waptutils import get_sha256
from waptserver.model import SyncStatus
import json
import os
import datetime

def get_tree_of_files_rec(adir = '', all_files = {},rmpath = '',changelog = None):
    for entry in os.listdir(adir):
        full_path = os.path.join(adir, entry)
        minpath = os.path.normpath(os.path.relpath(full_path,rmpath)).replace(os.sep, '/')
        all_files[minpath]={}
        if os.path.isdir(full_path):
            all_files[minpath]['isDir']=True
            all_files[minpath]['lastmodification']=os.path.getmtime(full_path)
            all_files[minpath]['size']=os.path.getsize(full_path)
            if changelog:
                changelog['new'][minpath]=dict(all_files[minpath])
            all_files[minpath]['files']={}
            get_tree_of_files_rec(full_path,all_files[minpath]['files'],rmpath,changelog)
        else:
            all_files[minpath]['isDir']=False
            all_files[minpath]['size']=os.path.getsize(full_path)
            all_files[minpath]['lastmodification']=os.path.getmtime(full_path)
            all_files[minpath]['sum']=get_sha256(full_path)
            if changelog:
                changelog['new'][minpath]=all_files[minpath]
    return all_files

def get_tree_of_files(dirs = []):
    all_files = {}
    for adir in dirs:
        if os.path.isdir(adir):
            minpath=os.path.normpath(os.path.relpath(adir,os.path.dirname(adir))).replace(os.sep, '/')
            all_files[minpath]={}
            all_files[minpath]['lastmodification']=os.path.getmtime(adir)
            all_files[minpath]['size']=os.path.getsize(adir)
            all_files[minpath]['realpath']=os.path.normpath(adir)
            all_files[minpath]['isDir']=True
            all_files[minpath]['files']={}
            get_tree_of_files_rec(adir,all_files[minpath]['files'],os.path.dirname(adir))
    return all_files

def put_tree_of_files_in_sync_file(filesync = '',dirs = [],username = 'SERVER'):
    with open(filesync,'w+') as f:
        tree_of_files =  get_tree_of_files(dirs)
        SyncStatus.delete().execute()
        data = {}
        data['updated_by']=username
        data['updated_on']=datetime.datetime.now()
        data['created_by']=username
        data['created_on']=datetime.datetime.now()
        data['version'] = 1
        changelog = unicode(json.dumps(tree_of_files))
        data['changelog'] = changelog
        SyncStatus.create(**data)
        tree_of_files_version = {}
        tree_of_files_version['version'] = 1
        tree_of_files_version['files'] = tree_of_files
        f.write(unicode(json.dumps(tree_of_files_version,f)))
        return tree_of_files_version

def actualize_tree_of_files_rec(adir = '',dico = {},rmpath = '',changelog = None):
    listdirdico = dico.keys()
    for entry in os.listdir(adir):
        fullpath=os.path.join(adir,entry)
        minpath=os.path.normpath(os.path.relpath(fullpath,rmpath)).replace(os.sep, '/')
        if (dico.get(minpath)):
            listdirdico.remove(minpath)
            if (dico[minpath]['lastmodification']==os.path.getmtime(fullpath)) and (dico[minpath]['size']==os.path.getsize(fullpath)):
                if dico[minpath]['isDir']:
                    actualize_tree_of_files_rec(fullpath,dico[minpath]['files'],rmpath,changelog)
                else:
                    continue
            else:
                if os.path.isdir(fullpath):
                    dico[minpath]['lastmodification']=os.path.getmtime(fullpath)
                    dico[minpath]['size']=os.path.getsize(fullpath)
                    changelog['modified'][minpath]=dict(dico[minpath])
                    if (dico[minpath]['isDir']):
                        actualize_tree_of_files_rec(fullpath,dico[minpath]['files'],rmpath,changelog)
                    else:
                        dico[minpath]['isDir']=True
                        dico[minpath]['files']={}
                        del dico[minpath]['sum']
                        get_tree_of_files_rec(fullpath,dico[minpath]['files'],rmpath,changelog)
                    del changelog['modified'][minpath]['files']
                else:
                    dico[minpath]['lastmodification']=os.path.getmtime(fullpath)
                    dico[minpath]['sum']=get_sha256(fullpath)
                    dico[minpath]['size']=os.path.getsize(fullpath)
                    if (dico[minpath]['isDir']):
                        dico[minpath]['isDir']=False
                        del dico[minpath]['files']
                    changelog['modified'][minpath]=dico[minpath]
        else:
            dico[minpath]={}
            dico[minpath]['lastmodification']=os.path.getmtime(fullpath)
            dico[minpath]['size']=os.path.getsize(fullpath)
            if os.path.isdir(fullpath):
                dico[minpath]['isDir']=True
                changelog['new'][minpath]=dict(dico[minpath])
                dico[minpath]['files']={}
                get_tree_of_files_rec(fullpath,dico[minpath]['files'],rmpath,changelog)
            else:
                dico[minpath]['isDir']=False
                dico[minpath]['sum']=get_sha256(fullpath)
                changelog['new'][minpath]=dico[minpath]
    for entry in listdirdico:
        changelog['deleted'][entry]=dict(dico[entry])
        if dico[entry]['isDir']:
            del changelog['deleted'][minpath]['files']
        del dico[entry]

def actualize_tree_of_files(dico = {},changelog = {}):
    changelog['new']={}
    changelog['deleted']={}
    changelog['modified']={}
    for adir in dico:
            actualize_tree_of_files_rec(dico[adir]['realpath'],dico[adir]['files'],os.path.dirname(dico[adir]['realpath']),changelog)
    return dico

def actualize_tree_of_files_in_sync_file(filesync = '',username='SERVER'):
    with open(filesync,'r') as f:
        tree_of_files = json.load(f)
        changelog = {}
        new_tree = {}
        new_tree['files']=actualize_tree_of_files(tree_of_files['files'],changelog)
        if changelog['new'] or changelog['deleted'] or changelog['modified']:
            new_tree['version']=tree_of_files['version']+1
            data = {}
            data['updated_by']=username
            data['updated_on']=datetime.datetime.now()
            data['created_by']=username
            data['created_on']=datetime.datetime.now()
            data['version'] = new_tree['version']
            data['changelog'] = changelog
            SyncStatus.create(**data)
        else:
            new_tree['version']=tree_of_files['version']
        new_tree['changelog']=changelog
    with open(filesync,'w') as f:
        f.write(unicode(json.dumps(new_tree,f)))
        return new_tree

def update_file_tree_of_files(filesync = '', dirs = [],username='SERVER'):
    if not(os.path.isfile(filesync)):
        return put_tree_of_files_in_sync_file(filesync,dirs,username)
    else:
        return actualize_tree_of_files_in_sync_file(filesync,username)