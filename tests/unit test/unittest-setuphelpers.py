#!/usr/bin/python
#-*- coding: utf-8 -*-
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

#import des bibliothèque nécessaire
from setuphelpers import *
from setuphelpers import CalledProcessErrorOutput##on l'import a part car pas dans le * de setuphelper
from setuphelpers import get_user_from_profpath
import psutil
import win32serviceutil
import requests
import win32ui
import unittest
import time
import _winreg
from win32com.shell import shell, shellcon
import ctypes
import json
import wmi
import datetime


##tuto : https://openclassrooms.com/courses/apprenez-a-programmer-en-python/les-tests-unitaires-avec-unittest
##doc : https://docs.python.org/3/library/unittest.html

##=========
##TODO
##=========
##Not done becoause deprecated
##get_task
##run_task
##delete_task
##disable_task
##enable_task
##create_daily_task
##create_onetime_task
##--------------------------------
##Not done because need an win 10 vm:
##remove_metroapp
##--------------------------------
##Not done because : impossible now
##reboot_machine
##--------------------------------
##not done because never use and can't test it
##adjust_current_privileges

class Test_Setup_Helpers(unittest.TestCase):

    def setUp(self):
        ##for test ensure dir
       self.dir_to_ensure =r'C:\Users\Default\AppData\Local\Temp\test\test\itswork\\'
       ##for ensure_list
       self.list_1 = 'test,test,test,,,'
       self.list_2 = 'test2,test2,test2'
       self.list_3 = None
       self.current_user = os.environ['USERPROFILE']
       self.softTestExt = r'c:\tranquilit\wapt\tests\TestExtension\TestExtension.exe'
       self.computername = 'wsbharismendy'
       self.hostname ='wsbharismendy.brice.lan'
       self.domain_name =u'brice.lan'
       self.logged_user = os.environ['USERNAME']
       self.registered_organization = u'Orgname'
       self.emplacementTest_ini = 'c:/tranquilit/wapt/tests/test.ini'
       self.test_dir = u'c:\\tranquilit\\wapt\\tests\\'
       self.networkingResult =[{'addr': '192.168.149.195','broadcast': '192.168.149.255', 'connected': True,'iface': '{CF93A805-7868-4320-B01C-B63443230A9F}', 'mac': '9e:80:4d:3f:f8:1f','netmask': '255.255.255.0'}]
       self.gateway=[u'192.168.149.254']
       self.profilPathFromSid =u'C:\\Windows\\ServiceProfiles\\LocalService'
       self.userFromProPath = u'LocalService'
       self.ListeDesUtilisateur = [u'AUTORITE NT\\Syst\xe8me', u'AUTORITE NT\\SERVICE LOCAL', u'AUTORITE NT\\SERVICE R\xc9SEAU', u'BRICE\\test', u'BRICE\\administrator', u'administrator', u'WSBHARISMENDY\\bharismendy-adm', u'WSBHARISMENDY\\Administrateur']
       self.AdminLocal = [u'Administrateur', u'bharismendy-adm']
       self.user ='Administrateur'#name of an local user
       self.local_group =[u'Administrateurs']#Group of user in self.user
       self.members_groups_administrateur =[u'WSBHARISMENDY\\Administrateur', u'WSBHARISMENDY\\bharismendy-adm', u'BRICE\\Domain Admins']#members of the administrator's group
       self.dll = self.test_dir +'test.dll'
       self.windows_version = Version('6.1.7601')
       self.os_language = 'fr'
       self.ExeInstallerInfoDefaultValue ={'architecture': 'all', 'description': u'Firefox (Mozilla)', 'filename': 'Firefox Setup Stub 53.0.exe', 'silentflags': '/s', 'simplename': u'firefox', 'type': 'SFXCab', 'uninstallkey': None, 'version': u'4.42'}
       self.MsiInstallerInfoDefaultValue = {'architecture': 'all', 'description': u'7-Zip 9.20 (Igor Pavlov)', 'filename': '7z920.msi', 'silentflags': '/q /norestart', 'simplename': u'7-zip-9.20', 'type': 'MSI', 'uninstallkey': u'{23170F69-40C1-2701-0920-000001000000}','version': u'9.20.00.0'}
       self.version_python= '2.7.13150'
       self.python_key = '{4A656C6C-D24A-473F-9747-3A8D00907A03}'

    def test_ensure_dir(self):
        if os.path.isdir(self.dir_to_ensure):
            shutil.rmtree(r'C:\Users\Default\AppData\Local\Temp\test')
        ensure_dir(self.dir_to_ensure)
        self.assertEqual(True, os.path.isdir(self.dir_to_ensure))

    def test_ensure_unicode(self):
        self.assertEqual(u'\xe9\xe9',ensure_unicode (str('éé')))
        self.assertEqual(u'\xe9\xe9',ensure_unicode (u'éé'))
        self.assertEqual(u'Exception: test',ensure_unicode (Exception("test")))
        self.assertEqual(u'Exception: ',ensure_unicode (Exception()))
        self.assertEqual(u'\u6298',ensure_unicode (u'折'))
        self.assertEqual( u'\u0118',ensure_unicode (u'Ę'))


    def test_called_process_error_output(self):
        with self.assertRaises(CalledProcessErrorOutput):
            run(r'dir 666:\\')


    def test_ensure_list(self):
        self.assertEqual(['test', 'test', 'test', '', '', ''],ensure_list(self.list_1,False))
        self.assertEqual(['test', 'test', 'test'],ensure_list(self.list_1,True))
        self.assertEqual(['test2', 'test2', 'test2'],ensure_list(self.list_2))
        self.assertEqual(None,ensure_list(self.list_3,True,True))
        self.assertEqual([],ensure_list(self.list_3))


    def test_create_shortcut(self):
        if os.path.islink(r'C:\Users\Default\AppData\Local\Temp\test.lnk'):
            os.remove('C:\Users\Default\AppData\Local\Temp\test.lnk')
        self.assertEqual(None,create_shortcut(r'C:\Users\Default\AppData\Local\Temp\test.lnk',target='c:\\wapt\\waptconsole.exe'))


    def test_create_desktop_shortcut(self):
        if os.path.islink(r'C:\Users\Public\Desktop\WAPT Console Management.lnk'):
            os.remove('C:\Users\Public\Desktop\WAPT Console Management.lnk')
        self.assertEqual(r'C:\Users\Public\Desktop\WAPT Console Management.lnk',create_desktop_shortcut(r'WAPT Console Management',target=r'c:\wapt\waptconsole.exe'))

        if os.path.islink(r'C:\Users\Public\Desktop\WAPT local status.url'):
            os.remove(r'C:\Users\Public\Desktop\WAPT local status.url')
        self.assertEqual(r'C:\Users\Public\Desktop\WAPT local status.url',create_desktop_shortcut(r'WAPT local status',target='http://localhost:8088/'))

    def test_create_user_desktop_shortcut(self):
        if os.path.islink(self.current_user+u'\\AppData\\Roaming\\Microsoft\Windows\\Start Menu\\Console WAPT.lnk'):
            os.remove(self.current_user+u'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Console WAPT.lnk')
        self.assertEqual(self.current_user+u'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Console WAPT.lnk',create_user_programs_menu_shortcut('Console WAPT', target=makepath('c:/wapt','waptconsole.exe')))

        if os.path.islink(self.current_user+u'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Doc-TranquilIT.url'):
            os.remove(self.current_user+u'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Doc-TranquilIT.url')
        self.assertEqual(self.current_user+u'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Doc-TranquilIT.url',create_user_programs_menu_shortcut('Doc-TranquilIT', target='https://doc.wapt.fr'))


    def test_create_programs_menu_shortcut(self):
        if os.path.islink(u'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Doc-TranquilIT.url'):
            os.remove(u'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Doc-TranquilIT.url')
        self.assertEqual(u'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Doc-TranquilIT.url',create_programs_menu_shortcut('Doc-TranquilIT', target='https://doc.wapt.fr'))

        if os.path.islink(u'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Console WAPT.lnk'):
            os.remove(u'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Console WAPT.lnk')
        self.assertEqual(u'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Console WAPT.lnk',create_programs_menu_shortcut('Console WAPT', target=makepath('c:/wapt','waptconsole.exe')))



    def test_create_user_programs_menu_shortcut(self):
        if os.path.islink(self.current_user+u'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Doc-TranquilIT.url'):
            os.remove(self.current_user+u'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Doc-TranquilIT.url')
        self.assertEqual(self.current_user+u'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Doc-TranquilIT.url',create_user_programs_menu_shortcut('Doc-TranquilIT', target='https://doc.wapt.fr'))

        if os.path.islink(self.current_user+u'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Console WAPT.lnk'):
            os.remove(self.current_user+u'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Console WAPT.lnk')
        self.assertEqual(self.current_user+u'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Console WAPT.lnk',create_user_programs_menu_shortcut('Console WAPT', target=makepath('c:/wapt','waptconsole.exe')))


    def test_remove_user_programs_menu_shortcut(self):
        if not os.path.islink(self.current_user+u'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Doc-TranquilIT.url'):
            create_user_programs_menu_shortcut('Doc-TranquilIT', target='https://doc.wapt.fr')
        self.assertEqual(None,remove_user_programs_menu_shortcut(self.current_user+u'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Doc-TranquilIT.url'))

    def test_remove_programs_menu_shortcut(self):
        if not os.path.islink(u'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Doc-TranquilIT.url'):
            create_programs_menu_shortcut('Doc-TranquilIT', target='https://doc.wapt.fr')
        self.assertEqual(None,remove_programs_menu_shortcut(u'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Doc-TranquilIT.url'))

    def test_remove_desktop_shortcut(self):
        if not os.path.islink(r'C:\Users\Public\Desktop\WAPT Console Management.lnk'):
            create_desktop_shortcut(r'WAPT Console Management',target=r'c:\wapt\waptconsole.exe')
        self.assertEqual(None,remove_programs_menu_shortcut(r'C:\Users\Public\Desktop\WAPT Console Management.lnk'))


    def test_remove_user_desktop_shortcut(self):
        if not os.path.islink(self.current_user+u'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Doc-TranquilIT.url'):
            create_user_desktop_shortcut('Doc-TranquilIT', target='https://doc.wapt.fr')
        self.assertEqual(None,remove_user_desktop_shortcut(self.current_user+u'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Doc-TranquilIT.url'))


    def test_wgets(self):
        data = wgets('https://wapt/ping')
        if "msg" in data:
            Request = u'work'
        self.assertEqual(u'work',Request)
        Request = u'Doesn\'t Work'
        data = wgets('https://wapt.tranquilit.local/ping',{'https':'https://srvproxy:8080'})
        if "msg" in data:
            Request = u'work'
        self.assertEqual(u'work',Request)


    def test_get_disk_free_space(self):
        self.assertEqual(psutil.disk_usage(".").free,get_disk_free_space('c:'))


    def test_wget(self):
        respath = wget('http://wapt.tranquil.it/wapt/tis-7zip_16.04-5_all.wapt','c:\\tmp\\test.wapt',proxies={'https':'https://srvproxy:8080'})
        self.assertEqual(True, os.stat(respath).st_size>10000)
        respath = wget('http://localhost:8088/runstatus','c:\\tmp\\test.json')
        self.assertEqual(True, os.stat(respath).st_size<10000)


    def test_filecopyto(self):
        if not os.path.isfile('c:/tmp/fc.test'):
            with open('c:/tmp/fc.test','wb') as f:
                f.write('test')
        if not os.path.isdir('c:/tmp/target'):
            os.mkdir('c:/tmp/target')
        if os.path.isfile('c:/tmp/target/fc.test'):
            os.unlink('c:/tmp/target/fc.test')
        filecopyto('c:/tmp/fc.test','c:/tmp/target')
        self.assertEqual(True,os.path.isfile('c:/tmp/target/fc.test'))


    def test_register_ext(self):
        if not os.path.isfile('c:/tmp/fc.test'):
            with open('c:/tmp/fc.test','wb') as f:
                f.write('test')
        register_ext(appname='TestExtension',fileext='.test',icon=r'c:\wapt\wapt.ico',shellopen=self.softTestExt)
        if ( run('c:/tmp/fc.test',timeout = 4)):
            res = True
        else:
            res = False
        self.assertEqual(True,res)


    def test_default_oncopy(self):
        if ('temptest' in os.listdir(r'c:\tmp')):
            shutil.rmtree(r'c:\tmp\temptest\\')
        os.makedirs(r'c:\tmp\temptest\test')
        if not os.path.isfile('c:/tmp/temptest/test/test.txt'):
            with open('c:/tmp/temptest/test/test.txt','wb') as f:
                f.write('test')
        self.assertEqual(True,default_oncopy('copie',r'c:\tmp\temptest\test\test.txt',r'c:\tmp'))


    def test_default_overwrite_older(self):
        if not os.path.isfile('c:/tmp/testoverride.txt'):
            with open('c:/tmp/testoverride.txt','wb') as f:
                f.write('test')
        time.sleep(2)
        if not os.path.isfile('c:/tmp/testoverride2.txt'):
            with open('c:/tmp/testoverride2.txt','wb') as f:
                f.write('test')
        self.assertEqual(True,default_overwrite_older(r'c:/tmp/testoverride2.txt',r'c:/tmp/testoverride.txt'))
        os.remove('c:/tmp/testoverride2.txt')
        os.remove('c:/tmp/testoverride.txt')
        if not os.path.isfile('c:/tmp/testoverride.txt'):
            with open('c:/tmp/testoverride.txt','wb') as f:
                f.write('test')
        time.sleep(2)
        if not os.path.isfile('c:/tmp/testoverride2.txt'):
            with open('c:/tmp/testoverride2.txt','wb') as f:
                f.write('test')
        self.assertEqual(False,default_overwrite_older(r'c:/tmp/testoverride.txt',r'c:/tmp/testoverride2.txt'))
        os.remove('c:/tmp/testoverride2.txt')
        os.remove('c:/tmp/testoverride.txt')


    def test_dir_is_empty(self):
        if os.path.isdir(r'c:\tmp\1\\'):
            shutil.rmtree(r'c:\tmp\1\\')
        os.mkdir(r'c:\tmp\1\\')
        self.assertEqual(True,dir_is_empty(r'c:\tmp\1\\'))
        shutil.rmtree(r'c:\tmp\1\\')


    def test_all_files(self):
        if os.path.isdir(r'c:\tmp\1\\'):
            shutil.rmtree(r'c:\tmp\1\\')
        os.mkdir(r'c:\tmp\1\\')
        if not os.path.isfile('c:/tmp/1/texte.txt'):
            with open('c:/tmp/1/texte.txt','wb') as f:
                f.write('test')
        if not os.path.isfile('c:/tmp/1/texte.bat'):
            with open('c:/tmp/1/texte.bat','wb') as f:
                f.write('test')
        self.assertEqual(['c:\\tmp\\1\\texte.bat', 'c:\\tmp\\1\\texte.txt'],all_files(r'c:\tmp\1\\'))
        self.assertEqual(['c:\\tmp\\1\\texte.txt'],all_files(r'c:\tmp\1\\',pattern='*.txt'))
        shutil.rmtree(r'c:\tmp\1\\')


    def test_copytree2(self):##a améliorer
        copytree2(r'c:\tranquilit\wapt\tests',r'c:\tranquilit\wapt\tests2')
        self.assertEqual(True,isdir(r'c:\tranquilit\wapt\tests2'))
        remove_tree(r'c:\tranquilit\wapt\tests2')
        self.assertEqual(False,isdir(r'c:\tranquilit\wapt\tests2'))


    def test_run(self):## a appronfondir
        self.assertIn(u'test\r\n',run('echo test'))
        try:
            run(r'ping /t 127.0.0.1',timeout=3)
        except TimeoutExpired:
            time = u'out'
            self.assertEqual(u'out',time)
        out = []
        pids = []
        def getlines(line):
            out.append(line)
        run(r'dir /B c:\windows\explorer.exe',pidlist=pids,on_write=getlines)
        self.assertEqual(['explorer.exe\r\n'],out)


    def test_run_notfatal(self):
        self.assertEqual('',run_notfatal('fakeprogram.exe'))
        self.assertIn(u'\r\n',run_notfatal(self.softTestExt))


    def test_shell_launch(self):
        self.assertEqual(None,shell_launch('c:/tmp/fc.test'))


    def test_isrunning(self):
        self.assertEqual(True,isrunning('explorer'))
        self.assertEqual(False,isrunning('fakeprog'))


    def test_killalltasks(self):
        if not isrunning('notepad.exe'):
            os.system('start notepad.exe')
        self.assertEqual(None,killalltasks('notepad.exe'))

    def test_killtree(self):
        while isrunning('notepad.exe'):
            proc = psutil.Popen('notepad.exe')
            os.system('Taskkill /PID '+proc.pid+' /F')
        proc = psutil.Popen('notepad.exe')
        self.assertEqual(None,killtree(proc.pid))


    def test_findprocess(self):
        if not isrunning('notepad.exe'):
            os.system('start notepad.exe')
        result = []
        for p in psutil.process_iter():
            try:
                if p.name().lower() in ['notepad','notepad.exe']:
                    result.append(p)
            except (psutil.AccessDenied,psutil.NoSuchProcess):
                pass

        self.assertEqual(result,find_processes('notepad.exe'))


    def test_programfiles64(self):
        self.assertEqual('C:\\Program Files',programfiles64)


    def test_programfiles(self):
        self.assertEqual('C:\\Program Files',programfiles)


    def test_programfiles32(self):
        self.assertEqual('C:\\Program Files (x86)',programfiles32)


    def test_iswin64(self):
        self.assertEqual(True,iswin64())


    def test_get_computername(self):
        self.assertEqual(self.computername,get_computername())


    def test_get_hostname(self):
        self.assertEqual(self.hostname,get_hostname())


    def test_get_domain_fromregistry(self):
        self.assertEqual(self.domain_name,get_domain_fromregistry())


    def test_get_loggedinusers(self):
        self.assertEqual([u'administrator'],get_loggedinusers())


    def test_registered_organization(self):
        self.assertEqual(self.registered_organization,registered_organization())


    def test_reg_openkey_noredir(self):
        res = False
        with reg_openkey_noredir(HKEY_LOCAL_MACHINE,u"software\\microsoft\\windows\\currentversion") as key:
             res = True
        self.assertEqual(True,res)

    def test_reg_closekey(self):
        key = reg_openkey_noredir(HKEY_LOCAL_MACHINE,u"software\\microsoft\\windows\\currentversion")
        res = False
        reg_closekey(key)
        if key.handle == 0 :
            res = True
        self.assertEqual(True,res)

    def test_reg_key_exists(self):
        res= False
        try:
          if reg_key_exists(HKEY_LOCAL_MACHINE,makepath('SOFTWARE','wow6432Node','Microsoft','Notepad')):
            res = True
        except :
            res = False
        self.assertEqual(True,res)

    def test_reg_value_exists(self):
        res = False
        try:
            if reg_value_exists(HKEY_LOCAL_MACHINE,makepath('SOFTWARE','Microsoft','Windows','CurrentVersion'),'CommonFilesDir'):
                res = True
        except :
            res = False
        self.assertEqual(True,res)


    def test_reg_getvalue(self):
        os.system
        with reg_openkey_noredir(HKEY_LOCAL_MACHINE,u"software\\microsoft\\windows\\currentversion") as zkey:
            path = reg_getvalue(zkey,r'ProgramFilesPath')
        self.assertEqual(r'%ProgramFiles%',path)


    def test_reg_setvalue(self):
        if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle'):
            os.system(r'REG ADD HKLM\Software\MaCle /v Path /t REG_EXPAND_SZ /d test')
        with reg_openkey_noredir(HKEY_LOCAL_MACHINE,u"software\\MaCle",KEY_WRITE) as key:
            reg_setvalue(key,u'Path','testing')
        with reg_openkey_noredir(HKEY_LOCAL_MACHINE,u"software\\MaCle") as zkey:
            path = reg_getvalue(zkey,r'Path')
        self.assertEqual('testing',path)


    def test_reg_delvalue(self):
        res = False
        with disable_file_system_redirection():
            if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle'):
                os.system(r'REG ADD HKLM\Software\MaCle /v Path /t REG_EXPAND_SZ /d test')
            with reg_openkey_noredir(HKEY_LOCAL_MACHINE,u"software\\MaCle",KEY_WRITE) as key:
                self.assertEqual(True,reg_delvalue(key,'Path'))

    def test_reg_enum_subkeys(self):
        with disable_file_system_redirection():
            if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle'):
                os.system (r'REG ADD HKLM\Software\MaCle /v Path /t REG_EXPAND_SZ /d test')
            if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle\\MasousCle'):
                os.system(r'REG ADD HKLM\Software\MaCle\MasousCle /v Path /t REG_EXPAND_SZ /d test')
        list_of_subkey =list(reg_enum_subkeys(reg_openkey_noredir(HKEY_LOCAL_MACHINE,u'Software\\MaCle',KEY_READ)))
        self.assertEqual([u'MasousCle'],list_of_subkey)


    def test_reg_enum_values(self):
        with disable_file_system_redirection():
            if reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle'):
                os.system (r'REG DELETE HKLM\Software\MaCle /f')
            if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle'):
                os.system (r'REG ADD HKLM\Software\MaCle /v Path /t REG_EXPAND_SZ /d test')
            if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle\\MasousCle'):
                os.system(r'REG ADD HKLM\Software\MaCle\MasousCle /v Path /t REG_EXPAND_SZ /d test')
        list_of_values =list(reg_enum_values(reg_openkey_noredir(HKEY_LOCAL_MACHINE,u'Software\\MaCle',KEY_READ)))
        self.assertEqual([(u'Path', u'test', 2)],list_of_values)


    def test_registry_setstring(self):
        with disable_file_system_redirection():
            if reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle'):
                os.system (r'REG DELETE HKLM\Software\MaCle /f')
            if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle'):
                os.system (r'REG ADD HKLM\Software\MaCle /v Path /t REG_EXPAND_SZ /d test')
            if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle\\MasousCle'):
                os.system(r'REG ADD HKLM\Software\MaCle\MasousCle /v Path /t REG_EXPAND_SZ /d test')
        registry_setstring(HKEY_LOCAL_MACHINE,u'Software\\MaCle','Path','mystring')
        list_of_string =list(reg_enum_values(reg_openkey_noredir(HKEY_LOCAL_MACHINE,u'Software\\MaCle',KEY_READ)))
        self.assertEqual([(u'Path', u'mystring', 1)],list_of_string)

    def test_registry_readstring(self):
        with disable_file_system_redirection():
            if reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle'):
                os.system (r'REG DELETE HKLM\Software\MaCle /f')
            if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle'):
                os.system (r'REG ADD HKLM\Software\MaCle /v Path /t REG_EXPAND_SZ /d test')
            if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle\\MasousCle'):
                os.system(r'REG ADD HKLM\Software\MaCle\MasousCle /v Path /t REG_EXPAND_SZ /d test')
        list_of_string = registry_readstring(HKEY_LOCAL_MACHINE,r'SYSTEM/CurrentControlSet/services/Tcpip/Parameters','Hostname')
        self.assertEqual(self.computername,list_of_string)


    def test_registry_set(self):
        with disable_file_system_redirection():
            if reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle'):
                os.system (r'REG DELETE HKLM\Software\MaCle /f')
            if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle'):
                os.system (r'REG ADD HKLM\Software\MaCle /v Path /t REG_EXPAND_SZ /d test')
            if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle\\MasousCle'):
                os.system(r'REG ADD HKLM\Software\MaCle\MasousCle /v Path /t REG_EXPAND_SZ /d test')
        registry_set(HKEY_LOCAL_MACHINE,u'Software\\MaCle','test','test')
        res = False
        try:
            if reg_value_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle','test'):
                res = True
        except :
            res = False
        self.assertEqual(True,res)


    def test_registry_delete(self):
        with disable_file_system_redirection():
            if reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle'):
                os.system (r'REG DELETE HKLM\Software\MaCle /f')
            if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle'):
                os.system (r'REG ADD HKLM\Software\MaCle /v Path /t REG_EXPAND_SZ /d test')
            if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle\\MasousCle'):
                os.system(r'REG ADD HKLM\Software\MaCle\MasousCle /v Path /t REG_EXPAND_SZ /d test')
            registry_set(HKEY_LOCAL_MACHINE,u'Software\\MaCle','test_t','test-t')
        registry_delete(HKEY_LOCAL_MACHINE,u'Software\\MaCle','test_t')
        res = False
        try:
            if not reg_value_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle','test_t'):
                res = True
        except :
            res = False
        self.assertEqual(True,res)


    def test_registry_deletekey(self):
        with disable_file_system_redirection():
            if reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle'):
                os.system (r'REG DELETE HKLM\Software\MaCle /f')
            if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle'):
                os.system (r'REG ADD HKLM\Software\MaCle /v Path /t REG_EXPAND_SZ /d test')
            if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle\\MasousCle'):
                os.system(r'REG ADD HKLM\Software\MaCle\MasousCle /v Path /t REG_EXPAND_SZ /d test')
            registry_deletekey(HKEY_LOCAL_MACHINE,u'Software\\MaCle','MasousCle')
        res = False
        try:
            if not reg_key_exists(HKEY_LOCAL_MACHINE,u'Software\\MaCle\\MasousCle'):
                res = True
        except :
            res = False
        self.assertEqual(True,res)


    def test_inifile_hasoption(self):
        fichier = open(self.test_dir+"testFile.ini", "w+")
        fichier.write(" ")
        fichier.close()

        inifile_writestring(self.test_dir+"testFile.ini",'global','version','1.1.2')
        self.assertEqual(True,inifile_hasoption(self.test_dir+"testFile.ini",'global','version'))
        self.assertEqual(False,inifile_hasoption(self.test_dir+"testFile.ini",'global','dontexist'))

        os.remove(self.test_dir+"testFile.ini")

    def test_inifile_hassection(self):
        fichier = open(self.test_dir+"testFile.ini", "w+")
        fichier.write(" ")
        fichier.close()

        inifile_writestring(self.test_dir+"testFile.ini",'global','version','1.1.2')
        self.assertEqual(True,inifile_hassection(self.test_dir+"testFile.ini",'global'))
        self.assertEqual(False,inifile_hassection(self.test_dir+"testFile.ini",'dontexist'))

        os.remove(self.test_dir+"testFile.ini")

    def test_inifile_deleteoption(self):
        fichier = open(self.test_dir+"testFile.ini", "w+")
        fichier.write(" ")
        fichier.close()

        inifile_writestring(self.test_dir+"testFile.ini",'global','version','1.1.2')
        self.assertEqual(True,inifile_deleteoption(self.test_dir+"testFile.ini",'global','version'))
        self.assertEqual(False,inifile_deleteoption(self.test_dir+"testFile.ini",'global','version'))

        os.remove(self.test_dir+"testFile.ini")

    def test_inifile_deletesection(self):
        fichier = open(self.test_dir+"testFile.ini", "w+")
        fichier.write(" ")
        fichier.close()

        inifile_writestring(self.test_dir+"testFile.ini",'global','version','1.1.2')
        self.assertEqual(True,inifile_deletesection(self.test_dir+"testFile.ini",'global'))
        self.assertEqual(False,inifile_deletesection(self.test_dir+"testFile.ini",'global'))

        os.remove(self.test_dir+"testFile.ini")

    def test_inifile_readstring(self):
        fichier = open(self.test_dir+"testFile.ini", "w+")
        fichier.write(" ")
        fichier.close()

        inifile_writestring(self.test_dir+"testFile.ini",'global','version','1.1.2')
        self.assertEqual('1.1.2',inifile_readstring(self.test_dir+"testFile.ini",'global','version'))
        self.assertEqual(None,inifile_readstring(self.test_dir+"testFile.ini",'global','dontexist'))

        os.remove(self.test_dir+"testFile.ini")

    def test_inifile_writestring(self):
        inifile_writestring(self.emplacementTest_ini,'global','version','1.1.1')
        self.assertEqual('1.1.1',inifile_readstring(self.emplacementTest_ini,'global','version'))


    def test_disable_file_system_redirection(self):
        with disable_file_system_redirection():
            self.assertEqual(u'C:\\Program Files (x86)',winshell.get_path(shellcon.CSIDL_PROGRAM_FILES))


    def test_system32(self):
        self.assertEqual(r'C:\Windows\system32',system32())


    def test_set_file_visible(self):

        fichier = open(self.test_dir+"testFile.txt", "w+")
        fichier.write("Test")
        fichier.close()

        set_file_visible(self.test_dir+"testFile.txt")
        self.assertEqual(32,ctypes.windll.kernel32.GetFileAttributesW(unicode(self.test_dir+"testFile.txt")))
        if (ctypes.windll.kernel32.GetFileAttributesW(unicode(self.test_dir+"testFile.txt"))==34):
            ret = ctypes.windll.kernel32.SetFileAttributesW(unicode(self.emplacementTest_ini),32  & ~FILE_ATTRIBUTE_HIDDEN)
        os.remove(self.test_dir+"testFile.txt")

    def test_set_file_hidden(self):

        fichier = open(self.test_dir+"testFile.txt", "w+")
        fichier.write("Test")
        fichier.close()

        set_file_hidden(self.test_dir+"testFile.txt")
        FILE_ATTRIBUTE_HIDDEN = 0x02
        self.assertEqual(34,ctypes.windll.kernel32.GetFileAttributesW(unicode(self.test_dir+"testFile.txt")))
        if (ctypes.windll.kernel32.GetFileAttributesW(unicode(self.emplacementTest_ini))==34):
            ret = ctypes.windll.kernel32.SetFileAttributesW(unicode(self.emplacementTest_ini),32  & ~FILE_ATTRIBUTE_HIDDEN)
        os.remove(self.test_dir+"testFile.txt")

    def test_replace_at_next_reboot(self):
        fichier = open(self.test_dir+"testFile.txt", "w+")
        fichier.write("Test")
        fichier.close()
        if reg_value_exists(HKEY_LOCAL_MACHINE,u'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\','PendingFileRenameOperations'):
            os.system(r'reg delete HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\ /v PendingFileRenameOperations')
        res = False
        replace_at_next_reboot(self.test_dir+"testFile.txt",self.test_dir+"testFile2.txt")
        if reg_value_exists(HKEY_LOCAL_MACHINE,u'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\','PendingFileRenameOperations'):
            res = True
        self.assertEqual(True,res)
        os.system(r'reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\\" /v PendingFileRenameOperations /f')
        os.remove(self.test_dir+"testFile.txt")


    def test_at_next_reboot(self):
        fichier = open(self.test_dir+"testFile.txt", "w+")
        fichier.write("Test")
        fichier.close()
        if reg_value_exists(HKEY_LOCAL_MACHINE,u'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\','PendingFileRenameOperations'):
            os.system(r'reg delete HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\ /v PendingFileRenameOperations')
        res = False
        delete_at_next_reboot(self.test_dir+"testFile.txt")
        if reg_value_exists(HKEY_LOCAL_MACHINE,u'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\','PendingFileRenameOperations'):
            res = True
        self.assertEqual(True,res)
        os.system(r'reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\\" /v PendingFileRenameOperations /f')
        os.remove(self.test_dir+"testFile.txt")


    def test_add_shutdown_script(self):
        index = add_shutdown_script(r'c:\wapt\wapt-get.exe','update')
        res =[0,None]
        self.assertEqual(True,index in res)


    def test_remove_shutdown_script(self):
        index = remove_shutdown_script(r'c:\wapt\wapt-get.exe','update')
        self.assertEqual(0,index)


    def test_shutdown_scripts_ui_visible(self):
        res = True
        try :
            shutdown_scripts_ui_visible(None)
            shutdown_scripts_ui_visible(False)
            shutdown_scripts_ui_visible(True)
        except :
            res = False
        self.assertEqual(True,res)


    def test_uninstall_cmd(self):
         old_softs = installed_softwares('mozilla firefox')
         for soft in old_softs:
            self.assertEqual([u'C:\\Program Files (x86)\\Mozilla Firefox\\uninstall\\helper.exe', '/S'],uninstall_cmd(soft['key']))


    def test_uninstall_key_exists(self):
        self.assertEqual(False,uninstall_key_exists('isdhfsdihfpsdhfpshdfposdhf'))


    def test_installed_softwares(self):
        softs = installed_softwares('python')
        if softs:
            for soft in softs:
                self.assertEqual(['MsiExec.exe', '/norestart', '/q', '/X'+self.python_key+''],uninstall_cmd(soft['key']))


    def test_install_location(self):
        self.assertEqual(u'',install_location(self.python_key))


    def test_currentdate(self):
        self.assertEqual(time.strftime('%Y%m%d'),currentdate())


    def test_currentdatetime(self):
        self.assertEqual(time.strftime('%Y%m%d-%H%M%S'),currentdatetime())


    def test_register_uninstall(self):
        register_uninstall('{ffffffffffffffffffff}','uninstallme')
        res = False
        with disable_file_system_redirection():
            if reg_key_exists(HKEY_LOCAL_MACHINE,r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{ffffffffffffffffffff}'):
                res = True
                os.system (r'REG DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{ffffffffffffffffffff} /f')
        self.assertEqual(True,res)


    def test_register_windows_uninstall(self):
        with disable_file_system_redirection():
            if reg_key_exists(HKEY_LOCAL_MACHINE,r'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\testpack'):
                os.system (r'REG DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\testpack /f')
        class package_entry:
            def __init__(self):
                self.package = 'testpack'
                self.description= 'a totally fake package'
                self.version= '666'
                self.maintainer = 'natas'
        mypack = package_entry()
        register_windows_uninstall(mypack)
        res = False
        with disable_file_system_redirection():
            if reg_key_exists(HKEY_LOCAL_MACHINE,r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\testpack'):
                res = True
                os.system (r'REG DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\testpack /f')
        self.assertEqual(True,res)



    def test_unregister_uninstall(self):
        with disable_file_system_redirection():
            if reg_key_exists(HKEY_LOCAL_MACHINE,r'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\testpack'):
                os.system (r'REG DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\testpack /f')
        class package_entry:
            def __init__(self):
                self.package = 'testpack'
                self.description= 'a totally fake package'
                self.version= '666'
                self.maintainer = 'natas'
        mypack = package_entry()
        register_windows_uninstall(mypack)
        unregister_uninstall(mypack.package)
        res = False
        with disable_file_system_redirection():
            if not reg_key_exists(HKEY_LOCAL_MACHINE,r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\testpack'):
                res = True
                os.system (r'REG DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\testpack /f')
        self.assertEqual(True,res)


    def test_networking(self):
        self.assertAlmostEqual(self.networkingResult,networking())


    def test_dmi_info(self):
        dmi = dmi_info()
        self.assertEqual(True,'UUID' in dmi['System_Information'])
        self.assertEqual(True, 'Product_Name' in dmi['System_Information'])


    def test_win_startup_info(self):
        self.assertEqual(True,u'common_startup' in json.dumps(win_startup_info()))


    def test_wmi_info(self):
        self.assertEqual(True,u'BIOSVersion' in json.dumps(wmi_info()))


    def test_wmi_info_basic(self):
        r = wmi_info_basic()
        self.assertEqual(True,'System_Information' in r,)


    def test_set_computer_description(self):
        set_computer_description(u'test')
        for win32_os in wmi.WMI().Win32_OperatingSystem():
            desc = win32_os.Description
        self.assertEqual('test',desc)

##fonctionne pas sur windows non activé
   # def test_critical_system_pending_updates(self):
  #      self.assertEqual([],critical_system_pending_updates())#the os must be up to date

    def test_get_default_gateways(self):
        self.assertEqual(self.gateway,get_default_gateways())


    def test_host_info(self):
         hi = host_info()
         self.assertEqual(True,'computer_fqdn' in hi and 'connected_ips' in hi and 'computer_name' in hi and 'mac' in hi)


    def test_wua_agent_version(self):
        self.assertEqual(get_file_properties(makepath(system32(),'wuapi.dll'))['ProductVersion'],wua_agent_version())


    def test_get_profile_path(self):
        self.assertEqual(self.profilPathFromSid,get_profile_path('S-1-5-19'))#get the profile path for localService


    def test_get_user_from_profpath(self):
        self.assertEqual(self.userFromProPath,get_user_from_profpath('S-1-5-19'))


    def test_get_user_from_sid(self):
        self.assertEqual(u'AUTORITE NT\\SERVICE LOCAL',get_user_from_sid('S-1-5-19'))


    def test_get_profiles_users(self):
        self.assertEqual(self.ListeDesUtilisateur,get_profiles_users())


    def test_get_last_logged_on_user(self):
        with disable_file_system_redirection():
            self.assertEqual(registry_readstring(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI','LastLoggedOnUser',''),get_last_logged_on_user())


    def test_local_drives(self):
        drives=local_drives()
        self.assertEqual(True,u'C' in drives)


    def test_get_file_properties(self):
        xp = get_file_properties(r'c:\windows\explorer.exe')
        self.assertEqual(True,'FileVersion' in xp and 'FileDescription' in xp)


    def test_get_msi_properties(self):
        zprop = get_msi_properties(r'C:\tranquilit\wapt\tests\7z920.msi')
        self.assertEqual(True,'ProductVersion' in zprop and 'ProductCode' in zprop and 'ProductName' in zprop)


    def test_local_users(self):
        users = local_users()
        self.assertEqual(True,u'Invit\xe9' in users)


    def test_local_groups(self):
        groups = local_groups()
        self.assertEqual(True,u'Utilisateurs' in groups)


    def test_local_admins(self):
        admins = local_admins()
        self.assertEqual(self.AdminLocal,admins)

    def test_local_group_memberships(self):
        self.assertEqual(self.local_group,local_group_memberships(self.user))


    def test_local_group_members(self):
        members = local_group_members('Administrateurs')
        self.assertEqual(self.members_groups_administrateur,members)


    def test_remove_file(self):
        fichier = open(self.test_dir+"removeme.txt", "w")
        fichier.write("Test")
        fichier.close()
        self.assertEqual(None,remove_file(self.test_dir))


    def test_remove_tree(self):
        res = False
        try:
            path = self.test_dir+'testrmtree\subdir'
            if (os.path.isdir(path)):
                shutil.rmtree(self.test_dir+'testrmtree')
            os.makedirs(path)
            fichier = open(path+"removeme.txt", "w")
            fichier.write("Test")
            fichier.close()
            remove_tree(self.test_dir+'testrmtree')
            res = True
        except:
            res = False

        self.assertEqual(res,True)


    def test_makepath(self):
        self.assertEqual('C:\\Program Files',makepath('c:',programfiles))


    def test_service_installed(self):
        self.assertEqual(True,service_installed('WAPTService'))

    def test_service_start(self):
        if 4 in win32serviceutil.QueryServiceStatus('WAPTService'):
            os.system('Net Stop WAPTService')

        service_start('WAPTService')
        self.assertEqual((16, 4, 7, 0, 0, 0, 0),win32serviceutil.QueryServiceStatus('WAPTService'))
        #check if the service is started and if service_start get an error and start it

        if 1 in win32serviceutil.QueryServiceStatus('WAPTService'):
            os.system('Net Start WAPTService')


    def test_service_stop(self):
        if 1 in win32serviceutil.QueryServiceStatus('WAPTService'):
            os.system('Net Start WAPTService')

        service_stop('WAPTService')
        self.assertEqual(True,1 in win32serviceutil.QueryServiceStatus('WAPTService'))
        #check if the service is started and if service_start get an error and start it

        if 1 in win32serviceutil.QueryServiceStatus('WAPTService'):
            os.system('Net Start WAPTService')


    def test_service_restart(self):
        if 1 in win32serviceutil.QueryServiceStatus('WAPTService'):
            os.system('Net Start WAPTService')

        service_restart('WAPTService')
        self.assertEqual(True,4 in win32serviceutil.QueryServiceStatus('WAPTService'))
        #check if the service is started and if service_start get an error and start it

        if 1 in win32serviceutil.QueryServiceStatus('WAPTService'):
            os.system('Net Start WAPTService')


    def test_service_is_running (self):
        if 1 in win32serviceutil.QueryServiceStatus('WAPTService'):
            os.system('Net Start WAPTService')

        state = service_is_running('WAPTService')
        self.assertEqual(True,state)


    def test_service_is_stopped(self):
        if 4 in win32serviceutil.QueryServiceStatus('WAPTService'):
            os.system('Net Stop WAPTService')

        state = service_is_stopped('WAPTService')
        self.assertEqual(True,state)

        if 1 in win32serviceutil.QueryServiceStatus('WAPTService'):
            os.system('Net Start WAPTService')

    def test_user_appdata(self):
        self.assertEqual(self.current_user+'\\AppData\\Roaming',user_appdata())


    def test_user_local_appdata(self):
        self.assertEqual(self.current_user+'\\AppData\\Local',user_local_appdata())


    def test_mkdirs(self):
        path = self.test_dir+'testrmtree\subdir'
        if (os.path.isdir(path)):
            shutil.rmtree(self.test_dir+'testrmtree')
        mkdirs(path)
        res = False
        if (os.path.isdir(path)):
            res = True
            shutil.rmtree(self.test_dir+'testrmtree')
        self.assertEqual(True,res)

    def test_user_desktop(self):
        self.assertEqual(self.current_user+'\\Desktop',user_desktop())


    def test_common_desktop(self):
        self.assertEqual(u'C:\\Users\\Public\\Desktop',common_desktop())


    def test_add_to_system_path(self):
        with reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',sam=KEY_READ | KEY_WRITE) as key:
            old = reg_getvalue(key,'Path')
        add_to_system_path(self.test_dir)
        with reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',sam=KEY_READ | KEY_WRITE) as key:
            value_of_path = reg_getvalue(key,'Path').split(';')
            self.assertEqual(True,self.test_dir in value_of_path)
            reg_setvalue(key,"Path",old)

    def test_remove_from_system_path(self):
        with reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',sam=KEY_READ | KEY_WRITE) as key:
            old = reg_getvalue(key,'Path')
        add_to_system_path(self.test_dir)
        remove_from_system_path(self.test_dir)
        with reg_openkey_noredir(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',sam=KEY_READ | KEY_WRITE) as key:
            value_of_path = reg_getvalue(key,'Path').split(';')
            self.assertEqual(True,self.test_dir not in value_of_path)
            reg_setvalue(key,"Path",old)


    def test_set_environ_variable(self):
        set_environ_variable('WAPT_HOME','c:\\wapt')
        self.assertEqual('c:\\wapt',os.environ['WAPT_HOME'])
        unset_environ_variable('WAPT_HOME')


    def test_unset_environ_variable(self):
        set_environ_variable('WAPT_HOME','c:\\wapt')
        unset_environ_variable('WAPT_HOME')
        res = False
        if not reg_value_exists(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment','WAPT_HOME'):
            res = True
        self.assertEqual(True,res)


    def test_windows_version(self):
        self.assertEqual(self.windows_version,windows_version())


    def test_get_current_user(self):
        self.assertEqual(self.logged_user,get_current_user())


    def test_get_language(self):
        self.assertEqual(self.os_language,get_language())


    def test_get_appath(self):
        self.assertEqual(u'c:\\wapt\\wapt-get.exe',get_appath('wapt-get.exe'))
        self.assertEqual(u'C:\\Program Files\\Internet Explorer\\IEXPLORE.EXE',get_appath('IEXPLORE.exe'))


    def test_get_installer_defaults(self):
        ExeInstallerInfo = get_installer_defaults(r'c:\tranquilit\wapt\tests\Firefox Setup Stub 53.0.exe')
        MsiInstallerInfo = get_installer_defaults(r'c:\tranquilit\wapt\tests\7z920.msi')
        self.assertEqual(self.ExeInstallerInfoDefaultValue,ExeInstallerInfo)
        self.assertEqual(self.MsiInstallerInfoDefaultValue,MsiInstallerInfo)


    def test_getsilentflags(self):
        self.assertEqual('/q /norestart',getsilentflags(r'C:\tranquilit\wapt\tests\7z920.msi'))


    def test_need_install(self):
        #software key = python
        def verspython(key):
                return key['name'].replace('Python ','')


        self.assertEqual(True,need_install(None,min_version=self.version_python,force=True,get_version=verspython))#test paramètre key

        self.assertEqual(True,need_install(self.python_key,min_version=self.version_python,force=True,get_version=verspython))#Test paramètre force

        self.assertEqual(False,need_install(self.python_key,min_version=None,force=False,get_version=verspython))#test paramètre min version

        self.assertEqual(True,need_install(self.python_key,min_version=self.version_python,force=False,get_version=verspython))#test param get_version

        self.assertEqual(True,need_install(self.python_key,min_version='99',force=False,get_version=None))#test param min_version

        self.assertEqual(False,need_install(self.python_key,min_version=self.version_python,force=False,get_version=verspython))#test param min_version


    def test_install_msi_if_needed(self):
        try:
            run(uninstall_cmd(r'{23170F69-40C1-2701-0920-000001000000}'))
        except:
            print()
        self.assertEqual(None,install_msi_if_needed(r'C:\tranquilit\wapt\tests\7z920.msi'))


    def test_install_exe_if_needed(self):
        try:
            run(uninstall_cmd(r'VLC media player'))
        except:
            print()
        self.assertEqual(None, install_exe_if_needed(r'C:\tranquilit\wapt\tests\vlc-2.2.4-win32.exe'))



    def test_installed_windows_updates(self):
        InstalledUpdate = installed_windows_updates()
        self.assertIs(type(InstalledUpdate),list)

    def test_local_desktops(self):
        self.assertEqual(True,u'C:\\Windows\\ServiceProfiles\\LocalService\\Desktop' in local_desktops())


    def test_local_desktops(self):
        self.assertEqual(True,u'C:\\Windows\\ServiceProfiles\\LocalService' in local_users_profiles())


    def test_run_powershell(self):
        retourPS =run_powershell('Get-Location')
        self.assertIs(type(retourPS),dict)
        self.assertEqual(4,len(retourPS))


    def test_isodate2datetime(self):
        self.assertEqual(datetime.datetime.now().isoformat(),datetime2isodate())


    def test_httpdatetime2isodate(self):
        last_modified = requests.head('https://wapt/wapt/Packages',headers={'cache-control':'no-cache','pragma':'no-cache'},verify=False).headers['Last-Modified']
        self.assertEqual(19,len(httpdatetime2isodate(last_modified)))


    def test_isodate2datetime(self):
        #could be better test but don't see how to do
        date = datetime.datetime.now()
        test = datetime.datetime.strptime(date.isoformat().split('.')[0] , "%Y-%m-%dT%H:%M:%S")
        self.assertEqual(test,isodate2datetime(date.isoformat()))


    def test_time2display(self):
        date = datetime.datetime.now()
        self.assertEqual(date.strftime("%Y-%m-%d %H:%M"),time2display(date))

    def test_hours_minutes(self):
        self.assertEqual(None, hours_minutes(None))
        self.assertEqual('06:00',hours_minutes(6))


    def test_fileisodate(self):
        filename = r'c:\tranquilit\wapt\tests\mustremove_usedfortest.txt'
        file_date =  datetime.datetime.fromtimestamp(os.stat(filename).st_mtime).isoformat()
        self.assertEqual(file_date,fileisodate(filename))


    def test_dateof(self):
        date = datetime.datetime.now()
        res=date.replace(hour=0,minute=0,second=0,microsecond=0)
        self.assertEqual(res,dateof(date))

    #can't be tested
    #def test_error(self):
     #   self.assertEqual(True,'Fatal error : test' in error('test'))

    def test_create_user(self):
        res = []
        if u'unittest' in local_users():
            delete_user('unittest')

        #test 1 minimum of parameter
        create_user('unittest','MyAmazingTisPass')
        if u'unittest' in local_users():
            res.append(True)
            delete_user('unittest')
        else:
            res.append(False)

        #test with an optionnal parameter
        create_user('unittest','MyAmazingTisPass','the little user')
        if u'unittest' in local_users():
            res.append(True)
            delete_user('unittest')
        else:
            res.append(False)
        #test with another optionnal parameter
        create_user('unittest','MyAmazingTisPass',None,'some coment')
        if u'unittest' in local_users():
            res.append(True)
            delete_user('unittest')
        else:
            res.append(False)

        #test with two optionnal parameter
        create_user('unittest','MyAmazingTisPass','full name','with comment')
        if u'unittest' in local_users():
            res.append(True)
            delete_user('unittest')
        else:
            res.append(False)
        self.assertEqual(True, False not in res)


    def test_create_group(self):
        if u'toto' in local_groups():
            delete_group('toto')
        res = False
        create_group('toto')
        if u'toto' in local_groups():
            res = True
            delete_group('toto')
        self.assertEqual(True,res)


    def test_add_user_to_group(self):
        if u'unittest' not in local_users():
            create_user('unittest','MyAmazingTisPass','the little user')
        if u'toto' not in local_groups():
            create_group('toto')
        if u'unittest' in local_group_members('toto'):
            remove_user_from_group('unittest','toto')
        add_user_to_group(u'unittest',u'toto')
        res = False
        if  os.environ['COMPUTERNAME']+u'\\unittest' in local_group_members('toto'):
            res = True

        remove_user_from_group('unittest','toto')
        delete_user(u'unittest')
        delete_group('toto')

        self.assertEqual(True,res)


    def test_remove_user_from_group(self):
        if u'unittest' not in local_users():
            create_user('unittest','MyAmazingTisPass','the little user')
        if u'toto' not in local_groups():
            create_group('toto')
        if u'unittest' not in local_group_members('toto'):
            add_user_to_group('unittest','toto')

        remove_user_from_group('unittest','toto')

        res = False

        if u'unittest' not in local_group_members('toto'):
            res = True

        delete_user(u'unittest')
        delete_group('toto')

        self.assertEqual(True,res)

    def test_delete_group(self):
        if u'toto' not in local_groups():
            create_group('toto')
        delete_group('toto')
        res = False
        if u'toto' not in local_groups():
            res = True
        self.assertEqual(True,res)


    def test_delete_user(self):
        res = False
        if u'unittest' not in local_users():
            create_user('unittest','MyAmazingTisPass')
        delete_user('unittest')
        if u'unittest' not in local_users():
            res = True
        self.assertEqual(True,res)


    def test_register_dll(self):
        #todo add a real return code
        self.assertEqual(None,register_dll(r'C:\tranquilit\wapt\tests\midas.dll'))

    def test_unregister_dll(self):
        #todo add a real return code
        self.assertEqual(None,register_dll(r'C:\tranquilit\wapt\tests\midas.dll'))





if __name__ == "__main__":
    unittest.main()

