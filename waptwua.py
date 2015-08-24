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
__version__ = "1.3.1"


import datetime
import json
import logging
import os
import platform
import requests
import sys
import time
import win32com.client
import wmi
from optparse import OptionParser
from urlparse import urlparse
from setuphelpers import *


v = (sys.version_info.major, sys.version_info.minor)
if v != (2, 7):
    raise Exception('waptwua supports only Python 2.7, not %d.%d' % v)


#https://msdn.microsoft.com/en-us/library/ff357803%28v=vs.85%29.aspx
UpdateClassifications = {
 '28bc880e-0592-4cbf-8f95-c79b17911d5f': 'UpdateRollups',    # Ensemble de mises à jour
 'b54e7d24-7add-428f-8b75-90a396fa584f': 'FeaturePacks',     # feature packs
 'e6cf1350-c01b-414d-a61f-263d14d133b4': 'CriticalUpdates',  # Mises à jour critiques
 '0fa1201d-4330-4fa8-8ae9-b877473b6441': 'SecurityUpdates',  # Mises à jour de la sécurité
 'cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83': 'Updates',          # Mises à jour
 'e0789628-ce08-4437-be74-2495b842f43b': 'DefinitionUpdates',# Mises à jour de définitions
 'b4832bd8-e735-4761-8daf-37f882276dab': 'Tools',            # Outils
 'ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0': 'Drivers',          # Pilotes
 '68c5b0a3-d1a6-4553-ae49-01d3a7827828': 'ServicePacks',     # Services pack
 '434de588-ed14-48f5-8eed-a15e09a991f6': 'Connectors',       #
 '5c9376ab-8ce6-464a-b136-22113dd69801': 'Application',      #
 '9511d615-35b2-47bb-927f-f73d8e9260bb': 'Guidance',         #
 'e140075d-8433-45c3-ad87-e72345b36078': 'DeveloperKits',    #
 }

#https://msdn.microsoft.com/en-us/library/bb902472%28v=vs.85%29.aspx
DetectoIds = {
 '59653007-e2e9-4f71-8525-2ff588527978': 'x64-based systems',
 'aabd43ad-a183-4f0b-8eee-8dbbcd67687f': 'Itanium-based systems',
 '3e0afb10-a9fb-4c16-a60e-5790c3803437': 'x86-based systems',
}


Products = {
    "fdcfda10-5b1f-4e57-8298-c744257e30db":"Active Directory Rights Management Services Client 2.0",
    "57742761-615a-4e06-90bb-008394eaea47":"Active Directory",
    "5d6a452a-55ba-4e11-adac-85e180bda3d6":"Antigen for Exchange/SMTP",
    "116a3557-3847-4858-9f03-38e94b977456":"Antigen",
    "b86cf33d-92ac-43d2-886b-be8a12f81ee1":"Bing Bar",
    "2b496c37-f722-4e7b-8467-a7ad1e29e7c1":"Bing",
    "34aae785-2ae3-446d-b305-aec3770edcef":"BizTalk Server 2002",
    "86b9f801-b8ec-4d16-b334-08fba8567c17":"BizTalk Server 2006R2",
    "b61793e6-3539-4dc8-8160-df71054ea826":"BizTalk Server 2009",
    "61487ade-9a4e-47c9-baa5-f1595bcdc5c5":"BizTalk Server 2013",
    "ed036c16-1bd6-43ab-b546-87c080dfd819":"BizTalk Server",
    "83aed513-c42d-4f94-b4dc-f2670973902d":"CAPICOM",
    "236c566b-aaa6-482c-89a6-1e6c5cac6ed8":"Category for System Center Online Client",
    "ac615cb5-1c12-44be-a262-fab9cd8bf523":"Compute Cluster Pack",
    "eb658c03-7d9f-4bfa-8ef3-c113b7466e73":"Data Protection Manager 2006",
    "48ce8c86-6850-4f68-8e9d-7dc8535ced60":"Developer Tools, Runtimes, and Redistributables",
    "f76b7f51-b762-4fd0-a35c-e04f582acf42":"Dictionary Updates for Microsoft IMEs",
    "83a83e29-7d55-44a0-afed-aea164bc35e6":"Exchange 2000 Server",
    "3cf32f7c-d8ee-43f8-a0da-8b88a6f8af1a":"Exchange Server 2003",
    "ab62c5bd-5539-49f6-8aea-5a114dd42314":"Exchange Server 2007 and Above Anti-spam",
    "26bb6be1-37d1-4ca6-baee-ec00b2f7d0f1":"Exchange Server 2007",
    "9b135dd5-fc75-4609-a6ae-fb5d22333ef0":"Exchange Server 2010",
    "d3d7c7a6-3e2f-4029-85bf-b59796b82ce7":"Exchange Server 2013",
    "352f9494-d516-4b40-a21a-cd2416098982":"Exchange",
    "fa9ff215-cfe0-4d57-8640-c65f24e6d8e0":"Expression Design 1",
    "f3b1d39b-6871-4b51-8b8c-6eb556c8eee1":"Expression Design 2",
    "18a2cff8-9fd2-487e-ac3b-f490e6a01b2d":"Expression Design 3",
    "9119fae9-3fdd-4c06-bde7-2cbbe2cf3964":"Expression Design 4",
    "5108d510-e169-420c-9a4d-618bdb33c480":"Expression Media 2",
    "d8584b2b-3ac5-4201-91cb-caf6d240dc0b":"Expression Media V1",
    "a33f42ac-b33f-4fd2-80a8-78b3bfa6a142":"Expression Web 3",
    "3b1e1746-d99b-42d4-91fd-71d794f97a4d":"Expression Web 4",
    "ca9e8c72-81c4-11dc-8284-f47156d89593":"Expression",
    "d72155f3-8aa8-4bf7-9972-0a696875b74e":"Firewall Client for ISA Server",
    "0a487050-8b0f-4f81-b401-be4ceacd61cd":"Forefront Client Security",
    "a38c835c-2950-4e87-86cc-6911a52c34a3":"Forefront Endpoint Protection 2010",
    "86134b1c-cf56-4884-87bf-5c9fe9eb526f":"Forefront Identity Manager 2010 R2",
    "d7d32245-1064-4edf-bd09-0218cfb6a2da":"Forefront Identity Manager 2010",
    "a6432e15-a446-44af-8f96-0475c472aef6":"Forefront Protection Category",
    "f54d8a80-c7e1-476c-9995-3d6aee4bfb58":"Forefront Server Security Category",
    "84a54ea9-e574-457a-a750-17164c1d1679":"Forefront Threat Management Gateway, Definition Updates for HTTP Malware Inspection",
    "06bdf56c-1360-4bb9-8997-6d67b318467c":"Forefront TMG MBE",
    "59f07fb7-a6a1-4444-a9a9-fb4b80138c6d":"Forefront TMG",
    "f8c3c9a9-10de-4f09-bc16-5eb1b861fb4c":"Forefront",
    "f0474daf-de38-4b6e-9ad6-74922f6f539d":"Fotogalerie-Installation und -Upgrades",
    "d84d138e-8423-4102-b317-91b1339aa9c9":"HealthVault Connection Center Upgrades",
    "2e068336-2ead-427a-b80d-5b0fffded7e7":"HealthVault Connection Center",
    "0c6af366-17fb-4125-a441-be87992b953a":"Host Integration Server 2000",
    "784c9f6d-959a-433f-b7a3-b2ace1489a18":"Host Integration Server 2004",
    "eac7e88b-d8d4-4158-a828-c8fc1325a816":"Host Integration Server 2006",
    "42b678ae-2b57-4251-ae57-efbd35e7ae96":"Host Integration Server 2009",
    "3f3b071e-c4a6-4bcc-b6c1-27122b235949":"Host Integration Server 2010",
    "5964c9f1-8e72-4891-a03a-2aed1c4115d2":"HPC Pack 2008",
    "4f93eb69-8b97-4677-8de4-d3fca7ed10e6":"HPC Pack",
    "d123907b-ba63-40cb-a954-9b8a4481dded":"Installation von OneCare Family Safety",
    "b627a8ff-19cd-45f5-a938-32879dd90123":"Internet Security and Acceleration Server 2004",
    "2cdbfa44-e2cb-4455-b334-fce74ded8eda":"Internet Security and Acceleration Server 2006",
    "0580151d-fd22-4401-aa2b-ce1e3ae62bc9":"Internet Security and Acceleration Server",
    "5cc25303-143f-40f3-a2ff-803a1db69955":"Lokal veröffentlichte Pakete",
    "7c40e8c2-01ae-47f5-9af2-6e75a0582518":"Lokaler Herausgeber",
    "00b2d754-4512-4278-b50b-d073efb27f37":"Microsoft Application Virtualization 4.5",
    "c755e211-dc2b-45a7-be72-0bdc9015a63b":"Microsoft Application Virtualization 4.6",
    "1406b1b4-5441-408f-babc-9dcb5501f46f":"Microsoft Application Virtualization 5.0",
    "523a2448-8b6c-458b-9336-307e1df6d6a6":"Microsoft Application Virtualization",
    "7e903438-3690-4cf0-bc89-2fc34c26422b":"Microsoft BitLocker Administration and Monitoring v1",
    "c8c19432-f207-4d9d-ab10-764f3d29744d":"Microsoft BitLocker Administration and Monitoring",
    "587f7961-187a-4419-8972-318be1c318af":"Microsoft Dynamics CRM 2011 SHS",
    "2f3d1aba-2192-47b4-9c8d-87b41f693af4":"Microsoft Dynamics CRM 2011",
    "0dbc842c-730f-4361-8811-1b048f11c09b":"Microsoft Dynamics CRM",
    "e7ba9d21-4c88-4f88-94cb-a23488e59ebd":"Microsoft HealthVault",
    "5e870422-bd8f-4fd2-96d3-9c5d9aafda22":"Microsoft Lync 2010",
    "04d85ac2-c29f-4414-9cb6-5bcd6c059070":"Microsoft Lync Server 2010",
    "01ce995b-6e10-404b-8511-08142e6b814e":"Microsoft Lync Server 2013",
    "2af51aa0-509a-4b1d-9218-7e7508f05ec3":"Microsoft Lync Server and Microsoft Lync",
    "935c5617-d17a-37cc-dbcf-423e5beab8ea":"Microsoft Online Services",
    "b0247430-6f8d-4409-b39b-30de02286c71":"Microsoft Online Services-Anmelde-Assistent",
    "a8f50393-2e42-43d1-aaf0-92bec8b60775":"Microsoft Research AutoCollage 2008",
    "0f3412f2-3405-4d86-a0ff-0ede802227a8":"Microsoft Research AutoCollage",
    "b567e54e-648b-4ac6-9171-149a19a73da8":"Microsoft Security Essentials",
    "e9ece729-676d-4b57-b4d1-7e0ab0589707":"Microsoft SQL Server 2008 R2 - PowerPivot for Microsoft Excel 2010",
    "56750722-19b4-4449-a547-5b68f19eee38":"Microsoft SQL Server 2012",
    "fe324c6a-dac1-aca8-9916-db718e48fa3a":"Microsoft SQL Server PowerPivot for Excel",
    "a73eeffa-5729-48d4-8bf4-275132338629":"Microsoft StreamInsight V1.0",
    "4c1a298e-8dbd-5d8b-a52f-6c176fdd5904":"Microsoft StreamInsight",
    "5ef2c723-3e0b-4f87-b719-78b027e38087":"Microsoft System Center Data Protection Manager",
    "bf6a6018-83f0-45a6-b9bf-074a78ec9c82":"Microsoft System Center DPM 2010",
    "29fd8922-db9e-4a97-aa00-ca980376b738":"Microsoft System Center Virtual Machine Manager 2007",
    "7e5d0309-78dd-4f52-a756-0259f88b634b":"Microsoft System Center Virtual Machine Manager 2008",
    "b790e43b-f4e4-48b4-9f0c-499194f00841":"Microsoft Works 8",
    "e9c87080-a759-475a-a8fa-55552c8cd3dc":"Microsoft Works 9",
    "56309036-4c77-4dd9-951a-99ee9c246a94":"Microsoft",
    "6b9e8b26-8f50-44b9-94c6-7846084383ec":"MS Security Essentials",
    "4217668b-66f0-42a0-911e-a334a5e4dbad":"Network Monitor 3",
    "35c4463b-35dc-42ac-b0ba-1d9b5c505de2":"Network Monitor",
    "8508af86-b85e-450f-a518-3b6f8f204eea":"New Dictionaries for Microsoft IMEs",
    "6248b8b1-ffeb-dbd9-887a-2acf53b09dfe":"Office 2002/XP",
    "1403f223-a63f-f572-82ba-c92391218055":"Office 2003",
    "041e4f9f-3a3d-4f58-8b2f-5e6fe95c4591":"Office 2007",
    "84f5f325-30d7-41c4-81d1-87a0e6535b66":"Office 2010",
    "704a0a4a-518f-4d69-9e03-10ba44198bd5":"Office 2013",
    "22bf57a8-4fe1-425f-bdaa-32b4f655284b":"Office Communications Server 2007 R2",
    "e164fc3d-96be-4811-8ad5-ebe692be33dd":"Office Communications Server 2007",
    "504ae250-57c5-484a-8a10-a2c35ea0689b":"Office Communications Server And Office Communicator",
    "8bc19572-a4b6-4910-b70d-716fecffc1eb":"Office Communicator 2007 R2",
    "03c7c488-f8ed-496c-b6e0-be608abb8a79":"Office Live",
    "ec231084-85c2-4daf-bfc4-50bbe4022257":"Office Live-Add-In",
    "477b856e-65c4-4473-b621-a8b230bb70d9":"Office",
    "dd78b8a1-0b20-45c1-add6-4da72e9364cf":"OOBE ZDP",
    "7cf56bdd-5b4e-4c04-a6a6-706a2199eff7":"Report Viewer 2005",
    "79adaa30-d83b-4d9c-8afd-e099cf34855f":"Report Viewer 2008",
    "f7f096c9-9293-422d-9be8-9f6e90c2e096":"Report Viewer 2010",
    "9f9b1ace-a810-11db-bad5-f7f555d89593":"SDK Components",
    "ce62f77a-28f3-4d4b-824f-0f9b53461d67":"Search Enhancement Pack",
    "6cf036b9-b546-4694-885a-938b93216b66":"Security Essentials",
    "9f3dd20a-1004-470e-ba65-3dc62d982958":"Silverlight",
    "fe729f7e-3945-11dc-8e0c-cd1356d89593":"Silverlight",
    "6750007f-c908-4f2c-8aff-48ca6d36add6":"Skype for Windows",
    "1e602215-b397-46ca-b1a8-7ea0059517bc":"Skype",
    "7145181b-9556-4b11-b659-0162fa9df11f":"SQL Server 2000",
    "60916385-7546-4e9b-836e-79d65e517bab":"SQL Server 2005",
    "bb7bc3a7-857b-49d4-8879-b639cf5e8c3c":"SQL Server 2008 R2",
    "c5f0b23c-e990-4b71-9808-718d353f533a":"SQL Server 2008",
    "7fe4630a-0330-4b01-a5e6-a77c7ad34eb0":"SQL Server 2012 Product Updates for Setup",
    "c96c35fc-a21f-481b-917c-10c4f64792cb":"SQL Server Feature Pack",
    "0a4c6c73-8887-4d7f-9cbe-d08fa8fa9d1e":"SQL Server",
    "daa70353-99b4-4e04-b776-03973d54d20f":"System Center 2012 - App Controller",
    "b0c3b58d-1997-4b68-8d73-ab77f721d099":"System Center 2012 - Data Protection Manager",
    "bf05abfb-6388-4908-824e-01565b05e43a":"System Center 2012 - Operations Manager",
    "ab8df9b9-8bff-4999-aee5-6e4054ead976":"System Center 2012 - Orchestrator",
    "6ed4a93e-e443-4965-b666-5bc7149f793c":"System Center 2012 - Virtual Machine Manager",
    "50d71efd-1e60-4898-9ef5-f31a77bde4b0":"System Center 2012 SP1 - App Controller",
    "dd6318d7-1cff-44ed-a0b1-9d410c196792":"System Center 2012 SP1 - Data Protection Manager",
    "80d30b43-f814-41fd-b7c5-85c91ea66c45":"System Center 2012 SP1 - Operation Manager",
    "ba649061-a2bd-42a9-b7c3-825ce12c3cd6":"System Center 2012 SP1 - Virtual Machine Manager",
    "ae4500e9-17b0-4a78-b088-5b056dbf452b":"System Center Advisor",
    "d22b3d16-bc75-418f-b648-e5f3d32490ee":"System Center Configuration Manager 2007",
    "23f5eb29-ddc6-4263-9958-cf032644deea":"System Center Online",
    "9476d3f6-a119-4d6e-9952-8ad28a55bba6":"System Center Virtual Machine Manager",
    "26a5d0a5-b108-46f1-93fa-f2a9cf10d029":"System Center",
    "5a456666-3ac5-4162-9f52-260885d6533a":"Systems Management Server 2003",
    "78f4e068-1609-4e7a-ac8e-174288fa70a1":"Systems Management Server",
    "ae4483f4-f3ce-4956-ae80-93c18d8886a6":"Threat Management Gateway Definition Updates for Network Inspection System",
    "cd8d80fe-5b55-48f1-b37a-96535dca6ae7":"TMG Firewall Client",
    "4ea8aeaf-1d28-463e-8179-af9829f81212":"Update zur Browserauswahl in Europa (nur Europa)",
    "c8a4436c-1043-4288-a065-0f37e9640d60":"Virtual PC",
    "6d992428-3b47-4957-bb1a-157bd8c73d38":"Virtual Server",
    "f61ce0bd-ba78-4399-bb1c-098da328f2cc":"Virtual Server",
    "a0dd7e72-90ec-41e3-b370-c86a245cd44f":"Visual Studio 2005",
    "e3fde9f8-14d6-4b5c-911c-fba9e0fc9887":"Visual Studio 2008",
    "cbfd1e71-9d9e-457e-a8c5-500c47cfe9f3":"Visual Studio 2010 Tools for Office Runtime",
    "c9834186-a976-472b-8384-6bb8f2aa43d9":"Visual Studio 2010",
    "abddd523-04f4-4f8e-b76f-a6c84286cc67":"Visual Studio 2012",
    "cf4aa0fc-119d-4408-bcba-181abb69ed33":"Visual Studio 2013",
    "3b4b8621-726e-43a6-b43b-37d07ec7019f":"Windows 2000",
    "bfe5b177-a086-47a0-b102-097e4fa1f807":"Windows 7",
    "3e5cc385-f312-4fff-bd5e-b88dcf29b476":"Windows 8 Language Interface Packs",
    "97c4cee8-b2ae-4c43-a5ee-08367dab8796":"Windows 8 Language Packs",
    "405706ed-f1d7-47ea-91e1-eb8860039715":"Windows 8.1 Drivers",
    "18e5ea77-e3d1-43b6-a0a8-fa3dbcd42e93":"Windows 8.1 Dynamic Update",
    "14a011c7-d17b-4b71-a2a4-051807f4f4c6":"Windows 8.1 Language Interface Packs",
    "01030579-66d2-446e-8c65-538df07e0e44":"Windows 8.1 Language Packs",
    "6407468e-edc7-4ecd-8c32-521f64cee65e":"Windows 8.1",
    "2ee2ad83-828c-4405-9479-544d767993fc":"Windows 8",
    "393789f5-61c1-4881-b5e7-c47bcca90f94":"Windows Consumer Preview Dynamic Update",
    "8c3fcc84-7410-4a95-8b89-a166a0190486":"Windows Defender",
    "50c04525-9b15-4f7c-bed4-87455bcd7ded":"Windows Dictionary Updates",
    "f14be400-6024-429b-9459-c438db2978d4":"Windows Embedded Developer Update",
    "f4b9c883-f4db-4fb5-b204-3343c11fa021":"Windows Embedded Standard 7",
    "a36724a5-da1a-47b2-b8be-95e7cd9bc909":"Windows Embedded",
    "6966a762-0c7c-4261-bd07-fb12b4673347":"Windows Essential Business Server 2008 Setup Updates",
    "e9b56b9a-0ca9-4b3e-91d4-bdcf1ac7d94d":"Windows Essential Business Server 2008",
    "649f3e94-ed2f-42e8-a4cd-e81489af357c":"Windows Essential Business Server Preinstallation Tools",
    "41dce4a6-71dd-4a02-bb36-76984107376d":"Windows Essential Business Server",
    "470bd53a-c36a-448f-b620-91feede01946":"Windows GDR-Dynamic Update",
    "5ea45628-0257-499b-9c23-a6988fc5ea85":"Windows Live Toolbar",
    "0ea196ba-7a32-4e76-afd8-46bd54ecd3c6":"Windows Live",
    "afd77d9e-f05a-431c-889a-34c23c9f9af5":"Windows Live",
    "b3d0af68-8a86-4bfc-b458-af702f35930e":"Windows Live",
    "e88a19fb-a847-4e3d-9ae2-13c2b84f58a6":"Windows Media Dynamic Installer",
    "8c27cdba-6a1c-455e-af20-46b7771bbb96":"Windows Next Graphics Driver Dynamic update",
    "2c62603e-7a60-4832-9a14-cfdfd2d71b9a":"Windows RT 8.1",
    "0a07aea1-9d09-4c1e-8dc7-7469228d8195":"Windows RT",
    "7f44c2a7-bc36-470b-be3b-c01b6dc5dd4e":"Windows Server 2003, Datacenter Edition",
    "dbf57a08-0d5a-46ff-b30c-7715eb9498e9":"Windows Server 2003",
    "fdfe8200-9d98-44ba-a12a-772282bf60ef":"Windows Server 2008 R2",
    "ec9aaca2-f868-4f06-b201-fb8eefd84cef":"Windows Server 2008 Server-Manager - Dynamic Installer",
    "ba0ae9cc-5f01-40b4-ac3f-50192b5d6aaf":"Windows Server 2008",
    "26cbba0f-45de-40d5-b94a-3cbe5b761c9d":"Windows Server 2012 Language Packs",
    "8b4e84f6-595f-41ed-854f-4ca886e317a5":"Windows Server 2012 R2 Language Packs",
    "d31bd4c3-d872-41c9-a2e7-231f372588cb":"Windows Server 2012 R2",
    "a105a108-7c9b-4518-bbbe-73f0fe30012b":"Windows Server 2012",
    "eef074e9-61d6-4dac-b102-3dbe15fff3ea":"Windows Server Solutions Best Practices Analyzer 1.0",
    "4e487029-f550-4c22-8b31-9173f3f95786":"Windows Server-Manager - Windows Server Updates Services (WSUS) Dynamic Installer",
    "032e3af5-1ac5-4205-9ae5-461b4e8cd26d":"Windows Small Business Server 2003",
    "7fff3336-2479-4623-a697-bcefcf1b9f92":"Windows Small Business Server 2008 Migration Preparation Tool",
    "575d68e2-7c94-48f9-a04f-4b68555d972d":"Windows Small Business Server 2008",
    "1556fc1d-f20e-4790-848e-90b7cdbedfda":"Windows Small Business Server 2011 Standard",
    "68623613-134c-4b18-bcec-7497ac1bfcb0":"Windows Small Business Server",
    "e7441a84-4561-465f-9e0e-7fc16fa25ea7":"Windows Ultimate Extras",
    "90e135fb-ef48-4ad0-afb5-10c4ceb4ed16":"Windows Vista Dynamic Installer",
    "a901c1bd-989c-45c6-8da0-8dde8dbb69e0":"Windows Vista Ultimate Language Packs",
    "26997d30-08ce-4f25-b2de-699c36a8033a":"Windows Vista",
    "a4bedb1d-a809-4f63-9b49-3fe31967b6d0":"Windows XP 64-Bit Edition Version 2003",
    "4cb6ebd5-e38a-4826-9f76-1416a6f563b0":"Windows XP x64 Edition",
    "558f4bc3-4827-49e1-accf-ea79fd72d4c9":"Windows XP",
    "6964aab4-c5b5-43bd-a17d-ffb4346a8e1d":"Windows",
    "81b8c03b-9743-44b1-8c78-25e750921e36":"Works 6-9 Converter",
    "2425de84-f071-4358-aac9-6bbd6e0bfaa7":"Works",
    "a13d331b-ce8f-40e4-8a18-227bf18f22f3":"Writer-Installation und -Upgrades",
}

def get_product_id(expr):
    """Find product ids matching expr"""
    result = []
    match = re.compile(expr,re.IGNORECASE)
    for key,value in Products.iteritems():
        if match.match(value) or expr == key:
            result.append(key)
    return result

Severities = {
    None:'None',
    0:'Critical',
    1:'Important',
    2:'Moderate',
    3:'Low',
}

InstallResult = {
  0: 'NotStarted',
  1: 'InProgress',
  2: 'Succeeded',
  3: 'SucceededWithErrors',
  4: 'Failed',
  5: 'Aborted',
 }


WUA_MAJOR_VERSION = 7
WUA_MINOR_VERSION = 6


def map_classifications(lst):
    """Given a list of updateclassification id or updateclassification names
      return list of UpdateClassification names
    """
    if lst is None:
        return None
    result = []
    for cat in lst:
        if cat in UpdateClassifications:
            result.append(cat)
        elif cat.lower() in [c.lower() for c in UpdateClassifications.values()]:
            for (k,v) in UpdateClassifications.iteritems():
                if v.lower() == cat.lower():
                    result.append(k)
                    break
        else:
            raise Exception('unknown UpdateClassification %s' % cat)
    return result


def sha1_for_file(fname, block_size=2**20):
    import hashlib
    f = open(fname,'rb')
    sha1 = hashlib.sha1()
    while True:
        data = f.read(block_size)
        if not data:
            break
        sha1.update(data)
    return sha1.hexdigest()

# XXX returns None (ie False in boolean context) if nothing looks like a sha1
# hash in the file name -> false positives?
def check_sha1_filename(target):
    # check sha1 sum if possible...
    if os.path.isfile(target):
        sha1sum_parts = os.path.basename(target).rsplit('.',1)[0].rsplit('_',1)
        if sha1sum_parts:
            sha1sum = sha1sum_parts[1]
            # looks like hex sha1
            if len(sha1sum) == 40 and (sha1sum != sha1_for_file(target)):
                return False
        return True


class WAPTDiskSpaceException(Exception):
    def __init__(self, message, free_space):
        self.message = message
        self.free_space = free_space

    def __unicode__(self):
        return unicode(self.message) + u'; free space: ' + unicode(self.free_space / 2**20) + u'MB'

    def __str__(self):
        return unicode(self).encode('utf-8')



class WaptWUA(object):
    def __init__(self,wapt,windows_updates_rules = {}, filter="Type='Software' and IsInstalled=0 and IsHidden=0"):
        self.wapt = wapt
        self.cache_path = os.path.abspath(makepath(wapt.wapt_base_dir,'waptwua','cache'))
        self.wsusscn2 = makepath(self.cache_path, 'wsusscn2.cab')
        self._update_session = None
        self._update_service_manager = None
        self._update_searcher = None
        self._update_service = None
        self.filter = filter

        self.windows_updates_rules = windows_updates_rules

        #
        self.forbidden_updates = windows_updates_rules.get('forbidden_updates',None)
        self.allowed_updates = windows_updates_rules.get('allowed_updates',None)
        self.allowed_severities = windows_updates_rules.get('allowed_severities',None)
        self.allowed_classifications = windows_updates_rules.get('allowed_classifications',None)

        self._updates = None
        # to store successful changes in read only properties of _updates after initial scan
        self._cached_updates = {}

    @staticmethod
    def automatic_updates(enable):

        if enable:
            expected = 0x4
        else:
            expected = 0x1

        key = reg_openkey_noredir(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update')
        updatevalue = reg_getvalue(key, 'AUOptions')
        reg_closekey(key)

        if updatevalue != expected:
            if enable:
                logger.info("auto update disabled, enabling")
            else:
                logger.info("auto update enabled, disabling")
            key = reg_openkey_noredir(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update', KEY_WRITE)
            reg_setvalue(key, 'AUOptions', expected, REG_DWORD)
            reg_closekey(key)
            try:
                import subprocess
                subprocess.check_output(['net', 'stop',  'wuauserv'])
                subprocess.check_output(['net', 'start', 'wuauserv'])
            except Exception as e:
                print('Could not restart wuauserv: %s', str(e))

    @staticmethod
    def disable_os_upgrade():

        try:
            v = platform.win32_ver()[1].split('.')
            if int(v[0]) < 6 or int(v[1]) < 1:
                logger.info('OS version < 6.1, no need to disable OS upgrades.')
                return
        except Exception as e:
            logger.warning('Problem when parsing windows version: %s' % str(e))
            return

        try:
            key = reg_openkey_noredir(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate')
            updatevalue = reg_getvalue(key, 'DisableOSUpgrade')
            reg_closekey(key)
            if updatevalue != 0x1:
                key = reg_openkey_noredir(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate', KEY_WRITE)
                reg_setvalue(key, 'DisableOSUpgrade', 0x1, REG_DWORD)
                reg_closekey(key)
        except Exception as e:
            print('Could not disable automatic upgrades: %s', str(e))


    def wua_agent_version(self):
        try:
            return get_file_properties(os.path.join(system32(),'Wuaueng.dll'))['ProductVersion']
        except Exception:
            try:
                agent_info = win32com.client.Dispatch("Microsoft.Update.AgentInfo")
                return agent_info.GetInfo("ProductVersionString")
            except Exception:
                return '0.0.0'


    def ensure_minimum_wua_version(self):
        v = map(int, self.wua_agent_version().split('.'))
        if v[0] < WUA_MAJOR_VERSION or (v[0] == WUA_MAJOR_VERSION and v[1] < WUA_MINOR_VERSION):
            raise Exception('Minimum required WUA version: %d.%d' % (WUA_MAJOR_VERSION, WUA_MINOR_VERSION))


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

        products = [ Products.get(c.CategoryID,c.CategoryID) for c in update.Categories if c.Type == 'Product']
        classifications = [ UpdateClassifications.get(c.CategoryID,c.CategoryID) for c in update.Categories if c.Type == 'UpdateClassification']

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
            changetime = datetime2isodate(datetime.datetime.fromtimestamp(int(update.LastDeploymentChangeTime))),
            product = (products and products[0]) or "",
            classification = (classifications and classifications[0] or ""),
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

    def download_wsusscan_cab(self):
        """Download from wapt server the last version of wsusscn2.cab database for offline update scan.
        """
        if len(self.wapt.repositories)>0:
            try:
                self.wapt.write_param('waptwua.status','UPDATING')
                cab_location = '%swua/wsusscn2.cab' % self.wapt.repositories[0].repo_url
                cab_target = self.wsusscn2
                cab_current_date = self.wapt.read_param('waptwua.wsusscn2cab_date')
                r = requests.head(
                    cab_location,
                    timeout=self.wapt.repositories[0].timeout,
                    proxies=self.wapt.repositories[0].proxies,
                    verify=self.wapt.repositories[0].verify_cert,
                    )
                r.raise_for_status()
                cab_new_date = httpdatetime2isodate(r.headers['last-modified'])
                if not isfile(cab_target) or (cab_new_date > cab_current_date ):
                    wget(cab_location,cab_target,proxies=self.wapt.repositories[0].proxies,connect_timeout=self.wapt.repositories[0].timeout)
                    self.wapt.write_param('waptwua.wsusscn2cab_date',cab_new_date)
                    logger.debug('New wusscn2.cab date : %s'%cab_new_date)
                self.wapt.write_param('waptwua.status','DBREADY')
            except Exception as e:
                self.wapt.write_param('waptwua.status','ERROR')
                raise


    def update_wsusscan_cab(self):
        try:
            self.download_wsusscan_cab()
        except Exception as e:
            if isfile(self.wsusscn2):
                print('Unable to refresh wsusscan cab, using old one. (error: %s)' % e)
            else:
                print('Unable to get wsusscan cab, aborting.')
                raise


    @property
    def update_searcher(self):
        """Instantiate a updateSearcher instance
        """
        if not self._update_searcher:
            # use wsus offline updates index cab
            print('   Connecting to local update searcher using offline wsusscn2 file...')
            self._update_service = self.update_service_manager.AddScanPackageService("Offline Sync Service",self.wsusscn2)
            self._update_searcher = self.update_session.CreateUpdateSearcher()
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
                self._updates = []
                self._cached_updates = {}
                for update in search_result.Updates:
                    self._updates.append(update)
            finally:
                self.wapt.write_param('waptwua.status','READY')
        return self._updates


    def is_allowed(self,update):
        """Check if an update is allowed
            allowed if not explicitly  forbidden and in allowed classifications
        """
        # check by KB list as well as by updateId list
        kbs = [ "KB%s" % kb for kb in update.KBArticleIDs ]

        allowed_kb = False
        if self.allowed_updates is not None:
            for kb in kbs:
                if kb in self.allowed_updates:
                    allowed_kb = True
                    break

        forbidden_kb = False
        if self.forbidden_updates is not None:
            for kb in kbs:
                if kb in self.forbidden_updates:
                    forbidden_kb = True
                    break

        allowed_classification = self.allowed_classifications is None
        if self.allowed_classifications is not None:
            # get updateClassification list of this update
            update_class = [c.CategoryID for c in update.Categories if c.Type == 'UpdateClassification']
            for cat in map_classifications(self.allowed_classifications):
                if cat in update_class:
                    allowed_classification = True
                    break

        allowed_severity = self.allowed_severities is None or update.MsrcSeverity in self.allowed_severities

        return not forbidden_kb and \
                (self.forbidden_updates is None or not update.Identity.UpdateID in self.forbidden_updates) and \
                (
                    (allowed_classification and allowed_severity) or
                    (self.allowed_updates is not None and (update.Identity.UpdateID in self.allowed_updates or allowed_kb))
                )

    def scan_updates_status(self):
        """Check all updates and filter out which one should be installed"""
        logger.info('Allowed classifications:%s'%self.allowed_classifications or 'All')
        logger.info('Forbidden updates:%s'%self.forbidden_updates or 'None')
        logger.info('Allowed severities:%s'%(self.allowed_severities or 'All'))
        logger.info('Allowed additional specific updates:%s'%self.allowed_updates or 'None')

        installed,pending,discarded = 0,0,0

        self.update_wsusscan_cab()

        if self.check_last_successful_scan():
            logger.info('Bypassing scan, no change since last successful scan')
            full_stats = self.stored_status()
            installed = len([ u for u in full_stats['updates'] if u['status'] == 'OK'])
            pending =   len([ u for u in full_stats['updates'] if u['status'] == 'PENDING'])
            discarded = len([ u for u in full_stats['updates'] if u['status'] == 'DISCARDED'])
            return (installed, pending, discarded)

        logger.debug('Scanning installed / not installed Updates')
        start_time = time.time()
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
        scan_duration = int(time.time() - start_time)
        logger.debug('Writing status in local wapt DB')
        self.wapt.write_param('waptwua.wua_agent_version',json.dumps(self.wua_agent_version()))
        self.wapt.write_param('waptwua.windows_updates_rules',json.dumps(self.windows_updates_rules))

        self.wapt.write_param('waptwua.updates',json.dumps([ self.update_as_dict(u) for u in self.updates]))

        self.wapt.write_param('waptwua.last_scan_duration',json.dumps(scan_duration))
        self.wapt.write_param('waptwua.last_scan_date',datetime2isodate())
        if not pending:
            self.wapt.write_param('waptwua.status','OK')
        else:
            self.wapt.write_param('waptwua.status','PENDING_UPDATES')

        self.write_last_successful_scan()

        # send status to wapt server
        logger.debug('Updating workstation status on remote wapt server')
        self.wapt.update_server_status()
        return (installed,pending,discarded)


    def check_last_successful_scan(self):
        if not os.path.exists(self.wsusscn2):
            raise Exception('Unexpected: missing scan file %s' % self.wsusscn2)
        new_hash = sha1_for_file(self.wsusscn2)
        old_hash = self.wapt.read_param('waptwua.wsusscn2_checksum')
        return old_hash == new_hash


    def write_last_successful_scan(self):
        cksum = sha1_for_file(self.wsusscn2)
        self.wapt.write_param('waptwua.wsusscn2_checksum', cksum)


    def wget_update(self,url,target):

        def checked_wget(url, target, **kwargs):
            tmp_target = target + '.part'
            if os.path.exists(tmp_target):
                # XXX what about concurrent downloads?
                os.unlink(tmp_target)
            wget(url, tmp_target, **kwargs)
            if check_sha1_filename(tmp_target) == False:
                os.unlink(tmp_target)
                raise Exception('checked_wget: bad sha1 checksum for tmp_target %s' % tmp_target)
            else:
                os.rename(tmp_target, target)

        # try using specialized proxy
        url_parts = urlparse(url)

        if len(self.wapt.repositories)>0:
            repo_parts = urlparse(self.wapt.repositories[0].repo_url)
            wua_proxy = {'http':'http://%s:8123' % (repo_parts.netloc,)}
        else:
            repo_parts = None
            wua_proxy = None
        try:
            # direct download of prefetch
            patch_url = '%s://%s%swua%s' % (repo_parts.scheme,repo_parts.netloc,repo_parts.path,url_parts.path)
            checked_wget(patch_url,target,proxies=self.wapt.repositories[0].proxies)
        except Exception:
            # trigger background download on server
            try:
                res = self.wapt.waptserver.get('api/v2/download_windows_update?url=%s'%url)
                if 'result' not in res:
                    raise Exception('Requested %s, Unexpected reply from server: %s' % (url, str(res)))
                patch_url = '%s://%s%s' % (repo_parts.scheme,repo_parts.netloc,res['result']['url'])
                checked_wget(patch_url, target, proxies=self.wapt.repositories[0].proxies)
            except Exception:
                # using polipo proxy or direct download
                #checked_wget(url, target, proxies=wua_proxy)
                # Temporary: prevent the client from directly reaching Microsoft
                raise


    def _check_disk_space(self):
        for d in wmi.WMI().Win32_LogicalDisk():
            device = d.Name
            if device == 'C:' and int(d.FreeSpace) < 2 ** 30:
                raise WAPTDiskSpaceException('Not enough space left on device ' + device, d.FreeSpace)


    def download_single(self,update):
        result = []
        try:

            self._check_disk_space()

            self.wapt.write_param('waptwua.status','DOWNLOADING')

            for dc in update.DownloadContents:
                #https://msdn.microsoft.com/en-us/library/windows/desktop/aa386120(v=vs.85).aspx
                print "update.DownloadContents", dc.DownloadUrl
                target = makepath(self.cache_path,os.path.split(dc.DownloadUrl)[1])
                files = win32com.client.Dispatch('Microsoft.Update.StringColl')
                if not isfile(target):
                    try:
                        self.wget_update(dc.DownloadUrl,target)
                    except Exception as e:
                        print "ERROR: skipping download %s, reason: %s" % (dc.DownloadUrl, str(e))
                        continue
                    result.append(dc.DownloadUrl)
                if isfile(target):
                    files.add(target)

                for fn in files:
                    print "%s put to local WUA cache for update" % (fn,)
                    #if isfile(fn):
                    #    remove_file(fn)

                if len(list(files)) > 0:
                    update.CopyToCache(files)

            for bu in update.BundledUpdates:
                files = win32com.client.Dispatch('Microsoft.Update.StringColl')
                for dc in bu.DownloadContents:
                    #https://msdn.microsoft.com/en-us/library/windows/desktop/aa386120(v=vs.85).aspx
                    print "dc.DownloadUrl", dc.DownloadUrl
                    target = makepath(self.cache_path,os.path.split(dc.DownloadUrl)[1])
                    if not isfile(target):
                        try:
                            self.wget_update(dc.DownloadUrl,target)
                        except Exception as e:
                            print "ERROR: skipping download %s, reason: %s" % (dc.DownloadUrl, str(e))
                            continue
                        result.append(dc.DownloadUrl)
                    if isfile(target):
                        files.add(target)

                for fn in files:
                    print "%s put to local WUA cache for update" % (fn,)

                if len(list(files)) > 0:
                    bu.CopyToCache(files)

            self.wapt.write_param('waptwua.status','READY')
        # We can't handle errors here.
        except Exception:
            raise
        return result

    def download_updates(self):
        """Download all pending updates and put them in Windows Update cache

        """
        result = []
        try:
            for update in self.updates:
                if not update.IsInstalled and self.is_allowed(update) and not update.IsDownloaded:
                    # IUpdate : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386099(v=vs.85).aspx
                    # IUpdate2 : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386100(v=vs.85).aspx
                    result.extend(self.download_single(update))
            self.scan_updates_status()
        except WAPTDiskSpaceException:
            logger.error('Disk Space Error')
            self.wapt.write_param('waptwua.status','DISK_SPACE_ERROR')
        except Exception as e:
            logger.error('Unexpected error:' + str(e))
            self.wapt.write_param('waptwua.status','ERROR')
        self.wapt.update_server_status()
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
                        if self.is_allowed(update):
                            self.store_cached_update_property(update,'IsInstalled',True)

            else:
                self.wapt.write_param('waptwua.rebootrequired',json.dumps(False))
                self.wapt.write_param('waptwua.last_install_result','None')

            self.wapt.write_param('waptwua.last_install_batch',json.dumps(result))
            self.wapt.write_param('waptwua.last_install_date',datetime2isodate())
        except WAPTDiskSpaceException:
            self.wapt.write_param('waptwua.status','DISK_SPACE_ERROR')
            logger.error('Disk Space Error')
        except Exception:
            self.wapt.write_param('waptwua.status','ERROR')
        finally:
            self.scan_updates_status()
        self.wapt.update_server_status()
        return result


    def stored_status(self):
        return {
            'last_scan_date':self.wapt.read_param('waptwua.last_scan_date',None),
            'last_install_batch':self.wapt.read_param('waptwua.last_install_batch',None),
            'last_install_date':self.wapt.read_param('waptwua.last_install_date',None),
            'last_install_result':self.wapt.read_param('waptwua.last_install_result',None),
            'last_scan_duration':self.wapt.read_param('waptwua.last_scan_duration',None),
            'wsusscn2cab_date':self.wapt.read_param('waptwua.wsusscn2cab_date',None),
            'rebootrequired':self.wapt.read_param('waptwua.rebootrequired',None),
            'updates':json.loads(self.wapt.read_param('waptwua.updates','[]')),
            'status':self.wapt.read_param('waptwua.status',None),
            'wua_agent_version':self.wapt.read_param('waptwua.wua_agent_version',None),
            'windows_updates_rules':json.loads(self.wapt.read_param('waptwua.windows_updates_rules','{}')),
            }

def status():
        stat = wua.stored_status()
        stat['installed'] = len([ u for u in stat['updates'] if u['status'] == 'OK'])
        stat['pending'] = len([ u for u in stat['updates'] if u['status'] == 'PENDING'])
        stat['discarded'] = len([ u for u in stat['updates'] if u['status'] == 'DISCARDED'])

        return u"""\
windows_updates_rules: %(windows_updates_rules)s

Status:            %(status)s
Installed updates: %(installed)s
Pending updates:   %(pending)s
Discarded updates: %(discarded)s
Reboot required:   %(rebootrequired)s

Last install date:   %(last_install_date)s
Last install result: %(last_install_result)s

WSUSScan cab date: %(wsusscn2cab_date)s
        """ % stat

if __name__ == '__main__':
    from common import Wapt

    def_allowed_updates = None
    def_forbidden_updates = None
    def_allowed_severities = None
    def_allowed_classifications = None

    parser=OptionParser(usage=__doc__)
    parser.add_option("-S","--severities", dest="allowed_severities", default=def_allowed_severities, help="Allow updates by severity. csv list of Critical,Important,Moderate,Low. If empty : allow all. (default: %default)")
    parser.add_option("-C","--classifications", dest="allowed_classifications", default=def_allowed_classifications, help="Allow updates by claffication. csv list of "+','.join(UpdateClassifications.values())+". If empty : allow all. (default: %default)")
    parser.add_option("-a","--allowed", dest="allowed_updates", default=def_allowed_updates, help="Allow updates by update-id or KB. csv list of id to allow (default: %default)")
    parser.add_option("-b","--forbidden", dest="forbidden_updates", default=def_forbidden_updates, help="Forbid updates by update-id or KB. csv list (default: %default)")
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

    wapt = Wapt(config_filename=options.config)

    allowed_updates = ensure_list(options.allowed_updates,allow_none = True)
    forbidden_updates = ensure_list(options.forbidden_updates,allow_none = True)
    allowed_severities = ensure_list(options.allowed_severities,allow_none = True)
    allowed_classifications = ensure_list(options.allowed_classifications,allow_none = True)

    stored_windows_updates_rules = json.loads(wapt.read_param('waptwua.windows_updates_rules','{}'))
    if not stored_windows_updates_rules:
        stored_windows_updates_rules = {}

    if allowed_updates is None and forbidden_updates is None and allowed_classifications is None and allowed_severities is None:
        # get from wapt db
        allowed_updates = stored_windows_updates_rules.get('allowed_updates',None)
        forbidden_updates = stored_windows_updates_rules.get('forbidden_updates',None)
        allowed_severities = stored_windows_updates_rules.get('allowed_severities',None)
        allowed_classifications = stored_windows_updates_rules.get('allowed_classifications',None)
    else:
        # store settings
        stored_windows_updates_rules['allowed_updates'] = allowed_updates
        stored_windows_updates_rules['forbidden_updates'] = forbidden_updates
        stored_windows_updates_rules['allowed_severities'] = allowed_severities
        stored_windows_updates_rules['allowed_classifications'] = allowed_classifications
        wapt.write_param('waptwua.windows_updates_rules',json.dumps(stored_windows_updates_rules))

    wua = WaptWUA(wapt, windows_updates_rules = stored_windows_updates_rules)
    wua.ensure_minimum_wua_version()

    if len(args) <1:
        print parser.usage
        sys.exit(1)

    action = args[0]

    if action == 'scan':
        pass
    elif wua.wapt.waptwua_enabled == False:
        raise Exception('waptwua is currently disabled.')
    else:
        wua.automatic_updates(False)
        wua.disable_os_upgrade()

    if action == 'scan':
        installed,pending,discarded = wua.scan_updates_status()
        print status()
    elif action == 'download':
        print wua.download_updates()
        print wua.stored_status()
        logger.info('%s'%wua.stored_status())
        print status()
    elif action == 'install':
        print wua.install_updates()
        print status()
    elif action == 'status':
        print status()
    else:
        print parser.usage

