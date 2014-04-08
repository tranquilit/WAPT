#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013  Tranquil IT Systems http://www.tranquil.it
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users Windows PC.
#
#    This is a port of some function of ekeyfinder application
#    Copyright (C) 2011 Enchanted Keyfinder Project
#    Copyright (C) 1999-2008  Magical Jelly Bean Software
#
#    see https://code.google.com/p/msoffice-product-key-decoder for python parts
#
#    Contributor(s):
#                    Oliver Schneider (assarbad)
#                    Sam Gleske (sag47)
#                    VersionBoy (versionboy)
#
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
import platform,sys,os
import math
import _winreg

###########
HKEY_CLASSES_ROOT = _winreg.HKEY_CLASSES_ROOT
HKEY_CURRENT_USER = _winreg.HKEY_CURRENT_USER
HKEY_LOCAL_MACHINE = _winreg.HKEY_LOCAL_MACHINE
HKEY_USERS = _winreg.HKEY_USERS
HKEY_CURRENT_CONFIG = _winreg.HKEY_CURRENT_CONFIG

KEY_WRITE = _winreg.KEY_WRITE
KEY_READ = _winreg.KEY_READ

REG_SZ = _winreg.REG_SZ
REG_MULTI_SZ = _winreg.REG_MULTI_SZ
REG_DWORD = _winreg.REG_DWORD
REG_EXPAND_SZ = _winreg.REG_EXPAND_SZ


def reg_openkey_noredir(key, sub_key, sam=_winreg.KEY_READ,create_if_missing=False):
    """Open the registry key\subkey with access rights sam
        Returns a key handle for reg_getvalue and reg_set_value
       key     : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
       sub_key : string like "software\\microsoft\\windows\\currentversion"
       sam     : a boolean comination of KEY_READ | KEY_WRITE
       create_if_missing : True to create the sub_key if not exists, access rights will include KEY_WRITE
    """
    try:
        if platform.machine() == 'AMD64':
            return _winreg.OpenKey(key,sub_key,0, sam | _winreg.KEY_WOW64_64KEY)
        else:
            return _winreg.OpenKey(key,sub_key,0,sam)
    except WindowsError,e:
        if e.errno == 2:
            if create_if_missing:
                if platform.machine() == 'AMD64':
                    return _winreg.CreateKeyEx(key,sub_key,0, sam | _winreg.KEY_READ| _winreg.KEY_WOW64_64KEY | _winreg.KEY_WRITE )
                else:
                    return _winreg.CreateKeyEx(key,sub_key,0,sam | _winreg.KEY_READ | _winreg.KEY_WRITE )
            else:
                raise WindowsError(e.errno,'The key %s can not be opened' % sub_key)


def reg_getvalue(key,name,default=None):
    """Return the value of specified name inside 'key' folder
         key  : handle of registry key as returned by reg_openkey_noredir()
         name : value name or None for key default value
         default : value returned if specified name doesn't exist
    """
    try:
        return _winreg.QueryValueEx(key,name)[0]
    except WindowsError,e:
        if e.errno in(259,2):
            # WindowsError: [Errno 259] No more data is available
            # WindowsError: [Error 2] Le fichier spécifié est introuvable
            return default
        else:
            raise


def registry_readstring(root,path,keyname,default=''):
    """Return a string from registry
        root    : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
        path    : string like "software\\microsoft\\windows\\currentversion"
                           or "software\\wow6432node\\microsoft\\windows\\currentversion"
        keyname : None for value of key or str for a specific value like 'CommonFilesDir'
    the path can be either with backslash or slash"""
    path = path.replace(u'/',u'\\')
    try:
        key = reg_openkey_noredir(root,path)
        result = reg_getvalue(key,keyname,default)
        return result
    except:
        return default


def isWinXP():
  # Returns true if the operating system is Windows XP
  return platform.win32_ver()[0] == 'XP'


def isWinNT4():
  return platform.win32_ver()[0] == 'NT4'


def isWin2k():
  return platform.win32_ver()[0] == '2000'


def isWin7():
  return platform.win32_ver()[0] == '7'


def isValidWinProdID(sProdID):
    #Represents the stripped list of bad Product ID's.
    BadProductIDList = ('64064371823', '64130937623', '64206458023', '64246436423',
         '64333470123', '64408177223', '64445126523', '64487489623',
         '64493370423', '64496239623', '64583325423', '64599496223',
         '64603184323', '64610408123', '64610510323', '64731883823',
         '64759202923', '64767783423', '64830169123', '64881999223',
         '64910676523', '64994139223', '65029231223')
    if isWinXP():
        #Remove hyphens if any from Product ID.
        sStripedProdID = sProdID.replace('-','')
    #Remove the first 5 characters from Product ID.
    sStripedProdID = sStripedProdID[5:]
    #Remove the last 3 characters from Product ID.
    sStripedProdID = sStripedProdID[:-3]
    #Devel's own
    if (sStripedProdID == '640000035623') or (sStripedProdID == '640200176523'):
        return False
    #Remove the 10th character from Product ID.
    sStripedProdID = sStripedProdID[:9]+sStripedProdID[10:]
    if sStripedProdID in BadProductIDList:
        return False
    return True


def WinVersion():
    windows = registry_readstring(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion','ProductName','')
    if windows:
        return windows
    if IsWinNT4():
        return 'Microsoft Windows NT'
#b24chrs = (string.digits + string.ascii_uppercase)[:24]
generic_b24chrs = '0123456789ABCDEFGHIJKLMN'

code_len = 25  # encoded key length (user-readable key)
bin_len = 15  # binary key length
regkey_idx = 52  # start of key in DPID for 2003, 2007
regkey_idx_2010 = 0x328  # start in DPID for 2010

b24chrs = 'BCDFGHJKMPQRTVWXY2346789'
reg_root = r'Software\Microsoft\Office'


def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]


def b24encode(input, outlen=None, chrmap=None):

    # The number of coded characters to actually generate can't be
    # determined soley from the input length, but we can guess.
    if outlen is None:
        # each base24 code char takes ~4.585 bits (ln24 / ln2)
        outlen = int(math.ceil(8*len(input) / 4.585))

    # Use default character mapping [0-9A-N] if none provided
    if chrmap is None:
        chrmap = generic_b24chrs

    input = [ord(i) for i in input[::-1]]
    '''
    # takes less memory (does it piecewise), but more complex
    decoded = []
    for i in range(0,encoded_chars + 1)[::-1]:
        r = 0
        for j in range(0,15)[::-1]:
            r = (r * 256) ^ input[j]
            input[j] = r / 24
            r = r % 24

        print b24chrs[r]
        decoded = decoded.append(b24chrs[r])

    return decoded[::-1]
    '''

    # simple, but eats a ton of memory and probably time if the
    # encoded string is large
    enc = 0
    for i in input:
        enc = enc * 256 + i

    dec = []
    for i in range(outlen):
        dec.append(chrmap[enc % 24])
        enc = enc // 24

    dec.reverse()
    return ''.join(dec)


def b24decode(input, chrmap=None):

    # Use default character mapping [0-9A-N] if none provided
    if chrmap is None:
        chrmap = generic_b24chrs

    # clean invalid characters from input (e.g. '-' (dashes) in product key)
    # and map to \x00 through \x23.
    rmchrs = []
    for i in xrange(256):
        if not chr(i) in chrmap:
            rmchrs.append(chr(i))
    tt = string.maketrans(chrmap, ''.join([chr(i) for i in xrange(24)]))
    input = input.translate(tt, ''.join(rmchrs))

    encnum = 0
    for cc in input:
        encnum *= 24
        encnum += ord(cc)

    enc = []
    while encnum:
        enc.append(encnum % 256)
        encnum = encnum // 256

    return ''.join([chr(i) for i in enc])


def msoKeyDecode(regkey, ID=False):
    '''Decodes a registry key value, by extracting product key
    from bytes 52-66 and decoding.

    Office 2010 (14.0) appears to store the key at 0x328 to 0x337 in
    DPID.  The "Registration" tree is different (cluttered) versus
    other versions, and the DPID value is (exactly) 7 times longer than
    before (1148 bytes, up from 164).

    Tested with a 2010 full suite and a trial of Visio.

    Parameters:
    - regkey is a string containing the contents of "DigitalProductID"
    - version is the decimal version number given by the key directly
    under the "Office" key root
    '''
    '''
    if version is None:
        version = 11 # (default 2003, 2007 appears to be compatible.)

    if float(version) < 14:
        enckey = regkey[regkey_idx:regkey_idx+bin_len]
    else:
        enckey = regkey[regkey_idx_2010:regkey_idx_2010+bin_len]
    '''
    if ID:
        enckey = regkey[regkey_idx_2010:regkey_idx_2010+bin_len]
    else:
        enckey = regkey[regkey_idx:regkey_idx+bin_len]

    deckey = b24encode(enckey, code_len, chrmap=b24chrs)

    return '-'.join(list(chunks(deckey,5)))


def GetMSDPID3(sHivePath):
    """return dict (sProdID, sMSKey)"""

    """
    var
      MyReg: TRegistry;
      iBinarySize: integer;
      HexBuf: array of byte;
      dwChannel : DWord;
      wMajor: word;
      sText: string;
      i: integer;
      cSAMDesired: cardinal;
    """
    key = reg_openkey_noredir(HKEY_LOCAL_MACHINE,sHivePath)
    result = {}
    if reg_getvalue(key,'DigitalProductID',None):
        (HexBuf,rtype) = _winreg.QueryValueEx(key,'DigitalProductID')
        iBinarySize = len(HexBuf)
        if iBinarySize >= 67:  # Incomplete data but might still be enough
            sProdID = 'Not found'
            sProdID = reg_getvalue(key,'ProductID')
            sText = ''
            for i in range(5,31):
                if HexBuf[i] != '\x00':
                    sText += HexBuf[i]
            #Compare Product ID's
            if sText == sProdID:
                result['key_match'] = True
            else:
                result['key_match'] = True
            result['product_id'] = sProdID

            # Edition ID
            sText = '';
            for i in range(33,45):
                if HexBuf[i] != "\x00":
                    sText = sText + HexBuf[i]
            result['product_partnr'] = sText

            # Channel Type
            # the 2 bytes need to be shifted in reverse order, as the WORD is stored in little-endian.
            wMajor = (ord(HexBuf[5]) << 8) or (ord(HexBuf[4]))
            if wMajor == 3:
                dwChannel = (ord(HexBuf[83]) << 24) or (ord(HexBuf[82]) << 16) or (ord(HexBuf[81]) << 8) or ord(HexBuf[80])
                if dwChannel==0:
                    result['product_source'] = 'Installed from ''Full Packaged Product'' media.'
                elif dwChannel==1:
                    result['product_source'] = 'Installed from ''Compliance Checked Product'' media.'
                elif dwChannel==2:
                    result['product_source'] = 'Installed from ''OEM'' media.'
                elif dwChannel==3:
                    result['product_source'] = 'Installed from ''Volume'' media.'

            result['product_key'] = msoKeyDecode( HexBuf,wMajor != 3)
        elif iBinarySize == 0:
            result['product_key'] = 'The CD Key data is empty!'
        else:
            result['product_key'] = 'Some CD Key data is missing!';
    return result


def windows_product_infos():
    infos = GetMSDPID3(r'SOFTWARE\Microsoft\Windows NT\CurrentVersion')
    infos['version'] = WinVersion()
    return infos

if __name__=='__main__':
    print windows_product_infos()
