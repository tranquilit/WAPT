unit uAdapterInfo;
// from http://stackoverflow.com/questions/325872/detect-an-internet-connection-activation-with-delphi/331421#331421
interface

uses
  Classes,
  SysUtils;

const
  MAX_INTERFACE_NAME_LEN = $100;
  ERROR_SUCCESS   = 0;
  MAXLEN_IFDESCR  = $100;
  MAXLEN_PHYSADDR = 8;

  MIB_IF_OPER_STATUS_NON_OPERATIONAL = 0;
  MIB_IF_OPER_STATUS_UNREACHABLE = 1;
  MIB_IF_OPER_STATUS_DISCONNECTED = 2;
  MIB_IF_OPER_STATUS_CONNECTING  = 3;
  MIB_IF_OPER_STATUS_CONNECTED   = 4;
  MIB_IF_OPER_STATUS_OPERATIONAL = 5;

  MIB_IF_TYPE_OTHER    = 1;
  MIB_IF_TYPE_ETHERNET = 6;
  MIB_IF_TYPE_TOKENRING = 9;
  MIB_IF_TYPE_FDDI     = 15;
  MIB_IF_TYPE_PPP      = 23;
  MIB_IF_TYPE_LOOPBACK = 24;
  MIB_IF_TYPE_SLIP     = 28;

  MIB_IF_ADMIN_STATUS_UP      = 1;
  MIB_IF_ADMIN_STATUS_DOWN    = 2;
  MIB_IF_ADMIN_STATUS_TESTING = 3;

  _MAX_ROWS_ = 20;
  ANY_SIZE   = 1;


type
  MIB_IFROW = record
    wszName:    array[0 .. (MAX_INTERFACE_NAME_LEN * 2 - 1)] of char;
    dwIndex:    longint;
    dwType:     longint;
    dwMtu:      longint;
    dwSpeed:    longint;
    dwPhysAddrLen: longint;
    bPhysAddr:  array[0 .. (MAXLEN_PHYSADDR - 1)] of byte;
    dwAdminStatus: longint;
    dwOperStatus: longint;
    dwLastChange: longint;
    dwInOctets: longint;
    dwInUcastPkts: longint;
    dwInNUcastPkts: longint;
    dwInDiscards: longint;
    dwInErrors: longint;
    dwInUnknownProtos: longint;
    dwOutOctets: longint;
    dwOutUcastPkts: longint;
    dwOutNUcastPkts: longint;
    dwOutDiscards: longint;
    dwOutErrors: longint;
    dwOutQLen:  longint;
    dwDescrLen: longint;
    bDescr:     array[0 .. (MAXLEN_IFDESCR - 1)] of char;
  end;

type
  MIB_IPADDRROW = record
    dwAddr:      longint;
    dwIndex:     longint;
    dwMask:      longint;
    dwBCastAddr: longint;
    dwReasmSize: longint;
    unused1:     word;
    unused2:     word;
  end;

type
  _IfTable = record
    nRows: longint;
    ifRow: array[1.._MAX_ROWS_] of MIB_IFROW;
  end;

type
  _IpAddrTable = record
    dwNumEntries: longint;
    table: array[1..ANY_SIZE] of MIB_IPADDRROW;
  end;



function GetIfTable(pIfTable: Pointer; var pdwSize: longint; bOrder: longint): longint;
  stdcall;
function GetIpAddrTable(pIpAddrTable: Pointer; var pdwSize: longint;
  bOrder: longint): longint; stdcall;

function Get_if_type(iType: integer): string;
function Get_if_admin_status(iStatus: integer): string;
function Get_if_oper_status(iStatus: integer): string;


implementation

function GetIfTable; stdcall; external 'IPHLPAPI.DLL';
function GetIpAddrTable; stdcall; external 'IPHLPAPI.DLL';

function Get_if_type(iType: integer): string;
var
  sResult: string;
begin
  sResult := 'UNKNOWN';
  case iType of
    1: sResult   := 'Other';
    6: sResult   := 'Ethernet';
    9: sResult   := 'Tokenring';
    15: sResult  := 'FDDI';
    23: sResult  := 'PPP';
    24: sResult  := 'Local loopback';
    28: sResult  := 'SLIP';
    37: sResult  := 'ATM';
    71: sResult  := 'IEEE 802.11';
    131: sResult := 'Tunnel';
    144: sResult := 'IEEE 1394 (Firewire)';
  end;

  Result := sResult;
end;

function Get_if_admin_status(iStatus: integer): string;
var
  sResult: string;
begin
  sResult := 'UNKNOWN';

  case iStatus of
    1: sResult := 'UP';
    2: sResult := 'DOWN';
    3: sResult := 'TESTING';
  end;

  Result := sResult;
end;

function Get_if_oper_status(iStatus: integer): string;
var
  sResult: string;
begin
  sResult := 'UNKNOWN';

  case iStatus of
    0: sResult := 'NON_OPERATIONAL';
    1: sResult := 'UNREACHABLE';
    2: sResult := 'DISCONNECTED';
    3: sResult := 'CONNECTING';
    4: sResult := 'CONNECTED';
    5: sResult := 'OPERATIONAL';
  end;

  Result := sResult;
end;

end.
