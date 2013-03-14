unit NetworkAdapterInfo;
// from http://stackoverflow.com/questions/325872/detect-an-internet-connection-activation-with-delphi/331421#331421
interface
{$mode delphi}
{$R-}

uses interfaces,Classes, SysUtils;

type
  TAdapterInfo = array of record
    dwIndex:    longint;
    dwType:     longint;
    dwMtu:      longint;
    dwSpeed:    extended;
    dwPhysAddrLen: longint;
    bPhysAddr:  string;
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
    bDescr:     string;
    sIpAddress: string;
    sIpMask:    string;
  end;

  function Get_EthernetAdapterDetail(var AdapterDataFound: TAdapterInfo): boolean;

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
    P_IfTable = ^_IfTable;
    _IfTable = record
      nRows: longint;
      ifRow: array[1.._MAX_ROWS_] of MIB_IFROW;
    end;

  type
    P_IpAddrTable = ^_IpAddrTable;
    _IpAddrTable = record
      dwNumEntries: longint;
      table: array[1..ANY_SIZE] of MIB_IPADDRROW;
    end;


  function Get_if_type(iType: integer): string;
  function Get_if_admin_status(iStatus: integer): string;
  function Get_if_oper_status(iStatus: integer): string;



implementation
uses Windows,JwaIpRtrMib,winsock;

function GetIfTable(pIfTable: P_IfTable; var pdwSize: LongInt; bOrder: BOOL): DWORD; stdcall; external 'IPHLPAPI.DLL';
function GetIpAddrTable(pIpAddrTable: P_IpAddrTable; var pdwSize: LongInt; bOrder: BOOL): DWORD; stdcall; external 'IPHLPAPI.DLL';

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


function Get_EthernetAdapterDetail(var AdapterDataFound: TAdapterInfo): boolean;
var
  pIfTable: ^_IfTable;
  pIpTable: ^_IpAddrTable;
  ifTableSize, ipTableSize: longint;
  tmp:      string;
  i, j, k, m: integer;
  ErrCode:  longint;
  sAddr, sMask: in_addr;
  IPAddresses, IPMasks: TStringList;
  sIPAddressLine, sIPMaskLine: string;
  bResult:  boolean;
begin
  bResult  := True; //default return value
  pIfTable := nil;
  pIpTable := nil;

  IPAddresses := TStringList.Create;
  IPMasks     := TStringList.Create;

  try
    // First: just get the buffer size.
    // TableSize returns the size needed.
    ifTableSize := 0; // Set to zero so the GetIfTabel function
    // won't try to fill the buffer yet,
    // but only return the actual size it needs.
    GetIfTable(pIfTable, ifTableSize, TRue);
    if (ifTableSize < SizeOf(MIB_IFROW) + Sizeof(longint)) then
    begin
      bResult := False;
      Result  := bResult;
      Exit; // less than 1 table entry?!
    end;

    ipTableSize := 0;
    GetIpAddrTable(pIpTable, ipTableSize, True);
    if (ipTableSize < SizeOf(MIB_IPADDRROW) + Sizeof(longint)) then
    begin
      bResult := False;
      Result  := bResult;
      Exit; // less than 1 table entry?!
    end;

    // Second:
    // allocate memory for the buffer and retrieve the
    // entire table.
    GetMem(pIfTable, ifTableSize);
    ErrCode := GetIfTable(pIfTable, ifTableSize, True);

    if ErrCode <> ERROR_SUCCESS then
    begin
      bResult := False;
      Result  := bResult;
      Exit; // OK, that did not work.
      // Not enough memory i guess.
    end;

    GetMem(pIpTable, ipTableSize);
    ErrCode := GetIpAddrTable(pIpTable, ipTableSize, True);

    if ErrCode <> ERROR_SUCCESS then
    begin
      bResult := False;
      Result  := bResult;
      Exit;
    end;

    for k := 1 to pIpTable^.dwNumEntries do
    begin
      sAddr.S_addr := pIpTable^.table[k].dwAddr;
      sMask.S_addr := pIpTable^.table[k].dwMask;

      sIPAddressLine := Format('0x%8.8x', [(pIpTable^.table[k].dwIndex)]) +
        '=' + Format('%s', [inet_ntoa(sAddr)]);
      sIPMaskLine    := Format('0x%8.8x', [(pIpTable^.table[k].dwIndex)]) +
        '=' + Format('%s', [inet_ntoa(sMask)]);

      IPAddresses.Add(sIPAddressLine);
      IPMasks.Add(sIPMaskLine);
    end;

    SetLength(AdapterDataFound, pIfTable^.nRows); //initialize the array or records
    for i := 1 to pIfTable^.nRows do
      try
        //if pIfTable^.ifRow[i].dwType=MIB_IF_TYPE_ETHERNET then
        //begin
        m := i - 1;
        AdapterDataFound[m].dwIndex := 4;//(pIfTable^.ifRow[i].dwIndex);
        AdapterDataFound[m].dwType := (pIfTable^.ifRow[i].dwType);
        AdapterDataFound[m].dwIndex := (pIfTable^.ifRow[i].dwIndex);
        AdapterDataFound[m].sIpAddress :=
          IPAddresses.Values[Format('0x%8.8x', [(pIfTable^.ifRow[i].dwIndex)])];
        AdapterDataFound[m].sIpMask :=
          IPMasks.Values[Format('0x%8.8x', [(pIfTable^.ifRow[i].dwIndex)])];
        AdapterDataFound[m].dwMtu := (pIfTable^.ifRow[i].dwMtu);
        AdapterDataFound[m].dwSpeed := (pIfTable^.ifRow[i].dwSpeed);
        AdapterDataFound[m].dwAdminStatus := (pIfTable^.ifRow[i].dwAdminStatus);
        AdapterDataFound[m].dwOperStatus := (pIfTable^.ifRow[i].dwOperStatus);
        AdapterDataFound[m].dwInUcastPkts := (pIfTable^.ifRow[i].dwInUcastPkts);
        AdapterDataFound[m].dwInNUcastPkts := (pIfTable^.ifRow[i].dwInNUcastPkts);
        AdapterDataFound[m].dwInDiscards := (pIfTable^.ifRow[i].dwInDiscards);
        AdapterDataFound[m].dwInErrors := (pIfTable^.ifRow[i].dwInErrors);
        AdapterDataFound[m].dwInUnknownProtos := (pIfTable^.ifRow[i].dwInUnknownProtos);
        AdapterDataFound[m].dwOutNUcastPkts := (pIfTable^.ifRow[i].dwOutNUcastPkts);
        AdapterDataFound[m].dwOutUcastPkts := (pIfTable^.ifRow[i].dwOutUcastPkts);
        AdapterDataFound[m].dwOutDiscards := (pIfTable^.ifRow[i].dwOutDiscards);
        AdapterDataFound[m].dwOutErrors := (pIfTable^.ifRow[i].dwOutErrors);
        AdapterDataFound[m].dwOutQLen := (pIfTable^.ifRow[i].dwOutQLen);
        AdapterDataFound[m].bDescr := (pIfTable^.ifRow[i].bDescr);

        tmp := '';
        for j := 0 to pIfTable^.ifRow[i].dwPhysAddrLen - 1 do
        begin
          if Length(tmp) > 0 then
            tmp := tmp + '-' + format('%.2x', [pIfTable^.ifRow[i].bPhysAddr[j]])
          else
            tmp := tmp + format('%.2x', [pIfTable^.ifRow[i].bPhysAddr[j]]);
        end;

        if Length(tmp) > 0 then
        begin
          AdapterDataFound[m].bPhysAddr := tmp;
        end;
      except
        bResult := False;
        Result  := bResult;
        Exit;
      end;
  finally
    if Assigned(pIfTable) then
    begin
      FreeMem(pIfTable, ifTableSize);
    end;

    FreeAndNil(IPMasks);
    FreeAndNil(IPAddresses);
  end;

  Result := bResult;
end;

end.
