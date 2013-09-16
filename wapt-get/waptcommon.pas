unit waptcommon;
{ -----------------------------------------------------------------------
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
}

{$mode objfpc}{$H+}
interface
  uses
     Classes, SysUtils,
     DB,sqldb,sqlite3conn,SuperObject,syncobjs;

  const
    waptservice_port:integer = 8088;

  Function  GetMainWaptRepo:String;
  Function  GetWaptServerURL:String;
  function GetWaptPrivateKey: String;

  function  GetLDAPServer(dnsdomain:String=''): String;

  Function  GetWaptLocalURL:String;


  function WaptIniFilename: Utf8String; // for local wapt install directory
  function AppIniFilename: Utf8String;  // current applicatin parameters in user space

  function WaptgetPath: Utf8String;
  function WaptservicePath: Utf8String;
  function WaptDBPath: Utf8String;
  function WaptExternalRepo(inifilename:String=''): Utf8String;
  function GetWaptRepoURL: Utf8String;

  //function http_post(url: string;Params:String): String;

  function GetEthernetInfo(ConnectedOnly:Boolean):ISuperObject;
  function LocalSysinfo: ISuperObject;
  function GetLocalIP: string;
  function GetDNSServer:AnsiString;
  function GetDNSDomain:AnsiString;

  function WAPTServerJsonGet(action: String;args:Array of const): ISuperObject;
  function WAPTLocalJsonGet(action:String):ISuperObject;

Type
  TFormatHook = Function(Dataset:TDataset;Data,FN:Utf8String):UTF8String of object;

  { TWAPTDB }
  TWAPTDB = class(TObject)
  private
    fsqltrans : TSQLTransaction;
    fdb : TSQLite3Connection;
    dbinuse : TCriticalSection;
    function QueryCreate(SQL: String): TSqlQuery;
    property db:TSQLite3Connection read fDB;
    property sqltrans:TSQLTransaction read fsqltrans;
  public
    constructor create(dbpath:String);
    destructor Destroy; override;

    // execute SQL query and returns a JSON structure with records (stArray)
    function Select(SQL:String):ISuperObject;
    function dumpdb:ISuperObject;

    procedure SetParam(name,value:String);
    function GetParam(name:String):String;

    function QueryToHTMLtable(SQL: String; FormatHook: TFormatHook=nil): String;
  end;



implementation

uses FileUtil,soutils,tiscommon,Windows,Variants,winsock,IdDNSResolver,IdExceptionCore,JwaIpHlpApi,JwaIpTypes,
    NetworkAdapterInfo,tisinifiles,registry,tisstrings;


Function GetDNSServers:TDynStringArray;
var
  pFI: PFixedInfo;
  pIPAddr: PIPAddrString;
  OutLen: Cardinal;
begin
  SetLength(Result,0);
  OutLen := SizeOf(TFixedInfo);
  GetMem(pFI, SizeOf(TFixedInfo));
  try
    if GetNetworkParams(pFI, OutLen) = ERROR_BUFFER_OVERFLOW then
    begin
      ReallocMem(pFI, OutLen);
      if GetNetworkParams(pFI, OutLen) <> NO_ERROR then Exit;
    end;
    // If there is no network available there may be no DNS servers defined
    if pFI^.DnsServerList.IpAddress.S[0] = #0 then Exit;
    // Add first server
    SetLength(Result,length(Result)+1);
    Result[length(Result)-1] := pFI^.DnsServerList.IpAddress.S;
    // Add rest of servers
    pIPAddr := pFI^.DnsServerList.Next;
    while Assigned(pIPAddr) do
    begin
      SetLength(Result,length(Result)+1);
      Result[length(Result)-1] := pIPAddr^.IpAddress.S;
      pIPAddr := pIPAddr^.Next;
    end;
  finally
    FreeMem(pFI);
  end;
end;

function GetDNSServer:AnsiString;
var
  dnsserv : TDynStringArray;
begin
  dnsserv := GetDNSServers;
  if length(dnsserv)>0 then
    result := GetDNSServers[0]
  else
    result :='';
end;

//Get dns domain from global tcpip parameters in registry
function GetDNSDomain:AnsiString;
var
  reg:TRegistry;
begin
  reg := TRegistry.create;
  try
    reg.RootKey:=HKEY_LOCAL_MACHINE;
    if reg.OpenKeyReadOnly('SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters') then
    begin
      if reg.ValueExists('Domain') then
        Result := reg.ReadString('Domain');
      if Result='' then
        if reg.ValueExists('DhcpDomain') then
          Result := reg.ReadString('DhcpDomain');
    end;
  finally
    reg.Free;
  end;
end;

function WAPTServerJsonGet(action: String;args:Array of const): ISuperObject;
var
  strresult : String;
begin
  if GetWaptServerURL = '' then
    raise Exception.Create('wapt_server is not defined in your wapt-get.ini file');
  if StrLeft(action,1)<>'/' then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);
  strresult:=httpGetString(GetWaptServerURL+action);
  Result := SO(strresult);
end;

function WAPTLocalJsonGet(action: String): ISuperObject;
var
  strresult : String;
begin
  if StrLeft(action,1)<>'/' then
    action := '/'+action;
  strresult:=httpGetString(GetWaptLocalURL+action);
  Result := SO(strresult);
end;

function GetMainWaptRepo: String;
var
  resolv : TIdDNSResolver;
  rec : TResultRecord;
  i:integer;
  first : integer;
  ais : TAdapterInfo;

  dnsdomain,
  dnsserver:String;

begin
  result := IniReadString(WaptIniFilename,'Global','repo_url');
  if (Result <> '') then
    exit;

  if Get_EthernetAdapterDetail(ais) then
  begin
    for i:=0 to length(ais)-1 do
    with ais[i] do
      if (sIpAddress<>'') and (sIpMask<>'') and (dwType=MIB_IF_TYPE_ETHERNET) and (dwOperStatus>=MIB_IF_OPER_STATUS_CONNECTED) then begin
        Logger(bDescr+' '+sIpAddress+'/'+sIpMask+' mac:'+ais[i].bPhysAddr,INFO);
    end;
  end;

  dnsdomain:=GetDNSDomain;
  dnsserver:=GetDNSServer;

  if (dnsserver<>'') and (dnsdomain<>'') then
  try
    resolv := TIdDNSResolver.Create(Nil);
    try
      resolv.Host:=dnsserver;
      resolv.ClearInternalQuery;
      resolv.QueryType := [TQueryRecordTypes.qtService];
      resolv.WaitingTime:=400;
      resolv.Resolve('_wapt._tcp.'+dnsdomain+'.');
      first:=MaxInt;
      for i := 0 to resolv.QueryResult.count - 1 do
      begin
        rec := resolv.QueryResult.Items[i];
        if rec is TSRVRecord then
        with (rec as TSRVRecord) do begin
           if Priority<first then
           begin
             first := Priority;
             if Port=443 then
                Result := 'https://'+Target+':'+IntToStr(Port)+'/wapt'
             else
                Result := 'http://'+Target+':'+IntToStr(Port)+'/wapt';
           end;
        end;
      end;
    finally
      resolv.free;
    end;
  except
    on EIdDnsResolverError do
      Logger('SRV lookup failed',DEBUG)
    else
      Raise;
  end;
  Logger('trying '+result,INFO);
  if (Result='') or not  Wget_try(result) then
    result := '';
end;

function GetLDAPServer(dnsdomain:String=''): String;
var
  resolv : TIdDNSResolver;
  rec : TResultRecord;
  i:integer;
  highest : integer;
  ais : TAdapterInfo;

  dnsserver:String;

begin
  if dnsdomain='' then
    dnsdomain:=GetDNSDomain;

  dnsserver:=GetDNSServer;

  if (dnsserver<>'') and (dnsdomain<>'') then
  try
    resolv := TIdDNSResolver.Create(Nil);
    try
      resolv.Host:=dnsserver;
      resolv.ClearInternalQuery;
      resolv.QueryType := [TQueryRecordTypes.qtService];
      resolv.WaitingTime:=400;
      resolv.Resolve('_ldap._tcp.'+dnsdomain+'.');
      highest:=-1;
      for i := 0 to resolv.QueryResult.count - 1 do
      begin
        rec := resolv.QueryResult.Items[i];
        if rec is TSRVRecord then
        with (rec as TSRVRecord) do begin
           if Priority>highest then
           begin
             Highest := Priority;
             Result := Target+':'+IntToStr(Port);
           end;
        end;
      end;
    finally
      resolv.free;
    end;
  except
    on EIdDnsResolverError do
      Logger('SRV lookup failed',DEBUG)
    else
      Raise;
  end;
end;


function GetEthernetInfo(ConnectedOnly:Boolean):ISuperObject;
var
  i:integer;
  ais : TAdapterInfo;
  ao : ISuperObject;
begin
  result := TSuperObject.Create(stArray);
  if Get_EthernetAdapterDetail(ais) then
  begin
    for i:=0 to length(ais)-1 do
    with ais[i] do
      if  (dwType=MIB_IF_TYPE_ETHERNET) and (dwAdminStatus = MIB_IF_ADMIN_STATUS_UP) and
        (not ConnectedOnly  or ((dwOperStatus>=MIB_IF_OPER_STATUS_CONNECTED) and (sIpAddress<>'') and (sIpMask<>'')))then begin
      begin
        ao := TSuperObject.Create;
        ao.I['index'] :=  dwIndex;
        ao.S['type'] := Get_if_type(dwType);
        ao.I['mtu'] := dwMtu;
        ao.D['speed'] := dwSpeed;
        ao.S['mac'] := StringReplace(LowerCase(bPhysAddr),'-',':',[rfReplaceAll]);
        ao.S['adminStatus:'] := Get_if_admin_status(dwAdminStatus);
        ao.S['operStatus'] := Get_if_oper_status(dwOperStatus);
        ao.S['description'] :=  bDescr;
        ao.S['ipAddress'] := sIpAddress;
        ao.S['ipMask'] := sIpMask;
        result.AsArray.Add(ao);
      end;
    end;
  end;
end;

function GetWaptServerURL: String;
begin
  result := IniReadString(WaptIniFilename,'Global','wapt_server');
end;


function GetWaptRepoURL: Utf8String;
begin
  result := IniReadString(WaptIniFilename,'Global','repo_url');
  if Result = '' then
      Result:='http://wapt/wapt/';
end;


function GetWaptPrivateKey: String;
begin
  result := IniReadString(WaptIniFilename,'Global','private_key');
end;
function GetWaptLocalURL: String;
begin
  result := format('http://localhost:%d',[waptservice_port]);
end;

function WaptgetPath: Utf8String;
begin
  result := ExtractFilePath(ParamStr(0))+'\wapt-get.exe'
end;

function WaptservicePath: Utf8String;
begin
  result := ExtractFilePath(ParamStr(0))+'\waptservice.exe'
end;


function WaptIniFilename: Utf8String;
begin
  result := ExtractFilePath(ParamStr(0))+'\wapt-get.ini';
end;

function AppIniFilename: Utf8String;
begin
  result := GetAppConfigDir(False)+GetApplicationName+'.ini';
end;

function WaptDBPath: Utf8String;
begin
  Result := IniReadString(WaptIniFilename,'Global','dbdir');
  if Result<>'' then
    result :=  AppendPathDelim(result)+'waptdb.sqlite'
  else
    result := ExtractFilePath(ParamStr(0))+'\db\waptdb.sqlite'
end;

function WaptExternalRepo(inifilename:String=''): Utf8String;
begin
  if inifilename='' then
     inifilename:=AppIniFilename;
  Result := IniReadString(inifilename,'Global','templates_repo_url');
  if Result = '' then
      Result:='http://wapt.tranquil.it/wapt/';
end;

constructor Twaptdb.create(dbpath:String);
begin
  dbinuse := syncobjs.TCriticalSection.Create;

  // The sqlite dll is either in the same dir as application, or in the DLLs directory, or relative to dbpath (in case of initial install)
  if FileExists(AppendPathDelim(ExtractFilePath(ParamStr(0)))+'sqlite3.dll') then
    SQLiteLibraryName:=AppendPathDelim(ExtractFilePath(ParamStr(0)))+'sqlite3.dll'
  else if FileExists(AppendPathDelim(ExtractFilePath(ParamStr(0)))+'DLLs\sqlite3.dll') then
    SQLiteLibraryName:=AppendPathDelim(ExtractFilePath(ParamStr(0)))+'DLLs\sqlite3.dll'
  else if FileExists(AppendPathDelim(ExtractFilePath(dbpath))+'..\DLLs\sqlite3.dll') then
    SQLiteLibraryName:=AppendPathDelim(ExtractFilePath(dbpath))+'..\DLLs\sqlite3.dll';

  fsqltrans := TSQLTransaction.Create(Nil);
  fdb := TSQLite3Connection.Create(Nil);
  db.LoginPrompt := False;
  if not DirectoryExists(ExtractFileDir(dbpath)) then
    mkdir(ExtractFileDir(dbpath));
  db.DatabaseName := dbpath;
  db.KeepConnection := False;
  db.Transaction := SQLTrans;
  sqltrans.DataBase := db;

end;

destructor Twaptdb.Destroy;
begin
  try
    db.Close;
  finally
    dbinuse.Free;
    if Assigned(db) then
      db.free;
    if Assigned(sqltrans) then
      sqltrans.free;
  end;

  inherited Destroy;
end;

function TWAPTDB.Select(SQL: String): ISuperObject;
var
  query : TSQLQuery;
begin
  dbinuse.Acquire;
  try
    //db.Open;
    Query := TSQLQuery.Create(Nil);
    try
      Query.DataBase := db;
      Query.Transaction := sqltrans;

      Query.SQL.Text:=SQL;
      Query.Open;
      Result := Dataset2SO(Query);

    finally
      Query.Free;
      db.Close;
    end;
  finally
    dbinuse.Leave;
  end;
end;


function TWAPTDB.dumpdb: ISuperObject;
var
  tables:TStringList;
  i:integer;
begin
  dbinuse.Acquire;
  try
    Result := TSuperObject.Create;
    try
      tables := TStringList.Create;
      db.GetTableNames(tables);
      for i:=0 to tables.Count-1 do
        if tables[i] <> 'sqlite_sequence' then
          Result[tables[i]] := Select('select * from '+tables[i]);
    finally
      tables.Free;
    end;

  finally
    dbinuse.Release;
  end;
end;

procedure TWAPTDB.SetParam(name, value: String);
var
  q:TSQLQuery;
begin
  try
    dbinuse.Acquire;
    q := QueryCreate('insert or replace into wapt_params(name,value,create_date) values (:name,:value,:date)');
    try
      try
        q.ParamByName('name').AsString:=name;
        q.ParamByName('value').AsString:=value;
        q.ParamByName('date').AsString:=FormatDateTime('YYYYMMDD-hhnnss',Now);
        q.ExecSQL;
        sqltrans.Commit;
      except
        sqltrans.Rollback;
      end;
    finally
      q.Free;
    end;
  finally
    db.Close;
    dbinuse.Release;
  end;
end;

function TWAPTDB.GetParam(name: String): String;
var
  q:TSQLQuery;
begin
  try
    dbinuse.Acquire;
    result := '';
    q := QueryCreate('select value from wapt_params where name=:name');
    try
      try
        q.ParamByName('name').AsString:=name;
        q.open;
        Result := q.Fields[0].AsString;
        sqltrans.Commit;
      except
        sqltrans.Rollback;
      end;
    finally
      q.Free;
    end;

  finally
    db.Close;
    dbinuse.Release;
  end;
end;

function TWAPTDB.QueryCreate(SQL: String):TSQLQuery;
var
    ds:TSQLQuery;
begin
  ds := TSQLQuery.Create(Nil);
  ds.DataBase := db;
  ds.Transaction := sqltrans;
  ds.SQL.Text:=SQL;
  ds.ParseSQL:=True;
  ds.Open;
  result := ds;
end;

function TWAPTDB.QueryToHTMLtable(SQL: String;FormatHook: TFormatHook=Nil):String;
var
    ds:TSQLQuery;
    i:integer;
begin
  dbinuse.Acquire;
  try
    ds := TSQLQuery.Create(Nil);
    ds.DataBase := db;
    ds.Transaction := sqltrans;
    ds.SQL.Text:=SQL;
    ds.ParseSQL:=True;
    ds.Open;

    result := '<table><tr>';
    For i:=0 to ds.FieldCount-1 do
      if ds.Fields[i].Visible then
        Result := Result + '<th>'+ds.Fields[i].DisplayLabel+'</th>';
    result := Result+'</tr>';
    ds.First;
    while not ds.EOF do
    begin
      result := Result + '<tr>';
      For i:=0 to ds.FieldCount-1 do
        if ds.Fields[i].Visible then
        begin
          if Assigned(FormatHook) then
            Result := Result + '<td>'+FormatHook(ds,ds.Fields[i].AsString,ds.Fields[i].FieldName)+'</td>'
          else
            Result := Result + '<td>'+ds.Fields[i].AsString+'</td>';
        end;
      result := Result+'</tr>';
      ds.Next;
    end;
    result:=result+'</table>';
  finally
    db.Close;
    dbinuse.Release;
  end;
end;



//////

function VarArrayToStr(const vArray: variant): string;

    function _VarToStr(const V: variant): string;
    var
    Vt: integer;
    begin
    Vt := VarType(V);
        case Vt of
          varSmallint,
          varInteger  : Result := IntToStr(integer(V));
          varSingle,
          varDouble,
          varCurrency : Result := FloatToStr(Double(V));
          varDate     : Result := VarToStr(V);
          varOleStr   : Result := WideString(V);
          varBoolean  : Result := VarToStr(V);
          varVariant  : Result := VarToStr(Variant(V));
          varByte     : Result := char(byte(V));
          varString   : Result := String(V);
          varArray    : Result := VarArrayToStr(Variant(V));
        end;
    end;

var
i : integer;
begin
    Result := '[';
     if (VarType(vArray) and VarArray)=0 then
       Result := _VarToStr(vArray)
    else
    for i := VarArrayLowBound(vArray, 1) to VarArrayHighBound(vArray, 1) do
     if i=VarArrayLowBound(vArray, 1)  then
      Result := Result+_VarToStr(vArray[i])
     else
      Result := Result+'|'+_VarToStr(vArray[i]);

    Result:=Result+']';
end;

function VarStrNull(const V:OleVariant):string; //avoid problems with null strings
begin
  Result:='';
  if not VarIsNull(V) then
  begin
    if VarIsArray(V) then
       Result:=VarArrayToStr(V)
    else
    Result:=VarToStr(V);
  end;
end;

{function GetWMIObject(const objectName: String): IDispatch; //create the Wmi instance
var
  chEaten: PULONG;
  BindCtx: IBindCtx;
  Moniker: IMoniker;
begin
  OleCheck(CreateBindCtx(0, bindCtx));
  OleCheck(MkParseDisplayName(BindCtx, StringToOleStr(objectName), chEaten, Moniker));
  OleCheck(Moniker.BindToObject(BindCtx, nil, IDispatch, Result));
end;

function GetWin32_BIOSInfo:ISuperObject;
var
  objWMIService : OleVariant;
  colItems      : OleVariant;
  colItem       : Variant;
  oEnum,pEnum   : IEnumvariant;
  sValue        : string;
  p             : Variant;
  i:integer;
begin;
  Result := TSuperObject.Create;
  objWMIService := GetWMIObject('winmgmts:\\localhost\root\CIMV2');
  colItems      := objWMIService.ExecQuery('SELECT * FROM Win32_BIOS','WQL',0);
  oEnum         := IUnknown(colItems._NewEnum) as IEnumVariant;

  while oEnum.Next(1, colItem, nil) = 0 do
  begin
    Result.S['Manufacturer'] := VarStrNull(colItem.Properties_.Item('Manufacturer').Value);
    //Result.S['Manufacturer'] := VarStrNull(colItem.Properties_.Item('Manufacturer').Value);
    Result.S['SerialNumber'] := VarStrNull(colItem.Properties_.Item('SerialNumber').Value);
    colItem:=Unassigned;
  end;
end;

}

const
  CFormatIPMask = '%d.%d.%d.%d';

function GetLocalIP: string;
var
  I, VAttempt: Integer;
  VStrTemp, VSitesToTry: TStringList;
{$IFDEF UNIX}
  VProcess: TProcess;
{$ENDIF}
{$IFDEF MSWINDOWS}
var
  VWSAData: TWSAData;
  VHostEnt: PHostEnt;
  VName: string;
{$ENDIF}
begin
  Result := '';
{$IFDEF UNIX}
      VStrTemp := TStringList.Create;
      VProcess := TProcess.Create(nil);
      try
        VProcess.CommandLine :=
          'sh -c "ifconfig eth0 | awk ''/inet end/ {print $3}''"';
        VProcess.Options := [poWaitOnExit, poUsePipes];
        VProcess.Execute;
        VStrTemp.LoadFromStream(VProcess.Output);
        Result := Trim(VStrTemp.Text);
      finally
        VStrTemp.Free;
        VProcess.Free;
      end;
{$ENDIF}
{$IFDEF MSWINDOWS}
{$HINTS OFF}
      WSAStartup(2, VWSAData);
{$HINTS ON}
      SetLength(VName, 255);
      GetHostName(PChar(VName), 255);
      SetLength(VName, StrLen(PChar(VName)));
      VHostEnt := GetHostByName(PChar(VName));
      with VHostEnt^ do
        Result := Format(CFormatIPMask, [Byte(h_addr^[0]), Byte(h_addr^[1]),
          Byte(h_addr^[2]), Byte(h_addr^[3])]);
      WSACleanup;
{$ENDIF}
end;

procedure QuickSort(var A: Array of String);

procedure Sort(l, r: Integer);
var
  i, j,aux: integer;
  y,x:string;
begin
  i := l; j := r; x := a[(l+r) DIV 2];
  repeat
    while strIcomp(pchar(a[i]),pchar(x))<0 do i := i + 1;
    while StrIComp(pchar(x),pchar(a[j]))<0 do j := j - 1;
    if i <= j then
    begin

      y := a[i]; a[i] := a[j]; a[j] := y;
      i := i + 1; j := j - 1;
    end;
  until i > j;
  if l < j then Sort(l, j);
  if i < r then Sort(i, r);
end;

begin
  if length(A)>0 then
    Sort(Low(A),High(A));
end;

// Takes first (alphabetical) mac address of connected ethernet interface
function GetSystemUUID:String;
var
  eth,card : ISuperObject;
  macs: array of String;
  i:integer;
  guid : TGUID;
begin
  eth := GetEthernetInfo(True);
  i:=0;
  for card in eth do
  begin
    SetLength(macs,i+1);
    macs[i] := card.S['mac'];
    inc(i);
  end;
  if length(macs)>0 then
  begin
    QuickSort(macs);
    result := macs[0]
  end
  else
  begin
    CreateGUID(guid);
    result := UUIDToString(guid);
  end;
end;

function LocalSysinfo: ISUperObject;
var
      so:ISuperObject;
      //CPUInfo:TCpuInfo;
      Cmd,IPS:String;
      st : TStringList;
      waptdb:TWAPTDB;
begin
  so := TSuperObject.Create;
  //so.S['uuid'] := GetSystemUUID;
  so.S['workgroupname'] := GetWorkGroupName;
  so.S['localusername'] := tiscommon.GetUserName;
  so.S['computername'] :=  tiscommon.GetComputerName;
  so.S['workgroupname'] :=  tiscommon.GetWorkgroupName;
  so.S['domainname'] :=  tiscommon.GetDomainName;
  so.S['systemmanufacturer'] := GetSystemManufacturer;
  so.S['systemproductname'] := GetSystemProductName;
  so.S['biosversion'] := GetBIOSVersion;
  so.S['biosvendor'] := GetBIOSVendor;
  so.S['biosdate'] := GetBIOSDate;
  so['ethernet'] := GetEthernetInfo(false);
  so.S['ipaddress'] := GetLocalIP;
  so.S['waptget-version'] := GetApplicationVersion(WaptgetPath);
  so.S['waptservice-version'] := GetApplicationVersion(WaptservicePath);
  so.S['wapt-dbpath'] := WaptDBPath;

  waptdb := TWAPTDB.create(WaptDBPath);
  try
    so.S['wapt-dbversion'] := waptdb.GetParam('db_version');
  finally
    waptdb.Free;
  end;
  result := so;
end;

initialization
//  if not Succeeded(CoInitializeEx(nil, COINIT_MULTITHREADED)) then;
    //Raise Exception.Create('Unable to initialize ActiveX layer');

finalization
//  CoUninitialize();
end.

