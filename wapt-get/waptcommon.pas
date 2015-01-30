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
     Classes, SysUtils, Windows,
     DB,sqldb,sqlite3conn,SuperObject,syncobjs,IdComponent,tiscommon,tishttp, DefaultTranslator;

  Function  GetMainWaptRepo:String;
  Function  GetWaptServerURL:String;
  function GetWaptPrivateKeyPath: String;

  //function  GetLDAPServer(dnsdomain:String=''): String;

  function DNSAQuery(name:AnsiString):ISuperObject;
  function DNSSRVQuery(name:AnsiString):ISuperObject;
  function DNSCNAMEQuery(name:AnsiString):ISuperObject;

  Function  GetWaptLocalURL:String;


  function AppLocalDir: Utf8String; // returns Users/<user>/local/appdata/<application_name>
  function AppIniFilename: Utf8String; // returns Users/<user>/local/appdata/<application_name>/<application_name>.ini
  function WaptIniFilename: Utf8String; // for local wapt install directory

  function WaptBaseDir: Utf8String; // c:\wapt
  function WaptgetPath: Utf8String; // c:\wapt\wapt-get.exe
  function WaptservicePath: Utf8String;
  function WaptDBPath: Utf8String;
  function WaptTemplatesRepo(inifilename:String=''): Utf8String;
  function GetWaptRepoURL: Utf8String;

  function ReadWaptConfig(inifile:String = ''): Boolean;

  //function http_post(url: string;Params:String): String;

  function GetEthernetInfo(ConnectedOnly:Boolean):ISuperObject;
  function LocalSysinfo: ISuperObject;
  function GetLocalIP: string;
  function GetDNSServer:AnsiString;
  function GetDNSDomain:AnsiString;

  function WAPTServerJsonGet(action: String;args:Array of const; enableProxy:Boolean= False;user:AnsiString='';password:AnsiString=''): ISuperObject;
  function WAPTServerJsonPost(action: String;args:Array of const;data: ISuperObject; enableProxy:Boolean= False;user:AnsiString='';password:AnsiString=''): ISuperObject;
  function WAPTLocalJsonGet(action:String;user:AnsiString='';password:AnsiString='';timeout:integer=1000):ISuperObject;

  Function IdWget(const fileURL, DestFileName: Utf8String; CBReceiver:TObject=Nil;progressCallback:TProgressCallback=Nil;enableProxy:Boolean=False): boolean;
  Function IdWget_Try(const fileURL: Utf8String;enableProxy:Boolean=False): boolean;
  function IdHttpGetString(url: ansistring; enableProxy:Boolean= False;
      ConnectTimeout:integer=4000;SendTimeOut:integer=60000;ReceiveTimeOut:integer=60000;user:AnsiString='';password:AnsiString=''):RawByteString;
  function IdHttpPostData(const UserAgent: ansistring; const url: Ansistring; const Data: RawByteString; enableProxy:Boolean= False;
     ConnectTimeout:integer=4000;SendTimeOut:integer=60000;ReceiveTimeOut:integer=60000;user:AnsiString='';password:AnsiString=''):RawByteString;


  function RunAsAdmin(const Handle: Hwnd; aFile : Ansistring; Params: Ansistring): Boolean;

  function CreateSelfSignedCert(orgname,
          wapt_base_dir,
          destdir,
          country,
          locality,
          organization,
          orgunit,
          commonname,
          email:String
      ):String;

  function WAPTServerJsonMultipartFilePost(waptserver,action: String;args:Array of const;
      FileArg,FileName:String; enableProxy:Boolean= False;
      user:AnsiString='';password:AnsiString='';OnHTTPWork:TWorkEvent=Nil):ISuperObject;

  function CreateWaptSetup(default_public_cert:String='';default_repo_url:String='';
            default_wapt_server:String='';destination:String='';company:String='';OnProgress:TNotifyEvent = Nil;OverrideBaseName:String=''):String;

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

const
  waptservice_port:integer = 8088;
  waptserver_port:integer = 80;
  waptserver_ssl_port:integer = 443;
  zmq_port:integer = 5000;

  CacheWaptServerUrl: AnsiString = 'None';
  WaptServerUser: AnsiString ='admin';
  WaptServerPassword: Ansistring ='';
  HttpProxy:AnsiString = '';
  UseProxyForRepo: Boolean = False;
  UseProxyForServer: Boolean = False;
  UseProxyForTemplates: Boolean = False;

  Language:String = '';
  FallBackLanguage:String = '';

implementation

uses FileUtil, soutils, Variants, winsock, ShellApi, JwaIpHlpApi,
  JwaIpTypes, NetworkAdapterInfo, tisinifiles, registry, tisstrings, JwaWinDNS, JwaWinsock2,
  IdHttp,IdSSLOpenSSL,IdMultipartFormData,IdExceptionCore,IdException,Dialogs,Regex,UnitRedirect, IdURI,
  uwaptres,gettext;

function IPV42String(ipv4:LongWord):String;
begin
  Result :=  format('%D.%D.%D.%D',[ipv4  and $FF, (ipv4  shr 8) and $FF,  (ipv4  shr 16) and $FF, (ipv4  shr 24) and $FF]);
end;

function DNSAQuery(name: AnsiString): ISuperObject;
var
  resultname : PPWideChar;
  ppQueryResultsSet : PDNS_RECORD;
  retvalue: Integer;
  res : AnsiString;
  rec:ISuperObject;
begin
  Result := TSuperObject.Create(stArray);
  ppQueryResultsSet := Nil;
  retvalue := DnsQuery(
    PAnsiChar(name),
    DNS_TYPE_A,
    DNS_QUERY_BYPASS_CACHE,
    Nil,
    @ppQueryResultsSet,
    Nil);
  if (retvalue=0) and (ppQueryResultsSet<>Nil) then
  try
    while ppQueryResultsSet<>Nil do
    begin
      if (ppQueryResultsSet^.wType=DNS_TYPE_A) and (ppQueryResultsSet^.Data.A.IpAddress<>0) then
      begin
        res := IPV42String(ppQueryResultsSet^.Data.A.IpAddress);
        UniqueString(res);
        Result.AsArray.Add(res);
      end;
      ppQueryResultsSet:= ppQueryResultsSet^.pNext;
    end;
  finally
    DnsRecordListFree(ppQueryResultsSet,DnsFreeRecordList);
  end;
end;

//query current dns server for SRV record and return a list of {name,priority,weight,port}
function DNSSRVQuery(name:AnsiString):ISuperObject;
var
  resultname : PPWideChar;
  ppQueryResultsSet : PDNS_RECORD;
  retvalue: Integer;
  res : AnsiString;
  rec:ISuperObject;
begin
  Result := TSuperObject.Create(stArray);
  ppQueryResultsSet := Nil;
  retvalue := DnsQuery(
    PAnsiChar(name),
    DNS_TYPE_SRV,
    DNS_QUERY_BYPASS_CACHE,
    Nil,
    @ppQueryResultsSet,
    Nil);
  if (retvalue=0) and (ppQueryResultsSet<>Nil) then
  try
    while ppQueryResultsSet<>Nil do
    begin
      rec:= TSuperObject.Create(stObject);
      if ppQueryResultsSet^.wType=DNS_TYPE_SRV then
      begin
        res := ppQueryResultsSet^.Data.SRV.pNameTarget;
        UniqueString(res);
        rec.S['name'] := res;
        rec.I['port'] := ppQueryResultsSet^.Data.SRV.wPort;
        rec.I['priority'] := ppQueryResultsSet^.Data.SRV.wPriority;
        rec.I['weight'] := ppQueryResultsSet^.Data.SRV.wWeight;
        Result.AsArray.Add(rec);
      end;
      ppQueryResultsSet:= ppQueryResultsSet^.pNext;
    end;
    SortByFields(Result,['priority','port']);
  finally
    DnsRecordListFree(ppQueryResultsSet,DnsFreeRecordList);
  end;
end;

//query current dns server for CNAME record and return a list of {name}
function DNSCNAMEQuery(name:AnsiString):ISuperObject;
var
  resultname : PPWideChar;
  ppQueryResultsSet : PDNS_RECORD;
  retvalue: Integer;
  res : AnsiString;
  rec:ISuperObject;
begin
  Result := TSuperObject.Create(stArray);
  ppQueryResultsSet := Nil;
  retvalue := DnsQuery(
    PAnsiChar(name),
    DNS_TYPE_CNAME,
    DNS_QUERY_BYPASS_CACHE,
    Nil,
    @ppQueryResultsSet,
    Nil);
  if (retvalue=0) and (ppQueryResultsSet<>Nil) then
  try
    while ppQueryResultsSet<>Nil do
    begin
      if (ppQueryResultsSet^.wType=DNS_TYPE_CNAME) and (ppQueryResultsSet^.Data.PTR.pNameHost<>Nil) then
      begin
        res := ppQueryResultsSet^.Data.PTR.pNameHost;
        UniqueString(res);
        Result.AsArray.Add(res);
      end;
      ppQueryResultsSet:= ppQueryResultsSet^.pNext;
    end;
  finally
    DnsRecordListFree(ppQueryResultsSet,DnsFreeRecordList);
  end;
end;

// launch aFile with Params asking for a different user
function RunAsAdmin(const Handle: Hwnd; aFile : Ansistring; Params: Ansistring): Boolean;
var
  sei:  TSHELLEXECUTEINFO;
begin
  FillChar(sei, SizeOf(sei), 0);
  With sei do begin
     cbSize := SizeOf(sei);
     Wnd := Handle;
     //fMask := SEE_MASK_FLAG_DDEWAIT or SEE_MASK_FLAG_NO_UI;
     fMask := SEE_MASK_FLAG_DDEWAIT;
     lpVerb := 'runAs';
     lpFile := PAnsiChar(aFile);
     lpParameters := PAnsiChar(Params);
     nShow := SW_SHOWNORMAL;
  end;
  Result := ShellExecuteExA(@sei);
end;


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

procedure IdConfigureProxy(http:TIdHTTP;ProxyUrl:String);
var
  url : TIdURI;
begin
  url := TIdURI.Create(ProxyUrl);
  try
    if ProxyUrl<>'' then
    begin
      http.ProxyParams.BasicAuthentication:=url.Username<>'';
      http.ProxyParams.ProxyUsername:=url.Username;
      http.ProxyParams.ProxyPassword:=url.Password;
      http.ProxyParams.ProxyServer:=url.Host;
      http.ProxyParams.ProxyPort:=StrToInt(url.Port);
    end
    else
    begin
      http.ProxyParams.BasicAuthentication:=False;
      http.ProxyParams.ProxyUsername:='';
      http.ProxyParams.ProxyPassword:='';
      http.ProxyParams.ProxyServer:='';
    end;
  finally
    url.Free;
  end;
end;

type
  TIdProgressProxy=Class(TComponent)
  public
    status:String;
    current,total:Integer;
    CBReceiver:TObject;
    progressCallback:TProgressCallback;
    procedure OnWorkBegin(ASender: TObject; AWorkMode: TWorkMode; AWorkCountMax: Int64);
    procedure OnWork(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64);
  end;

procedure  TIdProgressProxy.OnWorkBegin(ASender: TObject; AWorkMode: TWorkMode; AWorkCountMax: Int64);
begin
  total := AWorkCountMax;
  current := 0;
  with (ASender as TIdHTTP) do
  begin
    if Assigned(progressCallback) then
      if not progressCallback(CBReceiver,current,total) then
        raise EHTTPException.Create('Download stopped by user',0);
  end;
end;

procedure TIdProgressProxy.OnWork(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64);
begin
  current := AWorkCount;
  with (ASender as TIdHTTP) do
  begin
    if Assigned(progressCallback) then
      if not progressCallback(CBReceiver,current,total) then
        raise EHTTPException.Create(rsDlStoppedByUser,0);
  end;
end;

function IdWget(const fileURL, DestFileName: Utf8String; CBReceiver: TObject;
  progressCallback: TProgressCallback; enableProxy: Boolean): boolean;
var
  http:TIdHTTP;
  OutputFile:TFileStream;
  progress : TIdProgressProxy;
  ssl: boolean;
  ssl_handler: TIdSSLIOHandlerSocketOpenSSL;

begin
  http := TIdHTTP.Create;
  http.HandleRedirects:=True;
  http.Request.AcceptLanguage := StrReplaceChar(Language,'_','-')+','+ FallBackLanguage;

  ssl := copy(fileURL, 1, length('https://')) = 'https://';
  if (ssl) then
  begin
    ssl_handler := TIdSSLIOHandlerSocketOpenSSL.Create;
	  HTTP.IOHandler := ssl_handler;
  end
  else
    ssl_handler := Nil;

  OutputFile :=TFileStream.Create(DestFileName,fmCreate);
  progress :=  TIdProgressProxy.Create(Nil);
  progress.progressCallback:=progressCallback;
  progress.CBReceiver:=CBReceiver;
  try
    try
      //http.ConnectTimeout := ConnectTimeout;
      if enableProxy then
        IdConfigureProxy(http,HttpProxy);
      if Assigned(progressCallback) then
      begin
        http.OnWorkBegin:=@progress.OnWorkBegin;
        http.OnWork:=@progress.OnWork;
      end;

      http.Get(fileURL,OutputFile);
      Result := True
    except
      on E:EIdReadTimeout do
      begin
        Result := False;
        FreeAndNil(OutputFile);
        if FileExists(DestFileName) then
          DeleteFileUTF8(DestFileName);
      end;
      on E:Exception do
      begin
        Result := False;
        FreeAndNil(OutputFile);
        if FileExists(DestFileName) then
          DeleteFileUTF8(DestFileName);
        raise;
      end;
    end;
  finally
    FreeAndNil(progress);
    if Assigned(OutputFile) then
      FreeAndNil(OutputFile);
    http.Free;
    if Assigned(ssl_handler) then
      FreeAndNil(ssl_handler);
  end;
end;

function IdWget_Try(const fileURL: Utf8String; enableProxy: Boolean): boolean;
var
  http:TIdHTTP;
  ssl: boolean;
  ssl_handler: TIdSSLIOHandlerSocketOpenSSL;

begin
  http := TIdHTTP.Create;
  http.HandleRedirects:=True;
  http.Request.AcceptLanguage := StrReplaceChar(Language,'_','-')+','+ FallBackLanguage;

  ssl := copy(fileUrl, 1, length('https://')) = 'https://';
  if (ssl) then
  begin
    ssl_handler := TIdSSLIOHandlerSocketOpenSSL.Create;
	  HTTP.IOHandler := ssl_handler;
  end
  else
    ssl_handler := Nil;


  try
    try
      http.ConnectTimeout := 1000;
      if enableProxy then
        IdConfigureProxy(http,HttpProxy);
      http.Head(fileURL);
      Result := True
    except
      on E:EIdReadTimeout do
      begin
        Result := False;
      end;
    end;
  finally
    http.Free;
    if Assigned(ssl_handler) then
      FreeAndNil(ssl_handler);
  end;
end;


function IdHttpGetString(url: ansistring; enableProxy:Boolean= False;
    ConnectTimeout:integer=4000;SendTimeOut:integer=60000;ReceiveTimeOut:integer=60000;user:AnsiString='';password:AnsiString=''):RawByteString;
var
  http:TIdHTTP;
  ssl: boolean;
  ssl_handler: TIdSSLIOHandlerSocketOpenSSL;
begin
  http := TIdHTTP.Create;
  http.HandleRedirects:=True;
  http.Request.AcceptLanguage := StrReplaceChar(Language,'_','-')+','+ FallBackLanguage;

  ssl := copy(url, 1, length('https://')) = 'https://';
  if (ssl) then
  begin
    ssl_handler := TIdSSLIOHandlerSocketOpenSSL.Create;
	  HTTP.IOHandler := ssl_handler;
  end
  else
    ssl_handler := Nil;

  try
    try
      http.ConnectTimeout:=ConnectTimeout;
      if user <>'' then
      begin
        http.Request.BasicAuthentication:=True;
        http.Request.Username:=user;
        http.Request.Password:=password;
      end;

      if enableProxy then
        IdConfigureProxy(http,HttpProxy);

      Result := http.Get(url);

    except
      on E:EIdReadTimeout do Result := '';
    end;
  finally
    http.Free;
    if Assigned(ssl_handler) then
      FreeAndNil(ssl_handler);
  end;
end;

function IdHttpPostData(const UserAgent: ansistring; const url: Ansistring; const Data: RawByteString; enableProxy:Boolean= False;
   ConnectTimeout:integer=4000;SendTimeOut:integer=60000;ReceiveTimeOut:integer=60000;user:AnsiString='';password:AnsiString=''):RawByteString;
var
  http:TIdHTTP;
  DataStream:TStringStream;
  progress : TIdProgressProxy;
  ssl: boolean;
  ssl_handler: TIdSSLIOHandlerSocketOpenSSL;

begin
  http := TIdHTTP.Create;
  http.HandleRedirects:=True;
  http.Request.AcceptLanguage := StrReplaceChar(Language,'_','-')+','+ FallBackLanguage;

  ssl := copy(url, 1, length('https://')) = 'https://';
  if (ssl) then
  begin
    ssl_handler := TIdSSLIOHandlerSocketOpenSSL.Create;
	  HTTP.IOHandler := ssl_handler;
  end
  else
    ssl_handler := Nil;


  DataStream :=TStringStream.Create(Data);
  {progress :=  TIdProgressProxy.Create(Nil);
  progress.progressCallback:=progressCallback;
  progress.CBReceiver:=CBReceiver;}
  try
    try
      http.ConnectTimeout := ConnectTimeout;
      if enableProxy then
        IdConfigureProxy(http,HttpProxy);
      {if Assigned(progressCallback) then
      begin
        http.OnWorkBegin:=@progress.OnWorkBegin;
        http.OnWork:=@progress.OnWork;
      end;}

      Result := http.Post(url,DataStream);
    except
      on E:EIdReadTimeout do
        Result := '';
    end;
  finally
    //FreeAndNil(progress);
    if Assigned(DataStream) then
      FreeAndNil(DataStream);
    http.Free;
    if Assigned(ssl_handler) then
      FreeAndNil(ssl_handler);
  end;
end;


function WAPTServerJsonGet(action: String; args: array of const;
  enableProxy: Boolean; user: AnsiString; password: AnsiString): ISuperObject;
var
  strresult : String;
begin
  if GetWaptServerURL = '' then
    raise Exception.CreateFmt(rsUndefWaptSrvInIni, [AppIniFilename]);
  if (StrLeft(action,1)<>'/') and (StrRight(GetWaptServerURL,1)<>'/') then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);
  strresult:=IdhttpGetString(GetWaptServerURL+action, enableProxy,4000,60000,60000,user,password);
  Result := SO(strresult);
end;

function WAPTServerJsonPost(action: String; args: array of const;
  data: ISuperObject; enableProxy: Boolean; user: AnsiString;
  password: AnsiString): ISuperObject;
var
  res:String;
begin
  if GetWaptServerURL = '' then
    raise Exception.CreateFmt(rsUndefWaptSrvInIni, [AppIniFilename]);
  if (StrLeft(action,1)<>'/') and (StrRight(GetWaptServerURL,1)<>'/') then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);
  res := IdhttpPostData('wapt', GetWaptServerURL+action, data.AsJson, enableProxy,4000,60000,60000,user,password);
  result := SO(res);
end;

function WAPTLocalJsonGet(action: String; user: AnsiString;
  password: AnsiString; timeout: integer): ISuperObject;
var
  strresult : String;
  http:TIdHTTP;
begin
  http := TIdHTTP.Create;
  try
    try
      http.Request.AcceptLanguage := StrReplaceChar(Language,'_','-')+','+ FallBackLanguage;
      http.ConnectTimeout:=timeout;
      if user <>'' then
      begin
        http.Request.BasicAuthentication:=True;
        http.Request.Username:=user;
        http.Request.Password:=password;
      end;

      if copy(action,length(action),1)<>'/' then
        action := '/'+action;


      strresult := http.Get(GetWaptLocalURL+action);
      Result := SO(strresult);

    except
      on E:EIdReadTimeout do Result := Nil;
    end;
  finally
    http.Free;
  end;
end;


function GetMainWaptRepo: String;
var
  i:integer;
  first : integer;
  ais : TAdapterInfo;

  dnsdomain,
  dnsserver:AnsiString;

  rec,recs : ISuperObject;
  wapthost:AnsiString;

begin
  result := IniReadString(AppIniFilename,'Global','repo_url');
  if (Result <> '') then
    exit;

  dnsdomain:=GetDNSDomain;

  //dnsserver:=GetDNSServer;
  if dnsdomain<>'' then
  begin
    //SRV _wapt._tcp
    recs := DNSSRVQuery('_wapt._tcp.'+dnsdomain);
    for rec in recs do
    begin
      if rec.I['port'] = 443 then
        Result := 'https://'+rec.S['name']+'/wapt'
      else
        Result := 'http://'+rec.S['name']+':'+rec.S['port']+'/wapt';
      Logger('trying '+result,INFO);
      if IdWget_try(result,UseProxyForRepo) then
        Exit;
    end;

    //CNAME wapt.
    recs := DNSCNAMEQuery('wapt'+dnsdomain);
    for rec in recs do
    begin
      Result := 'http://'+rec.AsString+'/wapt';
      Logger('trying '+result,INFO);
      if IdWget_try(result,UseProxyForRepo) then
        Exit;
    end;

    //A wapt
    Result := 'http://wapt.'+dnsdomain+'/wapt';
      Logger('trying '+result,INFO);
      if IdWget_try(result,UseProxyForRepo) then
        Exit;
  end;
  result :='';
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
var
  i:integer;
  first : integer;
  ais : TAdapterInfo;

  dnsdomain,
  dnsserver:AnsiString;

  rec,recs : ISuperObject;
  wapthost:AnsiString;

begin
  if CacheWaptServerUrl<>'None' then
  begin
    Result := CacheWaptServerUrl;
    Exit;
  end;

  if IniHasKey(AppIniFilename,'Global','wapt_server') then
  begin
    result := IniReadString(AppIniFilename,'Global','wapt_server');
    if (Result <> '') then
    begin
      CacheWaptServerUrl := Result;
      exit;
    end;
  end
  else
  begin
    // No waptserver at all
    CacheWaptServerUrl := '';
    result :='';
    Exit;
  end;


  dnsdomain:=GetDNSDomain;
  //dnsserver:=GetDNSServer;
  if dnsdomain<>'' then
  begin
    //SRV _wapt._tcp
    recs := DNSSRVQuery('_waptserver._tcp.'+dnsdomain);
    for rec in recs do
    begin
      if rec.I['port'] = 443 then
        Result := 'https://'+rec.S['name']
      else
        Result := 'http://'+rec.S['name']+':'+rec.S['port'];
      Logger('trying '+result,INFO);
      if IdWget_try(result,UseProxyForServer) then
      begin
        CacheWaptServerUrl := Result;
        exit;
      end;
    end;
  end;
  result :='';
  CacheWaptServerUrl := 'None';
end;

{
function GetWaptServerURL: String;
begin
  result := IniReadString(AppIniFilename,'Global','wapt_server');
end;
}

function GetWaptRepoURL: Utf8String;
begin
  result := IniReadString(AppIniFilename,'Global','repo_url');
  if Result = '' then
      Result:='http://wapt/wapt';
  if result[length(result)] = '/' then
    result := copy(result,1,length(result)-1);
end;


function GetWaptPrivateKeyPath: String;
begin
  result := IniReadString(AppIniFilename,'Global','private_key');
end;
function GetWaptLocalURL: String;
begin
  result := format('http://127.0.0.1:%d',[waptservice_port]);
end;

function WaptBaseDir: Utf8String;
begin
  result := ExtractFilePath(ParamStr(0));
end;

function WaptgetPath: Utf8String;
begin
  result := ExtractFilePath(ParamStr(0))+'wapt-get.exe'
end;

function WaptservicePath: Utf8String;
begin
  result := ExtractFilePath(ParamStr(0))+'waptservice.exe'
end;

function AppLocalDir: Utf8String;
begin
  result := GetAppConfigDir(False);
end;

function AppIniFilename: Utf8String;
begin
  result := GetAppConfigDir(False)+GetApplicationName+'.ini';
end;

function WaptIniFilename: Utf8String;
begin
  result := ExtractFilePath(ParamStr(0))+'wapt-get.ini';
end;

function ReadWaptConfig(inifile:String = ''): Boolean;
begin
  if inifile='' then
    inifile:=WaptIniFilename;
  if not FileExistsUTF8(inifile) then
    Result := False
  else
  begin
    waptservice_port := IniReadInteger(inifile,'global','waptservice_port',8088);
    FallBackLanguage := IniReadString(inifile,'global','language','');
    if FallBackLanguage ='' then
        GetLanguageIDs(Language,FallBackLanguage);

    waptserver_port := IniReadInteger(inifile,'global','waptserver_port',80);
    waptserver_ssl_port := IniReadInteger(inifile,'global','waptserver_sslport',443);
    zmq_port := IniReadInteger(inifile,'global','zmq_port',5000);

    HttpProxy := IniReadString(inifile,'global','http_proxy','');
    UseProxyForRepo := IniReadBool(inifile,'global','use_http_proxy_for_repo',False);
    UseProxyForServer := IniReadBool(inifile,'global','use_http_proxy_for_server',False);
    UseProxyForTemplates := IniReadBool(inifile,'global','use_http_proxy_for_remplates',False);
    Result := True
  end;
end;

function WaptDBPath: Utf8String;
begin
  Result := IniReadString(AppIniFilename,'Global','dbdir');
  if Result<>'' then
    result :=  AppendPathDelim(result)+'waptdb.sqlite'
  else
    result := ExtractFilePath(ParamStr(0))+'db\waptdb.sqlite'
end;


function WaptTemplatesRepo(inifilename:String=''): Utf8String;
begin
  if inifilename='' then
     inifilename:=AppIniFilename;
  Result := IniReadString(inifilename,'Global','templates_repo_url');
  if Result = '' then
      Result:='http://wapt.tranquil.it/wapt/';
end;



function WaptUseLocalConnectionProxy(inifilename:String=''): Boolean;
begin
  if inifilename='' then
     inifilename:=AppIniFilename;
  Result := StrIsOneOf(IniReadString (inifilename,'Global','use_local_connection_proxy'),['True','true','1'] );
end;

constructor TWAPTDB.create(dbpath:String);
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

destructor TWAPTDB.Destroy;
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

function LocalSysinfo: ISuperObject;
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

// qad %(key)s python format
function pyformat(template:String;params:ISuperobject):String;
var
  key,value:ISuperObject;
begin
  Result := template;
  for key in params.AsObject.GetNames do
    Result := StringReplace(Result,'%('+key.AsString+')s',params.S[key.AsString],[rfReplaceAll]);
end;

function WAPTServerJsonMultipartFilePost(waptserver, action: String;
  args: array of const; FileArg, FileName: String; enableProxy: Boolean;
  user: AnsiString; password: AnsiString; OnHTTPWork: TWorkEvent): ISuperObject;
var
  res:String;
  http:TIdHTTP;
  ssl: boolean;
  ssl_handler: TIdSSLIOHandlerSocketOpenSSL;
  St:TIdMultiPartFormDataStream;
begin
  if StrLeft(action,1)<>'/' then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);
  http := TIdHTTP.Create;
  http.Request.AcceptLanguage := StrReplaceChar(Language,'_','-')+','+ FallBackLanguage;

  ssl := copy(waptserver, 1, length('https://')) = 'https://';
  if (ssl) then
  begin
    ssl_handler := TIdSSLIOHandlerSocketOpenSSL.Create(nil);
	  http.IOHandler := ssl_handler;
  end
  else
    ssl_handler := Nil;

  St := TIdMultiPartFormDataStream.Create;
  try
    http.Request.BasicAuthentication:=True;
    http.Request.Username:=user;
    http.Request.Password:=password;
    http.OnWork:=OnHTTPWork;

    St.AddFile(FileArg,FileName);
    try
      res := HTTP.Post(waptserver+action,St);
    except
      on E:EIdException do ShowMessage(E.Message);
    end;
    result := SO(res);
  finally
    st.Free;
    HTTP.Free;
    if assigned(ssl_handler) then
	    ssl_handler.Free;
  end;
end;

function CreateSelfSignedCert(orgname,
        wapt_base_dir,
        destdir,
        country,
        locality,
        organization,
        orgunit,
        commonname,
        email:String
    ):String;
var
  opensslbin,opensslcfg,opensslcfg_fn,destpem,destcrt : String;
  params : ISuperObject;
begin
    destpem := AppendPathDelim(destdir)+orgname+'.pem';
    destcrt := AppendPathDelim(destdir)+orgname+'.crt';
    if not DirectoryExists(destdir) then
        mkdir(destdir);
    params := TSuperObject.Create;
    params.S['country'] := country;
    params.S['locality'] :=locality;
    params.S['organization'] := organization;
    params.S['unit'] := orgunit;
    params.S['commonname'] := commonname;
    params.S['email'] := email;

    opensslbin :=  AppendPathDelim(wapt_base_dir)+'lib\site-packages\M2Crypto\openssl.exe';
    opensslcfg :=  pyformat(FileToString(AppendPathDelim(wapt_base_dir) + 'templates\openssl_template.cfg'),params);
    opensslcfg_fn := AppendPathDelim(destdir)+'openssl.cfg';
    StringToFile(opensslcfg_fn,opensslcfg);
    try
      SetEnvironmentVariable(PAnsiChar('OPENSSL_CONF'),PAnsiChar(opensslcfg_fn));
      if ExecuteProcess(opensslbin,'req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout "'+destpem+'" -out "'+destcrt+'"',[]) <> 0 then
        result :=''
      else
        result := destpem;
    finally
      SysUtils.DeleteFile(opensslcfg_fn);
    end;
end;

function CreateWaptSetup(default_public_cert:String='';default_repo_url:String='';
          default_wapt_server:String='';destination:String='';company:String='';OnProgress:TNotifyEvent = Nil;OverrideBaseName:String=''):String;
var
  OutputFile,iss_template,custom_iss,source,target,outputname,junk : String;
  iss,new_iss,line : ISuperObject;
  wapt_base_dir,inno_fn: String;
  re : TRegexEngine;
  exitstatus:integer;

  function startswith(st:ISuperObject;subst:String):Boolean;
  begin
    result := (st <>Nil) and (st.DataType = stString) and (pos(subst,trim(st.AsString))=1)
  end;

begin
    wapt_base_dir:= WaptBaseDir;
    OutputFile := '';
    iss_template := wapt_base_dir + '\waptsetup' + '\waptsetup.iss';
    custom_iss := wapt_base_dir + '\' + 'waptsetup' + '\' + 'custom_waptsetup.iss';
    iss := SplitLines(FileToString(iss_template));
    new_iss := TSuperObject.Create(stArray);
    for line in iss do
    begin
        if startswith(line,'#define default_repo_url') then
            new_iss.AsArray.Add(format('#define default_repo_url "%s"',[default_repo_url]))
        else if startswith(line,'#define default_wapt_server') then
            new_iss.AsArray.Add(format('#define default_wapt_server "%s"',[default_wapt_server]))
        else if startswith(line,'#define output_dir') then
            new_iss.AsArray.Add(format('#define output_dir "%s"' ,[destination]))
        else if startswith(line,'WizardImageFile=') then

        else if startswith(line,'OutputBaseFilename') then
            begin
                if length(OverrideBaseName) <> 0 then
                    outputname := OverrideBaseName
                else
                    StrSplit(line.AsString,'=',outputname,junk)
                ;
                outputfile := wapt_base_dir + '\' + 'waptsetup' + '\' + outputname + '.exe';
                new_iss.AsArray.Add(format('OutputBaseFilename=%s' ,[outputname]));
            end
        else if not startswith(line,'#define signtool') then
            new_iss.AsArray.Add(line)
        ;
    end;

    source := default_public_cert;
    target := ExtractFileDir(iss_template) + '..' + 'ssl' + ExtractFileName(source);
    if not FileExists(target) then
      if not FileUtil.CopyFile(source,target,True) then
        raise Exception.CreateFmt(rsCertificateCopyFailure,[source,target]);
    StringToFile(custom_iss,SOUtils.Join(#13#10,new_iss));

    inno_fn :=  wapt_base_dir + '\waptsetup' + '\innosetup' + '\ISCC.exe';
    if not FileExists(inno_fn) then
        raise Exception.CreateFmt(rsInnoSetupUnavailable, [inno_fn]);
    Sto_RedirectedExecute(format('"%s"  %s',[inno_fn,custom_iss]),'',3600000,'','','',OnProgress);
    Result := destination + '\' + outputname + '.exe';
end;



initialization
//  if not Succeeded(CoInitializeEx(nil, COINIT_MULTITHREADED)) then;
    //Raise Exception.Create('Unable to initialize ActiveX layer');
   if not ReadWaptConfig then
      GetLanguageIDs(Language,FallBackLanguage);

finalization
//  CoUninitialize();
end.

