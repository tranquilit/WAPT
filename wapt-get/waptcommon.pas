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
     SuperObject,IdComponent,tiscommon,tisstrings, DefaultTranslator;

  type
      TProgressCallback=function(Receiver:TObject;current,total:Integer):Boolean of object;
      TLoginCallback = function(realm:String;var user,password:String):Boolean of object;

      { EHTTPException }

      EHTTPException=Class(Exception)
        HTTPStatus: Integer;
        constructor Create(const msg: string;AHTTPStatus:Integer);
      end;

  function GetWaptPrivateKeyPath: String;

  Function GetWaptLocalURL:String;

  function AppLocalDir: Utf8String; // returns Users/<user>/local/appdata/<application_name>
  function AppIniFilename: Utf8String; // returns Users/<user>/local/appdata/<application_name>/<application_name>.ini
  function WaptIniFilename: Utf8String; // for local wapt install directory

  function WaptBaseDir: Utf8String; // c:\wapt
  function WaptgetPath: Utf8String; // c:\wapt\wapt-get.exe
  function WaptservicePath: Utf8String; //c:\wapt\waptservice.exe # obsolete
  function WaptDBPath: Utf8String;
  function WaptTemplatesRepo(inifilename:String=''): Utf8String; // http://wapt.tranquil.it/wapt/

  function GetWaptRepoURL: Utf8String; // from wapt-get.ini, can be empty
  Function GetMainWaptRepo:String;   // read from ini, if empty, do a discovery using dns
  Function GetWaptServerURL:String;  // read ini. if no wapt_server key -> return '', return value in inifile or perform a DNS discovery

  function ReadWaptConfig(inifile:String = ''): Boolean; //read global parameters from wapt-get ini file

  function GetEthernetInfo(ConnectedOnly:Boolean):ISuperObject;
  function LocalSysinfo: ISuperObject;
  function GetLocalIP: string;

  function WAPTServerJsonGet(action: String;args:Array of const): ISuperObject; //use global credentials and proxy settings
  function WAPTServerJsonPost(action: String;args:Array of const;data: ISuperObject): ISuperObject; //use global credentials and proxy settings
  function WAPTLocalJsonGet(action:String;user:AnsiString='';password:AnsiString='';timeout:integer=1000):ISuperObject;

  Function IdWget(const fileURL, DestFileName: Utf8String; CBReceiver:TObject=Nil;progressCallback:TProgressCallback=Nil;enableProxy:Boolean=False): boolean;
  Function IdWget_Try(const fileURL: Utf8String;enableProxy:Boolean=False): boolean;
  function IdHttpGetString(const url: ansistring; enableProxy:Boolean= False;
      ConnectTimeout:integer=4000;SendTimeOut:integer=60000;ReceiveTimeOut:integer=60000;user:AnsiString='';password:AnsiString=''):RawByteString;
  function IdHttpPostData(const url: Ansistring; const Data: RawByteString; enableProxy:Boolean= False;
     ConnectTimeout:integer=4000;SendTimeOut:integer=60000;ReceiveTimeOut:integer=60000;user:AnsiString='';password:AnsiString=''):RawByteString;

  function GetReachableIP(IPS:ISuperObject;port:word):String;

  //return ip for waptservice
  function WaptServiceReachableIP(UUID:String;hostdata:ISuperObject=Nil):String;

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
      FileArg,FileName:String;
      user:AnsiString='';password:AnsiString='';OnHTTPWork:TWorkEvent=Nil):ISuperObject;

  function CreateWaptSetup(default_public_cert:String='';default_repo_url:String='';
            default_wapt_server:String='';destination:String='';company:String='';OnProgress:TNotifyEvent = Nil;OverrideBaseName:String=''):String;

const
  waptservice_port:integer = 8088;
  waptservice_sslport:integer = -1;
  waptserver_port:integer = 80;
  waptserver_sslport:integer = 443;
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

  WAPTServerMinVersion='1.2.3';

implementation

uses FileUtil, soutils, Variants,uwaptres,waptwinutils,tisinifiles,tislogging,
  NetworkAdapterInfo, JwaWinsock2,
  IdHttp,IdSSLOpenSSL,IdMultipartFormData,IdExceptionCore,IdException,IdURI,
  gettext,IdStack;


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

  { HTTPException }

  constructor EHTTPException.Create(const msg: string; AHTTPStatus: Integer);
  begin
    inherited Create(msg);
    HTTPStatus:=AHTTPStatus;
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
  http.Request.UserAgent:=ApplicationName+'/'+GetApplicationVersion+' '+http.Request.UserAgent;

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
  http.Request.UserAgent:=ApplicationName+'/'+GetApplicationVersion+' '+http.Request.UserAgent;

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
        Result := False;
      on E:EIdSocketError do
        Result := False;
    end;
  finally
    http.Free;
    if Assigned(ssl_handler) then
      FreeAndNil(ssl_handler);
  end;
end;


function IdHttpGetString(const url: ansistring; enableProxy:Boolean= False;
    ConnectTimeout:integer=4000;SendTimeOut:integer=60000;ReceiveTimeOut:integer=60000;user:AnsiString='';password:AnsiString=''):RawByteString;
var
  http:TIdHTTP;
  ssl: boolean;
  ssl_handler: TIdSSLIOHandlerSocketOpenSSL;
begin
  http := TIdHTTP.Create;
  http.HandleRedirects:=True;
  http.Request.AcceptLanguage := StrReplaceChar(Language,'_','-')+','+ FallBackLanguage;
  http.Request.UserAgent:=ApplicationName+'/'+GetApplicationVersion+' '+http.Request.UserAgent;

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

function IdHttpPostData(const url: Ansistring; const Data: RawByteString; enableProxy:Boolean= False;
   ConnectTimeout:integer=4000;SendTimeOut:integer=60000;ReceiveTimeOut:integer=60000;user:AnsiString='';password:AnsiString=''):RawByteString;
var
  http:TIdHTTP;
  DataStream:TStringStream;
  ssl: boolean;
  ssl_handler: TIdSSLIOHandlerSocketOpenSSL;

begin
  http := TIdHTTP.Create;
  http.HandleRedirects:=True;
  http.Request.AcceptLanguage := StrReplaceChar(Language,'_','-')+','+ FallBackLanguage;
  http.Request.UserAgent:=ApplicationName+'/'+GetApplicationVersion+' '+http.Request.UserAgent;

  ssl := copy(url, 1, length('https://')) = 'https://';
  if (ssl) then
  begin
    ssl_handler := TIdSSLIOHandlerSocketOpenSSL.Create;
	  http.IOHandler := ssl_handler;
  end
  else
    ssl_handler := Nil;

  if user <>'' then
  begin
    http.Request.BasicAuthentication:=True;
    http.Request.Username:=user;
    http.Request.Password:=password;
  end;

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


function WAPTServerJsonGet(action: String; args: array of const): ISuperObject;
var
  strresult : String;
begin
  if GetWaptServerURL = '' then
    raise Exception.CreateFmt(rsUndefWaptSrvInIni, [AppIniFilename]);
  if (StrLeft(action,1)<>'/') and (StrRight(GetWaptServerURL,1)<>'/') then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);
  strresult:=IdhttpGetString(GetWaptServerURL+action,UseProxyForServer,4000,60000,60000,waptServerUser, waptServerPassword);
  Result := SO(strresult);
end;

function WAPTServerJsonPost(action: String; args: array of const;
  data: ISuperObject): ISuperObject;
var
  res:String;
begin
  if GetWaptServerURL = '' then
    raise Exception.CreateFmt(rsUndefWaptSrvInIni, [AppIniFilename]);
  if (StrLeft(action,1)<>'/') and (StrRight(GetWaptServerURL,1)<>'/') then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);
  res := IdhttpPostData(GetWaptServerURL+action, data.AsJson, UseProxyForServer,4000,60000,60000,WaptServerUser,WaptServerPassword);
  result := SO(res);
end;

function WAPTLocalJsonGet(action: String; user: AnsiString;
  password: AnsiString; timeout: integer): ISuperObject;
var
  url,strresult : String;
  http:TIdHTTP;
  ssl: boolean;
  ssl_handler: TIdSSLIOHandlerSocketOpenSSL;


begin
  http := TIdHTTP.Create;
  try
    try
      http.Request.AcceptLanguage := StrReplaceChar(Language,'_','-')+','+ FallBackLanguage;
      http.Request.UserAgent:=ApplicationName+'/'+GetApplicationVersion+' '+http.Request.UserAgent;
      http.ConnectTimeout:=timeout;

      if user <>'' then
      begin
        http.Request.BasicAuthentication:=True;
        http.Request.Username:=user;
        http.Request.Password:=password;
      end;

      if copy(action,length(action),1)<>'/' then
        action := '/'+action;

      url := GetWaptLocalURL+action;
      ssl := copy(url, 1, length('https://')) = 'https://';
      if (ssl) then
      begin
        ssl_handler := TIdSSLIOHandlerSocketOpenSSL.Create;
    	  HTTP.IOHandler := ssl_handler;
      end
      else
        ssl_handler := Nil;


      strresult := http.Get(url);
      Result := SO(strresult);

    except
      on E:EIdReadTimeout do Result := Nil;
    end;
  finally
    http.Free;
  end;
end;

function SameNet(connected:ISuperObject;IP:AnsiString):Boolean;
var
  conn:ISuperObject;
begin
  for conn in Connected do
  begin
    if SameIPV4Subnet(conn.S['ipAddress'],IP,conn.S['ipMask']) then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

function GetMainWaptRepo: String;
var
  rec,recs,ConnectedIps,ServerIp : ISuperObject;
  url,dnsdomain:AnsiString;

begin
  result := IniReadString(AppIniFilename,'Global','repo_url','');
  if (Result <> '') then
    exit;

  dnsdomain:=GetDNSDomain;
  if dnsdomain<>'' then
  begin
    ConnectedIps := GetEthernetInfo(True);

    //SRV _wapt._tcp
    recs := DNSSRVQuery('_wapt._tcp.'+dnsdomain);
    for rec in recs do
    begin
      if rec.I['port'] = 443 then
        url := 'https://'+rec.S['name']+'/wapt'
      else
        url := 'http://'+rec.S['name']+':'+rec.S['port']+'/wapt';
      rec.S['url'] := url;
      try
        ServerIp := DNSAQuery(rec.S['name']);
        if ServerIp.AsArray.Length > 0 then
          rec.B['outside'] := not SameNet(ConnectedIps,ServerIp.AsArray.S[0])
        else
          rec.B['outside'] := True;
      except
        rec.B['outside'] := True;
      end;
      // order is priority asc but wieght desc
      rec.I['weight'] := - rec.I['weight'];
    end;
    SortByFields(recs,['outside','priority','weight']);

    for rec in recs do
    begin
      Logger('trying '+rec.S['url'],INFO);
      if IdWget_try(rec.S['url'],UseProxyForRepo) then
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


function GetWaptServerURL: string;
var
  dnsdomain, url: ansistring;
  rec, recs, ConnectedIps, ServerIp: ISuperObject;

begin
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

  if CacheWaptServerUrl<>'None' then
  begin
    Result := CacheWaptServerUrl;
    Exit;
  end;

  ConnectedIps := NetworkConfig;
  dnsdomain := GetDNSDomain;
  if dnsdomain <> '' then
  begin
    //SRV _wapt._tcp
    recs := DNSSRVQuery('_waptserver._tcp.' + dnsdomain);
    for rec in recs do
    begin
      if rec.I['port'] = 443 then
        url := 'https://' + rec.S['name']
      else
        url := 'http://' + rec.S['name'] + ':' + rec.S['port'];
      rec.S['url'] := url;
      try
        ServerIp := DNSAQuery(rec.S['name']);
        if ServerIp.AsArray.Length > 0 then
          rec.B['outside'] := not SameNet(ConnectedIps, ServerIp.AsArray.S[0])
        else
          rec.B['outside'] := True;
      except
        rec.B['outside'] := True;
      end;
      // order is priority asc but wieght desc
      rec.I['weight'] := -rec.I['weight'];
    end;
    SortByFields(recs, ['outside', 'priority', 'weight']);

    for rec in recs do
    begin
      Result := rec.S['url'];
      CacheWaptServerUrl := Result;
      exit;
    end;
  end;

  //None found by DNS Query
  Result := '';
  //Invalid cache
  CacheWaptServerUrl := 'None';
end;


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
  if waptservice_port >0 then
      result := format('http://127.0.0.1:%d',[waptservice_port])
  else
  if waptservice_sslport >0 then
      result := format('https://127.0.0.1:%d',[waptservice_sslport]);
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
  result := GetAppConfigDir(False)+ApplicationName+'.ini';
end;

function WaptIniFilename: Utf8String;
begin
  result := ExtractFilePath(ParamStr(0))+'wapt-get.ini';
end;

function ReadWaptConfig(inifile:String = ''): Boolean;
var
  i: Integer;
begin
  if inifile='' then
    inifile:=WaptIniFilename;
  if not FileExistsUTF8(inifile) then
    Result := False
  else
  begin
    waptservice_port := IniReadInteger(inifile,'global','waptservice_port',-1);
    waptservice_sslport := IniReadInteger(inifile,'global','waptservice_sslport',-1);
    if (waptservice_port<=0) and (waptservice_sslport<=0) then
      waptservice_port := 8088;

    // override lang setting
    for i := 1 to Paramcount - 1 do
      if (ParamStrUTF8(i) = '--LANG') or (ParamStrUTF8(i) = '-l') or
        (ParamStrUTF8(i) = '--lang') then
        begin
          Language := ParamStrUTF8(i + 1);
          FallBackLanguage := copy(ParamStrUTF8(i + 1),1,2);
        end;

    if Language = '' then
    begin
      Language := IniReadString(inifile,'global','language','');       ;
      FallBackLanguage := copy(Language,1,2);
      if FallBackLanguage ='' then
          GetLanguageIDs(Language,FallBackLanguage);
    end;

    waptserver_port := IniReadInteger(inifile,'global','waptserver_port',80);
    waptserver_sslport := IniReadInteger(inifile,'global','waptserver_sslport',443);
    zmq_port := IniReadInteger(inifile,'global','zmq_port',5000);

    HttpProxy := IniReadString(inifile,'global','http_proxy','');
    UseProxyForRepo := IniReadBool(inifile,'global','use_http_proxy_for_repo',False);
    UseProxyForServer := IniReadBool(inifile,'global','use_http_proxy_for_server',False);
    UseProxyForTemplates := IniReadBool(inifile,'global','use_http_proxy_for_templates',False);
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
{$IFDEF UNIX}
  VProcess: TProcess;
{$ENDIF}
{$IFDEF MSWINDOWS}
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
  i, j: integer;
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
  result := so;
end;

// qad %(key)s python format
function pyformat(template:String;params:ISuperobject):String;
var
  key:ISuperObject;
begin
  Result := template;
  for key in params.AsObject.GetNames do
    Result := StringReplace(Result,'%('+key.AsString+')s',params.S[key.AsString],[rfReplaceAll]);
end;

function WAPTServerJsonMultipartFilePost(waptserver, action: String;
  args: array of const; FileArg, FileName: String;
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
  http.Request.UserAgent:=ApplicationName+'/'+GetApplicationVersion+' '+http.Request.UserAgent;

  if UseProxyForServer then
    IdConfigureProxy(http,HttpProxy);

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
      on E:EIdException do raise;
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
  iss_template,custom_iss,source,target,outputname,junk : String;
  iss,new_iss,line : ISuperObject;
  wapt_base_dir,inno_fn: String;

  function startswith(st:ISuperObject;subst:String):Boolean;
  begin
    result := (st <>Nil) and (st.DataType = stString) and (pos(subst,trim(st.AsString))=1)
  end;

begin
    wapt_base_dir:= WaptBaseDir;
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
                new_iss.AsArray.Add(format('OutputBaseFilename=%s' ,[outputname]));
            end
        else if not startswith(line,'#define signtool') then
            new_iss.AsArray.Add(line)
        ;
    end;

    source := default_public_cert;
    target := ExtractFileDir(iss_template) + '  \..\ssl\' + ExtractFileName(source);
    if not FileExists(target) then
      if not FileUtil.CopyFile(source,target,True) then
        raise Exception.CreateFmt(rsCertificateCopyFailure,[source,target]);
    StringToFile(custom_iss,SOUtils.Join(#13#10,new_iss));

    inno_fn :=  wapt_base_dir + '\waptsetup' + '\innosetup' + '\ISCC.exe';
    if not FileExists(inno_fn) then
        raise Exception.CreateFmt(rsInnoSetupUnavailable, [inno_fn]);
    Run(format('"%s"  %s',[inno_fn,custom_iss]),'',3600000,'','','',OnProgress);
    Result := destination + '\' + outputname + '.exe';
end;



function GetReachableIP(IPS:ISuperObject;port:word):String;
var
  IP:ISuperObject;
begin
  Result :='';
  if (IPS=Nil) or (IPS.DataType=stNull) then
    Result := ''
  else
  if (IPS.DataType=stString) then
  begin
    if CheckOpenPort(port,IPS.AsString,1000) then
      Result := IPS.AsString
    else
      Result := '';
  end
  else
  if IPS.DataType=stArray then
  begin
    for IP in IPS do
    begin
      if CheckOpenPort(port,IP.AsString,1000) then
      begin
        Result := IP.AsString;
        Break;
      end;
    end;
  end;
end;


//Check on which IP:port the waptservice is reachable for machine UUID
function WaptServiceReachableIP(UUID:String;hostdata:ISuperObject=Nil): String;
var
  wapt_listening_address,IP_Port:ISuperObject;
begin
  Result :='';
  // try to get from hostdata
  if (hostdata<>Nil) and (hostdata.S['uuid'] = UUID) then
  begin
    wapt_listening_address := hostdata['wapt.listening_address.address'];
    if (wapt_listening_address<>Nil) and (wapt_listening_address.AsString<>'') then
      result := format('%s:%s',[hostdata.S['wapt.listening_address.address'],hostdata.S['wapt.listening_address.port']]);
  end;
  if result = '' then
  begin
    // no hostdata, ask the server.
    IP_Port := WAPTServerJsonGet('host_reachable_ip/uuid=%s',[UUID]);
    result := format('%s:%s',[IP_Port.AsArray.S[0],IP_Port.AsArray.S[1]]);
  end;
end;



initialization
//  if not Succeeded(CoInitializeEx(nil, COINIT_MULTITHREADED)) then;
    //Raise Exception.Create('Unable to initialize ActiveX layer');
   if not ReadWaptConfig then
      GetLanguageIDs(Language,FallBackLanguage);

finalization
//  CoUninitialize();
end.

