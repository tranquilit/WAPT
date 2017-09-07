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
     SuperObject,IdComponent,IdHttp,IdCookieManager,DefaultTranslator;

  type
      TProgressCallback=function(Receiver:TObject;current,total:Integer):Boolean of object;
      TLoginCallback = function(realm:String;var user,password:String):Boolean of object;

      { EHTTPException }

      EHTTPException=Class(Exception)
        HTTPStatus: Integer;
        constructor Create(const msg: string;AHTTPStatus:Integer);
      end;

  function GetWaptPersonalCertificatePath: Utf8String;

  Function GetWaptLocalURL:String;

  function AppLocalDir: Utf8String; // returns Users/<user>/local/appdata/<application_name>
  function AppIniFilename: Utf8String; // returns Users/<user>/local/appdata/<application_name>/<application_name>.ini
  function WaptIniFilename: Utf8String; // for local wapt install directory

  function WaptBaseDir: Utf8String; // c:\wapt
  function WaptgetPath: Utf8String; // c:\wapt\wapt-get.exe
  function WaptservicePath: Utf8String; //c:\wapt\waptservice.exe # obsolete
  function WaptDBPath: Utf8String;

  function GetWaptRepoURL: Utf8String; // from wapt-get.ini, can be empty
  Function GetMainWaptRepo:String;   // read from ini, if empty, do a discovery using dns
  Function GetWaptServerURL:String;  // read ini. if no wapt_server key -> return '', return value in inifile or perform a DNS discovery

  function GetWaptServerCertificateFilename(inifilename:AnsiString=''):AnsiString;

  function ReadWaptConfig(inifilename:String = ''): Boolean; //read global parameters from wapt-get ini file

  function GetEthernetInfo(ConnectedOnly:Boolean):ISuperObject;
  function LocalSysinfo: ISuperObject;
  function GetLocalIP: Ansistring;

  //call url action on waptserver. action can contains formatting chars like %s which will be replaced by args with the Format function.
  function WAPTServerJsonGet(action: String;args:Array of const;method:AnsiString='GET';ConnectTimeout:integer=4000;SendTimeout:integer=60000;ReceiveTimeout:integer=60000): ISuperObject; //use global credentials and proxy settings
  function WAPTServerJsonPost(action: String;args:Array of const;data: ISuperObject;ConnectTimeout:integer=4000;SendTimeout:integer=60000;ReceiveTimeout:integer=60000): ISuperObject; //use global credentials and proxy settings
  function WAPTLocalJsonGet(action:String;user:AnsiString='';password:AnsiString='';timeout:integer=1000;OnAuthorization:TIdOnAuthorization=Nil;RetryCount:Integer=3):ISuperObject;

  Function IdWget(const fileURL, DestFileName: Utf8String; CBReceiver:TObject=Nil;progressCallback:TProgressCallback=Nil;enableProxy: Boolean=False;userAgent:String='';VerifyCertificateFilename:String='';CookieManage:TIdCookieManager=Nil): boolean;
  Function IdWget_Try(const fileURL: Utf8String;enableProxy:Boolean=False;userAgent:String='';VerifyCertificateFilename:String='';CookieManage:TIdCookieManager=Nil): boolean;
  function IdHttpGetString(const url: ansistring; enableProxy:Boolean= False;
      ConnectTimeout:integer=4000;
      SendTimeOut:integer=60000;
      ReceiveTimeOut:integer=60000;
      user:AnsiString='';password:AnsiString='';
      method:AnsiString='GET';userAGent:String='';
      VerifyCertificateFilename:String='';AcceptType:String='application/json';
      CookieManager:TIdCookieManager=Nil):RawByteString;

  function IdHttpPostData(const url: Ansistring; const Data: RawByteString; enableProxy:Boolean= False;
      ConnectTimeout:integer=4000;SendTimeOut:integer=60000;
      ReceiveTimeOut:integer=60000;
      user:AnsiString='';password:AnsiString='';userAgent:String='';
      ContentType:String='application/json';
      VerifyCertificateFilename:String='';AcceptType:String='application/json';
      CookieManager:TIdCookieManager=Nil):RawByteString;

  function GetReachableIP(IPS:ISuperObject;port:word):String;

  //return ip for waptservice
  function WaptServiceReachableIP(UUID:String;hostdata:ISuperObject=Nil):String;

  function WAPTServerJsonMultipartFilePost(waptserver,action: String;args:Array of const;
      FileArg,FileName:String;
      user:AnsiString='';password:AnsiString='';OnHTTPWork:TWorkEvent=Nil;VerifyCertificateFilename:String=''):ISuperObject;

  function CreateWaptSetup(default_public_cert:Utf8String='';default_repo_url:Utf8String='';
            default_wapt_server:Utf8String='';destination:Utf8String='';company:Utf8String='';OnProgress:TNotifyEvent = Nil;OverrideBaseName:Utf8String='';
            VerifyCert:Utf8String='0'; UseKerberos:Boolean=False; CheckCertificatesValidity:Boolean=True):Utf8String;

  function pyformat(template:String;params:ISuperobject):String;
  function pyformat(template:Utf8String;params:ISuperobject):Utf8String; overload;

  function CARoot:String;

  function CreateSelfSignedCert(keyfilename,
          crtbasename,
          wapt_base_dir,
          destdir,
          country,
          locality,
          organization,
          orgunit,
          commonname,
          email,
          keypassword:Utf8String;
          codesigning:Boolean
      ):Utf8String;

// get
function GetWaptServerSession(server_url:String = ''; user:String = '';password:String = ''):TIdCookieManager;

function DefaultUserAgent:String;

const
  waptwua_enabled : boolean = False;

  waptservice_port:integer = 8088;
  waptservice_sslport:integer = -1;
  waptserver_port:integer = 80;
  waptserver_sslport:integer = 443;
  zmq_port:integer = 5000;
  waptservice_timeout:integer = 2;

  WaptServerUser: AnsiString ='admin';
  WaptServerPassword: Ansistring ='';
  WaptServerUUID: AnsiString ='';

  // active session until user or password is changed
  WaptServerSession: TIdCookieManager = Nil;

  HttpProxy:AnsiString = '';
  UseProxyForRepo: Boolean = False;
  UseProxyForServer: Boolean = False;

  Language:String = '';
  FallBackLanguage:String = '';

  DefaultPackagePrefix:String = '';
  DefaultSourcesRoot:String = '';

  AuthorizedCertsDir:Utf8String = '';

  TemplatesRepoUrl:String = 'https://store.wapt.fr/wapt';

  AdvancedMode:Boolean = False;

  WAPTServerMinVersion='1.5.0.11';

implementation

uses LazFileUtils, LazUTF8, soutils, Variants,uwaptres,waptwinutils,tisinifiles,tislogging,
  NetworkAdapterInfo, JwaWinsock2,
  IdSSLOpenSSL,IdMultipartFormData,IdExceptionCore,IdException,IdURI,
  gettext,IdStack,IdCompressorZLib,sha1,IdAuthentication,shfolder,IniFiles,tiscommon,tisstrings, RxStrUtils;

const
  CacheWaptServerUrl: AnsiString = 'None';
  wapt_config_filename : Utf8String = '';

function DefaultUserAgent:String;
begin
  Result := ApplicationName+'/'+GetApplicationVersion;
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

function GetHostFromURL(url:AnsiString):AnsiString;
var
  uri : TIdURI;
begin
  uri := TIdURI.Create(url);
  try
    Result := uri.Host;
  finally
    uri.Free;
  end;
end;

type
  TSSLVerifyCert = class(TObject)
    hostname:AnsiString;
    constructor Create(ahostname:AnsiString);
    function VerifypeerCertificate(Certificate: TIdX509; AOk: Boolean; ADepth, AError: Integer): Boolean;
  end;

constructor TSSLVerifyCert.Create(ahostname:AnsiString);
var
  sslCheck:TSSLVerifyCert;
begin
  hostname:=ahostname;
end;

function TSSLVerifyCert.VerifypeerCertificate(Certificate: TIdX509; AOk: Boolean; ADepth, AError: Integer): Boolean;
var
  Subject,SubjectAlternativeName:String;
  CNPart,token,att,value:String;
  cnpos:Integer;
begin
  Subject := Certificate.Subject.OneLine;
  if ADepth = 0 then
  begin
    while Subject<>'' do
    begin
      token := StrToken(Subject,'/');
      att := Copy(token,1,pos('=',token)-1);
      value := Copy(token,pos('=',token)+1,255);
      if LowerCase(att) = 'cn' then
      begin
        CNPart := value;
        break;
      end;
    end;
    {SubjectAlternativeName := Certificate.SubjectAlternativeName ;
    cnpos  := pos('/cn=',LowerCase(SubjectAlternativeName))+Length('/cn=');
    CNPart := Copy(LowerCase(s),cnpos,255);}

    //check subject is hostname
    Result := AOk and IsWild(hostname,CNPart,True);

  end
  else
    Result := AOk;
end;

function GetSSLIOHandler(ForUrl:String;CAPath:String = 'C:\tranquilit\wapt\lib\site-packages\certifi\cacert.pem';ServerCert:String=''):TIdSSLIOHandlerSocketOpenSSL;
var
  sslCheck:TSSLVerifyCert;
begin
  Result := TIdSSLIOHandlerSocketOpenSSL.Create;
  Result.SSLOptions.Method:=sslvSSLv23;
  Result.SSLOptions.VerifyDirs:=CAPath;

  sslCheck := TSSLVerifyCert.Create(GetHostFromURL(ForUrl));

  // init check of https server certificate
  if (ServerCert<>'') and (ServerCert <>'0') then
  begin
    Result.SSLOptions.VerifyMode:=[sslvrfPeer];
    Result.OnVerifyPeer:=@sslCheck.VerifypeerCertificate;
    //Self signed
    if (CAPath='') or (ServerCert<>'1') then
    begin
      Result.SSLOptions.RootCertFile := ServerCert;
      //Result.SSLOptions.CertFile := ServerCert;
    end
    else
    begin
      if DirectoryExists(CAPath) then
        Result.SSLOptions.VerifyDirs := CAPath
      else
        Result.SSLOptions.RootCertFile := CAPath;
      //Result.SSLOptions.CertFile := ServerCert;
      Result.SSLOptions.VerifyDepth := 20;
    end
  end;
end;

function IdWget(const fileURL, DestFileName: Utf8String; CBReceiver: TObject;
  progressCallback: TProgressCallback; enableProxy: Boolean=False;userAgent:String='';  VerifyCertificateFilename:String='';CookieManage:TIdCookieManager=Nil): boolean;
var
  http:TIdHTTP;
  OutputFile:TFileStream;
  progress : TIdProgressProxy;
  ssl_handler: TIdSSLIOHandlerSocketOpenSSL;
  sslCheck:TSSLVerifyCert;

begin
  sslCheck:=Nil;
  ssl_handler:=Nil;

  http := TIdHTTP.Create;
  http.HandleRedirects:=True;
  http.Request.AcceptLanguage := StrReplaceChar(Language,'_','-')+','+ FallBackLanguage;

  if userAgent='' then
    http.Request.UserAgent := DefaultUserAgent
  else
    http.Request.UserAgent := userAgent;

  http.Request.BasicAuthentication:=True;

  OutputFile :=TFileStream.Create(DestFileName,fmCreate);
  progress :=  TIdProgressProxy.Create(Nil);
  progress.progressCallback:=progressCallback;
  progress.CBReceiver:=CBReceiver;
  try
    // init ssl stack
    ;
    ssl_handler := TIdSSLIOHandlerSocketOpenSSL.Create;
    ssl_handler.SSLOptions.Method:=sslvSSLv23;

  	HTTP.IOHandler := ssl_handler;
    sslCheck := TSSLVerifyCert.Create(GetHostFromURL(fileurl));


    if (VerifyCertificateFilename<>'') and (VerifyCertificateFilename <>'0') then
    begin
      ssl_handler.SSLOptions.VerifyDepth:=20;
      ssl_handler.SSLOptions.VerifyMode:=[sslvrfPeer];
      ssl_handler.OnVerifyPeer:=@sslCheck.VerifypeerCertificate;
      //Self signed
      if VerifyCertificateFilename<>'1' then
      begin
        ssl_handler.SSLOptions.RootCertFile :=VerifyCertificateFilename;
        //ssl_handler.SSLOptions.CertFile := VerifyCertificateFilename;
      end
      else
      begin
        if DirectoryExists(CARoot) then
          ssl_handler.SSLOptions.VerifyDirs := CARoot
        else
          ssl_handler.SSLOptions.RootCertFile := CARoot;
        //ssl_handler.SSLOptions.CertFile := '';
      end
    end;

    try
      //http.ConnectTimeout := ConnectTimeout;
      if HttpProxy<>'' then
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
    if Assigned(sslCheck) then
      FreeAndNil(sslCheck);
  end;
end;

function IdWget_Try(const fileURL: Utf8String; enableProxy: Boolean;userAgent:String='';VerifyCertificateFilename:String='';CookieManage:TIdCookieManager=Nil): boolean;
var
  http:TIdHTTP;
  ssl_handler: TIdSSLIOHandlerSocketOpenSSL;
  sslCheck:TSSLVerifyCert;
begin
  sslCheck:=Nil;
  ssl_handler:=Nil;

  http := TIdHTTP.Create;
  http.HandleRedirects:=True;
  http.Request.AcceptLanguage := StrReplaceChar(Language,'_','-')+','+ FallBackLanguage;
  if userAgent='' then
    http.Request.UserAgent := DefaultUserAgent
  else
    http.Request.UserAgent := userAgent;

  try
    // init ssl stack
    ssl_handler := TIdSSLIOHandlerSocketOpenSSL.Create;
    ssl_handler.SSLOptions.Method:=sslvSSLv23;

  	HTTP.IOHandler := ssl_handler;
    sslCheck := TSSLVerifyCert.Create(GetHostFromURL(fileurl));

    if (VerifyCertificateFilename<>'') and (VerifyCertificateFilename <>'0') then
    begin
      ssl_handler.SSLOptions.VerifyDepth:=20;
      ssl_handler.SSLOptions.VerifyMode:=[sslvrfPeer];
      ssl_handler.OnVerifyPeer:=@sslCheck.VerifypeerCertificate;
      //Self signed
      if VerifyCertificateFilename<>'1' then
      begin
        ssl_handler.SSLOptions.RootCertFile :=VerifyCertificateFilename;
        //ssl_handler.SSLOptions.CertFile := VerifyCertificateFilename;
      end
      else
      begin
        if DirectoryExists(CARoot) then
          ssl_handler.SSLOptions.VerifyDirs := CARoot
        else
          ssl_handler.SSLOptions.RootCertFile := CARoot;
        //ssl_handler.SSLOptions.CertFile := '';
      end
    end;

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
    if Assigned(sslCheck) then
      FreeAndNil(sslCheck);
  end;
end;

function IdHttpGetString(const url: ansistring; enableProxy:Boolean= False;
    ConnectTimeout:integer=4000;SendTimeOut:integer=60000;ReceiveTimeOut:integer=60000;user:AnsiString='';password:AnsiString='';method:AnsiString='GET';userAGent:String='';VerifyCertificateFilename:String='';
    AcceptType:String='application/json';CookieManager:TIdCookieManager=Nil):RawByteString;
var
  http:TIdHTTP;
  ssl_handler: TIdSSLIOHandlerSocketOpenSSL;
  sslCheck:TSSLVerifyCert;
begin
  sslCheck:=Nil;
  ssl_handler:=Nil;

  http := TIdHTTP.Create;
  http.HandleRedirects:=True;
  http.Request.AcceptLanguage := StrReplaceChar(Language,'_','-')+','+ FallBackLanguage;
  if userAgent='' then
    http.Request.UserAgent := DefaultUserAgent
  else
    http.Request.UserAgent := userAgent;

  http.compressor :=  TIdCompressorZLib.Create(Nil);

  if CookieManager<>Nil then
    http.CookieManager := CookieManager;

  try
    // init ssl stack
    ssl_handler := TIdSSLIOHandlerSocketOpenSSL.Create;
    ssl_handler.SSLOptions.Method:=sslvSSLv23;

    http.IOHandler := ssl_handler;
    sslCheck := TSSLVerifyCert.Create(GetHostFromURL(url));

    http.Request.Accept := AcceptType;

    if (VerifyCertificateFilename<>'') and (VerifyCertificateFilename <>'0') then
    begin
      ssl_handler.SSLOptions.VerifyDepth:=20;
      ssl_handler.SSLOptions.VerifyMode:=[sslvrfPeer];
      ssl_handler.OnVerifyPeer:=@sslCheck.VerifypeerCertificate;
      //Self signed
      if VerifyCertificateFilename<>'1' then
      begin
        ssl_handler.SSLOptions.RootCertFile :=VerifyCertificateFilename;
        //ssl_handler.SSLOptions.CertFile := VerifyCertificateFilename;
      end
      else
      begin
        if DirectoryExists(CARoot) then
          ssl_handler.SSLOptions.VerifyDirs := CARoot
        else
          ssl_handler.SSLOptions.RootCertFile := CARoot;
        //ssl_handler.SSLOptions.CertFile := '';
      end
    end;

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

      if method = 'GET' then
        Result := http.Get(url)
      else if method = 'DELETE' then
        Result := http.Delete(url)
      else raise Exception.CreateFmt('Unsupported method %s',[method]);

    except
      on E:EIdReadTimeout do Result := '';
    end;
  finally
    if Assigned(http.Compressor) then
    begin
      http.Compressor.Free;
      http.Compressor := Nil;
    end;
    http.Free;
    if Assigned(ssl_handler) then
      FreeAndNil(ssl_handler);
    if Assigned(sslCheck) then
      FreeAndNil(sslCheck);
  end;
end;

function IdHttpPostData(const url: Ansistring; const Data: RawByteString; enableProxy:Boolean= False;
   ConnectTimeout:integer=4000;SendTimeOut:integer=60000;ReceiveTimeOut:integer=60000;user:AnsiString='';password:AnsiString='';userAgent:String='';ContentType:String='application/json';VerifyCertificateFilename:String='';
   AcceptType:String='application/json';CookieManager:TIdCookieManager=Nil):RawByteString;
var
  http:TIdHTTP;
  DataStream:TStringStream;
  ssl_handler: TIdSSLIOHandlerSocketOpenSSL;
  sslCheck:TSSLVerifyCert;
  compressor: TIdCompressorZLib;

begin
  sslCheck:=Nil;
  ssl_handler:=Nil;

  http := TIdHTTP.Create;
  http.HandleRedirects:=True;
  http.Compressor := TIdCompressorZLib.Create;

  if CookieManager<>Nil then
    http.CookieManager := CookieManager;

  http.Request.AcceptLanguage := StrReplaceChar(Language,'_','-')+','+ FallBackLanguage;
  if userAgent='' then
    http.Request.UserAgent := DefaultUserAgent
  else
    http.Request.UserAgent := userAgent;

  http.Request.ContentType:=ContentType;
  http.Request.ContentEncoding:='UTF-8';

  http.Request.Accept:=AcceptType;

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
    // init ssl stack
    ssl_handler := TIdSSLIOHandlerSocketOpenSSL.Create;
    ssl_handler.SSLOptions.Method:=sslvSSLv23;

    HTTP.IOHandler := ssl_handler;
    sslCheck := TSSLVerifyCert.Create(GetHostFromURL(url));

    if (VerifyCertificateFilename<>'') and (VerifyCertificateFilename <>'0') then
    begin
      ssl_handler.SSLOptions.VerifyDepth:=20;
      ssl_handler.SSLOptions.VerifyMode:=[sslvrfPeer];
      ssl_handler.OnVerifyPeer:=@sslCheck.VerifypeerCertificate;
      //Self signed
      if VerifyCertificateFilename<>'1' then
      begin
        ssl_handler.SSLOptions.RootCertFile :=VerifyCertificateFilename;
        //ssl_handler.SSLOptions.CertFile := VerifyCertificateFilename;
      end
      else
      begin
        if DirectoryExists(CARoot) then
          ssl_handler.SSLOptions.VerifyDirs := CARoot
        else
          ssl_handler.SSLOptions.RootCertFile := CARoot;
        //ssl_handler.SSLOptions.CertFile := '';
      end
    end;

    try
      http.ConnectTimeout := ConnectTimeout;
      if enableProxy then
        IdConfigureProxy(http,HttpProxy);
      {if Assigned(progressCallback) then
      begin
        http.OnWorkBegin:=@progress.OnWorkBegin;
        http.OnWork:=@progress.OnWork;
      end;}

      Result := http.Post(url,DataStream)
    except
      on E:EIdReadTimeout do
        Result := '';
    end;
  finally
    //FreeAndNil(progress);
    if Assigned(DataStream) then
      FreeAndNil(DataStream);
    if Assigned(http.Compressor) then
    begin
      http.Compressor.Free;
      http.Compressor := Nil;
    end;
    http.Free;
    if Assigned(ssl_handler) then
      FreeAndNil(ssl_handler);
    if Assigned(sslCheck) then
      FreeAndNil(sslCheck);
  end;
end;


function WAPTServerJsonGet(action: String; args: array of const;method:AnsiString='GET';
    ConnectTimeout:integer=4000;SendTimeout:integer=60000;ReceiveTimeout:integer=60000): ISuperObject;
var
  strresult : String;
begin
  if GetWaptServerURL = '' then
    raise Exception.CreateFmt(rsUndefWaptSrvInIni, [WaptIniFilename]);
  if (StrLeft(action,1)<>'/') and (StrRight(GetWaptServerURL,1)<>'/') then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);
  strresult:=IdhttpGetString(GetWaptServerURL+action,UseProxyForServer,ConnectTimeout,SendTimeout ,ReceiveTimeout,
    waptServerUser,waptServerPassword,method,'',GetWaptServerCertificateFilename,'application/json',GetWaptServerSession());
  Result := SO(strresult);
end;

function WAPTServerJsonDelete(action: String; args: array of const): ISuperObject;
var
  strresult : String;
begin
  if GetWaptServerURL = '' then
    raise Exception.CreateFmt(rsUndefWaptSrvInIni, [WaptIniFilename]);
  if (StrLeft(action,1)<>'/') and (StrRight(GetWaptServerURL,1)<>'/') then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);
  strresult:=IdhttpGetString(GetWaptServerURL+action,UseProxyForServer,4000,60000,60000,waptServerUser, waptServerPassword,
    'DELETE','',GetWaptServerCertificateFilename,'application/json',GetWaptServerSession());
  Result := SO(strresult);
end;

function WAPTServerJsonPost(action: String; args: array of const;
  data: ISuperObject;ConnectTimeout:integer=4000;SendTimeout:integer=60000;ReceiveTimeout:integer=60000): ISuperObject;
var
  res:String;
begin
  if GetWaptServerURL = '' then
    raise Exception.CreateFmt(rsUndefWaptSrvInIni, [WaptIniFilename]);
  if (StrLeft(action,1)<>'/') and (StrRight(GetWaptServerURL,1)<>'/') then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);
  res := IdhttpPostData(GetWaptServerURL+action, data.AsJson, UseProxyForServer,ConnectTimeout,SendTimeout,ReceiveTimeout,
    WaptServerUser,WaptServerPassword,'','application/json',GetWaptServerCertificateFilename,'application/json',GetWaptServerSession());
  result := SO(res);
end;

function WAPTLocalJsonGet(action: String; user: AnsiString;
  password: AnsiString; timeout: integer;OnAuthorization:TIdOnAuthorization=Nil;RetryCount:Integer=3): ISuperObject;
var
  url,strresult : String;
  http:TIdHTTP;
  ssl_handler: TIdSSLIOHandlerSocketOpenSSL;
begin
  ssl_handler := Nil;
  http := TIdHTTP.Create;
  try
    try
      http.Request.AcceptLanguage := StrReplaceChar(Language,'_','-')+','+ FallBackLanguage;
      http.Request.UserAgent := DefaultUserAgent;
      http.ConnectTimeout := timeout;
      http.ReadTimeout:=timeout;

      if (user<>'') or (OnAuthorization <> Nil) then
      begin
        http.Request.Authentication := TIdBasicAuthentication.Create;
        http.Request.Authentication.Username:=user;
        http.Request.Authentication.Password:=password;
        http.MaxAuthRetries := 2;
        http.OnAuthorization:=OnAuthorization;
      end;

      if copy(action,length(action),1)<>'/' then
        action := '/'+action;

      url := GetWaptLocalURL+action;
      ssl_handler := TIdSSLIOHandlerSocketOpenSSL.Create;
      ssl_handler.SSLOptions.Method:=sslvSSLv23;

      HTTP.IOHandler := ssl_handler;
      strresult := '';
      repeat
        try
          strresult := http.Get(url);
        except
          Sleep(1000);
          Dec(RetryCount);
          if (RetryCount<=0) then
            raise;
        end;
      until (strresult<>'') or (RetryCount<=0);
      Result := SO(strresult);

    except
      on E:EIdReadTimeout do Result := Nil;
    end;
  finally
    http.Free;
    if Assigned(ssl_handler) then
      FreeAndNil(ssl_handler);
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
  result := IniReadString(WaptIniFilename,'Global','repo_url','');
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
      Result := rec.S['url'];
      Logger('trying '+Result,INFO);
      if IdWget_try(Result,UseProxyForRepo,'','0') then
        Exit;
    end;

    //CNAME wapt.
    recs := DNSCNAMEQuery('wapt'+dnsdomain);
    for rec in recs do
    begin
      Result := 'http://'+rec.AsString+'/wapt';
      Logger('trying '+result,INFO);
      if IdWget_try(result,UseProxyForRepo,'','0') then
        Exit;
    end;

    //A wapt
    Result := 'http://wapt.'+dnsdomain+'/wapt';
      Logger('trying '+result,INFO);
      if IdWget_try(result,UseProxyForRepo,'','0') then
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
  dnsdomain, url: ansistring;
  rec, recs, ConnectedIps, ServerIp: ISuperObject;

begin
  if CacheWaptServerUrl<>'None' then
  begin
    Result := CacheWaptServerUrl;
    Exit;
  end;

  if IniHasKey(WaptIniFilename,'Global','wapt_server') then
  begin
    result := IniReadString(WaptIniFilename,'Global','wapt_server');
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
  result := IniReadString(WaptIniFilename,'Global','repo_url');
  if Result = '' then
      Result:='http://wapt/wapt';
  if result[length(result)] = '/' then
    result := copy(result,1,length(result)-1);
end;


function GetWaptPersonalCertificatePath: Utf8String;
begin
  result := utf8Decode(IniReadString(WaptIniFilename,'Global','personal_certificate_path'));
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
  result := ExtractFilePath(ParamStrUtf8(0))+'wapt-get.exe'
end;

function WaptservicePath: Utf8String;
begin
  result := ExtractFilePath(ParamStrUtf8(0))+'waptservice.exe'
end;

function GetSpecialFolderPath(folder : integer) : widestring;
const
  SHGFP_TYPE_CURRENT = 0;
var
  path: array [0..MAX_PATH] of widechar;
begin
  if SUCCEEDED(SHGetFolderPathW(0,folder,0,SHGFP_TYPE_CURRENT, @path[0])) then
    Result := IncludeTrailingPathDelimiter(path)
  else
    Result := '';
end;

function AppLocalDir: Utf8String;
begin
  //Result :=  IncludeTrailingPathDelimiter(UTF16ToUTF8(GetSpecialFolderPath(CSIDL_LOCAL_APPDATA)))+ApplicationName;
  result := AnsiToUtf8(GetAppConfigDir(False));
end;

function AppIniFilename: Utf8String;
begin
  //Result :=  IncludeTrailingPathDelimiter(IncludeTrailingPathDelimiter(GetSpecialFolderPath(CSIDL_LOCAL_APPDATA))+ApplicationName)+ApplicationName+'.ini';
  result := AnsiToUtf8(GetAppConfigDir(False))+ApplicationName+'.ini';
end;

function WaptIniFilename: Utf8String;
begin
  if wapt_config_filename = '' then
      wapt_config_filename := ExtractFilePath(ParamStrUTF8(0))+'wapt-get.ini';
  result :=  wapt_config_filename;
end;

function GetWaptServerCertificateFilename(inifilename:AnsiString=''): AnsiString;
begin
  if inifilename='' then
     inifilename:=WaptIniFilename;
  Result := IniReadString(inifilename,'global','verify_cert','');
  if (Result <> '') and not FileExists(Result) then
  begin
    if StrIsOneOf(Result,['0','false','no',''],False) then
      Result := '0'
    else
      if StrIsOneOf(Result,['1','true','yes'],False) then
        Result := '1';
  end;
  If Result = '' then
    Result := '1';
end;

// Read Wapt config from inifile, set global const wapt_config_filename
// if inifile is empty, read from result of WaptIniFilename (wapt_config_filename if set, appinifile if exists, else wapt-get.ini)
function ReadWaptConfig(inifilename:String = ''): Boolean;
var
  i: Integer;
  inifile: TIniFile;
begin
  // reset cache
  CacheWaptServerUrl := 'None';

  if inifilename='' then
    inifilename:=WaptIniFilename;

  if (inifilename<>'') then
    wapt_config_filename := inifilename;

  if not FileExistsUTF8(inifilename) then
    Result := False
  else
  with TIniFile.Create(inifilename) do
  try
    waptservice_port := ReadInteger('global','waptservice_port',-1);
    waptservice_sslport := ReadInteger('global','waptservice_sslport',-1);
    if (waptservice_port<=0) and (waptservice_sslport<=0) then
      waptservice_port := 8088;

    waptservice_timeout := ReadInteger('global','waptservice_timeout',2);

    Language := '';
    // override lang setting
    for i := 1 to Paramcount - 1 do
      if (ParamStrUtf8(i) = '--LANG') or (ParamStrUtf8(i) = '-l') or
        (ParamStr(i) = '--lang') then
        begin
          Language := ParamStrUTF8(i + 1);
          FallBackLanguage := copy(ParamStrUTF8(i + 1),1,2);
        end;

    if Language = '' then
    begin
      Language := ReadString('global','language','');       ;
      FallBackLanguage := copy(Language,1,2);
      //if FallBackLanguage ='' then
      //    GetLanguageIDs(Language,FallBackLanguage);
    end;

    waptserver_port := ReadInteger('global','waptserver_port',80);
    waptserver_sslport := ReadInteger('global','waptserver_sslport',443);
    zmq_port := ReadInteger('global','zmq_port',5000);

    HttpProxy := ReadString('global','http_proxy','');
    UseProxyForRepo := ReadBool('global','use_http_proxy_for_repo',False);
    UseProxyForServer := ReadBool('global','use_http_proxy_for_server',False);

    TemplatesRepoUrl := ReadString('wapt-templates','repo_url','https://store.wapt.fr/wapt/');
    AuthorizedCertsDir := ReadString('wapt-templates', 'public_certs_dir', AppendPathDelim(GetAppdataFolder)+'waptconsole\ssl');
    if (AuthorizedCertsDir<>'') and not DirectoryExists(AuthorizedCertsDir) then
    try
      CreateDirUTF8(AuthorizedCertsDir);
    finally
    end;

    AdvancedMode := ReadBool('global','advanced_mode',False);

    DefaultPackagePrefix := ReadString('global','default_package_prefix','');
    DefaultSourcesRoot := ReadString('global','default_sources_root','');

    Result := True

  finally
    Free;
  end;
end;

function WaptDBPath: Utf8String;
begin
  Result := IniReadString(WaptIniFilename,'Global','dbdir');
  if Result<>'' then
    result :=  AppendPathDelim(result)+'waptdb.sqlite'
  else
    result := ExtractFilePath(ParamStr(0))+'db\waptdb.sqlite'
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

function GetLocalIP: Ansistring;
var
{$IFDEF UNIX}
  VProcess: TProcess;
{$ENDIF}
{$IFDEF MSWINDOWS}
  VWSAData: TWSAData;
  VHostEnt: PHostEnt;
  VName: Ansistring;
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
      GetHostName(PAnsiChar(VName), 255);
      SetLength(VName, StrLen(PAnsiChar(VName)));
      VHostEnt := GetHostByName(PAnsiChar(VName));
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

function pyformat(template:Utf8String;params:ISuperobject):Utf8String; overload;
var
  key:ISuperObject;
begin
  Result := template;
  for key in params.AsObject.GetNames do
    Result := UTF8StringReplace(Result,'%('+key.AsString+')s',params.S[key.AsString],[rfReplaceAll]);
end;

function CARoot: String;
begin
  if DirectoryExists(IncludeTrailingPathDelimiter(WaptBaseDir)+'ssl\ca') then
    Result := IncludeTrailingPathDelimiter(WaptBaseDir)+'ssl\ca'
  else
    Result := IncludeTrailingPathDelimiter(WaptBaseDir)+'lib\site-packages\certifi\cacert.pem';
end;

function WAPTServerJsonMultipartFilePost(waptserver, action: String;
  args: array of const; FileArg, FileName: String;
  user: AnsiString; password: AnsiString; OnHTTPWork: TWorkEvent;VerifyCertificateFilename:String=''): ISuperObject;
var
  res:String;
  http:TIdHTTP;
  ssl_handler: TIdSSLIOHandlerSocketOpenSSL;
  St:TIdMultiPartFormDataStream;
  sslCheck:TSSLVerifyCert;
  compressor: TIdCompressorZLib;

begin
  if StrLeft(action,1)<>'/' then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);
  http := TIdHTTP.Create;
  http.Request.AcceptLanguage := StrReplaceChar(Language,'_','-')+','+ FallBackLanguage;
  http.Request.UserAgent := DefaultUserAgent;
  http.HandleRedirects:=True;

  http.Compressor := TIdCompressorZLib.Create;

  if UseProxyForServer then
    IdConfigureProxy(http,HttpProxy);

  ssl_handler := TIdSSLIOHandlerSocketOpenSSL.Create(nil);
  ssl_handler.SSLOptions.Method:=sslvSSLv23;

  http.IOHandler := ssl_handler;

  sslCheck := TSSLVerifyCert.Create(GetHostFromURL(waptserver));

  if (VerifyCertificateFilename<>'') and (VerifyCertificateFilename <>'0') then
  begin
    ssl_handler.SSLOptions.VerifyDepth:=20;
    ssl_handler.SSLOptions.VerifyMode:=[sslvrfPeer];
    ssl_handler.OnVerifyPeer:=@sslCheck.VerifypeerCertificate;
    //Self signed
    if VerifyCertificateFilename<>'1' then
    begin
      ssl_handler.SSLOptions.RootCertFile :=VerifyCertificateFilename;
      //ssl_handler.SSLOptions.CertFile := VerifyCertificateFilename;
    end
    else
    begin
      if DirectoryExists(CARoot) then
        ssl_handler.SSLOptions.VerifyDirs := CARoot
      else
        ssl_handler.SSLOptions.RootCertFile := CARoot;
      //ssl_handler.SSLOptions.CertFile := '';
    end
  end;

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
    if Assigned(http.Compressor) then
    begin
      http.Compressor.Free;
      http.Compressor := Nil;
    end;

    http.Free;
    if assigned(ssl_handler) then
	    ssl_handler.Free;
  end;
end;


function CreateWaptSetup(default_public_cert:Utf8String='';default_repo_url:Utf8String='';
          default_wapt_server:Utf8String='';destination:Utf8String='';company:Utf8String='';OnProgress:TNotifyEvent = Nil;OverrideBaseName:Utf8String='';
          VerifyCert:Utf8String='0'; UseKerberos:Boolean=False; CheckCertificatesValidity:Boolean=True):Utf8String;
var
  iss_template,custom_iss,source,target,outputname,junk : utf8String;
  iss,new_iss,line : ISuperObject;
  wapt_base_dir,inno_fn,p12keypath,signtool: Utf8String;

  function startswith(st:ISuperObject;subst:Utf8String):Boolean;
  begin
    result := (st <>Nil) and (st.DataType = stString) and (pos(subst,trim(st.AsString))=1)
  end;

begin
    wapt_base_dir:= WaptBaseDir;
    iss_template := AppendPathDelim(wapt_base_dir) + 'waptsetup\waptsetup.iss';
    custom_iss := AppendPathDelim(wapt_base_dir) + 'waptsetup\custom_waptsetup.iss';
    iss := SplitLines(FileToString(iss_template));
    new_iss := TSuperObject.Create(stArray);
    for line in iss do
    begin
        if startswith(line,'#define default_repo_url') then
            new_iss.AsArray.Add(format('#define default_repo_url "%s"',[default_repo_url]))
        else if startswith(line,'#define default_wapt_server') then
            new_iss.AsArray.Add(format('#define default_wapt_server "%s"',[default_wapt_server]))
        else if startswith(line,'#define repo_url') then
            new_iss.AsArray.Add(format('#define repo_url "%s"',[default_repo_url]))
        else if startswith(line,'#define wapt_server') then
            new_iss.AsArray.Add(format('#define wapt_server "%s"',[default_wapt_server]))
        else if startswith(line,'#define output_dir') then
            new_iss.AsArray.Add(format('#define output_dir "%s"' ,[destination]))
        else if startswith(line,'#define Company') then
            new_iss.AsArray.Add(format('#define Company "%s"' ,[company]))
        else if startswith(line,'#define install_certs') then
            new_iss.AsArray.Add(format('#define install_certs 1' ,[]))
        else if startswith(line,'#define is_waptagent') then
            new_iss.AsArray.Add(format('#define is_waptagent 1' ,[]))
        else if startswith(line,'#define use_kerberos') then
        begin
            if UseKerberos then
              new_iss.AsArray.Add(format('#define use_kerberos 1' ,[]))
            else
              new_iss.AsArray.Add(format('#define use_kerberos 0' ,[]))
        end
        else if startswith(line,'#define check_certificates_validity') then
        begin
            if CheckCertificatesValidity then
              new_iss.AsArray.Add(format('#define check_certificates_validity 1' ,[]))
            else
              new_iss.AsArray.Add(format('#define check_certificates_validity 0' ,[]))
        end
        else if startswith(line,'#define verify_cert') then
          new_iss.AsArray.Add(format('#define verify_cert "%s"',[VerifyCert]))
        else if startswith(line,'WizardImageFile=') then

        else if startswith(line,'OutputBaseFilename') then
            begin
                if length(OverrideBaseName) <> 0 then
                begin
                    outputname := OverrideBaseName;
                    new_iss.AsArray.Add(format('OutputBaseFilename=%s' ,[outputname]));
                end
                else
                    new_iss.AsArray.Add(line);
            end
        else if not startswith(line,'#define signtool') then
            new_iss.AsArray.Add(line);
    end;

    source := default_public_cert;
    target := ExpandFileName(AppendPathDelim(ExtractFileDir(iss_template))+ '..\ssl\' + ExtractFileName(source));
    if not FileExistsUTF8(target) then
      if not CopyFile(PChar(source),PChar(target),True) then
        raise Exception.CreateFmt(rsCertificateCopyFailure,[source,target]);
    StringToFile(custom_iss,SOUtils.Join(#13#10,new_iss));

    inno_fn :=  AppendPathDelim(wapt_base_dir) + 'waptsetup\innosetup\ISCC.exe';
    if not FileExists(inno_fn) then
        raise Exception.CreateFmt(rsInnoSetupUnavailable, [inno_fn]);
    Run(format('"%s"  "%s"',[inno_fn,custom_iss]),'',3600000,'','','',OnProgress);
    Result := AppendPathDelim(destination) + outputname + '.exe';
    signtool :=  AppendPathDelim(wapt_base_dir) + 'utils\signtool.exe';
    p12keyPath := ChangeFileExt(GetWaptPersonalCertificatePath,'.p12');
    if FileExists(signtool) and FileExists(p12keypath) then
      Run(format('"%s" sign /f "%s" "%s"',[signtool,p12keypath,Result]),'',3600000,'','','',OnProgress);

    // Create waptagent.sha256
    StringToFile(AppendPathDelim(wapt_base_dir) + 'waptupgrade\waptagent.sha256',SHA256Hash(Result)+'  waptagent.exe');
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

function CreateSelfSignedCert(keyfilename,
        crtbasename,
        wapt_base_dir,
        destdir,
        country,
        locality,
        organization,
        orgunit,
        commonname,
        email,
        keypassword:Utf8String;
        codesigning:Boolean
    ):Utf8String;
var
  opensslbin,opensslcfg,opensslcfg_fn,destpem,destcrt,destp12 : Utf8String;
  params : ISuperObject;
  returnCode:integer;
begin
  result := '';
  if FileExists(keyfilename) then
    destpem := keyfilename
  else
  begin
    if ExtractFileNameOnly(keyfilename) = keyfilename then
      destpem := AppendPathDelim(destdir)+ExtractFileNameOnly(keyfilename)+'.pem'
    else
      destpem := keyfilename;
  end;
  if crtbasename = '' then
    crtbasename := ExtractFileNameOnly(keyfilename);

  destcrt := AppendPathDelim(destdir)+crtbasename+'.crt';
  destp12 := AppendPathDelim(destdir)+crtbasename+'.p12';
  if not DirectoryExists(destdir) then
       CreateDir(destdir);

  params := TSuperObject.Create;
  params.S['country'] := UTF8Decode(country);
  params.S['locality'] :=UTF8Decode(locality);
  params.S['organization'] := UTF8Decode(organization);
  params.S['unit'] := UTF8Decode(orgunit);
  params.S['commonname'] := UTF8Decode(commonname);
  params.S['email'] := UTF8Decode(email);
  if codesigning then
    params.S['req_extensions'] := 'v3_ca_codesign_reqext'
  else
    params.S['req_extensions'] := 'v3_ca';

  opensslbin :=  AppendPathDelim(wapt_base_dir)+'openssl.exe';
  opensslcfg :=  pyformat(FileToString(AppendPathDelim(wapt_base_dir) + 'templates\openssl_template.cfg'),params);
  opensslcfg_fn := AppendPathDelim(destdir)+'openssl.cfg';
  StringToFile(opensslcfg_fn,opensslcfg);
  try
    SetEnvironmentVariable('OPENSSL_CONF', PChar(opensslcfg_fn));

    // Create private key  if not already exist
    if not FileExists(destpem) then
    begin
      if keypassword<>'' then
        returnCode := ExecuteProcess(opensslbin,'genrsa -aes128 -passout pass:"'+keypassword+'" -out "'+destpem+'" 2048',[])
      else
        returnCode := ExecuteProcess(opensslbin,'genrsa -nodes -out "'+destpem+'" 2048',[]);
    end;

    returnCode := ExecuteProcess(opensslbin,'req -utf8 -passin pass:"'+keypassword+'" -key "'+destpem+'" -new -x509 -days 3650 -sha256 -out "'+destcrt+'"',[]);

    if returnCode= 0 then
      result := destcrt;

    // create a .pfx .p12 for ms signtool
    if FileExists(destpem) and FileExists(destcrt) then
      if ExecuteProcess(opensslbin,'pkcs12 -export -inkey "'+destpem+'" -in "'+destcrt+'" -out "'+destp12+'" -name "'+ commonname+'" -passin pass:"'+keypassword+'" -passout pass:'+keypassword,[]) <> 0 then
        raise Exception.Create('Unable to create p12 file for signtool');

  finally
    SysUtils.DeleteFile(opensslcfg_fn);
  end;
end;

function GetWaptServerSession(server_url:String = '';user: String=''; password: String=''): TIdCookieManager;
begin
  if  (server_url='') and (user<>'') and (password<>'') and
      ((server_url <> GetWaptServerURL) or (user <> WaptServerUser)  or (password<> WaptServerPassword)) and
      Assigned(WaptServerSession) then
    FreeAndNil(WaptServerSession);
  if WaptServerSession = Nil then
    WaptServerSession := TIdCookieManager.Create();
  Result := WaptServerSession;
  //WaptServerUser := user;
  //WaptServerPassword := password;
end;


initialization
//  if not Succeeded(CoInitializeEx(nil, COINIT_MULTITHREADED)) then;
    //Raise Exception.Create('Unable to initialize ActiveX layer');
   GetLanguageIDs(Language,FallBackLanguage);
   waptwua_enabled := FileExists(WaptBaseDir+'\waptwua\waptwua.py');

finalization
//  CoUninitialize();
end.

