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

{$ifdef unix}
interface
  uses
     Classes, SysUtils, SuperObject,IdComponent,IdCookieManager,IdSSLOpenSSL,
     DefaultTranslator,httpsend,
     IdAuthentication, Process;

  type
      TProgressCallback=function(Receiver:TObject;current,total:Integer):Boolean of object;
      TLoginCallback = function(realm:String;var user,password:String):Boolean of object;

      { EHTTPException }

      EHTTPException=Class(Exception)
        HTTPStatus: Integer;
        constructor Create(const msg: string;AHTTPStatus:Integer);
      end;

  Function GetWaptLocalURL:String;
  function GetHostFromURL(url:String):String;

  function AppLocalDir: String; // returns Users/<user>/local/appdata/<application_name>
  function AppIniFilename(AApplicationName:String=''): String; // returns ConfigFilename parameter or Users/<user>/local/appdata/<application_name>/<application_name>.ini
  function WaptIniFilename: String; // for local wapt install directory

  function WaptBaseDir: String; // c:\wapt
  function WaptgetPath: String; // c:\wapt\wapt-get.exe
  function WaptDBPath: String;

  function GetRepoURLFromDNS(RepoName:String;dnsdomain:String='';http_proxy:String=''):String;
  function GetRepoURLFromIni(RepoName:String='wapt'): String; // from wapt-get.ini, can be empty
  Function GetMainWaptRepoURL:String;   // read from ini, if empty, do a discovery using dns
  Function GetWaptServerURLFromIni:String;  // read ini. if no wapt_server key -> return '', return value in inifile or perform a DNS discovery
  Function GetWaptServerURL:String;  // read ini. if no wapt_server key -> return '', return value in inifile or perform a DNS discovery

  function GetWaptServerCertificateFilename(inifilename:String=''):String;

  function GetWaptLicencesDirectory(inifilename:String=''):String;


  function ReadWaptConfig(inifilename:String = ''): Boolean; //read global parameters from wapt-get ini file

  function GetEthernetInfo(ConnectedOnly:Boolean):ISuperObject;
  function LocalSysinfo: ISuperObject;
  function GetLocalIP: Ansistring;

  //call url action on waptserver. action can contains formatting chars like %s which will be replaced by args with the Format function.
  function WAPTServerJsonGet(action: String;args:Array of const;method:AnsiString='GET';ConnectTimeout:integer=4000;SendTimeout:integer=60000;ReceiveTimeout:integer=60000): ISuperObject; //use global credentials and proxy settings
  function WAPTServerJsonPost(action: String;args:Array of const;data: ISuperObject;method:AnsiString='POST';ConnectTimeout:integer=4000;SendTimeout:integer=60000;ReceiveTimeout:integer=60000): ISuperObject; //use global credentials and proxy settings
  function WAPTServerJsonDelete(action: String; args: array of const): ISuperObject;

  // From https://stackoverflow.com/questions/30441377/how-to-verify-server-hostname
  type
    THostnameValidationResult = (hvrMatchNotFound, hvrNoSANPresent, hvrMatchFound);

  var
    X509_get_ext_d2i: Pointer = nil;

  type
    TSSLVerifyCert = class(TObject)
      Hostname:AnsiString;
    protected
      function Hostmatch(Pattern: String): Boolean;
      function ValidateHostname(Certificate: TIdX509): THostnameValidationResult;
      function MatchesSAN(Certificate: TIdX509): THostnameValidationResult;
      function MatchesCN(Certificate: TIdX509): THostnameValidationResult;
    public
      constructor Create(AHostname:AnsiString);
      function VerifyPeerCertificate(Certificate: TIdX509; AOk: Boolean; ADepth, AError: Integer): Boolean;
    end;

  // for synapse httpsend auth callback
  type THTTPSendAuthorization=procedure(Sender: THttpSend; var ShouldRetry: Boolean;RetryCount:integer) of object;

  function WAPTLocalJsonGet(action:String;user:AnsiString='';password:AnsiString='';timeout:integer=-1;
              OnAuthorization:THTTPSendAuthorization=Nil;RetryCount:Integer=0):ISuperObject;

  Function IdWget(const fileURL, DestFileName: Utf8String; CBReceiver:TObject=Nil;progressCallback:TProgressCallback=Nil;HttpProxy: String='';userAgent:String='';
              VerifyCertificateFilename:String='';CookieManager:TIdCookieManager=Nil;ClientCertFilename:String='';ClientKeyFilename:String=''): boolean;
  Function IdWget_Try(const fileURL: Utf8String;HttpProxy: String='';userAgent:String='';VerifyCertificateFilename:String='';CookieManager:TIdCookieManager=Nil;
              ClientCertFilename:String='';
              ClientKeyFilename:String=''): boolean;

  function IdHttpGetString(const url: ansistring; HttpProxy: String='';
      ConnectTimeout:integer=4000;
      SendTimeOut:integer=60000;
      ReceiveTimeOut:integer=60000;
      user:AnsiString='';password:AnsiString='';
      method:AnsiString='GET';userAGent:String='';
      VerifyCertificateFilename:String='';AcceptType:String='application/json';
      CookieManager:TIdCookieManager=Nil;
      ClientCertFilename:String='';
      ClientKeyFilename:String=''):RawByteString;

  function IdHttpPostData(const url: Ansistring; const Data: RawByteString; const Method: String='POST'; const HttpProxy: String='';
      ConnectTimeout:integer=4000;SendTimeOut:integer=60000;
      ReceiveTimeOut:integer=60000;
      user:AnsiString='';password:AnsiString='';userAgent:String='';
      ContentType:String='application/json';
      VerifyCertificateFilename:String='';AcceptType:String='application/json';
      CookieManager:TIdCookieManager=Nil;
      ClientCertFilename:String='';
      ClientKeyFilename:String='';
      OnHTTPWork:TWorkEvent=Nil;
      DataStream:TStream=Nil):RawByteString;

  function GetReachableIP(IPS:ISuperObject;port:word;Timeout:Integer=3000):String;

  //return ip for waptservice
  function WaptServiceReachableIP(UUID:String;hostdata:ISuperObject=Nil):String;

  function WAPTServerJsonMultipartFilePost(waptserver,action: String;args:Array of const;
      FileArg,FileName:String;
      user:AnsiString='';password:AnsiString='';OnHTTPWork:TWorkEvent=Nil;VerifyCertificateFilename:String=''):ISuperObject;

  function CreateWaptSetup(default_public_cert:Utf8String='';default_repo_url:Utf8String='';
            default_wapt_server:Utf8String='';BuildDir:Utf8String='';company:Utf8String='';OnProgress:TNotifyEvent = Nil;WaptEdition:Utf8String='waptagent';
            VerifyCert:Utf8String='0'; UseKerberos:Boolean=False;
            EnterpriseEdition:Boolean=False; OverwriteRepoURL:Boolean=True;OverwriteWaptServerURL:Boolean=True;
            UseFQDNAsUUID:Boolean=False;
            UseRandomUUID:Boolean=False;
            UseADGroups:Boolean=False;
            UseRepoRules:Boolean=False;
            AppendHostProfiles:String='';
            WUAParams:ISuperObject=Nil;
            WaptauditTaskPeriod:String='';
            PrivateKeyPassword:String=''
            ):Utf8String;

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

// Read/Write ini parameters from
{function WaptIniReadBool(const user,item: string;Default:Boolean=False): Boolean;
function WaptIniReadInteger(const user,item: string;Default:Integer=0): Integer;
function WaptIniReadString(const user,item: string;Default:String=''): string;
procedure WaptIniWriteBool(const user,item: string; Value: Boolean);
procedure WaptIniWriteInteger(const user,item: string; Value: Integer);
procedure WaptIniWriteString(const user,item, Value: string);
}
Function ISO8601ToDateTime(Value: String):TDateTime;
Function DateTimeToISO8601(Value: TDateTime=0):String;

Function WaptEdition:String;

Function RegisteredExePath(ExeName:String):String;

Function GetWaptBaseDir():String;

// Get the registered install location for an application from registry given its executable name
function RegisteredAppInstallLocation(UninstallKey:String): String;


function MakeValidPackageName(st:String):String;

type
  { IWaptSigner }
  IWaptSigner = interface
    ['{3C083083-36B2-487F-A670-932F7EED6254}']
    function SignData(Data:String): String;
  end;


  { IWaptSignatureChecker}
  IWaptSignatureChecker = interface
    ['{A7949187-C3B2-406F-9A97-3D42EBA8EF9F}']
    function VerifyDataSignature(Data:String;Signature:String): Boolean;
  end;

  { TWaptRepo }
  TWaptRepo = class(TPersistent)
  private
    FClientCertificatePath: String;
    FClientPrivateKeyPath: String;
    FDNSDomain: String;
    FHttpProxy: String;
    FIsUpdated: Boolean;
    FName: String;
    FPackages: ISuperObject;
    FRepoURL: String;
    FServerCABundle: String;
    FSignersCABundle: String;
    FTimeOut: Double;
    function GetRepoURL: String;
    procedure SetClientCertificatePath(AValue: String);
    procedure SetClientPrivateKeyPath(AValue: String);
    procedure SetDNSDomain(AValue: String);
    procedure SetHttpProxy(AValue: String);
    procedure SetIsUpdated(AValue: Boolean);
    procedure SetName(AValue: String);
    procedure SetPackages(AValue: ISuperObject);
    procedure SetRepoURL(AValue: String);
    procedure SetServerCABundle(AValue: String);
    procedure SetSignersCABundle(AValue: String);
    procedure SetTimeOut(AValue: Double);
  public
    constructor Create(AName:String='';ARepoURL:String='');
    procedure LoadFromInifile(IniFilename:String;Section:String;Reset:Boolean=False);
    procedure SaveToInifile(IniFilename:String;Section:String);
    function IdWgetFromRepo(const fileURL, DestFileName: String; CBReceiver:TObject=Nil;progressCallback:TProgressCallback=Nil;CookieManage:TIdCookieManager=Nil): boolean;
    property Packages:ISuperObject read FPackages write SetPackages;

  published
    property IsUpdated:Boolean read FIsUpdated write SetIsUpdated;
    property Name:String read FName write SetName;
    property RepoURL:String read GetRepoURL write SetRepoURL;
    property DNSDomain:String read FDNSDomain write SetDNSDomain;
    property SignersCABundle:String read FSignersCABundle write SetSignersCABundle;
    property ServerCABundle:String read FServerCABundle write SetServerCABundle;
    property ClientCertificatePath:String read FClientCertificatePath write SetClientCertificatePath;
    property ClientPrivateKeyPath:String read FClientPrivateKeyPath write SetClientPrivateKeyPath;
    property HttpProxy:String read FHttpProxy write SetHttpProxy;
    property TimeOut:Double read FTimeOut write SetTimeOut;
  end;


  { TWaptRepo }

  { TWaptServer }

  TWaptServer = class(TPersistent)
  private
    FProgressReceiver: TObject;
    FClientCertificatePath: String;
    FClientPrivateKeyPath: String;
    FDNSDomain: String;
    FHttpProxy: String;
    FIsConfigUpdated: Boolean;
    FOnGetPrivateKeyPassword: TPasswordEvent;
    FOnGetUserPassword: TLoginCallback;
    FOnHTTPWork: TWorkEvent;
    FOnProgress: TProgressCallback;
    FUser: String;
    FUserToken: String;
    FWaptServerURL: String;
    FServerCABundle: String;
    FTimeOut: Double;
    FCookieManager: TIdCookieManager;
    FSSLHandler: TIdSSLIOHandlerSocketOpenSSL;
    FSSLCheckCert: TSSLVerifyCert;

    function GetCookieManager: TIdCookieManager;
    function GetSSLCheckCert: TSSLVerifyCert;
    function GetSSLHandler: TIdSSLIOHandlerSocketOpenSSL;
    function GetUser: String;
    function GetUserAgent: String;
    function GetUserToken: String;
    function GetWaptServerURL: String;
    procedure SetClientCertificatePath(AValue: String);
    procedure SetClientPrivateKeyPath(AValue: String);
    procedure SetDNSDomain(AValue: String);
    procedure SetHttpProxy(AValue: String);
    procedure SetIsConfigUpdated(AValue: Boolean);
    procedure SetOnGetPrivateKeyPassword(AValue: TPasswordEvent);
    procedure SetOnGetUserPassword(AValue: TLoginCallback);
    procedure SetOnHTTPWork(AValue: TWorkEvent);
    procedure SetServerCABundle(AValue: String);
    procedure SetTimeOut(AValue: Double);
    procedure SetUser(AValue: String);
    procedure SetWaptServerURL(AValue: String);
  public
    constructor Create(AWaptServerURL: String);
    destructor Destroy; Override;
    procedure LoadFromInifile(IniFilename:String;Section:String;Reset:Boolean=False);
    procedure SaveToInifile(IniFilename:String;Section:String);

    {
    function HttpGetString(action: String; args: array of const;
      Method: AnsiString = 'GET';AcceptType:String='application/json'): String;
    function HttpPostData(action: String; args: array of const; Data: String=''; DataStream: TStream=Nil;
      Method: AnsiString = 'POST';ContentType: String = 'application/json'; AcceptType:String='application/json'): String;
    }

    //;ConnectTimeout:integer=4000;SendTimeout:integer=60000;ReceiveTimeout:integer=60000
    //call url action on waptserver. action can contains formatting chars like %s which will be replaced by args with the Format function.
    function JsonGet(action: String;args:Array of const;method:AnsiString='GET'): ISuperObject; //use global credentials and proxy settings
    function JsonPost(action: String;args:Array of const;data: ISuperObject;method:AnsiString='POST'): ISuperObject; //use global credentials and proxy settings
    function JsonDelete(action: String; args: array of const): ISuperObject;

    function SOApplyUpdates(const datasets: array of ISuperObject):Boolean;
    function SOIsUpdated(const datasets: Array of ISuperObject):Boolean;


  published
    property IsConfigUpdated:Boolean read FIsConfigUpdated write SetIsConfigUpdated;
    property SSLHandler: TIdSSLIOHandlerSocketOpenSSL read GetSSLHandler;
    property SSLCheckCert: TSSLVerifyCert read GetSSLCheckCert;

    property UserAgent:String read GetUserAgent;
    property CookieManager:TIdCookieManager read GetCookieManager;

    property WaptServerURL:String read GetWaptServerURL write SetWaptServerURL;
    property DNSDomain:String read FDNSDomain write SetDNSDomain;
    property ServerCABundle:String read FServerCABundle write SetServerCABundle;
    property ClientCertificatePath:String read FClientCertificatePath write SetClientCertificatePath;
    property ClientPrivateKeyPath:String read FClientPrivateKeyPath write SetClientPrivateKeyPath;
    property HttpProxy:String read FHttpProxy write SetHttpProxy;
    property TimeOut:Double read FTimeOut write SetTimeOut;
    property User: String read GetUser write SetUser;
    property UserToken:String read GetUserToken write FUserToken;
    property OnGetUserPassword:TLoginCallback read FOnGetUserPassword write SetOnGetUserPassword;
    property OnGetPrivateKeyPassword:TPasswordEvent read FOnGetPrivateKeyPassword write SetOnGetPrivateKeyPassword;
    property OnHTTPWork:TWorkEvent read FOnHTTPWork write SetOnHTTPWork;
    property OnProgress:TProgressCallback read FOnProgress write FOnProgress;
    property ProgressReceiver:TObject read FProgressReceiver write FProgressReceiver;
  end;

const
  waptservice_port:integer = 8088;
  waptserver_port:integer = 80;
  waptserver_sslport:integer = 443;
  waptservice_timeout:integer = 20;

  WaptServerUser: String ='admin';
  WaptServerPassword: String ='';
  WaptServerUUID: String ='';
  WaptServerEdition: String ='';

  // active session until user or password is changed
  WaptServerSession: TIdCookieManager = Nil;

  HttpProxy:String = '';
  UseProxyForRepo: Boolean = False;
  UseProxyForServer: Boolean = False;

  Language:String = '';
  LanguageFull:String = '';

  DefaultPackagePrefix:String = '';
  DefaultSourcesRoot:String = '';

  AuthorizedCertsDir:String = '';

  AdvancedMode:Boolean = False;

  EnableExternalTools:Boolean = True;
  EnableManagementFeatures:Boolean = True;

  EnableWaptWUAFeatures:Boolean = True;

  HideUnavailableActions:Boolean = False;

  WaptPersonalCertificatePath: String ='';

  WaptClientCertFilename:String='';
  WaptClientKeyFilename:String='';

  WaptCAKeyFilename: String ='';
  WaptCACertFilename: String ='';

  WAPTServerMinVersion='1.7.4';

  FAppIniFilename:String = '';

  DefaultMaturity:String = '';

  OnWaptGetKeyPassword: TPasswordEvent = Nil;


implementation

uses LazFileUtils, LazUTF8, FileUtil, soutils, Variants,uwaptres,waptutils,uwaptcrypto,tisinifiles,tislogging,
  NetworkAdapterInfo,
  IdHTTP,
  IdMultipartFormData,IdExceptionCore,IdException,IdURI,IdHeaderList,
  gettext,IdStack,IdCompressorZLib,
  IdSSLOpenSSLHeaders,IdCTypes,
  IniFiles,tiscommon,strutils,tisstrings,registry,ssl_openssl;

const
  CacheWaptServerUrl: String = 'None';
  wapt_config_filename : String = '';
  AppVersion : String = '0.0.0';

type
  TX509_get_ext_d2i = function(a: PX509; nid: TIdC_INT; var pcrit: PIdC_INT; var pidx: PIdC_INT): PSTACK_OF_GENERAL_NAME cdecl;


function DefaultUserAgent:String;
begin
  Result := ApplicationName+'/'+AppVersion;
end;

function WaptIniReadBool(const user, item: string; Default: Boolean): Boolean;
begin
  if user = '' then
    Result := IniReadBool(WaptIniFilename,'global',item,default)
  else
  begin
    if IniHasKey(AppIniFilename,user,item) then
      Result := IniReadBool(AppIniFilename,user,item,default)
    else
      Result := IniReadBool(AppIniFilename,'global',item,default);
	end;
end;

function WaptIniReadInteger(const user, item: string; Default: Integer
			): Integer;
begin
  if user = '' then
    Result := IniReadInteger(WaptIniFilename,'global',item,default)
  else
  begin
    if IniHasKey(AppIniFilename,user,item) then
      Result := IniReadInteger(AppIniFilename,user,item,default)
    else
      Result := IniReadInteger(AppIniFilename,'global',item,default);
	end;
end;

function WaptIniReadString(const user, item: string; Default: String): string;
begin
  if user = '' then
    Result := IniReadString(WaptIniFilename,'global',item,default)
  else
  begin
    if IniHasKey(AppIniFilename,user,item) then
      Result := IniReadString(AppIniFilename,user,item,default)
    else
      Result := IniReadString(AppIniFilename,'global',item,default);
	end;
end;

procedure WaptIniWriteBool(const user, item: string; Value: Boolean);
begin
  if user = '' then
    IniWriteBool(WaptIniFilename,'global',item,value)
  else
    IniWriteBool(AppIniFilename,user,item,value)
end;

procedure WaptIniWriteInteger(const user, item: string; Value: Integer);
begin
  if user = '' then
    IniWriteInteger(WaptIniFilename,'global',item,value)
  else
    IniWriteInteger(AppIniFilename,user,item,value)
end;

procedure WaptIniWriteString(const user, item, Value: string);
begin
  if user = '' then
    IniWriteString(WaptIniFilename,'global',item,value)
  else
    IniWriteString(AppIniFilename,user,item,value)
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
    ProgressReceiver:TObject;
    progressCallback:TProgressCallback;
    procedure OnWorkBegin(ASender: TObject; AWorkMode: TWorkMode; AWorkCountMax: Int64);
    procedure OnWork(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64);
  end;

{ TWaptServer }

procedure TWaptServer.SetDNSDomain(AValue: String);
begin
  if FDNSDomain=AValue then Exit;
  FDNSDomain := AValue;
  FIsConfigUpdated := True;
end;

function TWaptServer.GetWaptServerURL: String;
begin
  Result := FWaptServerURL;
end;

function TWaptServer.GetSSLCheckCert: TSSLVerifyCert;
begin
  if (FSSLCheckCert=Nil) or (FSSLCheckCert.Hostname <> GetHostFromURL(WaptServerURL)) then
  begin
    If Assigned(FSSLCheckCert) then
      FreeAndNil(FSSLCheckCert);
    FSSLCheckCert := TSSLVerifyCert.Create(GetHostFromURL(WaptServerURL));
  end;
  Result := FSSLCheckCert;
end;

function TWaptServer.GetSSLHandler: TIdSSLIOHandlerSocketOpenSSL;
begin
  If (FSSLHandler=Nil) or (FSSLHandler.SSLOptions.RootCertFile <> ServerCABundle) Then
  begin
    If Assigned(FSSLHandler) then
      FreeAndNil(FSSLHandler);
    FSSLHandler := TIdSSLIOHandlerSocketOpenSSL.Create;
    if (ServerCABundle<>'') and (ServerCABundle <>'0') then
    begin
      SSLHandler.SSLOptions.VerifyDepth := 20;
      SSLHandler.SSLOptions.VerifyMode := [sslvrfPeer];
      SSLHandler.OnVerifyPeer := @SSLCheckCert.VerifyPeerCertificate;
      //Self signed
      if ServerCABundle <> '1' then
        SSLHandler.SSLOptions.RootCertFile := ServerCABundle
      else
      begin
        if DirectoryExists(CARoot) then
          SSLHandler.SSLOptions.VerifyDirs := CARoot
        else
          SSLHandler.SSLOptions.RootCertFile := CARoot;
      end
    end;
  end;
  Result := FSSLHandler;
end;

function TWaptServer.GetCookieManager: TIdCookieManager;
begin
  if FCookieManager<>Nil then
    FCookieManager := TIdCookieManager.Create;
  Result := FCookieManager;
end;

function TWaptServer.GetUser: String;
var
  password:String;
begin
  if (FUser='') then
  begin
    //if Assigned(OnGetUserPassword) then
    //  OnGetUserPassword(WaptServerURL,FUser,Password);
  end;
  Result := FUser;
end;

function TWaptServer.GetUserAgent: String;
begin
  Result := ApplicationName+'/'+AppVersion;
end;

function TWaptServer.GetUserToken: String;
var
  SORes,UserPassword:ISuperObject;
  aUser,aPassword: String;
begin
  if (FUserToken='') then
  begin
    // Auth using certificates or basic auth
    if OnGetUserPassword(WaptServerURL+'/api/v3/login',aUser,aPassword) then
    begin
      UserPassword := SO();
      UserPassword.S['user'] := aUser;
      UserPassword.S['password'] := aPassword;

      sores := JsonPost('/api/v3/login', [],UserPassword);
      if sores.B['success'] then
      begin
        FUserToken := sores.S['token'];
        WaptServerUUID := UTF8Encode(sores['result'].S['server_uuid']);
        WaptServerEdition := UTF8Encode(sores['result'].S['edition']);
      end
      else
        Raise Exception.CreateFmt('You have to login with proper Wapt user/password. Error: %s',[sores.S['message']]);
    end
    else
      Raise Exception.Create('You have to login with proper Wapt user/password.');
  end;
  Result := FUserToken;
end;

procedure TWaptServer.SetClientCertificatePath(AValue: String);
begin
  if FClientCertificatePath=AValue then Exit;
  FClientCertificatePath:=AValue;
  FIsConfigUpdated := True;
  if (FClientCertificatePath<>'') then
    SSLHandler.SSLOptions.CertFile := FClientCertificatePath;
end;

procedure TWaptServer.SetClientPrivateKeyPath(AValue: String);
begin
  if FClientPrivateKeyPath=AValue then Exit;
  FClientPrivateKeyPath:=AValue;
  FIsConfigUpdated := True;
  if (FClientPrivateKeyPath<>'') then
  begin
    SSLHandler.SSLOptions.KeyFile:=FClientPrivateKeyPath;
    SSLHandler.OnGetPassword:=OnGetPrivateKeyPassword;
  end;
end;

procedure TWaptServer.SetHttpProxy(AValue: String);
begin
  if FHttpProxy=AValue then Exit;
  FHttpProxy:=AValue;
  FIsConfigUpdated:=True;
end;

procedure TWaptServer.SetIsConfigUpdated(AValue: Boolean);
begin
  if FIsConfigUpdated=AValue then Exit;
  FIsConfigUpdated:=AValue;
end;

procedure TWaptServer.SetOnGetPrivateKeyPassword(AValue: TPasswordEvent);
begin
  if FOnGetPrivateKeyPassword=AValue then Exit;
  FOnGetPrivateKeyPassword:=AValue;
end;

procedure TWaptServer.SetOnGetUserPassword(AValue: TLoginCallback);
begin
  if FOnGetUserPassword=AValue then Exit;
  FOnGetUserPassword:=AValue;
end;

procedure TWaptServer.SetOnHTTPWork(AValue: TWorkEvent);
begin
  if FOnHTTPWork=AValue then Exit;
  FOnHTTPWork:=AValue;
end;

procedure TWaptServer.SetWaptServerURL(AValue: String);
begin
  if FWaptServerURL=AValue then Exit;
  If Assigned(FSSLCheckCert) then
    FreeAndNil(FSSLCheckCert);
  FWaptServerURL:=AValue;
  FIsConfigUpdated := True;
end;

procedure TWaptServer.SetServerCABundle(AValue: String);
begin
  if FServerCABundle=AValue then Exit;
  FServerCABundle:=AValue;
  FIsConfigUpdated := True;
end;

procedure TWaptServer.SetTimeOut(AValue: Double);
begin
  if FTimeOut=AValue then Exit;
  FTimeOut:=AValue;
  FIsConfigUpdated := True;
end;

procedure TWaptServer.SetUser(AValue: String);
begin
  if FUser=AValue then Exit;
  FUser:=AValue;
end;


constructor TWaptServer.Create(AWaptServerURL: String);
begin
  inherited Create;
  WaptServerURL:=AWaptServerURL;
  TimeOut := 5;
  IsConfigUpdated:=False;
end;

destructor TWaptServer.Destroy;
begin
  if Assigned(FSSLHandler) then
    FreeAndNil(FSSLHandler);
  if Assigned(FSSLCheckCert) then
    FreeAndNil(FSSLCheckCert);
  if Assigned(FCookieManager) then
    FreeAndNil(FCookieManager);
  inherited;
end;

procedure TWaptServer.LoadFromInifile(IniFilename: String; Section: String;
  Reset: Boolean);
begin
  if Section ='' then
    Section := 'global';
  if Reset then
  begin
    WaptServerURL:='';
    DNSDomain := '';
    HttpProxy:='';
    ServerCABundle:='';
    TimeOut:=5.0;
  end;
  if section <> '' then
    with TIniFile.Create(IniFilename) do
    try
      begin
        WaptServerURL := ReadString(Section,'wapt_server',WaptServerURL);
        DNSDomain := ReadString(Section,'dnsdomain',ReadString('global','dnsdomain',DNSDomain));
        HttpProxy:= ReadString(Section,'http_proxy',ReadString('global','http_proxy',HttpProxy));
        ServerCABundle:=ReadString(Section,'verify_cert',ReadString('global','verify_cert',ServerCABundle));
        TimeOut:=ReadFloat(Section,'timeout',ReadFloat('global','timeout',TimeOut));
        ClientCertificatePath :=ReadString(Section,'client_certificate',ReadString('global','client_certificate',ClientCertificatePath));
        ClientPrivateKeyPath :=ReadString(Section,'client_private_key',ReadString('global','client_private_key',ClientPrivateKeyPath));
        FIsConfigUpdated:=False;
      end;
    finally
      Free;
    end;
end;

procedure TWaptServer.SaveToInifile(IniFilename: String; Section: String);
begin
  if Section ='' then
    Section := 'global';

  if section = '' then
    Raise Exception.Create('Unable to save Repo settings, Section parameter is empty');

  with TIniFile.Create(IniFilename) do
  try
    WriteString(Section,'wapt_server',WaptServerURL);
    WriteString(Section,'dnsdomain',DNSDomain);
    WriteString(Section,'http_proxy',HttpProxy);
    WriteString(Section,'verify_cert',ServerCABundle);
    WriteString(Section,'client_certificate',ClientCertificatePath);
    WriteString(Section,'client_private_key',ClientPrivateKeyPath);
    WriteFloat(Section,'timeout',TimeOut);
    FIsConfigUpdated:=False;
  finally
    Free;
  end;
end;

{
function TWaptServer.HttpGetString(action: String; args: array of const;
    Method:AnsiString='GET';AcceptType:String='application/json'): String;
var
  http:TIdHTTP;
  url: String;
  progress:TIdProgressProxy;
begin
  if WaptServerURL = '' then
    raise Exception.CreateFmt(rsUndefWaptSrvInIni, [WaptIniFilename]);
  if (StrLeft(action,1)<>'/') and (StrRight(GetWaptServerURL,1)<>'/') then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);

  url := WaptServerURL+action;

  http := TIdHTTP.Create;
  try
    http.Compressor :=  TIdCompressorZLib.Create(Nil);
    http.CookieManager := CookieManager;
    http.HandleRedirects:=True;
    http.Request.AcceptLanguage := Language;

    if UserAgent='' then
      http.Request.UserAgent := DefaultUserAgent
    else
      http.Request.UserAgent := userAgent;

    http.IOHandler := SSLHandler;
    http.Request.Accept := AcceptType;

    progress := TIdProgressProxy.Create(Nil);
    progress.ProgressCallback := OnProgress;
    progress.ProgressReceiver := ProgressReceiver;

    try
      http.ConnectTimeout := round(Timeout*1000);

      if (User <>'') and (FUserToken<>'') then
      begin
        http.Request.BasicAuthentication:=True;
        http.Request.Username:=User;
        http.Request.Password:=UserToken;
      end;

      if Assigned(OnHTTPWork) then
        http.OnWork:=OnHTTPWork;

      if Assigned(Progress) then
      begin
        http.OnWorkBegin:=@progress.OnWorkBegin;
        http.OnWork:=@progress.OnWork;
      end;

      if HttpProxy<>'' then
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
  end;
end;
}

{
function TWaptServer.HttpPostData(action: String; args: array of const;
  Data: String=''; DataStream: TStream=Nil; Method: AnsiString = 'POST';
  ContentType: String = 'application/json'; AcceptType: String = 'application/json'): String;
var
  http:TIdHTTP;
  tmpDataStream: Boolean;
  url: String;
  progress:TIdProgressProxy;
begin
  if WaptServerURL = '' then
    raise Exception.CreateFmt(rsUndefWaptSrvInIni, [WaptIniFilename]);
  if (StrLeft(action,1)<>'/') and (StrRight(GetWaptServerURL,1)<>'/') then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);

  url := WaptServerURL+action;

  http := TIdHTTP.Create;
  try
    if not Assigned(DataStream) then
    begin
      DataStream:= TStringStream.Create(Data);
      tmpDataStream := True;
    end
    else
      tmpDataStream := False;

    http.HandleRedirects:=True;
    http.Compressor := TIdCompressorZLib.Create;
    http.CookieManager := CookieManager;
    http.Request.AcceptLanguage := Language;
    if userAgent='' then
      http.Request.UserAgent := DefaultUserAgent
    else
      http.Request.UserAgent := userAgent;

    http.Request.ContentType := ContentType;
    http.Request.ContentEncoding:='UTF-8';
    http.Request.Accept:=AcceptType;

    HTTP.IOHandler := SSLHandler;

    //Todo : handle authentication in multiple steps
    // first check with current known credentials, then if 404, try with next in turn
    // We should get the preferred order of auth methods from server 404 error result
    // At each step, we ask user with callback for password or key locatio or pwd location
    if user <> '' then
    begin
      http.Request.BasicAuthentication:=True;
      http.Request.Username := user;
      http.Request.Password := UserToken;
    end;

    progress := TIdProgressProxy.Create(Nil);
    progress.ProgressCallback := OnProgress;
    progress.ProgressReceiver := ProgressReceiver;

    try
      http.ConnectTimeout := Round(Timeout*1000);
      if HttpProxy<>'' then
        IdConfigureProxy(http,HttpProxy);

      if Assigned(OnHTTPWork) then
        http.OnWork:=OnHTTPWork;

      if Assigned(progress.progressCallback) then
      begin
        http.OnWorkBegin:=@progress.OnWorkBegin;
        http.OnWork:=@progress.OnWork;
      end;

      try
        if Method = 'POST' then
          Result := http.Post(url,DataStream)
        else if Method = 'PUT' then
          Result := http.Put(url,DataStream)
        else if Method = 'DELETE' then
          http.Delete(url);
      except
        on E:EIdHTTPProtocolException do
          writeln(E.Message);

      end;

    except
      // ??? -> handle issue !
      on E:EIdReadTimeout do
        Result := '';
    end;
  finally
    FreeAndNil(progress);
    if tmpDataStream and Assigned(DataStream) then
      FreeAndNil(DataStream);
    if Assigned(http.Compressor) then
    begin
      http.Compressor.Free;
      http.Compressor := Nil;
    end;
    FreeAndNil(http);
  end;
end;
}

function TWaptServer.JsonGet(action: String; args: array of const;
  method: AnsiString): ISuperObject;
var
  StrResult: String;
begin
  // StrResult := HttpGetString(action,args,method);
  // Result := SO(StrResult);
end;

function TWaptServer.JsonPost(action: String; args: array of const;
  data: ISuperObject; method: AnsiString): ISuperObject;
begin

end;

function TWaptServer.JsonDelete(action: String;
  args: array of const): ISuperObject;
var
  StrResult: String;
begin
  // StrResult := HttpGetString(action,args,'DELETE');
  // Result := SO(StrResult);
end;

function TWaptServer.SOApplyUpdates(const datasets: array of ISuperObject
  ): Boolean;
var
  ADataset: ISuperObject;
begin
  for ADataset in datasets do
    if SOIsUpdated([ADataset]) then
    begin

    end;
  result := not SOIsUpdated(datasets);
end;

function TWaptServer.SOIsUpdated(const datasets: array of ISuperObject): Boolean;
var
  ADataset,Rec: ISuperObject;
begin
  Result := False;
  for ADataset in datasets do
  begin
    if ADataset <> Nil then
      for Rec in ADataset do
        if Rec.B['_edited'] then
        begin
          Result := True;
          Exit;
        end;
  end;
end;


{ TWaptRepo }

procedure TWaptRepo.SetHttpProxy(AValue: String);
begin
  if FHttpProxy=AValue then Exit;
  FHttpProxy:=AValue;
end;

procedure TWaptRepo.SetIsUpdated(AValue: Boolean);
begin
  if FIsUpdated=AValue then Exit;
  FIsUpdated:=AValue;
end;

procedure TWaptRepo.SetDNSDomain(AValue: String);
begin
  if FDNSDomain=AValue then Exit;
  FDNSDomain:=AValue;
end;

function TWaptRepo.GetRepoURL: String;
begin
  Result := FRepoURL;
end;

procedure TWaptRepo.SetClientCertificatePath(AValue: String);
begin
  if FClientCertificatePath=AValue then Exit;
  FClientCertificatePath:=AValue;
  FIsUpdated:=True;
end;

procedure TWaptRepo.SetClientPrivateKeyPath(AValue: String);
begin
  if FClientPrivateKeyPath=AValue then Exit;
  FClientPrivateKeyPath:=AValue;
  FIsUpdated:=True;
end;

procedure TWaptRepo.SetName(AValue: String);
begin
  if FName=AValue then Exit;
  FName:=AValue;
  FIsUpdated:=True;
end;

procedure TWaptRepo.SetPackages(AValue: ISuperObject);
begin
  if FPackages=AValue then Exit;
  FPackages:=AValue;
  FIsUpdated:=True;
end;

procedure TWaptRepo.SetRepoURL(AValue: String);
begin
  if FRepoURL=AValue then Exit;
  FRepoURL:=AValue;
  FIsUpdated:=True;
end;

procedure TWaptRepo.SetServerCABundle(AValue: String);
begin
  if FServerCABundle=AValue then Exit;
  FServerCABundle:=AValue;
  FIsUpdated:=True;
end;

  procedure TWaptRepo.SetSignersCABundle(AValue: String);
  begin
    if FSignersCABundle=AValue then Exit;
    FSignersCABundle:=AValue;
    FIsUpdated:=True;
  end;

procedure TWaptRepo.SetTimeOut(AValue: Double);
begin
  if FTimeOut=AValue then Exit;
  FTimeOut:=AValue;
  FIsUpdated:=True;
end;

  constructor TWaptRepo.Create(AName: String='';ARepoURL:String='');
  begin
    inherited Create;
    RepoURL:=ARepoURL;
    Name := AName;
    TimeOut := 5;
    FIsUpdated := False;
  end;

  procedure TWaptRepo.LoadFromInifile(IniFilename: String; Section: String;Reset:Boolean=False);
  begin
    if Section ='' then
      Section := Name;
    if Reset then
    begin
      RepoURL:='';
      DNSDomain := '';
      HttpProxy:='';
      ServerCABundle:='';
      SignersCABundle:='';
      TimeOut:=5.0;
      FIsUpdated:=False;
    end;
    if section <> '' then
      with TIniFile.Create(IniFilename) do
      try
        begin
          RepoURL := ReadString(Section,'repo_url',RepoURL);
          DNSDomain := ReadString(Section,'dnsdomain',ReadString('global','dnsdomain',DNSDomain));
          HttpProxy:= ReadString(Section,'http_proxy',ReadString('global','http_proxy',HttpProxy));
          ServerCABundle:=ReadString(Section,'verify_cert',ReadString('global','verify_cert',ServerCABundle));
          SignersCABundle:=ReadString(Section,'public_certs_dir',ReadString('global','public_certs_dir',SignersCABundle));
          TimeOut:=ReadFloat(Section,'timeout',ReadFloat('global','timeout',TimeOut));
          ClientCertificatePath :=ReadString(Section,'client_certificate',ReadString('global','client_certificate',ClientCertificatePath));
          ClientPrivateKeyPath :=ReadString(Section,'client_private_key',ReadString('global','client_private_key',ClientPrivateKeyPath));
          FIsUpdated:=False;
        end;
      finally
        Free;
      end;
  end;

  procedure TWaptRepo.SaveToInifile(IniFilename: String; Section: String);
  begin
    if Section ='' then
      Section := Name;

    if section = '' then
      Raise Exception.Create('Unable to save Repo settings, Section parameter is empty');

    with TIniFile.Create(IniFilename) do
    try
      WriteString(Section,'repo_url',RepoURL);
      WriteString(Section,'dnsdomain',DNSDomain);
      WriteString(Section,'http_proxy',HttpProxy);
      WriteString(Section,'verify_cert',ServerCABundle);
      WriteString(Section,'public_certs_dir',SignersCABundle);
      WriteString(Section,'client_certificate',ClientCertificatePath);
      WriteString(Section,'client_private_key',ClientPrivateKeyPath);
      WriteFloat(Section,'timeout',TimeOut);
      FIsUpdated:=False;
    finally
      Free;
    end;
  end;

  function TWaptRepo.IdWgetFromRepo(const fileURL, DestFileName: String; CBReceiver:TObject=Nil;progressCallback:TProgressCallback=Nil;CookieManage:TIdCookieManager=Nil): boolean;
  begin
     Result:=IdWget(fileURL,DestFileName,CBReceiver,progressCallback,HttpProxy,'',ServerCABundle,Nil,ClientCertificatePath,ClientPrivateKeyPath);
  end;

{ HTTPException }

constructor EHTTPException.Create(const msg: string; AHTTPStatus: Integer);
begin
  inherited Create(msg);
  HTTPStatus:=AHTTPStatus;
end;


procedure  TIdProgressProxy.OnWorkBegin(ASender: TObject; AWorkMode: TWorkMode; AWorkCountMax: Int64);
begin
{  total := AWorkCountMax;
  current := 0;
  with (ASender as TIdHTTP) do
  begin
    if Assigned(progressCallback) and Assigned(ProgressReceiver) then
      if not progressCallback(ProgressReceiver,current,total) then
        raise EHTTPException.Create(rsDlStoppedByUser,0);
  end;}
end;



procedure TIdProgressProxy.OnWork(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64);
begin
{  current := AWorkCount;
  with (ASender as TIdHTTP) do
  begin
    if Assigned(progressCallback) and Assigned(ProgressReceiver)  then
      if not progressCallback(ProgressReceiver,current,total) then
        raise EHTTPException.Create(rsDlStoppedByUser,0);
  end;}
end;

function GetHostFromURL(url:String):String;
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


function ExtendIndyCryptoLibrary(): Boolean;
var
  hIdCrypto: HMODULE;
begin
  Result := False;

  // Try to get handle to Indy used crypto library
  if not IdSSLOpenSSL.LoadOpenSSLLibrary() then
    Exit;
  hIdCrypto := IdSSLOpenSSLHeaders.GetCryptLibHandle();
  if hIdCrypto = 0 then
    Exit();

  {
  // Try to get exported methods that are needed additionally
  X509_get_ext_d2i := GetProcAddress(hIdCrypto, PChar('X509_get_ext_d2i'));

  Result := Assigned(X509_get_ext_d2i);
  }
end;


/// TSSLVerifycert


constructor TSSLVerifyCert.Create(AHostname:AnsiString);
begin
  Hostname:=AHostname;
end;

function TSSLVerifyCert.Hostmatch(Pattern: String): Boolean;
begin
  Result := IsWild(Hostname,Pattern,True);
end;

function TSSLVerifyCert.MatchesSAN(Certificate: TIdX509): THostnameValidationResult;
var
  pcrit, pidx: PIdC_INT;
  psan_names: PSTACK_OF_GENERAL_NAME;
  san_names_nb: Integer;
  pcurrent_name: PGENERAL_NAME;
  i: Integer;
  DnsName: String;
  FX509_get_ext_d2i: TX509_get_ext_d2i;
begin
  Result := hvrMatchNotFound;

  // Try to extract the names within the SAN extension from the certificate
  pcrit := nil;
  pidx := nil;
  // if not transtyped from pointer to TX509_get_ext_d2i, it raises AV ...
  FX509_get_ext_d2i := TX509_get_ext_d2i(X509_get_ext_d2i);
  psan_names := FX509_get_ext_d2i(Certificate.Certificate, NID_subject_alt_name, pcrit, pidx);
  // Check if SAN is present
  if psan_names <> nil then
  begin
    san_names_nb := sk_num(PSTACK(psan_names));
    // Check each name within the extension
    for i := 0 to san_names_nb-1 do
    begin
      pcurrent_name := PGENERAL_NAME( sk_value(PSTACK(psan_names), i) );
      if pcurrent_name^._type = GEN_DNS then
      begin
        // Current name is a DNS name, let's check it
        DnsName := String(pcurrent_name^.d.dNSName^.data);
        // Compare expected Hostname with the DNS name
        if Hostmatch(DnsName) then
        begin
          Result := hvrMatchFound;
          Break;
        end;
      end;
    end;
  end
  else
    Result := hvrNoSANPresent;
  // Clean up
  sk_free(PSTACK(psan_names));
end;

function TSSLVerifyCert.MatchesCN(Certificate: TIdX509): THostnameValidationResult;
var
  TempList: TStringList;
  Cn: String;
begin
  Result := hvrMatchNotFound;

  // Extract CN from Subject
  TempList := TStringList.Create();
  try
    TempList.Delimiter := '/';
    TempList.DelimitedText := Certificate.Subject.OneLine;
    Cn := Trim(TempList.Values['CN']);
  finally
    FreeAndNil(TempList);
  end;

  // Compare expected Hostname with the CN
  if Hostmatch(Cn) then
    Result := hvrMatchFound;
end;

function TSSLVerifyCert.ValidateHostname(Certificate: TIdX509): THostnameValidationResult;
begin
  // First try the Subject Alternative Names extension
  Result := MatchesSAN(Certificate);
  if Result = hvrNoSANPresent then
  begin
    // Extension was not found: try the Common Name
    Result := MatchesCN(Certificate);
  end;
end;

function TSSLVerifyCert.VerifyPeerCertificate(Certificate: TIdX509; AOk: Boolean; ADepth, AError: Integer): Boolean;
begin
  if ADepth = 0 then
    Result := AOk and (ValidateHostname(Certificate)=hvrMatchFound)
  else
    Result := AOk;
end;

function GetSSLIOHandler(ForUrl:String;
      CAPath:String = 'C:\tranquilit\wapt\lib\site-packages\certifi\cacert.pem';
      ServerCert:String='';
      ClientCertFilename:String='';
      ClientKeyFilename:String=''):TIdSSLIOHandlerSocketOpenSSL;
var
  SSLCheckCert:TSSLVerifyCert;
begin
  Result := TIdSSLIOHandlerSocketOpenSSL.Create;
  Result.SSLOptions.Method:=sslvSSLv23;
  Result.SSLOptions.Mode:=sslmClient;
  Result.SSLOptions.VerifyDirs:=CAPath;

  SSLCheckCert := TSSLVerifyCert.Create(GetHostFromURL(ForUrl));
  Result.OnVerifyPeer := @SSLCheckCert.VerifyPeerCertificate;

  if (ClientCertFilename<>'') and (ClientKeyFilename<>'') then
  begin
    Result.SSLOptions.CertFile:=ClientCertFilename;
    Result.SSLOptions.KeyFile:=ClientKeyFilename;
    Result.OnGetPassword:=OnWaptGetKeyPassword;
  end;

  if (ServerCert<>'') and (ServerCert <>'0') then
  begin
    Result.SSLOptions.VerifyMode:=[sslvrfPeer];
    Result.OnVerifyPeer:=@SSLCheckCert.VerifyPeerCertificate;
    //Self signed
    if (CAPath='') or (ServerCert<>'1') then
      Result.SSLOptions.RootCertFile := ServerCert
    else
    begin
      if DirectoryExists(CAPath) then
        Result.SSLOptions.VerifyDirs := CAPath
      else
        Result.SSLOptions.RootCertFile := CAPath;
      Result.SSLOptions.VerifyDepth := 20;
    end
  end;
end;

function IdWget(const fileURL, DestFileName: Utf8String; CBReceiver: TObject;
  progressCallback: TProgressCallback; HttpProxy: String='';userAgent:String='';
  VerifyCertificateFilename:String='';
  CookieManager:TIdCookieManager=Nil;
  ClientCertFilename:String='';ClientKeyFilename:String=''): boolean;
var
  {http:TIdHTTP;}
  OutputFile:TFileStream;
  progress : TIdProgressProxy;
  SSLHandler: TIdSSLIOHandlerSocketOpenSSL;
  SSLCheckCert:TSSLVerifyCert;

begin
  SSLCheckCert:=Nil;
  SSLHandler:=Nil;

{  http := TIdHTTP.Create;
  http.HandleRedirects:=True;
  http.Request.AcceptLanguage := Language;

  if CookieManager<>Nil then
    http.CookieManager := CookieManager;

  if userAgent='' then
    http.Request.UserAgent := DefaultUserAgent
  else
    http.Request.UserAgent := userAgent;

  http.Request.BasicAuthentication:=True;

  OutputFile :=TFileStream.Create(DestFileName,fmCreate);
  progress :=  TIdProgressProxy.Create(Nil);
  progress.progressCallback:=progressCallback;
  progress.ProgressReceiver:=CBReceiver;
  try
    // init ssl stack
    SSLHandler := TIdSSLIOHandlerSocketOpenSSL.Create;
    SSLHandler.SSLOptions.Method:=sslvSSLv23;
    SSLHandler.SSLOptions.Mode:=sslmClient;
    if (ClientCertFilename<>'') and (ClientKeyFilename<>'') then
    begin
      SSLHandler.SSLOptions.CertFile:=ClientCertFilename;
      SSLHandler.SSLOptions.KeyFile:=ClientKeyFilename;
      SSLHandler.OnGetPassword:=OnWaptGetKeyPassword;
    end;

  	HTTP.IOHandler := SSLHandler;
    SSLCheckCert := TSSLVerifyCert.Create(GetHostFromURL(fileurl));


    if (VerifyCertificateFilename<>'') and (VerifyCertificateFilename <>'0') then
    begin
      SSLHandler.SSLOptions.VerifyDepth:=20;
      SSLHandler.SSLOptions.VerifyMode:=[sslvrfPeer];
      SSLHandler.OnVerifyPeer:=@SSLCheckCert.VerifyPeerCertificate;
      //Self signed
      if VerifyCertificateFilename<>'1' then
        SSLHandler.SSLOptions.RootCertFile :=VerifyCertificateFilename
      else
      begin
        if DirectoryExists(CARoot) then
          SSLHandler.SSLOptions.VerifyDirs := CARoot
        else
          SSLHandler.SSLOptions.RootCertFile := CARoot;
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
    if Assigned(SSLHandler) then
      FreeAndNil(SSLHandler);
    if Assigned(SSLCheckCert) then
      FreeAndNil(SSLCheckCert);
  end;
  }
end;

function IdWget_Try(const fileURL: Utf8String; HttpProxy: String='';userAgent:String='';
      VerifyCertificateFilename:String='';CookieManager:TIdCookieManager=Nil;
      ClientCertFilename:String='';
      ClientKeyFilename:String=''): boolean;
var
  http:TIdHTTP;
  SSLHandler: TIdSSLIOHandlerSocketOpenSSL;
  SSLCheckCert:TSSLVerifyCert;
begin
  SSLCheckCert:=Nil;
  SSLHandler:=Nil;

  http := TIdHTTP.Create;
  http.HandleRedirects:=True;
  http.Request.AcceptLanguage := Language;
  if userAgent='' then
    http.Request.UserAgent := DefaultUserAgent
  else
    http.Request.UserAgent := userAgent;

  if CookieManager<>Nil then
    http.CookieManager := CookieManager;

  try
    // init ssl stack
    SSLHandler := TIdSSLIOHandlerSocketOpenSSL.Create;
    SSLHandler.SSLOptions.Method:=sslvSSLv23;
    if (ClientCertFilename<>'') and (ClientKeyFilename<>'') then
    begin
      SSLHandler.SSLOptions.CertFile:=ClientCertFilename;
      SSLHandler.SSLOptions.KeyFile:=ClientKeyFilename;
      SSLHandler.OnGetPassword:=OnWaptGetKeyPassword;
    end;

  	HTTP.IOHandler := SSLHandler;
    SSLCheckCert := TSSLVerifyCert.Create(GetHostFromURL(fileurl));

    if (VerifyCertificateFilename<>'') and (VerifyCertificateFilename <>'0') then
    begin
      SSLHandler.SSLOptions.VerifyDepth:=20;
      SSLHandler.SSLOptions.VerifyMode:=[sslvrfPeer];
      SSLHandler.OnVerifyPeer:=@SSLCheckCert.VerifyPeerCertificate;
      //Self signed
      if VerifyCertificateFilename<>'1' then
      begin
        SSLHandler.SSLOptions.RootCertFile :=VerifyCertificateFilename;
        //SSLHandler.SSLOptions.CertFile := VerifyCertificateFilename;
      end
      else
      begin
        if DirectoryExists(CARoot) then
          SSLHandler.SSLOptions.VerifyDirs := CARoot
        else
          SSLHandler.SSLOptions.RootCertFile := CARoot;
        //SSLHandler.SSLOptions.CertFile := '';
      end
    end;

    try
      http.ConnectTimeout := 1000;
      if HttpProxy<>'' then
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
    if Assigned(SSLHandler) then
      FreeAndNil(SSLHandler);
    if Assigned(SSLCheckCert) then
      FreeAndNil(SSLCheckCert);
  end;
end;

function IdHttpGetString(const url: ansistring; HttpProxy:String='';
    ConnectTimeout:integer=4000;SendTimeOut:integer=60000;ReceiveTimeOut:integer=60000;user:AnsiString='';password:AnsiString='';method:AnsiString='GET';userAGent:String='';VerifyCertificateFilename:String='';
    AcceptType:String='application/json';
    CookieManager:TIdCookieManager=Nil;
    ClientCertFilename:String='';
    ClientKeyFilename:String=''):RawByteString;
var
  http:TIdHTTP;
  SSLHandler: TIdSSLIOHandlerSocketOpenSSL;
  SSLCheckCert:TSSLVerifyCert;
begin
  SSLCheckCert:=Nil;
  SSLHandler:=Nil;

  http := TIdHTTP.Create;
  http.HandleRedirects:=True;
  http.Request.AcceptLanguage := Language;
  if userAgent='' then
    http.Request.UserAgent := DefaultUserAgent
  else
    http.Request.UserAgent := userAgent;

  http.compressor :=  TIdCompressorZLib.Create(Nil);

  if CookieManager<>Nil then
    http.CookieManager := CookieManager;

  try
    // init ssl stack
    SSLHandler := TIdSSLIOHandlerSocketOpenSSL.Create;
    SSLHandler.SSLOptions.Method:=sslvSSLv23;
    if (ClientCertFilename<>'') and (ClientKeyFilename<>'') then
    begin
      SSLHandler.SSLOptions.CertFile:=ClientCertFilename;
      SSLHandler.SSLOptions.KeyFile:=ClientKeyFilename;
      SSLHandler.OnGetPassword:=OnWaptGetKeyPassword;
    end;

    http.IOHandler := SSLHandler;
    SSLCheckCert := TSSLVerifyCert.Create(GetHostFromURL(url));

    http.Request.Accept := AcceptType;

    if (VerifyCertificateFilename<>'') and (VerifyCertificateFilename <>'0') then
    begin
      SSLHandler.SSLOptions.VerifyDepth:=20;
      SSLHandler.SSLOptions.VerifyMode:=[sslvrfPeer];
      SSLHandler.OnVerifyPeer:=@SSLCheckCert.VerifyPeerCertificate;
      //Self signed
      if VerifyCertificateFilename<>'1' then
        SSLHandler.SSLOptions.RootCertFile :=VerifyCertificateFilename
      else
      begin
        if DirectoryExists(CARoot) then
          SSLHandler.SSLOptions.VerifyDirs := CARoot
        else
          SSLHandler.SSLOptions.RootCertFile := CARoot;
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

      if HttpProxy<>'' then
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
    if Assigned(SSLHandler) then
      FreeAndNil(SSLHandler);
    if Assigned(SSLCheckCert) then
      FreeAndNil(SSLCheckCert);
  end;
end;

function IdHttpPostData(const url: Ansistring; const Data: RawByteString; const Method: String='POST'; const HttpProxy: String='';
   ConnectTimeout:integer=4000;SendTimeOut:integer=60000;ReceiveTimeOut:integer=60000;user:AnsiString='';password:AnsiString='';userAgent:String='';ContentType:String='application/json';VerifyCertificateFilename:String='';
   AcceptType:String='application/json';CookieManager:TIdCookieManager=Nil;ClientCertFilename:String='';ClientKeyFilename:String='';OnHTTPWork:TWorkEvent=Nil;DataStream:TStream=Nil):RawByteString;
var
  http:TIdHTTP;
  //DataStream:TStringStream;
  tmpDataStream: Boolean;
  ssl_handler: TIdSSLIOHandlerSocketOpenSSL;
  sslCheck:TSSLVerifyCert;
begin
  sslCheck:=Nil;
  ssl_handler:=Nil;

  http := TIdHTTP.Create;
  http.HandleRedirects:=True;
  http.Compressor := TIdCompressorZLib.Create;

  if CookieManager<>Nil then
    http.CookieManager := CookieManager;

  http.Request.AcceptLanguage := Language;
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

  {
  progress :=  TIdProgressProxy.Create(Nil);
  progress.progressCallback:=progressCallback;
  progress.CBReceiver:=CBReceiver;}

  if not Assigned(DataStream) then
  begin
    DataStream:= TStringStream.Create(Data);
    tmpDataStream := True;
  end
  else
    tmpDataStream := False;

  try
    // init ssl stack
    ssl_handler := TIdSSLIOHandlerSocketOpenSSL.Create;
    ssl_handler.SSLOptions.Method:=sslvSSLv23;
    if (ClientCertFilename<>'') and (ClientKeyFilename<>'') then
    begin
      ssl_handler.SSLOptions.CertFile:=ClientCertFilename;
      ssl_handler.SSLOptions.KeyFile:=ClientKeyFilename;
      ssl_handler.OnGetPassword:=OnWaptGetKeyPassword;
    end;

    HTTP.IOHandler := ssl_handler;
    sslCheck := TSSLVerifyCert.Create(GetHostFromURL(url));

    if (VerifyCertificateFilename<>'') and (VerifyCertificateFilename <>'0') then
    begin
      ssl_handler.SSLOptions.VerifyDepth:=20;
      if (ClientCertFilename<>'') and (ClientKeyFilename<>'') then
      begin
        ssl_handler.SSLOptions.CertFile:=ClientCertFilename;
        ssl_handler.SSLOptions.KeyFile:=ClientKeyFilename;
        ssl_handler.OnGetPassword:=OnWaptGetKeyPassword;
      end;

      ssl_handler.SSLOptions.VerifyMode:=[sslvrfPeer];
      ssl_handler.OnVerifyPeer:=@sslCheck.VerifyPeerCertificate;
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
      if HttpProxy<>'' then
        IdConfigureProxy(http,HttpProxy);

      if Assigned(OnHTTPWork) then
        http.OnWork:=OnHTTPWork;

      {if Assigned(progressCallback) then
      begin
        http.OnWorkBegin:=@progress.OnWorkBegin;
        http.OnWork:=@progress.OnWork;
      end;}

      if Method = 'POST' then
        Result := http.Post(url,DataStream)
      else if Method = 'PUT' then
        Result := http.Put(url,DataStream)
      else if Method = 'DELETE' then
        http.Delete(url);

    except
      on E:EIdReadTimeout do
        Result := '';
    end;
  finally
    //FreeAndNil(progress);
    if tmpDataStream and Assigned(DataStream) then
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
  Proxy,strresult : String;
begin
  if GetWaptServerURL = '' then
    raise Exception.CreateFmt(rsUndefWaptSrvInIni, [WaptIniFilename]);
  if (StrLeft(action,1)<>'/') and (StrRight(GetWaptServerURL,1)<>'/') then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);
  if UseProxyForServer then
    Proxy:=HttpProxy
  else
    Proxy:='';

  strresult:=IdhttpGetString(GetWaptServerURL+action,Proxy,ConnectTimeout,SendTimeout ,ReceiveTimeout,
    waptServerUser,waptServerPassword,method,'',GetWaptServerCertificateFilename,'application/json',GetWaptServerSession(),
    WaptClientCertFilename,WaptClientKeyFilename );
  Result := SO(strresult);
end;

function WAPTServerJsonDelete(action: String; args: array of const): ISuperObject;
var
  strresult,proxy : String;
begin
  if GetWaptServerURL = '' then
    raise Exception.CreateFmt(rsUndefWaptSrvInIni, [WaptIniFilename]);
  if (StrLeft(action,1)<>'/') and (StrRight(GetWaptServerURL,1)<>'/') then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);

  if UseProxyForServer then
    Proxy:=HttpProxy
  else
    Proxy:='';

  strresult:=IdhttpGetString(GetWaptServerURL+action,proxy,4000,60000,60000,waptServerUser, waptServerPassword,
    'DELETE','',GetWaptServerCertificateFilename,'application/json',GetWaptServerSession(),
    WaptClientCertFilename,WaptClientKeyFilename );
  Result := SO(strresult);
end;

function WAPTServerJsonPost(action: String; args: array of const;
  data: ISuperObject;method:AnsiString='POST';ConnectTimeout:integer=4000;SendTimeout:integer=60000;ReceiveTimeout:integer=60000): ISuperObject;
var
  res,proxy:String;
begin
  if GetWaptServerURL = '' then
    raise Exception.CreateFmt(rsUndefWaptSrvInIni, [WaptIniFilename]);
  if (StrLeft(action,1)<>'/') and (StrRight(GetWaptServerURL,1)<>'/') then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);
  if UseProxyForServer then
    Proxy:=HttpProxy
  else
    Proxy:='';

  res := IdhttpPostData(GetWaptServerURL+action, Utf8Encode(data.AsJson), method, proxy, ConnectTimeout,SendTimeout,ReceiveTimeout,
    WaptServerUser,WaptServerPassword,'','application/json',GetWaptServerCertificateFilename,'application/json',GetWaptServerSession(),
    WaptClientCertFilename,WaptClientKeyFilename );
  result := SO(res);
end;

function WAPTLocalJsonGet(action: String; user: AnsiString;
  password: AnsiString; timeout: integer=-1;OnAuthorization:THTTPSendAuthorization=Nil;RetryCount:Integer=0): ISuperObject;

var
  url,strresult : String;
  http:THTTPSend;
  StartTime: DWord;
  ShouldRetry:Boolean;
  Retries:Integer;
begin
  http := THTTPSend.Create;
  try
    http.Headers.Add('Accept-Language: '+Language);
    http.UserAgent := DefaultUserAgent;
    http.MimeType  := 'application/json';

    if timeout<=0 then
      timeout := waptservice_timeout * 1000;

    http.Timeout := timeout;

    if action[1]<>'/' then
      action := '/'+action;

    url := GetWaptLocalURL+action;
    {if pos('https',url)>0 then
      http.Sock.CreateWithSSL(TSSLOpenSSL);}

    StartTime:=GetTickCount;
    Logger(Format('url: %s timeout: %d',[url,timeout]),DEBUG);

    if (user<>'') or (OnAuthorization <> Nil) then
    begin
      http.Username:=user;
      http.Password:=password;
    end;

    strresult := '';
    Retries := 0;
    ShouldRetry:=True;
    While ShouldRetry do
    begin
      ShouldRetry := False;
      if http.HTTPMethod('GET',url) then
        SetString(strresult, PAnsiChar(http.Document.Memory), http.Document.Size)
      else
        Raise EIdSocketError.CreateError(http.Sock.LastError,http.Sock.LastErrorDesc);

      if (http.ResultCode=200) then
        break
      else
      if (http.ResultCode=401) then
      begin
        inc(Retries);
        if Assigned(OnAuthorization) and ((RetryCount=-1) or ((RetryCount>0) and (Retries <= RetryCount))) then
          OnAuthorization(http,ShouldRetry,Retries)
        else
          Raise Exception.Create('EIdHTTPProtocolException replacement');
//          Raise EIdHTTPProtocolException.CreateError(http.ResultCode,strresult,http.ResultString);
      end
      else
        Raise Exception.Create('EIdHTTPProtocolException replacement');
//        Raise EIdHTTPProtocolException.CreateError(http.ResultCode,strresult,http.ResultString);
      http.Clear;
      http.Headers.Add('Accept-Language: '+Language);
      http.UserAgent := DefaultUserAgent;
      http.MimeType  := 'application/json';
    End;
    Result := SO(strresult);
    Logger(Format('url: %s : OK Duration: %d',[url,(GetTickCount-StartTime)]),DEBUG);

  finally
    http.Free;
  end;
end;

function SameNet(connected:ISuperObject;IP:String):Boolean;
var
  conn:ISuperObject;
begin
  {for conn in Connected do
  begin
    if SameIPV4Subnet(UTF8Encode(conn.S['ipAddress']),UTF8Encode(IP),UTF8Encode(conn.S['ipMask'])) then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;}
end;

function GetEthernetInfo(ConnectedOnly:Boolean):ISuperObject;
var
  i:integer;
  //ais : TAdapterInfo;
  ao : ISuperObject;
begin
  {result := TSuperObject.Create(stArray);
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
  }
end;

function GetWaptServerURLFromIni: String;
begin
  if IniHasKey(WaptIniFilename,'global','wapt_server') then
    result := IniReadString(WaptIniFilename,'global','wapt_server');
    if (Result <> '') then
      exit
  else
    Result := '';
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

  if IniHasKey(WaptIniFilename,'global','wapt_server') then
  begin
    result := IniReadString(WaptIniFilename,'global','wapt_server');
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
{
  ConnectedIps := NetworkConfig;
  dnsdomain := GetDNSDomain;
  if dnsdomain <> '' then
  begin
    //SRV _wapt._tcp
    recs := DNSSRVQuery('_waptserver._tcp.' + dnsdomain);
    for rec in recs do
    begin
      if rec.I['port'] = 443 then
        url := 'https://' + UTF8Encode(rec.S['name'])
      else
        url := 'http://' + UTF8Encode(rec.S['name']) + ':' + UTF8Encode(rec.S['port']);
      rec.S['url'] := url;
      try
        ServerIp := DNSAQuery(UTF8Encode(rec.S['name']));
        if ServerIp.AsArray.Length > 0 then
          rec.B['outside'] := not SameNet(ConnectedIps, UTF8Encode(ServerIp.AsArray.S[0]))
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
      Result := UTF8Encode(rec.S['url']);
      CacheWaptServerUrl := Result;
      exit;
    end;
  end;

  //None found by DNS Query
  Result := '';
  //Invalid cache
  CacheWaptServerUrl := 'None';
  }
end;


function GetRepoURLFromDNS(RepoName:String;dnsdomain:String='';http_proxy:String=''):String;
var
  rec,recs,ConnectedIps,ServerIp : ISuperObject;
  url:AnsiString;
begin
  result :='';
  {if dnsdomain='' then
    dnsdomain := GetDNSDomain;

  if dnsdomain <> '' then
  begin
    ConnectedIps := GetEthernetInfo(True);

    //SRV _wapt._tcp
    recs := DNSSRVQuery(Format('_%s._tcp.%s',[lowercase(RepoName),lowercase(dnsdomain)]));
    for rec in recs do
    begin
      if rec.I['port'] = 443 then
        url := UTF8Encode('https://'+rec.S['name']+'/wapt')
      else
        url := UTF8Encode('http://'+rec.S['name']+':'+rec.S['port']+'/wapt');
      rec.S['url'] := url;
      try
        ServerIp := DNSAQuery(UTF8Encode(rec.S['name']));
        if ServerIp.AsArray.Length > 0 then
          rec.B['outside'] := not SameNet(ConnectedIps,UTF8Encode(ServerIp.AsArray.S[0]))
        else
          rec.B['outside'] := True;
      except
        rec.B['outside'] := True;
      end;
      // order is priority asc but weight desc
      rec.I['weight'] := - rec.I['weight'];
    end;
    SortByFields(recs,['outside','priority','weight']);

    for rec in recs do
    begin
      Result := UTF8Encode(rec.S['url']);
      Logger('trying '+Result,INFO);
      if IdWget_try(Result+'/Packages',http_proxy,'','0',Nil,WaptClientCertFilename,WaptClientKeyFilename) then
        Exit;
    end;

    //CNAME wapt.
    recs := DNSCNAMEQuery(RepoName+'.'+dnsdomain);
    for rec in recs do
    begin
      Result := UTF8Encode('http://'+rec.AsString+'/wapt');
      Logger('trying '+result,INFO);
      if IdWget_try(result,http_proxy,'','0',Nil,WaptClientCertFilename,WaptClientKeyFilename ) then
        Exit;
    end;

    //A wapt
    Result := 'http://'+RepoName+'.'+dnsdomain+'/wapt';
      Logger('trying '+result,INFO);
      if IdWget_try(result,http_proxy,'','0',Nil,WaptClientCertFilename,WaptClientKeyFilename) then
        Exit;
  end;}
end;

function GetRepoURLFromIni(RepoName:String='wapt'): String;
var
  section:String;
  repositories:TDynStringArray;
begin
  result := '';

  if (RepoName='wapt') then
  begin
    if IniHasKey(WaptIniFilename,'wapt','repo_url') then
      section:='wapt'
    else
    if IniHasKey(WaptIniFilename,'global','repo_url') then
      section:='global'
    else
    begin
      repositories := StrSplit(IniReadString(WaptIniFilename,'global','repositories'),',',True);
      if Length(repositories)>0 then
        section := repositories[0];
    end;
  end;

  if (RepoName='wapt-host') then
  begin
    if IniHasKey(WaptIniFilename,'wapt-host','repo_url') then
      section:='wapt-host'
    else
    if IniHasKey(WaptIniFilename,'global','repo_url') then
    begin
      section:='global';
      result := IniReadString(WaptIniFilename,section,'repo_url')+'-host';
    end
    else
    begin
      repositories := StrSplit(IniReadString(WaptIniFilename,'global','repositories'),',',True);
      if Length(repositories)>0 then
      begin
        // Last repo is main fallback so is more entitled to have up-to-date host packages
        section := repositories[length(repositories)-1];
        result := IniReadString(WaptIniFilename,section,'repo_url')+'-host';
      end;
    end;
  end;

  if result = '' then
    result := IniReadString(WaptIniFilename,section,'repo_url');

  if (result <> '') and (RightStr(result,1) = '/') then
    result := copy(result,1,length(result)-1);
end;

function GetMainWaptRepoURL: String;
var
  dnsdomain,Proxy:AnsiString;
begin
  result := GetRepoURLFromIni('wapt');
  if (Result <> '') then
    exit;

  if UseProxyForRepo then
    Proxy:=HttpProxy
  else
    Proxy:='';

  dnsdomain:='';//GetDNSDomain;
  if dnsdomain<>'' then
    Result := GetRepoURLFromDNS('wapt',dnsdomain,Proxy);
end;


function GetWaptLocalURL: String;
begin
  if waptservice_port >0 then
    result := format('http://127.0.0.1:%d',[waptservice_port])
  else
    result :='';
end;



function WaptBaseDir: String;
begin
  result := GetCmdParams('waptbasedir',ExtractFileDir(ParamStrUTF8(0)));
  if lowercase(ExtractFileName(result)) = 'scripts' then
    Result := ExtractFileDir(result);
  Result := AppendPathDelim(Result);
end;

function WaptgetPath: String;
begin
  result := IncludeTrailingPathDelimiter(WaptBaseDir)+'wapt-get.exe'
end;

function GetSpecialFolderPath(folder : integer) : String;
const
  SHGFP_TYPE_CURRENT = 0;
var
  path: array [0..MAX_PATH] of widechar;
begin
  {if SUCCEEDED(SHGetFolderPathW(0,folder,0,SHGFP_TYPE_CURRENT, @path[0])) then
    Result := IncludeTrailingPathDelimiter(UTF8Encode(WideString(path)))
  else}
    Result := '';
end;

function AppLocalDir: String;
begin
  //Result :=  GetSpecialFolderPath(CSIDL_LOCAL_APPDATA))+ApplicationName;
  result := AnsiToUtf8(GetAppConfigDir(False));
end;

function AppIniFilename(AApplicationName:String=''): String;
begin
  {if FAppIniFilename = '' then
  begin
    if AApplicationName='' then
      AApplicationName:=ApplicationName;
    FAppIniFilename := GetCmdParams('ConfigFilename',GetCmdParams('config',GetCmdLineArg('c',['-'])));
    if FAppIniFilename = '' then
      FAppIniFilename := AApplicationName+'.ini';

    if ExtractFileDir(FAppIniFilename)='' then
      FAppIniFilename := IncludeTrailingPathDelimiter(IncludeTrailingPathDelimiter(GetWindowsSpecialDir(CSIDL_LOCAL_APPDATA))+AApplicationName)+FAppIniFilename;
    if ExtractFileExt(FAppIniFilename)='' then
      FAppIniFilename := FAppIniFilename+'.ini';

  end;
  Result := FAppIniFilename;}
  Result := '/home/octavel/wapt-get.ini'; // TODO change
end;

function WaptIniFilename: String;
begin
  if wapt_config_filename = '' then
      wapt_config_filename := IncludeTrailingPathDelimiter(WaptBaseDir)+'wapt-get.ini';
  result :=  wapt_config_filename;
end;

function GetWaptServerCertificateFilename(inifilename:String=''): String;
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

function GetWaptLicencesDirectory(inifilename: String): String;
begin
  if inifilename='' then
     inifilename:=WaptIniFilename;
  Result := IniReadString(inifilename,'global','licences_directory','');
  If Result = '' then
    Result := AppendPathDelim(WaptBaseDir)+'licences';
end;

// Read Wapt config from inifile, set global const wapt_config_filename
// if inifile is empty, read from result of WaptIniFilename (wapt_config_filename if set, appinifile if exists, else wapt-get.ini)
function ReadWaptConfig(inifilename:String = ''): Boolean;
var
  i: Integer;
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
    if (waptservice_port<=0) then
      waptservice_port := 8088;

    waptservice_timeout := ReadInteger('global','waptservice_timeout',10);

    GetLanguageIDs(LanguageFull,Language);
    // override lang setting
    for i := 1 to Paramcount - 1 do
      if (ParamStrUtf8(i) = '--LANG') or (ParamStrUtf8(i) = '-l') or
        (ParamStr(i) = '--lang') then
          Language := ParamStrUTF8(i + 1);

    if Language = '' then
      Language := ReadString('global','language','');

    waptserver_port := ReadInteger('global','waptserver_port',80);
    waptserver_sslport := ReadInteger('global','waptserver_sslport',443);

    HttpProxy := ReadString('global','http_proxy','');
    UseProxyForRepo := ReadBool('global','use_http_proxy_for_repo',False);
    UseProxyForServer := ReadBool('global','use_http_proxy_for_server',False);

    AdvancedMode := ReadBool('global','advanced_mode',AdvancedMode);
    EnableExternalTools := ReadBool('global','enable_external_tools',EnableExternalTools);
    EnableManagementFeatures := ReadBool('global','enable_management_features',EnableManagementFeatures);
    EnableWaptWUAFeatures := ReadBool('global','waptwua_enabled',EnableWaptWUAFeatures);

    DefaultPackagePrefix := ReadString('global','default_package_prefix','');
    DefaultSourcesRoot := ReadString('global','default_sources_root','');

    // for packages / configuration / actions signature
    WaptPersonalCertificatePath :=  ReadString('global','personal_certificate_path','');

    WaptCAKeyFilename := ReadString('global', 'default_ca_key_path', '');
    WaptCACertFilename := ReadString('global', 'default_ca_cert_path', '');

    // For ssl client auth on wapt server and repos
    WaptClientCertFilename :=  ReadString('global','client_certificate','');
    WaptClientKeyFilename :=  ReadString('global','client_private_key','');

    AuthorizedCertsDir := ReadString('global','public_certs_dir',MakePath([WaptBaseDir,'ssl']));
    DefaultMaturity :=  ReadString('global','default_maturity','');

    Result := True

  finally
    Free;
  end;
end;

function WaptDBPath: String;
begin
  Result := IniReadString(WaptIniFilename,'global','dbdir');
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
          varOleStr   : Result := UTF8Encode(WideString(V));
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
  VStrTemp: TStringList;
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
    macs[i] := UTF8Encode(card.S['mac']);
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
    result := UTF8Encode(UUIDToString(guid));
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
  so.S['domainname'] :=  tiscommon.GetDomainName; // TODO changer tout
  so.S['systemmanufacturer'] := ''; // GetSystemManufacturer;
  so.S['systemproductname'] := ''; // GetSystemProductName;
  so.S['biosversion'] := ''; // GetBIOSVersion;
  so.S['biosvendor'] := ''; // GetBIOSVendor;
  so.S['biosdate'] := ''; // GetBIOSDate;
  so['ethernet'] := GetEthernetInfo(false);
  so.S['ipaddress'] := GetLocalIP;
  so.S['waptget-version'] := ''; //GetApplicationVersion(WaptgetPath);
  result := so;
end;

// qad %(key)s python format
function pyformat(template:String;params:ISuperobject):String;
var
  key:ISuperObject;
begin
  Result := template;
  for key in params.AsObject.GetNames do
    Result := StringReplace(Result,'%('+UTF8Encode(key.AsString)+')s',UTF8Encode(params.S[key.AsString]),[rfReplaceAll]);
end;

function pyformat(template:Utf8String;params:ISuperobject):Utf8String; overload;
var
  key:ISuperObject;
begin
  Result := template;
  for key in params.AsObject.GetNames do
    Result := UTF8StringReplace(Result,'%('+UTF8Encode(key.AsString)+')s',UTF8Encode(params.S[key.AsString]),[rfReplaceAll]);
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

begin
  if StrLeft(action,1)<>'/' then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);
  http := TIdHTTP.Create;
  http.Request.AcceptLanguage := Language;
  http.Request.UserAgent := DefaultUserAgent;
  http.HandleRedirects:=True;

  http.Compressor := TIdCompressorZLib.Create;

  if UseProxyForServer then
    IdConfigureProxy(http,HttpProxy);

  ssl_handler := TIdSSLIOHandlerSocketOpenSSL.Create(nil);
  ssl_handler.SSLOptions.Method:=sslvSSLv23;
  if (WaptClientCertFilename<>'') and (WaptClientKeyFilename<>'') then
  begin
    ssl_handler.SSLOptions.CertFile:=WaptClientCertFilename;
    ssl_handler.SSLOptions.KeyFile:=WaptClientKeyFilename;
    ssl_handler.OnGetPassword:=OnWaptGetKeyPassword;
  end;

  http.IOHandler := ssl_handler;

  sslCheck := TSSLVerifyCert.Create(GetHostFromURL(waptserver));

  if (VerifyCertificateFilename<>'') and (VerifyCertificateFilename <>'0') then
  begin
    ssl_handler.SSLOptions.VerifyDepth:=20;
    ssl_handler.SSLOptions.VerifyMode:=[sslvrfPeer];
    ssl_handler.OnVerifyPeer:=@sslCheck.VerifyPeerCertificate;
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
    res := HTTP.Post(waptserver+action,St);
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


function CreateWaptSetup(default_public_cert: Utf8String;
  default_repo_url: Utf8String; default_wapt_server: Utf8String;
  BuildDir: Utf8String; company: Utf8String; OnProgress: TNotifyEvent;
  WaptEdition: Utf8String; VerifyCert: Utf8String; UseKerberos: Boolean;
  EnterpriseEdition: Boolean;
  OverwriteRepoURL: Boolean; OverwriteWaptServerURL: Boolean;
  UseFQDNAsUUID:Boolean=False; UseRandomUUID:Boolean=False; UseADGroups:Boolean=False;
  UseRepoRules:Boolean=False; AppendHostProfiles:String='';
  WUAParams:ISuperObject=Nil;
  WaptauditTaskPeriod:String='';
  PrivateKeyPassword:String=''): Utf8String;
var
  iss_template,custom_iss,FN,SSLDir,SSLServerDir,
  DestVerifyCert,Destination,SignArg: String;
  iss,new_iss,line : ISuperObject;
  akey : ISuperObject;

  //WuaKey,WuaParams: ISuperObject;

  wapt_base_dir,inno_fn,p12keypath,signtool:  Utf8String;

  function startswith(st:ISuperObject;subst:Utf8String):Boolean;
  begin
    result := (st <>Nil) and (st.DataType = stString) and (pos(subst,trim(st.AsString))=1)
  end;

begin
  try
    wapt_base_dir:= WaptBaseDir;
    if not DirectoryExistsUTF8(BuildDir) then
      mkdir(BuildDir);

    SSLDir := MakePath([BuildDir,'ssl']);
    if not DirectoryExistsUTF8(SSLDir) then
      mkdir(SSLDir);

    if (default_public_cert<>'') and DirectoryExistsUTF8(default_public_cert) and (default_public_cert <> SSLDir) then
      CopyDirTree(default_public_cert,SSLDir,[cffCreateDestDirectory,cffPreserveTime]);

    Destination := MakePath([BuildDir,'waptupgrade']);
    //  upgrade package sources
    CopyDirTree(MakePath([wapt_base_dir,'waptupgrade']),Destination,
      [cffCreateDestDirectory,cffPreserveTime]);

    iss_template := MakePath([wapt_base_dir,'waptsetup','waptagent.iss']);
    custom_iss := MakePath([BuildDir,'custom_waptagent.iss']);

    iss := SplitLines(FileToString(iss_template));
    new_iss := TSuperObject.Create(stArray);

    // copy server check cert to build dir
    SSLServerDir:=MakePath([SSLDir,'server']);
    if not DirectoryExistsUTF8(SSLServerDir) then
      mkdir(SSLServerDir);

    If (VerifyCert<>'') and (VerifyCert<>'0') and (VerifyCert<>'1') then
    begin
      // copy ca bundle to build dest ssl\server dir
      if VerifyCert<>MakePath([SSLServerDir,ExtractFileName(VerifyCert)]) then
        CopyFile(VerifyCert,MakePath([SSLServerDir,ExtractFileName(VerifyCert)]) ,[cffOverwriteFile,cffPreserveTime],True);
      DestVerifyCert:=MakePath(['{app}\ssl\server',ExtractFileName(VerifyCert)]);
    end
    else
      DestVerifyCert := VerifyCert;

    for line in iss do
    begin
        if startswith(line,'#define default_repo_url') then
            new_iss.AsArray.Add(format('#define default_repo_url "%s"',[default_repo_url]))
        else if startswith(line,'#define default_wapt_server') then
            new_iss.AsArray.Add(format('#define default_wapt_server "%s"',[default_wapt_server]))
        else if startswith(line,'#define repo_url') and OverwriteRepoURL then
            new_iss.AsArray.Add(format('#define repo_url "%s"',[default_repo_url]))
        else if startswith(line,'#define wapt_server') and OverwriteWaptServerURL then
            new_iss.AsArray.Add(format('#define wapt_server "%s"',[default_wapt_server]))
        else if startswith(line,'#define output_dir') then
            new_iss.AsArray.Add(format('#define output_dir "%s"' ,[destination]))
        else if startswith(line,'#define Company') then
            new_iss.AsArray.Add(format('#define Company "%s"' ,[company]))
        else if startswith(line,'#define set_install_certs') then
            new_iss.AsArray.Add(format('#define set_install_certs "1"' ,[]))
        else if startswith(line,'#define append_host_profiles') and (AppendHostProfiles<>'') then
            new_iss.AsArray.Add(format('#define append_host_profiles "%s"' ,[AppendHostProfiles]))
        else if startswith(line,'#define set_waptaudit_task_period') and (WaptauditTaskPeriod<>'') then
            new_iss.AsArray.Add(format('#define set_waptaudit_task_period "%s"' ,[WaptauditTaskPeriod]))
        else if startswith(line,'#define use_ad_groups') then
        begin
            if UseADGroups then
              new_iss.AsArray.Add(format('#define use_ad_groups "1"' ,[]))
            else
              new_iss.AsArray.Add(format('#define use_ad_groups ""' ,[]))
        end
        else if startswith(line,'#define use_repo_rules') then
        begin
            if UseRepoRules then
              new_iss.AsArray.Add(format('#define use_repo_rules "1"' ,[]))
            else
              new_iss.AsArray.Add(format('#define use_repo_rules "0"' ,[]))
        end
        else if startswith(line,'#define use_fqdn_as_uuid') then
        begin
            if UseFQDNAsUUID then
              new_iss.AsArray.Add(format('#define use_fqdn_as_uuid "1"' ,[]))
            else
              new_iss.AsArray.Add(format('#define use_fqdn_as_uuid ""' ,[]))
        end
        else if startswith(line,'#define use_random_uuid') then
        begin
            if UseRandomUUID then
              new_iss.AsArray.Add(format('#define use_random_uuid "1"' ,[]))
            else
              new_iss.AsArray.Add(format('#define use_random_uuid ""' ,[]))
        end
        else if startswith(line,'#define set_use_kerberos') then
        begin
            if UseKerberos then
              new_iss.AsArray.Add(format('#define set_use_kerberos "1"' ,[]))
            else
              new_iss.AsArray.Add(format('#define set_use_kerberos "0"' ,[]))
        end
        else if startswith(line,'#define set_verify_cert') then
          new_iss.AsArray.Add(format('#define set_verify_cert "%s"',[DestVerifyCert]))
        else if startswith(line,';#define waptenterprise') then
        begin
            if EnterpriseEdition then
              new_iss.AsArray.Add(format('#define waptenterprise',[]))
            else
              new_iss.AsArray.Add(format('#undef waptenterprise',[]))
        end
        // WUA Params
        else if startswith(line,'#define waptwua') and (WUAParams<>Nil) then
        begin
          new_iss.AsArray.Add(line);
          for akey in WUAParams.AsObject.GetNames do
          begin
            if WUAParams[akey.AsString]<>Nil then
              new_iss.AsArray.Add(Format('  #define set_waptwua_%s "%s"',[akey.AsString,WUAParams.S[akey.AsString]]));
          end;
        end
        else if startswith(line,'#define edition') and (waptedition <> '') then
          new_iss.AsArray.Add(format('#define edition "%s"' ,[waptedition]))
        else if startswith(line,'#define wapt_base_dir') and (wapt_base_dir <> '') then
          new_iss.AsArray.Add(format('#define wapt_base_dir "%s"' ,[wapt_base_dir]))
        else if not startswith(line,'#define signtool') then
            new_iss.AsArray.Add(line);
    end;

    StringToFile(custom_iss,Utf8Encode(SOUtils.Join(#13#10,new_iss)));

    inno_fn :=  AppendPathDelim(wapt_base_dir) + 'waptsetup\innosetup\ISCC.exe';
    if not FileExists(inno_fn) then
        raise Exception.CreateFmt(rsInnoSetupUnavailable, [inno_fn]);
    //Run(format('"%s"  "%s"',[inno_fn,custom_iss]),'',3600000,'','','',OnProgress);
    Result := AppendPathDelim(destination) + WaptEdition + '.exe';
    signtool :=  AppendPathDelim(wapt_base_dir) + 'utils\signtool.exe';
    p12keyPath := ChangeFileExt(WaptPersonalCertificatePath,'.p12');
    if FileExists(signtool) and FileExists(p12keypath) then
    try
      SignArg := '';
      If PrivateKeyPassword<>'' then
        SignArg := Format('/p "%s"',[PrivateKeyPassword]);
      //Run(format('"%s" sign /f "%s" %s "%s"',[signtool,p12keypath,SignArg, Result]),'',3600000,'','','',OnProgress);
    except
      on E:Exception do
        Logger('Unable to sign waptagent:'+E.Message);
    end;
    // Create waptagent.sha256
    StringToFile(AppendPathDelim(BuildDir) + 'waptupgrade\waptagent.sha256',SHA256Hash(Result)+'  waptagent.exe');
  except
    If DirectoryExistsUTF8(Destination) then
      DeleteDirectory(Destination,False);
    If DirectoryExistsUTF8(SSLDir) then
      DeleteDirectory(SSLDir,False);
    raise;
  end;
end;

function GetReachableIP(IPS:ISuperObject;port:word;Timeout:Integer=3000):String;
var
  IP:ISuperObject;
begin
  Result :='';
  if (IPS=Nil) or (IPS.DataType=stNull) then
    Result := ''
  else
  if (IPS.DataType=stString) then
  begin
    if CheckOpenPort(port,UTF8Encode(IPS.AsString),timeout) then
      Result := UTF8Encode(IPS.AsString)
    else
      Result := '';
  end
  else
  if IPS.DataType=stArray then
  begin
    for IP in IPS do
    begin
      if CheckOpenPort(port,UTF8Encode(IP.AsString),timeout) then
      begin
        Result := UTF8Encode(IP.AsString);
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
       ForceDirectories(destdir);

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
  opensslcfg :=  pyformat(Utf8String(UTF8Decode(FileToString(AppendPathDelim(wapt_base_dir) + 'templates\openssl_template.cfg'))),params);
  opensslcfg_fn := AppendPathDelim(destdir)+'openssl.cfg';
  StringToFile(opensslcfg_fn,opensslcfg);
  try
    //SetEnvironmentVariable('OPENSSL_CONF', PChar(opensslcfg_fn));

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
end;

function ISO8601ToDateTime(Value: String): TDateTime;
var
    FormatSettings: TFormatSettings;
begin
    //GetLocaleFormatSettings(GetThreadLocale, FormatSettings);
    FormatSettings.TimeSeparator := ':';
    FormatSettings.DateSeparator := '-';
    FormatSettings.ShortDateFormat := 'yyyy-MM-dd';
    Result := StrToDate(copy(Value,1,10),FormatSettings)+StrToTime(copy(Value,12,8),FormatSettings);
end;

function DateTimeToISO8601(Value: TDateTime=0): String;
begin
  if Value = 0 then
    Value := Now;
  Result := FormatDateTime('yyyy"-"mm"-"dd"T"hh":"nn":"ss',Now);
end;

function WaptEdition: String;
begin
  if FileExists(MakePath([WaptBaseDir,'waptenterprise','licencing.py'])) then
    Result := 'enterprise'
  else
    Result := 'community';
end;

// Get the registered application location from registry given its executable name
function RegisteredExePath(ExeName:String): String;
var
  Reg: TRegistry;
  KeyPath: String;
begin
  result := '';
  Reg := TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  With Reg do
  try
    RootKey:=HKEY_LOCAL_MACHINE;
    KeyPath := 'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\'+ExeName;
    if KeyExists(KeyPath) and OpenKey(KeyPath,False) then
    begin
      Result := ReadString('');
      CloseKey;
    end
    else
    begin
      KeyPath := 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\'+ExeName;
      if KeyExists(KeyPath) and OpenKey(KeyPath,False) then
      begin
        Result := ReadString('');
        CloseKey;
      end;
    end;
  finally
    Reg.Free;
  end;
end;

// Get the WAPT base directory from the target of the wapt-get symlink in the path
function GetWaptBaseDir(): String;
var
  WaptGetPath: string;
  LinkTarget: string;
begin
  if not RunCommand('which', ['wapt-get'], WaptGetPath) then
  begin
       WriteLn('wapt-get not found in path : cannot get WAPT base dir');
       Exit();
  end;

  Delete(WaptGetPath, length(WaptGetPath), 1); // removing the endline

  if not RunCommand('readlink', [WaptGetPath], LinkTarget) then
  begin
       WriteLn(Format('%s is not a symlink : cannot get WAPT base dir', [WaptGetPath]));
       Exit();
  end;

  Result := ExtractFilePath(LinkTarget);
end;

// Get the registered install location for an application from registry given its executable name
function RegisteredAppInstallLocation(UninstallKey:String): String;
var
  Reg: TRegistry;
  KeyPath: String;
begin
  result := '';
  Reg := TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  With Reg do
  try
    RootKey:=HKEY_LOCAL_MACHINE;
    KeyPath := 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'+UninstallKey;
    if KeyExists(KeyPath) and OpenKey(KeyPath,False) then
    begin
      Result := ReadString('InstallLocation');
      CloseKey;
    end
    else
    begin
      KeyPath := 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'+UninstallKey;
      if KeyExists(KeyPath) and OpenKey(KeyPath,False) then
      begin
        Result := ReadString('InstallLocation');
        CloseKey;
      end;
    end;
  finally
    Reg.Free;
  end;
end;

// should match what is written in python waptpackage.make_valid_package_name()
function MakeValidPackageName(st: String): String;
var
  i:integer;
begin
  result :='';
  for i := 1 to length(st) do
    case st[i] of
      ' ': result := Result+'~';
      ',': result := Result+'_';
      '0'..'9', 'A'..'Z', 'a'..'z', '-','_','=','~','.': result := Result+st[i];
    end;
end;

initialization
//  if not Succeeded(CoInitializeEx(nil, COINIT_MULTITHREADED)) then;
    //Raise Exception.Create('Unable to initialize ActiveX layer');
  GetLanguageIDs(LanguageFull,Language);
  ExtendIndyCryptoLibrary();
  AppVersion := ''; //GetApplicationVersion();


finalization
//  CoUninitialize();
end.
{$else}
interface

implementation

end.
{$endif}
