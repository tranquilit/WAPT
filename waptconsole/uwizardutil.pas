unit uwizardutil;

{$mode objfpc}{$H+}

interface

uses

  sysutils,
  Classes,
  IdCookieManager,
  dynlibs,
  waptcommon;

type

  TCreateSignedCertParams = record
    keyfilename           : UnicodeString;
    crtbasename           : UnicodeString;
    destdir               : UnicodeString;
    country               : UnicodeString;
    locality              : UnicodeString;
    organization          : UnicodeString;
    orgunit               : UnicodeString;
    commonname            : UnicodeString;
    keypassword           : UnicodeString;
    email                 : UnicodeString;
    codesigning           : Boolean;
    IsCACert              : Boolean;
    CACertificateFilename : UnicodeString;
    CAKeyFilename         : UnicodeString;

    _certificate          : String;
    _error_message        : String;
  end;
  PCreateSignedCertParams = ^TCreateSignedCertParams;

  TCreateWaptSetupParams = record
    default_public_cert       : Utf8String;
    default_repo_url          : Utf8String;
    default_wapt_server       : Utf8String;
    destination               : Utf8String;
    company                   : Utf8String;
    OnProgress                : TNotifyEvent;
    WaptEdition               : Utf8String;
    VerifyCert                : Utf8String;
    UseKerberos               : Boolean;
    CheckCertificatesValidity : Boolean;
    EnterpriseEdition         : Boolean;
    OverwriteRepoURL          : Boolean;
    OverwriteWaptServerURL    : Boolean;

    _agent_filename           : String;
    _err_message              : String;
    _result                   : integer;
  end;
  PCreateWaptSetupParams = ^TCreateWaptSetupParams;


  TWaptBuildWaptUpgradeParams = record
    config_filename      : String;
    server_username      : String;
    server_password      : String;
    dualsign             : boolean;
    private_key_password : String;
  end;
  PWaptBuildWaptUpgradeParams = ^TWaptBuildWaptUpgradeParams;


function CreateWaptSetupParams( params : PCreateWaptSetupParams ) : integer;
function CreateSignedCertParams( params : PCreateSignedCertParams ) : integer;

function ServerCertificatSaveChain( var filename : String; const url : String; destdir : String ) : integer;
function check_key_password(key_filename: String; password: String): boolean;
function wapt_build_and_upload_waptupgrade(const params : PWaptBuildWaptUpgradeParams ) : String;
function IdWget_is_404(const url: Utf8String;HttpProxy: String='';userAgent:String='';VerifyCertificateFilename:String='';CookieManager:TIdCookieManager=Nil): boolean;
function check_wapt_installation() : boolean;

function ensure_process_not_running( const process_name : String ) : boolean;


function sys_killall( const ExeFileName: string ) : integer;

function ExtractFileNameNoExt( filename : String ) : string;
function fs_path_exists( const path : String ) : boolean;
function fs_path_concat( const p1 : String; const p2 : String ) : String;
function fs_directory_is_writable( const path : String ): boolean;

function random_alphanum( size : integer ) : String;

function wapt_json_response_is_success( var success : boolean; const json : String ) : integer;


function url_force_protocol( const url : String; const protocol : String ) : String;
function url_concat( const left : String; const right : String ) : String;
function url_resolv_to_same_ip( var same : boolean; const url1 : String ; const url2 : String ) : integer;
function url_hostname( const url : String ) : String;

function http_get(var output: String; const url: String): integer;
function http_reponse_code( var response_code : integer; const url : String ) : integer;

function https_get( var output: String; const https_url: String; certificat_verify : boolean ): integer;
function https_post(var output: String; const https_url: String; certificat_verify : boolean; const content_type : String; const post_data : String): integer;
function https_post_json(var output: String; const https_url: String; certificat_verify : boolean; const post_data : String): integer;

function https_certificate_extract_hostname( var hostname : String; const https_url : String ) : integer;
function https_certificate_is_valid( var valid : boolean; const https_url: String ) : integer;
function https_certificate_is_pinned( var pinned : boolean; const https_url : String ) : integer;
function https_certificate_pin( const https_url : String ) : integer;
function https_certificate_pinned_filename( var filename : String; const https_url : String ) : integer;


function crypto_check_key_password(var success: boolean; const key_filename: String; const password: String): integer;


function process_launch( const command_line : String ) : integer;


implementation

uses
  PythonEngine,
  windows,
  JwaWindows,
  process,
  Forms,
  Controls,
  Dialogs,
  tiscommon,
  superobject,
  tisstrings,
  IdURI,
  IdHTTP,
  VarPyth,
  LazFileUtils,
  dmwaptpython;

const
  HTTP_TIMEOUT : integer = 4 * 1000;


function ensure_process_not_running( const process_name : String ) : boolean;
const
  SLEEP_TIME_BEFORE_RETRY_MS = 2 * 1000;
label
  LBL_START;
var
  msg : String;
  mr  : TModalResult;
begin
LBL_START:
  if not ProcessExists( process_name ) then
    exit( true );

  msg := Format(  'An instance of %s has been found.' + #13#10 +
                  'The program cannot continue unitl this process has terminated.' + #13#10 + #13#10 +
                  'Click on Yes to kill all the process named %s' + #13#10 +
                  'Click on Retry to recheck processes satus' + #13#10 +
                  'Click on Cancel to abort',
                  [process_name, process_name] );

  mr := MessageDlg(  'Error', msg, mtWarning, [mbYes,mbRetry,mbCancel], 0 );

  if mrCancel = mr then
    exit( false );

  if mrRetry = mr then
  begin
    Sleep( SLEEP_TIME_BEFORE_RETRY_MS );
    goto LBL_START;
  end;

  if mrYes = mr then
    result :=  sys_killall(process_name) = 0;

end;

function sys_killall( const ExeFileName: string ) : integer;
label
  LBL_FAILED;
const
  WAIT_TERMINATION_TIME_MS  = 5 * 1000;
  PROCESS_TERMINATE=$0001;
var
  b : WINBOOL;
  h_process_list: THandle;
  h_process : THandle;
  process_entry: TProcessEntry32;
  s : String;
begin

  result := 0;

  h_process := 0;
  h_process_list := 0;

  s := UpperCase(ExeFileName);

  h_process_list := CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0);
  process_entry.dwSize := sizeof(TProcessEntry32);

  b := Process32First(h_process_list,process_entry);
  while integer(b) <> 0 do
  begin
    if s = UpperCase(process_entry.szExeFile) then
    begin
      h_process := OpenProcess( PROCESS_TERMINATE or SYNCHRONIZE, BOOL(0), process_entry.th32ProcessID);
      if h_process = 0 then
        goto LBL_FAILED;
      b := TerminateProcess( h_process, 1 );
      if b = WINBOOL(0) then
        goto LBL_FAILED;
      if WAIT_OBJECT_0 <> WaitForSingleObject( h_process, WAIT_TERMINATION_TIME_MS ) then
        goto LBL_FAILED;
      CloseHandle( h_process );
    end;
    b := Process32Next( h_process_list, process_entry );
  end;
  CloseHandle( h_process_list );

  exit(0);

LBL_FAILED:
  if h_process <> 0 then
    CloseHandle( h_process );
  if h_process_list <> 0 then
    CloseHandle( h_process_list );
  exit(-1);
end;


function ExtractFileNameNoExt( filename : String ) : string;
var
  i : integer;
  s : integer;
  e : integer;
  sz : integer;
begin
  sz := Length(filename);
  e := sz + 1;
  s := e;
  for i := sz downto 1 do
  begin
    if PathDelim = filename[i] then
      break
    else if '.' = filename[i] then
      e := i;
    s := i;
  end;

  e := e - s;
  if e = 0 then
    exit('');
  result := Copy( filename, s, e);
end;

function fs_path_exists(const path: String): boolean;
begin
  if FileExists( path ) then
      exit( true );
  if DirectoryExists( path ) then
      exit( true );

  exit( false );
end;

function fs_path_concat(const p1: String; const p2: String): String;
var
  s : integer;
  c : integer;
begin
  result := ExcludeTrailingPathDelimiter(p1);
  c := Length(p2);
  if c = 0 then
    exit;
  if p2[c] = PathDelim then
    c := c -1;

  s := 1;
  if p2[1] = PathDelim then
  begin
    s := 2;
    c := c -1;
  end;

  if c > 0 then
    result := result +  PathDelim + Copy( p2, s, c );
end;

function fs_directory_is_writable(const path: String): boolean;
var
  h : THandle;
  f : RawByteString;
begin

  if not DirectoryExists(path) then
    exit( false );

  repeat
    f := IncludeTrailingPathDelimiter(path) +  random_alphanum( 20 );
  until not FileExists(f);

  h := FileCreate(f);
  if h = THandle(-1) then
    exit( false );

  FileClose(h);

  if not DeleteFile( @f[1] ) then
    exit( false );

  exit(true);
end;


function random_alphanum( size: integer): String;
var
  i : integer;
  r : integer;
begin
  Randomize;
  SetLength( result, size );
  i := 1;

  while i <> size do
  begin
    // 48-57  Number
    // 65-90  Upper letters
    // 97-122 Lower letters
    case Random(3) of
      0 : r := 48 + Random(10);
      1 : r := 65 + Random(26);
      2 : r := 97 + Random(26);
    end;
    result[i] := Char(r);
    inc(i);
  end;

end;


function wapt_json_response_is_success(var success: boolean; const json: String  ): integer;
var
  so : ISuperObject;
begin
  so := TSuperObject.ParseString( @WideString(json)[1], true );

  if not assigned( so ) then
    exit( -1 );

  so := so.O[ 'success' ];
  if not assigned( so ) then
      exit( -1 );

  if not (so.GetDataType = stBoolean) then
    exit( -1 );

  success := so.AsBoolean;
  exit( 0 );
end;



function IdWget_is_404(const url : Utf8String;HttpProxy: String='';userAgent:String='';VerifyCertificateFilename:String='';CookieManager:TIdCookieManager=Nil): boolean;
begin
  try
    IdWget_Try( url, HttpProxy, userAgent, VerifyCertificateFilename, CookieManager );
    exit( false );
  except on Ex : Exception do
    begin
      if Pos('404', ex.Message) = 0 then
        exit( false );
      exit( true );
    end;
  end;
end;

function check_wapt_installation(): boolean;
label
  LBL_FAIL;
var
  lh : TLibHandle;
begin
  lh := 0;

  lh := LoadLibrary('libopenssl.' + SharedSuffix);
  if lh = 0 then
    goto LBL_FAIL;
  FreeLibrary( lh );


  exit(true);

LBL_FAIL:
  if lh <> 0 then
    FreeLibrary( lh );
  exit(false);
end;


function CreateSignedCertParams(params: PCreateSignedCertParams): integer;
begin
  try
      params^._certificate := CreateSignedCert(
      params^.keyfilename,
      params^.crtbasename,
      params^.destdir,
      params^.country,
      params^.locality,
      params^.organization,
      params^.orgunit,
      params^.commonname,
      params^.email,
      params^.keypassword,
      params^.codesigning,
      params^.IsCACert,
      params^.CACertificateFilename,
      params^.CAKeyFilename
    );
    result := 0;
  except on Ex : Exception do
    begin
      params^._error_message := ex.Message;
      result := -1;
    end;
  end;
end;





function CreateWaptSetupParams(params: PCreateWaptSetupParams): integer;
var
  agent : String;
begin
  params^._agent_filename :=  '';
  params^._err_message := '';


  agent := fs_path_concat( params^.destination, 'waptagent.exe' );
  if FileExists(agent) then
    DeleteFile(@agent[1]);
  agent := '';


  try
    agent  := UTF8Encode( CreateWaptSetup(
      params^.default_public_cert,
      params^.default_repo_url,
      params^.default_wapt_server,
      params^.destination,
      params^.company,
      params^.OnProgress,
      params^.WaptEdition,
      params^.VerifyCert,
      params^.UseKerberos,
      params^.CheckCertificatesValidity,
      params^.EnterpriseEdition,
      params^.OverwriteRepoURL,
      params^.OverwriteWaptServerURL
    ) );
    params^._agent_filename := agent;
    params^._result := 0;
    exit(0);

  except on Ex : Exception do
      params^._err_message := Ex.Message;
  end;

  params^._result := -1;
  exit(-1);
end;

function wapt_build_and_upload_waptupgrade(  const params : PWaptBuildWaptUpgradeParams ): String;
var
  SignDigests : String;
  BuildResult: Variant;
begin
  BuildResult := nil;

  // create waptupgrade package (after waptagent as we need the updated waptagent.sha1 file)
  SignDigests := 'sha256';
  if params^.dualsign then
    SignDigests := SignDigests + ',sha1';

  //BuildResult is a PackageEntry instance
  BuildResult := DMPython.waptdevutils.build_waptupgrade_package(
      waptconfigfile    := params^.config_filename,
      wapt_server_user  := params^.server_username,
      wapt_server_passwd:= params^.server_password,
      key_password      := params^.private_key_password,
      sign_digests      := SignDigests
      );

  if not VarPyth.VarIsNone(BuildResult) and FileExistsUTF8(VarPythonAsString(BuildResult.get('localpath'))) then
  begin
    Result := BuildResult.get('filename');
    DeleteFileUTF8(VarPythonAsString(BuildResult.get('localpath')));
  end
  else
    Result := '';
end;








function check_key_password(key_filename: String; password: String): boolean;
var
  v : Variant;
begin
  try
    v := DMPython.waptcrypto.check_key_password( key_filename := key_filename, password := password );
    exit(PyVarToSuperObject(v).AsBoolean);
  except
    exit(false);
  end;
end;


function ServerCertificatSaveChain( var filename : String; const url : String; destdir : String ) : integer;
var
  cert_filename: String;
  cert_chain   : Variant;
  pem_data     : Variant;
  cert         : Variant;
begin
  try
    cert_chain := DMPython.waptcrypto.get_peer_cert_chain_from_server(url);
    pem_data   := DMPython.waptcrypto.get_cert_chain_as_pem(certificates_chain := cert_chain);
    if VarIsNone(pem_data) then
      exit(-1);
    cert  := cert_chain.__getitem__(0);
    cert_filename :=  IncludeTrailingPathDelimiter(destdir) + cert.cn + '.crt';
    if not DirectoryExists(destdir) then
      ForceDirectory(destdir);
    StringToFile(cert_filename, pem_data, false );
    filename := cert_filename;
    exit(0);
  except
    exit(-1);
  end;
end;


function url_force_protocol(const url: String; const protocol: String) : String;
var
  uri : TIdURI;
begin
  // Handling url even if only hostname is provided
  uri := TIdURI.Create( url );
  try
    uri.Protocol := protocol;
    result := protocol + '://';
    if Length(uri.Username) > 0 then
    begin
      result := result + uri.Username;
      if Length(uri.Password) > 0 then
        result := result + ':' + uri.Password;
      result := result + '@';
    end;
    result := result + uri.Host;
    result := result + uri.GetPathAndParams;
  finally
    uri.Free;
  end;
end;

function url_concat(const left: String; const right: String): String;
var
  r : integer;
begin
  result := left;

  if result[ Length(result) ] <> '/' then
    result := result + '/';

  r := length(right);
  if right[1] = '/' then
    result := result + Copy(right, 2, r - 1 )
  else
    result := result + right;
end;

function url_resolv_to_same_ip(var same: boolean; const url1: String;  const url2: String): integer;
var
  uri : TIdURI;
  s1 : String;
  s2 : String;
begin
  uri := nil;
  s1 := url_force_protocol( url1, 'p' );
  s2 := url_force_protocol( url2, 'p' );

  uri := TIdURI.Create();
  try
    uri.URI := s1;
    s1 := GetIPFromHost( uri.Host );

    uri.URI := s2;
    s2 := GetIPFromHost( uri.Host );

    uri.Free;

    same := s1 = s2;

    exit(0);
  except
  end;

  if Assigned(uri) then
    uri.Free;

  exit(-1);
end;

function url_hostname(const url: String): String;
var
  s : String;
  uri : TIdURI;
begin
  s := url_force_protocol( url, 'p' );
  uri := TIdURI.Create(s);
  result := uri.Host;
  uri.Free;
end;



function http_get(var output: String; const url: String): integer;
var
  http : TIdHTTP;
begin
  http := TIdHTTP.Create;
  http.HandleRedirects  := True;
  http.ConnectTimeout   := HTTP_TIMEOUT;
  http.ReadTimeout      := HTTP_TIMEOUT;

  try
    output := http.Get( url );
    result := 0;
  except
    result := -1;
  end;

  http.Free;
end;

function http_reponse_code(var response_code: integer; const url: String ): integer;
var
  http : TIdHTTP;
  u : String;
begin

  u := url_force_protocol( url, 'http' );

  http := TIdHTTP.Create;
  http.HandleRedirects  := True;
  http.ConnectTimeout   := HTTP_TIMEOUT;
  http.ReadTimeout      := HTTP_TIMEOUT;

  try
    http.Get( u );
  except
  end;

  if http.ResponseCode = -1 then
  begin
    http.Free;
    exit( -1 );
  end;


  response_code := http.ResponseCode;
  http.Free;
  exit(0);

end;



function https_certificat_option( verify : boolean; pinned_certificat_filename : String ) : String;
begin
  if verify = false then
    exit( '0' );

  pinned_certificat_filename := Trim(pinned_certificat_filename);
  if Length(pinned_certificat_filename) = 0 then
    exit('1');

  exit( pinned_certificat_filename );
end;




function https_get(var output: String; const https_url: String; certificat_verify: boolean): integer;
const
  proxy         : String = '';
  user          : String = '';
  password      : String = '';
  method        : String = 'GET';
  userAGent     : String = '';
  AcceptType    : String = '';
  CookieManager : TIdCookieManager = Nil;
var
  f :  String;
  c : String;
  r : integer;
begin
  r := https_certificate_pinned_filename( f, https_url );
  if r <> 0 then
    exit(r);
  c := https_certificat_option( certificat_verify, 'ssl/server/' + f  );
  try
    output := IdHttpGetString( https_url, proxy, HTTP_TIMEOUT, HTTP_TIMEOUT, HTTP_TIMEOUT, user, password, method, userAGent, C, AcceptType, CookieManager );
    exit(0);
  except
  end;
  exit(-1);
end;

function https_post(var output: String; const https_url: String; certificat_verify: boolean; const content_type: String; const post_data: String): integer;
const
  proxy         : String    ='';
  user          : AnsiString='';
  password      : AnsiString='';
  userAgent     : String    ='';
  AcceptType    : String    ='';
  CookieManager : TIdCookieManager = Nil;
var
  f : String;
  c : String;
  r : integer;
begin
  r := https_certificate_pinned_filename( f, https_url );
  if r <> 0 then
    exit( r );

  c := https_certificat_option( certificat_verify, 'ssl/server/' + f );
  try
    output := IdHttpPostData( https_url,  post_data, proxy, HTTP_TIMEOUT, HTTP_TIMEOUT, HTTP_TIMEOUT, user, password, userAgent, content_type, C, AcceptType, CookieManager );
    exit( 0 );
  except
    exit( -1 );
  end;
end;

function https_post_json(var output: String; const https_url: String; certificat_verify: boolean; const post_data: String): integer;
begin
  result := https_post( output, https_url, certificat_verify, 'application/json',  post_data );
end;

function https_certificate_extract_hostname( var hostname : String; const https_url : String ) : integer;
var
  url: String;
  v  : Variant;
  s : String;
begin
  if not Assigned(DMPython) then
    exit(-1);

  url := url_force_protocol( https_url, 'https' );

  try
    v := DMPython.waptcrypto.get_peer_cert_chain_from_server( url );
    if VarIsNone( v ) then
      exit(-1);

    v := v.__getitem__(0);
    if VarIsNone(v) then
      exit(-1);

    v := v.cn;
    if VarIsNone(v) then
      exit(-1);

    s := v;
    s := trim(s);

    if Length(s) = 0 then
      exit(-1);

    hostname := s;
    exit(0);
  except
  end;
  exit(-1);
end;

function https_certificate_is_valid( var valid : boolean; const https_url: String ) : integer;
const
  proxy         : String = '';
  ConnectTimeout: integer= 4000;
  SendTimeOut   : integer= 60000;
  ReceiveTimeOut: integer= 60000;
  user          : String = '';
  password      : String = '';
  method        : String = 'GET';
  userAGent     : String = '';
  AcceptType    : String = '';
  CookieManager : TIdCookieManager = Nil;
var
  hostname  : String;
  r         : integer;
  certificat: String;
begin
  r := https_certificate_extract_hostname( hostname, https_url );
  if r <> 0 then
    exit( r );

  certificat := 'ssl/server/' + hostname + '.crt';
  if not FileExists( certificat ) then
    certificat := '1';

  try
    IdHttpGetString( https_url, proxy, ConnectTimeout, SendTimeOut, ReceiveTimeOut, user, password, method, userAGent, certificat, AcceptType, CookieManager );
    valid := true;
    exit( 0 );
  except
  end;
  valid := false;
  exit( 0 );
end;

function https_certificate_is_pinned( var pinned : boolean; const https_url : String ) : integer;
var
  hostname : String;
  r        : integer;
begin
  r := https_certificate_extract_hostname( hostname, https_url );
  if r <> 0 then
    exit( r );
  pinned := FileExists( 'ssl/server/' + hostname + '.crt' );
  exit( 0 );
end;

function https_certificate_pin( const https_url : String ) : integer;
var
  r : integer;
  f : String;
begin
  r := https_certificate_pinned_filename( f, https_url );
  if r <> 0 then
    exit( r );

  r := ServerCertificatSaveChain( f, https_url, 'ssl/server/' );
  if r <> 0 then
    exit( r );

  exit( 0 );
end;

function https_certificate_pinned_filename( var filename : String ; const https_url: String): integer;
var
  h : String;
  r : integer;
begin
  r := https_certificate_extract_hostname( h, https_url );
  if r <> 0 then
    exit( r );
  filename := h + '.crt';
  exit( 0 );
end;

function crypto_check_key_password(var success: boolean; const key_filename: String; const password: String): integer;
const
  _FAILED = -1;
  _TRUE   =  1;
  _FALSE  =  0;
var
  r : Variant;
  pe : TPythonEngine;
begin
  pe := GetPythonEngine();
  if not Assigned(pe) then
    exit(-1);

  try
    r := DMPython.waptcrypto.check_key_password( key_filename := key_filename, password := password );
  except
    exit(-1);
  end;

  if VarIsNone(r) then
    exit(-1);

  if not VarIsBool(r) then
    exit(-1);

  result := pe.PyObject_IsTrue( ExtractPythonObjectFrom(r));
  if _FAILED = result  then
    exit;

  success := _TRUE = result;
  exit(0);
end;

function process_launch(const command_line: String): integer;
var
  p  : TProcess;
begin
  p := TProcess.Create( nil );
  p.Executable := command_line;
  try
    p.Execute;
    result := 0;
  Except on E : EProcess do
    result := -1;
  end;
  p.Free;
end;

end.

