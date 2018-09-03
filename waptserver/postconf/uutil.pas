unit uutil;

{$mode objfpc}{$H+}

interface

uses
  IdHTTP,
  Classes, SysUtils;

type
Tcreate_signed_cert_params = record
  keyfilename           : String;
  crtbasename           : String;
  destdir               : String;
  country               : String;
  locality              : String;
  organization          : String;
  orgunit               : String;
  commonname            : String;
  keypassword           : String;
  email                 : String;
  codesigning           : Boolean;
  IsCACert              : Boolean;
  CACertificateFilename : String;
  CAKeyFilename         : String;

  _certificate          : String;
  _error_message        : String;
end;
Pcreate_signed_cert_params = ^Tcreate_signed_cert_params;

Tcreate_setup_waptagent_params = record
  default_public_cert       : String;
  default_repo_url          : String;
  default_wapt_server       : String;
  destination               : String;
  company                   : String;
  OnProgress                : TNotifyEvent;
  WaptEdition               : String;
  VerifyCert                : String;
  UseKerberos               : Boolean;
  CheckCertificatesValidity : Boolean;
  EnterpriseEdition         : Boolean;
  OverwriteRepoURL          : Boolean;
  OverwriteWaptServerURL    : Boolean;

  _agent_filename           : String;
  _err_message              : String;
  _result                   : integer;
end;
Pcreate_setup_waptagent_params = ^Tcreate_setup_waptagent_params;

Tcreate_package_waptupgrade_params = record
  config_filename      : String;
  server_username      : String;
  server_password      : String;
  dualsign             : boolean;
  private_key_password : String;

  _filename             : String;
  _err_message          : String;
  _result               : integer;
end;
Pcreate_package_waptupgrade_params = ^Tcreate_package_waptupgrade_params;

TRunSyncParameters = record
  cmd_line         : String;
  timout_ms        : integer;
  on_run_sync_out  : procedure ( const str_out : PChar ) of object;
  on_run_sync_err  : procedure ( const str_err : PChar ) of object;
end;
PRunSyncParameters = ^TRunSyncParameters;




function str_is_alphanum( const str : String ) : boolean;
function str_is_empty_when_trimmed( const str : String ) : boolean;


procedure create_signed_cert_params_init( params : PCreate_signed_cert_params );
function  create_signed_cert_params( params: PCreate_signed_cert_params ): integer;

procedure create_setup_waptagent_params_init( params : Pcreate_setup_waptagent_params );
function  create_setup_waptagent_params( params : Pcreate_setup_waptagent_params ) : integer;

procedure create_package_waptupgrade_params_init( params : Pcreate_package_waptupgrade_params );
function  create_package_waptupgrade_params( params : Pcreate_package_waptupgrade_params ) : integer;


function crypto_check_key_password(var success: boolean; const key_filename: String; const password: String): integer;

function ensure_process_not_running( const process_name : String ) : boolean;
function killall( const ExeFileName: string ) : integer;

function extract_filename_without_extension( var f : String; filename : String ) :integer;

function launch_console( const params : String = '') : integer;
function launch_process( const binary : String; const params: String = ''): integer;

function readfile_available( h : THandle; buffer : PDWORD; buffer_size : integer ) : integer;
function run_sync( params : PRunSyncParameters ) : integer;
function srv_exist( var exist : boolean; const name: String): integer;

function url_concat(const left: String; const right: String): String;
function url_protocol(var protocol: String; const url: String): integer;
function http_create( https : boolean ) : TIdHTTP;
procedure http_free( var http  : TIdHTTP );
function http_is_valid_url(const url: String): boolean;
function http_post(var output: String; const url: String; const content_type: String; const post_data: String): integer;
function http_reponse_code(var response_code: integer; const url: String ): integer;
function http_get(var output: String; const url: String ): integer;



function wapt_json_response_is_success(var success: boolean; const json: String  ): integer;
function wapt_server_ping( const server_url : String ) : boolean;

function offset_language(): integer;

implementation

uses
  LCLTranslator,
  LazUTF8,
  IdSSLOpenSSL,
  IdCookieManager,
  superobject,
  windows,
  JwaWindows,
  tiscommon,
  Controls,
  Forms,
  Dialogs,
  uWaptServerRes,
  waptcommon,
  PythonEngine,
  VarPyth,
  character,
  udefault,
  dmwaptpython;

function str_is_alphanum( const str : String ) : boolean;
var
  i : integer;
begin
  for i := 1 to Length(str) do
  begin
    if not IsLetterOrDigit( str[i] ) then
      exit(false);
  end;
  exit(true);
end;

function str_is_empty_when_trimmed( const str : String ) : boolean;
var
  s : String;
  r : integer;
begin
  s := trim(str);
  r := Length(s);
  exit( 0 = r );
end;

procedure create_signed_cert_params_init( params : PCreate_signed_cert_params );
begin
  FillChar( params^, sizeof(TCreate_signed_cert_params), 0 );
  params^.keyfilename           := '';
  params^.crtbasename           := DEFAULT_CERT_CRTBASENAME;
  params^.destdir               := '';
  params^.country               := DEFAULT_CERT_COUNTRY;
  params^.locality              := DEFAULT_CERT_LOCALITY;
  params^.organization          := DEFAULT_CERT_ORGANIZATION;
  params^.orgunit               := DEFAULT_CERT_ORGUNIT;
  params^.commonname            := DEFAULT_CERT_COMMON_NAME;
  params^.keypassword           := '';
  params^.email                 := DEFAULT_CERT_EMAIL;
  params^.codesigning           := DEFAULT_CERT_CODESIGNING;
  params^.IsCACert              := DEFAULT_CERT_ISCACERT;
  params^.CACertificateFilename := DEFAULT_CERT_CACERTIFICATEFILENAME;
  params^.CAKeyFilename         := DEFAULT_CERT_CAKEYFILENAME;

  params^._certificate          := '';
  params^._error_message        := '';
end;

function create_signed_cert_params(params: PCreate_signed_cert_params): integer;
begin
  try
      params^._certificate := CreateSignedCert(
      UTF8Decode(params^.keyfilename),
      UTF8Decode(params^.crtbasename),
      UTF8Decode(params^.destdir),
      UTF8Decode(params^.country),
      UTF8Decode(params^.locality),
      UTF8Decode(params^.organization),
      UTF8Decode(params^.orgunit),
      UTF8Decode(params^.commonname),
      UTF8Decode(params^.email),
      UTF8Decode(params^.keypassword),
      params^.codesigning,
      params^.IsCACert,
      UTF8Decode(params^.CACertificateFilename),
      UTF8Decode(params^.CAKeyFilename)
    );
    result := 0;
  except on Ex : Exception do
    begin
      params^._error_message := ex.Message;
      result := -1;
    end;
  end;
end;

procedure create_setup_waptagent_params_init( params : Pcreate_setup_waptagent_params );
begin
  FillChar( params^, sizeof(Tcreate_setup_waptagent_params), 0 );


  params^.default_public_cert       := '';
  params^.default_repo_url          := '';
  params^.default_wapt_server       := '';
  params^.destination               := '';
  params^.company                   := '';
  params^.OnProgress                := nil;
  params^.WaptEdition               := DEFAULT_SETUP_AGENT_EDITION;
  params^.VerifyCert                := '0';
  params^.UseKerberos               := false;
  params^.CheckCertificatesValidity := false;
  params^.EnterpriseEdition         := DMPython.IsEnterpriseEdition;
  params^.OverwriteRepoURL          := True;
  params^.OverwriteWaptServerURL    := True;

  params^._agent_filename           := '';
  params^._err_message              := '';
  params^._result                   := 0;

end;

function create_setup_waptagent_params( params: Pcreate_setup_waptagent_params ): integer;
var
  agent : String;
begin
  params^._agent_filename :=  '';
  params^._err_message    := '';


  agent := IncludeTrailingPathDelimiter(params^.destination) + DEFAULT_SETUP_AGENT_FILENAME;
  if FileExists(agent) then
    SysUtils.DeleteFile(agent);
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

procedure create_package_waptupgrade_params_init( params: Pcreate_package_waptupgrade_params);
begin
  FillChar( params^, sizeof(Tcreate_package_waptupgrade_params) , 0 );
end;

function create_package_waptupgrade_params( params: Pcreate_package_waptupgrade_params): integer;
var
  SignDigests : String;
  v: Variant;
  s : String;
begin
  v := nil;

  SignDigests := 'sha256';
  if params^.dualsign then
    SignDigests := SignDigests + ',sha1';

  try
    //BuildResult is a PackageEntry instance
    v := DMPython.waptdevutils.build_waptupgrade_package(
      waptconfigfile    := params^.config_filename,
      wapt_server_user  := params^.server_username,
      wapt_server_passwd:= params^.server_password,
      key_password      := params^.private_key_password,
      sign_digests      := SignDigests
      );


    if not VarPyth.VarIsNone(v) and FileExists( UTF8Encode(VarPythonAsString(v.get('localpath')))) then
    begin
      params^._filename := v.get('filename');
      s := VarPythonAsString( v.get('localpath') );
      SysUtils.DeleteFile(s);
      params^._result := 0;
    end
  except on ex : Exception do
    begin
      params^._err_message := ex.Message;
      params^._result := -1;
    end;
  end;

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

  r := DMPython.waptcrypto.check_key_password( key_filename := key_filename, password := password );

  if VarIsNone(r) then
    exit(-1);

  if not VarIsBool(r) then
    exit(-1);

  result := pe.PyObject_IsTrue( ExtractPythonObjectFrom(r));
  if _FAILED = result  then
    exit(-1);

  success := _TRUE = result;
  exit(0);
end;

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

  msg := Format( rs_other_process_has_been_found, [process_name, process_name] );

  mr := MessageDlg(  'Error', msg, mtWarning, [mbYes,mbRetry,mbCancel], 0 );

  if mrCancel = mr then
    exit( false );

  if mrRetry = mr then
  begin
    Sleep( SLEEP_TIME_BEFORE_RETRY_MS );
    goto LBL_START;
  end;

  if mrYes = mr then
    result :=  killall(process_name) = 0;

end;

function killall( const ExeFileName: string ) : integer;
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



function extract_filename_without_extension(var f: String; filename: String ): integer;
var
  s : String;
  i : integer;
  l : integer;
  p : integer;
begin
  s := ExtractFileName( filename );
  l := Length(s);

  if l = 0 then
    exit(-1);

  p := 0;
  for i := l downto 1 do
  begin
    if '.' = s[i] then
    begin
      p := i;
      break;
    end;
  end;

  case p of
    0,1 : f := s;
    else
      f := Copy( s, 1, i -1 );
  end;

  exit(0);

end;

function launch_console(const params: String): integer;
var
  cmd : String;
begin
  cmd := IncludeTrailingPathDelimiter(WaptBaseDir)+ 'waptconsole.exe';
  result := launch_process( cmd, params );
end;

function launch_process( const binary : String; const params: String): integer;
var
  wcmd    : WideString;
  wparams : WideString;
  r       : HINST;
  msg     : String;
begin
  wcmd := WideString(binary);
  if not FileExists(wcmd) then
    exit(-1);

  r := ShellExecuteW(0,'open', @wcmd[1], @wparams[1], Nil, SW_SHOW);
  if r < 32 then
  begin
    case r of
      0                     : msg := 'The operating system is out of memory or resources.';
      ERROR_FILE_NOT_FOUND  : msg := 'The specified file was not found.';
      ERROR_PATH_NOT_FOUND  : msg := 'The specified path was not found..';
      ERROR_BAD_FORMAT      : msg := 'The .exe file is invalid (non-Win32 .exe or error in .exe image)..';
      5                     : msg := 'The operating system denied access to the specified file..'; {SE_ERR_ACCESSDENIED}
      SE_ERR_ASSOCINCOMPLETE: msg := 'The file name association is incomplete or invalid..';
      SE_ERR_DDEBUSY        : msg := 'The DDE transaction could not be completed because other DDE transactions were being processed..';
      SE_ERR_DDEFAIL        : msg := 'The DDE transaction failed..';
      SE_ERR_DDETIMEOUT     : msg := 'The DDE transaction could not be completed because the request timed out..';
      32                    : msg := 'The specified DLL was not found..'; {SE_ERR_DLLNOTFOUND}
      SE_ERR_NOASSOC        : msg := 'There is no application associated with the given file name extension. This error will also be returned if you attempt to print a file that is not printable..';
      8                     : msg := 'There was not enough memory to complete the operation..'; {SE_ERR_OOM}
      SE_ERR_SHARE          : msg := 'A sharing violation occured.';
      else
        msg := Format('Unknow error %d', [r] );
    end;
    MessageDlg( Application.Name, msg, mtError, [mbOK], 0 );
    exit( -1 );
  end;

  exit(0);
end;

function readfile_available( h : THandle; buffer : PDWORD; buffer_size : integer ) : integer;
var
  bytes_available: DWORD;
  bytes_readed   : DWORD;
  b : BOOL;
begin
  b := PeekNamedPipe( h, nil, 0, nil, @bytes_available, nil );
  if not b then
    exit(-1);

  if bytes_available = 0 then
    exit(0);

  b := ReadFile( h, buffer, bytes_available, @bytes_readed, nil );
  if not b then
    exit(-1);

  exit( bytes_readed )
end;


function run_sync(params: PRunSyncParameters): integer;
label
  LBL_FAIL;
const
  I  : integer = 0;
  O  : integer = 1;
  E  : integer = 2;
  R  : integer = 0;
  W  : integer = 1;
  WAIT_DURATION : integer = 15;
  BUFFER_SIZE  = 4096 - 1;
var
  sa : SECURITY_ATTRIBUTES;
  si : STARTUPINFO;
  pi : PROCESS_INFORMATION;
  b  : BOOL;
  dw : DWORD;
  buffer : array[0..BUFFER_SIZE-1] of DWORD;
  handles : array[0..2, 0..1] of THandle;
  rr : integer;

  procedure __process_pipes();
  begin
    // Read output
    if Assigned(params^.on_run_sync_out) then
    begin
      rr := readfile_available( handles[O,R], buffer, BUFFER_SIZE );
      if rr > 0 then
      begin
        buffer[rr] := 0;
        params^.on_run_sync_out( @buffer[0] );
      end;
    end;

    // Read eror
    if Assigned(params^.on_run_sync_err) then
    begin
      rr := readfile_available( handles[E,R], buffer, BUFFER_SIZE );
      if rr > 0 then
      begin
        buffer[rr] := 0;
        params^.on_run_sync_err( @buffer[0] );
      end;
    end;

  end;

begin


  //
  FillChar( handles, sizeof(THandle) * 6, 0 );
  FillChar( pi, sizeof(PROCESS_INFORMATION), 0 );

  //
  FillChar( sa, sizeof(SECURITY_ATTRIBUTES), 0 );
  sa.nLength := sizeof(SECURITY_ATTRIBUTES);
  sa.bInheritHandle := TRUE;

  CreatePipe( handles[I,R], handles[I,W], @sa, 0 );
  CreatePipe( handles[O,R], handles[O,W], @sa, 0 );
  CreatePipe( handles[E,R], handles[E,W], @sa, 0 );

  //
  FillChar( si, sizeof(STARTUPINFO), 0 );
  si.cb           := sizeof(STARTUPINFO);
  si.dwFlags      := STARTF_USESHOWWINDOW or STARTF_USESTDHANDLES;
  si.wShowWindow  := SW_HIDE;
  si.hStdInput    := handles[I,R];
  si.hStdOutput   := handles[O,W];
  si.hStdError    := handles[E,W];

  UniqueString( params^.cmd_line );
  b := CreateProcess( nil, @params^.cmd_line[1], nil, nil, True, CREATE_NEW_CONSOLE, nil, nil, si, pi );
  if not b then
    goto LBL_FAIL;

  CloseHandle( handles[I,R] );
  CloseHandle( handles[O,W] );
  CloseHandle( handles[E,W] );

  while (params^.timout_ms > 0) do
  begin
    __process_pipes();
    Application.ProcessMessages;
    dw := WaitForSingleObject( pi.hProcess, WAIT_DURATION );
    if WAIT_TIMEOUT = dw then
      dec( params^.timout_ms, WAIT_DURATION )
    else if WAIT_OBJECT_0 = dw then
      break
    else
      goto LBL_FAIL;
  end;

  // Terminate process
  if params^.timout_ms < 1 then
    TerminateProcess( pi.hProcess, UINT(ERROR_CANCELLED) );


  __process_pipes();
  Application.ProcessMessages;

  b := GetExitCodeProcess(pi.hProcess, &dw);



  CloseHandle( handles[I,W] );
  CloseHandle( handles[O,R] );
  CloseHandle( handles[E,R] );


  if b then
    exit(dw);

  exit(0);

LBL_FAIL:

  if pi.hProcess <> 0 then
    TerminateProcess( pi.hProcess, UINT(ERROR_CANCELLED) );

  CloseHandle( handles[I,R] );
  CloseHandle( handles[I,W] );
  CloseHandle( handles[O,R] );
  CloseHandle( handles[O,W] );
  CloseHandle( handles[E,R] );
  CloseHandle( handles[E,W] );

  exit( -1 );
end;

function srv_exist( var exist : boolean; const name: String): integer;
var
  params : TRunSyncParameters;
  r : integer;
begin
  FillChar( params, sizeof(PRunSyncParameters), 0 );

  params.cmd_line := 'sc query ' + name;
  params.timout_ms := 2 * 1000;

  try
    r := run_sync( @params );
    exist := r = 0;
    if (r = 0)  or (r = 1060) then
      exit(0);
    exit(-1);
  except on Ex : EOSError do
    begin
      exist := Pos(  '1060', ex.Message ) = 0;
      if not exist then
        exit(0);
      exit(-1);
    end;
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

function wapt_server_ping( const server_url: String ): Boolean;
label
  LBL_FAILED;
var
  s : String;
  r : integer;
  so: ISuperObject;
  url : String;
begin
  url := url_concat(server_url, '/ping');
  r := http_get( s, url );
  if r <> 0 then
    exit( false );

  so := TSuperObject.ParseString(  @WideString(s)[1], false );
  if not Assigned(so) then
    goto LBL_FAILED;

  so := so.O['result'];
  if not Assigned(so) then
    goto LBL_FAILED;

  so := so.O['version'];
  if not Assigned(so) then
    goto LBL_FAILED;

  exit( true );

LBL_FAILED:
  exit(false);
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



function url_protocol(var protocol: String; const url: String): integer;
var
  i : integer;
begin
  i := Pos('://', url);
  if i = 0 then
    exit(-1);
  dec(i);
  protocol := Copy( url, 1, i );
  exit(0);
end;


function http_create( https : boolean ) : TIdHTTP;
var
  http : TIdHTTP;
  ssl  : TIdSSLIOHandlerSocketOpenSSL;
begin
  ssl := nil;

  http := TIdHTTP.Create;
  http.HandleRedirects  := True;
  http.ConnectTimeout   := HTTP_TIMEOUT;
  http.ReadTimeout      := HTTP_TIMEOUT;
  http.IOHandler        := nil;

  if https then
  begin
    ssl := TIdSSLIOHandlerSocketOpenSSL.Create;
    ssl.SSLOptions.Method := sslvSSLv23;
    http.IOHandler := ssl;
  end;


  result := http;
end;

procedure http_free( var http  : TIdHTTP );
begin
  if nil <> http.IOHandler then
  begin
    http.IOHandler.Free;
    http.IOHandler := nil;
  end;
  http.Free;
  http := nil;
end;

function http_is_valid_url(const url: String): boolean;
var
  proto : String;
  b_http : boolean;
  b_https : boolean;
begin
  if 0 <> url_protocol( proto, url) then
    exit( false );

  b_http := proto = 'http';
  b_https:= proto = 'https';

  result := b_http or b_https;
end;


function http_post(var output: String; const url: String; const content_type: String; const post_data: String): integer;
const
  proxy         : String    ='';
  user          : AnsiString='';
  password      : AnsiString='';
  userAgent     : String    ='';
  AcceptType    : String    ='';
  CookieManager : TIdCookieManager = Nil;
  VerifyCertificateFilename : String = '0';
begin

  if not http_is_valid_url(url) then
  begin
    output := 'Invalid url';
    exit( -1 );
  end;

  try
    output := IdHttpPostData( url,
                              post_data,
                              proxy,
                              HTTP_TIMEOUT,
                              HTTP_TIMEOUT,
                              HTTP_TIMEOUT,
                              user,
                              password,
                              userAgent,
                              content_type,
                              VerifyCertificateFilename,
                              AcceptType,
                              CookieManager );
    exit( 0 );
  except on e : Exception do
    begin
      output := e.Message;
      exit( -1 );
    end;
  end;
end;

function http_reponse_code(var response_code: integer; const url: String ): integer;
var
  http : TIdHTTP;
  proto : String;
  b_https : Boolean;
begin

  if not http_is_valid_url(url) then
    exit(-1);

  url_protocol( proto, url );
  b_https := proto = 'https';

  http := http_create( b_https );

  try
    http.Get(url);
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

function http_get(var output: String; const url: String ): integer;
var
  http : TIdHTTP;
  proto : String;
  b_http : boolean;
  b_https : boolean;
begin

  if not http_is_valid_url(url) then
  begin
    output := 'Invalid url';
    exit( -1 );
  end;

  url_protocol( proto, url );
  b_https:= proto = 'https';

  http := http_create( b_https );


  try
    output := http.Get( url );
    result := 0;
  except on E : Exception do
    begin
      result := -1;
      output := e.Message;
    end;
  end;

  http_free( http );

end;

function offset_language(): integer;
const
  PAGES_EN_OFFSET : integer =	0;
  PAGES_FR_OFFSET : integer =	1;
  PAGES_DE_OFFSET : integer =	2;
var
  Lang, FallbackLang: String;
  i : Integer;
begin
  { XXX This is not what I'd call clean language detection... }
  for i := 1 to ParamCount-1 do
  if ((ParamStr(i) = '-l') or (ParamStr(i) = '--lang')) and (i+1 <> ParamCount-1) then
  begin

    if 'de' = ParamStr(i+1)then
    begin
       result := PAGES_DE_OFFSET;
       exit;
    end;

    if 'fr' = ParamStr(i+1) then
    begin
       result := PAGES_FR_OFFSET;
       exit;
    end;

    if 'en' = ParamStr(i+1) then
    begin
      result := PAGES_EN_OFFSET;
      exit;
    end;

  end;

  LazGetLanguageIDs(Lang, FallbackLang);
  if FallbackLang = 'fr' then
    result := PAGES_FR_OFFSET
  else if FallbackLang = 'de' then
    result := PAGES_DE_OFFSET
  else
    result := PAGES_EN_OFFSET;

  SetDefaultLang( FallbackLang );

end;

end.

