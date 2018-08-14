unit uutil;

{$mode objfpc}{$H+}

interface

uses
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

implementation

uses
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

end.

