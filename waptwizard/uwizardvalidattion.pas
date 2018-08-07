unit uwizardvalidattion;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  Controls,
  Classes,
  SysUtils,
  uwizardutil
  ;



function wizard_validate_str_not_empty_when_trimmed( w : TWizard; control : TControl; failed_description : String ) : Boolean;
function wizard_validate_str_length_not_zero( w : TWizard; control : TControl; failed_description : String ) : Boolean;
function wizard_validate_str_is_alphanum( w : TWizard;  const str : String; control : TControl ) :  Boolean;
function wizard_validate_str_password_are_equals( w : TWizard; const s1 : String; const s2 : String; control : TControl ) : Boolean;
function wizard_validate_str_is_valid_port_number( w : TWizard; ctrl : TControl; const str : String ) : boolean;

function wizard_validate_waptserver_ping( w : TWizard; const server_url : String; control : TControl ) : Boolean;
function wizard_validate_waptserver_version_not_less( w : TWizard; const  server_url : String; version : String; control : TControl ) : Boolean;
function wizard_validate_waptserver_login( w : TWizard;  const server_url : String; verify_cert : boolean; const login : String; const password : String; control : TControl ) : boolean;
function wizard_validate_waptserver_waptagent_is_not_present( w : TWizard;  const server_url : String; control : TControl ) : Boolean;
function wizard_validate_waptserver_stop_services_no_fail( w : TWizard; control : TControl ) : Boolean;
function wizard_validate_waptserver_start_services( w : TWizard; control : TControl ) : Boolean;
function wizard_validate_waptserver_stop_services( w : TWizard; control : TControl ) : Boolean;

function wizard_validate_service_start( w : TWizard; control : TControl; const name : String ) : Boolean;

function wizard_validate_fs_directory_exist( w : TWizard;  const path : String; control : TControl ) : boolean;
function wizard_validate_fs_can_create_file( w : TWizard;  const path : String; control : TControl ) : boolean;
function wizard_validate_fs_can_create_directory( w :TWizard; const path : String; control : TControl ) : boolean;
function wizard_validate_fs_file_not_exist( w : TWizard; const filename :PChar; const validation_description : PChar; const validation_error : PChar; control : TControl ) : Boolean;
function wizard_validate_fs_ensure_directory( w : TWizard; const path : String; control : TControl ) : Boolean;


function wizard_validate_change_current_user( w : TWizard; const login : PChar; const password : PChar; const failed_string : PChar; control : TControl ) : Boolean;
function wizard_validate_crypto_decrypt_key( w :TWizard; control : TControl; const key_filename : String; const password : String ) : Boolean;
function wizard_validate_crypto_key_and_certificate_are_related( w : TWizard; control : TControl;  const pem : String; const crt : String ) : Boolean;


function wizard_validate_sys_no_innosetup_process( w : TWizard ) : Boolean;


function wizard_validate_net_local_port_is_closed( w : TWizard; port : UInt16; control : TControl ) : Boolean;
function wizard_validate_os_version_for_server( w : TWizard; control : TControl ) : Boolean;

function wizard_validate_run_command_sync( w : TWizard; params : PRunParamatersSync;  const description : String; const error : String; control : TControl ) : boolean;

function wizard_validate_path_is_waptserver( w : TWizard; control : TControl; const path : String ) : boolean;


function wizard_validate_package_prefix( w : TWizard; control : TControl; const prefix : String ) : boolean;

implementation

uses
  {$ifdef windows}
  win32proc,
  windows,
  {$endif}
  IdStack,
  IdTCPClient,
  Dialogs,
  tiscommon,
  waptcommon,
  superobject,
  character,
  EditBtn,
  StdCtrls,
  ComCtrls;

function compare_version( const v1 : String; const v2 : String ): integer;
var
  i : integer;
  l : integer;
  versions : array[0..1] of String;
begin

  versions[0] := v1;
  versions[1] := v2;

  if Length(v1) > Length(v2) then
    l := Length(v1)
  else
    l := Length(v2);

  SetLength( versions[0], l);
  SetLength( versions[1], l );

  for i := 1 to l do
  begin
    if not IsDigit( versions[0][i] ) then
      versions[0][i] := '0';
    if not IsDigit( versions[1][i] ) then
      versions[1][i] := '0';
  end;

  result := StrToInt(versions[0]) - StrToInt(versions[1]);
end;


function wizard_validate_str_not_empty_when_trimmed( w : TWizard; control: TControl; failed_description: String): Boolean;
var
  s : String;
begin
  w.SetValidationDescription( 'Validating field are not empty' );

  if control is TEdit then
    s := TEdit(control).Text
  else if control is TDirectoryEdit then
    s := TDirectoryEdit(control).Text
  else if control is TFileNameEdit then
    s:= TFileNameEdit(control).Text
  else
    Assert( false );

  s := Trim(s);

  if Length(s) = 0 then
  begin
    w.show_validation_error( control, failed_description );
    exit(false);
  end;

  w.ClearValidationDescription();
  exit(true);
end;

function wizard_validate_str_length_not_zero(w: TWizard; control: TControl; failed_description: String): Boolean;
var
  s : String;
begin
  w.SetValidationDescription( 'Validating field are not empty' );

  s := '';

  if control is TEdit then
    s := TEdit(control).Text
  else if control is TDirectoryEdit then
    s := TDirectoryEdit(control).Text
  else if control is TFileNameEdit then
    s:= TFileNameEdit(control).Text
  else
    Assert( false );

  if Length(s) = 0 then
  begin
    w.show_validation_error( control, failed_description );
    exit(false);
  end;

  w.ClearValidationDescription();
  exit(true);
end;

function wizard_validate_str_is_alphanum( w : TWizard; const str: String; control: TControl ): Boolean;
var
  i : integer;
begin
  w.SetValidationDescription( 'Validating field is alphanum' );

  for i := 1 to Length(str) do
    if not IsLetterOrDigit( str[i] ) then
    begin
      w.show_validation_error( control, 'Only alpha numeric characters are allowed' );
      exit( false );
    end;

  w.ClearValidationDescription();
  exit( true );
end;


function wizard_validate_str_password_are_equals(w: TWizard; const s1: String; const s2: String; control: TControl): Boolean;
begin
  w.SetValidationDescription('Validating passwords are equals');
  if s1 <> s2 then
  begin
    w.show_validation_error( control, 'Supplied password differs');
    exit(false);
  end;
  w.ClearValidationDescription();
  exit( true) ;
end;

function wizard_validate_str_is_valid_port_number( w : TWizard; ctrl : TControl; const str : String ) : boolean;
const
  MSG_NOT_A_VALID_PORT_NUMBER : String = 'Not a valid port number';
var
  p : integer;
begin
  try
    p := StrToInt(str);
    if 65535 <> (65535 or p) then
     raise Exception.Create('');
    exit(true);
  Except
  end;
  w.show_validation_error( ctrl, MSG_NOT_A_VALID_PORT_NUMBER);
  exit(false);
end;

function wizard_validate_waptserver_ping( w : TWizard; const server_url: String; control: TControl): Boolean;
const
  MSG_FAILED_PING : String = 'Failed to connect to wapt server : %s';
label
  LBL_NOT_A_WAPTSERVER;
var
  s : String;
  r : integer;
  so: ISuperObject;
  url : String;
begin
  w.SetValidationDescription( 'Validating connection to wapt server' );

  url := url_concat(server_url, '/ping');
  r := http_get( s, url );
  if r <> 0 then
  begin
    w.show_validation_error( control, Format( MSG_FAILED_PING, [s]) );
    exit( false );
  end;

  so := TSuperObject.ParseString(  @WideString(s)[1], false );
  if not Assigned(so) then
    goto LBL_NOT_A_WAPTSERVER;


  so := so.O['result'];
  if not Assigned(so) then
    goto LBL_NOT_A_WAPTSERVER;

  so := so.O['version'];
  if not Assigned(so) then
    goto LBL_NOT_A_WAPTSERVER;

  w.ClearValidationDescription();
  exit( true );

LBL_NOT_A_WAPTSERVER:
  w.show_validation_error( control, 'Host is not a wapt server');
  exit(false);
end;


function wizard_validate_waptserver_version_not_less( w : TWizard; const server_url: String; version: String; control: TControl): Boolean;
label
  LBL_FAILED_TO_OBTAIN_VERSION;
var
  url : String;
  so  : ISuperObject;
  s   : String;
  r   : integer;
  msg : String;
begin


  w.SetValidationDescription( 'Validating server version' );
  url := server_url + '/ping';
  url := url_force_protocol( url, 'http' );
  r := http_get( s, url );
  if r <> 0 then
    goto LBL_FAILED_TO_OBTAIN_VERSION;

  so := TSuperObject.ParseString( @WideString(s)[1] , false );
  if not assigned(so) then
    goto LBL_FAILED_TO_OBTAIN_VERSION;

  if not assigned(so.O['result'] )then
    goto LBL_FAILED_TO_OBTAIN_VERSION;

  if not assigned(so.O['result'].O['version']) then
    goto LBL_FAILED_TO_OBTAIN_VERSION;

  s := UTF8Encode( so.O['result'].S['version'] );
  if compare_version( s, version ) < 0 then
  begin
    msg :=       'Wapt server version does not match wizard version : ' + #13#10;
    msg := msg + 'Server   version is %s' + #13#10;
    msg := msg + 'Required version is %s' + #13#10;
    msg := msg + 'Download the waptsetup from the server to use the correct version' + #13#10;
    msg := msg + 'or specify another server url';
    msg := Format( msg, [ s, version] );
    w.show_validation_error( control, msg  );
    exit(false);
  end;

  w.ClearValidationDescription();
  exit( true );

LBL_FAILED_TO_OBTAIN_VERSION:
  w.show_validation_error( control, 'Failed to obtain WAPT server version' + #13#10 + 'Installation may be broken, reinstall server' );
  exit(false);
end;



function wizard_validate_waptserver_login(w: TWizard; const server_url: String; verify_cert: boolean; const login: String; const password: String; control: TControl): boolean;
var
  so  : ISuperObject;
  r   : integer;
  s   : String;
  b   : boolean;
  url : String;
  b_https : boolean;
begin
  w.SetValidationDescription( 'Validating server authentification' );


  so := TSuperObject.ParseString( '{}', false );
  so.S['user'] := UTF8decode(login);
  so.S['password'] := UTF8Decode(password);

  r := url_protocol( s, server_url );
  if r <> 0 then
    exit(false);
  b_https := s = 'https';

  verify_cert := verify_cert and b_https;
  url := url_concat( server_url , '/api/v3/login' );
  if b_https then
    r := http_post( s, url, MIME_APPLICATION_JSON, UTF8Encode(so.AsJSon(false)) );
  if r <> 0 then
  begin
    w.show_Error( 'A problem has occured when trying to login to server' );
    exit( false  );
  end;

  r := wapt_json_response_is_success( b, s );
  if r <> 0 then
  begin
    w.show_validation_error( nil, 'Wapt server installation may be broken'  );
    exit( false  );
  end;

  if not b then
  begin
    w.show_validation_error( control, 'Bad username/password' );
    exit(false);
  end;

  w.ClearValidationDescription();
  exit( true );

end;

function wizard_validate_waptserver_waptagent_is_not_present( w : TWizard; const server_url: String; control: TControl): Boolean;
var
  r  : integer;
  rc : integer;
  url : String;
begin
  w.SetValidationDescription( 'Validating waptagent is not present on server' );

  url := url_concat( server_url, '/wapt/waptagent.exe' );
  r := http_reponse_code( rc, url );
  if r <> 0 then
  begin
    w.show_error( 'An problem has occured while try to download wapt agent' );
    exit( false );
  end;

  if 200 = rc then
  begin
    w.show_validation_error( control, 'Wapt agent has been found on the server' );
    exit( false );
  end;

  if 404 <> rc then
  begin
    w.show_error( 'An problem has occured while try to download wapt agent' );
    exit( false  );
  end;


  w.ClearValidationDescription();
  exit( true );

end;

function wizard_validate_waptserver_stop_services_no_fail( w: TWizard; control: TControl ): Boolean;
const
  TIMEOUT_SECONDS : integer = 60;
begin
  w.SetValidationDescription( 'Stopping WAPT services' );
  service_stop_no_fail( flip(WAPT_SERVICES), TIMEOUT_SECONDS );
  w.ClearValidationError();
  exit( true );
end;

function wizard_validate_waptserver_start_services(w: TWizard; control: TControl ): Boolean;
const
  TIMEOUT_SECONDS : integer = 60;
  MSG : String = 'Starting service %s';
var
  i : integer;
  r : integer;
  m : integer;
  s : String;
begin
  m := Length(WAPT_SERVICES) -1;
  for i := 0 to m do
  begin
    s := Format( MSG, [ WAPT_SERVICES[i] ] );
    w.SetValidationDescription( s );
    r := service_set_state( WAPT_SERVICES[i], ssRunning, TIMEOUT_SECONDS );
    if r <> 0 then
      exit( false );
  end;
  w.ClearValidationError();
  exit( true );
end;

function wizard_validate_waptserver_stop_services(w: TWizard; control: TControl ): Boolean;
const
  TIMEOUT_SECONDS : integer = 60;
  MSG : String = 'Stopping service %s';
var
  i : integer;
  r : integer;
  m : integer;
  s : String;
begin
  m := Length(WAPT_SERVICES) -1;
  for i := m downto 0 do
  begin
    s := Format( MSG, [ WAPT_SERVICES[i] ] );
    w.SetValidationDescription( s );
    service_stop_no_fail( flip(WAPT_SERVICES), TIMEOUT_SECONDS );
  end;
  w.ClearValidationError();
  exit( true );
end;

function wizard_validate_service_start(w: TWizard; control: TControl; const name: String): Boolean;
const
  TIMEOUT_SECONDS : integer = 15;
  MSG : String = 'Starting service %s';
var
  r : integer;
  s : String;
begin
  s := Format( MSG, [ name ] );
  w.SetValidationDescription( s );
  r := service_set_state( name, ssRunning, TIMEOUT_SECONDS );
  if r <> 0 then
  begin
    w.show_validation_error( control, 'An error has occured while starting service ' + name );
    exit( false );
  end;

  w.ClearValidationError();
  exit( true );
end;




function wizard_validate_fs_directory_exist( w : TWizard; const path: String; control: TControl ): boolean;
begin
  w.SetValidationDescription( Format('Validation directory %s exist', [path]) );

  if not DirectoryExists( path) then
  begin
    w.show_validation_error( control, Format('"%s" is not a directory', [path]) );
    exit( false );
  end;

  w.ClearValidationDescription();
  exit( true );
end;



function wizard_validate_fs_can_create_file( w : TWizard; const path: String; control: TControl): boolean;
begin
  if not wizard_validate_fs_directory_exist( w, path, control ) then
    exit( false );

  w.SetValidationDescription( Format('Validating directory %s is writable', [path]) );

  if not fs_directory_is_writable( path ) then
  begin
    w.show_validation_error( control, Format('"%s" is not a writable directory', [path]) );
    exit( false );
  end;


  w.ClearValidationDescription();
  exit( true );
end;

function wizard_validate_fs_can_create_directory(w: TWizard; const path: String; control: TControl): boolean;
begin
  if not wizard_validate_fs_directory_exist( w, path, control ) then
    exit( false );

  if not fs_directory_is_writable( path ) then
  begin
    w.show_validation_error( control, Format('"%s" is not a writable directory', [path]) );
    exit( false );
  end;

  w.ClearValidationDescription();
  exit( true );
end;

function wizard_validate_fs_file_not_exist(w: TWizard; const filename: PChar; const validation_description: PChar; const validation_error: PChar; control: TControl ): Boolean;
begin
  if Assigned(validation_description) then
    w.SetValidationDescription( validation_description )
  else
    w.SetValidationDescription( Format( 'Validating file "%s" not exist', [filename] ) );

  if FileExists( filename) then
  begin
    if Assigned( validation_error ) then
      w.show_validation_error( control, validation_error )
    else
      w.show_validation_error( control, Format('"%s" already exist', [filename] ) );
    exit( false );
  end;

  w.ClearValidationDescription();
  exit( true );
end;

function wizard_validate_fs_ensure_directory(w: TWizard; const path: String; control: TControl ): Boolean;
var
  s : String;
begin
  s := Format( 'Validating %s exist and is a writable directory', [path] );
  w.SetValidationDescription(s);

  if not DirectoryExists( path ) then
  begin
    s := Format( 'Create directory %s ?', [path] );
    if mrNo = w.show_question( s, mbYesNo ) then
    begin
      w.show_validation_error( control, 'A writable directory is need to continue' );
      exit(false);
    end;

    if not CreateDir( path ) then
    begin
      w.show_validation_error( control, Format('Failed to create directory %s', [path]) );
      exit(false);
    end;
  end;

  if not fs_directory_is_writable(path) then
  begin
    w.show_validation_error( control, Format('Directory %s is not writable',[path]) );
    exit(false);
  end;

    w.ClearValidationDescription();
  exit(true);
end;

function wizard_validate_change_current_user(w: TWizard; const login: PChar; const password: PChar; const failed_string: PChar; control: TControl ): Boolean;
{$ifdef windows}
var
  b : boolean;
  h : THANDLE;
{$endif}
begin
  w.SetValidationDescription( 'Validating can changing current user');

{$ifdef windows}
  b := LogonUser( login, nil, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, @h  );
  b := b and ImpersonateLoggedOnUser( h );
  if b then
  begin
    RevertToSelf();
    w.ClearValidationDescription();
    exit( true );
  end;

  if Assigned(failed_string) then
    w.show_validation_error( control, failed_string )
  else
    w.show_validation_error( control, 'Bad login/password' );
  exit( false );

{$else}
  w.show_validation_error( control, 'Validation not yet implemented');
  exit(false);
{$endif}
end;


function wizard_validate_crypto_decrypt_key(w: TWizard; control: TControl; const key_filename: String; const password: String): Boolean;
var
  r : integer;
  b : boolean;
begin
  w.SetValidationDescription( 'Validating key can be decryted' );

  r := crypto_check_key_password( b, key_filename, password );
  if r <> 0 then
  begin
    w.show_validation_error( control, 'An error has occured while trying key decryption' );
    exit(false);
  end;

  if not b then
  begin
    w.show_validation_error( control, 'Bad password');
    exit(false);
  end;

  w.ClearValidationDescription();
  exit(true);

end;

function wizard_validate_crypto_key_and_certificate_are_related(w: TWizard; control: TControl; const pem: String; const crt: String): Boolean;
var
  s : String;
begin
  w.SetValidationDescription( 'Validating certificate and key are related' );

  // todo
  s := ExtractFileNameNoExt(pem);
  if pos( s, crt ) = 0 then
  begin
    w.show_validation_error( control, 'Certificate and key aren''t related' );
    exit(false);
  end;

  w.ClearValidationDescription();
  exit(true);
end;

function wizard_validate_sys_no_innosetup_process(w: TWizard): Boolean;
begin
  w.SetValidationDescription( 'Checking if there is no inno setup process running' );
  if not ensure_process_not_running('ISCC.exe') then
  begin
    w.show_validation_error( nil, 'A instance of ISCC as been found, cannot continue.');
    exit( false);
  end;
  w.ClearValidationDescription();
  exit(true);
end;



function wizard_validate_net_local_port_is_closed(w: TWizard; port: UInt16; control: TControl): Boolean;
var
  tcp_client : TIdTCPClient;
  msg : String;
begin
  msg := Format( 'Checking that local port %d is not hold by another process' , [port] );
  w.SetValidationDescription( msg );

  tcp_client := TIdTCPClient.Create( nil );
  try
    tcp_client.Connect( 'localhost', port  );
    result := not tcp_client.Connected;
    if tcp_client.Connected then
    begin
      tcp_client.DisconnectNotifyPeer;
      msg :=       'Local port %d is used by another process. ';
      msg := msg + 'Select another port or check your ';
      msg := msg + 'configuration';
      msg := Format( msg, [port] );
    end
  except on Ex : EIdSocketError do
    begin
      result := 10061 = ex.LastError;
      if not result then
        msg := Format( 'Error %d - %s', [ ex.LastError, ex.Message] );
    end;
  end;
  tcp_client.Free;

  if result then
    w.ClearValidationDescription()
  else
    w.show_validation_error( control, msg );



end;

{$ifdef WINDOWS}
function wizard_validate_os_version_for_server(w: TWizard; control: TControl ): Boolean;
var
  msg : String;
begin
  w.ClearValidationError();
  w.SetValidationDescription(  'Checking Windows version' );

  if WindowsVersion < wv7 then
  begin
    msg := 'Minimal required version for server installation is Windows 7';
    w.show_validation_error( control, msg );
    exit( false );
  end;

  w.ClearValidationDescription();
  exit( true );
end;
{$else}
must implement this
{$endif}



function wizard_validate_run_command_sync(w: TWizard; params: PRunParamatersSync; const description: String; const error: String; control: TControl): boolean;
var
  r : integer;
  msg : String;
begin
  w.SetValidationDescription( description );
  try
    r := run_sync( params );
  except on Ex : Exception do
    begin
      msg := Format( '%s ( %s )', [ error ,ex.Message ] );
      w.show_validation_error( control, msg );
      exit( false );
    end;
  end;

  if r <> 0 then
  begin
    w.show_validation_error( control, error );
    exit( false );
  end;

  exit( true );
end;

function wizard_validate_path_is_waptserver(w: TWizard; control: TControl; const path: String): boolean;
var
  s : String;
begin
  w.SetValidationDescription( 'Validating path is a valid waptserver path' );
  s := fs_path_concat( path, 'conf/waptserver.ini');
  if not FileExists(s) then
  begin
    w.show_validation_error( control, 'Not a valid waptserver path');
    exit(false);
  end;
  w.ClearValidationDescription();
  exit(true);
end;

function wizard_validate_package_prefix(w: TWizard; control: TControl; const prefix: String): boolean;
begin
  if not wizard_validate_str_not_empty_when_trimmed( w, control, 'Package prefix cannot be empty' ) then
    exit( false );
  if not wizard_validate_str_is_alphanum( w, prefix, control ) then
    exit(false);

  exit(true);
end;



end.

