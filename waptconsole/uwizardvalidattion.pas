unit uwizardvalidattion;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  Controls,
  Classes, SysUtils;



function wizard_validate_str_not_empty_when_trimmed( w : TWizard; control : TControl; failed_description : String ) : Boolean;
function wizard_validate_str_length_not_zero( w : TWizard; control : TControl; failed_description : String ) : Boolean;
function wizard_validate_str_is_alphanum( w : TWizard;  const str : String; control : TControl ) :  Boolean;

function wizard_validate_waptserver_ping( w : TWizard; const server_url : String; control : TControl ) : Boolean;
function wizard_validate_waptserver_version_not_less( w : TWizard; const  server_url : String; version : String; control : TControl ) : Boolean;
function wizard_validate_waptserver_login( w : TWizard;  const server_url : String; const login : String; const password : String; control : TControl ) : boolean;
function wizard_validate_waptserver_waptagent_is_not_present( w : TWizard;  const server_url : String; control : TControl ) : Boolean;

function wizard_validate_fs_directory_exist( w : TWizard;  const path : String; control : TControl ) : boolean;
function wizard_validate_fs_can_create_file( w : TWizard;  const path : String; control : TControl ) : boolean;
function wizard_validate_fs_can_create_directory( w :TWizard; const path : String; control : TControl ) : boolean;
function wizard_validate_fs_file_not_exist( w : TWizard; const filename :PChar; const validation_description : PChar; const validation_error : PChar; control : TControl ) : Boolean;


function wizard_validate_change_current_user( w : TWizard; const login : PChar; const password : PChar; const failed_string : PChar; control : TControl ) : Boolean;


implementation

uses
  {$ifdef windows}
  windows,
  {$endif}
  tiscommon,
  waptcommon,
  uwizardutil,
  superobject,
  character,
  EditBtn,
  StdCtrls,
  ComCtrls;

function wizard_validate_str_not_empty_when_trimmed( w : TWizard; control: TControl; failed_description: String): Boolean;
var
  s : String;
begin
  w.SetValidationDescription( 'Validating field are not empty' );

  if control is TEdit then
    s := TEdit(control).Text
  else if control is TDirectoryEdit then
    s := TDirectoryEdit(control).Text
  else
    Assert( false );

  s := Trim(s);

  if Length(s) = 0 then
  begin
    w.ShowValidationError( control, failed_description );
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
  else
    Assert( false );

  if Length(s) = 0 then
  begin
    w.ShowValidationError( control, failed_description );
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
      w.ShowValidationError( control, 'Only alpha numeric characters are allowed' );
      exit( false );
    end;

  w.ClearValidationDescription();
  exit( true );
end;

function wizard_validate_waptserver_ping( w : TWizard; const server_url: String; control: TControl): Boolean;
label
  LBL_NOT_A_WAPTSERVER;
var
  s : String;
  r : integer;
  so: ISuperObject;
begin
  w.SetValidationDescription( 'Validating connection to wapt server' );

  s := server_url + '/ping';
  s := url_force_protocol( s, 'http' );
  r := http_get( s, s );
  if r <> 0 then
  begin
    w.ShowValidationError( control, 'Failed to connect to wapt server');
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
  w.ShowValidationError( control, 'Host is not a wapt server');
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
  r := CompareVersion( s, version );
  if r < 0 then
  begin
    w.ShowValidationError( control, Format('Wapt  version is too old ( %s < %s )', [ s, WAPTServerMinVersion])  );
    exit(false);
  end;

  w.ClearValidationDescription();
  exit( true );

LBL_FAILED_TO_OBTAIN_VERSION:
  w.ShowValidationError( control, 'Failed to obtain WAPT server version' + #13#10 + 'Installation may be broken, reinstall server' );
  exit(false);
end;



function wizard_validate_waptserver_login( w : TWizard; const server_url: String; const login: String; const password: String; control: TControl): boolean;
var
  so  : ISuperObject;
  r   : integer;
  s   : String;
  url : String;
  b   : boolean;
begin
  w.SetValidationDescription( 'Validating server authentification' );


  so := TSuperObject.ParseString( '{}', false );
  so.S['user'] := UTF8decode(login);
  so.S['password'] := UTF8Decode(password);

  url := url_force_protocol( server_url, 'https' );
  url := url_concat( url , '/api/v3/login' );
  r := https_post_json ( s, url, true, UTF8Encode(so.AsJSon(false)) );
  if r <> 0 then
  begin
    w.ShowError( 'A problem has occured when trying to login to server' );
    exit( false  );
  end;

  r := wapt_json_response_is_success( b, s );
  if r <> 0 then
  begin
    w.ShowValidationError( nil, 'Wapt server installation may be broken'  );
    exit( false  );
  end;

  if not b then
  begin
    w.ShowValidationError( control, 'Bad username/password' );
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
    w.ShowError( 'An problem has occured while try to download wapt agent' );
    exit( false );
  end;

  if 200 = rc then
  begin
    w.ShowValidationError( control, 'Wapt agent has been found on the server' );
    exit( false );
  end;

  if 404 <> rc then
  begin
    w.ShowError( 'An problem has occured while try to download wapt agent' );
    exit( false  );
  end;


  w.ClearValidationDescription();
  exit( true );

end;

function wizard_validate_fs_directory_exist( w : TWizard; const path: String; control: TControl ): boolean;
begin
  w.SetValidationDescription( Format('Validation directory %s exist', [path]) );

  if not DirectoryExists( path) then
  begin
    w.ShowValidationError( control, Format('"%s" is not a directory', [path]) );
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

  if not fs_directory_is_file_writable( path ) then
  begin
    w.ShowValidationError( control, Format('"%s" is not a writable directory', [path]) );
    exit( false );
  end;


  w.ClearValidationDescription();
  exit( true );
end;

function wizard_validate_fs_can_create_directory(w: TWizard; const path: String; control: TControl): boolean;
begin
  if not wizard_validate_fs_directory_exist( w, path, control ) then
    exit( false );

  if not fs_directory_is_dir_writable( path ) then
  begin
    w.ShowValidationError( control, Format('"%s" is not a writable directory', [path]) );
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
      w.ShowValidationError( control, validation_error )
    else
      w.ShowValidationError( control, Format('"%s" already exist', [filename] ) );
    exit( false );
  end;

  w.ClearValidationDescription();
  exit( true );
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
    w.ShowValidationError( control, failed_string )
  else
    w.ShowValidationError( control, 'Bad login/password' );
  exit( false );

{$else}
  w.ShowValidationError( control, 'Validation not yet implemented');
  exit(false);
{$endif}
end;



end.

