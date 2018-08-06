unit uwizardconfigserver_data;

{$mode objfpc}{$H+}

interface

uses

  uwizard,
  Classes, SysUtils;


const

    PAGE_WELCOME                 : String = 'welcome';
    PAGE_SERVER_OPTIONS          : String = 'server_options';
    PAGE_KEYOPTION               : String = 'key_option';
    PAGE_CONSOLE                 : String = 'console';
    PAGE_PACKAGE_CREATE_NEW_KEY  : String = 'package_create_new_key';
    PAGE_PACKAGE_USE_EXISTING_KEY: String = 'package_use_existing_key';
    PAGE_SERVER_URL              : String = 'server_url';
    PAGE_BUILD_AGENT             : String = 'build_agent';
    PAGE_WAPT_SERVICE            : String = 'restart_wapt_service';
    PAGE_FINISHED                : String = 'finished';


type

  TWizardConfigServerData = record
    wapt_server                     : String;
    wapt_user                       : String;
    wapt_password                   : String;
    wapt_password_crypted           : String;
    default_package_prefix          : String;
    package_certificate             : String;
    package_private_key             : String;
    package_private_key_password    : String;
    verify_cert                     : String;
    is_enterprise_edition           : boolean;
    launch_console                  : boolean;
    check_certificates_validity     : String;
    repo_url                        : String;
    nginx_http                      : UInt16;
    nginx_https                     : UInt16;

    has_found_waptagent             : boolean;
    has_found_waptservice           : boolean;
  end;
  PWizardConfigServerData = ^TWizardConfigServerData;


  procedure data_init( data : PWizardConfigServerData );
  function data_write_ini_waptserver(  data : PWizardConfigServerData;  w : TWizard ): integer;
  function data_write_ini_waptget(     data : PWizardConfigServerData;  w : TWizard ): integer;
  function data_write_ini_waptconsole( data : PWizardConfigServerData;  w : TWizard ): integer;
  function data_write_cnf_nginx(       data : PWizardConfigServerData; w : TWizard ): integer;

implementation


uses

  IdURI,
  VarPyth,
  PythonEngine,
  WrapDelphi,

  dialogs,
  dmwaptpython,
  uwapt_ini,
  uwizardutil,
  IniFiles;

procedure data_init( data : PWizardConfigServerData );
var
  s : String;
  r : integer;
  ini : TIniFile;
  uri : TIdURI;
begin
  FillChar( data^, sizeof(TWizardConfigServerData), 0 );

// [wapt-templates]
// repo_url=https://store.wapt.fr/wapt
// verify_cert=1


  data^.is_enterprise_edition := DMPython.IsEnterpriseEdition;
  data^.wapt_server  := 'https://localhost';
  data^.wapt_user    := 'admin';
  data^.repo_url     := 'https://localhost/wapt';
  data^.nginx_http   := 80;
  data^.nginx_https  := 443;
  data^.default_package_prefix := 'test';
  data^.launch_console  := true;
  data^.check_certificates_validity := '0';
  data^.verify_cert  := '0';
  data^.package_certificate := '';
  data^.package_private_key := '';
  data^.package_private_key_password := '';
  data^.has_found_waptagent   := false;
  data^.has_found_waptservice := false;




  // Override from wapt-get.ini
  r := wapt_ini_waptget(s);
  if r = 0 then
  begin
    ini := TIniFile.Create( s );
    try
      data^.wapt_server := Trim(ini.ReadString( INI_GLOBAL, INI_WAPT_SERVER, data^.wapt_server ));
      data^.repo_url    := Trim(ini.ReadString( INI_GLOBAL, INI_REPO_URL, data^.repo_url ));
      data^.default_package_prefix := Trim(ini.ReadString(INI_GLOBAL, INI_DEFAULT_PACKAGE_PREFIX, data^.default_package_prefix) );
      data^.package_certificate := Trim(ini.ReadString(INI_GLOBAL, INI_PERSONAL_CERTIFICATE_PATH, data^.package_certificate) );
    finally
      FreeAndNil(ini);
    end;
  end;


  uri := TIdURI.Create();
  uri.URI := data^.wapt_server;

  if 'http' = uri.Protocol then
    if Length(uri.Port) > 0 then
      data^.nginx_http := StrToInt(uri.port);

  if 'https' = uri.Protocol then
    if Length(uri.Port) > 0 then
      data^.nginx_https := StrToInt(uri.Port);
  FreeAndNil(uri);


  // Has an downloadable agent ?
  r := wapt_installpath_waptserver( s);
  if r = 0 then
  begin
    s := IncludeTrailingBackslash(s) +  'waptserver\repository\wapt\waptagent.exe';
    data^.has_found_waptagent := FileExists(s);
  end;

  // Has wapt service installed ?
  r := wapt_installpath_waptservice(s);
  data^.has_found_waptservice := r = 0;



end;


function data_write_ini_waptserver( data : PWizardConfigServerData; w : TWizard ): integer;
var
  ini : TIniFile;
  r   : integer;
  s   : String;
begin
  ini := nil;



  // waptserver.ini
  w.SetValidationDescription( 'Writing wapt server configuration file' );
  r := wapt_server_installation(s);
  if r <> 0 then
    exit(-1);
  wapt_ini_waptserver( s, s );
  try

    ini := TIniFile.Create(s);
    ini.WriteString( INI_OPTIONS, INI_WAPT_PASSWORD, data^.wapt_password_crypted );

    result := 0;
  except on Ex : Exception do
    begin
      result := -1;
      w.SetValidationDescription( ex.Message );
    end;
  end;

  // wapt-get.ini
  data_write_ini_waptget( data, w );


  if Assigned(ini) then
    FreeAndNil(ini);

end;



function data_write_ini_waptconsole( data : PWizardConfigServerData; w : TWizard ): integer;
var
  ini : TIniFile;
  s   : String;
begin
  ini := nil;

  w.SetValidationDescription( 'Writing waptconsole configuration file' );
  try

    // waptconsole.ini
    wapt_ini_waptconsole(s);
    ini := TIniFile.Create( s );
    ini.WriteString( INI_GLOBAL, INI_CHECK_CERTIFICATES_VALIDITY, data^.check_certificates_validity );
    ini.WriteString( INI_GLOBAL, INI_VERIFIY_CERT,                data^.verify_cert );
    ini.WriteString( INI_GLOBAL, INI_WAPT_SERVER,                 data^.wapt_server );
    ini.WriteString( INI_GLOBAL, INI_REPO_URL,                    data^.wapt_server + '/wapt');
    ini.WriteString( INI_GLOBAL, INI_DEFAULT_PACKAGE_PREFIX,      data^.default_package_prefix );
    ini.WriteString( INI_GLOBAL, INI_PERSONAL_CERTIFICATE_PATH,   data^.package_certificate );
    wapt_ini_write_tis_repo( ini );
    FreeAndNil( ini );


    data_write_ini_waptget( data, w );

    result := 0;
  except on Ex : Exception do
    begin
      result := -1;
      w.SetValidationDescription( ex.Message );
    end;
  end;

  if Assigned(ini) then
    FreeAndNil(ini);

end;

function data_write_ini_waptget( data : PWizardConfigServerData; w : TWizard ): integer;
var
  ini : TIniFile;
  s   : String;
  r   : integer;
 begin
  ini := nil;

  w.SetValidationDescription( 'Writing wapt-get configuration file' );

  r := wapt_installpath_waptservice(s);
  if r <> 0 then
    exit(-1);
  s := IncludeTrailingBackslash(s) + 'wapt-get.ini';
  try
    // wapt-get.ini
    ini := TIniFile.Create( s );
    ini.WriteString( INI_GLOBAL, INI_CHECK_CERTIFICATES_VALIDITY, data^.check_certificates_validity );
    ini.WriteString( INI_GLOBAL, INI_VERIFIY_CERT,                data^.verify_cert );
    ini.WriteString( INI_GLOBAL, INI_WAPT_SERVER,                 data^.wapt_server );
    ini.WriteString( INI_GLOBAL, INI_REPO_URL,                    data^.repo_url );
    ini.WriteString( INI_GLOBAL, INI_DEFAULT_PACKAGE_PREFIX,      data^.default_package_prefix );
    ini.WriteString( INI_GLOBAL, INI_PERSONAL_CERTIFICATE_PATH,   data^.package_certificate );
    wapt_ini_write_tis_repo( ini );
    FreeAndNil( ini );
    result := 0;
  except on Ex : Exception do
    begin
      result := -1;
      w.SetValidationDescription( ex.Message );
    end;
  end;

  if Assigned(ini) then
    FreeAndNil(ini);

end;


function fs_filesize( h : THandle ) : Int64;
var
  p : Int64;
begin
  p := FileSeek( h, 0, fsFromCurrent );
  result := FileSeek( h, 0, fsFromEnd );
  FileSeek( h, p, fsFromBeginning );
end;

function fs_fileread_to_string( var str : String; h : THandle ) : integer;
label
  LBL_FAILED;
var
  r : Int64;
  sz : Int64;
  p : Int64;
begin
  p := -1;

  if h = THandle(-1) then
    exit(-1);

  p := FileSeek( h, 0, fsFromCurrent );

  r := fs_filesize(h);
  if r < 1 then
    goto LBL_FAILED;

  SetLength( str, r );

  FileSeek( h, 0, fsFromBeginning );

  sz := FileRead( h, str[1], r );
  if sz <> r then
    goto LBL_FAILED;

  FileSeek( h, p, fsFromBeginning );

  exit( 0);

LBL_FAILED:
  SetLength( str, 0 );

  if p <> -1 then
    FileSeek( h, p, fsFromBeginning );

  exit(-1);
end;



function data_write_cnf_nginx( data: PWizardConfigServerData; w: TWizard ): integer;

var
  sl : TStringList;
  wapt_root_dir : String;
  wapt_folder   : String;
  r : integer;
begin
  result := -1;
  wapt_folder := '';

  r := wapt_installpath_waptserver( wapt_root_dir );
  if r <> 0 then
    exit( r );


  wapt_root_dir := StringReplace( wapt_root_dir, '\', '\\', [rfReplaceAll] );
  wapt_folder   := StringReplace( wapt_folder,   '\', '\\', [rfReplaceAll] );

  sl := TStringList.Create;
  sl.Append( 'from waptserver import winsetup;');
  sl.Append( 'from waptserver import config;');
  sl.Append( 'winsetup.conf = config.load_config();');
  sl.Append( Format('winsetup.conf[''nginx_http'']  = %d;', [data^.nginx_http])  );
  sl.Append( Format('winsetup.conf[''nginx_https''] = %d;', [data^.nginx_https]) );
  sl.Append( Format('winsetup.make_nginx_config( wapt_root_dir="%s", wapt_folder="%s", force=True);', [wapt_root_dir, wapt_folder]) );


  result := -1;
  try
    DMPython.PythonEng.ExecStrings( sl );
    result := 0;
  except on E : Exception do
    w.show_error( e.Message );
  end;

  sl.Free;

end;


end.

