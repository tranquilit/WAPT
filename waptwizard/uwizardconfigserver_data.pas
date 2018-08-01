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
    server_certificate              : String;
    launch_console                  : boolean;
    check_certificates_validity     : String;
    repo_url                        : String;
    configure_console               : Boolean;
  end;
  PWizardConfigServerData = ^TWizardConfigServerData;



  function TWizardConfigServerData_write_ini_waptserver(  data : PWizardConfigServerData; w : TWizard ): integer;
  function TWizardConfigServerData_write_ini_waptconsole( data : PWizardConfigServerData; w : TWizard ): integer;
  function TWizardConfigServerData_write_ini_waptget(     data : PWizardConfigServerData; w : TWizard ): integer;

implementation


uses
  uwapt_ini,
  uwizardutil,
  IniFiles;


function TWizardConfigServerData_write_ini_waptserver( data : PWizardConfigServerData; w : TWizard ): integer;
var
  ini : TIniFile;
  r   : integer;
  s   : String;
begin
  ini := nil;

  w.SetValidationDescription( 'Writing wapt server configuration file' );

  r := wapt_server_installation(s);
  if r <> 0 then
    exit(-1);
  wapt_ini_waptserver( s, s );
  try


    // waptserver.ini
    ini := TIniFile.Create(s);
    ini.WriteString( INI_OPTIONS, INI_DB_NAME,       'wapt');
    ini.WriteString( INI_OPTIONS, INI_DB_USER,       'wapt' );
    ini.WriteString( INI_OPTIONS, INI_WAPT_USER,     'admin' );
    ini.WriteString( INI_OPTIONS, INI_WAPT_PASSWORD, data^.wapt_password_crypted );
    ini.WriteString( INI_OPTIONS, INI_ALLOW_UNAUTHENTICATED_REGISTRATION, 'True' );
    r := Length( Trim(ini.ReadString( INI_OPTIONS, INI_SERVER_UUID, '')) );
    if r = 0 then
      ini.WriteString( INI_OPTIONS, INI_SERVER_UUID, random_server_uuid() );
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



function TWizardConfigServerData_write_ini_waptconsole( data : PWizardConfigServerData; w : TWizard ): integer;
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
    FreeAndNil( ini );


    // write wapt-get template
    wapt_installpath_waptserver(s);
    s := IncludeTrailingBackslash(s) + 'wapt-get.ini';
    ini := TIniFile.Create( s );
    ini.WriteString( INI_GLOBAL, INI_CHECK_CERTIFICATES_VALIDITY, data^.check_certificates_validity );
    ini.WriteString( INI_GLOBAL, INI_VERIFIY_CERT,                data^.verify_cert );
    ini.WriteString( INI_GLOBAL, INI_WAPT_SERVER,                 data^.wapt_server );
    ini.WriteString( INI_GLOBAL, INI_REPO_URL,                    data^.wapt_server + '/wapt');
    ini.WriteString( INI_GLOBAL, INI_DEFAULT_PACKAGE_PREFIX,      data^.default_package_prefix );
    ini.WriteString( INI_GLOBAL, INI_PERSONAL_CERTIFICATE_PATH,   data^.package_certificate );
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

function TWizardConfigServerData_write_ini_waptget( data : PWizardConfigServerData; w : TWizard ): integer;
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
    ini := TIniFile.Create(s);
    ini.WriteString( INI_GLOBAL, INI_CHECK_CERTIFICATES_VALIDITY, data^.check_certificates_validity );
    ini.WriteString( INI_GLOBAL, INI_VERIFIY_CERT,                data^.verify_cert );
    ini.WriteString( INI_GLOBAL, INI_WAPT_SERVER,                 data^.wapt_server );
    ini.WriteString( INI_GLOBAL, INI_REPO_URL,                    data^.wapt_server + '/wapt' );
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

end.

