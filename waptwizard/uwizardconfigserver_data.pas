unit uwizardconfigserver_data;

{$mode objfpc}{$H+}

interface

uses

  uwizard,
  Classes, SysUtils;

type

  TWizardConfigServerData = record
    wapt_server                     : String;
    wapt_user                       : String;
    wapt_password                   : String;
    default_package_prefix          : String;
    personal_certificate_path       : String;
    package_certificate             : String;
    package_private_key             : String;
    package_private_key_password    : String;
    verify_cert                     : String;
    is_enterprise_edition           : boolean;
    server_certificate              : String;
    launch_console                  : boolean;
    check_certificates_validity     : String;
  end;
  PWizardConfigServerData = ^TWizardConfigServerData;



  function TWizardConfigServerData_write_ini_waptserver(  data : PWizardConfigServerData; w : TWizard ): integer;
  function TWizardConfigServerData_write_ini_waptconsole( data : PWizardConfigServerData; w : TWizard ): integer;
  function TWizardConfigServerData_write_ini_waptget(     data : PWizardConfigServerData; w : TWizard ): integer;

implementation


uses
  uwapt_ini,
  DCPsha256,
  ucrypto_pbkdf2,
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
  try

    s := PBKDF2( data^.wapt_password, random_alphanum(5), 29000, 32, TDCP_sha256);

    // waptserver.ini
    ini := TIniFile.Create( 'conf\waptserver.ini' );
    ini.WriteString( INI_OPTIONS, INI_DB_NAME,       'wapt');
    ini.WriteString( INI_OPTIONS, INI_DB_USER,       'wapt' );
    ini.WriteString( INI_OPTIONS, INI_WAPT_USER,     'admin' );
    ini.WriteString( INI_OPTIONS, INI_WAPT_PASSWORD, s );
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
    ini.WriteString( INI_GLOBAL, INI_PERSONAL_CERTIFICATE_PATH,   data^.personal_certificate_path );
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
begin
  ini := nil;

  w.SetValidationDescription( 'Writing wapt-get configuration file' );
  try

    // wapt-get.ini
    ini := TIniFile.Create('wapt-get.ini' );
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

