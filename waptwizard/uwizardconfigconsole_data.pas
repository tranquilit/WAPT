unit uwizardconfigconsole_data;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  Classes, SysUtils;

const

    WizardConfigConsole_page_welcome                 : String = 'welcome';
    WizardConfigConsole_page_server                  : String = 'server';
    WizardConfigConsole_page_keyoption               : String = 'key_option';
    WizardConfigConsole_page_package_create_new_key  : String = 'package_create_new_key';
    WizardConfigConsole_page_package_use_existing_key: String = 'package_use_existing_key';
    WizardConfigConsole_page_build_agent             : String = 'build_agent';
    WizardConfigConsole_page_finished                : String = 'finished';

type
  TWizardConfigConsoleData = record
    is_enterprise_edition         : boolean;
    wapt_server                   : String;
    wapt_user                     : String;
    wapt_password                 : String;
    default_package_prefix        : String;
    personal_certificate_path     : String;
    package_certificate           : String;
    package_private_key           : String;
    package_private_key_password  : String;
    verify_cert                   : String;
    server_certificate            : String;
    launch_console                : boolean;
    check_certificates_validity   : String;
    repo_url                      : String;
  end;
  PWizardConfigConsoleData = ^TWizardConfigConsoleData;



  function TWizardConfigConsoleData_write_ini_waptconsole( data : PWizardConfigConsoleData; w : TWizard ): integer;
  function TWizardConfigConsoleData_write_ini_waptget( data : PWizardConfigConsoleData; w : TWizard ): integer;

implementation


uses
  uwapt_ini,
  uwizardutil,
  IniFiles;

// waptconsole.ini
function TWizardConfigConsoleData_write_ini_waptconsole( data: PWizardConfigConsoleData; w: TWizard): integer;
var
  ini : TIniFile;
  s   : String;
begin
  result := -1;
  try
    wapt_ini_waptconsole(s);
    ini := TIniFile.Create( s );
    ini.WriteString( INI_GLOBAL, INI_CHECK_CERTIFICATES_VALIDITY, data^.check_certificates_validity );
    ini.WriteString( INI_GLOBAL, INI_VERIFIY_CERT,                data^.verify_cert);
    ini.WriteString( INI_GLOBAL, INI_WAPT_SERVER,                 data^.wapt_server );
    ini.WriteString( INI_GLOBAL, INI_REPO_URL,                    data^.repo_url );
    ini.WriteString( INI_GLOBAL, INI_DEFAULT_PACKAGE_PREFIX,      data^.default_package_prefix );
    ini.WriteString( INI_GLOBAL, INI_PERSONAL_CERTIFICATE_PATH,   data^.package_certificate );
    result := 0;
  finally
    if Assigned(ini) then
      FreeAndNil(ini);
  end;
end;

// wapt-get.ini
function TWizardConfigConsoleData_write_ini_waptget( data: PWizardConfigConsoleData; w: TWizard): integer;
var
  ini : TIniFile;
  s   : String;
  r : integer;
begin
  result := -1;
  try
    r := wapt_ini_waptget(s);
    ini := TIniFile.Create( s );
    ini.WriteString( INI_GLOBAL, INI_CHECK_CERTIFICATES_VALIDITY, data^.check_certificates_validity );
    ini.WriteString( INI_GLOBAL, INI_VERIFIY_CERT,                data^.verify_cert);
    ini.WriteString( INI_GLOBAL, INI_WAPT_SERVER,                 data^.wapt_server);
    ini.WriteString( INI_GLOBAL, INI_REPO_URL,                    data^.repo_url );
    result := 0;
  finally
    if Assigned(ini) then
      FreeAndNil(ini);
  end;
end;


end.

