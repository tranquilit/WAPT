unit uwapt_ini;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;


const

  INI_ALLOW_UNAUTHENTICATED_REGISTRATION  : String = 'allow_unauthenticated_registration';
  INI_CHECK_CERTIFICATES_VALIDITY         : String = 'check_certificates_validity';
  INI_DB_NAME                             : String = 'db_name';
  INI_DB_USER                             : String = 'db_user';
  INI_DEFAULT_PACKAGE_PREFIX              : String = 'default_package_prefix';
  INI_GLOBAL                              : String = 'global';
  INI_OPTIONS                             : String = 'options';
  INI_PERSONAL_CERTIFICATE_PATH           : String = 'personal_certificate_path';
  INI_REPO_URL                            : String = 'repo_url';
  INI_SECRET_KEY                          : String = 'secret_key';
  INI_SERVER_UUID                         : String = 'server_uuid';
  INI_VERIFIY_CERT                        : String = 'verify_cert';
  INI_WAPT_SERVER                         : String = 'wapt_server';
  INI_WAPT_USER                           : String = 'wapt_user';
  INI_WAPT_PASSWORD                       : String = 'wapt_password';
  INI_WAPTWUA_FOLDER                      : String = 'waptwua_folder';
  INI_SEND_USAGE_REPORT                   : String = 'send_usage_report';
  INI_USE_HOSTPACKAGE                     : String = 'use_hostpackages';
  INI_USE_KERBEROS                        : String = 'use_kerberos';



  INI_WAPTTEMPLATES                       : String = 'wapt-templates';

  function wapt_ini_waptconsole(var s: String): integer;
  function wapt_ini_waptserver( const base_path :String; var s : String ) : integer;

implementation

uses
  uwizardutil;

function wapt_ini_waptconsole(var s: String): integer;
begin
  s := ExcludeTrailingBackslash( GetAppConfigDir(False) );
  s := ExtractFileDir(s);
  s := IncludeTrailingBackslash(s) + 'waptconsole';
  s := IncludeTrailingBackslash(s) + 'waptconsole.ini';
  if FileExists(s) then
    exit(0);
  exit(-1);
end;

function wapt_ini_waptserver(const base_path: String; var s: String): integer;
begin
  s := fs_path_concat( base_path, 'conf/waptserver.ini' );
  if FileExists(s) then
      exit(0);
  exit(-1);
end;

end.

