unit udefault;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

const
  DEFAULT_PRIVATE_KEY_DIRECTORY       : String = 'c:\private';
  DEFAULT_PACKAGE_PREFIX              : String = 'test';
  DEFAULT_PASSWORD_CHAR               : Char   = '*';
  DEFAULT_MINIMUN_PASSWORD_LENGTH     : integer = 6;

  DEFAULT_CERT_COUNTRY                : String = 'FR';
  DEFAULT_CERT_CRTBASENAME            : String = '';
  DEFAULT_CERT_LOCALITY               : String = '';
  DEFAULT_CERT_ORGANIZATION           : String = '';
  DEFAULT_CERT_ORGUNIT                : String = '';
  DEFAULT_CERT_COMMON_NAME            : String = '';
  DEFAULT_CERT_EMAIL                  : String = '';
  DEFAULT_CERT_CODESIGNING            : Boolean = True;
  DEFAULT_CERT_ISCACERT               : Boolean = False;
  DEFAULT_CERT_CACERTIFICATEFILENAME  : String = '';
  DEFAULT_CERT_CAKEYFILENAME          : String = '';


  DEFAULT_SETUP_AGENT_EDITION         : String = 'waptagent';
  DEFAULT_SETUP_AGENT_FILENAME        : String = 'waptagent.exe';


  EXTENSION_PRIVATE_KEY               : String = 'pem';
  EXTENTION_CERTIFICATE               : String = 'crt';

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
  INI_WAPT_STORE_URL                      : String = 'https://store.wapt.fr/wapt';


  SETUP_AGENT_SIZE : integer = 1024 * 1024 * 21;

  ISCC_EXE : String = 'ISCC.exe';

  INI_FILE_WAPTCONSOLE : String = '';
  INI_FILE_WAPTGET     : String = '';

  MIME_APPLICATION_JSON : String = 'application/json';

  HTTP_TIMEOUT          : integer = 4 * 1000;
  HTTP_RESPONSE_CODE_OK : integer = 200;

  HTML_NO_DOC : String = '<HTML><HEAD><HEAD><BODY><BODY></HTML>';

  FILE_FILTER_PRIVATE_KEY : String = 'Private key file (*.pem)|*.PEM';
  FILE_FILTER_CERTIFICATE : String = 'Certificate file (*.crt)|*.CRT';


  WAPT_SERVICE_WAPTPOSTGRESQL : String = 'WAPTPostgresql';
  WAPT_SERVICE_WAPTTASKS      : String = 'WAPTtasks';
  WAPT_SERVICE_WAPTSERVER     : String = 'WAPTServer';
  WAPT_SERVICE_WAPTNGINX      : String = 'WAPTNginx';
  WAPT_SERVICE_WAPTSERVICE    : String = 'WAPTService';

  RUN_TIMEOUT_MS = 10 *1000;

implementation

uses
  uutil,
  waptcommon;

procedure init();
var
  s : String;
  r : integer;
begin

  // waptconsole.ini
  INI_FILE_WAPTCONSOLE := AppIniFilename();
  r := extract_filename_without_extension( s, INI_FILE_WAPTCONSOLE );
  if r = 0 then
    INI_FILE_WAPTCONSOLE := StringReplace( INI_FILE_WAPTCONSOLE, s, 'waptconsole', [rfReplaceAll] )
  else
    INI_FILE_WAPTCONSOLE := '';

  // wapt-get.ini
  INI_FILE_WAPTGET := IncludeTrailingPathDelimiter(WaptBaseDir) + 'wapt-get.ini';

end;

initialization
init();
end.

