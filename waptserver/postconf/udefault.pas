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


  SETUP_AGENT_SIZE : integer = 1024 * 1024 * 21;

  ISCC_EXE : String = 'ISCC.exe';

implementation

end.

