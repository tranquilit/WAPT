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

  EXTENSION_PRIVATE_KEY               : String = 'pem';
  EXTENTION_CERTIFICATE               : String = 'crt';

implementation

end.

