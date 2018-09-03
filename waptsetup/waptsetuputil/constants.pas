unit constants;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

const

  DIALOG_TITLE          : String = 'Validation';
  PROTOCOLS             : array[0..1] of String = ( 'http', 'https' );
  MIME_APPLICATION_JSON : String = 'application/json';
  HTTP_TIMEOUT          : integer = 1 * 500;
  HTTP_RESPONSE_CODE_OK : integer = 200;
  HTML_NO_DOC           : String = '<HTML><HEAD><HEAD><BODY><BODY></HTML>';

implementation

end.

