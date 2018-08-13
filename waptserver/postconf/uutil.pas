unit uutil;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
TCreate_signed_cert_params = record
  keyfilename           : String;
  crtbasename           : String;
  destdir               : String;
  country               : String;
  locality              : String;
  organization          : String;
  orgunit               : String;
  commonname            : String;
  keypassword           : String;
  email                 : String;
  codesigning           : Boolean;
  IsCACert              : Boolean;
  CACertificateFilename : String;
  CAKeyFilename         : String;

  _certificate          : String;
  _error_message        : String;
end;
PCreate_signed_cert_params = ^TCreate_signed_cert_params;

function str_is_alphanum( const str : String ) : boolean;
function str_is_empty_when_trimmed( const str : String ) : boolean;


procedure create_signed_cert_params_init( params : PCreate_signed_cert_params );
function create_signed_cert_params( params: PCreate_signed_cert_params ): integer;

function crypto_check_key_password(var success: boolean; const key_filename: String; const password: String): integer;

implementation

uses
  PythonEngine,
  VarPyth,
  character,
  udefault,
  dmwaptpython;

function str_is_alphanum( const str : String ) : boolean;
var
  i : integer;
begin
  for i := 1 to Length(str) do
  begin
    if not IsLetterOrDigit( str[i] ) then
      exit(false);
  end;
  exit(true);
end;

function str_is_empty_when_trimmed( const str : String ) : boolean;
var
  s : String;
  r : integer;
begin
  s := trim(str);
  r := Length(s);
  exit( 0 = r );
end;

procedure create_signed_cert_params_init( params : PCreate_signed_cert_params );
begin
  FillChar( params^, sizeof(TCreate_signed_cert_params), 0 );
  params^.keyfilename           := '';
  params^.crtbasename           := DEFAULT_CERT_CRTBASENAME;
  params^.destdir               := '';
  params^.country               := DEFAULT_CERT_COUNTRY;
  params^.locality              := DEFAULT_CERT_LOCALITY;
  params^.organization          := DEFAULT_CERT_ORGANIZATION;
  params^.orgunit               := DEFAULT_CERT_ORGUNIT;
  params^.commonname            := DEFAULT_CERT_COMMON_NAME;
  params^.keypassword           := '';
  params^.email                 := DEFAULT_CERT_EMAIL;
  params^.codesigning           := DEFAULT_CERT_CODESIGNING;
  params^.IsCACert              := DEFAULT_CERT_ISCACERT;
  params^.CACertificateFilename := DEFAULT_CERT_CACERTIFICATEFILENAME;
  params^.CAKeyFilename         := DEFAULT_CERT_CAKEYFILENAME;

  params^._certificate          := '';
  params^._error_message        := '';
end;

function create_signed_cert_params( params: PCreate_signed_cert_params ): integer;
begin
  try
      params^._certificate := CreateSignedCert(
      UTF8Decode(params^.keyfilename),
      UTF8Decode(params^.crtbasename),
      UTF8Decode(params^.destdir),
      UTF8Decode(params^.country),
      UTF8Decode(params^.locality),
      UTF8Decode(params^.organization),
      UTF8Decode(params^.orgunit),
      UTF8Decode(params^.commonname),
      UTF8Decode(params^.email),
      UTF8Decode(params^.keypassword),
      params^.codesigning,
      params^.IsCACert,
      UTF8Decode(params^.CACertificateFilename),
      UTF8Decode(params^.CAKeyFilename)
    );
    result := 0;
  except on Ex : Exception do
    begin
      params^._error_message := ex.Message;
      result := -1;
    end;
  end;
end;


function crypto_check_key_password(var success: boolean; const key_filename: String; const password: String): integer;
const
  _FAILED = -1;
  _TRUE   =  1;
  _FALSE  =  0;
var
  r : Variant;
  pe : TPythonEngine;
begin
  pe := GetPythonEngine();
  if not Assigned(pe) then
    exit(-1);

  r := DMPython.waptcrypto.check_key_password( key_filename := key_filename, password := password );

  if VarIsNone(r) then
    exit(-1);

  if not VarIsBool(r) then
    exit(-1);

  result := pe.PyObject_IsTrue( ExtractPythonObjectFrom(r));
  if _FAILED = result  then
    exit(-1);

  success := _TRUE = result;
  exit(0);
end;

end.

