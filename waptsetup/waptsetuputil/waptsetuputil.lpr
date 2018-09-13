library waptsetuputil;

{$mode objfpc}{$H+}

{$ifndef WINDOWS}
{$error}
{$endif}

{$R *.res}

uses
  constants,
  setupvalidation,
  LCLProc,
  Interfaces,
  Forms,
  LCLTranslator,
  sysutils,
  Dialogs,
  indylaz,
  lazcontrols,
  Classes, translations;


procedure waptsetuputil_init( language : integer ); stdcall;
var
  b : Boolean;
begin
  b := language = (language AND $3 );
  if not b then
    language:= LANGUAGE_EN;
  LANGUAGE_ID := language;

  SetUnitResourceStrings('constants', @TranslateConsts, Nil);
end;


function waptsetuputil_validate_wapt_server_install_ports() : boolean; stdcall;
begin
  result :=            validate_wapt_server_install_port(   80, true );
  result := result and validate_wapt_server_install_port(  443, false );
  result := result and validate_wapt_server_install_port( 8080, true );
end;





exports
  waptsetuputil_init,
  waptsetuputil_validate_wapt_server_install_ports;





end.

