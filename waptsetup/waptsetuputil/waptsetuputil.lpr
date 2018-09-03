library waptsetuputil;

{$mode objfpc}{$H+}

{$ifndef WINDOWS}
{$error}
{$endif}

uses
  constants,
  setuputil,
  Translations,
  LCLProc,
  Interfaces,
  Forms,
  LCLTranslator,
  sysutils,
  Dialogs,
  indylaz,
  lazcontrols,
  Classes;








function validate_wapt_server_install_port( port : integer ) : boolean; stdcall;
label
  LBL_FAILED;
var
  r   : integer;
  url : String;
  b   : boolean;
  i : integer;
  j : integer;
  msg : String;

  sl : TStringList;

begin
  sl := nil;

  b := port <> 0;
  b := b and (port = (port and $FFFF));
  if not b then
  begin
    msg := Format( '%d is not a valid port number' + #13#10 + 'Please select a port number between 1-65535', [port] );
    MessageDlg( DIALOG_TITLE, msg, mtError, [mbOK], 0 );
    goto LBL_FAILED;
  end;

  sl := TStringList.Create;
  r := list_interfaces( sl );
  if r <> 0 then
  begin
    msg := Format( 'A problem has occured while getting list of network interfaces', [] );
    MessageDlg( DIALOG_TITLE, msg, mtError, [mbOK], 0 );
    goto LBL_FAILED;
  end;



  for i:= 0 to sl.Count -1 do
  begin
    for j := 0 to Length(PROTOCOLS) - 1 do
    begin
      url := protocols[j] + '://' + sl[i] + ':' + IntToStr(port);
//      ShowMessage( 'Test url : ' + url );
      r := wapt_ping( b, url );
      // Closed or filtered
      if r <> 0 then
        continue;
      // wapt server
      if b then
        continue;
      goto LBL_FAILED;
    end;
  end;

  sl.Free;
  exit( true );

LBL_FAILED:

  if Assigned(sl) then
    sl.Free;

  exit( false );
end;



exports
  validate_wapt_server_install_port;





end.

