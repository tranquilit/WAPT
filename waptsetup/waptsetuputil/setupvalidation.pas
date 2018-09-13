unit setupvalidation;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

function validate_wapt_server_install_port( port : integer; is_http : boolean ) : boolean;

implementation

uses
  setuputil,
  constants,
  Dialogs,
  Forms,
  Controls;


function validate_wapt_server_install_port( port : integer; is_http : boolean ) : boolean;
label
  LBL_SUCCESS,
  LBL_RETRY,
  LBL_FAILED;
var
  r   : integer;
  url : String;
  b   : boolean;
  i : integer;
  msg : String;
  sl : TStringList;

begin
  sl := nil;

  b := port <> 0;
  b := b and (port = (port and $FFFF));
  if not b then
  begin
    msg := Format( rs_error_not_a_valid_port, [port] );
    MessageDlg( DIALOG_TITLE, msg, mtError, [mbOK], 0 );
    goto LBL_FAILED;
  end;

LBL_RETRY:
  sl := TStringList.Create;
  r := list_interfaces( sl );
  if r <> 0 then
  begin
    msg := rs_error_list_iface;
    MessageDlg( DIALOG_TITLE, msg, mtError, [mbOK], 0 );
    goto LBL_FAILED;
  end;


  for i:= 0 to sl.Count -1 do
  begin

    if is_http then
      url := 'http://'
    else
      url := 'https://';

      url := url + sl[i] + ':' + IntToStr(port);
      r := wapt_ping( b, url );
      if r <> 0 then
        continue;
      if b then
        continue;

      msg := Format( rs_port_is_used, [sl[i], port] );
      r := MessageDlg( DIALOG_TITLE, msg, mtError, mbAbortRetryIgnore, 0 );
      if mrRetry = r then
      begin
        sl.Free;
        goto LBL_RETRY;
      end;

      if mrIgnore = r then
        goto LBL_SUCCESS;

      goto LBL_FAILED;
  end;

LBL_SUCCESS:
  sl.Free;
  exit( true );

LBL_FAILED:
  if Assigned(sl) then
    sl.Free;
  exit( false );
end;

end.

