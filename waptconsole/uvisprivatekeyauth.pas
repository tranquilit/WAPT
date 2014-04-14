unit uvisprivatekeyauth;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons;

type

  { TvisPrivateKeyAuth }

  TvisPrivateKeyAuth = class(TForm)
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    edPasswordKey: TEdit;
    Label1: TLabel;
    laKeyPath: TLabel;
    laPassword: TLabel;
    Panel1: TPanel;
    procedure edPasswordKeyKeyPress(Sender: TObject; var Key: char);
  private
    { private declarations }
  public
    { public declarations }
  end;

function privateKeyPassword: Ansistring;

var
  visPrivateKeyAuth: TvisPrivateKeyAuth;

implementation

uses waptcommon, dmwaptpython;

{$R *.lfm}
const
  CachedPrivateKeyPassword: Ansistring ='';

function privateKeyPassword: Ansistring;
var
  KeyIsProtected:Boolean;
begin
  if not FileExists(GetWaptPrivateKeyPath) then
    CachedPrivateKeyPassword := ''
  else
  begin
    KeyIsProtected := StrToBool(DMPython.RunJSON(
      format('common.private_key_has_password(r"%s")',
      [GetWaptPrivateKeyPath])).AsString);
    if KeyIsProtected then
      while StrToBool(DMPython.RunJSON(format('common.check_key_password(r"%s","%s")',[GetWaptPrivateKeyPath, CachedPrivateKeyPassword])).AsString) do
      begin
        with TvisPrivateKeyAuth.Create(Application.MainForm) do
        try
          laKeyPath.Caption := GetWaptPrivateKeyPath;
          if ShowModal = mrOk then
            cachedPrivateKeyPassword := edPasswordKey.Text
          else
          begin
            CachedPrivateKeyPassword := '';
            Result := CachedPrivateKeyPassword;
            Exit;
          end;
        finally
          Free;
        end;
      end
    else
      CachedPrivateKeyPassword :='';
  end;
  Result := CachedPrivateKeyPassword;
end;


{ TvisPrivateKeyAuth }

procedure TvisPrivateKeyAuth.edPasswordKeyKeyPress(Sender: TObject;
  var Key: char);
begin
  if Key=#13 then
  begin
     BitBtn1.Click;
  end;
end;

end.

