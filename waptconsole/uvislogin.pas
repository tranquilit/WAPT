unit uvislogin;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons, ButtonPanel, LCLType;

type

  { TVisLogin }

  TVisLogin = class(TForm)
    ButtonPanel1: TButtonPanel;
    edPassword: TEdit;
    edUser: TEdit;
    edWaptServerName: TEdit;
    Label1: TLabel;
    laPassword: TLabel;
    laPassword1: TLabel;
    procedure edPasswordKeyDown(Sender: TObject; var Key: Word;
      Shift: TShiftState);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisLogin: TVisLogin;

implementation

{$R *.lfm}

{ TVisLogin }

procedure TVisLogin.edPasswordKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
    if Key = VK_RETURN then
  begin
    edPassword.SelectAll;
  end;
end;

end.

