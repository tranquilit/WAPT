unit uvislogin;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons, ButtonPanel, LCLType,uwaptconsole,waptcommon ;

type

  { TVisLogin }

  TVisLogin = class(TForm)
    BitBtn1: TBitBtn;
    ButtonPanel1: TButtonPanel;
    edPassword: TEdit;
    edUser: TEdit;
    edWaptServerName: TEdit;
    Label1: TLabel;
    laPassword: TLabel;
    laPassword1: TLabel;
    procedure BitBtn1Click(Sender: TObject);
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

procedure TVisLogin.BitBtn1Click(Sender: TObject);
begin
    VisWaptGUI.ActWAPTLocalConfig.Execute;
    edWaptServerName.Text:=waptcommon.GetWaptServerURL;
end;

end.

