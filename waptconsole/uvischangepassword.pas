unit uvischangepassword;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ButtonPanel,
  ExtCtrls, DefaultTranslator;

type

  { TVisChangePassword }

  TVisChangePassword = class(TForm)
    ButtonPanel1: TButtonPanel;
    EdNewPassword2: TLabeledEdit;
    EdNewPassword1: TLabeledEdit;
    EdOldPassword: TLabeledEdit;
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisChangePassword: TVisChangePassword;

implementation
uses uWaptConsoleRes,waptcommon,UScaleDPI;

{$R *.lfm}

{ TVisChangePassword }

procedure TVisChangePassword.FormCloseQuery(Sender: TObject;
  var CanClose: boolean);
begin
  CanClose:=True;
  if (ModalResult=mrOk) then
  begin
    if (EdNewPassword1.Text<>EdNewPassword2.text) then
    begin
       ShowMessage(rsDiffPwError);
       CanClose:=False;
    end;
    if (EdNewPassword1.Text='') then
    begin
      ShowMessage(rsEmptyNewPwError);
      CanClose:=False;
    end;
    if (EdOldPassword.Text='' )then
    begin
      ShowMessage(rsEmptyOldPwError);
      CanClose:=False;
    end;
    if waptServerPassword <> EdOldPassword.Text then
    begin
      ShowMessage(rsIncorrectOldPwError);
      CanClose:=False;
    end;
  end;
end;

procedure TVisChangePassword.FormCreate(Sender: TObject);
begin
    ScaleDPI(Self,96); // 96 is the DPI you designed

end;

end.

