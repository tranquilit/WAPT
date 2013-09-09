unit uvischangepassword;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ButtonPanel,
  ExtCtrls;

type

  { TVisChangePassword }

  TVisChangePassword = class(TForm)
    ButtonPanel1: TButtonPanel;
    EdNewPassword2: TLabeledEdit;
    EdNewPassword1: TLabeledEdit;
    EdOldPassword: TLabeledEdit;
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisChangePassword: TVisChangePassword;

implementation

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
       ShowMessage('Les mots de passe sont différents');
       CanClose:=False;
    end;
    if (EdNewPassword1.Text='') then
    begin
      ShowMessage('Le nouveau mot de passe ne doit pas être vide');
      CanClose:=False;
    end;
    if (EdOldPassword.Text='' )then
    begin
      ShowMessage('L''ancien mot de passe ne doit pas être vide');
      CanClose:=False;
    end;
    if waptServerPassword<>EdOldPassword.Text then
    begin
      ShowMessage('L''ancien mot de passe ne correspond pas');
      CanClose:=False;
    end;
  end;
end;

end.

