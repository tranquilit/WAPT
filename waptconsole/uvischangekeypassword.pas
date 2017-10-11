unit uVisChangeKeyPassword;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons, EditBtn, DefaultTranslator;

type

  { TVisChangeKeyPassword }

  TVisChangeKeyPassword = class(TForm)
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    EdKeyFilename: TFileNameEdit;
    EdKeyPassword: TEdit;
    EdKeypassword2: TEdit;
    edOldKeyPassword: TEdit;
    LabConfirmPwd: TLabel;
    Label17: TLabel;
    Label9: TLabel;
    laPassword: TLabel;
    Panel1: TPanel;
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisChangeKeyPassword: TVisChangeKeyPassword;

implementation

uses uSCaleDPI,dmwaptpython,VarPyth,waptcommon,variants;

{$R *.lfm}

{ TVisChangeKeyPassword }

procedure TVisChangeKeyPassword.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
  EdKeyFilename.text := VarPythonAsString(MainModule.waptdevutils.get_private_key_encrypted(certificate_path:=GetWaptPersonalCertificatePath(),password:=DMPython.privateKeyPassword));
  if EdKeyFilename.Text <>'' then
    edOldKeyPassword.Text:= DMPython.privateKeyPassword;
end;

procedure TVisChangeKeyPassword.FormShow(Sender: TObject);
begin
  if edOldKeyPassword.Text<>'' then
    EdKeyPassword.SetFocus;
end;

procedure TVisChangeKeyPassword.FormCloseQuery(Sender: TObject;
  var CanClose: boolean);
var
   key,oldpassword,newpassword,filename,filenameold,filenamenew:Variant;
begin
  if ModalResult = mrOk then
  begin
    if EdKeyPassword.Text <> EdKeypassword2.Text then
      raise Exception.Create('New and confrmed password don''t match, please reenter them');
    oldpassword := edOldKeyPassword.Text;
    if edOldKeyPassword.Text = '' then
      key := MainModule.waptcrypto.SSLPrivateKey(filename := EdKeyFilename.text)
    else
      key := MainModule.waptcrypto.SSLPrivateKey(filename := EdKeyFilename.text,  password := oldpassword);

    if VarIsNull(key) then
      raise Exception.Create('Unable to decrypt key with provided old password, please retry');
    newpassword := EdKeyPassword.Text;
    filename := EdKeyFilename.text;
    filenameold := filename+'.old';
    filenamenew := filename+'.new';
    if EdKeyPassword.Text = '' then
      key.save_as_pem(filename := filenamenew)
    else
      key.save_as_pem(filename := filenamenew, password := newpassword);
    if RenameFile(filename,filenameold) and RenameFile(filenamenew,filename) then
      DeleteFile(filenameold)
    else
      raise Exception.create('Unable to save new encrypted key');
    CanClose:=FileExists(filename);
    if CanClose then
    begin
      if EdKeyFilename.text = GetWaptPersonalCertificatePath then
        DMPython.privateKeyPassword := EdKeyPassword.Text;
      ShowMessage('Password changed successfully');
    end;
  end;
end;

end.

