unit uVisCreateKey;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Dialogs, ExtCtrls,
  StdCtrls, Buttons, EditBtn, DefaultTranslator;

type

  { TVisCreateKey }

  TVisCreateKey = class(TForm)
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    CBCodeSigning: TCheckBox;
    CBIsCA: TCheckBox;
    DirectoryCert: TDirectoryEdit;
    edCommonName: TEdit;
    edCertBaseName: TEdit;
    EdCACertificate: TFileNameEdit;
    EdCAKeyFilename: TFileNameEdit;
    EdKeyPassword: TEdit;
    EdKeypassword2: TEdit;
    edCountry: TEdit;
    edEmail: TEdit;
    edUnit: TEdit;
    edOrganization: TEdit;
    edLocality: TEdit;
    EdKeyFilename: TFileNameEdit;
    Label1: TLabel;
    Label10: TLabel;
    Label11: TLabel;
    Label12: TLabel;
    Label13: TLabel;
    Label14: TLabel;
    Label15: TLabel;
    Label16: TLabel;
    Label17: TLabel;
    Label18: TLabel;
    LabConfirmPwd: TLabel;
    Label19: TLabel;
    Label2: TLabel;
    Label9: TLabel;
    Panel1: TPanel;
    Panel2: TPanel;
    Shape1: TShape;
    StaticText1: TStaticText;
    procedure DirectoryCertAcceptDirectory(Sender: TObject; var Value: String);
    procedure DirectoryCertAcceptFileName(Sender: TObject; var Value: String);
    procedure EdCACertificateExit(Sender: TObject);
    procedure edCommonNameExit(Sender: TObject);
    procedure EdKeyFilenameAcceptFileName(Sender: TObject; var Value: String);
    procedure EdKeyFilenameExit(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
  private
    procedure SetDefaultCN;
    { private declarations }
  public
    { public declarations }
    procedure MakeCertName;
    Function GetCertFilename:String;
  end;

var
  VisCreateKey: TVisCreateKey;

implementation
{$R *.lfm}

uses
  inifiles,uWaptConsoleRes,uWaptRes,uSCaleDPI, dmwaptpython,lazFileUtils,waptcommon,VarPyth;

{ TVisCreateKey }

procedure TVisCreateKey.FormCloseQuery(Sender: TObject; var CanClose: boolean);
begin
  if (ModalResult=mrOk) then
  begin
    if not FileExists(EdKeyFilename.Text) and ((EdKeyPassword.Text='') or (EdKeyPassword.Text<>EdKeypassword2.Text)) then
    begin
      CanClose:=False;
      ShowMessage('Please confirm the password for the encryption of the new private key');
      EdKeypassword2.SetFocus;
    end
    else
    if FileExists(EdKeyFilename.Text) and (EdKeyPassword.Text='') then
    begin
      CanClose:=False;
      ShowMessage('Please enter the password for the decryption of the private key');
      EdKeypassword.SetFocus;
    end
    else
    if Trim(edCommonName.Text) = ''then
    begin
      showMessage(rsInputCommonName);
      CanClose:=False;
    end else
    if (EdKeyFileName.Text = '') then
    begin
      showMessage(rsInputKeyName);
      CanClose:=False;
    end else
      CanClose:= not FileExists(GetCertFilename) or (Dialogs.MessageDlg('Confirm overwrite of certificate','Certificate '+GetCertFilename+' already exists. Confirm the overwrite of it',mtConfirmation,mbYesNoCancel,0) = mrYes)
  end
  else
    CanClose:=True;
end;

procedure TVisCreateKey.SetDefaultCN;
var
  pemfn:String;
  crtfn:String;
begin
  if FileExists(EdKeyFilename.FileName) then
    pemfn := EdKeyFilename.FileName
  else
    pemfn := DirectoryCert.text+'\'+ExtractFileNameOnly(EdKeyFilename.Text)+'.pem';

  // by default check if already a certificate with same basename as private key in target directory...
  crtfn := DirectoryCert.Text+'\'+ExtractFileNameOnly(pemfn)+'.crt';

  if FileExists(crtfn) then
    edCommonName.text := dmwaptpython.DMPython.PythonEng.EvalStringAsStr(Format('common.SSLCertificate(r"""%s""").cn or ""',[crtfn]))
  // use file basename as CommonName
  else if edCommonName.text='' then
    edCommonName.Text:=ExtractFileNameOnly(crtfn);
end;


procedure TVisCreateKey.MakeCertName;
var
  certFile:String;
begin
  certFile := AppendPathDelim(DirectoryCert.Text)+ExtractFileNameOnly(EdKeyFileName.Text)+'.crt';
  if FileExists(certFile) then
    certFile := AppendPathDelim(DirectoryCert.Text)+ExtractFileNameOnly(EdKeyFileName.Text)+'-'+FormatDateTime('yyyymmdd-hhnnss',Now)+'.crt';
  edCertBaseName.Text:=ExtractFileNameOnly(certFile);
end;

function TVisCreateKey.GetCertFilename: String;
begin
  Result := AppendPathDelim(DirectoryCert.Text)+edCertBaseName.Text;
end;

procedure TVisCreateKey.EdKeyFilenameAcceptFileName(Sender: TObject;
  var Value: String);
begin
  if UTF8Decode(Value) <> Value then
  begin
    ShowMessage('Bad key filename, use only ASCII characters');
    Value :='';
  end
  else
  begin
    EdKeyFilename.FIlename := Value;
    SetDefaultCN;
  end;
  EdKeypassword2.Visible:= not FileExists(EdKeyFilename.Text);
  LabConfirmPwd.Visible := EdKeypassword2.Visible;

  if FileExists(EdKeyFilename.Text) then
    edCertBaseName.SetFocus
  else
    EdKeyPassword.SetFocus;
end;

procedure TVisCreateKey.DirectoryCertAcceptFileName(Sender: TObject;
  var Value: String);
begin
  Value := ExtractFileDir(Value);
end;

procedure TVisCreateKey.EdCACertificateExit(Sender: TObject);
begin
  CBIsCA.Checked := not ((EdCACertificate.Text<>'') or (EdCAKeyFilename.Text<>''));
end;

procedure TVisCreateKey.DirectoryCertAcceptDirectory(Sender: TObject;
  var Value: String);
begin
  EdKeyFilename.InitialDir:=Value;
  EdCACertificate.InitialDir:=Value;
  EdCAKeyFilename.InitialDir:=Value;

end;

procedure TVisCreateKey.edCommonNameExit(Sender: TObject);
begin
  MakeCertName;
end;

procedure TVisCreateKey.EdKeyFilenameExit(Sender: TObject);
begin
  SetDefaultCN;
  EdKeypassword2.Visible:= not FileExists(EdKeyFilename.Text);
  LabConfirmPwd.Visible := EdKeypassword2.Visible;

end;

procedure TVisCreateKey.FormCreate(Sender: TObject);
var
  pkey:Utf8String;
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
  pkey := GetWaptPersonalCertificatePath;
  if pkey<>'' then
    DirectoryCert.Text:=ExtractFileDir(pkey)
  else
    DirectoryCert.Text:='c:\private';
  SetDefaultCN;

  with TINIFile.Create(AppIniFilename) do
  try
    EdCAKeyFilename.Text := ReadString('global', 'default_ca_key_path', '');
    EdCACertificate.Text := ReadString('global', 'default_ca_cert_path', '');
  finally
    Free;
  end;

end;

end.

