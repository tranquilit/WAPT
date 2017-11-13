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
    EdCACertificate: TFileNameEdit;
    EdCAKeyFilename: TFileNameEdit;
    edCertBaseName: TEdit;
    edCommonName: TEdit;
    edCountry: TEdit;
    edEmail: TEdit;
    EdKeyFilename: TFileNameEdit;
    EdKeyPassword: TEdit;
    EdKeypassword2: TEdit;
    edLocality: TEdit;
    edOrganization: TEdit;
    edUnit: TEdit;
    Filler: TPanel;
    Filler2: TPanel;
    Filler3: TPanel;
    LabCACert: TLabel;
    LabCAKey: TLabel;
    LabCertName: TLabel;
    LabCN: TLabel;
    LabConfirmPwd: TLabel;
    LabCountry: TLabel;
    Label1: TLabel;
    LabCountr: TLabel;
    Label11: TLabel;
    LabCity: TLabel;
    LabKeyFN: TLabel;
    LabKeyPassword: TLabel;
    LabLocality: TLabel;
    LabMail: TLabel;
    LabOptional: TStaticText;
    LabOrg: TLabel;
    LabService: TLabel;
    Label17: TLabel;
    Label19: TLabel;
    Label2: TLabel;
    Label9: TLabel;
    LabTargetDir: TLabel;
    LabUnit: TLabel;
    PanCA2: TPanel;
    PanCASize1: TPanel;
    PanCASize2: TPanel;
    PanCATop: TPanel;
    PanCertificate: TPanel;
    PanDirectoryCert: TPanel;
    Panel1: TPanel;
    Panel2: TPanel;
    PanCA: TPanel;
    Panel4: TPanel;
    Panel5: TPanel;
    PanKey: TPanel;
    PanSize1: TPanel;
    PanSize2: TPanel;
    Shape1: TShape;
    Shape2: TShape;
    procedure DirectoryCertAcceptDirectory(Sender: TObject; var Value: String);
    procedure DirectoryCertAcceptFileName(Sender: TObject; var Value: String);
    procedure DirectoryCertExit(Sender: TObject);
    procedure EdCACertificateExit(Sender: TObject);
    procedure edCommonNameExit(Sender: TObject);
    procedure EdKeyFilenameAcceptFileName(Sender: TObject; var Value: String);
    procedure EdKeyFilenameExit(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
  private
    FCertificateFilename: String;
    FPrivateKeyFilename: String;
    function CreateKeyAndCertificate: String;
    function GetCertificateFilename: String;
    function GetPrivateKeyFilename: String;
    procedure SetDefaultCN;
    { private declarations }
  public
    { public declarations }
    procedure MakeDefaultCertName;
    Function GetCertFilename:String;
  published
    property PrivateKeyFilename:String read GetPrivateKeyFilename;
    property CertificateFilename:String read GetCertificateFilename;
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
    if not FileExistsUTF8(EdKeyFilename.Text) and ((EdKeyPassword.Text='') or (EdKeyPassword.Text<>EdKeypassword2.Text)) then
    begin
      CanClose:=False;
      ShowMessage('Please confirm the password for the encryption of the new private key');
      EdKeypassword2.SetFocus;
    end
    else
    if FileExistsUTF8(EdKeyFilename.Text) and (EdKeyPassword.Text='') then
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
    begin
      if FileExistsUTF8(GetCertFilename) then
        MakeDefaultCertName;
      FCertificateFilename := CreateKeyAndCertificate;
      CanClose:=FileExistsUTF8(FCertificateFilename) and FileExistsUTF8(FPrivateKeyFilename);
    end;
  end
  else
    CanClose:=True;
end;

function TVisCreateKey.CreateKeyAndCertificate:String;
var
  pemfn, certFile: String;
  CreatePrivateKey: boolean;
begin
  Result := '';
  try
    CreatePrivateKey := not FileExistsUTF8(EdKeyFileName.FileName);
    if not CreatePrivateKey then
      pemfn:=EdKeyFilename.FileName
    else
      pemfn:=AppendPathDelim(DirectoryCert.Text)+ExtractFileNameOnly(EdKeyFileName.Text)+'.pem';

    certFile := CreateSignedCert(
      utf8Decode(pemfn),
      utf8Decode(edCertBaseName.Text),
      WaptBaseDir(),
      utf8Decode(DirectoryCert.Text),
      utf8Decode(edCountry.Text),
      utf8Decode(edLocality.Text),
      utf8Decode(edOrganization.Text),
      utf8Decode(edUnit.Text),
      utf8Decode(edCommonName.Text),
      edEmail.Text,
      EdKeyPassword.Text,
      CBCodeSigning.Checked,
      CBIsCA.Checked,
      EdCACertificate.Text,
      EdCAKeyFilename.Text);

    FPrivateKeyFilename:=pemfn;

    if FileExistsUTF8(certFile) then
    begin
      if CreatePrivateKey then
        ShowMessageFmt(rsKeyPairGenSuccess,
          [UTF8Encode(pemfn),UTF8Encode(certFile)])
      else
        ShowMessageFmt(rsPublicKeyGenSuccess,
          [UTF8Encode(certFile)]);
      Result := certFile;
    end
    else
      Result := '';
  except
    on e: Exception do
    begin
      ShowMessage(format(rsPublicKeyGenError, [e.Message]));
      FPrivateKeyFilename:='';
      Result:='';
    end;
  end
end;

function TVisCreateKey.GetCertificateFilename: String;
begin
  Result := FCertificateFilename;
end;

function TVisCreateKey.GetPrivateKeyFilename: String;
begin
  result := FPrivateKeyFilename;
end;


procedure TVisCreateKey.SetDefaultCN;
var
  crtfn,fnraw:String;
begin
  MakeDefaultCertName;
  // by default check if already a certificate with same basename as private key in target directory...
  if EdKeyFilename.Text <> '' then
  begin
    crtfn := DirectoryCert.Text+'\'+ExtractFileNameOnly(EdKeyFilename.Text)+'.crt';

    if FileExistsUTF8(crtfn) then
    begin
      fnraw := UTF8Decode(crtfn);
      edCommonName.text := utf8encode(VarPythonAsString(Mainmodule.waptcrypto.SSLCertificate(crt_filename := fnraw).cn))
    end
    // use file basename as CommonName
    else if edCommonName.text='' then
      edCommonName.Text:=ExtractFileNameOnly(crtfn);
  end;
end;

procedure TVisCreateKey.MakeDefaultCertName;
var
  certFile:String;
begin
  if EdKeyFileName.Text<> '' then
  begin
    certFile := AppendPathDelim(DirectoryCert.Text)+ExtractFileNameOnly(EdKeyFileName.Text)+'.crt';
    if FileExistsUTF8(certFile) then
      certFile := AppendPathDelim(DirectoryCert.Text)+ExtractFileNameOnly(EdKeyFileName.Text)+'-'+FormatDateTime('yyyymmdd-hhnnss',Now)+'.crt';
    edCertBaseName.Text := ExtractFileNameOnly(certFile);
  end;
end;

function TVisCreateKey.GetCertFilename: String;
begin
  Result := AppendPathDelim(DirectoryCert.Text)+edCertBaseName.Text;
  if ExtractFileExt(Result)<>'' then
    Result := Result + '.crt';
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
  EdKeypassword2.Visible:= not FileExistsUTF8(EdKeyFilename.Text);
  LabConfirmPwd.Visible := EdKeypassword2.Visible;

  if FileExistsUTF8(EdKeyFilename.Text) then
    edCertBaseName.SetFocus
  else
    EdKeyPassword.SetFocus;
end;

procedure TVisCreateKey.DirectoryCertAcceptFileName(Sender: TObject;
  var Value: String);
begin
  Value := ExtractFileDir(Value);
end;

procedure TVisCreateKey.DirectoryCertExit(Sender: TObject);
begin
  EdKeyFilename.InitialDir:=DirectoryCert.Directory;
  EdCACertificate.InitialDir:=DirectoryCert.Directory;
   EdCAKeyFilename.InitialDir:=DirectoryCert.Directory;
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
  MakeDefaultCertName;
end;

procedure TVisCreateKey.EdKeyFilenameExit(Sender: TObject);
begin
  If EdKeyFilename.Text <> '' then
  begin
    if not FileExistsUTF8(EdKeyFilename.FileName) then
      EdKeyFilename.FileName := DirectoryCert.text+'\'+ExtractFileNameOnly(EdKeyFilename.Text);
    if ExtractFileExt(EdKeyFilename.FileName) <> '.pem' then
      EdKeyFilename.FileName := EdKeyFilename.FileName + '.pem';
    SetDefaultCN;
    MakeDefaultCertName;
  end;

  EdKeypassword2.Visible:= not FileExistsUTF8(EdKeyFilename.Text);
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

  if PanCA.Visible then
    with TINIFile.Create(AppIniFilename) do
    try
      EdCAKeyFilename.Text := ReadString('global', 'default_ca_key_path', '');
      EdCACertificate.Text := ReadString('global', 'default_ca_cert_path', '');
    finally
      Free;
    end;

end;

end.

