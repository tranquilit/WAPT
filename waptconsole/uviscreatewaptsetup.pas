unit uVisCreateWaptSetup;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  EditBtn, ExtCtrls, Buttons, ActnList, DefaultTranslator, Menus;

type

  { TVisCreateWaptSetup }

  TVisCreateWaptSetup = class(TForm)
    ActGetServerCertificate: TAction;
    ActionList1: TActionList;
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    CBCheckCertificatesValidity: TCheckBox;
    CBDualSign: TCheckBox;
    CBVerifyCert: TCheckBox;
    CBUseKerberos: TCheckBox;
    EdServerCertificate: TFileNameEdit;
    edWaptServerUrl: TEdit;
    fnWaptDirectory: TDirectoryEdit;
    edRepoUrl: TEdit;
    edOrgName: TEdit;
    fnPublicCert: TFileNameEdit;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    Label6: TLabel;
    MenuItem1: TMenuItem;
    Panel1: TPanel;
    PopupMenu1: TPopupMenu;
    procedure ActGetServerCertificateExecute(Sender: TObject);
    procedure CBVerifyCertClick(Sender: TObject);
    procedure fnPublicCertEditingDone(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisCreateWaptSetup: TVisCreateWaptSetup;

implementation

{$R *.lfm}

uses
  Variants,dmwaptpython,IdUri,IdSSLOpenSSLHeaders,uWaptConsoleRes,uWaptRes,UScaleDPI, tiscommon,
  tisstrings,waptcommon,VarPyth,superobject;

{ TVisCreateWaptSetup }
procedure TVisCreateWaptSetup.FormCloseQuery(Sender: TObject; var CanClose: boolean);
var
  pingResult: ISuperobject;
begin
  CanClose:= True;
  if (ModalResult=mrOk) then
  begin
    if fnPublicCert.FileName='' then
    begin
      showMessage(rsInputPubKeyPath);
      CanClose:=False;
    end;
    if not DirectoryExists(fnWaptDirectory.Caption) then
    begin
      ShowMessageFmt(rsInvalidWaptSetupDir, [fnWaptDirectory.Directory]);
      CanClose:=False;
    end;
    if (CBVerifyCert.Checked) and (pos(lowercase(WaptBaseDir),lowercase(EdServerCertificate.Text))<>1) then
    begin
      ShowMessageFmt(rsInvalidServerCertificateDir, [EdServerCertificate.Text]);
      CanClose:=False;
    end;
    // check ssl cert is OK
    if (CBVerifyCert.Checked) then
    try
      PingResult := SO(IdhttpGetString(edWaptServerUrl.Text+'/ping','',4000,60000,60000,'','','GET','',EdServerCertificate.Text));
    except
      on E:EIdOpenSSLAPICryptoError do
      begin
        ShowMessageFmt(rsInvalidServerCertificate, [EdServerCertificate.Text]);
        CanClose:=False;
      end;
    end;
  end;
end;

procedure TVisCreateWaptSetup.fnPublicCertEditingDone(Sender: TObject);
begin
  if FileExists(fnPublicCert.FileName) then
    edOrgName.text := VarPythonAsString(dmpython.waptcrypto.SSLCertificate(crt_filename := fnPublicCert.FileName).cn);
    //edOrgName.text := dmwaptpython.DMPython.PythonEng.EvalStringAsStr(Format('common.SSLCertificate(r"""%s""").cn',[fnPublicCert.FileName]));

end;

procedure TVisCreateWaptSetup.CBVerifyCertClick(Sender: TObject);
begin
  If not CBVerifyCert.Checked then
    EdServerCertificate.Text:='0'
  else
    if (EdServerCertificate.Text='') or (EdServerCertificate.Text='0') then
      EdServerCertificate.Text:=CARoot();

  EdServerCertificate.Enabled:=CBVerifyCert.Checked;
end;

procedure TVisCreateWaptSetup.ActGetServerCertificateExecute(Sender: TObject);
var
  i:integer;
  certfn: String;
  url,certchain,pem_data,certbundle,certs,cert:Variant;
begin
  url := edWaptServerUrl.Text;
  With TIdURI.Create(url) do
  try
    try
      certfn:= AppendPathDelim(WaptBaseDir)+'ssl\server\'+Host+'.crt';
      certchain := dmpython.waptcrypto.get_peer_cert_chain_from_server(url);
      pem_data := dmpython.waptcrypto.SSLCABundle(certificates:=certchain).as_pem('--noarg--');
      if not VarIsNull(pem_data) then
      begin
        if not DirectoryExists(ExtractFileDir(certfn)) then
          ForceDirectory(ExtractFileDir(certfn));
        StringToFile(certfn,pem_data);
        EdServerCertificate.Text := certfn;
        CBVerifyCert.Checked:=True;
      end
      else
        raise Exception.Create('No certificate returned from  get_pem_server_certificate');
    except
      on E:Exception do ShowMessage('Unable to get https server certificate for url '+url+' '+E.Message);
    end;
  finally
    Free;
  end;
end;

procedure TVisCreateWaptSetup.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
end;

procedure TVisCreateWaptSetup.FormShow(Sender: TObject);
begin
  if edOrgName.Text='' then
    if FileExists(fnPublicCert.FileName) then
      edOrgName.text := VarPythonAsString(dmpython.waptcrypto.SSLCertificate(crt_filename := fnPublicCert.FileName).cn);
      //edOrgName.text := dmwaptpython.DMPython.PythonEng.EvalStringAsStr(Format('common.SSLCertificate(r"""%s""").cn',[fnPublicCert.FileName]));

  CBVerifyCert.Checked:=(EdServerCertificate.Text<>'') and (EdServerCertificate.Text<>'0');
  CBVerifyCertClick(Sender);

  if not CBCheckCertificatesValidity.Checked then
    CBCheckCertificatesValidity.Visible := True;

end;

end.

