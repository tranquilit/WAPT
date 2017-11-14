unit uvisrepositories;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, RTTICtrls, Forms, Controls, Graphics,
  Dialogs, ExtCtrls, Buttons, DefaultTranslator, StdCtrls, EditBtn, ActnList,
  waptcommon;

type

  { TVisRepositories }

  TVisRepositories = class(TForm)
    ActDownloadCertificate: TAction;
    ActGetServerCertificate: TAction;
    ActCertifiCACert: TAction;
    ActSaveSettings: TAction;
    ActUnregisterRepo: TAction;
    ActRegisterRepo: TAction;
    ActSelectHttpsBundle: TAction;
    ActSelectCertDir: TAction;
    ActionList1: TActionList;
    ActOpenCertDir: TAction;
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    BitBtn3: TBitBtn;
    butBrowseCerts: TButton;
    ButDefaultWaptBundle: TButton;
    ButExploreDir: TButton;
    ButGetServerBundle: TButton;
    ButSelectCABundle: TButton;
    ButSelectCABundle1: TButton;
    ButSelectCABundle2: TButton;
    cbCheckHTTPS: TCheckBox;
    cbAdvanced2: TCheckBox;
    CBCheckSignature: TCheckBox;
    EdHttpProxy: TTIEdit;
    EdName: TTIComboBox;
    EdServerCABundle: TTIEdit;
    EdSignersCABundle: TTIEdit;
    ImageList1: TImageList;
    labCertsDir: TLabel;
    Label6: TLabel;
    labRepoURL: TLabel;
    labProxy: TLabel;
    labCertDir: TLabel;
    DlgOpenCrt: TOpenDialog;
    labName: TLabel;
    PanAdvanced: TPanel;
    panCertActions: TPanel;
    PanBottom: TPanel;
    Panel2: TPanel;
    panDir: TPanel;
    panHttps1: TPanel;
    panHttps2: TPanel;
    panNameActions: TPanel;
    panPackageSign1: TPanel;
    panPackageSign2: TPanel;
    panProxyActions: TPanel;
    panServerCAAction: TPanel;
    panURLActions: TPanel;
    EdRepoURL: TTIEdit;
    procedure ActCertifiCACertExecute(Sender: TObject);
    procedure ActDownloadCertificateExecute(Sender: TObject);
    procedure ActDownloadCertificateUpdate(Sender: TObject);
    procedure ActGetServerCertificateExecute(Sender: TObject);
    procedure ActOpenCertDirExecute(Sender: TObject);
    procedure ActRegisterRepoExecute(Sender: TObject);
    procedure ActRegisterRepoUpdate(Sender: TObject);
    procedure ActSaveSettingsExecute(Sender: TObject);
    procedure ActSaveSettingsUpdate(Sender: TObject);
    procedure ActSelectHttpsBundleExecute(Sender: TObject);
    procedure ActUnregisterRepoExecute(Sender: TObject);
    procedure ActUnregisterRepoUpdate(Sender: TObject);
    procedure cbAdvanced2Click(Sender: TObject);
    procedure cbCheckHTTPSClick(Sender: TObject);
    procedure CBCheckSignatureClick(Sender: TObject);
    procedure EdNameSelect(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    FRepoName: String;
    FWaptRepo: TWaptRepo;
    procedure FillReposList;
    procedure SetRepoName(AValue: String);
    { private declarations }
  public
    { public declarations }
    property RepoName:String read FRepoName write SetRepoName;
    property WaptRepo:TWaptRepo read FWaptRepo;
  end;

var
  VisRepositories: TVisRepositories;

implementation
uses uSCaleDPI,LCLIntf,tisinifiles,IniFiles,tiscommon,URIParser,dmwaptpython,variants,VarPyth,tisstrings,uWaptConsoleRes;
{$R *.lfm}

{ TVisRepositories }


procedure TVisRepositories.FillReposList;
var
  inifile: TIniFile;
begin
  inifile := TIniFile.Create(AppIniFilename);
  try
    inifile.ReadSections(EdName.Items);
    if EdName.Items.IndexOf('global')>=0 then
      EdName.Items.Delete(EdName.Items.IndexOf('global'));
    if EdName.Items.IndexOf('options')>=0 then
      EdName.Items.Delete(EdName.Items.IndexOf('options'));
  finally
    inifile.Free;
  end;
end;

procedure TVisRepositories.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
  ScaleImageList(ImageList1,96);

  FWaptRepo := TWaptRepo.Create(FRepoName);

  FillReposList;

  EdName.Link.TIObject := FWaptRepo;
  EdRepoURL.Link.TIObject := FWaptRepo;
  EdHttpProxy.Link.TIObject := FWaptRepo;
  EdServerCABundle.Link.TIObject := FWaptRepo;
  EdSignersCABundle.Link.TIObject := FWaptRepo;

end;

procedure TVisRepositories.FormDestroy(Sender: TObject);
begin
  if Assigned(FWaptRepo) then
    FreeAndNil(FWaptRepo);
end;

procedure TVisRepositories.FormShow(Sender: TObject);
begin
  WaptRepo.LoadFromInifile(WaptIniFilename,RepoName);
  cbAdvanced2Click(Nil);
  cbCheckHTTPS.Checked:=(FWaptRepo.ServerCABundle <>'') and (FWaptRepo.ServerCABundle<>'0');
  cbCheckHTTPSClick(Nil);

  CBCheckSignature.Checked:=(FWaptRepo.SignersCABundle <>'');
  CBCheckSignatureClick(Nil);

  BitBtn1.SetFocus;
end;

procedure TVisRepositories.SetRepoName(AValue: String);
begin
  if WaptRepo.Name=AValue then Exit;
  FRepoName := AValue;
  WaptRepo.Name:=AValue;
  WaptRepo.LoadFromInifile(WaptIniFilename,AValue);
  EdName.ReadOnly:=AValue<>'';
end;

procedure TVisRepositories.ActDownloadCertificateExecute(Sender: TObject);
begin
  OpenDocument(WaptRepo.RepoURL+'/ssl');
end;

procedure TVisRepositories.ActCertifiCACertExecute(Sender: TObject);
begin
  WaptRepo.ServerCABundle:=CARoot;
end;

procedure TVisRepositories.ActDownloadCertificateUpdate(Sender: TObject);
begin
  ActDownloadCertificate.Enabled:=WaptRepo.RepoURL <> '';;
end;

procedure TVisRepositories.ActGetServerCertificateExecute(Sender: TObject);
var
  certfn: String;
  pem_data:Variant;
  RepoURI:TURI;
begin
  RepoURI := ParseURI(WaptRepo.RepoURL);
  certfn:= AppendPathDelim(Appuserinipath)+'ssl\server\'+RepoURI.Host+'.crt';
  try
    pem_data := dmpython.waptcrypto.SSLCABundle(certificates := dmpython.waptcrypto.get_peer_cert_chain_from_server(url := WaptRepo.RepoURL)).as_pem('--noarg--');
    if not VarIsNull(pem_data) then
    begin
      if not DirectoryExists(ExtractFileDir(certfn)) then
        ForceDirectory(ExtractFileDir(certfn));
      StringToFile(certfn,pem_data);
      WaptRepo.ServerCABundle := certfn;
    end
    else
      raise Exception.Create('No certificate returned from  get_pem_server_certificate');
  except
    on E:Exception do ShowMessage('Unable to get https server certificate for url '+WaptRepo.RepoURL+' '+E.Message);
  end;
end;

procedure TVisRepositories.ActOpenCertDirExecute(Sender: TObject);
begin
  if not DirectoryExists(WaptRepo.SignersCABundle) then
    mkdir(WaptRepo.SignersCABundle);
  OpenDocument(WaptRepo.SignersCABundle);
end;

procedure TVisRepositories.ActRegisterRepoExecute(Sender: TObject);
begin
  RepoName:='';
  EdName.ReadOnly:=False;
  EdName.SetFocus;
end;

procedure TVisRepositories.ActRegisterRepoUpdate(Sender: TObject);
begin
  ActRegisterRepo.Enabled := not WaptRepo.IsUpdated;
end;

procedure TVisRepositories.ActSaveSettingsExecute(Sender: TObject);
begin
  WaptRepo.SaveToInifile(WaptIniFilename,'');
  ModalResult:=mrOk;
end;

procedure TVisRepositories.ActSaveSettingsUpdate(Sender: TObject);
begin
  ActSaveSettings.Enabled := (WaptRepo.Name<>'') and WaptRepo.IsUpdated;
end;

procedure TVisRepositories.ActSelectHttpsBundleExecute(Sender: TObject);
begin
  DlgOpenCrt.FileName:=WaptRepo.ServerCABundle;
  if DlgOpenCrt.Execute then
    WaptRepo.ServerCABundle:=DlgOpenCrt.FileName;
end;

procedure TVisRepositories.ActUnregisterRepoExecute(Sender: TObject);
var
  inifile: TIniFile;
begin
  if MessageDlg(format(rsRepositoryUnregisterConfirm, [WaptRepo.Name]),
        mtConfirmation, mbYesNoCancel, 0) = mrYes then
  begin
    inifile := TIniFile.Create(AppIniFilename);
    try
      if inifile.SectionExists(WaptRepo.Name) then
      begin
        inifile.EraseSection(WaptRepo.Name);
        EdName.Items.Delete(EdName.Items.IndexOf(WaptRepo.Name));
      end;
      if EdName.Items.Count>0 then
        EdName.ItemIndex:=0
      else
        EdName.ItemIndex:=-1;
      EdNameSelect(Nil);

    finally
      inifile.Free;
    end;
  end;
end;

procedure TVisRepositories.ActUnregisterRepoUpdate(Sender: TObject);
begin
  ActUnregisterRepo.Enabled := WaptRepo.Name<>'Global';
end;

procedure TVisRepositories.cbAdvanced2Click(Sender: TObject);
begin
  PanAdvanced.Visible:=cbAdvanced2.Checked;
end;

procedure TVisRepositories.cbCheckHTTPSClick(Sender: TObject);
begin
  If not cbCheckHTTPS.Checked then
    WaptRepo.ServerCABundle := '0'
  else
    if (WaptRepo.ServerCABundle='') or (WaptRepo.ServerCABundle='0') then
      WaptRepo.ServerCABundle := CARoot();

  EdServerCABundle.Enabled := cbCheckHTTPS.Checked;
  ActGetServerCertificate.Enabled := cbCheckHTTPS.Checked;
  ActCertifiCACert.Enabled := cbCheckHTTPS.Checked;
  ActSelectHttpsBundle.Enabled := cbCheckHTTPS.Checked;;
end;

procedure TVisRepositories.CBCheckSignatureClick(Sender: TObject);
begin
  If not CBCheckSignature.Checked then
    WaptRepo.SignersCABundle := ''
  else
    if (WaptRepo.SignersCABundle='') then
      WaptRepo.SignersCABundle := AppendPathDelim(WaptBaseDir)+'ssl';

  EdSignersCABundle.Enabled := CBCheckSignature.Checked;
  ActSelectCertDir.Enabled := CBCheckSignature.Checked;
  ActOpenCertDir.Enabled := CBCheckSignature.Checked;
end;

procedure TVisRepositories.EdNameSelect(Sender: TObject);
begin
  RepoName:=EdName.Text;
end;


procedure TVisRepositories.FormCloseQuery(Sender: TObject; var CanClose: boolean
  );
begin
  if ModalResult=mrOK then
  try
    CanClose:=True;
  finally
  end
  else
    CanClose:=True;
end;


end.

