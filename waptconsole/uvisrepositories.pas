unit uvisrepositories;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, RTTICtrls, Forms, Controls, Graphics, Dialogs,
  ExtCtrls, Buttons, DefaultTranslator, StdCtrls, EditBtn, ActnList, waptcommon;

type

  { TVisRepositories }

  TVisRepositories = class(TForm)
    ActDownloadCertificate: TAction;
    ActGetServerCertificate: TAction;
    ActCertifiCACert: TAction;
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
    CBCheckSignature: TCheckBox;
    cbEnableCheckHttps: TCheckBox;
    EdHttpProxy: TTIEdit;
    EdServerCABundle: TTIEdit;
    EdSignersCABundle: TTIEdit;
    ImageList1: TImageList;
    labCertsDir: TLabel;
    Label6: TLabel;
    labRepoURL: TLabel;
    labProxy: TLabel;
    labCertDir: TLabel;
    DlgOpenCrt: TOpenDialog;
    panCertActions: TPanel;
    Panel1: TPanel;
    Panel2: TPanel;
    panDir: TPanel;
    panHttps1: TPanel;
    panHttps2: TPanel;
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
    procedure ActSelectHttpsBundleExecute(Sender: TObject);
    procedure cbEnableCheckHttpsClick(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    FRepoName: String;
    FWaptRepo: TWaptRepo;
    function GetRepoName: String;
    function GetWaptRepo: TWaptRepo;
    procedure SetRepoName(AValue: String);
    procedure SetWaptRepo(AValue: TWaptRepo);
    { private declarations }
  public
    { public declarations }
    property RepoName:String read GetRepoName write SetRepoName;
    property WaptRepo:TWaptRepo read GetWaptRepo write SetWaptRepo;
  end;

var
  VisRepositories: TVisRepositories;

implementation
uses uSCaleDPI,LCLIntf,tisinifiles,IniFiles,tiscommon,URIParser,dmwaptpython,variants,VarPyth,tisstrings;
{$R *.lfm}

{ TVisRepositories }

procedure TVisRepositories.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
  WaptRepo := TWaptRepo.Create('global');
end;

procedure TVisRepositories.FormShow(Sender: TObject);
begin
  WaptRepo.LoadFromInifile(WaptIniFilename,'');
end;

procedure TVisRepositories.SetWaptRepo(AValue: TWaptRepo);
begin
  if FWaptRepo=AValue then Exit;
  FWaptRepo:=AValue;

  EdRepoURL.Link.TIObject := WaptRepo;
  EdHttpProxy.Link.TIObject := WaptRepo;
  EdServerCABundle.Link.TIObject := WaptRepo;
  EdSignersCABundle.Link.TIObject := WaptRepo;

  cbEnableCheckHttps.Checked:=(WaptRepo.ServerCABundle <>'') and (WaptRepo.ServerCABundle<>'0');
  cbEnableCheckHttpsClick(Nil);

end;

procedure TVisRepositories.SetRepoName(AValue: String);
begin
  if FRepoName=AValue then Exit;
  FRepoName:=AValue;
  WaptRepo.LoadFromInifile(WaptIniFilename,FRepoName);
end;

function TVisRepositories.GetRepoName: String;
begin
  Result := WaptRepo.Name;
end;

function TVisRepositories.GetWaptRepo: TWaptRepo;
begin
  if not Assigned(FWaptRepo) then
  begin
    FWaptRepo := TWaptRepo.Create(FRepoName);
    FWaptRepo.LoadFromInifile(WaptIniFilename,FRepoName);
  end;
  Result := FWaptRepo;
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
  i:integer;
  certfn: String;
  pem_data,certbundle,certs,cert:Variant;
  RepoURI:TURI;
begin
  RepoURI := ParseURI(WaptRepo.RepoURL);
  certfn:= waptbasedir+'ssl\server\'+RepoURI.Host+'.crt';
  try
    pem_data := MainModule.waptcrypto.SSLCABundle(certificates := MainModule.waptcrypto.get_peer_cert_chain_from_server(url := WaptRepo.RepoURL)).as_pem('--noarg--');
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

procedure TVisRepositories.ActSelectHttpsBundleExecute(Sender: TObject);
begin
  DlgOpenCrt.FileName:=WaptRepo.ServerCABundle;
  if DlgOpenCrt.Execute then
    WaptRepo.ServerCABundle:=DlgOpenCrt.FileName;
end;

procedure TVisRepositories.cbEnableCheckHttpsClick(Sender: TObject);
begin
  If not cbEnableCheckHttps.Checked then
    WaptRepo.ServerCABundle := '0'
  else
    if (WaptRepo.ServerCABundle='') or (WaptRepo.ServerCABundle='0') then
      WaptRepo.ServerCABundle := CARoot();

  EdServerCABundle.Enabled := cbEnableCheckHttps.Checked;
  ActGetServerCertificate.Enabled := cbEnableCheckHttps.Checked;
  ActCertifiCACert.Enabled := cbEnableCheckHttps.Checked;
  ActSelectHttpsBundle.Enabled := cbEnableCheckHttps.Checked;;
end;


procedure TVisRepositories.FormCloseQuery(Sender: TObject; var CanClose: boolean
  );
begin
  if ModalResult=mrOK then
  try
    WaptRepo.SaveToInifile(WaptIniFilename,'');
    CanClose:=True;
  finally
  end
  else
    CanClose:=True;
end;


end.

