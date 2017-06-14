unit uviswaptconfig;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, LSControls, Forms,
  Controls, Graphics, Dialogs, ButtonPanel,
  StdCtrls, ExtCtrls,EditBtn, DefaultTranslator, ComCtrls, ActnList;

type

  { TVisWAPTConfig }

  TVisWAPTConfig = class(TForm)
    ActCheckAndSetwaptserver: TAction;
    ActDownloadCertificate: TAction;
    ActOpenCertDir: TAction;
    ActionList1: TActionList;
    Button1: TButton;
    Button2: TButton;
    Button3: TButton;
    Button4: TButton;
    ButtonPanel1: TButtonPanel;
    cbManual: TCheckBox;
    cbSendStats: TCheckBox;
    cbUseProxyForRepo: TCheckBox;
    cbDebugWindow: TCheckBox;
    cbUseProxyForServer: TCheckBox;
    cbLanguage: TComboBox;
    EdTemplatesAuthorizedCertsDir: TDirectoryEdit;
    eddefault_package_prefix: TLabeledEdit;
    eddefault_sources_root: TDirectoryEdit;
    edhttp_proxy_templates: TLabeledEdit;
    edhttp_proxy: TLabeledEdit;
    edPersonalCertificatePath: TFileNameEdit;
    edrepo_url: TLabeledEdit;
    edServerAddress: TLabeledEdit;
    edtemplates_repo_url: TLabeledEdit;
    edwapt_server: TLabeledEdit;
    ImageList1: TImageList;
    ImgStatusRepo: TImage;
    ImgStatusServer: TImage;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    Label7: TLabel;
    Label8: TLabel;
    Label9: TLabel;
    labStatusRepo: TLabel;
    labStatusServer: TLabel;
    PageControl1: TPageControl;
    pgBase: TTabSheet;
    pgAdvanced: TTabSheet;
    Timer1: TTimer;
    procedure ActCheckAndSetwaptserverExecute(Sender: TObject);
    procedure ActDownloadCertificateExecute(Sender: TObject);
    procedure ActDownloadCertificateUpdate(Sender: TObject);
    procedure ActOpenCertDirExecute(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure cbManualClick(Sender: TObject);
    procedure eddefault_package_prefixExit(Sender: TObject);
    procedure edrepo_urlExit(Sender: TObject);
    procedure edServerAddressChange(Sender: TObject);
    procedure edServerAddressEnter(Sender: TObject);
    procedure edServerAddressExit(Sender: TObject);
    procedure edServerAddressKeyPress(Sender: TObject; var Key: char);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure HelpButtonClick(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
  private
    function CheckServer(Address: String): Boolean;
    { private declarations }
  public
    { public declarations }
  end;

var
  VisWAPTConfig: TVisWAPTConfig;

implementation
uses waptcommon,LCLIntf,IDURI,superobject,uWaptConsoleRes,uScaleDPI,tisstrings;
{$R *.lfm}

{ TVisWAPTConfig }

procedure TVisWAPTConfig.Button1Click(Sender: TObject);
begin
  try
    ShowMessage(WAPTServerJsonGet('api/v1/usage_statistics',[])['result'].AsJSon(True));
  except
    on E:Exception do
      ShowMessage('Unable to retrieve statistics : '+E.Message);
  end;
end;

procedure TVisWAPTConfig.ActCheckAndSetwaptserverExecute(Sender: TObject);
begin
  ActCheckAndSetwaptserver.Enabled:=False;
  ImageList1.GetBitmap(2, ImgStatusRepo.Picture.Bitmap);
  ImageList1.GetBitmap(2, ImgStatusServer.Picture.Bitmap);
  Timer1Timer(Timer1);
end;

procedure TVisWAPTConfig.ActDownloadCertificateExecute(Sender: TObject);
begin
  OpenDocument(edtemplates_repo_url.Text+'/ssl');
end;

procedure TVisWAPTConfig.ActDownloadCertificateUpdate(Sender: TObject);
begin
  ActDownloadCertificate.Enabled:=edtemplates_repo_url.text <> '';;
end;

procedure TVisWAPTConfig.ActOpenCertDirExecute(Sender: TObject);
begin
  if not DirectoryExists(EdTemplatesAuthorizedCertsDir.Directory) then
    mkdir(EdTemplatesAuthorizedCertsDir.Directory);
  OpenDocument(EdTemplatesAuthorizedCertsDir.Directory);
end;

procedure TVisWAPTConfig.cbManualClick(Sender: TObject);
begin
  edrepo_url.Enabled:=cbManual.Checked;
  edwapt_server.Enabled:=cbManual.Checked;

  if not cbManual.Checked then
  begin
    if edServerAddress.Text <> '' then
    begin
      edrepo_url.Text := 'https://'+edServerAddress.Text+'/wapt';
      edwapt_server.Text := 'https://'+edServerAddress.Text;
    end
    else
    begin
      edrepo_url.Text := GetMainWaptRepo;
      edwapt_server.Text := GetWaptServerURL;
    end;
  end;
end;

function MakeIdent(st:String):String;
var
  i:integer;
begin
  result :='';
  for i := 1 to length(st) do
    if CharIsValidIdentifierLetter(st[i]) then
      result := Result+st[i];
end;

procedure TVisWAPTConfig.eddefault_package_prefixExit(Sender: TObject);
begin
  eddefault_package_prefix.Text:=LowerCase(MakeIdent(eddefault_package_prefix.Text));
end;

procedure TVisWAPTConfig.edrepo_urlExit(Sender: TObject);
var
  servername1,servername2:String;
begin
  with TIdURI.Create(edrepo_url.Text) do
  try
    servername1:=Host;
  finally
    Free;
  end;
  with TIdURI.Create(edwapt_server.Text) do
  try
    servername2:=Host;
  finally
    Free;
  end;

  if servername1=servername2 then
  begin
    edServerAddress.Text:=servername1
  end
  else
  begin
    edServerAddress.Text:='';
    edServerAddress.Font.Color := clInactiveCaptionText;
  end;
end;

function TVisWAPTConfig.CheckServer(Address:String):Boolean;
var
  serverRes:ISuperObject;
  strRes,packages:String;
begin
  ImageList1.GetBitmap(2, ImgStatusRepo.Picture.Bitmap);
  ImageList1.GetBitmap(2, ImgStatusServer.Picture.Bitmap);
  Application.ProcessMessages;

  try
    try
      result :=True;
      Screen.Cursor:=crHourGlass;
      try
        if not cbManual.Checked then
        if edServerAddress.Text <> '' then
        begin
          edrepo_url.Text := 'https://'+edServerAddress.Text+'/wapt';
          edwapt_server.Text := 'https://'+edServerAddress.Text;
        end
        else
        begin
          edrepo_url.Text := GetMainWaptRepo;
          edwapt_server.Text := GetWaptServerURL;
        end;

        serverRes := SO(IdhttpGetString(edwapt_server.Text+'/ping',cbUseProxyForServer.Checked,200,60000,60000));
        if serverRes = Nil then
          raise Exception.CreateFmt(rsWaptServerError,['Bad answer']);
        if not serverRes.B['success'] then
          raise Exception.CreateFmt(rsWaptServerError,[serverRes.S['msg']]);

        labStatusServer.Caption:= Format('Server access: %s. %s', [serverRes.S['success'],UTF8Encode(serverRes.S['msg'])]);
        ImageList1.GetBitmap(0, ImgStatusServer.Picture.Bitmap)
      except
        on E:Exception do
        begin
          ImageList1.GetBitmap(1, ImgStatusServer.Picture.Bitmap);
          labStatusServer.Caption:=Format('Server access error: %s',[e.Message]);
        end;
      end;

      try
        packages := IdHttpGetString(edrepo_url.Text+'/Packages',cbUseProxyForRepo.Checked,200,60000,60000);
        if length(packages)<=0 then
          Raise Exception.Create('Packages file empty or not found');
        labStatusRepo.Caption:=Format('Repository access OK', []);
        ImageList1.GetBitmap(0, ImgStatusRepo.Picture.Bitmap);
      except
        on E:Exception do
        begin
          ImageList1.GetBitmap(1, ImgStatusRepo.Picture.Bitmap);
          labStatusRepo.Caption:=Format('Repository access error: %s',[e.Message]);
        end;
      end;

      result := (serverRes<>Nil) and (serverRes.B['success']) and (packages<>'');
    finally
      Screen.Cursor:=crDefault;
    end;
  except
    Result := False;
  end;
end;

procedure TVisWAPTConfig.edServerAddressChange(Sender: TObject);
begin
  //cbManual.Checked:=False;
  labStatusRepo.Caption := '';
  labStatusServer.Caption := '';
  ImageList1.GetBitmap(2, ImgStatusRepo.Picture.Bitmap);
  ImageList1.GetBitmap(2, ImgStatusServer.Picture.Bitmap);

end;

procedure TVisWAPTConfig.edServerAddressEnter(Sender: TObject);
begin
  ButtonPanel1.OKButton.Default:=False;
end;

procedure TVisWAPTConfig.edServerAddressExit(Sender: TObject);
begin
    ButtonPanel1.OKButton.Default:=True;

end;

procedure TVisWAPTConfig.edServerAddressKeyPress(Sender: TObject; var Key: char
  );
begin
  if key=#13 then
    ActCheckAndSetwaptserver.Execute;
end;

procedure TVisWAPTConfig.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
  ScaleImageList(ImageList1,96);
  EdTemplatesAuthorizedCertsDir.Directory:=AuthorizedCertsDir;
end;

procedure TVisWAPTConfig.FormShow(Sender: TObject);
begin
  cbManualClick(cbManual);
  edrepo_urlExit(Sender);
end;

procedure TVisWAPTConfig.HelpButtonClick(Sender: TObject);
begin
  OpenDocument(AppIniFilename);
end;

procedure TVisWAPTConfig.Timer1Timer(Sender: TObject);
begin
  timer1.Enabled:= False;
  ActCheckAndSetwaptserver.Enabled:=True;
  if CheckServer(edServerAddress.Text) then
  begin
    edServerAddress.Font.Color :=clText ;
  end;
end;

end.

