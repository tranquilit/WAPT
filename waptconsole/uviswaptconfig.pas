unit uviswaptconfig;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms,
  Controls, Graphics, Dialogs, ButtonPanel,
  StdCtrls, ExtCtrls,EditBtn, DefaultTranslator;

type

  { TVisWAPTConfig }

  TVisWAPTConfig = class(TForm)
    Button1: TButton;
    Button2: TButton;
    ButtonPanel1: TButtonPanel;
    cbSendStats: TCheckBox;
    cbUseProxyForRepo: TCheckBox;
    cbUseProxyForServer: TCheckBox;
    cbAdvanced: TCheckBox;
    cbUseProxyForTemplate: TCheckBox;
    eddefault_package_prefix: TLabeledEdit;
    eddefault_sources_root: TDirectoryEdit;
    edhttp_proxy: TLabeledEdit;
    edhttp_proxy_templates: TLabeledEdit;
    edprivate_key: TFileNameEdit;
    edrepo_url: TLabeledEdit;
    edServerAddress: TLabeledEdit;
    edtemplates_repo_url: TLabeledEdit;
    edwapt_server: TLabeledEdit;
    ImageList1: TImageList;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    Label6: TLabel;
    Label7: TLabel;
    Label8: TLabel;
    labStatusRepo: TLabel;
    labStatusServer: TLabel;
    panAdvanced: TPanel;
    Panel1: TPanel;
    panClient: TPanel;
    Timer1: TTimer;
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure cbAdvancedClick(Sender: TObject);
    procedure edrepo_urlExit(Sender: TObject);
    procedure edServerAddressChange(Sender: TObject);
    procedure edServerAddressEnter(Sender: TObject);
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
uses waptcommon,LCLIntf,IDURI,superobject,uWaptConsoleRes;
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

procedure TVisWAPTConfig.Button2Click(Sender: TObject);
begin
  if CheckServer(edServerAddress.Text) then
  begin
    Timer1Timer(Timer1);
  end;
end;

procedure TVisWAPTConfig.cbAdvancedClick(Sender: TObject);
begin
  panAdvanced.Visible := cbAdvanced.Checked;
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
  if address = '' then
  begin
    labStatusRepo.Caption:='';
    labStatusRepo.Caption:='';
    result := False;
    Exit;
  end;

  try
    try
      Screen.Cursor:=crHourGlass;
      try
        serverRes := SO(IdhttpGetString('https://'+address+'/ping',cbUseProxyForServer.Checked,200,60000,60000));
        if serverRes<>Nil then
          labStatusServer.Caption:= Format('Server access: %s. %s', [serverRes.S['success'],UTF8Encode(serverRes.S['msg'])])
        else
          raise Exception.CreateFmt(rsWaptServerError,['Bad answer'])
      except
        on E:Exception do
          labStatusServer.Caption:=Format('Server access error: %s',[e.Message]);
      end;

      try
        packages := IdHttpGetString('http://'+address+'/wapt/Packages',cbUseProxyForRepo.Checked,200,60000,60000);
        if length(packages)>0 then
          labStatusRepo.Caption:=Format('Repository access OK', [])
        else
          labStatusRepo.Caption:=Format('Repository access error: %s',['Packages file empty or not found']);
      except
        on E:Exception do
          labStatusRepo.Caption:=Format('Repository access error: %s',[e.Message]);
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
  labStatusRepo.Caption := '';
  labStatusServer.Caption := '';
end;

procedure TVisWAPTConfig.edServerAddressEnter(Sender: TObject);
begin
  if edServerAddress.Font.Color = clInactiveCaptionText then
     edServerAddress.Clear;
end;

procedure TVisWAPTConfig.FormShow(Sender: TObject);
begin
  cbAdvancedClick(cbAdvanced);
  edrepo_urlExit(Sender);
end;

procedure TVisWAPTConfig.HelpButtonClick(Sender: TObject);
begin
  OpenDocument(AppIniFilename);
end;

procedure TVisWAPTConfig.Timer1Timer(Sender: TObject);
begin
  timer1.Enabled:= False;
  if CheckServer(edServerAddress.Text) then
  begin
    edServerAddress.Font.Color :=clText ;
    edrepo_url.Text := 'http://'+edServerAddress.Text+'/wapt';
    edwapt_server.Text := 'https://'+edServerAddress.Text;
  end;
end;

end.

