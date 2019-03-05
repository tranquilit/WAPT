unit uviswaptconfig;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, ButtonPanel, StdCtrls,
  ExtCtrls, EditBtn, DefaultTranslator, ComCtrls, ActnList, Grids, DBGrids,
  Menus, Buttons, sogrid, types, inifiles,
  VirtualTrees, superobject;

type

  { TVisWAPTConfig }

  TVisWAPTConfig = class(TForm)
    ActCheckAndSetwaptserver: TAction;
    ActDownloadCertificate: TAction;
    ActGetServerCertificate: TAction;
    ActCheckPersonalKey: TAction;
    ActCreateKeyCert: TAction;
    ActAddPlugin: TAction;
    ActDeletePlugin: TAction;
    ActSaveConfig: TAction;
    ActOpenCertDir: TAction;
    ActionList1: TActionList;
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    Button1: TButton;
    Button2: TButton;
    Button3: TButton;
    Button5: TButton;
    Button6: TButton;
    ButtonPanel1: TButtonPanel;
    cbManual: TCheckBox;
    cbSendStats: TCheckBox;
    cbUseProxyForRepo: TCheckBox;
    cbUseProxyForServer: TCheckBox;
    CBVerifyCert: TCheckBox;
    EdLicencesDirectory: TDirectoryEdit;
    EdMaturity: TComboBox;
    EdServerCertificate: TFileNameEdit;
    edDefaultPackagePrefix: TLabeledEdit;
    eddefault_sources_root: TDirectoryEdit;
    edhttp_proxy: TLabeledEdit;
    edPersonalCertificatePath: TFileNameEdit;
    edrepo_url: TLabeledEdit;
    edServerAddress: TLabeledEdit;
    edwapt_server: TLabeledEdit;
    ImageList1: TImageList;
    ImgStatusPersonalCertificate: TImage;
    ImgStatusLicences: TImage;
    ImgStatusRepo: TImage;
    ImgStatusServer: TImage;
    ImgStatusPackagePrefix: TImage;
    Label1: TLabel;
    Label2: TLabel;
    LabLicencesDirectory: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    Label6: TLabel;
    Label7: TLabel;
    Label8: TLabel;
    labStatusRepo: TLabel;
    labStatusServer: TLabel;
    MainMenu1: TMainMenu;
    PageControl1: TPageControl;
    pgBase: TTabSheet;
    pgAdvanced: TTabSheet;
    GridPlugins: TSOGrid;
    pgPlugins: TTabSheet;
    Timer1: TTimer;
    procedure ActAddPluginExecute(Sender: TObject);
    procedure ActCreateKeyCertExecute(Sender: TObject);
    procedure ActDeletePluginExecute(Sender: TObject);
    procedure ActCheckAndSetwaptserverExecute(Sender: TObject);
    procedure ActCheckPersonalKeyExecute(Sender: TObject);
    procedure ActCheckPersonalKeyUpdate(Sender: TObject);
    procedure ActGetServerCertificateExecute(Sender: TObject);
    procedure ActGetServerCertificateUpdate(Sender: TObject);
    procedure ActSaveConfigExecute(Sender: TObject);
    procedure ActSaveConfigUpdate(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure cbManualClick(Sender: TObject);
    procedure CBVerifyCertClick(Sender: TObject);
    procedure edDefaultPackagePrefixExit(Sender: TObject);
    procedure edrepo_urlExit(Sender: TObject);
    procedure edServerAddressChange(Sender: TObject);
    procedure edServerAddressEnter(Sender: TObject);
    procedure edServerAddressExit(Sender: TObject);
    procedure edServerAddressKeyPress(Sender: TObject; var Key: char);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure GridPluginsEditing(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; var Allowed: Boolean);
    procedure HelpButtonClick(Sender: TObject);
    procedure OKButtonClick(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
  private
    FIniFilename: String;
    Finifile: TIniFile;
    function CheckServer(Address: String): Boolean;
    function GetGridHostsPluginsFromIni: ISuperObject;
    function GetInifile: TIniFile;
    procedure SetIniFilename(AValue: String);
    procedure SetStatus(img:TImage;status:Integer);
    { private declarations }
  public
    { public declarations }
    property IniFile: TIniFile read GetInifile;
    property IniFileName:String read FIniFilename write SetIniFilename;
  end;

var
  VisWAPTConfig: TVisWAPTConfig;

implementation
uses base64, tiscommon,waptcommon,LCLIntf,IDURI,uWaptConsoleRes,
    tisstrings,dmwaptpython,variants,VarPyth,uvisprivatekeyauth,tisinifiles,
    LazFileUtils,FileUtil,strutils,Windows,uWaptPythonUtils,uVisCreateKey;
{$R *.lfm}

{ TVisWAPTConfig }

const
  ssUnknown=0;
  ssWaiting=1;
  ssError=2;
  ssWarning=3;
  ssOK=4;

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
var
  url: TIdURI;
begin
  ActCheckAndSetwaptserver.Enabled:=False;
  if pos('http',lowercase(edServerAddress.Text))<=0 then
    edServerAddress.Text := 'https://'+edServerAddress.Text;

  with TIdURI.Create(edServerAddress.Text) do
  try
    edServerAddress.Text:=Host;
    if Port<>'' then
      edServerAddress.Text:=edServerAddress.Text + ':' + Port;
    if Document<>'' then
      edServerAddress.Text:=edServerAddress.Text+'/'+Document;
  finally
    Free;
  end;

  SetStatus(ImgStatusRepo,ssWaiting);
  SetStatus(ImgStatusServer,ssWaiting);
  Timer1Timer(Timer1);
end;

procedure TVisWAPTConfig.ActAddPluginExecute(Sender: TObject);
var
  APlugin: ISuperObject;
begin
  APlugin := TSuperObject.Create(stObject);
  APlugin.S['name'] := 'New';
  APlugin.S['executable'] := 'explorer.exe';
  APlugin.S['arguments'] := 'c:\';

  GridPlugins.Data.AsArray.Add(APlugin);
  GridPlugins.LoadData;
end;

procedure TVisWAPTConfig.ActCreateKeyCertExecute(Sender: TObject);
begin
  With TVisCreateKey.Create(Self) do
  try
    if ShowModal = mrOk then
    begin
      edPersonalCertificatePath.FileName:=CertificateFilename;
      //TODO propose to copy to trusted certs if no certificate exists at the moment
    end;
  finally
    Free;
  end;
end;

procedure TVisWAPTConfig.ActDeletePluginExecute(Sender: TObject);
begin
  GridPlugins.DeleteRows(GridPlugins.SelectedRows);
end;

procedure TVisWAPTConfig.ActCheckPersonalKeyExecute(Sender: TObject);
var
  keyPath: String;
  vpassword,vcertificate_path:Variant;

begin
  SetStatus(ImgStatusPersonalCertificate,ssWaiting);
  with TVisPrivateKeyAuth.Create(Application.MainForm) do
  try
    laKeyPath.Caption := edPersonalCertificatePath.text;
    if ShowModal = mrOk then
    begin
      vpassword := edPasswordKey.Text;
      vcertificate_path := PyUTF8Decode(edPersonalCertificatePath.Text);
      keyPath := VarPythonAsString(DMPython.waptdevutils.get_private_key_encrypted(certificate_path:=vcertificate_path,password:=vpassword));
      if keyPath = '' then
      begin
        SetStatus(ImgStatusPersonalCertificate,ssError);
        ShowMessageFmt('Error : No private key in directory %s could be decrypted with supplied password, or none matches the certificate.',[ExtractFileDir(edPersonalCertificatePath.Text)])
      end
      else
      begin
        if vpassword='' then
          ShowMessageFmt('Success: Matching private key %s found. Warning, key is not encrypted',[keyPath])
        else
          ShowMessageFmt('Success: Matching private key %s decrypted properly and matching the certificate.',[keyPath]);
        SetStatus(ImgStatusPersonalCertificate,ssOK);
      end;
    end;
  finally
    free;
  end;
end;

procedure TVisWAPTConfig.ActCheckPersonalKeyUpdate(Sender: TObject);
var
  prev:Boolean;
begin
  prev := ActCheckPersonalKey.Enabled;
  ActCheckPersonalKey.Enabled:= FileExistsUTF8(edPersonalCertificatePath.FileName);
  if not ActCheckPersonalKey.Enabled and (ImgStatusPersonalCertificate.Tag<>ssError) then
    SetStatus(ImgStatusPersonalCertificate,ssError)
  else if (prev <> ActCheckPersonalKey.Enabled) and (ImgStatusPersonalCertificate.Tag<>ssUnknown) then
    SetStatus(ImgStatusPersonalCertificate,ssUnknown);

  if (edDefaultPackagePrefix.Text='') then
    SetStatus(ImgStatusPackagePrefix,ssError)
  else
    SetStatus(ImgStatusPackagePrefix,ssOK);

  if (EdLicencesDirectory.Text<>'') then
    if not DirectoryExistsUTF8(EdLicencesDirectory.Text) then
      SetStatus(ImgStatusLicences,ssError)
    else
      SetStatus(ImgStatusLicences,ssUnknown);
end;

procedure TVisWAPTConfig.ActGetServerCertificateExecute(Sender: TObject);
var
  certfn: String;
  url,certchain,pem_data,cert:Variant;
  i: LongWord;
begin
  url := edwapt_server.Text;
  With TIdURI.Create(url) do
  try
    try
      certchain := dmpython.waptcrypto.get_peer_cert_chain_from_server(url);
      {for i := 0 to len(certchain)-1 do
        ShowMessage(VarPythonAsString('cn:'+certchain.__getitem__(i).cn)+#13#10+'sha256:'+VarPythonAsString(certchain.__getitem__(i).fingerprint));}
      pem_data := dmpython.waptcrypto.get_cert_chain_as_pem(certificates_chain:=certchain);
      if not VarIsNull(pem_data) then
      begin
        cert := certchain.__getitem__(0);
        certfn:= AppendPathDelim(WaptBaseDir)+'ssl\server\'+cert.cn+'.crt';
        if not DirectoryExists(ExtractFileDir(certfn)) then
          ForceDirectory(ExtractFileDir(certfn));
        StringToFile(certfn,String(pem_data));
        EdServerCertificate.Text := certfn;
        CBVerifyCert.Checked:=True;
        ActCheckAndSetwaptserver.Execute;
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

procedure TVisWAPTConfig.ActGetServerCertificateUpdate(Sender: TObject);
begin
  ActGetServerCertificate.Enabled := CBVerifyCert.Checked and (edwapt_server.Text <> '');
end;

procedure TVisWAPTConfig.ActSaveConfigExecute(Sender: TObject);
begin
  inifile.WriteString('global', 'repo_url', edrepo_url.Text);
  inifile.WriteString('global','verify_cert',EdServerCertificate.Text);

  inifile.WriteString('global', 'http_proxy', edhttp_proxy.Text);
  inifile.WriteString('global', 'default_package_prefix',
    LowerCase(edDefaultPackagePrefix.Text));
  inifile.WriteString('global', 'wapt_server', edwapt_server.Text);
  inifile.WriteString('global', 'default_sources_root',
    eddefault_sources_root.Text);
  inifile.WriteString('global', 'personal_certificate_path', edPersonalCertificatePath.Text);
  inifile.WriteBool('global', 'use_http_proxy_for_server',
    cbUseProxyForServer.Checked);
  inifile.WriteBool('global', 'use_http_proxy_for_repo',
    cbUseProxyForRepo.Checked);
  inifile.WriteBool('global', 'send_usage_report',
    cbSendStats.Checked);
  inifile.WriteString('global', 'default_maturity',EdMaturity.Text);

  inifile.WriteString('global','grid_hosts_plugins', EncodeStringBase64(GridPlugins.Data.AsJSon()));

  if EdLicencesDirectory.Directory<>'' then
    inifile.WriteString('global', 'licences_directory', EdLicencesDirectory.Directory);

  //inifile.WriteString('global','default_sources_url',eddefault_sources_url.text);
  ModalResult:=mrOk;
end;

procedure TVisWAPTConfig.SetStatus(img: TImage; status: Integer);
begin
  if Status>4 then
    Status := 0;
  if Img.Tag <> status then
  begin
    ImageList1.GetBitmap(status, Img.Picture.Bitmap);
    img.Tag:=status;
  end;
end;

procedure TVisWAPTConfig.ActSaveConfigUpdate(Sender: TObject);
begin
  ActSaveConfig.Enabled := FIniFilename <> '';
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
      edrepo_url.Text := GetMainWaptRepoURL;
      edwapt_server.Text := GetWaptServerURL;
    end;
  end;
end;

procedure TVisWAPTConfig.CBVerifyCertClick(Sender: TObject);
begin
  If not CBVerifyCert.Checked then
    EdServerCertificate.Text:='0'
  else
  begin
    if (EdServerCertificate.Text='') or (EdServerCertificate.Text='0') then
    begin
      EdServerCertificate.Text := IniReadString(IniFileName,'global','verify_cert','0');
      if (LowerCase(EdServerCertificate.Text) = '0') or (LowerCase(EdServerCertificate.Text) = 'false') then
        EdServerCertificate.Text:=CARoot();
      ActCheckAndSetwaptserver.Execute;
    end;
  end;

  EdServerCertificate.Enabled:=CBVerifyCert.Checked;
  ActGetServerCertificate.Enabled:=CBVerifyCert.Checked;

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

procedure TVisWAPTConfig.edDefaultPackagePrefixExit(Sender: TObject);
begin
  edDefaultPackagePrefix.Text:=LowerCase(MakeIdent(edDefaultPackagePrefix.Text));
end;

procedure TVisWAPTConfig.edrepo_urlExit(Sender: TObject);
var
  servername1,servername2:String;
begin
  with TIdURI.Create(edrepo_url.Text) do
  try
    servername1:=Host;
    if (Document<>'wapt') and (RightStr(Document,length('/wapt'))='/wapt') then
      servername1:=servername1+'/'+LeftStr(Document,Length(Document)-length('/wapt'));
  finally
    Free;
  end;
  with TIdURI.Create(edwapt_server.Text) do
  try
    servername2:=Host;
    if Document<>'' then
      servername2:=servername2+'/'+Document;
  finally
    Free;
  end;

  if servername1=servername2 then
  begin
    edServerAddress.Text:=servername1;
    edServerAddress.Font.Color := clDefault;
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
  strRes,packages,proxy:String;
begin
  SetStatus(ImgStatusRepo,ssWaiting);
  SetStatus(ImgStatusServer,ssWaiting);

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
          edrepo_url.Text := GetMainWaptRepoURL;
          edwapt_server.Text := GetWaptServerURL;
        end;

        if cbUseProxyForServer.Checked then
          proxy := edhttp_proxy.Text
        else
          proxy :='';

        serverRes := SO(IdhttpGetString(edwapt_server.Text+'/ping',proxy,200,60000,60000,'','','GET','',EdServerCertificate.Text,
          'application/json',Nil,WaptClientCertFilename,WaptClientKeyFilename));
        if serverRes = Nil then
          raise Exception.CreateFmt(rsWaptServerError,['Bad answer']);
        if not serverRes.B['success'] then
          raise Exception.CreateFmt(rsWaptServerError,[serverRes.S['msg']]);

        labStatusServer.Caption:= Format('Server access: %s. %s', [serverRes.S['success'],UTF8Encode(serverRes.S['msg'])]);
        SetStatus(ImgStatusServer,ssOK);
      except
        on E:Exception do
        begin
          SetStatus(ImgStatusServer,ssError);
          labStatusServer.Caption:=Format('Server access error: %s',[e.Message]);
        end;
      end;

      if cbUseProxyForRepo.Checked then
        proxy := edhttp_proxy.Text
      else
        proxy :='';

      try
        packages := IdHttpGetString(edrepo_url.Text+'/Packages',Proxy,200,60000,60000,'','','GET','',EdServerCertificate.Text,
            'application/binary',Nil,WaptClientCertFilename,WaptClientKeyFilename);
        if length(packages)<=0 then
          Raise Exception.Create('Packages file empty or not found');
        labStatusRepo.Caption:=Format('Repository access OK', []);
        SetStatus(ImgStatusRepo,ssOK);
      except
        on E:Exception do
        begin
          SetStatus(ImgStatusRepo,ssError);
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

function TVisWAPTConfig.GetInifile: TIniFile;
begin
  if Finifile = Nil then
    Finifile:=TIniFile.Create(FIniFilename);
  Result := Finifile;
end;

procedure TVisWAPTConfig.SetIniFilename(AValue: String);
begin
  if FIniFilename=AValue then Exit;
  FIniFilename:=AValue;
  if Assigned(FIniFile) then
    FreeAndNil(Finifile);

  edrepo_url.Text := inifile.ReadString('global', 'repo_url', '');

  EdServerCertificate.FileName:=inifile.ReadString('global','verify_cert','');

  edhttp_proxy.Text := inifile.ReadString('global', 'http_proxy', '');
  cbUseProxyForServer.Checked :=
    inifile.ReadBool('global', 'use_http_proxy_for_server', edhttp_proxy.Text <> '');
  cbUseProxyForRepo.Checked :=
    inifile.ReadBool('global', 'use_http_proxy_for_repo', edhttp_proxy.Text <> '');

  edDefaultPackagePrefix.Text :=
    inifile.ReadString('global', 'default_package_prefix', '');
  edwapt_server.Text := inifile.ReadString('global', 'wapt_server', '');

  eddefault_sources_root.Text :=
    inifile.ReadString('global', 'default_sources_root', 'c:\waptdev');

  edPersonalCertificatePath.Text := inifile.ReadString('global', 'personal_certificate_path', '');
  if edPersonalCertificatePath.text = '' then
    edPersonalCertificatePath.InitialDir:=GetUserDir
  else
    edPersonalCertificatePath.InitialDir:=ExtractFileDir(edPersonalCertificatePath.text);

  EdMaturity.Text := inifile.ReadString('global', 'default_maturity', '');

  EdLicencesDirectory.Directory := inifile.ReadString('global', 'licences_directory', '');

  cbSendStats.Checked :=
    inifile.ReadBool('global', 'send_usage_report', True);

  GridPlugins.Data := GetGridHostsPluginsFromIni;
end;

function TVisWAPTConfig.GetGridHostsPluginsFromIni: ISuperObject;
var
  b64: string;
begin
  // external commands list is stored as base64 encoded json in waptconsole.ini file
  b64 := inifile.readString('global','grid_hosts_plugins', '');
  if b64 <> '' then
     Result := SO(DecodeStringBase64(b64))
  else
     Result := TSuperObject.Create(stArray);
end;

procedure TVisWAPTConfig.edServerAddressChange(Sender: TObject);
begin
  //cbManual.Checked:=False;
  labStatusRepo.Caption := '';
  labStatusServer.Caption := '';
  SetStatus(ImgStatusRepo,0);
  SetStatus(ImgStatusServer,0);

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
  {$ifndef enterprise}
  EdLicencesDirectory.Visible := False;
  LabLicencesDirectory.Visible := False;
  ImgStatusLicences.Visible := False;
  {$endif}
end;

procedure TVisWAPTConfig.FormDestroy(Sender: TObject);
begin
  If Assigned(FIniFile) then
    FreeAndNil(Finifile);
end;

procedure TVisWAPTConfig.FormShow(Sender: TObject);
begin
  ImageList1.GetBitmap(ssUnknown, ImgStatusPackagePrefix.Picture.Bitmap);
  ImageList1.GetBitmap(ssUnknown, ImgStatusPersonalCertificate.Picture.Bitmap);
  ImageList1.GetBitmap(ssUnknown, ImgStatusRepo.Picture.Bitmap);
  ImageList1.GetBitmap(ssUnknown, ImgStatusServer.Picture.Bitmap);
  ImageList1.GetBitmap(ssUnknown, ImgStatusLicences.Picture.Bitmap);

  cbManualClick(cbManual);
  edrepo_urlExit(Sender);
  CBVerifyCert.Checked:=(EdServerCertificate.Text<>'') and (EdServerCertificate.Text<>'0');
  CBVerifyCertClick(Sender);

  if edwapt_server.Text<>'' then
    ActCheckAndSetwaptserver.Execute;

  if edwapt_server.Text='' then
      edwapt_server.SetFocus
  else if (edPersonalCertificatePath.Text='') then
    edPersonalCertificatePath.SetFocus
  else if (edDefaultPackagePrefix.Text='') then
    edDefaultPackagePrefix.Text:='';


end;

procedure TVisWAPTConfig.GridPluginsEditing(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; var Allowed: Boolean);
begin
  Allowed := True
end;

procedure TVisWAPTConfig.HelpButtonClick(Sender: TObject);
begin
  OpenDocument(FIniFilename);
end;

procedure TVisWAPTConfig.OKButtonClick(Sender: TObject);
begin
  ActSaveConfig.Execute;
end;

procedure TVisWAPTConfig.Timer1Timer(Sender: TObject);
begin
  timer1.Enabled:= False;
  ActCheckAndSetwaptserver.Enabled:=True;
  if CheckServer(edServerAddress.Text) then
    edServerAddress.Font.Color :=clText ;
end;

end.

