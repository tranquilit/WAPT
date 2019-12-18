unit uVisCreateWaptSetup;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, LazFileUtils, Forms, Controls, Graphics, Dialogs, StdCtrls,
  EditBtn, ExtCtrls, Buttons, ActnList, DefaultTranslator, Menus, sogrid,
  uVisLoading,IdComponent,superobject;

type

  { TVisCreateWaptSetup }
  TVisCreateWaptSetup = class(TForm)
    ActGetServerCertificate: TAction;
    ActionList1: TActionList;
    ButOK: TBitBtn;
    ButCancel: TBitBtn;
    CBCheckCertificatesValidity: TCheckBox;
    CBDualSign: TCheckBox;
    CBInstallWUAUpdatesAtShutdown: TCheckBox;
    CBUseFQDNAsUUID: TCheckBox;
    CBForceWaptServerURL: TCheckBox;
    CBUseRandomUUID: TCheckBox;
    CBVerifyCert: TCheckBox;
    CBUseKerberos: TCheckBox;
    CBForceRepoURL: TCheckBox;
    CBWUADefaultAllow: TCheckBox;
    CBWUADisable: TRadioButton;
    CBWUADontchange: TRadioButton;
    CBUseADGroups: TCheckBox;
    EdAuditScheduling: TComboBox;
    edAppendHostProfiles: TEdit;
    EdWUADownloadScheduling: TComboBox;
    EdServerCertificate: TFileNameEdit;
    edWaptServerUrl: TEdit;
    EdWUAInstallDelay: TEdit;
    edRepoUrl: TEdit;
    edOrgName: TEdit;
    fnPublicCert: TFileNameEdit;
    GBWUA: TGroupBox;
    GridCertificates: TSOGrid;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label5: TLabel;
    Label6: TLabel;
    Label7: TLabel;
    Label8: TLabel;
    Label9: TLabel;
    LabWUAInstallDelay: TLabel;
    LabWUAScanDownloadPeriod: TLabel;
    MenuItem1: TMenuItem;
    PanBottom: TPanel;
    PanClient: TPanel;
    PanAgentEnterprise: TPanel;
    PopupMenu1: TPopupMenu;
    CBWUAEnabled: TRadioButton;
    procedure ActGetServerCertificateExecute(Sender: TObject);
    procedure CBUseFQDNAsUUIDChange(Sender: TObject);
    procedure CBUseRandomUUIDChange(Sender: TObject);
    procedure CBVerifyCertClick(Sender: TObject);
    procedure CBWUADisableClick(Sender: TObject);
    procedure CBWUADontchangeClick(Sender: TObject);
    procedure CBWUAEnabledClick(Sender: TObject);
    procedure fnPublicCertEditingDone(Sender: TObject);
    procedure fnPublicCertExit(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    FCurrentVisLoading: TVisLoading;
    function GetCurrentVisLoading: TVisLoading;
    { private declarations }
    procedure IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: int64);
  public
    { public declarations }
    ActiveCertBundle: String;
    property CurrentVisLoading: TVisLoading read GetCurrentVisLoading;
    function GetWUAParams: ISuperObject;
    procedure SaveWAPTAgentSettings;

    Function BuildWaptSetup(BuildDir: String): String;
    procedure UploadWaptSetup(SetupFilename:String);
    Function BuildWaptUpgrade(WaptUpgradeSources: String):String;

  end;

var
  VisCreateWaptSetup: TVisCreateWaptSetup;

implementation

{$R *.lfm}

uses
  Variants,dmwaptpython,IdUri,IdSSLOpenSSLHeaders,uWaptConsoleRes,uWaptRes,
  tiscommon,tisstrings,waptcommon,VarPyth,inifiles,tisinifiles,
  PythonEngine, uWaptPythonUtils;

{ TVisCreateWaptSetup }
procedure TVisCreateWaptSetup.FormCloseQuery(Sender: TObject; var CanClose: boolean);
var
  pingResult: ISuperobject;
  AbsVerifyCertPath:String;
begin
  CanClose:= True;
  if (ModalResult=mrOk) then
  begin
    if ActiveCertBundle = '' then
    begin
      showMessage(rsInputPubKeyPath);
      CanClose:=False;
    end;
    if pos(lowercase(WaptBaseDir),lowercase(EdServerCertificate.Text))=1 then
    begin
      EdServerCertificate.Text := ExtractRelativepath(WaptBaseDir,EdServerCertificate.Text);
      AbsVerifyCertPath := ExpandFileName(AppendPathDelim(WaptBaseDir)+EdServerCertificate.Text);
    end
    else
      AbsVerifyCertPath := ExpandFileName(EdServerCertificate.Text);

    if (CBVerifyCert.Checked) and (pos(lowercase(WaptBaseDir),lowercase(AbsVerifyCertPath))<>1) then
    begin
      ShowMessageFmt(rsInvalidServerCertificateDir, [EdServerCertificate.Text]);
      CanClose:=False;
    end;
    // check ssl cert is OK
    if (CBVerifyCert.Checked) then
    try
      PingResult := SO(IdhttpGetString(edWaptServerUrl.Text+'/ping','',4000,60000,60000,'','','GET','',AbsVerifyCertPath,
        'application/json',Nil,WaptClientCertFilename,WaptClientKeyFilename));
    except
      on E:EIdOpenSSLAPICryptoError do
      begin
        ShowMessageFmt(rsInvalidServerCertificate, [EdServerCertificate.Text]);
        CanClose:=False;
      end;
    end;
  end;
end;

procedure TVisCreateWaptSetup.FormCreate(Sender: TObject);
begin
  PanAgentEnterprise.Visible := DMPython.IsEnterpriseEdition;
end;

procedure TVisCreateWaptSetup.fnPublicCertEditingDone(Sender: TObject);
var
  id: Integer;
  CABundle,CertIter,Cert,CertList: Variant;
  SOCert,SOCerts: ISuperObject;
  att:String;
  NewCertFilename:String;
  atts: Array[0..8] of String=('cn','issuer_cn','subject_dn','issuer_dn','fingerprint','not_after','is_ca','is_code_signing','serial_number');

begin
  NewCertFilename:=fnPublicCert.FileName;
  //if FileExistsUTF8(NewCertFilename) and ((ActiveCertBundle <> NewCertFilename) or (GridCertificates.Data = Nil) )  then
  try
    SOCerts := TSuperObject.Create(stArray);
    CABundle:=dmpython.waptcrypto.SSLCABundle('--noarg--');
    CABundle.add_pems(IncludeTrailingPathDelimiter(WaptBaseDir)+'ssl\*.crt');
    if FileExistsUTF8(NewCertFilename) then
    begin
      CABundle.add_pems(NewCertFilename);
      edOrgName.text := VarPythonAsString(dmpython.waptcrypto.SSLCertificate(crt_filename := NewCertFilename).cn);
    end;

    CertList := CABundle.certificates('--noarg--');
    CertIter := iter(CertList);
    id := 0;
    While VarIsPythonIterator(CertIter)  do
      try
        Cert := CertIter.next('--noarg--');
        SOCert := TSuperObject.Create(stObject) ; // PyVarToSuperObject(Cert.as_dict('--noarg--'));
        SOCert.I['id'] := id;
        inc(id);
        for att in atts do
          SOCert[att] := PyVarToSuperObject(Cert.__getattribute__(att));
        SOCert.S['x509_pem'] := VarPythonAsString(Cert.as_pem('--noarg--'));
        SOCerts.AsArray.Add(SOCert);
      except
        on EPyStopIteration do Break;
      end;
    GridCertificates.Data := SOCerts;
    ActiveCertBundle := fnPublicCert.FileName;
  finally
  end;
end;

procedure TVisCreateWaptSetup.fnPublicCertExit(Sender: TObject);
begin
  fnPublicCertEditingDone(Sender);
end;

procedure TVisCreateWaptSetup.CBVerifyCertClick(Sender: TObject);
begin
  If not CBVerifyCert.Checked then
    EdServerCertificate.Text:='0'
  else
    if (EdServerCertificate.Text='') or (EdServerCertificate.Text='0') then
    begin
      EdServerCertificate.Text := IniReadString(WaptIniFilename,'global','verify_cert','0');
      if (LowerCase(EdServerCertificate.Text) = '0') or (LowerCase(EdServerCertificate.Text) = 'false') then
        EdServerCertificate.Text:=CARoot();
    end;
  EdServerCertificate.Enabled:=CBVerifyCert.Checked;
end;

procedure TVisCreateWaptSetup.CBWUADisableClick(Sender: TObject);
begin
  if CBWUADisable.Checked then
  begin
    GBWUA.Enabled := False;
    CBWUAEnabled.Checked:=False;
    CBWUADontchange.Checked:=False;
  end
end;

procedure TVisCreateWaptSetup.CBWUADontchangeClick(Sender: TObject);
begin
  if CBWUADontchange.Checked then
  begin
    GBWUA.Enabled := False;
    CBWUAEnabled.Checked:=False;
    CBWUADisable.Checked:=False;
  end
end;

procedure TVisCreateWaptSetup.CBWUAEnabledClick(Sender: TObject);
begin
  if CBWUAEnabled.Checked then
  begin
    GBWUA.Enabled := True;
    CBWUADisable.Checked:=False;
    CBWUADontchange.Checked:=False;
  end
  else
    GBWUA.Enabled := False;
end;

procedure TVisCreateWaptSetup.ActGetServerCertificateExecute(Sender: TObject);
var
  certfn: String;
  url,certchain,pem_data,cert:Variant;
begin
  url := edWaptServerUrl.Text;
  With TIdURI.Create(url) do
  try
    try
      certchain := dmpython.waptcrypto.get_peer_cert_chain_from_server(url);
      pem_data := dmpython.waptcrypto.get_cert_chain_as_pem(certificates_chain:=certchain);
      if not VarIsNull(pem_data) then
      begin
        cert := certchain.__getitem__(0);
        certfn:= AppendPathDelim(WaptBaseDir)+'ssl\server\'+cert.cn+'.crt';
        if not DirectoryExists(ExtractFileDir(certfn)) then
          ForceDirectory(ExtractFileDir(certfn));
        StringToFile(certfn,UTF8Encode(VarPythonAsString(pem_data)));
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

procedure TVisCreateWaptSetup.CBUseFQDNAsUUIDChange(Sender: TObject);
begin
  If CBUseFQDNAsUUID.Checked and CBUseRandomUUID.Checked then
    CBUseRandomUUID.Checked := False;

end;

procedure TVisCreateWaptSetup.CBUseRandomUUIDChange(Sender: TObject);
begin
  If CBUseFQDNAsUUID.Checked and CBUseRandomUUID.Checked then
    CBUseFQDNAsUUID.Checked := False;

end;

procedure TVisCreateWaptSetup.FormDestroy(Sender: TObject);
begin
  if FCurrentVisLoading <> Nil then
    FreeAndNil(FCurrentVisLoading);
end;

procedure TVisCreateWaptSetup.FormShow(Sender: TObject);
var
  ini: TIniFile;
  DefaultCA,PersonalCertificate:String;
begin
  try
    ini := TIniFile.Create(AppIniFilename);
    DefaultCA := ini.ReadString('global', 'default_ca_cert_path', '');
    PersonalCertificate := ini.ReadString('global', 'personal_certificate_path', '');
    if (DefaultCA <> '') and FileExistsUTF8(DefaultCA) then
      ActiveCertBundle := DefaultCA
    else if (PersonalCertificate <> '') and FileExistsUTF8(PersonalCertificate) then
      ActiveCertBundle := PersonalCertificate
    else
      ActiveCertBundle := '';

    edWaptServerUrl.Text := ini.ReadString('global', 'wapt_server', '');
    edRepoUrl.Text := ini.ReadString('global', 'repo_url', '');
    EdServerCertificate.Text := ini.ReadString('global', 'verify_cert', '0'); ;
    CBUseKerberos.Checked:=ini.ReadBool('global', 'use_kerberos', False );
    CBCheckCertificatesValidity.Checked:=ini.ReadBool('global', 'check_certificates_validity',True );
    CBDualSign.Checked:= (ini.ReadString('global', 'sign_digests','') = 'sha256,sha1');
    CBUseFQDNAsUUID.Checked:= ini.ReadBool('global', 'use_fqdn_as_uuid',False);
    CBUseADGroups.Checked:= ini.ReadBool('global', 'use_ad_groups',False);

    fnPublicCert.FileName := UTF8Encode(ActiveCertBundle);
    if FileExistsUtf8(ActiveCertBundle) then
      fnPublicCertEditingDone(Sender);
        //edOrgName.text := VarPythonAsString(dmpython.waptcrypto.SSLCertificate(fnPublicCert.FileName).cn);
        //edOrgName.text := dmwaptpython.DMPython.PythonEng.EvalStringAsStr(Format('common.SSLCertificate(r"""%s""").cn',[fnPublicCert.FileName]));

    CBVerifyCert.Checked:=(EdServerCertificate.Text<>'') and (EdServerCertificate.Text<>'0');
    CBVerifyCertClick(Sender);

    if not CBCheckCertificatesValidity.Checked then
      CBCheckCertificatesValidity.Visible := True;

    if not DMPython.IsEnterpriseEdition then
      CBWUADontchange.Checked := True
    else
    begin
      if ini.ValueExists('global','waptaudit_task_period') then
        EdAuditScheduling.Text:= ini.ReadString('global','waptaudit_task_period','');

      if ini.SectionExists('waptwua') then
      begin
        // no key -> don't change anything -> grayed
        if not ini.ValueExists('waptwua','enabled') then
          CBWUADontchange.Checked:=True
        else
          CBWUAEnabled.Checked:=ini.ReadBool('waptwua','enabled',False);

        if not ini.ValueExists('waptwua','default_allow') then
          CBWUADefaultAllow.State:=cbGrayed
        else
          CBWUADefaultAllow.Checked:=ini.ReadBool('waptwua','default_allow',False);

        {if not ini.ValueExists('waptwua','offline') then
          CBWUAOffline.State:=cbGrayed
        else
          CBWUAOffline.Checked:=ini.ReadBool('waptwua','offline',True);

        if not ini.ValueExists('waptwua','allow_direct_download') then
          CBWUAAllowDirectDownload.State:=cbGrayed
        else
          CBWUAAllowDirectDownload.Checked:=ini.ReadBool('waptwua','allow_direct_download',True);
        }

        EdWUAInstallDelay.Text := ini.ReadString('waptwua','install_delay','');
        EdWUADownloadScheduling.Text := ini.ReadString('waptwua','download_scheduling','');

        CBInstallWUAUpdatesAtShutdown.Checked := ini.ReadBool('waptwua','install_at_shutdown',False);


      end
      else
      begin
        CBWUAEnabled.State:=cbGrayed;
        CBWUADefaultAllow.State:=cbGrayed;
        EdWUAInstallDelay.Text := '';
      end;
    end;
  finally
    MakeFullyVisible;
    ini.Free;
  end;
  if Screen.PixelsPerInch<>96 then
    GridCertificates.Header.Height:=trunc((GridCertificates.Header.MinHeight*Screen.PixelsPerInch)/96);
end;


procedure TVisCreateWaptSetup.SaveWAPTAgentSettings;
var
  ini: TIniFile;
begin
  try
    ini := TIniFile.Create(AppIniFilename);
    ini.WriteString('global', 'default_ca_cert_path',ActiveCertBundle );

    ini.WriteBool('global', 'use_kerberos', CBUseKerberos.Checked);
    ini.WriteBool('global', 'use_fqdn_as_uuid',CBUseFQDNAsUUID.Checked);
    ini.WriteBool('global', 'use_ad_groups',CBUseADGroups.Checked);

    if DMPython.IsEnterpriseEdition then
    begin
      ini.WriteString('global','waptaudit_task_period',EdAuditScheduling.Text);
      if (CBWUAEnabled.State in [cbChecked,cbGrayed]) then
      begin
        // no key -> don't change anything -> grayed
        if CBWUAEnabled.State <> cbGrayed then
          ini.WriteBool('waptwua','enabled',CBWUAEnabled.Checked);

        if CBWUADefaultAllow.State <> cbGrayed then
          ini.WriteBool('waptwua','default_allow',CBWUADefaultAllow.Checked);

        {if CBWUAOffline.State <> cbGrayed then
          ini.WriteBool('waptwua','offline',CBWUAOffline.Checked);

        if CBWUAAllowDirectDownload.State <> cbGrayed then
          ini.WriteBool('waptwua','allow_direct_download',CBWUAAllowDirectDownload.Checked);
        }
        ini.WriteString('waptwua','install_delay',EdWUAInstallDelay.Text);
        ini.WriteString('waptwua','download_scheduling',EdWUADownloadScheduling.Text);
        ini.WriteBool('waptwua','install_at_shutdown',CBInstallWUAUpdatesAtShutdown.Checked);
      end;
    end;

  finally
    ini.Free;
  end;
end;


function TVisCreateWaptSetup.GetCurrentVisLoading: TVisLoading;
begin
  if FCurrentVisLoading=Nil then
    FCurrentVisLoading:=TVisLoading.Create(Nil);
  Result := FCurrentVisLoading;
end;


function TVisCreateWaptSetup.BuildWaptSetup(BuildDir:String): String;
var
  WAPTSetupPath: string;
begin
  SaveWAPTAgentSettings;
  with CurrentVisLoading do
  try
    Screen.Cursor := crHourGlass;
    ProgressTitle(rsBuildInProgress);
    waptsetupPath := CreateWaptSetup(UTF8Encode(ActiveCertBundle),
      edRepoUrl.Text, edWaptServerUrl.Text,
      BuildDir,
      edOrgName.Text, @DoProgress, 'waptagent',
      EdServerCertificate.Text,
      CBUseKerberos.Checked,
      CBCheckCertificatesValidity.Checked,
      DMPython.IsEnterpriseEdition,
      CBForceRepoURL.Checked,
      CBForceWaptServerURL.Checked,
      CBUseFQDNAsUUID.Checked,
      CBUseRandomUUID.Checked,
      CBUseADGroups.Checked,
      edAppendHostProfiles.Text,
      GetWUAParams(),
      EdAuditScheduling.Text
      );
    Result := WAPTSetupPath;
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TVisCreateWaptSetup.UploadWaptSetup(SetupFilename: String);
var
  SORes: ISuperObject;
begin
  if FileExistsUTF8(SetupFilename) then
    With CurrentVisLoading do
    try
      Screen.Cursor := crHourGlass;
      ProgressTitle(rsUploadInProgressTitle);
      SORes := WAPTServerJsonMultipartFilePost(
        GetWaptServerURL, 'upload_waptsetup', [], 'file', SetupFilename,
        WaptServerUser, WaptServerPassword, @IdHTTPWork,GetWaptServerCertificateFilename);
      Finish;
      if SORes.S['status'] = 'OK' then
        ShowMessage(format(rsWaptSetupUploadSuccess, []))
      else
        ShowMessage(format(rsWaptUploadError, [SORes.S['message']]));
    finally
      Screen.Cursor := crDefault;
    end
  else
    raise Exception.CreateFmt(rsWaptSetupfileNotFound,[SetupFilename]);
end;

// Return base filename of built package. Empty string if no package built.
function TVisCreateWaptSetup.BuildWaptUpgrade(WaptUpgradeSources: String): String;
var
  SignDigests: String;
  BuildResult: Variant;
begin
  // create waptupgrade package (after waptagent as we need the updated waptagent.sha1 file)
  with CurrentVisLoading do
  begin
    ProgressTitle(rsBuildInProgress);
    try
      if CBDualSign.Checked then
        SignDigests := 'sha256,sha1'
      else
        SignDigests := 'sha256';

      BuildResult := Nil;


      //BuildResult is a PackageEntry instance
      BuildResult := DMPython.waptdevutils.build_waptupgrade_package(
          waptconfigfile := AppIniFilename(),
          sources_directory := WaptUpgradeSources,
          wapt_server_user := WaptServerUser,
          wapt_server_passwd := WaptServerPassword,
          key_password := dmpython.privateKeyPassword,
          sign_digests := SignDigests
          );

      if not VarPyth.VarIsNone(BuildResult) and FileExistsUTF8(VarPythonAsString(BuildResult.get('localpath'))) then
      begin
        Result := BuildResult.get('filename');
        ProgressTitle(rsCleanupTemporaryFiles);
        DeleteFileUTF8(VarPythonAsString(BuildResult.get('localpath')));
        ProgressTitle(rsWaptUpgradePackageBuilt);
      end
      else
        Result := '';
    except
      On E:Exception do
        Raise Exception.Create(rsWaptUpgradePackageBuildError+#13#10+E.Message);
    end;
    Finish;
  end;
end;

procedure TVisCreateWaptSetup.IdHTTPWork(ASender: TObject;
  AWorkMode: TWorkMode; AWorkCount: int64);
begin
  if CurrentVisLoading <> nil then
    CurrentVisLoading.DoProgress(ASender)
end;

function TVisCreateWaptSetup.GetWUAParams: ISuperObject;
begin
  if GBWUA.Visible then
  begin
    Result := TSuperObject.Create(stObject);
    //Result.S['filter'] := 'Type=''Software'' or Type=''Driver''';

    if CBWUAEnabled.Checked then
      Result.B['enabled'] := True
    else if CBWUADisable.Checked then
        Result.B['enabled'] := False
    else if CBWUADontchange.Checked then
      Result['enabled'] := Nil;

    if CBWUADefaultAllow.State = cbGrayed then
      Result['default_allow'] := Nil
    else
      Result.B['default_allow'] := CBWUADefaultAllow.Checked;

    if Trim(EdWUADownloadScheduling.Text) <>'' then
      Result.S['download_scheduling'] := Trim(EdWUADownloadScheduling.Text)
    else
      Result['download_scheduling'] := Nil;

    if Trim(EdWUAInstallDelay.Text) <>'' then
      Result.S['install_delay'] := Trim(EdWUAInstallDelay.Text)
    else
      Result['install_delay'] := Nil;

    {if CBWUAAllowDirectDownload.State = cbGrayed then
      Result['allow_direct_download'] := Nil
    else
      Result.B['allow_direct_download'] := CBWUAAllowDirectDownload.Checked;

    if CBWUAOffline.State = cbGrayed then
      Result['offline'] := Nil
    else
      Result.B['offline'] := CBWUAOffline.Checked;
    }

    if CBInstallWUAUpdatesAtShutdown.State = cbGrayed then
      Result['install_at_shutdown'] := Nil
    else
      Result.B['install_at_shutdown'] := CBInstallWUAUpdatesAtShutdown.Checked;

  end
  else
    result := Nil;
end;

end.

