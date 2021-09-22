unit uVisCreateWaptSetup;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, LazFileUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  LCLIntf,EditBtn, ExtCtrls, Buttons, ActnList, DefaultTranslator, Menus, sogrid,
  uVisLoading,IdComponent,superobject, VirtualTrees;

type

  { TVisCreateWaptSetup }
  TVisCreateWaptSetup = class(TForm)
    ActGetServerCertificate: TAction;
    ActionList1: TActionList;
    ButOK: TBitBtn;
    ButCancel: TBitBtn;
    CBDualSign: TCheckBox;
    CBInstallWUAUpdatesAtShutdown: TCheckBox;
    CBUseRepoRules: TCheckBox;
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
    CBIncludeNonCA: TCheckBox;
    EdAuditScheduling: TComboBox;
    edAppendHostProfiles: TEdit;
    EdWUADownloadScheduling: TComboBox;
    EdServerCertificate: TFileNameEdit;
    edWaptServerUrl: TEdit;
    EdWUAInstallDelay: TEdit;
    edRepoUrl: TEdit;
    edOrgName: TEdit;
    edPublicCertDir: TDirectoryEdit;
    GBWUA: TGroupBox;
    GridCertificates: TSOGrid;
    LabAuthCertsBundle: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label5: TLabel;
    Label6: TLabel;
    LabAuthor: TLabel;
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
    procedure CBIncludeNonCAClick(Sender: TObject);
    procedure CBUseFQDNAsUUIDChange(Sender: TObject);
    procedure CBUseRandomUUIDChange(Sender: TObject);
    procedure CBVerifyCertClick(Sender: TObject);
    procedure CBWUADisableClick(Sender: TObject);
    procedure CBWUADontchangeClick(Sender: TObject);
    procedure CBWUAEnabledClick(Sender: TObject);
    procedure edPublicCertDirAcceptDirectory(Sender: TObject; var Value: String
      );
    procedure edPublicCertDirEditingDone(Sender: TObject);
    procedure edPublicCertDirExit(Sender: TObject);
    procedure EdServerCertificateDblClick(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormDropFiles(Sender: TObject; const FileNames: array of String);
    procedure FormShow(Sender: TObject);
    procedure GridCertificatesDblClick(Sender: TObject);
    procedure GridCertificatesNodesDelete(Sender: TSOGrid; Rows: ISuperObject);
  private
    FCurrentVisLoading: TVisLoading;
    function GetCurrentVisLoading: TVisLoading;
    { private declarations }
    procedure IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: int64);
    procedure LoadTrustedCertificates(TrustedDirectory: String='';IncludeNonCA:Boolean=False);
  public
    { public declarations }
    BuildDir: String;
    property CurrentVisLoading: TVisLoading read GetCurrentVisLoading;
    function GetWUAParams: ISuperObject;
    procedure SaveWAPTAgentSettings;

    Function BuildWaptSetup: String;
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
  AbsVerifyCertPath,
  ServerSSLPath  :String;
begin
  CanClose:= True;
  if (ModalResult=mrOk) then
  begin
    ServerSSLPath := MakePath([BuildDir,'ssl','server']);
    if not DirectoryExistsUTF8(ServerSSLPath) then
      mkdir(ServerSSLPath);

    // check ssl cert is OK
    if (CBVerifyCert.Checked) then
    try
      if not StrIsOneOf(EdServerCertificate.Text,['0','1']) then
      begin
        EdServerCertificate.Text := ExpandFileName(EdServerCertificate.Text);

        // if server bundle is not in buildir, copy it
        if pos(lowercase(ServerSSLPath),lowercase(EdServerCertificate.Text)) <= 0 then
        begin
          AbsVerifyCertPath := MakePath([ServerSSLPath,ExtractFileName(EdServerCertificate.Text)]);
          CopyFile(EdServerCertificate.Text,AbsVerifyCertPath,[cffOverwriteFile],True);
        end
        else
          AbsVerifyCertPath := EdServerCertificate.Text;
      end
      else
        AbsVerifyCertPath := EdServerCertificate.Text;

      PingResult := SO(IdhttpGetString(edWaptServerUrl.Text+'/ping','',4000,60000,60000,'','','GET','',AbsVerifyCertPath,
        'application/json',Nil,WaptClientCertFilename,WaptClientKeyFilename));

      EdServerCertificate.Text := AbsVerifyCertPath;
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

function Dir(Directory,Pattern:String):TStringArray;
var
  Files:TStringList;
  i:Integer;
begin
  Files := FindAllFiles(Directory,Pattern,False);
  try
    SetLength(Result,Files.Count);
    for i:= 0 to Files.Count-1 do
      Result[i] := Files[i];
  finally
    FreeAndNil(Files);
  end;
end;

procedure TVisCreateWaptSetup.LoadTrustedCertificates(TrustedDirectory:String;IncludeNonCA:Boolean=False);
var
  id: Integer;
  NewCertDir,CABundle,CertIter,Cert,CertList: Variant;
  SOCert,SOCerts: ISuperObject;
  FN,SSLDir: String;
  att:String;
  atts: Array[0..9] of String=('cn','issuer_cn','subject_dn','issuer_dn','fingerprint',
      'not_after','is_ca','is_code_signing','serial_number','_public_cert_filename');

begin
  // temporary build ssldir where to copy trusted certs
  SSLDir := MakePath([BuildDir,'ssl']);
  if not DirectoryExistsUTF8(SSLDir) then
    ForceDirectoriesUTF8(SSLDir);

  // replace certs in target ssl builddir
  if (TrustedDirectory<>'') and (SSLDir <> TrustedDirectory) then
  begin
    for FN in Dir(SSLDir,'*.crt') do
      DeleteFileUTF8(MakePath([SSLDir,ExtractFileName(FN)]));

    for FN in Dir(TrustedDirectory,'*.crt') do
        CopyFile(FN,MakePath([SSLDir,ExtractFileName(FN)]),[cffOverWriteFile]);
  end;

  // load cert details in grid
  NewCertDir := UTF8Decode(SSLDir);
  try
    SOCerts := TSuperObject.Create(stArray);
    CABundle:=dmpython.waptcrypto.SSLCABundle('--noarg--');
    CABundle.add_pems(cert_pattern_or_dir := NewCertDir,trust_first := True);

    CertList := CABundle.trusted.values('--noarg--');
    CertIter := iter(CertList);
    id := 0;
    While VarIsPythonIterator(CertIter)  do
      try
        Cert := CertIter.next('--noarg--');
        If VarIsTrue(Cert.is_valid('--noarg--')) and (IncludeNonCA or VarIsTrue(Cert.is_ca)) then
        begin
          SOCert := TSuperObject.Create(stObject) ; // PyVarToSuperObject(Cert.as_dict('--noarg--'));
          SOCert.I['id'] := id;
          inc(id);
          for att in atts do
            SOCert[att] := PyVarToSuperObject(Cert.__getattribute__(att));
          SOCert.S['x509_pem'] := VarPythonAsString(Cert.as_pem('--noarg--'));
          SOCerts.AsArray.Add(SOCert);
        end
        else if FileExistsUTF8(VarPythonAsString(Cert._public_cert_filename)) then
          DeleteFileUTF8(VarPythonAsString(Cert._public_cert_filename));
      except
        on EPyStopIteration do Break;
      end;
    GridCertificates.Data := SOCerts;
  finally
  end;
end;

procedure TVisCreateWaptSetup.edPublicCertDirEditingDone(Sender: TObject);
begin
  LoadTrustedCertificates(edPublicCertDir.Directory,CBIncludeNonCA.Checked);
end;

procedure TVisCreateWaptSetup.edPublicCertDirExit(Sender: TObject);
begin
  LoadTrustedCertificates(edPublicCertDir.Directory,CBIncludeNonCA.Checked);
end;

procedure TVisCreateWaptSetup.EdServerCertificateDblClick(Sender: TObject);
begin
  OpenDocument(EdServerCertificate.FileName);
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

procedure TVisCreateWaptSetup.edPublicCertDirAcceptDirectory(Sender: TObject;
  var Value: String);
begin
  LoadTrustedCertificates(Value,CBIncludeNonCA.Checked);
end;

procedure TVisCreateWaptSetup.ActGetServerCertificateExecute(Sender: TObject);
var
  certfn,CN: String;
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
        CN := StrReplace(cert.cn,'*.','',[rfReplaceAll]);
        certfn:= AppendPathDelim(BuildDir)+'ssl\server\'+CN+'.crt';
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

procedure TVisCreateWaptSetup.CBIncludeNonCAClick(Sender: TObject);
begin
  LoadTrustedCertificates(edPublicCertDir.Directory,CBIncludeNonCA.Checked);
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

procedure TVisCreateWaptSetup.FormDropFiles(Sender: TObject;
  const FileNames: array of String);
var
  fn: String;
begin
  for fn in Filenames do
    CopyFile(fn,MakePath([BuildDir,'ssl',ExtractFileName(fn)]));
  LoadTrustedCertificates('',CBIncludeNonCA.Checked);
end;

procedure TVisCreateWaptSetup.FormShow(Sender: TObject);
var
  ini: TIniFile;
  WaptSSL,DefaultCA,PersonalCertificate:String;
begin
  try
    ini := TIniFile.Create(AppIniFilename);
    DefaultCA := ini.ReadString('global', 'default_ca_cert_path', '');
    PersonalCertificate := ini.ReadString('global', 'personal_certificate_path', '');
    WaptSSL := IncludeTrailingPathDelimiter(WaptBaseDir)+'ssl';
    if (DefaultCA <> '') then
    begin
      if FileExistsUTF8(DefaultCA) then
        edPublicCertDir.Directory := ExtractFileDir(DefaultCA)
      else if DirectoryExistsUTF8(DefaultCA) then
          edPublicCertDir.Directory := DefaultCA
    end
    else 
      edPublicCertDir.Directory := WaptSSL;
 
    if DirectoryExistsUTF8(edPublicCertDir.Directory) then
      edPublicCertDirEditingDone(Sender);

    // we get user private certificate
    if (GridCertificates.Data = Nil) or (GridCertificates.Data.AsArray.Length<=0) then
    begin
      edPublicCertDir.Directory := ExtractFileDir(WaptPersonalCertificatePath);
      edPublicCertDirEditingDone(Sender);
    end;

    edWaptServerUrl.Text := ini.ReadString('global', 'wapt_server', '');
    edRepoUrl.Text := ini.ReadString('global', 'repo_url', '');
    EdServerCertificate.Text := ini.ReadString('global', 'verify_cert', '0'); ;
    CBUseKerberos.Checked:=ini.ReadBool('global', 'use_kerberos', False );
    CBDualSign.Checked:= (ini.ReadString('global', 'sign_digests','') = 'sha256,sha1');
    CBUseFQDNAsUUID.Checked:= ini.ReadBool('global', 'use_fqdn_as_uuid',False);
    CBUseADGroups.Checked:= ini.ReadBool('global', 'use_ad_groups',False);

    CBVerifyCert.Checked:=(EdServerCertificate.Text<>'') and (EdServerCertificate.Text<>'0');
    CBVerifyCertClick(Sender);

    if not DMPython.IsEnterpriseEdition then
    begin
      CBUseRepoRules.Visible:=False;
      CBUseRepoRules.Checked:=False;
    end
    else
      CBUseRepoRules.Checked:= ini.ReadBool('global', 'use_repo_rules',False);

    CBWUADisable.Checked := False;
    CBWUAEnabled.Checked := False;
    CBWUADontchange.Checked := True;

    if DMPython.IsEnterpriseEdition then
    begin
      if ini.ValueExists('global','waptaudit_task_period') then
        EdAuditScheduling.Text:= ini.ReadString('global','waptaudit_task_period','');

      if ini.SectionExists('waptwua') then
      begin
        // no key -> don't change anything -> grayed
        CBWUADontchange.Checked := not ini.ValueExists('waptwua','enabled');
        if not CBWUADontchange.Checked then
          if ini.ReadBool('waptwua','enabled',False) then
            CBWUAEnabled.Checked := True
          else
            CBWUADisable.Checked := True;

        if not ini.ValueExists('waptwua','default_allow') then
          CBWUADefaultAllow.State:=cbUnchecked
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
        CBWUADefaultAllow.State:=cbUnchecked;
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

procedure TVisCreateWaptSetup.GridCertificatesDblClick(Sender: TObject);
begin
  if GridCertificates.FocusedRow <> Nil then
    OpenDocument(UTF8Encode(GridCertificates.FocusedRow.S['_public_cert_filename']));
end;

procedure TVisCreateWaptSetup.GridCertificatesNodesDelete(Sender: TSOGrid;
  Rows: ISuperObject);
var
  cert: ISuperObject;
begin
  for cert in Rows do
    DeleteFileUTF8(UTF8Encode(cert.S['_public_cert_filename']));
  edPublicCertDir.Directory:='';
  LoadTrustedCertificates('',CBIncludeNonCA.Checked);
end;

procedure TVisCreateWaptSetup.SaveWAPTAgentSettings;
var
  ini: TIniFile;
begin
  try
    ini := TIniFile.Create(AppIniFilename);
    ini.WriteString('global', 'default_ca_cert_path',edPublicCertDir.Directory );

    ini.WriteBool('global', 'use_kerberos', CBUseKerberos.Checked);
    ini.WriteBool('global', 'use_fqdn_as_uuid',CBUseFQDNAsUUID.Checked);
    ini.WriteBool('global', 'use_ad_groups',CBUseADGroups.Checked);
    if CBUseRepoRules.Visible then
      ini.WriteBool('global', 'use_repo_rules',CBUseRepoRules.Checked)
    else
      ini.DeleteKey('global', 'use_repo_rules');


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


function TVisCreateWaptSetup.BuildWaptSetup: String;
var
  WAPTSetupPath: string;
begin
  if BuildDir='' then
    BuildDir := GetTempFileNameUTF8('','wapt'+FormatDateTime('yyyymmdd"T"hhnnss',Now));
  SaveWAPTAgentSettings;

  // Copy selected trusted package certificates


  with CurrentVisLoading do
  try
    Screen.Cursor := crHourGlass;
    ProgressTitle(rsBuildInProgress);
    waptsetupPath := CreateWaptSetup(MakePath([BuildDir,'ssl']),
      edRepoUrl.Text, edWaptServerUrl.Text,
      BuildDir,
      edOrgName.Text, @DoProgress, 'waptagent',
      EdServerCertificate.Text,
      CBUseKerberos.Checked,
      FileExists(MakePath([WaptBaseDir,'waptenterprise','licencing.py'])),
      CBForceRepoURL.Checked,
      CBForceWaptServerURL.Checked,
      CBUseFQDNAsUUID.Checked,
      CBUseRandomUUID.Checked,
      CBUseADGroups.Checked,
      CBUseRepoRules.Checked,
      edAppendHostProfiles.Text,
      GetWUAParams(),
      EdAuditScheduling.Text,
      dmpython.privateKeyPassword
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
  BuildResult,VWaptServerPassword,WAPT,Mainrepo: Variant;
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

      VWaptServerPassword := PyUTF8Decode(WaptServerPassword);

      //AppIniFilename(),
      WAPT := DMPython.WAPT;
      MainRepo := DMPython.MainWaptRepo;
      //BuildResult is a PackageEntry instance
      BuildResult := DMPython.waptdevutils.build_waptupgrade_package(
          wapt := WAPT,
          mainrepo := MainRepo,
          sources_directory := WaptUpgradeSources,
          wapt_server_user := WaptServerUser,
          wapt_server_passwd := VWaptServerPassword,
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

