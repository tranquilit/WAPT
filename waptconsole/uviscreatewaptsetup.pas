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
    ActBuildUpload: TAction;
    ActionList1: TActionList;
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    CBCheckCertificatesValidity: TCheckBox;
    CBDualSign: TCheckBox;
    CBUseFQDNAsUUID: TCheckBox;
    CBForceWaptServerURL: TCheckBox;
    CBVerifyCert: TCheckBox;
    CBUseKerberos: TCheckBox;
    CBForceRepoURL: TCheckBox;
    CBWUADefaultAllow: TCheckBox;
    CBWUAOffline: TCheckBox;
    CBWUAEnabled: TCheckBox;
    CBWUAAllowDirectDownload: TCheckBox;
    edAppendHostProfiles: TEdit;
    EdServerCertificate: TFileNameEdit;
    edWaptServerUrl: TEdit;
    EdWUAInstallDelay: TEdit;
    EdWUADownloadScheduling: TEdit;
    fnWaptDirectory: TDirectoryEdit;
    edRepoUrl: TEdit;
    edOrgName: TEdit;
    fnPublicCert: TFileNameEdit;
    GridCertificates: TSOGrid;
    GBWUA: TGroupBox;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    Label6: TLabel;
    Label7: TLabel;
    Label8: TLabel;
    LabWUAInstallDelay: TLabel;
    LabWUAScanDownloadPeriod: TLabel;
    MenuItem1: TMenuItem;
    Panel1: TPanel;
    Panel2: TPanel;
    PopupMenu1: TPopupMenu;
    procedure ActGetServerCertificateExecute(Sender: TObject);
    procedure CBVerifyCertClick(Sender: TObject);
    procedure CBWUAEnabledClick(Sender: TObject);
    procedure fnPublicCertChange(Sender: TObject);
    procedure fnPublicCertEditingDone(Sender: TObject);
    procedure fnPublicCertExit(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormDestroy(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    FCurrentVisLoading: TVisLoading;
    function GetCurrentVisLoading: TVisLoading;
    { private declarations }
    procedure IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: int64);
  public
    { public declarations }
    ActiveCertBundle: UnicodeString;
    property CurrentVisLoading: TVisLoading read GetCurrentVisLoading;
    function GetWUAParams: ISuperObject;

    Function BuildWaptSetup: String;
    procedure UploadWaptSetup(SetupFilename:String);
    Function BuildWaptUpgrade(SetupFilename: String):String;

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
    if not DirectoryExists(fnWaptDirectory.Caption) then
    begin
      ShowMessageFmt(rsInvalidWaptSetupDir, [fnWaptDirectory.Directory]);
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
      PingResult := SO(IdhttpGetString(edWaptServerUrl.Text+'/ping','',4000,60000,60000,'','','GET','', AbsVerifyCertPath));
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
var
  id: Integer;
  CABundle,CertIter, Cert,CertList: Variant;
  SOCert,SOCerts: ISuperObject;
  att:String;
  NewCertFilename:UnicodeString;
  atts: Array[0..8] of String=('cn','issuer_cn','subject_dn','issuer_dn','fingerprint','not_after','is_ca','is_code_signing','serial_number');

begin
  NewCertFilename:=UTF8Decode(fnPublicCert.FileName);
  if FileExists(NewCertFilename) and ((ActiveCertBundle <> NewCertFilename) or (GridCertificates.Data = Nil) )  then
  try
    edOrgName.text := VarPythonAsString(dmpython.waptcrypto.SSLCertificate(crt_filename := NewCertFilename).cn);
    SOCerts := TSuperObject.Create(stArray);
    CABundle:=dmpython.waptcrypto.SSLCABundle(cert_pattern_or_dir := NewCertFilename);
    CABundle.add_pems(IncludeTrailingPathDelimiter(WaptBaseDir)+'ssl\*.crt');

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
    ActiveCertBundle := UTF8Decode(fnPublicCert.FileName);

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

procedure TVisCreateWaptSetup.CBWUAEnabledClick(Sender: TObject);
begin
  GBWUA.Enabled:=CBWUAEnabled.State = cbChecked;
end;

procedure TVisCreateWaptSetup.fnPublicCertChange(Sender: TObject);
begin
  fnPublicCertEditingDone(Sender);
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
      certchain := dmpython.waptcrypto.get_peer_cert_chain_from_server(url);
      pem_data := dmpython.waptcrypto.get_cert_chain_as_pem(certificates_chain:=certchain);
      if not VarIsNone(pem_data) then
      begin
        cert := certchain.__getitem__(0);
        certfn:= AppendPathDelim(WaptBaseDir)+'ssl\server\'+cert.cn+'.crt';
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

procedure TVisCreateWaptSetup.FormDestroy(Sender: TObject);
begin
  if FCurrentVisLoading <> Nil then
    FreeAndNil(FCurrentVisLoading);
end;

procedure TVisCreateWaptSetup.FormShow(Sender: TObject);
var
  ini: TIniFile;
begin
  try
    ini := TIniFile.Create(AppIniFilename);
    if ini.ReadString('global', 'default_ca_cert_path', '') <> '' then
      ActiveCertBundle := UTF8Decode(ini.ReadString('global', 'default_ca_cert_path', ''))
    else
      ActiveCertBundle := UTF8Decode(ini.ReadString('global', 'personal_certificate_path', ''));

    edWaptServerUrl.Text := ini.ReadString('global', 'wapt_server', '');
    edRepoUrl.Text := ini.ReadString('global', 'repo_url', '');
    EdServerCertificate.Text := ini.ReadString('global', 'verify_cert', '0'); ;
    CBUseKerberos.Checked:=ini.ReadBool('global', 'use_kerberos', False );
    CBCheckCertificatesValidity.Checked:=ini.ReadBool('global', 'check_certificates_validity',True );
    CBDualSign.Checked:= (ini.ReadString('global', 'sign_digests','') = 'sha256,sha1');
    CBUseFQDNAsUUID.Checked:= ini.ReadBool('global', 'use_fqdn_as_uuid',False);
    fnWaptDirectory.Directory := WaptBaseDir()+'\waptupgrade';

    fnPublicCert.FileName := UTF8Encode(ActiveCertBundle);
    if FileExists(ActiveCertBundle) then
      fnPublicCertEditingDone(Sender);
        //edOrgName.text := VarPythonAsString(dmpython.waptcrypto.SSLCertificate(crt_filename := fnPublicCert.FileName).cn);
        //edOrgName.text := dmwaptpython.DMPython.PythonEng.EvalStringAsStr(Format('common.SSLCertificate(r"""%s""").cn',[fnPublicCert.FileName]));

    CBVerifyCert.Checked:=(EdServerCertificate.Text<>'') and (EdServerCertificate.Text<>'0');
    CBVerifyCertClick(Sender);

    if not CBCheckCertificatesValidity.Checked then
      CBCheckCertificatesValidity.Visible := True;

    CBWUAEnabled.Visible:=DMPython.IsEnterpriseEdition;
    GBWUA.Visible:=DMPython.IsEnterpriseEdition;
    if not DMPython.IsEnterpriseEdition then
      CBWUAEnabled.State := cbGrayed
    else
    begin
      if ini.SectionExists('waptwua') then
      begin
        // no key -> don't change anything -> grayed
        if not ini.ValueExists('waptwua','enabled') then
          CBWUAEnabled.State:=cbGrayed
        else
          CBWUAEnabled.Checked:=ini.ReadBool('waptwua','enabled',False);

        if not ini.ValueExists('waptwua','default_allow') then
          CBWUADefaultAllow.State:=cbGrayed
        else
          CBWUADefaultAllow.Checked:=ini.ReadBool('waptwua','default_allow',False);

        if not ini.ValueExists('waptwua','offline') then
          CBWUAOffline.State:=cbGrayed
        else
          CBWUAOffline.Checked:=ini.ReadBool('waptwua','offline',True);

        if not ini.ValueExists('waptwua','allow_direct_download') then
          CBWUAAllowDirectDownload.State:=cbGrayed
        else
          CBWUAAllowDirectDownload.Checked:=ini.ReadBool('waptwua','allow_direct_download',True);

        EdWUAInstallDelay.Text := ini.ReadString('waptwua','install_delay','');
      end
      else
      begin
        CBWUAEnabled.State:=cbGrayed;
        CBWUADefaultAllow.State:=cbGrayed;
        EdWUAInstallDelay.Text := '';
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
  {// Global settings
  if CBWUADefaultAllow.State = cbChecked then
    Result.B['default_allow'] := True
  else if CBWUADefaultAllow.State.State = cbUnChecked then
    Result.B['default_allow'] := False
  else
    Result['default_allow'] := Nil;

  if Trim(EdWUAInstallDelay.Text) <>'' then
    Result.S['install_delay'] := Trim(EdWUAInstallDelay.Text)
  else
    Result['install_delay'] := Nil;

  Result.B['allow_direct_download'] := True;
  Result.B['offline'] := True;
  }


  with CurrentVisLoading do
  try
    Screen.Cursor := crHourGlass;
    ProgressTitle(rsBuildInProgress);
    waptsetupPath := CreateWaptSetup(UTF8Encode(ActiveCertBundle),
      edRepoUrl.Text, edWaptServerUrl.Text,
      fnWaptDirectory.Directory,
      edOrgName.Text, @DoProgress, 'waptagent',
      EdServerCertificate.Text,
      CBUseKerberos.Checked,
      CBCheckCertificatesValidity.Checked,
      DMPython.IsEnterpriseEdition,
      CBForceRepoURL.Checked,
      CBForceWaptServerURL.Checked,
      CBUseFQDNAsUUID.Checked,
      edAppendHostProfiles.Text,
      GetWUAParams()
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
      ProgressTitle(rsProgressTitle);
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
function TVisCreateWaptSetup.BuildWaptUpgrade(SetupFilename: String): String;
var
  BuildDir, SignDigests: String;
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
      BuildDir := GetTempDir(False);

      if RightStr(buildDir,1) = '\' then
        buildDir := copy(buildDir,1,length(buildDir)-1);

      //BuildResult is a PackageEntry instance
      BuildResult := DMPython.waptdevutils.build_waptupgrade_package(
          waptconfigfile := AppIniFilename(),
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
    Result.S['filter'] := 'Type=''Software'' or Type=''Driver''';

    if CBWUAEnabled.State = cbGrayed then
      Result['enabled'] := Nil
    else
      Result.B['enabled'] := CBWUAEnabled.Checked;

    if CBWUADefaultAllow.State = cbGrayed then
      Result['default_allow'] := Nil
    else
      Result.B['default_allow'] := CBWUADefaultAllow.Checked;

    Result.S['filter'] := 'Type=''Software'' or Type=''Driver''';

    if Trim(EdWUADownloadScheduling.Text) <>'' then
      Result.S['download_scheduling'] := Trim(EdWUADownloadScheduling.Text)
    else
      Result['download_scheduling'] := Nil;

    if Trim(EdWUAInstallDelay.Text) <>'' then
      Result.S['install_delay'] := Trim(EdWUAInstallDelay.Text)
    else
      Result['install_delay'] := Nil;

    if CBWUAAllowDirectDownload.State = cbGrayed then
      Result['allow_direct_download'] := Nil
    else
      Result.B['allow_direct_download'] := CBWUAAllowDirectDownload.Checked;

    if CBWUAOffline.State = cbGrayed then
      Result['offline'] := Nil
    else
      Result.B['offline'] := CBWUAOffline.Checked;
  end
  else
    result := Nil;
end;

end.

