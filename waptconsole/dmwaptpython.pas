unit dmwaptpython;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, LazFileUtils, LazUTF8, PythonEngine, PythonGUIInputOutput, WrapDelphi,
  VarPyth, vte_json, superobject, fpjson, jsonparser, DefaultTranslator,LCLTranslator,
  Controls,tisstrings;

type

  TVariantArray=Array of Variant;

  { TDMPython }

  TDMPython = class(TDataModule)
    PythonEng: TPythonEngine;
    PythonModuleDMWaptPython: TPythonModule;
    PythonOutput: TPythonGUIInputOutput;
    procedure DataModuleCreate(Sender: TObject);
    procedure DataModuleDestroy(Sender: TObject);
    procedure PythonModule1Events0Execute(Sender: TObject; PSelf,
      Args: PPyObject; var Result: PPyObject);
    procedure PythonModuleDMWaptPythonEvents1Execute(Sender: TObject; PSelf,
      Args: PPyObject; var Result: PPyObject);
  private
    FIsEnterpriseEdition: Boolean;
    Fcommon: Variant;
    FLanguage: String;
    FCachedPrivateKeyPassword: Ansistring;
    FPackagesAuthorizedCA: Variant;
    FMainWaptRepo: Variant;
    FPersonalCertificate: Variant;
    FWaptHostRepo: Variant;
    FWAPT: Variant;
    FWaptRepos: TVariantArray;
    Fwaptcrypto: Variant;
    Fsetuphelpers: Variant;
    Fwaptpackage: Variant;
    Fwaptdevutils: Variant;
    Flicencing: Variant;
    FWaptconsoleFacade: Variant;
    jsondata:TJSONData;
    {$ifdef ENTERPRISE}
    FMaxHostsCount:Integer;
    {$endif}

    FWaptConfigFileName: String;
    function Getcommon: Variant;
    function GetIsEnterpriseEdition: Boolean;
    function GetMainWaptRepo: Variant;
    function GetPackagesAuthorizedCA: Variant;
    function GetPersonalCertificate: Variant;
    function GetWaptconsoleFacade: Variant;
    function GetWaptHostRepo: Variant;
    function getprivateKeyPassword: RawByteString;
    function Getsetuphelpers: Variant;
    function GetWAPT: Variant;
    function Getwaptcrypto: Variant;
    function Getwaptdevutils: Variant;
    function Getwaptpackage: Variant;
    function Getlicencing: Variant;
    function GetWaptRepos: TVariantArray;
    procedure LoadJson(data: String);
    procedure Setcommon(AValue: Variant);
    procedure SetIsEnterpriseEdition(AValue: Boolean);
    procedure SetMainWaptRepo(AValue: Variant);
    procedure SetPackagesAuthorizedCA(AValue: Variant);
    procedure SetPersonalCertificate(AValue: Variant);
    procedure SetWaptHostRepo(AValue: Variant);
    procedure setprivateKeyPassword(AValue: Ansistring);
    procedure SetWAPT(AValue: Variant);
    procedure SetWaptConfigFileName(AValue: String);
    procedure SetLanguage(AValue: String);

    { private declarations }
  public
    { public declarations }
    PyWaptWrapper : TPyDelphiWrapper;
    {$ifdef ENTERPRISE}
    LicensedTo: String;
    ValidLicence: Boolean;
    {$endif}

    function CertificateIsCodeSigning(crtfilename:String):Boolean;
    property privateKeyPassword: Ansistring read getprivateKeyPassword write setprivateKeyPassword;
    procedure OnGetPrivateKeyPassword(var Password: String);

    property WaptConfigFileName:String read FWaptConfigFileName write SetWaptConfigFileName;
    function RunJSON(expr: String; jsonView: TVirtualJSONInspector=
      nil): ISuperObject;

    property Language:String read FLanguage write SetLanguage;
    property MainWaptRepo:Variant read GetMainWaptRepo write SetMainWaptRepo;
    property WaptHostRepo:Variant read GetWaptHostRepo write SetWaptHostRepo;
    property WaptRepos:TVariantArray read GetWaptRepos;
    property PackagesAuthorizedCA:Variant read GetPackagesAuthorizedCA write SetPackagesAuthorizedCA;

    property WAPT:Variant read GetWAPT write SetWAPT;
    property waptcrypto:Variant read Getwaptcrypto;
    property common:Variant read Getcommon;
    property setuphelpers:Variant read Getsetuphelpers;
    property waptpackage:Variant read Getwaptpackage;
    property waptdevutils:Variant read Getwaptdevutils;
    property IsEnterpriseEdition:Boolean read GetIsEnterpriseEdition write SetIsEnterpriseEdition;

    property WaptconsoleFacade:Variant read GetWaptconsoleFacade;

    property PersonalCertificate:Variant read GetPersonalCertificate write SetPersonalCertificate;
    function PersonalCertificateIsCodeSigning:Boolean;

    {$ifdef ENTERPRISE}
    property licencing:Variant read Getlicencing;
    property MaxHostsCount:Integer Read FMaxHostsCount;
    {$endif}
    function CheckLicence(domain: String; var LicencesLog: String): Integer;
    procedure CheckPySources;
    function GetUserAllowedPerimetersSHA256: TDynStringArray;
    function UserCertAllowedOnHost(Host:ISuperObject):Boolean;
    function AllowedHostsForUser(Hosts:ISuperObject;Const Fields:Array of String):ISuperObject;

    function GetPackageEntries(Repos: TVariantArray;PackageNames:String;
        HostCapabilities:Variant;var missing:String): ISuperObject;

  end;

  function ExtractResourceString(Ident:String):RawByteString;

  function ExtractCertificateOptionalsFields( cert_filename : String ) : ISuperObject;
var
  DMPython: TDMPython;

implementation
uses variants, waptcommon, uWaptPythonUtils, uWaptRes, uwaptcrypto, uvisprivatekeyauth, inifiles,
    forms,Dialogs,uvisloading,dateutils,gettext,soutils;
{$R *.lfm}
{$ifdef ENTERPRISE }
{$R res_enterprise.rc}
{$else}
{$R res_community.rc}
{$endif}

function ExtractResourceString(Ident: String): RawByteString;
var
  S: TResourceStream;
begin
  S := TResourceStream.Create(HInstance, Ident, MAKEINTRESOURCE(10)); // RT_RCDATA
  try
    SetLength(Result,S.Size);
    S.Seek(0,soFromBeginning);
    S.Read(PChar(Result)^,S.Size);
  finally
    S.Free; // destroy the resource stream
  end;
end;

procedure TDMPython.SetWaptConfigFileName(AValue: String);
var
  ini : TInifile;
  i: integer;
begin
  if FWaptConfigFileName=AValue then
    Exit;

  FWaptConfigFileName:=AValue;

  // reset Variant to force recreate Wapt instance
  FPackagesAuthorizedCA := Unassigned;
  FMainWaptRepo := Unassigned;
  FWaptHostRepo := Unassigned;
  FWaptRepos := Nil;
  FWapt := Unassigned;

  FPersonalCertificate := Unassigned;

  if AValue<>'' then
  try
    Screen.Cursor:=crHourGlass;
    if not DirectoryExists(ExtractFileDir(AValue)) then
      mkdir(ExtractFileDir(AValue));
    //Initialize waptconsole parameters with local workstation wapt-get parameters...
    if not FileExistsUTF8(AValue) then
      CopyFile(WaptIniFilename,AValue,True);

    // override lang setting
    waptcommon.Language := '';
    for i := 1 to Paramcount - 1 do
      if (ParamStrUTF8(i) = '--LANG') or (ParamStrUTF8(i) = '-l') or
        (ParamStrUTF8(i) = '--lang') then
          waptcommon.Language := ParamStrUTF8(i + 1);

    // get from ini
    if waptcommon.Language = '' then
    begin
      ini := TIniFile.Create(FWaptConfigFileName);
      try
        waptcommon.Language := ini.ReadString('global','language',waptcommon.Language);
      finally
        ini.Free;
      end;
    end;

    if waptcommon.Language = '' then
      GetLanguageIDs(waptcommon.LanguageFull, waptcommon.Language);
    Language:= waptcommon.Language;
  finally
    Screen.Cursor:=crDefault;
  end;
end;

procedure TDMPython.SetLanguage(AValue: String);
begin
  if FLanguage=AValue then Exit;
  FLanguage:=AValue;
  SetDefaultLang(FLanguage);
  {$IFDEF Windows}
  if FLanguage='fr' then
    GetLocaleFormatSettings($1252, DefaultFormatSettings)
  else
    GetLocaleFormatSettings($409, DefaultFormatSettings);
  {$ELSE}
  // TODO
  {$ENDIF}
end;

function TDMPython.CertificateIsCodeSigning(crtfilename: String): Boolean;
var
  crt: Variant;
  vcrt_filename: Variant;

begin
  if (crtfilename<>'') and FileExistsUTF8(crtfilename) then
  begin
    vcrt_filename := PyUTF8Decode(crtfilename);
    crt := dmpython.waptcrypto.SSLCertificate(vcrt_filename);
    result := VarPythonAsString(crt.has_usage('code_signing')) <> '';
  end
  else
    result := False;
end;

procedure TDMPython.DataModuleCreate(Sender: TObject);
var
  st:TStringList;
  RegWaptBaseDir:String;
  PythonLibName: String;
begin
  {$ifdef ENTERPRISE}
  {$ifndef DEVMODE}
  CheckPySources;
  {$endif}
  {$endif}

  {$ifdef WINDOWS}
  PythonLibName := 'python27.dll';
  {$else}
  PythonLibName := 'libpython2.7.so';
  {$endif}

  RegWaptBaseDir:=WaptBaseDir();
  if not FileExistsUTF8(AppendPathDelim(RegWaptBaseDir) + PythonLibName) then
    RegWaptBaseDir:=RegisteredAppInstallLocation('wapt_is1');

  if RegWaptBaseDir='' then
  begin
    {$ifdef WINDOWS}
    RegWaptBaseDir:=RegisteredExePath('wapt-get.exe');
    {$else}
    RegWaptBaseDir:=GetWaptBaseDir();
    {$endif}
  end;

  with PythonEng do
  begin
    AutoLoad := False;
    DllPath := RegWaptBaseDir;
    DllName := PythonLibName;
    UseLastKnownVersion := False;
    SetPythonHome(RegWaptBaseDir);
    LoadDLL;
  end;

  PyWaptWrapper := TPyDelphiWrapper.Create(Self);  // no need to destroy
  PyWaptWrapper.Engine := PythonEng;
  PyWaptWrapper.Module := PythonModuleDMWaptPython;
  PyWaptWrapper.Initialize;  // Should only be called if PyDelphiWrapper is created at run time

  st := TStringList.Create;
  try
    st.Append('import logging');
    st.Append('logger = logging.getLogger()');
    st.Append('logging.basicConfig(level=logging.WARNING)');
    PythonEng.ExecStrings(St);
  finally
    st.free;
  end;

  OnWaptGetKeyPassword := @Self.OnGetPrivateKeyPassword;

  {$ifdef ENTERPRISE}
  FMaxHostsCount :=0;
  {$endif}
end;

procedure TDMPython.DataModuleDestroy(Sender: TObject);
begin
  if Assigned(jsondata) then
    FreeAndNil(jsondata);

end;

procedure TDMPython.PythonModule1Events0Execute(Sender: TObject; PSelf,
  Args: PPyObject; var Result: PPyObject);
begin
  //ShowMessage(VarPythonCreate(Args).GetItem(0));
  Result := PythonEng.VariantAsPyObject(privateKeyPassword);
end;

procedure TDMPython.PythonModuleDMWaptPythonEvents1Execute(Sender: TObject;
  PSelf, Args: PPyObject; var Result: PPyObject);
var
  DoShow:Boolean;
  Progress,ProgressMax: Integer;
  Msg: String;
  NbArgs:Integer;
begin
  {args :
    0: ShowHide (bool or None) ,
    1: Progress(int or None),
    2: ProgressMax (int or None),
    3: Message (unicode or None)
  }
  NbArgs := PythonEng.PyTuple_Size(Args);

  if VisLoading = Nil then
    VisLoading := TVisLoading.Create(Application);

  // Current progress
  if NbArgs>=2 then
    if PythonEng.PyTuple_GetItem(Args,1) <> PythonEng.Py_None then
      Progress := PythonEng.PyLong_AsLong(PythonEng.PyTuple_GetItem(Args,1))
    else
      Progress := VisLoading.AProgressBar.Position
  else
    Progress:=VisLoading.AProgressBar.Position;

  // Max
  if NbArgs>=3 then
    if PythonEng.PyTuple_GetItem(Args,2) <> PythonEng.Py_None then
      ProgressMax := PythonEng.PyLong_AsLong(PythonEng.PyTuple_GetItem(Args,2))
    else
      ProgressMax :=  VisLoading.AProgressBar.Max
  else
    ProgressMax :=  VisLoading.AProgressBar.Max;

  // Message
  if NbArgs>=4 then
    if PythonEng.PyTuple_GetItem(Args,3) <> PythonEng.Py_None then
      Msg := PythonEng.PyString_AsDelphiString(PythonEng.PyTuple_GetItem(Args,3))
    else
      // use current one
      Msg := VisLoading.AMessage.Caption
  else
    Msg := VisLoading.AMessage.Caption;

  // show / hide
  if PythonEng.PyTuple_GetItem(Args,0) <> PythonEng.Py_None then
  begin
    DoShow := PythonEng.PyObject_IsTrue(PythonEng.PyTuple_GetItem(Args,0)) <> 0;
    If DoShow then
      ShowLoadWait(Msg, Progress,ProgressMax)
    else
      HideLoadWait();
  end
  else
  begin
    // change only msg and progress bar
    VisLoading.ProgressTitle(Msg);
    VisLoading.ProgressStep(Progress,ProgressMax);
  end;

  // get push on cancel button from user
  if (VisLoading<>Nil)  and (VisLoading.StopRequired) then
    Result := PythonEng.PyBool_FromLong(1)
  else
    Result:=PythonEng.ReturnNone;
end;

function TDMPython.RunJSON(expr: String; jsonView: TVirtualJSONInspector
  ): ISuperObject;
var
  res:String;
begin
  if Assigned(jsonView) then
    jsonView.Clear;

  res := PythonEng.EvalStringAsStr(format('jsondump(%s)',[expr]));
  result := SO( UTF8Decode(res) );

  if Assigned(jsonView) then
  begin
    LoadJson(res);
    jsonView.RootData := jsondata;
  end;

end;


procedure TDMPython.LoadJson(data: String);
var
  P:TJSONParser;
begin
  P:=TJSONParser.Create(Data,True);
  try
    if jsondata<>Nil then
      FreeAndNil(jsondata);
    jsondata := P.Parse;
  finally
      FreeAndNil(P);
  end;
end;

procedure TDMPython.Setcommon(AValue: Variant);
begin
  if VarCompareValue(Fcommon,AValue) = vrEqual  then Exit;
  Fcommon:=AValue;
end;

procedure TDMPython.SetIsEnterpriseEdition(AValue: Boolean);
begin
  {$ifdef ENTERPRISE}
  if AValue and not ValidLicence then
    Exit;
  FIsEnterpriseEdition:=AValue;
  {$else}
  FIsEnterpriseEdition := False;
  {$endif}
end;

procedure TDMPython.SetMainWaptRepo(AValue: Variant);
begin
  if VarCompareValue(FMainWaptRepo,AValue) = vrEqual  then Exit;
  FMainWaptRepo:=AValue;
  FWaptRepos := Nil;
end;

procedure TDMPython.SetPackagesAuthorizedCA(AValue: Variant);
begin
  if VarCompareValue(FPackagesAuthorizedCA,AValue) = vrEqual  then Exit;
  FPackagesAuthorizedCA := AValue;
end;

procedure TDMPython.SetPersonalCertificate(AValue: Variant);
begin
  if FPersonalCertificate=AValue then Exit;
  if not VarIsEmpty(FPersonalCertificate) then
    FPersonalCertificate:=Nil;
  FPersonalCertificate:=AValue;
end;

procedure TDMPython.SetWaptHostRepo(AValue: Variant);
begin
  if VarCompareValue(FWaptHostRepo,AValue) = vrEqual  then Exit;
  FWaptHostRepo:=AValue;
end;

//Returns the cached key password if it can decrypt a key matching Personal certificate
//If not, ask the user for a new password and try to decrypt a key
function TDMPython.getprivateKeyPassword: RawByteString;
var
  PrivateKeyPath:String;
  Password:String;
  RetryCount:integer;
  vcrt_filename: Variant;
begin
  if not FileExistsUTF8(WaptPersonalCertificatePath) then
    FCachedPrivateKeyPassword := ''
  else
  begin
    vcrt_filename:=PyUTF8Decode(WaptPersonalCertificatePath);
    RetryCount:=3;
    Password:= '';
    // try without password
    PrivateKeyPath := UTF8Encode(VarPythonAsString(DMPython.waptdevutils.get_private_key_encrypted(certificate_path:=vcrt_filename,password:=Password)));
    if (PrivateKeyPath ='') and (FCachedPrivateKeyPassword<>'') then
    begin
      Password := FCachedPrivateKeyPassword;
      PrivateKeyPath := UTF8Encode(VarPythonAsString(DMPython.waptdevutils.get_private_key_encrypted(certificate_path:=vcrt_filename,password:=Password)));
      // not found any keys, reset pwd cache to empty.
      if PrivateKeyPath='' then
        FCachedPrivateKeyPassword := '';
    end;

    if PrivateKeyPath ='' then
      while RetryCount>0 do
      begin
        with TVisPrivateKeyAuth.Create(Application.MainForm) do
        try
          laKeyPath.Caption := WaptPersonalCertificatePath;
          if ShowModal = mrOk then
          begin
            Password := edPasswordKey.Text;
            PrivateKeyPath := UTF8Encode(VarPythonAsString(DMPython.waptdevutils.get_private_key_encrypted(certificate_path:=vcrt_filename,password:=Password)));
            if PrivateKeyPath<>'' then
            begin
              FCachedPrivateKeyPassword:=edPasswordKey.Text;
              break;
            end;
          end
          else
          begin
            FCachedPrivateKeyPassword := '';
            break;
          end;
        finally
          Free;
        end;
        dec(RetryCount);
      end;

    if PrivateKeyPath='' then
      Raise Exception.CreateFmt('Unable to find and/or decrypt private key for personal certificate %s',[WaptPersonalCertificatePath]);
  end;
  Result := FCachedPrivateKeyPassword;
end;

function TDMPython.Getsetuphelpers: Variant;
begin
  if VarIsEmpty(Fsetuphelpers) or VarIsNull(Fsetuphelpers) then
    Fsetuphelpers:= VarPyth.Import('setuphelpers');
  Result := Fsetuphelpers;
end;

function TDMPython.GetWAPT: Variant;
var
  st:TStringList;
begin
  if VarIsNull(FWapt) or VarIsEmpty(FWapt) then
  begin
    st := TStringList.Create;
    try
      st.Append('import logging');
      st.Append('logger = logging.getLogger()');
      st.Append('logging.basicConfig(level=logging.WARNING)');
      st.Append('import common');
      st.Append('import waptconsole');
      st.Append('import setuphelpers');
      st.Append('common.default_pwd_callback = waptconsole.GetPrivateKeyPassword');
      st.Append(format('WAPT = common.Wapt(config_filename=r"%s".decode(''utf8''),disable_update_server_status=True)',[WaptConfigFileName]));
      st.Append('WAPT.dbpath=r":memory:"');
      st.Append('WAPT.use_hostpackages = False');
      st.Append('WAPT.filter_on_host_cap = False');
      st.Append('WAPT.private_dir = setuphelpers.makepath(setuphelpers.user_appdata(),''wapt'',''private'')');

      // declare WaptConsole feedback module
      st.Append('WAPT.progress_hook = waptconsole.UpdateProgress');
      st.Append('WAPT.private_key_password_callback = waptconsole.GetPrivateKeyPassword');

      PythonEng.ExecStrings(St);
      FWAPT := MainModule.WAPT;
    finally
      st.free;
    end;
  end;
  Result := FWAPT;
end;

function TDMPython.Getwaptcrypto: Variant;
begin
  if VarIsEmpty(Fwaptcrypto) or VarIsNull(Fwaptcrypto) then
    Fwaptcrypto:= VarPyth.Import('waptcrypto');
  Result := Fwaptcrypto;
end;

function TDMPython.Getwaptdevutils: Variant;
begin
  if VarIsEmpty(Fwaptdevutils) or VarIsNull(Fwaptdevutils) then
    Fwaptdevutils:= VarPyth.Import('waptdevutils');
  Result := Fwaptdevutils;

end;

function TDMPython.Getwaptpackage: Variant;
begin
  if VarIsEmpty(Fwaptpackage) or VarIsNull(Fwaptpackage) then
    Fwaptpackage:= VarPyth.Import('waptpackage');
  Result := Fwaptpackage;

end;

function TDMPython.GetMainWaptRepo: Variant;
var
  section:String;
  VWaptConfigFileName,cabundle:Variant;
begin
  if VarIsEmpty(FMainWaptRepo) then
  try
    with TIniFile.Create(WaptConfigFileName) do
    try
      ShowLoadWait('Loading main Wapt repo settings',0,4);
      if SectionExists('wapt') and (ReadString('wapt','repo_url','NONE')<>'NONE') then
        section := 'wapt'
      else
        section := 'global';
      cabundle := PackagesAuthorizedCA;
      FMainWaptRepo := dmpython.waptpackage.WaptRemoteRepo(name := section {, cabundle := cabundle});
      VWaptConfigFileName:=PyUTF8Decode(WaptConfigFileName);
      FMainWaptRepo.load_config_from_file(VWaptConfigFileName);
      FMainWaptRepo.private_key_password_callback := WaptconsoleFacade.GetPrivateKeyPassword;
      //todo : load client cert and key
    finally
      Free;
    end;
  finally
    HideLoadWait;
  end;
  Result := FMainWaptRepo;
end;

function TDMPython.GetWaptRepos: TVariantArray;
var
  Repositories,
  Section:String;
  VWaptConfigFileName,AdditionalRepo:Variant;
begin
  if not Assigned(FWaptRepos) then
  begin
    SetLength(FWaptRepos,1);
    FWaptRepos[0]:= GetMainWaptRepo;
    with TIniFile.Create(WaptConfigFileName) do
    try
      VWaptConfigFileName:=PyUTF8Decode(WaptConfigFileName);
      Repositories := ReadString('global','repositories','');
      if Repositories <> '' then
        for Section in StrSplit(repositories,',',True) do
          if Section <> 'wapt' then
          begin
            AdditionalRepo := dmpython.waptpackage.WaptRemoteRepo(name := section {, cabundle := cabundle});
            AdditionalRepo.load_config_from_file(VWaptConfigFileName);
            AdditionalRepo.private_key_password_callback := WaptconsoleFacade.GetPrivateKeyPassword;
            SetLength(FWaptRepos,Length(FWaptRepos)+1);
            FWaptRepos[Length(FWaptRepos)-1] := AdditionalRepo;
          end;
    finally
      Free;
    end;
  end;
  Result := FWaptRepos;
end;

function TDMPython.GetPackagesAuthorizedCA: Variant;
var
  CertDir: String;
begin
  if VarIsEmpty(FPackagesAuthorizedCA) then
  try
     CertDir:=PyUTF8Decode(AuthorizedCertsDir);
      FPackagesAuthorizedCA := waptcrypto.SSLCABundle(cert_pattern_or_dir := CertDir);
      FPackagesAuthorizedCA.add_pems(IncludeTrailingPathDelimiter(WaptBaseDir)+'ssl\*.crt');
  finally
  end;
  Result := FPackagesAuthorizedCA;
end;

function TDMPython.GetWaptHostRepo: Variant;
var
  section:String;
  VWaptConfigFileName,cabundle:Variant;
begin
  if VarIsEmpty(FWaptHostRepo) then
  try
    with TIniFile.Create(WaptConfigFileName) do
    try
      if SectionExists('wapt-host') and (ReadString('wapt-host','repo_url','NONE')<>'NONE') then
        section := 'wapt-host'
      else
        section := 'global';

      cabundle := VarPyth.None;
      // if check package signatures...
      //cabundle := PackagesAuthorizedCA;
      FWaptHostRepo := dmpython.common.WaptHostRepo(name := section, cabundle := cabundle );
      VWaptConfigFileName := PyUTF8Decode(WaptConfigFileName);
      FWaptHostRepo.load_config_from_file(VWaptConfigFileName);
      FWaptHostRepo.private_key_password_callback := WaptconsoleFacade.GetPrivateKeyPassword;
      //todo : load client cert and key
    finally
      Free;
    end;
  finally
  end;
  Result := FWaptHostRepo;
end;

function TDMPython.Getcommon: Variant;
begin
  if VarIsEmpty(Fcommon) or VarIsNull(Fcommon) then
  begin
    Fcommon:= VarPyth.Import('common');
    Fcommon.default_pwd_callback := WaptconsoleFacade.GetPrivateKeyPassword;
  end;
  Result := Fcommon;
end;

function TDMPython.GetIsEnterpriseEdition: Boolean;
begin
  {$ifdef ENTERPRISE}
  Result := ValidLicence and FIsEnterpriseEdition;
  {$else}
  Result := False;
  {$endif}
end;

procedure TDMPython.setprivateKeyPassword(AValue: Ansistring);
begin
  FCachedPrivateKeyPassword:=AValue;
end;


procedure TDMPython.SetWAPT(AValue: Variant);
begin
  if VarCompareValue(FWAPT,AValue) = vrEqual then Exit;
  FWAPT:=AValue;
end;



function ExtractCertificateOptionalsFields( cert_filename : String ) : ISuperObject;
var
  crt : Variant;
begin

  result := nil;

  if cert_filename = '' then
    exit;

  if FileExistsUTF8(cert_filename) = false then
    exit;

  crt := dmpython.waptcrypto.SSLCertificate(cert_filename);

  if VarIsNone( crt ) then
    exit;

  result := PyVarToSuperObject( crt.issuer );
end;

function TDMPython.PersonalCertificateIsCodeSigning: Boolean;
begin
  try
    Result := not VarIsEmpty(DMPython.PersonalCertificate) and not VarIsNull(DMPython.PersonalCertificate) and
      (VarPythonAsString(DMPython.PersonalCertificate.certificates('--noarg--').__getitem__(0).has_usage('code_signing'))<>'')
  except
    //Unable to load certificate...
    Result := False;
  end;
end;

//Returns a CABundle python object which contains the user certificate (first one) and potentially intermediate CA.
function TDMPython.GetPersonalCertificate: Variant;
var
  vcrt_filename: Variant;
begin
  if VarIsEmpty(FPersonalCertificate) or VarIsNull(FPersonalCertificate) then
  begin
    if (waptcommon.WaptPersonalCertificatePath <> '') and FileExistsUTF8(waptcommon.WaptPersonalCertificatePath) then
    try
      vcrt_filename := PyUTF8Decode(waptcommon.WaptPersonalCertificatePath);
      FPersonalCertificate := waptcrypto.SSLCABundle(vcrt_filename);
    except
      Result := Unassigned;
    end;
  end;
  Result := FPersonalCertificate;
end;

function TDMPython.GetUserAllowedPerimetersSHA256:TDynStringArray;
begin
  if not VarIsEmpty(DMPython.PersonalCertificate) and not VarIsNull(DMPython.PersonalCertificate) then
    result := StrSplit(DMPython.PersonalCertificate.certificates_sha256_fingerprints('--noarg--'),',')
  else
    result := TDynStringArray.Create;
end;

function TDMPython.UserCertAllowedOnHost(Host:ISuperObject):Boolean;
var
  Fingerprint:String;
  UserPerimeters: TDynStringArray;
  HostPerimeters: ISuperobject;
begin
  Result := False;
  If (Host = Nil) or not Assigned(Host['host_capabilities']) or
      not Assigned(Host['host_capabilities.packages_trusted_ca_fingerprints']) then
    Result := True
  else
  begin
    UserPerimeters := GetUserAllowedPerimetersSHA256;
    HostPerimeters := Host['host_capabilities.packages_trusted_ca_fingerprints'];
    for Fingerprint in UserPerimeters do
      If StrIn(Fingerprint,HostPerimeters) then
      begin
        Result := True;
        Break;
      end;
  end;
end;

function TDMPython.AllowedHostsForUser(Hosts: ISuperObject;
  const Fields: array of String): ISuperObject;
var
  Fingerprint:String;
  UserPerimeters: TDynStringArray;
  Host,HostPerimeters: ISuperobject;
begin
  Result := TSuperObject.Create(stArray);
  UserPerimeters := GetUserAllowedPerimetersSHA256;
  For Host in Hosts do
  begin
    If Assigned(Host['host_capabilities']) and
       Assigned(Host['host_capabilities.packages_trusted_ca_fingerprints']) then
    begin
      HostPerimeters := Host['host_capabilities.packages_trusted_ca_fingerprints'];
      for Fingerprint in UserPerimeters do
        If StrIn(Fingerprint,HostPerimeters) then
        begin
          Result.AsArray.Add(SOExtractFields(Host,Fields));
          Break;
        end;
    end;
  end;
end;

function TDMPython.GetPackageEntries(Repos: TVariantArray; PackageNames: String;
  HostCapabilities: Variant; var missing:String): ISuperObject;
var
  PackageCond: String;
  Repo,ARequest,Packages: Variant;
begin
  Result := TSuperObject.Create(stArray);
  if not VarIsNone(HostCapabilities) then
    ARequest := HostCapabilities.get_package_request_filter('--noarg--')
  else
    ARequest := waptpackage.PackageRequest('--noarg--');

  missing := '';
  for PackageCond  in StrSplit(PackageNames,',',True) do
  begin
    ARequest.request := PackageCond;
    Packages := None;
    // loop over all active repositiories
    for Repo in Repos do
    begin
      //append all matching packages
      if VarIsNone(Packages) then
        Packages := Repo.packages_matching(ARequest)
      else
        Packages.extend(Repo.packages_matching(ARequest));
    end;
    // take most recent...
    Packages.sort('--noarg--');
    if len(Packages)>0 then
      Result.AsArray.Add(PyVarToSuperObject(Packages.__getitem__(-1)))
    else
      missing := missing+','+PackageCond;
  end;
  if length(missing)>0 then
    missing := copy(missing,2,length(missing)-1);
end;

function TDMPython.GetWaptconsoleFacade: Variant;
begin
  if VarIsEmpty(FWaptconsoleFacade) or VarIsNull(FWaptconsoleFacade) then
    FWaptconsoleFacade := VarPyth.Import('waptconsole');
  Result := FWaptconsoleFacade;

end;


procedure TDMPython.OnGetPrivateKeyPassword(var Password: String);
begin
  Password := getprivateKeyPassword;
end;


{$ifdef ENTERPRISE}
{$include ..\waptenterprise\includes\dmwaptpython.inc}
{$else}
function TDMPython.CheckLicence(domain: String; var LicencesLog: String): Integer;
begin
  LicencesLog := 'WAPT Community Edition';
  if domain <> '' then
     LicencesLog := LicencesLog + ' for ' + domain;
  Result := -1;
end;

procedure TDMPython.CheckPySources;
begin
end;

function TDMPython.Getlicencing: Variant;
begin
  Result := Nil;
end;

{$endif}

end.

