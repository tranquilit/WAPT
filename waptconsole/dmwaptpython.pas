unit dmwaptpython;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, LazFileUtils, LazUTF8, PythonEngine, PythonGUIInputOutput,
  VarPyth, vte_json, superobject, fpjson, jsonparser, DefaultTranslator,LCLTranslator,
  Controls, WrapDelphi;

type

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
    Fwaptcrypto: Variant;
    Fsetuphelpers: Variant;
    Fwaptpackage: Variant;
    Fwaptdevutils: Variant;
    Flicencing: Variant;
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
    function GetWaptHostRepo: Variant;
    function getprivateKeyPassword: RawByteString;
    function Getsetuphelpers: Variant;
    function GetWAPT: Variant;
    function Getwaptcrypto: Variant;
    function Getwaptdevutils: Variant;
    function Getwaptpackage: Variant;
    function Getlicencing: Variant;
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

    property WaptConfigFileName:String read FWaptConfigFileName write SetWaptConfigFileName;
    function RunJSON(expr: String; jsonView: TVirtualJSONInspector=
      nil): ISuperObject;

    property Language:String read FLanguage write SetLanguage;
    property MainWaptRepo:Variant read GetMainWaptRepo write SetMainWaptRepo;
    property WaptHostRepo:Variant read GetWaptHostRepo write SetWaptHostRepo;
    property PackagesAuthorizedCA:Variant read GetPackagesAuthorizedCA write SetPackagesAuthorizedCA;

    property WAPT:Variant read GetWAPT write SetWAPT;
    property waptcrypto:Variant read Getwaptcrypto;
    property common:Variant read Getcommon;
    property setuphelpers:Variant read Getsetuphelpers;
    property waptpackage:Variant read Getwaptpackage;
    property waptdevutils:Variant read Getwaptdevutils;
    property IsEnterpriseEdition:Boolean read GetIsEnterpriseEdition write SetIsEnterpriseEdition;

    property PersonalCertificate:Variant read GetPersonalCertificate write SetPersonalCertificate;
    function PersonalCertificateIsCodeSigning:Boolean;

    {$ifdef ENTERPRISE}
    property licencing:Variant read Getlicencing;
    property MaxHostsCount:Integer Read FMaxHostsCount;
    {$endif}
    function CheckLicence(domain: String; var LicencesLog: String): Integer;
    procedure CheckPySources;

  end;

  function CreateSignedCert(keyfilename,
          crtbasename,
          destdir,
          country,
          locality,
          organization,
          orgunit,
          commonname,
          email,
          keypassword:UnicodeString;
          codesigning:Boolean;
          IsCACert:Boolean;
          CACertificateFilename:UnicodeString='';
          CAKeyFilename:UnicodeString=''
      ):String;


  function pyObjectToSuperObject(pvalue:PPyObject):ISuperObject;
  function PyVarToSuperObject(PyVar:Variant):ISuperObject;


  function SuperObjectToPyObject(aso:ISuperObject):PPyObject;
  function SuperObjectToPyVar(aso:ISuperObject):Variant;

  function ExtractResourceString(Ident:String):RawByteString;

  function PyUTF8Decode(s:RawByteString):UnicodeString;

  function ExtractCertificateOptionalsFields( cert_filename : String ) : ISuperObject;
var
  DMPython: TDMPython;

implementation
uses variants, waptcommon, uWaptRes, waptcrypto, uvisprivatekeyauth,inifiles,forms,Dialogs,uvisloading,dateutils,tisstrings,gettext;
{$R *.lfm}
{$ifdef ENTERPRISE }
{$R res_enterprise.rc}
{$else}
{$R res_community.rc}
{$endif}

function pyObjectToSuperObject(pvalue:PPyObject):ISuperObject;
var
  j,k: Integer;
  pyKey,pyDict,pyValue: PPyObject;
begin
  if GetPythonEngine.PyUnicode_Check(pvalue) or GetPythonEngine.PyString_Check(pvalue) then
    Result := TSuperObject.Create(GetPythonEngine.PyString_AsDelphiString(pvalue))
  else if GetPythonEngine.PyInt_Check(pvalue) then
    Result := TSuperObject.Create(GetPythonEngine.PyInt_AsLong(pvalue))
  else if GetPythonEngine.PyFloat_Check(pvalue) then
    Result := TSuperObject.Create(GetPythonEngine.PyFloat_AsDouble(pvalue))
  else if GetPythonEngine.PyList_Check(pvalue) then
  begin
    Result := TSuperObject.Create(stArray);
    for k := 0 to GetPythonEngine.PyList_Size(pvalue) - 1 do
        Result.AsArray.Add(pyObjectToSuperObject(GetPythonEngine.PyList_GetItem(pvalue,k)));
  end
  else if GetPythonEngine.PyTuple_Check(pvalue) then
  begin
    Result := TSuperObject.Create(stArray);
    for k := 0 to GetPythonEngine.PyTuple_Size(pvalue) - 1 do
        Result.AsArray.Add(pyObjectToSuperObject(GetPythonEngine.PyTuple_GetItem(pvalue,k)));
  end
  else if GetPythonEngine.PyDict_Check(pvalue) then
  begin
    Result := TSuperObject.Create(stObject);
    j := 0;
    pyKey := Nil;
    pyValue := Nil;
    while GetPythonEngine.PyDict_Next(pvalue,@j,@pyKey,@pyValue) <> 0 do
      Result[GetPythonEngine.PyObjectAsString(pyKey)] := pyObjectToSuperObject(pyvalue);
  end
  else if GetPythonEngine.PyObject_HasAttrString(pvalue,'as_dict') <> 0  then
  begin
    Result := TSuperObject.Create(stObject);
    pyDict := GetPythonEngine.PyObject_CallMethodStr(pvalue,'as_dict',Nil,Nil);
    j := 0;
    pyKey := Nil;
    pyValue := Nil;
    while GetPythonEngine.PyDict_Next(pyDict,@j,@pyKey,@pyValue) <> 0 do
      Result[GetPythonEngine.PyObjectAsString(pyKey)] := pyObjectToSuperObject(pyvalue);
  end
  else if pvalue = GetPythonEngine.Py_None then
    Result := TSuperObject.Create(stNull)
  else
    Result := TSuperObject.Create(GetPythonEngine.PyObjectAsString(pvalue));
end;

function PyVarToSuperObject(PyVar:Variant):ISuperObject;
begin
  Result := pyObjectToSuperObject(ExtractPythonObjectFrom(PyVar));
end;

function SuperObjectToPyObject(aso: ISuperObject): PPyObject;
var
  i:integer;
  item: ISuperObject;
  key: ISuperObject;

begin
  if aso<>Nil then
  begin
    case aso.DataType of
      stBoolean: begin
          if aso.AsBoolean then
            Result := PPyObject(GetPythonEngine.Py_True)
          else
            Result := PPyObject(GetPythonEngine.Py_False);
          GetPythonEngine.Py_INCREF(result);
      end;
      stNull: begin
          Result := GetPythonEngine.ReturnNone;
        end;
      stInt: begin
          Result := GetPythonEngine.PyInt_FromLong(aso.AsInteger);
        end;
      stDouble,stCurrency: begin
        Result := GetPythonEngine.PyFloat_FromDouble(aso.AsDouble);
        end;
      stString: begin
        Result := GetPythonEngine.PyUnicode_FromWideString(aso.AsString);
        end;
      stArray: begin
        Result := GetPythonEngine.PyTuple_New(aso.AsArray.Length);
        i:=0;
        for item in aso do
        begin
          GetPythonEngine.PyTuple_SetItem(Result,i,SuperObjectToPyObject(item));
          inc(i);
        end;
      end;
      stObject: begin
        Result := GetPythonEngine.PyDict_New();
        for key in Aso.AsObject.GetNames do
          GetPythonEngine.PyDict_SetItem(Result, SuperObjectToPyObject(key),SuperObjectToPyObject(Aso[key.AsString]));
      end
      else
        Result := GetPythonEngine.VariantAsPyObject(aso);
    end
  end
  else
    Result := GetPythonEngine.ReturnNone;
end;

function SuperObjectToPyVar(aso: ISuperObject): Variant;
begin
  result := VarPyth.VarPythonCreate(SuperObjectToPyObject(aso));
end;

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
  if FLanguage='fr' then
    GetLocaleFormatSettings($1252, DefaultFormatSettings)
  else
    GetLocaleFormatSettings($409, DefaultFormatSettings);
end;

function TDMPython.CertificateIsCodeSigning(crtfilename: String): Boolean;
var
  crt: Variant;
  vcrt_filename: Variant;

begin
  if (crtfilename<>'') and FileExistsUTF8(crtfilename) then
  begin
    vcrt_filename := PyUTF8Decode(crtfilename);
    crt := dmpython.waptcrypto.SSLCertificate(crt_filename:=vcrt_filename);
    result := VarPythonAsString(crt.has_usage('code_signing')) <> '';
  end
  else
    result := False;
end;

procedure TDMPython.DataModuleCreate(Sender: TObject);
var
  st:TStringList;
begin
  {$ifdef ENTERPRISE}
  CheckPySources;
  {$endif}

  with PythonEng do
  begin
    DllName := 'python27.dll';
    RegVersion := '2.7';
    UseLastKnownVersion := False;
    LoadDLL;
    Py_SetProgramName(PAnsiChar(ParamStr(0)));
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
        with TvisPrivateKeyAuth.Create(Application.MainForm) do
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
      st.Append(format('WAPT = common.Wapt(config_filename=r"%s".decode(''utf8''),disable_update_server_status=True)',[WaptConfigFileName]));
      st.Append('WAPT.dbpath=r":memory:"');
      st.Append('WAPT.use_hostpackages = False');

      // declare WaptConsole feedback module
      st.Append('import waptconsole');
      st.Append('WAPT.progress_hook = waptconsole.UpdateProgress');
      st.Append('common.default_pwd_callback = waptconsole.GetPrivateKeyPassword');
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
    finally
      Free;
    end;
  finally
    HideLoadWait;
  end;
  Result := FMainWaptRepo;
end;

function TDMPython.GetPackagesAuthorizedCA: Variant;
begin
  if VarIsEmpty(FPackagesAuthorizedCA) then
  try
      FPackagesAuthorizedCA := waptcrypto.SSLCABundle(cert_pattern_or_dir := PyUTF8Decode(AuthorizedCertsDir));
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
    Fcommon:= VarPyth.Import('common');
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


function CreateSignedCert(keyfilename,
        crtbasename,
        destdir,
        country,
        locality,
        organization,
        orgunit,
        commonname,
        email,
        keypassword:UnicodeString;
        codesigning:Boolean;
        IsCACert:Boolean;
        CACertificateFilename:UnicodeString='';
        CAKeyFilename:UnicodeString=''
    ):String;
var
  CAKeyFilenameU,destpem,destcrt : Variant;
  key,cert,cakey,cacert:Variant;
  cakey_pwd: String;
  ca_pem: RawByteString;

begin
  result := '';
  cacert := Null;
  cakey := Null;
  cakey_pwd := '';

  if (CACertificateFilename<>'') then
    if not FileExists(CACertificateFilename) then
      raise Exception.CreateFmt('CA Certificate %s does not exist',[CACertificateFilename])
    else
      cacert:= dmpython.waptcrypto.SSLCertificate(crt_filename := CACertificateFilename);

  if (CAKeyFilename<>'') then
    if not FileExists(CAKeyFilename) then
      raise Exception.CreateFmt('CA private key %s does not exist',[CAKeyFilename])
    else
    begin
      if InputQuery('CA Private key password','Password',True,cakey_pwd) then
      begin
        CAKeyFilenameU := CAKeyFilename;
        cakey:= dmpython.waptcrypto.SSLPrivateKey(filename := CAKeyFilenameU, password := cakey_pwd);
      end
      else
        raise Exception.CreateFmt('No password for decryption of %s',[CAKeyFilename]);
    end;

  if FileExists(keyfilename) then
    destpem := keyfilename
  else
  begin
    if ExtractFileNameOnly(keyfilename) = keyfilename then
      destpem := AppendPathDelim(destdir)+ExtractFileNameOnly(keyfilename)+'.pem'
    else
      destpem := keyfilename;
  end;

  if crtbasename = '' then
    crtbasename := ExtractFileNameOnly(keyfilename);

  destcrt := AppendPathDelim(destdir)+crtbasename+'.crt';
  if not DirectoryExists(destdir) then
    ForceDirectories(destdir);

  key := dmpython.waptcrypto.SSLPrivateKey(filename := destpem,password := keypassword);

  // Create private key  if not already exist
  if not FileExists(destpem) then
  begin
    key.create(bits := 2048);
    key.save_as_pem(password := keypassword)
  end;

  // None can not be passed... not accepted : invalid Variant type
  // using default None on the python side to workaround this...
  // python call
  if  VarIsNull(cacert) or VarIsNull(cakey) or VarIsEmpty(cacert) or VarIsEmpty(cakey) then
    // self signed
    cert := key.build_sign_certificate(
      cn := commonname,
      organization := organization,
      locality := locality,
      country := country,
      organizational_unit := orgunit,
      email := email,
      is_ca := IsCACert,
      is_code_signing := codesigning)
  else
    cert := key.build_sign_certificate(
      ca_signing_key := cakey,
      ca_signing_cert := cacert,
      cn := commonname,
      organization := organization,
      locality := locality,
      country := country,
      organizational_unit := orgunit,
      email := email,
      is_ca := IsCACert,
      is_code_signing := codesigning);

  cert.save_as_pem(filename := destcrt);

  if not VarIsNull(cacert) and not VarIsEmpty(cacert) then
    // append CA
    with TFileStream.Create(destcrt,fmOpenReadWrite) do
    try
      Seek(0,soEnd);
      ca_pem := VarToStr(cacert.as_pem('--noarg--'));
      WriteBuffer(ca_pem[1],length(ca_pem));
    finally
      Free;
    end;

  result := utf8encode(destcrt);
end;

function PyUTF8Decode(s:RawByteString):UnicodeString;
begin
  result := UTF8Decode(s);
end;

function ExtractCertificateOptionalsFields( cert_filename : String ) : ISuperObject;
var
  crt : Variant;
begin

  result := nil;

  if cert_filename = '' then
    exit;

  if FileExists(cert_filename) = false then
    exit;

  crt := dmpython.waptcrypto.SSLCertificate(crt_filename:=cert_filename);

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

function TDMPython.GetPersonalCertificate: Variant;
var
  vcrt_filename: Variant;
  bundle: Variant;
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

