unit dmwaptpython;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, LazFileUtils, LazUTF8, PythonEngine, PythonGUIInputOutput,
  VarPyth, vte_json, superobject, fpjson, jsonparser, DefaultTranslator,
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
    FMainWaptRepo: Variant;
    FWaptHostRepo: Variant;
    FWAPT: Variant;
    Fwaptcrypto: Variant;
    Fsetuphelpers: Variant;
    Fwaptpackage: Variant;
    Fwaptdevutils: Variant;
    Flicencing: Variant;
    jsondata:TJSONData;
    FMaxHostsCount:Integer;

    FWaptConfigFileName: Utf8String;
    function Getcommon: Variant;
    function GetIsEnterpriseEdition: Boolean;
    function GetMainWaptRepo: Variant;
    function GetWaptHostRepo: Variant;
    function getprivateKeyPassword: Ansistring;
    function Getsetuphelpers: Variant;
    function GetWAPT: Variant;
    function Getwaptcrypto: Variant;
    function Getwaptdevutils: Variant;
    function Getwaptpackage: Variant;
    function Getlicencing: Variant;
    procedure LoadJson(data: UTF8String);
    procedure Setcommon(AValue: Variant);
    procedure SetIsEnterpriseEdition(AValue: Boolean);
    procedure SetMainWaptRepo(AValue: Variant);
    procedure SetWaptHostRepo(AValue: Variant);
    procedure setprivateKeyPassword(AValue: Ansistring);
    procedure SetWAPT(AValue: Variant);
    procedure SetWaptConfigFileName(AValue: Utf8String);
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

    property WaptConfigFileName:Utf8String read FWaptConfigFileName write SetWaptConfigFileName;
    function RunJSON(expr: Utf8String; jsonView: TVirtualJSONInspector=
      nil): ISuperObject;

    property Language:String read FLanguage write SetLanguage;
    property MainWaptRepo:Variant read GetMainWaptRepo write SetMainWaptRepo;
    property WaptHostRepo:Variant read GetWaptHostRepo write SetWaptHostRepo;

    property WAPT:Variant read GetWAPT write SetWAPT;
    property waptcrypto:Variant read Getwaptcrypto;
    property common:Variant read Getcommon;
    property setuphelpers:Variant read Getsetuphelpers;
    property waptpackage:Variant read Getwaptpackage;
    property waptdevutils:Variant read Getwaptdevutils;
    property IsEnterpriseEdition:Boolean read GetIsEnterpriseEdition write SetIsEnterpriseEdition;
    property licencing:Variant read Getlicencing;

    property MaxHostsCount:Integer Read FMaxHostsCount;


    function CheckLicence(domain: String; var LicencesLog: String): Integer;
    procedure CheckPySources;

  end;


  function CreateSignedCert(keyfilename,
          crtbasename,
          wapt_base_dir,
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

var
  DMPython: TDMPython;

implementation
uses variants, waptcommon, waptcrypto, uvisprivatekeyauth,inifiles,forms,Dialogs,uvisloading,dateutils,tisstrings;
{$R *.lfm}
{$ifdef ENTERPRISE }
{$R res_enterprise.rc}
{$else}
{$R res_community.rc}
{$endif}

function pyObjectToSuperObject(pvalue:PPyObject):ISuperObject;
var
  i,j,k: Integer;
  pyKeys,pyKey,pyDict,pyValue: PPyObject;
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
    pyKeys := GetPythonEngine.PyDict_Keys(pvalue);
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
    pyKeys := GetPythonEngine.PyDict_Keys(pyDict);
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
  _list : PPyObject;
  item: ISuperObject;
  key: ISuperObject;

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
  end;
end;

function SuperObjectToPyVar(aso: ISuperObject): Variant;
begin
  result := VarPyth.VarPythonCreate(SuperObjectToPyObject(aso));
end;

function ExtractResourceString(Ident: String): RawByteString;
var
  S: TResourceStream;
  data:RawByteString;
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

procedure TDMPython.SetWaptConfigFileName(AValue: Utf8String);
var
  ini : TInifile;
  i: integer;
begin
  if FWaptConfigFileName=AValue then
    Exit;


  FWaptConfigFileName:=AValue;

  // reset Variant to force recreate Wapt instance
  FMainWaptRepo := Unassigned;
  FWaptHostRepo := Unassigned;
  FWapt := Unassigned;

  if AValue<>'' then
  try
    Screen.Cursor:=crHourGlass;
    if not DirectoryExists(ExtractFileDir(AValue)) then
      mkdir(ExtractFileDir(AValue));
    //Initialize waptconsole parameters with local workstation wapt-get parameters...
    if not FileExists(AValue) then
      CopyFile(Utf8ToAnsi(WaptIniFilename),Utf8ToAnsi(AValue),True);


    // override lang setting
    for i := 1 to Paramcount - 1 do
      if (ParamStrUTF8(i) = '--LANG') or (ParamStrUTF8(i) = '-l') or
        (ParamStrUTF8(i) = '--lang') then
        begin
          waptcommon.Language := ParamStrUTF8(i + 1);
          waptcommon.FallBackLanguage := copy(waptcommon.Language,1,2);
          Language:=FallBackLanguage;
        end;

    // get from ini
    if Language = '' then
    begin
      ini := TIniFile.Create(FWaptConfigFileName);
      try
        waptcommon.Language := ini.ReadString('global','language','');
        waptcommon.FallBackLanguage := copy(waptcommon.Language,1,2);
        Language := waptcommon.Language;
      finally
        ini.Free;
      end;
    end;
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
begin
  //CheckPySources;

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

  {$ifdef ENTERPRISE}
  FMaxHostsCount :=0;
  {else}
  FMaxHostsCount :=+MaxInt;
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
  NbArgs := PythonEng.PyTuple_Size(Args);
  DoShow := PythonEng.PyObject_IsTrue(PythonEng.PyTuple_GetItem(Args,0)) <> 0;
  if NbArgs>=2 then
    Progress := PythonEng.PyLong_AsLong(PythonEng.PyTuple_GetItem(Args,1))
  else
    Progress:=0;
  if NbArgs>=3 then
    ProgressMax := PythonEng.PyLong_AsLong(PythonEng.PyTuple_GetItem(Args,2))
  else
    ProgressMax := 100;

  if NbArgs>=4 then
    Msg := PythonEng.PyString_AsDelphiString(PythonEng.PyTuple_GetItem(Args,3))
  else
    Msg := '';

  If DoShow then
    ShowLoadWait(Msg, Progress,ProgressMax)
  else
    HideLoadWait();
  if (VisLoading<>Nil)  and (VisLoading.StopRequired) then
    Result := PythonEng.PyBool_FromLong(1)
  else
    Result:=PythonEng.ReturnNone;

end;

function TDMPython.RunJSON(expr: Utf8String; jsonView: TVirtualJSONInspector
  ): ISuperObject;
var
  res:UTF8String;
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

function TDMPython.CheckLicence(domain: String; var LicencesLog: String): Integer;
var
  lic:ISuperObject;
  LicFilename:String;
  LicFileList,LicList:TStringList;
  Licence: Variant;
  tisCertPEM:String;
  tisCert: Variant;
begin
  Result:=0;
  {$ifdef ENTERPRISE}
  ValidLicence:=False;
  LicencesLog := '';
  LicensedTo := '';
  LicFileList := FindAllFiles(AppendPathDelim(WaptBaseDir)+'licences','*.lic');
  LicList:=TStringList.Create;
  try
    tisCertPEM := ExtractResourceString('CATIS');
    tisCert:=waptcrypto.SSLCertificate(crt_string := tisCertPEM);
    for LicFilename in LicFileList do
    begin
      Licence:=licencing.WaptLicence(filename := LicFilename);
      try
        Licence.check_licence(tisCert);
        if Now >= UniversalTimeToLocal(ISO8601ToDateTime(VarPythonAsString(Licence.valid_until))) then
          raise Exception.Create('Licence has expired');
        LicencesLog := LicencesLog+Licence.__unicode__('--noarg--').encode('utf-8')+#13#10;
        //if domain = VarPythonAsString(licence.domain) then
          Result := Result + StrToInt(VarPythonAsString(Licence.count));
        if LicList.IndexOf(VarPythonAsString(Licence.licence_nr))>=0 then
          raise Exception.Create('Duplicated Licence nr');
        LicList.Add(VarPythonAsString(Licence.licence_nr));
        ValidLicence:=True;
        if LicensedTo<>'' then
          LicensedTo := LicensedTo+',';
        LicensedTo := LicensedTo + VarPythonAsString(Licence.licenced_to.encode('utf-8'));
      except
        on e:Exception do
          // Skip because of validation error
          LicencesLog := LicencesLog+'Licence '+LicFilename+' ERROR '+E.Message+' for '+Licence.__unicode__('--noarg--').encode('utf-8')+' Skipped.'+#13#10
      end;
    end;
    FMaxHostsCount := Result;

  finally
    LicList.Free;
    LicFileList.Free;
  end;
  {$endif ENTERPRISE}
end;

procedure TDMPython.CheckPySources;
var
  Line,Filename,ExpectedSha256,ActualSha256:String;
  Errors,Files:TStringList;
begin
  {$ifdef ENTERPRISE}
  try
    Errors := TStringList.Create;
    Files := TStringList.Create;
    Files.Text:=ExtractResourceString('CHECKFILES');
    for line in Files do
    try
      ExpectedSha256:= copy(Line,1,64);
      Filename := copy(Line,67,length(line));
      ActualSha256:=SHA256Hash(Filename);
      if ActualSha256<>ExpectedSha256 then
        Raise Exception.CreateFmt('%s: file corrupted. Expected %s, Actual %s ',[Filename,ExpectedSha256,ActualSha256]);
    except
      on E:Exception do
        Errors.Add(e.Message);
    end;
    if Errors.Count>0 then
      Raise Exception.CreateFmt('%d validation errors for Python sources: %s',[Errors.Count,#13#10+Errors.Text]);
  finally
    Errors.Free;
    Files.Free;
  end;
  {$endif}
end;

procedure TDMPython.LoadJson(data: UTF8String);
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
  if FIsEnterpriseEdition=AValue then Exit;
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

procedure TDMPython.SetWaptHostRepo(AValue: Variant);
begin
  if VarCompareValue(FWaptHostRepo,AValue) = vrEqual  then Exit;
  FWaptHostRepo:=AValue;
end;

function TDMPython.getprivateKeyPassword: Ansistring;
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

function TDMPython.Getlicencing: Variant;
begin
  if IsEnterpriseEdition and VarIsEmpty(Flicencing) or VarIsNull(Flicencing) then
    Flicencing:= VarPyth.Import('waptenterprise.licencing');
  Result := Flicencing;

end;

function TDMPython.GetMainWaptRepo: Variant;
var
  section:String;
  VWaptConfigFileName:Variant;
begin
  if VarIsEmpty(FMainWaptRepo) then
  try
    with TIniFile.Create(WaptConfigFileName) do
    try
      ShowLoadWait('Loading main Wapt repo settings',0,4);
      if SectionExists('wapt') and (ReadString('wapt','repourl','NONE')<>'NONE') then
        section := 'wapt'
      else
        section := 'global';
      FMainWaptRepo := dmpython.waptpackage.WaptRemoteRepo(name := section);
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

function TDMPython.GetWaptHostRepo: Variant;
var
  section:String;
  VWaptConfigFileName:Variant;
begin
  if VarIsEmpty(FWaptHostRepo) then
  try
    with TIniFile.Create(WaptConfigFileName) do
    try
      if SectionExists('wapt-host') and (ReadString('wapt-host','repourl','NONE')<>'NONE') then
        section := 'wapt-host'
      else
        section := 'global';
      FWaptHostRepo := dmpython.common.WaptHostRepo(name := section);
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
  Result := FIsEnterpriseEdition;
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
        wapt_base_dir,
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
  params : ISuperObject;
  returnCode:integer;
  rsa,key,cert,cakey,cacert:Variant;
  cakey_pwd: String;

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
        rsa := cakey.as_pem;
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
  result := utf8encode(destcrt);
end;

function PyUTF8Decode(s:RawByteString):UnicodeString;
begin
  result := UTF8Decode(s);
end;

end.

