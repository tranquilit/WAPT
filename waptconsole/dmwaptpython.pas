unit dmwaptpython;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil,LazFileUtils, PythonEngine, PythonGUIInputOutput, VarPyth,
  vte_json, superobject, fpjson, jsonparser, DefaultTranslator,WrapDelphi;

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
  private
    FLanguage: String;
    FCachedPrivateKeyPassword: Ansistring;
    jsondata:TJSONData;

    FWaptConfigFileName: Utf8String;
    function getprivateKeyPassword: Ansistring;
    procedure LoadJson(data: UTF8String);
    procedure setprivateKeyPassword(AValue: Ansistring);
    procedure SetWaptConfigFileName(AValue: Utf8String);
    procedure SetLanguage(AValue: String);

    { private declarations }
  public
    { public declarations }
    WAPT:Variant;
    PyWaptWrapper : TPyDelphiWrapper;

    property privateKeyPassword: Ansistring read getprivateKeyPassword write setprivateKeyPassword;

    property WaptConfigFileName:Utf8String read FWaptConfigFileName write SetWaptConfigFileName;
    function RunJSON(expr: UTF8String; jsonView: TVirtualJSONInspector=
      nil): ISuperObject;

    property Language:String read FLanguage write SetLanguage;
  end;

var
  DMPython: TDMPython;

implementation
uses waptcommon, uvisprivatekeyauth,inifiles,forms,controls,Dialogs;
{$R *.lfm}

procedure TDMPython.SetWaptConfigFileName(AValue: Utf8String);
var
  St:TStringList;
  ini : TInifile;
  i: integer;
begin
  if FWaptConfigFileName=AValue then
    Exit;

  FWaptConfigFileName:=AValue;
  if AValue<>'' then
  try
    Screen.Cursor:=crHourGlass;
    if not DirectoryExists(ExtractFileDir(AValue)) then
      mkdir(ExtractFileDir(AValue));
    //Initialize waptconsole parameters with local workstation wapt-get parameters...
    if not FileExistsUTF8(AValue) then
      CopyFile(Utf8ToAnsi(WaptIniFilename),Utf8ToAnsi(AValue),True);
    st := TStringList.Create;
    try
      st.Append('import logging');
      st.Append('import requests');
      st.Append('import json');
      st.Append('import os');
      st.Append('import common');
      st.Append('import waptpackage');
      st.Append('import waptdevutils');
      st.Append('import setuphelpers');
      st.Append('from waptutils import jsondump');
      st.Append('logger = logging.getLogger()');
      st.Append('logging.basicConfig(level=logging.WARNING)');
      st.Append(format('mywapt = common.Wapt(config_filename=r"%s".decode(''utf8''),disable_update_server_status=True)',[AValue]));
      st.Append('mywapt.dbpath=r":memory:"');
      st.Append('mywapt.use_hostpackages = False');
      st.Append('import dmwaptpython');

      //st.Append('mywapt.update(register=False)');
      PythonEng.ExecStrings(St);
      WAPT:=MainModule.mywapt;
    finally
      st.free;
    end;
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

procedure TDMPython.DataModuleCreate(Sender: TObject);

begin
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

end;

procedure TDMPython.DataModuleDestroy(Sender: TObject);
begin
  if Assigned(jsondata) then
    FreeAndNil(jsondata);

end;

procedure TDMPython.PythonModule1Events0Execute(Sender: TObject; PSelf,
  Args: PPyObject; var Result: PPyObject);
begin
  ShowMessage(VarPythonCreate(Args).GetItem(0));
  Result :=  PythonEng.ReturnNone;
end;

function TDMPython.RunJSON(expr: UTF8String; jsonView: TVirtualJSONInspector=Nil): ISuperObject;
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

function TDMPython.getprivateKeyPassword: Ansistring;
var
  PrivateKeyPath:String;
  Password:Variant;
  RetryCount:integer;
begin
  if not FileExists(GetWaptPersonalCertificatePath) then
    FCachedPrivateKeyPassword := ''
  else
  begin
    RetryCount:=3;
    Password:= '';
    // try without password
    PrivateKeyPath := MainModule.waptdevutils.get_private_key_encrypted(certificate_path:=GetWaptPersonalCertificatePath(),password:=Password);
    if (PrivateKeyPath ='') and (FCachedPrivateKeyPassword<>'') then
    begin
      Password := FCachedPrivateKeyPassword;
      PrivateKeyPath := MainModule.waptdevutils.get_private_key_encrypted(certificate_path:=GetWaptPersonalCertificatePath(),password:=Password);
      // not found any keys, reset pwd cache to empty.
      if PrivateKeyPath='' then
        FCachedPrivateKeyPassword := '';
    end;

    if PrivateKeyPath ='' then
      while RetryCount>0 do
      begin
        with TvisPrivateKeyAuth.Create(Application.MainForm) do
        try
          laKeyPath.Caption := GetWaptPersonalCertificatePath;
          if ShowModal = mrOk then
          begin
            Password := edPasswordKey.Text;
            PrivateKeyPath := MainModule.waptdevutils.get_private_key_encrypted(certificate_path:=GetWaptPersonalCertificatePath(),password:=Password);
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
      end
    else
      FCachedPrivateKeyPassword :='';

    if PrivateKeyPath='' then
      Raise Exception.Create('Unable to find and/or decrypt private key for personal certitificate '+GetWaptPersonalCertificatePath);
  end;
  Result := FCachedPrivateKeyPassword;
end;



procedure TDMPython.setprivateKeyPassword(AValue: Ansistring);
begin
  FCachedPrivateKeyPassword:=AValue;
end;



end.

