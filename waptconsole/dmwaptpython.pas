unit dmwaptpython;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, PythonEngine, PythonGUIInputOutput, VarPyth,
  vte_json, superobject, fpjson, jsonparser, DefaultTranslator;

type

  { TDMPython }

  TDMPython = class(TDataModule)
    PythonEng: TPythonEngine;
    PythonOutput: TPythonGUIInputOutput;
    procedure DataModuleCreate(Sender: TObject);
    procedure DataModuleDestroy(Sender: TObject);
  private
    FLanguage: String;
    jsondata:TJSONData;
    FWaptConfigFileName: String;
    procedure LoadJson(data: UTF8String);
    procedure SetWaptConfigFileName(AValue: String);
    procedure SetLanguage(AValue: String);

    { private declarations }
  public
    { public declarations }
    WAPT:Variant;

    property WaptConfigFileName:String read FWaptConfigFileName write SetWaptConfigFileName;
    function RunJSON(expr: UTF8String; jsonView: TVirtualJSONInspector=
      nil): ISuperObject;

    property Language:String read FLanguage write SetLanguage;
  end;

var
  DMPython: TDMPython;

implementation
uses waptcommon,inifiles;
{$R *.lfm}

procedure TDMPython.SetWaptConfigFileName(AValue: String);
var
  St:TStringList;
  ini : TInifile;
begin
  if FWaptConfigFileName=AValue then Exit;
  FWaptConfigFileName:=AValue;
  if AValue<>'' then
  begin
    if not DirectoryExists(ExtractFileDir(AValue)) then
      mkdir(ExtractFileDir(AValue));
    if not FileExists(AValue) then
      CopyFile(WaptIniFilename,AValue);
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
      st.Append('from common import jsondump');
      st.Append('logger = logging.getLogger()');
      st.Append('logging.basicConfig(level=logging.WARNING)');
      st.Append(format('mywapt = common.Wapt(config_filename=r"%s".decode(''utf8''),disable_update_server_status=True)',[AValue]));
      st.Append('mywapt.dbpath=r":memory:"');
      st.Append('mywapt.use_hostpackages = False');
      //st.Append('mywapt.update(register=False)');
      PythonEng.ExecStrings(St);
      WAPT:=MainModule.mywapt;
    finally
      st.free;
    end;
  end;

  ini := TIniFile.Create(AppIniFilename);
  try
    Language := ini.ReadString('global','language','');
  finally
    ini.Free;
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

end;

procedure TDMPython.DataModuleDestroy(Sender: TObject);
begin
  if Assigned(jsondata) then
    FreeAndNil(jsondata);

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



end.

