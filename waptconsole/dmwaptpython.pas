unit dmwaptpython;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, PythonEngine, PythonGUIInputOutput,VarPyth,vte_json,superobject,fpjson,jsonparser;

type

  { TDMPython }

  TDMPython = class(TDataModule)
    PythonEng: TPythonEngine;
    PythonOutput: TPythonGUIInputOutput;
    procedure DataModuleCreate(Sender: TObject);
    procedure DataModuleDestroy(Sender: TObject);
  private
    jsondata:TJSONData;
    FWaptConfigFileName: String;
    procedure LoadJson(data: UTF8String);
    procedure SetWaptConfigFileName(AValue: String);
    { private declarations }
  public
    { public declarations }
    WAPT:Variant;

    property WaptConfigFileName:String read FWaptConfigFileName write SetWaptConfigFileName;
    function RunJSON(expr: UTF8String; jsonView: TVirtualJSONInspector=
      nil): ISuperObject;

  end;

var
  DMPython: TDMPython;

implementation

{$R *.lfm}

procedure TDMPython.SetWaptConfigFileName(AValue: String);
var
  St:TStringList;
begin
  if FWaptConfigFileName=AValue then Exit;
  FWaptConfigFileName:=AValue;
  if AValue<>'' then
  begin
    st := TStringList.Create;
    try
      st.Append('from common import *');
      st.Append('from setuphelpers import *');
      st.Append('import logging');
      st.Append('import requests');
      st.Append('import json');
      st.Append('import os');
      st.Append('import waptdevutils');
      st.Append('logging.basicConfig(level=logging.WARNING)');
      st.Append(format('mywapt = Wapt(config_filename=r"%s".decode(''utf8''),disable_update_server_status=True)',[AValue]));
      st.Append('mywapt.dbpath=r":memory:"');
      st.Append('mywapt.update(register=False)');

      PythonEng.ExecStrings(St);
      WAPT:=MainModule.mywapt;
    finally
      st.free;
    end;
  end;
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

