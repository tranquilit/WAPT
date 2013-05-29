unit uVisAppWaptService;
{ -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013  Tranquil IT Systems http://www.tranquil.it
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users PC.
#
#    WAPT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    WAPT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with WAPT.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------
}

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, BufDataset, FileUtil, SynHighlighterPython, SynEdit, Forms,
  Controls, Graphics, Dialogs, ExtCtrls, StdCtrls, DBGrids, AtomPythonEngine,
  PythonGUIInputOutput, PythonEngine, db, sqldb, waptcommon;

type

  { TVisAppWAPTService }

  TVisAppWAPTService = class(TForm)
    PythonEngine1: TAtomPythonEngine;
    Button1: TButton;
    EdGroup: TEdit;
    eduser: TEdit;
    edpassword: TEdit;
    eddomain: TEdit;
    EdServer: TEdit;
    TestPython: TButton;
    Datasource1: TDatasource;
    ButSQL: TButton;
    DBGrid1: TDBGrid;
    EdSQL: TMemo;
    Panel1: TPanel;
    query: TSQLQuery;
    testedit: TSynEdit;
    SynPythonSyn1: TSynPythonSyn;
    procedure butLoaddllClick(Sender: TObject);
    procedure butLoaddllExit(Sender: TObject);
    procedure ButSQLClick(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure butunloadllClick(Sender: TObject);
    procedure Panel1Click(Sender: TObject);
    procedure TestPythonClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure ToggleBox1Change(Sender: TObject);
  private
    { private declarations }
    waptdb : TWAPTDB;
  public
    { public declarations }
  end;

var
  VisAppWAPTService: TVisAppWAPTService;

implementation
uses tisstrings,ldapauth,ldapsend,tiscommon,superobject,soutils,jwawinbase;

//uses waptwmi;

{$R *.lfm}

{ TVisAppWAPTService }

procedure TVisAppWAPTService.butLoaddllClick(Sender: TObject);
begin
end;

procedure TVisAppWAPTService.butLoaddllExit(Sender: TObject);
begin
end;

procedure TVisAppWAPTService.ButSQLClick(Sender: TObject);
begin
  query.Close;
  query.DataBase := waptdb.db;
  query.Transaction := waptdb.sqltrans;
  query.SQL.text := EdSQL.Text;
  query.Open;
end;

procedure TVisAppWAPTService.Button1Click(Sender: TObject);
var
 ldap:TLDAPSend;
 gr:TDynStringArray;
 groups : ISuperObject;
 htok:THandle;
begin
  {ldap := LDAPSSLLogin(edserver.Text,eduser.Text,eddomain.text,edpassword.Text);
  testedit.Lines.Text  := GetUserAndGroups(ldap,'dc=tranquilit,dc=local',eduser.Text,True).AsJSon(True);
  if UserIngroup(ldap,'dc=tranquilit,dc=local',eduser.Text,EdGroup.Text) then
    ShowMessage('user  is member of group '+EdGroup.Text);
  ldap.Free;}
  htok := UserLogin(eduser.Text,edpassword.Text,eddomain.Text);
  gr := GetGroups(GetDNSDomain,eduser.Text);
  if length(gr)>0 then
  begin
    groups := DynArr2SuperObject(gr);
    if groups<>Nil then
      ShowMessage(groups.asjson);
  end;
  if htok>0 then
    closeHandle(htok);
end;

procedure TVisAppWAPTService.butunloadllClick(Sender: TObject);
begin
end;

procedure TVisAppWAPTService.Panel1Click(Sender: TObject);
begin

end;

procedure TVisAppWAPTService.TestPythonClick(Sender: TObject);
begin

  PythonEngine1.ExecString(testedit.Lines.Text);
  ShowMessage(PythonEngine1.EvalStringAsStr('mywapt.update()'));
end;


procedure TVisAppWAPTService.FormCreate(Sender: TObject);
begin
  with pythonEngine1 do
  begin
    DllName := 'python27.dll';
    RegVersion := '2.7';
    UseLastKnownVersion := False;
    LoadDLL;
    Py_SetProgramName(PAnsiChar(ParamStr(0)));
  end;

  waptdb := TWAPTDB.Create(WaptDBPath);
  waptdb.OpenDB;

  eduser.text := tiscommon.GetUserName;
  eddomain.Text := GetWorkgroupName;

end;

procedure TVisAppWAPTService.ToggleBox1Change(Sender: TObject);
begin

end;

end.

