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
    procedure butunloadllClick(Sender: TObject);
    procedure Panel1Click(Sender: TObject);
    procedure TestPythonClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    { private declarations }
    waptdb : TWAPTDB;
  public
    { public declarations }
  end;

var
  VisAppWAPTService: TVisAppWAPTService;

implementation
uses tisstrings;

//uses waptwmi;

{$R *.lfm}

{ TVisAppWAPTService }

procedure TVisAppWAPTService.butLoaddllClick(Sender: TObject);
begin
    PythonEngine1.Initialize;
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
  waptdb := TWAPTDB.Create(WaptDBPath);
  waptdb.OpenDB;
end;

end.

