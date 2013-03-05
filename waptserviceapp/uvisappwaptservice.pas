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
  Classes, SysUtils, BufDataset, FileUtil, Forms, Controls, Graphics, Dialogs,
  ExtCtrls, StdCtrls, DBGrids, db, sqldb,waptcommon;

type

  { TVisAppWAPTService }

  TVisAppWAPTService = class(TForm)
    Button1: TButton;
    Datasource1: TDatasource;
    ButSQL: TButton;
    DBGrid1: TDBGrid;
    EdSQL: TMemo;
    Panel1: TPanel;
    query: TSQLQuery;
    procedure BufDataset1AfterEdit(DataSet: TDataSet);
    procedure ButSQLClick(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure Panel1Click(Sender: TObject);
  private
    { private declarations }
    waptdb : TWAPTDB;
  public
    { public declarations }
  end;

var
  VisAppWAPTService: TVisAppWAPTService;

implementation





//uses waptwmi;

{$R *.lfm}

{ TVisAppWAPTService }

procedure TVisAppWAPTService.BufDataset1AfterEdit(DataSet: TDataSet);
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
begin
  //EdSQL.Text := WMIBaseBoardInfo.AsJSon(True);
end;

procedure TVisAppWAPTService.FormCreate(Sender: TObject);
begin
  waptdb := TWAPTDB.Create(WaptDBPath);
  waptdb.OpenDB;
end;

procedure TVisAppWAPTService.Panel1Click(Sender: TObject);
begin
end;

end.

