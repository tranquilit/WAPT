unit uVisAppWaptService;

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

