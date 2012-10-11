unit uVisAppWaptService;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, BufDataset, FileUtil, Forms, Controls, Graphics, Dialogs,
  ExtCtrls, StdCtrls, DBGrids, db, sqldb, Sqlite3DS;

type

  { TVisAppWAPTService }

  TVisAppWAPTService = class(TForm)
    Datasource1: TDatasource;
    ButSQL: TButton;
    DBGrid1: TDBGrid;
    EdSQL: TMemo;
    Panel1: TPanel;
    query: TSQLQuery;
    procedure BufDataset1AfterEdit(DataSet: TDataSet);
    procedure ButSQLClick(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisAppWAPTService: TVisAppWAPTService;

implementation

uses WaptUnit;

{$R *.lfm}

{ TVisAppWAPTService }

procedure TVisAppWAPTService.BufDataset1AfterEdit(DataSet: TDataSet);
begin

end;

procedure TVisAppWAPTService.ButSQLClick(Sender: TObject);
begin
  query.Close;
  query.SQL.text := EdSQL.Text;
  query.Open;
end;

end.

