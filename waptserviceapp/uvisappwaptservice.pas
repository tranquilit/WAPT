unit uVisAppWaptService;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, BufDataset, FileUtil, Forms, Controls, Graphics, Dialogs, db;

type

  { TForm1 }

  TForm1 = class(TForm)
    procedure BufDataset1AfterEdit(DataSet: TDataSet);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.lfm}

{ TForm1 }

procedure TForm1.BufDataset1AfterEdit(DataSet: TDataSet);
begin

end;

end.

