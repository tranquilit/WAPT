unit uwaptexit;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, ComCtrls, ActnList, Buttons, sogrid, superobject;

type

  { TVisWaptExit }

  TVisWaptExit = class(TForm)
    actSkip: TAction;
    ActUpgrade: TAction;
    ActionList1: TActionList;
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    ImageList1: TImageList;
    Label1: TLabel;
    Memo1: TMemo;
    ProgressBar1: TProgressBar;
    GridTasks: TSOGrid;
    SODataSource1: TSODataSource;
    Timer1: TTimer;
    procedure actSkipExecute(Sender: TObject);
    procedure ActUpgradeExecute(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
    tasks : ISuperObject;
  end;

var
  VisWaptExit: TVisWaptExit;

implementation

uses tiscommon,waptcommon,soutils;
{$R *.lfm}

{ TVisWaptExit }

procedure TVisWaptExit.ActUpgradeExecute(Sender: TObject);
var
  aso: ISuperObject;
begin
  Timer1.Enabled := False;
  aso := WAPTLocalJsonGet('upgrade.json');
  Memo1.Text:=aso.AsJSon();
  tasks := aso['content'];
  GridTasks.Data := tasks;
end;

procedure TVisWaptExit.actSkipExecute(Sender: TObject);
begin
  Close;
end;

procedure TVisWaptExit.FormShow(Sender: TObject);
var
  aso: ISuperObject;
begin
  ActUpgrade.Enabled:=false;
  aso := WAPTLocalJsonGet('checkupgrades.json');
  if aso<>Nil then
  begin
    if aso['upgrades'].AsArray.Length = 0 then
    begin
      Memo1.Text:='Système à jour';
      //Close;
    end
    else
    begin
      ActUpgrade.Enabled:=True;
      Memo1.Text:= Join(#13#10, aso['upgrades']);
    end;
  end;
  tasks := WAPTLocalJsonGet('tasks_status.json');
  if tasks <>Nil then
    SODataSource1.Data := tasks;
  Timer1.Enabled := True;
end;

procedure TVisWaptExit.Timer1Timer(Sender: TObject);
var
  aso:ISuperObject;
begin
  Application.ProcessMessages;
  ProgressBar1.Position := ProgressBar1.Position+1;
  tasks := WAPTLocalJsonGet('tasks_status.json');
  if tasks <>Nil then
    SODataSource1.Data := tasks;

  aso := WAPTLocalJsonGet('checkupgrades.json');
  if aso<>Nil then
  begin
      if aso['upgrades'].AsArray.Length = 0 then
      begin
        Memo1.Text:='Système à jour';
        //Close;
      end
      else
      begin
        ActUpgrade.Enabled:=True;
        Memo1.Text:= Join(#13#10, aso['upgrades']);
      end;
  end;
  {
  if ProgressBar1.Position>=ProgressBar1.Max then
    ActUpgrade.Execute;
  }
end;

end.

