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
    upgrades,tasks,running,pending : ISuperObject;
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
  aso := WAPTLocalJsonGet('upgrade.json');
  Memo1.Text:=aso.AsJSon();
  tasks := aso['content'];
  GridTasks.Data := tasks;
  upgrades := Nil;
end;

procedure TVisWaptExit.actSkipExecute(Sender: TObject);
begin
  Close;
end;

procedure TVisWaptExit.FormShow(Sender: TObject);
var
  aso: ISuperObject;
begin
  aso := Nil;
  upgrades := Nil;
  tasks := Nil;
  running := Nil;
  pending := Nil;

  ActUpgrade.Enabled:=false;

  //Check if pending upgrades
  aso := WAPTLocalJsonGet('checkupgrades.json','','',10);
  if aso<>Nil then
    upgrades := aso['upgrades']
  else
    upgrades := Nil;

  //check if running or pending tasks.
  aso := WAPTLocalJsonGet('tasks.json','','',10);
  if aso<>Nil then
  begin
    running := aso['running'];
    pending := aso['pending'];
  end;

  //check if upgrades
  if ((upgrades =Nil) or (upgrades.AsArray.Length = 0)) and  ((running=Nil) or (running.DataType=stNull))  and ((pending = Nil) or (pending.AsArray.Length = 0)) then
  begin
   //Système à jour
    Memo1.Text:='Système à jour';
    Application.terminate;
  end
  else
  begin
    ActUpgrade.Enabled:=True;
    Memo1.Text:= Join(#13#10, aso['upgrades']);
  end;
  Timer1.Enabled := True;
end;

procedure TVisWaptExit.Timer1Timer(Sender: TObject);
var
  aso:ISuperObject;

begin
  timer1.Enabled:=False;
  try
    aso := WAPTLocalJsonGet('tasks.json');
    if aso <> Nil then
    begin
      running := aso['running'];
      pending := aso['pending'];
    end
    else
    begin
      running := Nil;
      pending := Nil;
    end;

    if ((running=Nil) or (Running.datatype=stNull)) and (pending=Nil) and (Tasks=Nil) and (upgrades=Nil) then
      Application.terminate;

    if ProgressBar1.Position>=ProgressBar1.Max then
    begin
      ActUpgrade.Execute;
      ProgressBar1.Position := 0;
    end
    else
      ProgressBar1.Position := ProgressBar1.Position+1;

    if (upgrades = Nil) and ((running<>Nil) or (pending<>Nil))  then
    begin
      if running.DataType<>stNull then
      begin
        ProgressBar1.Position:=running.I['progress'];
        Memo1.Lines.Text:=running.S['description']+#13#10+running.S['runstatus'];
      end;
      GridTasks.Data:=pending;
    end;
  finally
    Timer1.Enabled:=True;
    Application.ProcessMessages;
  end;
end;

end.

