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
    procedure ActUpgradeUpdate(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
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

uses tiscommon,waptcommon,soutils,simpleinternet,tisstrings;
{$R *.lfm}

{ TVisWaptExit }

function WAPTLocalJsonGet(action: String;user:AnsiString='';password:AnsiString='';timeout:integer=1000): ISuperObject;
var
  strresult : String;
begin
  if StrLeft(action,1)<>'/' then
    action := '/'+action;
  strresult := retrieve(GetWaptLocalURL+action);
  Result := SO(strresult);
end;


procedure TVisWaptExit.ActUpgradeExecute(Sender: TObject);
var
  aso: ISuperObject;
begin
  Timer1.Enabled := False;
  try
    aso := WAPTLocalJsonGet('upgrade.json');
    Memo1.Text:=aso.AsJSon();
    tasks := aso['content'];
    GridTasks.Data := tasks;
    upgrades := Nil;
    ProgressBar1.Position := 0;
  finally
    Timer1.Enabled := True;
  end;
end;

procedure TVisWaptExit.ActUpgradeUpdate(Sender: TObject);
begin
  ActUpgrade.Enabled:=(tasks=Nil) or (tasks.AsArray.Length=0);
end;

procedure TVisWaptExit.FormCloseQuery(Sender: TObject; var CanClose: boolean);
begin
  if ((running<>Nil) and (running.dataType<>stNull)) or
      ((pending<>Nil) and (pending.AsArray.Length>0))  then
    WAPTLocalJsonGet('cancel_all_tasks.json');
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
  if ((upgrades=Nil) or (upgrades.AsArray.Length = 0)) and  ((running=Nil) or (running.DataType=stNull))  and ((pending = Nil) or (pending.AsArray.Length = 0)) then
   //Système à jour
    Application.terminate
  else
  begin
    ActUpgrade.Enabled:=True;
    Memo1.Text:= Join(#13#10, upgrades);
  end;
  Timer1.Enabled := True;
end;

procedure TVisWaptExit.Timer1Timer(Sender: TObject);
var
  aso:ISuperObject;
begin
  timer1.Enabled:=False;
  try
    // get current tasks manager status
    aso := WAPTLocalJsonGet('tasks.json');
    if aso <> Nil then
    begin
      running := aso['running'];
      if (running<>Nil) and (running.DataType=stNull) then
        running := Nil;
      pending := aso['pending'];
      if (pending<>Nil) and (pending.AsArray.Length=0) then
        pending := Nil;
    end
    else
    begin
      running := Nil;
      pending := Nil;
    end;

    //tasks are remaining
    if (upgrades = Nil) and (
      ((running<>Nil) and (running.dataType<>stNull)) or
      ((pending<>Nil) and (pending.AsArray.Length>0)))  then
    begin
      if (running<>Nil) and (running.DataType<>stNull) then
      begin
        ProgressBar1.Position:=running.I['progress'];
        Memo1.Lines.Text:=running.S['description']+#13#10+running.S['runstatus'];
      end;
      GridTasks.Data:=pending;
    end;

    //No tasks and no upgrades
    if ((running=Nil) or (Running.datatype=stNull)) and ((pending=Nil) or (pending.AsArray.Length=0)) and (upgrades=Nil) then
      Close;

    //upgrades are pending, launch upgrades after timeout expired or manual action
    if (upgrades<>Nil) then
    begin
      if ProgressBar1.Position>=ProgressBar1.Max then
      begin
        ActUpgrade.Execute;
        ProgressBar1.Position := 0;
      end
      else
        ProgressBar1.Position := ProgressBar1.Position+1;
    end;

  finally
    Timer1.Enabled:=True;
    Application.ProcessMessages;
  end;
end;

end.

