unit uwaptexit;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, IDEWindowIntf, fpspreadsheetgrid, Forms,
  Controls, Graphics, Dialogs, StdCtrls, ExtCtrls, ActnList, Buttons,
  superobject, DefaultTranslator, ComCtrls, Grids, uWaptExitRes, sogrid;

type

  { TVisWaptExit }

  TVisWaptExit = class(TForm)
    ActShowDetails: TAction;
    ActionList1: TActionList;
    actSkip: TAction;
    ActUpgrade: TAction;
    BitBtn1: TBitBtn;
    ButUpgradeNow: TBitBtn;
    CheckBox1: TCheckBox;
    EdRunning: TEdit;
    GridPending: TSOGrid;
    Image1: TImage;
    LabDontShutdown: TLabel;
    LabIntro: TLabel;
    PanButtons: TPanel;
    ImageList1: TImageList;
    MemoLog: TMemo;
    panTop: TPanel;
    PanProgress: TPanel;
    panHaut: TPanel;
    panBas: TPanel;
    ProgressBar: TProgressBar;
    Timer1: TTimer;
    procedure ActShowDetailsExecute(Sender: TObject);
    procedure actSkipExecute(Sender: TObject);
    procedure actSkipUpdate(Sender: TObject);
    procedure ActUpgradeExecute(Sender: TObject);
    procedure ActUpgradeUpdate(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
  private
    FCountDown: Integer;
    FInitialCountDown: Integer;
    procedure SetCountDown(AValue: Integer);
    { private declarations }
    function  allow_cancel_upgrade:Boolean;
    procedure SetInitialCountDown(AValue: Integer);
  public
    { public declarations }
    upgrades,tasks,running,pending : ISuperObject;
    // wait for waptservice answer in seconds
    waptservice_timeout: Integer;
    property InitialCountDown:Integer read FInitialCountDown write SetInitialCountDown;
    property CountDown:Integer read FCountDown write SetCountDown;
  end;

var
  VisWaptExit: TVisWaptExit;

implementation

uses soutils,IniFiles,waptcommon,uScaleDPI;
{$R *.lfm}

{ TVisWaptExit }

const FAllow_cancel_upgrade:Boolean = True;

function  TVisWaptExit.allow_cancel_upgrade:Boolean;
begin
  Result := FAllow_cancel_upgrade and ((running=Nil) or (Running.datatype=stNull));
end;

procedure TVisWaptExit.SetInitialCountDown(AValue: Integer);
begin
  if FInitialCountDown=AValue then Exit;
  FInitialCountDown:=AValue;
end;

function GetWaptLocalURL: String;
begin
  result := format('http://127.0.0.1:%d',[waptservice_port]);
end;

function WaptIniFilename: Utf8String;
begin
  result := ExtractFilePath(ParamStr(0))+'wapt-get.ini';
end;

procedure TVisWaptExit.ActUpgradeExecute(Sender: TObject);
var
  aso: ISuperObject;
begin
  Timer1.Enabled := False;
  try
    aso := WAPTLocalJsonGet('upgrade.json','','',waptservice_timeout*1000);
    MemoLog.Text:=aso.AsJSon();
    tasks := aso['content'];
    pending := tasks;
    ProgressBar.Max:=tasks.AsArray.Length;
    ProgressBar.Position:=0;
    //GridTasks.Data := tasks;
    upgrades := Nil;
    CountDown := 0;
    ActUpgrade.Caption:=rsUpdatingSoftware;
    actSkip.Caption:=rsInterruptUpdate;
    ButUpgradeNow.Visible := False;
    LabIntro.Visible := False;
    LabDontShutdown.Visible := True;
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
  if  Not allow_cancel_upgrade and
       ( ((upgrades<>Nil) and (upgrades.AsArray.Length>0)) or
         ((running<>Nil) and (running.dataType<>stNull)) or
         ((pending<>Nil) and (pending.AsArray.Length>0))
       ) then
  begin
      CanClose:=False;
      Exit;
  end;

  if ((running<>Nil) and (running.dataType<>stNull)) or
      ((pending<>Nil) and (pending.AsArray.Length>0))  then

    if allow_cancel_upgrade then
      WAPTLocalJsonGet('cancel_all_tasks.json','','',waptservice_timeout*1000)
    else
      Canclose := False
end;

procedure TVisWaptExit.FormCreate(Sender: TObject);
var
  ini:TIniFile;
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
  ScaleImageList(ImageList1,96);
  waptservice_timeout := 2;

  //Load config
  ini := TIniFile.Create(WaptIniFilename);
  try
    Fallow_cancel_upgrade := ini.ReadBool('global','allow_cancel_upgrade',allow_cancel_upgrade);
    waptservice_timeout := ini.ReadInteger('global','waptservice_timeout',2);
    InitialCountDown := ini.ReadInteger('global','waptexit_countdown',10);
  finally
    ini.Free;
  end;
end;

procedure TVisWaptExit.actSkipExecute(Sender: TObject);
begin
  Close;
end;

procedure TVisWaptExit.actSkipUpdate(Sender: TObject);
begin
  actSkip.Enabled:=allow_cancel_upgrade;
end;

procedure TVisWaptExit.ActShowDetailsExecute(Sender: TObject);
begin
  panBas.Visible:=ActShowDetails.Checked;
end;

procedure TVisWaptExit.FormShow(Sender: TObject);
var
  aso: ISuperObject;
begin
  ActShowDetails.Checked:=False;

  aso := Nil;
  upgrades := Nil;
  tasks := Nil;
  running := Nil;
  pending := Nil;

  ActUpgrade.Enabled:=false;

  //Check if pending upgrades
  try
    aso := WAPTLocalJsonGet('checkupgrades.json','','',waptservice_timeout*1000);
    if aso<>Nil then
      upgrades := aso['upgrades']
    else
      upgrades := Nil;

    //check if running or pending tasks.
    aso := WAPTLocalJsonGet('tasks.json','','',waptservice_timeout*1000);
    if aso<>Nil then
    begin
      running := aso['running'];;
      pending := aso['pending'];
      GridPending.data := pending;
    end;

    //check if upgrades
    if ((upgrades=Nil) or (upgrades.AsArray.Length = 0)) and  ((running=Nil) or (running.DataType=stNull))  and ((pending = Nil) or (pending.AsArray.Length = 0)) then
     //Système à jour
      Application.terminate
    else
    begin
      ActUpgrade.Enabled:=True;
      MemoLog.Text:= Join(#13#10, upgrades);
    end;
    if allow_cancel_upgrade then
      CountDown:=InitialCountDown
    else
      CountDown:=0;
    Timer1.Enabled := True;

  except
    application.Terminate;
  end;
end;

procedure TVisWaptExit.Timer1Timer(Sender: TObject);
var
  aso:ISuperObject;
begin
  timer1.Enabled:=False;
  try
    // get current tasks manager status
    aso := WAPTLocalJsonGet('tasks.json','','',waptservice_timeout*1000);
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
      ((pending<>Nil) and (pending.AsArray.Length>0)))
    then
    begin
      GridPending.Data := pending;
      if (running<>Nil) and (running.DataType<>stNull) then
      begin
        //ProgressBar.Position:=running.I['progress'];
        EdRunning.Text := running.S['description'];
        MemoLog.Lines.Text := running.S['runstatus'];
      end;

      //GridTasks.Data:=pending;
    end;

    //No tasks and no upgrades
    if ((running=Nil) or (Running.datatype=stNull)) and ((pending=Nil) or (pending.AsArray.Length=0)) and (upgrades=Nil) then
      Close;

    if (pending<>Nil) then
      ProgressBar.Position:=ProgressBar.Max - pending.AsArray.Length;

    //upgrades are pending, launch upgrades after timeout expired or manual action
    if (upgrades<>Nil) then
    begin
      if CountDown<=0 then
      begin
        ActUpgrade.Execute;
        //ProgressBar.Position := 0;
      end
      else
        //ProgressBar.Position := ProgressBar.Position+1;
        CountDown:=CountDown-1;
    end;

  finally
    Timer1.Enabled:=True;
    Application.ProcessMessages;
  end;
end;

procedure TVisWaptExit.SetCountDown(AValue: Integer);
begin
  if FCountDown=AValue then Exit;
  FCountDown := AValue;
  if CountDown>0 then
  begin
    ActUpgrade.Caption:=Format(rsSoftwareUpdateIn,[IntToStr(CountDown)]);
    FCountDown:=AValue;
  end
  else
    ActUpgrade.Caption:=rsLaunchSoftwareUpdate;
end;

end.

