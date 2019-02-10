unit uwaptexit;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, LazFileUtils, Forms,
  Controls, Graphics, Dialogs, StdCtrls, ExtCtrls, ActnList, Buttons,
  superobject, DefaultTranslator, ComCtrls, uWaptExitRes, sogrid,uWAPTPollThreads,
  IdAntiFreeze;

type

  { TVisWaptExit }

  TVisWaptExit = class(TForm)
    ActStopCountDown: TAction;
    ActShowDetails: TAction;
    ActionList1: TActionList;
    actSkip: TAction;
    ActUpgrade: TAction;
    ButNotNow: TBitBtn;
    ButUpgradeNow: TBitBtn;
    CheckBox1: TCheckBox;
    CBSkipWindowsUpdates: TCheckBox;
    EdRunning: TEdit;
    GridPending: TSOGrid;
    CustomLogo: TImage;
    LabDontShutdown: TLabel;
    LabWaptUpgrades: TLabel;
    LabWUAUpgrades: TLabel;
    PanButtons: TPanel;
    ImageList1: TImageList;
    MemoLog: TListBox;
    PanOut: TPanel;
    panTop: TPanel;
    PanProgress: TPanel;
    panHaut: TPanel;
    panBas: TPanel;
    ProgressBar: TProgressBar;
    Splitter1: TSplitter;
    Timer1: TTimer;
    procedure ActShowDetailsExecute(Sender: TObject);
    procedure actSkipExecute(Sender: TObject);
    procedure actSkipUpdate(Sender: TObject);
    procedure ActStopCountDownExecute(Sender: TObject);
    procedure ActUpgradeExecute(Sender: TObject);
    procedure ActUpgradeUpdate(Sender: TObject);
    procedure ButUpgradeNowMouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure CBSkipWindowsUpdatesEnter(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormMouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure FormShow(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
  private
    { private declarations }
    FAllowCancelUpgrade: Boolean;
    FCountDown: Integer;
    FInitialCountDown: Integer;
    FPending: ISuperObject;
    FPriorities: String;
    FOnlyIfNotProcessRunning: Boolean;
    FInstallWUAUpdates: Boolean;
    FRunning: ISuperObject;
    procedure OnCheckTasksThreadNotify(Sender: TObject);
    procedure OnCheckWaptserviceNotify(Sender: TObject);
    procedure OnUpgradeTriggered(Sender: TObject);
    procedure SetCountDown(AValue: Integer);
    function  CheckAllowCancelUpgrade:Boolean;
    procedure SetInitialCountDown(AValue: Integer);
    procedure SetInstallWUAUpdates(AValue: Boolean);
    procedure SetPending(AValue: ISuperObject);
    procedure SetRunning(AValue: ISuperObject);
  public
    { public declarations }
    Upgrades,Removes,wua_status,wua_pending_count: ISuperObject;
    UpgradeTasks: ISuperObject;

    WAPTServiceRunning:Boolean;
    AutoUpgradeTime: TDateTime;

    DisableAutoUpgrade: Boolean;

    CheckTasksThread: TCheckTasksThread;

    Function ShouldBeUpgraded:Boolean;
    Function WorkInProgress:Boolean;

    // running task
    property running: ISuperObject read FRunning write SetRunning;
    property pending: ISuperObject read FPending write SetPending;

    property AllowCancelUpgrade:Boolean read FAllowCancelUpgrade write FAllowCancelUpgrade;
    property InitialCountDown:Integer read FInitialCountDown write SetInitialCountDown;
    property CountDown:Integer read FCountDown write SetCountDown;
    property Priorities: String read FPriorities write FPriorities;
    property OnlyIfNotProcessRunning: Boolean read FOnlyIfNotProcessRunning write FOnlyIfNotProcessRunning;
    property InstallWUAUpdates: Boolean read FInstallWUAUpdates write SetInstallWUAUpdates;
  end;

var
  VisWaptExit: TVisWaptExit;

implementation

uses soutils,IniFiles,waptcommon,tiscommon,typinfo,IdException,IdExceptionCore;
{$R *.lfm}
{$ifdef ENTERPRISE }
{$R res_enterprise.rc}
{$else}
{$R res_community.rc}
{$endif}

{ TVisWaptExit }


function  TVisWaptExit.CheckAllowCancelUpgrade:Boolean;
begin
  Result := AllowCancelUpgrade and ((running=Nil) or (Running.datatype=stNull));
end;

procedure TVisWaptExit.SetInitialCountDown(AValue: Integer);
begin
  if FInitialCountDown=AValue then Exit;
  FInitialCountDown:=AValue;
end;

procedure TVisWaptExit.SetInstallWUAUpdates(AValue: Boolean);
begin
  if FInstallWUAUpdates=AValue then Exit;
  FInstallWUAUpdates:=AValue;
end;

procedure TVisWaptExit.SetPending(AValue: ISuperObject);
begin
  if FPending=AValue then Exit;
  FPending:=AValue;

  GridPending.Data := pending;

  if (pending<>Nil) then
  begin
    if ProgressBar.Max=0 then
    begin
      ProgressBar.Max := pending.AsArray.Length;
      ProgressBar.Position := 0;
    end
    else
      ProgressBar.Position := ProgressBar.Max - pending.AsArray.Length;
  end;
  Application.ProcessMessages;
end;

procedure TVisWaptExit.SetRunning(AValue: ISuperObject);
var
  Description: String;
begin
  if FRunning=AValue then Exit;
  FRunning:=AValue;

  if (running<>Nil) then
  begin
    description := UTF8Encode(running.S['description']);
    if Length(description)>100 then
      EdRunning.Text := copy(description,1,100)+'...'
    else
      EdRunning.Text := description;
    MemoLog.Items.Text := UTF8Encode(running.S['runstatus']);
  end;
  Application.ProcessMessages;

end;

function GetWaptLocalURL: String;
begin
  result := format('http://127.0.0.1:%d',[waptservice_port]);
end;

function WaptIniFilename: Utf8String;
begin
  result := ExtractFilePath(ParamStr(0))+'wapt-get.ini';
end;


{ TCheckWaptservice }
type

{ TTriggerWaptserviceAction }

TTriggerWaptserviceAction = Class(TThread)
private
  FOnNotifyEvent: TNotifyEvent;
  procedure NotifyListener; Virtual;
  procedure SetOnNotifyEvent(AValue: TNotifyEvent);
public
  Action:String;
  Message:String;
  Tasks : ISuperObject;
  constructor Create(aNotifyEvent:TNotifyEvent;aAction:String='upgrade.json');
  procedure Execute; override;
  property OnNotifyEvent: TNotifyEvent read FOnNotifyEvent write SetOnNotifyEvent;
end;

{ TTriggerWaptserviceAction }

procedure TTriggerWaptserviceAction.NotifyListener;
begin
  if Assigned(FOnNotifyEvent) then
    FOnNotifyEvent(Self);
end;

procedure TTriggerWaptserviceAction.SetOnNotifyEvent(AValue: TNotifyEvent);
begin
  FOnNotifyEvent:=AValue;
end;

constructor TTriggerWaptserviceAction.Create(aNotifyEvent: TNotifyEvent;
  aAction: String);
begin
  inherited Create(False);
  OnNotifyEvent:=aNotifyEvent;
  Action := aAction;
  FreeOnTerminate:=True;
end;

procedure TTriggerWaptserviceAction.Execute;
begin
  try
    Tasks := WAPTLocalJsonGet(Action,'','',10000,Nil,3);
    Message := 'OK';
  except
    on E:EIdException do
    begin
      Tasks := Nil;
      Message :=  Format(rsErrorTriggeringTask,[E.Message]);
    end;
  end;
  Synchronize(@NotifyListener);
end;


procedure TVisWaptExit.OnUpgradeTriggered(Sender: TObject);
var
  aso: ISuperObject;
begin
  aso := (Sender as TTriggerWaptserviceAction).Tasks;
  if aso <> Nil then
  begin
    UpgradeTasks:= aso['content'];
    // be sure we don't close before getting new pending tasks with CheckTasksThread thread
    pending := UpgradeTasks;
    ProgressBar.max := ProgressBar.max + UpgradeTasks.AsArray.Length;

    ActUpgrade.Caption:=rsUpdatingSoftware;
    actSkip.Caption:=rsInterruptUpdate;
    ButUpgradeNow.Visible := False;
    LabWaptUpgrades.Visible := False;
    LabWUAUpgrades.Visible := False;
    LabDontShutdown.Visible := True;
  end
  else
  begin
    // something went wrong...
    UpgradeTasks:= Nil;
    //ShowMessage((Sender as TTriggerWaptserviceAction).Message);
    Close;
  end;
end;

procedure TVisWaptExit.ActUpgradeExecute(Sender: TObject);
var
  args: ISuperObject;
begin
  DisableAutoUpgrade:=True;
  CountDown := 0;
  ActUpgrade.Caption:=rsLaunchSoftwareUpdate;
  Application.ProcessMessages;

  if WAPTServiceRunning then
  begin
    args := TSuperObject.Create(stArray);
    if OnlyIfNotProcessRunning then
      args.AsArray.Add('only_if_not_process_running=1');
    if Priorities <> '' then
      args.AsArray.Add(Format('only_priorities=%s',[Priorities]));
    {$ifdef enterprise}
    if InstallWUAUpdates and not CBSkipWindowsUpdates.Checked then
      args.AsArray.Add(Format('install_wua_updates=1',[]));
    {$endif}
    TTriggerWaptserviceAction.Create(@OnUpgradeTriggered,'upgrade.json?'+Join('&',args));
  end
  else
    MemoLog.Items.Add('Service not running');
end;

procedure TVisWaptExit.ActUpgradeUpdate(Sender: TObject);
begin
  ActUpgrade.Enabled:= (upgrades <> Nil) and (UpgradeTasks=Nil);
end;

procedure TVisWaptExit.ButUpgradeNowMouseDown(Sender: TObject;
  Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
begin
  ActStopCountDown.execute;
end;

procedure TVisWaptExit.CBSkipWindowsUpdatesEnter(Sender: TObject);
begin
  ActStopCountDown.Execute;
end;

procedure TVisWaptExit.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin
  if Assigned(CheckTasksThread) and (not CheckTasksThread.Suspended) then
    CheckTasksThread.Terminate;
end;

procedure TVisWaptExit.FormCloseQuery(Sender: TObject; var CanClose: boolean);
begin
  if WAPTServiceRunning then
  begin
    if Not CheckAllowCancelUpgrade and WorkInProgress then
    begin
      CanClose:=False;
      Exit;
    end;

    if WorkInProgress then
      if CheckAllowCancelUpgrade then
        WAPTLocalJsonGet('cancel_all_tasks.json')
      else
        Canclose := False
  end
  else
    CanClose:=True;
end;

procedure TVisWaptExit.FormCreate(Sender: TObject);
var
  ini:TIniFile;
begin
  if FileExists(AppendPathDelim(WaptBaseDir)+'templates\waptexit-logo.png') then
    CustomLogo.Picture.LoadFromFile(AppendPathDelim(WaptBaseDir)+'templates\waptexit-logo.png')
  else
    CustomLogo.Picture.LoadFromResourceName(HINSTANCE,'WAPT_PNG',TPortableNetworkGraphic);

  ReadWaptConfig(WaptIniFilename);

  //Load config
  ini := TIniFile.Create(WaptIniFilename);
  try
    AllowCancelUpgrade := FindCmdLineSwitch('allow_cancel_upgrade') or ini.ReadBool('global','allow_cancel_upgrade',True);
    InitialCountDown := StrToInt(GetCmdParams('waptexit_countdown',ini.ReadString('global','waptexit_countdown','10')));
    Priorities := GetCmdParams('priorities',ini.ReadString('global','upgrade_priorities',''));
    OnlyIfNotProcessRunning :=  StrToBool(GetCmdParams('only_if_not_process_running',ini.ReadString('global','upgrade_only_if_not_process_running','0')));
    {$ifdef enterprise}
    InstallWUAUpdates := StrToBool(GetCmdParams('install_wua_updates',ini.ReadString('waptwua','install_at_shutdown','0')));
    CBSkipWindowsUpdates.Visible:=InstallWUAUpdates;
    {$else}
    CBSkipWindowsUpdates.Visible:=False;
    {$endif}
  finally
    ini.Free;
  end;

end;

procedure TVisWaptExit.FormDestroy(Sender: TObject);
begin
  FreeAndNil(CheckTasksThread);
end;

procedure TVisWaptExit.OnCheckWaptserviceNotify(Sender: TObject);
var
  aso: ISuperObject;
begin
  aso := Nil;
  upgrades := Nil;
  Removes := Nil;

  //Check if pending upgrades
  try
    WAPTServiceRunning:=(Sender as TCheckWaptservice).IsWaptServiceRunning;

    aso := (Sender as TCheckWaptservice).LastUpdateStatus;
    if aso<>Nil then
    begin
      upgrades := aso['upgrades'];
      Removes := aso['pending.remove'];
      {$ifdef enterprise}
      wua_status := aso['wua_status'];
      wua_pending_count := aso['wua_pending_count'];
      {$else}
      wua_status := Nil;
      wua_pending_count := Nil;
      {$endif}
    end;
  except
    on E:Exception do
    begin
      upgrades := Nil;
      Removes := Nil;
      wua_status := Nil;
      wua_pending_count := Nil;
    end;
  end;

  //check if upgrades
  if not ShouldBeUpgraded and not WorkInProgress then
    Application.terminate
  else
  begin
    if ShouldBeUpgraded then
    begin
      MemoLog.Items.Text:= Join(#13#10, upgrades);
      if Removes.AsArray.Length>0 then
        MemoLog.Items.Text:=MemoLog.Items.Text + #13#10 + Format(rsPendingRemoves,[Removes.AsArray.Length])+#13#10 +
            Join(#13#10, Removes);

      LabWaptUpgrades.Caption := Format(rsUpdatesAvailable,[upgrades.AsArray.Length+Removes.AsArray.Length]);
      {$ifdef enterprise}
      if (wua_status<>Nil) and (wua_pending_count<>Nil) then
      begin
        LabWUAUpgrades.Visible := True;
        LabWUAUpgrades.Caption := Format(rsWUAUpdatesAvailable,[wua_pending_count.AsInteger]);
      end;
      {$endif}
    end
  end;

  if CheckAllowCancelUpgrade then
  begin
    if AutoUpgradeTime < 1 then
    begin
      CountDown:=InitialCountDown;
      AutoUpgradeTime := Now + InitialCountDown / 3600.0 /24.0;
    end;
  end
  else
  begin
    CountDown:=0;
    AutoUpgradeTime := Now;
  end;
  Timer1.Enabled:=True;
end;

procedure TVisWaptExit.OnCheckTasksThreadNotify(Sender: TObject);
var
  aso:ISuperObject;
begin
  try
    aso := (Sender as TCheckTasksThread).Tasks;
    if aso <> Nil then
    begin
      running := aso['running'];
      if (running<>Nil) and (running.DataType=stNull) then
        running := Nil;
      pending := aso['pending'];
      if (pending<>Nil) and (pending.DataType=stArray) and (pending.AsArray.Length=0) then
        pending := Nil;
    end
    else
    begin
      running := Nil;
      pending := Nil;
      // service has been stopped
      if WAPTServiceRunning and not (Sender as TCheckTasksThread).WaptServiceRunning then
      begin
        MemoLog.Items.Add((Sender as TCheckTasksThread).Message);
        WAPTServiceRunning:=False;
        Close;
      end;
    end
  except
    running := Nil;
    pending := Nil;
  end
end;

procedure TVisWaptExit.FormMouseDown(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
begin
  ActStopCountDown.execute;
end;

procedure TVisWaptExit.actSkipExecute(Sender: TObject);
begin
  ActUpgrade.Enabled:=False;
  actSkip.Caption:=rsClosing;
  Application.ProcessMessages;
  Close;
end;

procedure TVisWaptExit.actSkipUpdate(Sender: TObject);
begin
  actSkip.Enabled:=CheckAllowCancelUpgrade;
end;

procedure TVisWaptExit.ActStopCountDownExecute(Sender: TObject);
begin
  if AllowCancelUpgrade then
  begin
    DisableAutoUpgrade:=True;
    CountDown:=0;
  end;
end;

procedure TVisWaptExit.ActShowDetailsExecute(Sender: TObject);
begin
  panBas.Visible:=ActShowDetails.Checked;
end;

function TVisWaptExit.ShouldBeUpgraded: Boolean;
begin
  Result := ((Upgrades <> Nil) and (Upgrades.AsArray <> Nil) and (Upgrades.AsArray.Length>0))
            or
            ((Removes <> Nil) and (Removes.AsArray <> Nil) and (Removes.AsArray.Length>0))
            {$ifdef enterprise}
            or
            (InstallWUAUpdates and Assigned(wua_status) and (wua_status.AsString <> 'OK') and
                                   Assigned(wua_pending_count) and (wua_pending_count.AsInteger > 0))
            {$endif}
            ;
end;

procedure TVisWaptExit.FormShow(Sender: TObject);
begin
  if not (GetServiceStatusByName('','WAPTService') in [ssRunning]) and not FindCmdLineSwitch('debug') then
  begin
    Close;
    Exit;
  end;

  ActShowDetails.Checked:=False;

  Upgrades := Nil;
  Removes := Nil;

  //Task
  running := Nil;
  pending := Nil;

  //when Upgrade button pressed
  UpgradeTasks := Nil;

  // Check service is running and list of upgrades in background at startup
  TCheckWaptservice.Create(@OnCheckWaptserviceNotify,3000);

  // Check running / pending tasks
  CheckTasksThread := TCheckTasksThread.Create(@OnCheckTasksThreadNotify);
  CheckTasksThread.Start;
end;

function TVisWaptExit.WorkInProgress: Boolean;
begin
  Result :=
      ((running<>Nil) and (running.dataType<>stNull)) or
      ((pending<>Nil) and (pending.dataType=stArray) and (pending.AsArray.Length>0))
end;

procedure TVisWaptExit.Timer1Timer(Sender: TObject);
begin
  timer1.Enabled:=False;
  try
    //No tasks and no upgrades
    if not WorkInProgress and (not ShouldBeUpgraded or (UpgradeTasks<>Nil)) then
      Close;

    //some upgrades are pending, launch upgrades after timeout expired or manual action
    if not DisableAutoUpgrade and ShouldBeUpgraded and (AutoUpgradeTime>1) and (Now >= AutoUpgradeTime) then
      ActUpgrade.Execute;

  finally
    if CountDown>0 then;
      CountDown := CountDown-1;
    Application.ProcessMessages;
    Timer1.Enabled := True;
  end;
end;

procedure TVisWaptExit.SetCountDown(AValue: Integer);
begin
  if FCountDown=AValue then Exit;
  FCountDown := AValue;
  if CountDown>0 then
  begin
    ActUpgrade.Caption:=Format(rsSoftwareUpdateIn,[IntToStr(FCountDown)]);
    FCountDown:=AValue;
  end
  else
    ActUpgrade.Caption:=rsLaunchSoftwareUpdate;
end;

end.

