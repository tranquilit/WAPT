unit uwaptexit;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, LazFileUtils, Forms,
  Controls, Graphics, Dialogs, StdCtrls, ExtCtrls, ActnList, Buttons,
  superobject, DefaultTranslator, ComCtrls, uWaptExitRes, sogrid,uWAPTPollThreads,
  VirtualTrees, ImgList;

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
    CBSkipWindowsUpdates: TCheckBox;
    CBShowDetails: TCheckBox;
    EdRunning: TEdit;
    CustomLogo: TImage;
    GridPending: TSOGrid;
    GridPendingUpgrades: TSOGrid;
    LabDontShutdown: TLabel;
    Label1: TLabel;
    LabPendingUpgrades: TLabel;
    LabWaptUpgrades: TLabel;
    LabWUAUpgrades: TLabel;
    PanButtons: TPanel;
    ImageList1: TImageList;
    MemoLog: TListBox;
    PanDetailsLeft: TPanel;
    panTopDetails: TPanel;
    PanOut: TPanel;
    panTop: TPanel;
    PanProgress: TPanel;
    panHaut: TPanel;
    panBas: TPanel;
    ProgressBar: TProgressBar;
    Splitter1: TSplitter;
    Splitter2: TSplitter;
    Splitter3: TSplitter;
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
    procedure FormShow(Sender: TObject);
    procedure GridPendingUpgradesGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: Boolean; var ImageIndex: Integer;
      var ImageList: TCustomImageList);
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
    function GetPackageStatus(LastUpdateStatus: ISuperObject): ISuperObject;
    procedure OnCheckTasksThreadNotify(Sender: TObject);
    procedure OnCheckEventsThreadNotify(Sender: TObject);
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

    WaitingForUpgradeTasks: Boolean;
    WaitingCountDown: Boolean;

    WAPTServiceRunning:Boolean;
    AutoUpgradeTime: TDateTime;

    // If True, waptexit will wait for any pending tasks but will not trigger additional upgrade tasks
    DisableUpgrade: Boolean;

    // Prevent the count down timed auto upgrade
    DisableAutoUpgrade: Boolean;

    CheckTasksThread: TCheckTasksThread;
    CheckEventsThread: TCheckEventsThread;

    Function ShouldBeUpgraded:Boolean;
    Function WorkInProgress:Boolean;

    // running task
    property Running: ISuperObject read FRunning write SetRunning;
    property Pending: ISuperObject read FPending write SetPending;

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
  Result := AllowCancelUpgrade and (Running=Nil);
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

  {if (pending<>Nil) then
  begin
    if ProgressBar.Max=0 then
    begin
      ProgressBar.Max := pending.AsArray.Length;
      ProgressBar.Position := 0;
    end
    else
      ProgressBar.Position := ProgressBar.Max - pending.AsArray.Length;
  end;}
  Application.ProcessMessages;
end;

procedure TVisWaptExit.SetRunning(AValue: ISuperObject);
var
  Description: String;
begin
  if FRunning=AValue then Exit;

  if (AValue<>Nil) and ((FRunning=Nil) or (FRunning.I['id']<>AValue.I['id']))  then
  begin
    description := UTF8Encode(AValue.S['description']);
    if Length(description)>100 then
      EdRunning.Text := copy(description,1,100)+'...'
    else
      EdRunning.Text := description;

    if AValue['runstatus']<>Nil then
      MemoLog.Items.Text := UTF8Encode(AValue.S['runstatus']);
  end
  else if (AValue=Nil) and (FRunning<>Nil) then
    EdRunning.Text := '';

  FRunning:=AValue;
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
  ProgressBar.Style:=pbstNormal;
  WaitingForUpgradeTasks := False;
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
  if DisableUpgrade then
    Exit;
  DisableAutoUpgrade:=True;
  CountDown := 0;
  ActUpgrade.Caption:=rsLaunchSoftwareUpdate;
  WaitingForUpgradeTasks := True;
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
    ProgressBar.Style:=pbstMarquee;
    EdRunning.Text:=rsLaunchSoftwareUpdate;
    TTriggerWaptserviceAction.Create(@OnUpgradeTriggered,'upgrade.json?'+Join('&',args));
  end
  else
    MemoLog.Items.Add('Service not running');
end;

procedure TVisWaptExit.ActUpgradeUpdate(Sender: TObject);
begin
  ActUpgrade.Enabled:= not DisableUpgrade and (upgrades <> Nil) and (UpgradeTasks=Nil) and (not WaitingForUpgradeTasks);
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
  if Assigned(CheckEventsThread) and (not CheckEventsThread.Suspended) then
    CheckEventsThread.Terminate;
end;

procedure TVisWaptExit.FormCloseQuery(Sender: TObject; var CanClose: boolean);
begin
  if WAPTServiceRunning then
  begin
    if Not AllowCancelUpgrade and WorkInProgress then
    begin
      CanClose:=False;
      Exit;
    end;

    if WorkInProgress then
    begin
      CanClose:= AllowCancelUpgrade and ((Running=Nil) or (MessageDlg(rsConfirmCancelTask,Format(rsConfirmCancelRunningTask,[Running.S['description']]),
          mtConfirmation, [mbYes, mbNo, mbCancel],0) = mrYes));

      if CanClose then
      begin
        if Running<>Nil then
          WAPTLocalJsonGet('cancel_running_task.json');
        WAPTLocalJsonGet('cancel_all_tasks.json')
      end
    end
    else
      CanClose := True;
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
    DisableUpgrade := StrToBool(GetCmdParams('waptexit_disable_upgrade',ini.ReadString('global','waptexit_disable_upgrade','0')));
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

  WaitingCountDown:=True;

end;

procedure TVisWaptExit.FormDestroy(Sender: TObject);
begin
  FreeAndNil(CheckTasksThread);
  FreeAndNil(CheckEventsThread);
end;

Function TVisWaptExit.GetPackageStatus(LastUpdateStatus:ISuperObject):ISuperObject;
var
  pr,row,lremoves:ISuperObject;
  i: integer;
begin
  Result := TSuperObject.Create(stArray);
  i := 0;
  lremoves := LastUpdateStatus['pending.remove'];
  if Assigned(lremoves) then
    for pr in lremoves do
    begin
      Row := TSuperObject.Create(stObject);
      Row.I['id'] := i;;
      Row.S['install_status'] := 'REMOVE';;
      Row['package'] := pr;
      Result.AsArray.Add(row);
      inc(i);
    end;

  for pr in LastUpdateStatus['upgrades'] do
  begin
    Row := TSuperObject.Create(stObject);
    Row.I['id'] := i;;
    Row.S['install_status'] := 'INSTALL';;
    Row['package'] := pr;
    Result.AsArray.Add(row);
    inc(i);
  end;
end;

procedure TVisWaptExit.OnCheckWaptserviceNotify(Sender: TObject);
var
  aso,RunningTasks: ISuperObject;
begin
  aso := Nil;
  Upgrades := Nil;
  Removes := Nil;

  //Check if pending upgrades
  try
    WAPTServiceRunning:=(Sender as TCheckWaptservice).IsWaptServiceRunning;

    if WAPTServiceRunning then
    begin
      CheckTasksThread.Start;
      CheckEventsThread.Start;
    end
    else
    begin
      EdRunning.Text := rsWaptServiceNotRunning;
      Application.ProcessMessages;
      Sleep(1000);
    end;

    aso := (Sender as TCheckWaptservice).LastUpdateStatus;
    if aso<>Nil then
    begin
      Upgrades := aso['upgrades'];
      Removes := aso['pending.remove'];

      // running is not safe here
      RunningTasks := aso['running_tasks'];
      if Assigned(RunningTasks) and Assigned(RunningTasks.AsArray) and (RunningTasks.AsArray.Length>0) then
        Running := RunningTasks.AsArray[0];


      {$ifdef enterprise}
      wua_status := aso['wua_status'];
      wua_pending_count := aso['wua_pending_count'];
      {$else}
      wua_status := Nil;
      wua_pending_count := Nil;
      {$endif}

      if ShouldBeUpgraded then
      begin
        EdRunning.Text := rsWaptUpgradespending;
        Application.ProcessMessages;
      end;
    end;
  except
    on E:Exception do
    begin
      upgrades := Nil;
      Removes := Nil;
      wua_status := Nil;
      wua_pending_count := Nil;
      EdRunning.Text:=E.Message;
      Application.ProcessMessages;
      Sleep(1000);
    end;
  end;

  //check if upgrades
  if not ShouldBeUpgraded and not WorkInProgress then
    Application.terminate
  else
  begin
    if ShouldBeUpgraded then
    begin
      GridPendingUpgrades.Data := GetPackageStatus(aso);
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
      WaitingCountDown:=True;
    end;
  end
  else
  begin
    CountDown:=0;
    AutoUpgradeTime := Now;
  end;

  // waptservice is running so start the count down
  if not DisableUpgrade then
    Timer1.Enabled:=True
  else
    // wa have disable the start of upgrade so close now.
    if not WorkInProgress then
      Application.Terminate;
end;

procedure TVisWaptExit.OnCheckTasksThreadNotify(Sender: TObject);
var
  Tasks:ISuperObject;
begin
  try
    Tasks := (Sender as TCheckTasksThread).Tasks;
    if (Tasks <> Nil) and (Tasks.AsObject<>Nil) then
    begin
      if Tasks.AsObject.Exists('running') then
      begin
        running := Tasks['running'];
        if (running<>Nil) and (running.DataType=stNull) then
          running := Nil;
      end;

      if Tasks.AsObject.Exists('pending') then
      begin
        pending := Tasks['pending'];
        if (pending<>Nil) and (pending.DataType=stArray) and (pending.AsArray.Length=0) then
          pending := Nil;
      end;
    end;

    WAPTServiceRunning := (Sender as TCheckTasksThread).WaptServiceRunning;

    if not WorkInProgress and not WaitingCountDown then
    begin
      //MemoLog.Items.Add((Sender as TCheckTasksThread).Message);
      MemoLog.Items.Text := (Sender as TCheckTasksThread).Message;
      Close;
    end;

  except
    running := Nil;
    pending := Nil;
  end
end;

procedure TVisWaptExit.OnCheckEventsThreadNotify(Sender: TObject);
var
  lastevent,events:ISuperObject;
begin
  try
    events := (Sender as TCheckEventsThread).Events;
    if events <> Nil then
    begin
      if (events.AsArray<>Nil) and (events.AsArray.Length>0) then
      for lastEvent in events do
      begin
        case lastEvent.S['event_type'] of
          'PRINT': MemoLog.Items.Text := lastEvent.S['data'];
          'TASK_START','TASK_STATUS','TASK_FINISH':
            begin
              ProgressBar.max:=100;
              if Assigned(running) then
                EdRunning.Text:= UTF8Encode(running.S['description']+': '+lastEvent.S['data.runstatus'])
              else
                EdRunning.Text:= UTF8Encode(lastEvent.S['data.runstatus']);
              if lastevent.I['data.progress']>0 then
              begin
                ProgressBar.Style:=pbstNormal;
                ProgressBar.Position:=lastevent.I['data.progress']
              end
              else
                ProgressBar.Style:=pbstMarquee;
            end;
          'STATUS': GridPendingUpgrades.Data := GetPackageStatus(lastEvent['data']);
        end;
      end;
    end
    else
    begin
      // service has been stopped
      if WAPTServiceRunning and not (Sender as TCheckEventsThread).WaptServiceRunning then
      begin
        //MemoLog.Items.Add((Sender as TCheckEventsThread).Message);
        MemoLog.Items.Text := (Sender as TCheckEventsThread).Message;
        WAPTServiceRunning:=False;
        CheckEventsThread.Terminate;
        CheckTasksThread.Terminate;
        Close;
      end;
    end
  except
    running := Nil;
    pending := Nil;
  end
end;

procedure TVisWaptExit.actSkipExecute(Sender: TObject);
begin
  ActUpgrade.Enabled:=False;
  actSkip.Caption:=rsClosing;
  actSkip.Enabled:=False;
  running := Nil;
  pending := Nil;
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
    WaitingCountDown:=False;
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
  TCheckWaptservice.Create(@OnCheckWaptserviceNotify);
  EdRunning.Text := rsCheckingUpgrades;


  // Check running / pending tasks
  CheckTasksThread := TCheckTasksThread.Create(@OnCheckTasksThreadNotify);
  CheckEventsThread := TCheckEventsThread.Create(@OnCheckEventsThreadNotify);
end;


procedure TVisWaptExit.GridPendingUpgradesGetImageIndexEx(
  Sender: TBaseVirtualTree; Node: PVirtualNode; Kind: TVTImageKind;
  Column: TColumnIndex; var Ghosted: Boolean; var ImageIndex: Integer;
  var ImageList: TCustomImageList);
var
  reachable,install_status: ISuperObject;
  propname: String;
  aGrid:TSOGrid;
begin
  aGrid := (Sender as TSOGrid);
  propName:=TSOGridColumn(aGrid.Header.Columns[Column]).PropertyName;

  if propName='install_status' then
  begin
    install_status := aGrid.GetCellData(Node, 'install_status', nil);
    if (install_status <> nil) then
    begin
      case install_status.AsString of
        'OK': ImageIndex := 4;
        'NEED-UPGRADE': ImageIndex := 5;
        'ERROR-UPGRADE','ERROR','ERROR-INSTALL': ImageIndex := 6;
        'MISSING','INSTALL': ImageIndex := 7;
        'REMOVE': ImageIndex := 8;
        'RUNNING': ImageIndex := 9;
      end;
    end;
  end
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
    if not DisableUpgrade and ShouldBeUpgraded and (AutoUpgradeTime>1) and (Now >= AutoUpgradeTime) then
      ActUpgrade.Execute

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

