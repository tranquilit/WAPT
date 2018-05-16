unit uDMWAPTTray;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, LazFileUtils, ExtCtrls, Menus, ActnList, Controls,
  superobject, DefaultTranslator, IdAntiFreeze, uWaptTrayRes;

type

  TTrayMode = (tmOK,tmRunning,tmUpgrades,tmErrors);

  { TDMWaptTray }
  TDMWaptTray = class(TDataModule)
    ActConfigure: TAction;
    ActForceRegister: TAction;
    ActCancelAllTasks: TAction;
    ActCancelRunningTask: TAction;
    ActServiceEnable: TAction;
    ActReloadConfig: TAction;
    ActShowTasks: TAction;
    ActSessionSetup: TAction;
    ActLocalInfo: TAction;
    ActWaptUpgrade: TAction;
    ActLaunchWaptConsole: TAction;
    ActionList1: TActionList;
    ActQuit: TAction;
    ActShowMain: TAction;
    ActShowStatus: TAction;
    ActUpdate: TAction;
    ActUpgrade: TAction;
    MenuItem10: TMenuItem;
    MenuItem12: TMenuItem;
    MenuItem13: TMenuItem;
    MenuItem14: TMenuItem;
    MenuItem15: TMenuItem;
    MenuItem16: TMenuItem;
    MenuItem17: TMenuItem;
    MenuItem18: TMenuItem;
    MenuItem19: TMenuItem;
    MenuItem20: TMenuItem;
    MenuItem21: TMenuItem;
    MenuItem22: TMenuItem;
    MenuItem23: TMenuItem;
    MenuItem11: TMenuItem;
    MenuItem7: TMenuItem;
    MenuItem8: TMenuItem;
    MenuItem9: TMenuItem;
    MenuWaptVersion: TMenuItem;
    TrayUpdate: TImageList;
    TrayRunning: TImageList;
    MenuItem1: TMenuItem;
    MenuItem2: TMenuItem;
    MenuItem4: TMenuItem;
    MenuItem5: TMenuItem;
    MenuItem6: TMenuItem;
    PopupMenu1: TPopupMenu;
    TrayIcon1: TTrayIcon;
    procedure ActCancelAllTasksExecute(Sender: TObject);
    procedure ActCancelRunningTaskExecute(Sender: TObject);
    procedure ActConfigureExecute(Sender: TObject);
    procedure ActForceRegisterExecute(Sender: TObject);
    procedure ActForceRegisterUpdate(Sender: TObject);
    procedure ActLaunchWaptConsoleExecute(Sender: TObject);
    procedure ActLaunchWaptConsoleUpdate(Sender: TObject);
    procedure ActLocalInfoExecute(Sender: TObject);
    procedure ActQuitExecute(Sender: TObject);
    procedure ActReloadConfigExecute(Sender: TObject);
    procedure ActServiceEnableExecute(Sender: TObject);
    procedure ActServiceEnableUpdate(Sender: TObject);
    procedure ActSessionSetupExecute(Sender: TObject);
    procedure ActShowStatusExecute(Sender: TObject);
    procedure ActShowTasksExecute(Sender: TObject);
    procedure ActUpdateExecute(Sender: TObject);
    procedure ActUpdateUpdate(Sender: TObject);
    procedure ActUpgradeExecute(Sender: TObject);
    procedure ActWaptUpgradeExecute(Sender: TObject);
    procedure DataModuleCreate(Sender: TObject);
    procedure DataModuleDestroy(Sender: TObject);
    procedure PopupMenu1Close(Sender: TObject);
    procedure PopupMenu1Popup(Sender: TObject);
    procedure TrayIcon1DblClick(Sender: TObject);
    procedure TrayIcon1MouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
  private
    Ftasks: ISuperObject;
    FtrayMode: TTrayMode;
    FWaptServiceRunning: Boolean;
    function GetrayHint: String;
    procedure Settasks(AValue: ISuperObject);
    procedure SettrayHint(AValue: String);
    procedure SetTrayIcon(idx: integer);
    procedure SettrayMode(AValue: TTrayMode);
    procedure SetWaptServiceRunning(AValue: Boolean);
    function  WaptConsoleFileName: String;
    procedure pollerEvent(Events:ISuperObject);
    { private declarations }
  public
    { public declarations }
    check_thread:TThread;
    check_waptservice:TThread;

    lastServiceMessage:TDateTime;
    LastEventId:Integer;

    popupvisible:Boolean;
    notify_user:Boolean;
    lastButton:TMouseButton;

    property tasks:ISuperObject read Ftasks write Settasks;
    property WaptServiceRunning:Boolean read FWaptServiceRunning write SetWaptServiceRunning;
    property trayMode:TTrayMode read FtrayMode write SettrayMode;
    property trayHint:String read GetrayHint write SettrayHint;

  end;

var
  DMWaptTray: TDMWaptTray;

implementation
uses LCLIntf,Forms,dialogs,windows,graphics,tiscommon,tisinifiles,
    waptcommon,waptwinutils,soutils,tisstrings,IdException;

{$R *.lfm}

type

  { TCheckWaptservice }

  TCheckWaptservice = Class(TThread)
  private
    WaptServiceRunning:Boolean;
    tasks : ISuperObject;
    procedure UpdateTasks;
  public
    PollTimeout:Integer;
    DMTray:TDMWaptTray;
    constructor Create(aDMWaptTray:TDMWaptTray);
    procedure Execute; override;
  end;


  { TPollThread }

  TPollThread = Class(TThread)
    procedure HandleMessage;

  public
    PollTimeout:Integer;

    DMTray:TDMWaptTray;
    Events: ISuperObject;
    LastReadEventId: Integer;

    constructor Create(aDMWaptTray:TDMWaptTray);
    destructor Destroy; override;
    procedure Execute; override;
  end;

{ TCheckWaptservice }

procedure TCheckWaptservice.UpdateTasks;
begin
  DMTray.WaptServiceRunning := WaptServiceRunning;
  DMTray.Tasks := tasks;
end;

constructor TCheckWaptservice.Create(aDMWaptTray: TDMWaptTray);
begin
  inherited Create(True);
  DMTray := aDMWaptTray;
  PollTimeout:=3000;
end;

procedure TCheckWaptservice.Execute;
begin
  While not Terminated do
  begin
    try
      //if CheckOpenPort(waptservice_port,'127.0.0.1',500) then
        tasks := WAPTLocalJsonGet('tasks_status.json','','',200);
        WaptServiceRunning:=True;
    except
      on E:EIdException do
      begin
        WaptServiceRunning:=False;
        tasks := Nil;
      end;
    end;
    Synchronize(@UpdateTasks);
    Sleep(PollTimeout);
  end;
end;

{ TPollThread }

procedure TPollThread.HandleMessage;
begin
  if Assigned(DMTray) then
    DMTray.pollerEvent(Events);
end;

constructor TPollThread.Create(aDMWaptTray:TDMWaptTray);
begin
  inherited Create(True);
  DMTray := aDMWaptTray;
end;

destructor TPollThread.Destroy;
begin
  inherited Destroy;
end;

procedure TPollThread.Execute;
begin
  while not Terminated do
  try
    Events := WAPTLocalJsonGet(Format('events?last_read=%d',[LastReadEventId]),'','',10000,Nil,0);
    if Events <> Nil then
    begin
      If Events.AsArray.Length>0 then
        LastReadEventId := Events.AsArray.O[Events.AsArray.Length-1].I['id'];
    end;
    Synchronize(@HandleMessage);
  except
    if not Terminated then
      Sleep(PollTimeout);
  end;
end;

{ TVisWAPTTray }

procedure TDMWaptTray.ActShowStatusExecute(Sender: TObject);
begin
  OpenURL(GetWaptLocalURL+'/status');
end;

procedure TDMWaptTray.ActShowTasksExecute(Sender: TObject);
begin
  OpenURL(GetWaptLocalURL+'/tasks');
end;

procedure TDMWaptTray.ActUpdateExecute(Sender: TObject);
var
  res : ISUperObject;
begin
  try
    res := WAPTLocalJsonGet('update.json');
  except
    on E:EIdException do
      WaptServiceRunning:=False;
  end;
end;

procedure TDMWaptTray.ActUpdateUpdate(Sender: TObject);
begin
  // 30s
  (Sender as TAction).Enabled := WaptServiceRunning;
end;

procedure TDMWaptTray.ActUpgradeExecute(Sender: TObject);
var
  res : ISUperObject;
begin
  try
    res := WAPTLocalJsonGet('upgrade.json');
  except
    on E:EIdException do
      WaptServiceRunning:=False;
  end;
end;

procedure TDMWaptTray.ActWaptUpgradeExecute(Sender: TObject);
var
  res : ISuperObject;
begin
  try
    res := WAPTLocalJsonGet('waptupgrade.json');
  except
    on E:EIdException do
      WaptServiceRunning:=False;
  end;
end;

procedure TDMWaptTray.DataModuleCreate(Sender: TObject);
var
  ActionName,SHiddenActions:String;
  HiddenActions:TDynStringArray;
  Action:TAction;


begin
  lastServiceMessage:=Now;

  //UniqueInstance1.Enabled:=True;
  if lowercase(GetUserName)='system' then exit;
  check_thread :=TPollThread.Create(Self);
  check_thread.Start;

  check_waptservice := TCheckWaptservice.Create(Self);
  check_waptservice.Start;

  notify_user:= IniReadBool(WaptIniFilename,'global','notify_user',Win32MajorVersion<=6 );

  ActForceRegister.Visible := waptcommon.GetWaptServerURL <>'';

  SHiddenActions := IniReadString(WaptIniFilename,'global','hidden_wapttray_actions','');
  if SHiddenActions<>'' then
  begin
    HiddenActions := StrSplit(SHiddenActions,',');
    for ActionName in HiddenActions do
    begin
      Action := FindComponent('Act'+ActionName) as TAction;
      if Action <> Nil then
        Action.Visible:=False;
    end;
  end;
end;

procedure TDMWaptTray.DataModuleDestroy(Sender: TObject);
begin
  if Assigned(check_thread) then
  begin
    TerminateThread(check_thread.Handle,0);
    FreeAndNil(check_thread);
  end;
  if Assigned(check_waptservice) then
  begin
    TerminateThread(check_waptservice.Handle,0);
    FreeAndNil(check_waptservice);
  end;
end;

procedure TDMWaptTray.PopupMenu1Close(Sender: TObject);
begin
  PopupVisible := false;
end;

procedure TDMWaptTray.PopupMenu1Popup(Sender: TObject);
begin
  MenuWaptVersion.Caption:=GetApplicationVersion(WaptgetPath);
  if FileExists(ExtractFilePath(ParamStr(0))+'revision.txt') then
    MenuWaptVersion.Caption:=MenuWaptVersion.Caption+' rev '+FileToString(ExtractFilePath(ParamStr(0))+'revision.txt');

  // to avoid message popups when popup menu is displayed
  PopupVisible := True;
end;

procedure TDMWaptTray.ActConfigureExecute(Sender: TObject);
begin
  RunAsAdmin(0,'cmd.exe','/C start notepad "'+WaptIniFilename+'"');
end;

procedure TDMWaptTray.ActCancelAllTasksExecute(Sender: TObject);
var
  res : ISuperObject;
begin
  try
    res := WAPTLocalJsonGet('cancel_all_tasks.json');
  except
    on E:EIdException do
      WaptServiceRunning:=False;
  end;
end;

procedure TDMWaptTray.ActCancelRunningTaskExecute(Sender: TObject);
var
  res : ISuperObject;
begin
  try
    res := WAPTLocalJsonGet('cancel_running_task.json');
  except
    on E:EIdException do
      WaptServiceRunning:=False;
  end;
end;

procedure TDMWaptTray.ActForceRegisterExecute(Sender: TObject);
var
  res : ISuperObject;
begin
  try
    res := WAPTLocalJsonGet('register.json');
  except
    on E:EIdException do
      WaptServiceRunning:=False;
  end;
end;

procedure TDMWaptTray.ActForceRegisterUpdate(Sender: TObject);
begin
  ActForceRegister.Visible := waptcommon.GetWaptServerURL <>'';
  (Sender as TAction).Enabled := WaptServiceRunning;
end;

procedure TDMWaptTray.ActLaunchWaptConsoleExecute(Sender: TObject);
var
  cmd:UnicodeString;
begin
  cmd := UTF8Decode(WaptConsoleFileName);
  ShellExecuteW(0,'open',PWideChar(cmd),Nil,Nil,0);
end;

procedure TDMWaptTray.ActLaunchWaptConsoleUpdate(Sender: TObject);
begin
  ActLaunchWaptConsole.Visible:=FileExists(AppendPathDelim(ExtractFileDir(ParamStr(0)))+'waptconsole.exe');
end;

function TDMWaptTray.WaptConsoleFileName: String;
begin
  result:=AppendPathDelim(ExtractFileDir(ParamStr(0)))+'waptconsole.exe';
end;

// Called whenever a zeromq message is published
procedure TDMWaptTray.pollerEvent(Events:ISuperObject);
var
  Step,EventType,msg,desc,summary:String;
  runstatus:String;
  running,upgrades,errors,taskresult : ISuperObject;
  task_notify_user:Boolean;
  Event,EventData:ISuperObject;
begin
  If Events <> Nil then
    for Event in Events do
    try
      WaptServiceRunning:=True;
      lastServiceMessage := Now;
      EventType := Event.S['event_type'];
      EventData := Event['data'];
      if EventType='STATUS' then
      begin
        runstatus := UTF8Encode(EventData.S['runstatus']);
        running := EventData['running_tasks'];
        upgrades := EventData['upgrades'];
        errors := EventData['errors'];
        if (running<>Nil) and (running.AsArray.Length>0) then
        begin
          trayMode:=tmRunning;
          trayHint:=format(rsInstalling, [utf8Encode(running.AsString)]);
        end
        else
        if runstatus<>'' then
        begin
          trayHint:=runstatus;
          trayMode:=tmRunning;
        end
        else
        if (errors<>Nil) and (errors.AsArray.Length>0) then
        begin
          trayHint:= format(rsErrorFor,[utf8Decode(Join(#13#10,errors))]);
          trayMode:=tmErrors;
        end
        else
        if (upgrades<>Nil) and (upgrades.AsArray.Length>0) then
        begin
          trayMode:=tmUpgrades;
          trayHint:= format(rsUpdatesAvailableFor,[utf8Encode(soutils.join(#13#10'-',upgrades))]);
        end
        else
        begin
          trayHint:='';
          trayMode:=tmOK;
        end;
      end
      else
      if EventType='PRINT' then
      begin
        msg := UTF8Encode(EventData.AsString);
        if TrayIcon1.BalloonHint<>msg then
        begin
          if TrayIcon1.BalloonHint<>msg then
          begin
            TrayIcon1.BalloonHint := msg;
            TrayIcon1.BalloonFlags:=bfNone;
            if not popupvisible and notify_user then
              TrayIcon1.ShowBalloonHint;
          end;
        end;
      end
      else
      if EventType.StartsWith('TASK_') then
      begin
        Step := EventType.Substring(5);
        taskresult := EventData;
        desc := UTF8Encode(taskresult.S['description']);
        summary := UTF8Encode(taskresult.S['summary']);

        if taskresult<>Nil then
        begin
          trayHint:= UTF8Encode(taskresult.S['runstatus']);
          if taskresult.B['notify_user'] then
            task_notify_user:=True
          else
            task_notify_user:=False;
        end
        else
        begin
          task_notify_user:=False;
          trayHint := '';
        end;

        if Step='ERROR' then
        begin
          trayMode:= tmErrors;
          if taskresult<>Nil then
            TrayIcon1.BalloonHint := format(rsErrorFor, [desc])
          else
            TrayIcon1.BalloonHint := rsError;
          TrayIcon1.BalloonFlags:=bfError;
          if not popupvisible and notify_user and task_notify_user then
            TrayIcon1.ShowBalloonHint;
        end
        else
        if Step='START' then
        begin
          trayMode:= tmRunning;
          if taskresult<>Nil then
            TrayIcon1.BalloonHint :=  format(rsTaskStarted, [desc])
          else
            TrayIcon1.BalloonHint := '';

          TrayIcon1.BalloonFlags:=bfInfo;
          if not popupvisible and notify_user and task_notify_user then
            TrayIcon1.ShowBalloonHint;
        end
        else
        if (Step='PROGRESS') or (Step='STATUS') then
        begin
          trayMode:= tmRunning;
          TrayIcon1.BalloonHint := desc+#13#10+Format('%.0f%%',[taskresult.D['progress']]);
          TrayIcon1.BalloonFlags:=bfInfo;
          if not popupvisible and notify_user and task_notify_user then
            TrayIcon1.ShowBalloonHint;
        end
        else
        if Step='FINISH' then
        begin
          trayMode:= tmOK;
          TrayIcon1.BalloonHint := format(rsTaskDone, [desc, summary]);
          TrayIcon1.BalloonFlags:=bfInfo;
          if not popupvisible and task_notify_user then
            TrayIcon1.ShowBalloonHint;
        end
        else
        if Step='CANCEL' then
        begin
          trayMode:= tmErrors;
          if taskresult.DataType = stObject then
          begin
             TrayIcon1.BalloonHint := utf8Encode(format(rsCanceling, [taskresult.S['description']]));
             TrayIcon1.BalloonFlags:=bfWarning;
             if not popupvisible and notify_user and task_notify_user  then
                TrayIcon1.ShowBalloonHint;
          end
          else
          begin
            TrayIcon1.BalloonHint := utf8Encode(rsNoTaskCanceled);
            TrayIcon1.BalloonFlags:=bfInfo;
            if not popupvisible and notify_user and task_notify_user  then
              TrayIcon1.ShowBalloonHint;
          end
        end;
      end;
    finally
    end;
end;

procedure TDMWaptTray.ActLocalInfoExecute(Sender: TObject);
begin
  OpenURL(GetWaptLocalURL+'/inventory');
end;

procedure TDMWaptTray.ActQuitExecute(Sender: TObject);
begin
  if Assigned(check_thread) then
    check_thread.Terminate;
  Application.Terminate;
end;

procedure TDMWaptTray.ActReloadConfigExecute(Sender: TObject);
var
  res:ISuperObject;
begin
  try
    res := WAPTLocalJsonGet('reload_config.json');
  except
    on E:EIdException do
      WaptServiceRunning:=False;
  end;
end;

procedure TDMWaptTray.ActServiceEnableExecute(Sender: TObject);
var
  res:String;
begin
  ActServiceEnable.Checked :=  GetServiceStatusByName('','waptservice') <> ssStopped;
  if ActServiceEnable.Checked then
  begin
    Run('net stop waptservice');
    lastServiceMessage:=0;
    ActServiceEnable.Update;
  end
  else
  begin
    res := Run('net start waptservice');
    lastServiceMessage:=Now;
    ActServiceEnable.Update;
  end;
end;

procedure TDMWaptTray.ActServiceEnableUpdate(Sender: TObject);
begin
  ActServiceEnable.Checked := WaptServiceRunning;
end;

procedure TDMWaptTray.ActSessionSetupExecute(Sender: TObject);
var
  res : String;
begin
  try
    res := Run(UTF8Decode(WaptgetPath+' session-setup ALL'),'',120*1000);
    ShowMessage(rsPackageConfigDone)
  except
    MessageDlg(rsError,rsPackageConfigError,mtError,[mbOK],0);
  end
end;

procedure TDMWaptTray.SetTrayIcon(idx:integer);
var
  lBitmap: TBitmap;
begin
  TrayIcon1.Animate:=False;
  lBitmap := TBitmap.Create;
  try
    TrayUpdate.GetBitmap(idx, lBitmap);
    TrayIcon1.Icon.Assign(lBitmap);
    TrayIcon1.InternalUpdate();
  finally
    lBitmap.Free;
  end;
end;

function TDMWaptTray.GetrayHint: String;
begin
  Result := TrayIcon1.Hint;
end;

procedure TDMWaptTray.Settasks(AValue: ISuperObject);
begin
  if Ftasks=AValue then Exit;
  Ftasks:=AValue;
end;

procedure TDMWaptTray.SettrayHint(AValue: String);
begin
  if TrayIcon1.Hint<>AValue then
  begin
    TrayIcon1.Hint := AValue;
    TrayIcon1.BalloonHint := AValue;
    {if not popupvisible and (AValue<>'') and notify_user then
      TrayIcon1.ShowBalloonHint;}
  end;
end;

procedure TDMWaptTray.SettrayMode(AValue: TTrayMode);
begin
  if FtrayMode=AValue then Exit;
  FtrayMode:=AValue;
  if FTraymode = tmOK then
    SetTrayIcon(0)
  else
  if FTraymode = tmRunning then
  begin
    TrayIcon1.Icons := TrayRunning;
    TrayIcon1.Animate:=True;
  end
  else
  if FTraymode = tmUpgrades then
  begin
    TrayIcon1.Icons := TrayUpdate;
    TrayIcon1.Animate:=True;
  end
  else
  if FTraymode = tmErrors then
  begin
    TrayIcon1.Icons := TrayUpdate;
    TrayIcon1.Animate:=False;
    SetTrayIcon(1);
  end;
end;

procedure TDMWaptTray.SetWaptServiceRunning(AValue: Boolean);
begin
  if FWaptServiceRunning=AValue then Exit;
  FWaptServiceRunning:=AValue;
  if not FWaptServiceRunning then
  begin
    trayMode:=tmErrors;
    trayHint:=rsWaptServiceTerminated;
  end;
end;

procedure TDMWaptTray.TrayIcon1DblClick(Sender: TObject);
var
  res:ISuperObject;
begin
  if lastButton=mbLeft then
  try
    res := WAPTLocalJsonGet('update.json');
    if (res<>Nil) and  (pos('ERROR',uppercase(res.AsJSon ))<=0) then
      TrayIcon1.BalloonHint:=rsChecking
    else
      TrayIcon1.BalloonHint:=rsErrorWhileChecking;
    if notify_user then
      TrayIcon1.ShowBalloonHint;
  except
    on E:Exception do
      begin
        TrayIcon1.BalloonHint := E.Message;
        trayMode:=tmErrors;
      end;
  end;
end;

procedure TDMWaptTray.TrayIcon1MouseDown(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
begin
  LastButton:=Button;
end;

end.

