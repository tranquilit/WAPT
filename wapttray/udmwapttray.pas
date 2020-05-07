unit uDMWAPTTray;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, LazFileUtils, ExtCtrls, Menus, ActnList, Controls,
  superobject, DefaultTranslator, Forms, uWaptTrayRes, LCLType;

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
    ApplicationProperties1: TApplicationProperties;
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
    Timer1: TTimer;
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
    procedure ApplicationProperties1EndSession(Sender: TObject);
    procedure ApplicationProperties1QueryEndSession(var Cancel: Boolean);
    procedure DataModuleCreate(Sender: TObject);
    procedure DataModuleDestroy(Sender: TObject);
    procedure PopupMenu1Close(Sender: TObject);
    procedure PopupMenu1Popup(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
    procedure TrayIcon1Click(Sender: TObject);
    procedure TrayIcon1DblClick(Sender: TObject);
    procedure TrayIcon1MouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
  private
    FLastUpdateStatus: ISuperObject;
    FtrayMode: TTrayMode;
    FWaptServiceRunning: Boolean;
    TaskInProgress: Boolean;
    InTrayDblClick: Boolean;
    function GetrayHint: String;
    procedure SetLastUpdateStatus(AValue: ISuperObject);
    procedure SettrayHint(AValue: String);
    procedure SetTrayIcon(idx: integer);
    procedure SettrayMode(AValue: TTrayMode);
    procedure SetWaptServiceRunning(AValue: Boolean);
    function  WaptConsoleFileName: String;
    procedure OnCheckEventsThreadNotify(Sender: TObject);
    procedure OnRunWaptServiceThreadNotify(Sender: TObject);
    { private declarations }
  public
    { public declarations }
    CheckEventsThread:TThread;
    CheckUpgradesThead:TThread;

    lastServiceMessage:TDateTime;
    LastEventId:Integer;

    popupvisible:Boolean;
    notify_user:Boolean;
    lastButton:TMouseButton;

    CurrentTask: String;

    procedure ShowBalloon(Msg:String;BalloonFlags:TBalloonFlags=bfNone);

    property LastUpdateStatus: ISuperObject read FLastUpdateStatus write SetLastUpdateStatus;
    property WaptServiceRunning:Boolean read FWaptServiceRunning write SetWaptServiceRunning;
    property trayMode:TTrayMode read FtrayMode write SettrayMode;
    property trayHint:String read GetrayHint write SettrayHint;

  end;

var
  DMWaptTray: TDMWaptTray;

implementation
uses LCLIntf,dialogs,windows,graphics,tiscommon,tisinifiles,
    waptcommon,waptutils,soutils,tisstrings,IdException,uWAPTPollThreads,
    Win32Int;

//Function ShutdownBlockReasonCreate(Handle: hWnd;pwszReason: LPCWSTR): Bool; StdCall; External 'user32';
//Function ShutdownBlockReasonDestroy(Handle: hWnd): Bool; StdCall; External 'user32';

{$R *.lfm}

type

  { TCheckUpgradesThread }

  TCheckUpgradesThread = Class(TThread)
  private
    IsWaptServiceRunning:Boolean;
    LastUpdateStatus : ISuperObject;
    procedure UpdateTasks;
  public
    PollTimeout:Integer;
    DMTray:TDMWaptTray;
    constructor Create(aDMWaptTray:TDMWaptTray);
    procedure Execute; override;
  end;


{ TCheckWaptservice }

procedure TCheckUpgradesThread.UpdateTasks;
begin
  DMTray.WaptServiceRunning := IsWaptServiceRunning;
  DMTray.LastUpdateStatus := LastUpdateStatus;
end;

constructor TCheckUpgradesThread.Create(aDMWaptTray: TDMWaptTray);
begin
  inherited Create(True);
  DMTray := aDMWaptTray;
  PollTimeout:=10000;

end;

procedure TCheckUpgradesThread.Execute;
begin
  While not Terminated do
  begin
    try
      LastUpdateStatus := WAPTLocalJsonGet('checkupgrades.json','','',200);
      IsWaptServiceRunning:=True;
    except
      on E:EIdException do
      begin
        IsWaptServiceRunning:=False;
        LastUpdateStatus := Nil;
      end;
    end;
    Synchronize(@UpdateTasks);
    Sleep(PollTimeout);
  end;
end;

{ TVisWAPTTray }

procedure TDMWaptTray.ActShowStatusExecute(Sender: TObject);
begin
  //OpenDocument(IncludeTrailingPathDelimiter(WaptBaseDir)+'waptself.exe');
  OpenDocument(GetWaptLocalURL+'/status');
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
    res := WAPTLocalJsonGet('update.json?notify_user=1');
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
    res := WAPTLocalJsonGet('upgrade.json?notify_user=1');
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
    res := WAPTLocalJsonGet('waptupgrade.json?notify_user=1');
  except
    on E:EIdException do
      WaptServiceRunning:=False;
  end;
end;

procedure TDMWaptTray.ApplicationProperties1EndSession(Sender: TObject);
begin
  //MessageBox(0,'Test end session: mises à jour','WAPT exit',0);
  //ShutdownBlockReasonDestroy(Application.MainFormHandle);
end;

procedure TDMWaptTray.ApplicationProperties1QueryEndSession(var Cancel: Boolean
  );
begin
  {Cancel := True;
  Application.MainForm.WindowState:=wsMaximized;
  ShutdownBlockReasonCreate(Application.MainFormHandle,'Mises a jour a faire');

  ShowMessage(IntToStr(GetLastError()));
  MessageBox(0,'Test query end session: mises à jour','WAPT exit',0);}
end;

procedure TDMWaptTray.DataModuleCreate(Sender: TObject);
var
  ActionName,SHiddenActions:String;
  HiddenActions:TDynStringArray;
  Action:TAction;
  amenuitem,prevvisible: TMenuItem;
  i:Integer;

begin
  lastServiceMessage:=Now;

  //UniqueInstance1.Enabled:=True;
  if lowercase(GetUserName)='system' then exit;
  CheckEventsThread :=TCheckEventsThread.Create(@OnCheckEventsThreadNotify);
  CheckEventsThread.Start;

  CheckUpgradesThead := TCheckUpgradesThread.Create(Self);
  CheckUpgradesThead.Start;

  notify_user:= IniReadBool(WaptIniFilename,'global','notify_user',False );

  SHiddenActions := IniReadString(WaptIniFilename,'global','hidden_wapttray_actions','');
  if SHiddenActions<>'' then
  begin
    HiddenActions := StrSplit(SHiddenActions,',');
    for ActionName in HiddenActions do
    begin
      Action := FindComponent('Act'+ActionName) as TAction;
      if Action <> Nil then
        Action.Visible:=False;
      if Action = ActForceRegister then
        Action.Visible:=Action.Visible and (waptcommon.GetWaptServerURL <>'');

      if Action = ActLaunchWaptConsole then
        Action.Visible:=Action.Visible and FileExists(AppendPathDelim(ExtractFileDir(ParamStr(0)))+'waptconsole.exe');
    end;
  end;
  for i:=PopupMenu1.Items.Count-1 downto 0 do
  begin
    amenuitem := PopupMenu1.Items[i];
    if amenuitem.IsLine and (i>0) and not popupMenu1.Items[i-1].Visible then
      amenuitem.Visible:=False;
  end;
end;

procedure TDMWaptTray.DataModuleDestroy(Sender: TObject);
begin
  if Assigned(CheckEventsThread) then
  begin
    TerminateThread(CheckEventsThread.Handle,0);
    FreeAndNil(CheckEventsThread);
  end;
  if Assigned(CheckUpgradesThead) then
  begin
    TerminateThread(CheckUpgradesThead.Handle,0);
    FreeAndNil(CheckUpgradesThead);
  end;
end;

procedure TDMWaptTray.PopupMenu1Close(Sender: TObject);
begin
  PopupVisible := false;
end;

procedure TDMWaptTray.PopupMenu1Popup(Sender: TObject);
begin
  MenuWaptVersion.Caption:=FileToString(ExtractFilePath(ParamStr(0))+'version-full');
  if FileExists(ExtractFilePath(ParamStr(0))+'revision.txt') then
    MenuWaptVersion.Caption:=MenuWaptVersion.Caption+' rev '+FileToString(ExtractFilePath(ParamStr(0))+'revision.txt');

  // to avoid message popups when popup menu is displayed
  PopupVisible := True;
end;

procedure TDMWaptTray.Timer1Timer(Sender: TObject);
begin
  Timer1.Enabled:=False;
  if not InTrayDblClick then
    TrayIcon1.ShowBalloonHint;
end;

procedure TDMWaptTray.TrayIcon1Click(Sender: TObject);
begin
  if not InTrayDblClick then
  begin
    Timer1.Interval:=GetDoubleClickTime+700;
    Timer1.Enabled := False;
    //Timer1.Enabled := True;
  end;
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
    res := WAPTLocalJsonGet('cancel_running_task.json?notify_user=1');
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
    res := WAPTLocalJsonGet('register.json?notify_user=1');
  except
    on E:EIdException do
      WaptServiceRunning:=False;
  end;
end;

procedure TDMWaptTray.ActForceRegisterUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled := WaptServiceRunning;
end;

procedure TDMWaptTray.ActLaunchWaptConsoleExecute(Sender: TObject);
var
  cmd:UnicodeString;
begin
  cmd := UTF8Decode(WaptConsoleFileName);
  ShellExecuteW(0,'open',PWideChar(cmd),Nil,Nil,0);
end;

function TDMWaptTray.WaptConsoleFileName: String;
begin
  result:=AppendPathDelim(ExtractFileDir(ParamStr(0)))+'waptconsole.exe';
end;

procedure TDMWaptTray.OnCheckEventsThreadNotify(Sender: TObject);
var
  Step,EventType,msg,desc,summary:String;
  runstatus:String;
  running,upgrades,errors,taskresult : ISuperObject;
  task_notify_user:Boolean;
  Events, Event,EventData:ISuperObject;
begin
  Events :=  (Sender as TCheckEventsThread).Events;

  If Events <> Nil then
    for Event in Events do
    try
      WaptServiceRunning:=True;
      lastServiceMessage := Now;
      EventType := Event.S['event_type'];
      EventData := Event['data'];
      if (EventType='STATUS') and not TaskInProgress then
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
        trayHint := msg;
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
          if taskresult.B['notify_user'] then
            task_notify_user:=True
          else
            task_notify_user:=False;
        end
        else
          task_notify_user:=False;

        if Step='ERROR' then
        begin
          TaskInProgress:=False;
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
          TaskInProgress:=True;
          CurrentTask:=desc;
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
          TaskInProgress:=True;
          trayMode:= tmRunning;
          trayHint := Format(rsTaskInProgress,[desc])+#13#10+taskresult.S['runstatus']+#13#10+Format('%.0f%%',[taskresult.D['progress']]);
          TrayIcon1.BalloonFlags:=bfInfo;
          if not popupvisible and notify_user and task_notify_user then
            TrayIcon1.ShowBalloonHint;
        end
        else
        if Step='FINISH' then
        begin
          trayMode:= tmOK;
          trayHint := format(rsTaskDone, [desc, summary]);
          TrayIcon1.BalloonFlags:=bfInfo;
          if not popupvisible and notify_user and task_notify_user then
            TrayIcon1.ShowBalloonHint;
          CurrentTask:='';;
          TaskInProgress:=False;
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
          end;
          CurrentTask:='';;
        end;
      end;
    finally
    end;
end;

procedure TDMWaptTray.OnRunWaptServiceThreadNotify(Sender: TObject);
begin
  with (Sender as TRunWaptService) do
  begin
    if StatusMessage.StartsWith('ERROR') then
      Self.ShowBalloon(StatusMessage,bfError)
    else
      Self.ShowBalloon(StatusMessage,bfInfo);
  end;
end;

procedure TDMWaptTray.ShowBalloon(Msg: String; BalloonFlags: TBalloonFlags);
begin
  if TrayIcon1.BalloonHint<>msg then
  begin
    TrayIcon1.BalloonHint := msg;
    TrayIcon1.BalloonFlags:=bfNone;
    if not popupvisible and notify_user then
      TrayIcon1.ShowBalloonHint;
  end;
end;

procedure TDMWaptTray.ActLocalInfoExecute(Sender: TObject);
begin
  OpenURL(GetWaptLocalURL+'/inventory');
end;

procedure TDMWaptTray.ActQuitExecute(Sender: TObject);
begin
  if Assigned(CheckEventsThread) then
    CheckEventsThread.Terminate;
  Application.Terminate;
end;

procedure TDMWaptTray.ActReloadConfigExecute(Sender: TObject);
var
  res:ISuperObject;
begin
  try
    res := WAPTLocalJsonGet('reload_config.json?notify_user=1');
  except
    on E:EIdException do
      WaptServiceRunning:=False;
  end;
end;

procedure TDMWaptTray.ActServiceEnableExecute(Sender: TObject);
begin
  ActServiceEnable.Checked:=not ActServiceEnable.Checked;
  TRunWaptService.Create(@OnRunWaptServiceThreadNotify,ActServiceEnable.Checked);
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

procedure TDMWaptTray.SetLastUpdateStatus(AValue: ISuperObject);
var
  UpgradesCount,RemovesCount,WUACount:Integer;
  Msg: String;
begin
  if LastUpdateStatus=AValue then Exit;
  FLastUpdateStatus:=AValue;
  // {"wua_status": "SCANNING",
  //  "errors": [], "wua_pending_count": 15, "running_tasks": [],
  //  "upgrades": [], "date": "2019-02-07T18:09:44.044000",
  //  "pending":
  //           {"upgrade": [], "additional": [], "install": [], "remove": ["compta2"]}}
  if Assigned(FLastUpdateStatus) then
  begin
    Msg := '';
    UpgradesCount := FLastUpdateStatus.A['upgrades'].Length;
    if UpgradesCount>0 then
      Msg := Msg + Format(rsPendingInstalls,[ Join(',',FLastUpdateStatus['upgrades']) ]);
    RemovesCount := FLastUpdateStatus.A['pending.remove'].Length;
    if RemovesCount>0 then
      Msg := Msg + Format(rsPendingRemoves,[ Join(',',FLastUpdateStatus['pending.remove']) ]);
    if not TaskInProgress  then
    begin
      if (UpgradesCount+RemovesCount>0) then
        trayMode:=tmUpgrades
      else
        trayMode:=tmOK;
      trayHint:=msg;
    end;
  end;
end;

procedure TDMWaptTray.SettrayHint(AValue: String);
begin
  if TrayIcon1.Hint<>AValue then
  begin
    if notify_user then
      TrayIcon1.ShowBalloonHint;
    TrayIcon1.Hint := AValue;
    TrayIcon1.BalloonHint := AValue;
  end;
end;

procedure TDMWaptTray.SettrayMode(AValue: TTrayMode);
begin
  if FtrayMode=AValue then Exit;
  FtrayMode:=AValue;
  if FTraymode = tmOK then
    SetTrayIcon(0)
  else if FTraymode = tmRunning then
  begin
    TrayIcon1.Icons := TrayRunning;
    TrayIcon1.Animate:=True;
  end
  else if FTraymode = tmUpgrades then
  begin
    TrayIcon1.Icons := TrayUpdate;
    TrayIcon1.Animate:=True;
  end
  else if FTraymode = tmErrors then
  begin
    TrayIcon1.Icons := TrayUpdate;
    TrayIcon1.Animate:=False;
    SetTrayIcon(1);
  end;
end;

procedure TDMWaptTray.SetWaptServiceRunning(AValue: Boolean);
begin
  if not FWaptServiceRunning then
  begin
    trayMode:=tmErrors;
    trayHint:=rsWaptServiceTerminated;
  end;
  if (FWaptServiceRunning<>AValue) and AValue then
  begin
    if not TaskInProgress then
      trayMode := tmOK;
    trayHint:=rsWaptServiceStarted;
  end;
  FWaptServiceRunning:=AValue;
end;

procedure TDMWaptTray.TrayIcon1DblClick(Sender: TObject);
var
  res:ISuperObject;
begin
  try
    Timer1.Enabled:=False;
    InTrayDblClick:=True;
    if lastButton=mbLeft then
    try
        res := WAPTLocalJsonGet('update.json?notify_user=1');
        if (res<>Nil) and  (pos('ERROR',uppercase(res.AsJSon ))<=0) then
          TrayIcon1.BalloonHint:=rsChecking
        else
          TrayIcon1.BalloonHint:=rsErrorWhileChecking;
        //if notify_user then
        TrayIcon1.ShowBalloonHint;
    except
      on E:Exception do
        begin
          trayHint := E.Message;
          trayMode:=tmErrors;
        end;
    end;
  finally
    InTrayDblClick:=False;
  end;
end;

procedure TDMWaptTray.TrayIcon1MouseDown(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
begin
  LastButton:=Button;
end;

end.

