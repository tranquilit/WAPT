unit uDMWAPTTray;

// dans cet ordre impérativement
{$mode delphiunicode}
{$codepage UTF8}

interface

uses
  Classes, SysUtils, FileUtil, ExtCtrls, Menus, ActnList, Controls,
  zmqapi, superobject, DefaultTranslator, uWaptTrayRes;

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
    MenuItem3: TMenuItem;
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
    procedure Timer1Timer(Sender: TObject);
    procedure TrayIcon1DblClick(Sender: TObject);
    procedure TrayIcon1MouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
  private
    Ftasks: ISuperObject;
    FtrayMode: TTrayMode;
    FWaptServiceRunning: Boolean;
    function GetrayHint: WideString;
    procedure Settasks(AValue: ISuperObject);
    procedure SettrayHint(AValue: WideString);
    procedure SetTrayIcon(idx: integer);
    procedure SettrayMode(AValue: TTrayMode);
    procedure SetWaptServiceRunning(AValue: Boolean);
    function  WaptConsoleFileName: String;
    procedure pollerEvent(message:TStringList);
    { private declarations }
  public
    { public declarations }
    check_thread:TThread;
    check_waptservice:TThread;

    lastServiceMessage:TDateTime;
    popupvisible:Boolean;
    notify_user:Boolean;
    lastButton:TMouseButton;

    current_task:ISuperObject;


    property tasks:ISuperObject read Ftasks write Settasks;
    property WaptServiceRunning:Boolean read FWaptServiceRunning write SetWaptServiceRunning;
    property trayMode:TTrayMode read FtrayMode write SettrayMode;
    property trayHint:WideString read GetrayHint write SettrayHint;

  end;

var
  DMWaptTray: TDMWaptTray;

implementation
uses LCLIntf,Forms,dialogs,windows,graphics,tiscommon,
    waptcommon,tisinifiles,soutils,UnitRedirect,tisstrings,tishttp,IdException,
    uWaptRes;

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


  { TZMQPollThread }

  TZMQPollThread = Class(TThread)
    procedure HandleMessage;

  public
    PollTimeout:Integer;
    zmq_context:TZMQContext;
    zmq_socket :TZMQSocket;

    DMTray:TDMWaptTray;
    message : TStringList;
    msg:Utf8String;

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
  PollTimeout:=5000;
end;

procedure TCheckWaptservice.Execute;
var
  newStatus:Boolean;
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
    Synchronize(UpdateTasks);
    Sleep(PollTimeout);
  end;
end;

{ TZMQPollThread }

procedure TZMQPollThread.HandleMessage;
begin
  if Assigned(DMTray) then
    DMTray.pollerEvent(message);
end;

constructor TZMQPollThread.Create(aDMWaptTray:TDMWaptTray);
begin
  inherited Create(True);
  message := TStringList.Create;
  DMTray := aDMWaptTray;
  // create ZMQ context.
  zmq_context := TZMQContext.Create;

  zmq_socket := zmq_context.Socket( stSub );
  zmq_socket.RcvHWM:= 10000;
  zmq_socket.SndHWM:= 10000;
  zmq_socket.connect( 'tcp://127.0.0.1:'+inttostr(zmq_port));
  //zmq_socket.Subscribe('TASKS');
  zmq_socket.Subscribe('');
  {zmq_socket.Subscribe('INFO');
  zmq_socket.Subscribe('TASKS');
  zmq_socket.Subscribe('PRINT');
  zmq_socket.Subscribe('CRITICAL');
  zmq_socket.Subscribe('WARNING');
  zmq_socket.Subscribe('STATUS');}
end;

destructor TZMQPollThread.Destroy;
begin
  message.Free;

  if Assigned(zmq_socket) then
    FreeAndNil(zmq_socket);
  if Assigned(zmq_context) then
    FreeAndNil(zmq_context);

  inherited Destroy;
end;

procedure TZMQPollThread.Execute;
var
  res : integer;
  part:Utf8String;
begin
  while not Terminated do
  begin
    //zmq_socket.recv(message);
    res := zmq_socket.recv(msg);
    while zmq_socket.RcvMore do
    begin
      res := zmq_socket.recv(part);
      msg:=msg+#13#10+part;
    end;
    message.Text:=msg;
    Synchronize(HandleMessage);
    {if not Terminated then
      Sleep(PollTimeout);}
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
begin
  lastServiceMessage:=Now;

  //UniqueInstance1.Enabled:=True;
  if lowercase(GetUserName)='system' then exit;
  check_thread :=TZMQPollThread.Create(Self);
  check_thread.Start;

  check_waptservice := TCheckWaptservice.Create(Self);
  check_waptservice.Start;

  notify_user := True;

  ActForceRegister.Visible := waptcommon.GetWaptServerURL <>'';

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
  if FileExists(ExtractFilePath(ParamStr(0))+'version') then
    MenuWaptVersion.Caption:=MenuWaptVersion.Caption+' rev '+FileToString(ExtractFilePath(ParamStr(0))+'version');

  // to avoid message popups when popup menu is displayed
  PopupVisible := True;
end;

procedure TDMWaptTray.Timer1Timer(Sender: TObject);
begin
  {if (Now - lastServiceMessage > 1/24/3600 * 30)  then
  begin
    trayMode:=tmErrors;
    trayHint:='Service inaccessible';
  end;}
end;

procedure TDMWaptTray.ActConfigureExecute(Sender: TObject);
begin
  //OpenDocument(WaptIniFilename);
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
  cmd:WideString;
begin
  cmd := WaptConsoleFileName;
  ShellExecuteW(0,Pchar('open'),PChar(cmd),Nil,Nil,0);
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
procedure TDMWaptTray.pollerEvent(message:TStringList);
var
  msg,msg_type,topic:String;
  bh,progress,runstatus:String;
  upgrade_status,running,upgrades,errors,taskresult,task,tasks : ISuperObject;
  task_notify_user:Boolean;
begin
  try
    WaptServiceRunning:=True;
    lastServiceMessage := Now;
    if message.Count>0 then
    begin
      msg_type := message[0];
      message.Delete(0);
      msg := message.Text;
      // changement hint et balloonhint
      if (msg_type='WARNING') or (msg_type='CRITICAL') then
      begin
          TrayIcon1.BalloonHint := UTF8Encode(msg);
          TrayIcon1.BalloonFlags:=bfError;
          if not popupvisible and notify_user then
            TrayIcon1.ShowBalloonHint;
      end
      else
      if msg_type='STATUS' then
      begin
        upgrade_status := SO(msg);
        runstatus := upgrade_status.S['runstatus'];
        running := upgrade_status['running_tasks'];
        upgrades := upgrade_status['upgrades'];
        errors := upgrade_status['errors'];
        if (running<>Nil) and (running.AsArray.Length>0) then
        begin
          trayMode:=tmRunning;
          trayHint:=UTF8Encode(format(rsInstalling, [running.AsString]));
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
          trayHint:=UTF8Encode(format(rsErrorFor,[Join(#13#10,errors)]));
          trayMode:=tmErrors;
        end
        else
        if (upgrades<>Nil) and (upgrades.AsArray.Length>0) then
        begin
          trayMode:=tmUpgrades;
          trayHint:=UTF8Encode(format(rsUpdatesAvailableFor,[soutils.join(#13#10'-',upgrades)]));
        end
        else
        begin
          trayHint:='';
          trayMode:=tmOK;
        end;
      end
      else
      if msg_type='PRINT' then
      begin
        if TrayIcon1.BalloonHint<>msg then
        begin
          if TrayIcon1.BalloonHint<>msg then
          begin
            TrayIcon1.BalloonHint := UTF8Encode(msg);
            TrayIcon1.BalloonFlags:=bfNone;
            if not popupvisible and notify_user then
              TrayIcon1.ShowBalloonHint;
          end;
        end;
      end
      else
      if msg_type='TASKS' then
      begin
        topic := message[0];
        message.Delete(0);
        msg := message.Text;
        taskresult := SO(message.Text);
        if taskresult<>Nil then
        begin
          trayHint:=taskresult.S['runstatus'];
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

        if topic='ERROR' then
        begin
          trayMode:= tmErrors;
          current_task := Nil;
          if taskresult<>Nil then
            TrayIcon1.BalloonHint := UTF8Encode(format(rsErrorFor, [taskresult.S['description']]))
          else
            TrayIcon1.BalloonHint := rsError;
          TrayIcon1.BalloonFlags:=bfError;
          if not popupvisible and task_notify_user then
            TrayIcon1.ShowBalloonHint;
        end
        else
        if topic='START' then
        begin
          trayMode:= tmRunning;
          if taskresult<>Nil then
            TrayIcon1.BalloonHint := UTF8Encode(format(rsTaskStarted, [taskresult.S['description']]))
          else
            TrayIcon1.BalloonHint := '';

          TrayIcon1.BalloonFlags:=bfInfo;
          current_task := taskresult;
          if not popupvisible and task_notify_user then
            TrayIcon1.ShowBalloonHint;
        end
        else
        if topic='PROGRESS' then
        begin
          trayMode:= tmRunning;
          TrayIcon1.BalloonHint := UTF8Encode(taskresult.S['description']+#13#10+Format('%.0f%%',[taskresult.D['progress']]));
          TrayIcon1.BalloonFlags:=bfInfo;
          if not popupvisible and task_notify_user then
            TrayIcon1.ShowBalloonHint;
          current_task := taskresult;
        end
        else
        if topic='FINISH' then
        begin
          trayMode:= tmOK;
          TrayIcon1.BalloonHint := UTF8Encode(format(rsTaskDone, [taskresult.S['description'], taskresult.S['summary']]));
          TrayIcon1.BalloonFlags:=bfInfo;
          if not popupvisible and task_notify_user then
            TrayIcon1.ShowBalloonHint;
          current_task := Nil;
        end
        else
        if topic='CANCEL' then
        begin
          trayMode:= tmErrors;
          current_task := Nil;

          if taskresult.DataType = stObject then
          begin
             TrayIcon1.BalloonHint :=UTF8Encode(format(rsCanceling, [UTF8Encode(taskresult.S['description'])]));
             TrayIcon1.BalloonFlags:=bfWarning;
             if not popupvisible and task_notify_user  then
                TrayIcon1.ShowBalloonHint;
          end
          else
          begin
            TrayIcon1.BalloonHint :=UTF8Encode(rsNoTaskCanceled);
            TrayIcon1.BalloonFlags:=bfInfo;
            if not popupvisible and task_notify_user  then
              TrayIcon1.ShowBalloonHint;
          end
        end;
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
  res:WideString;
  ss : TServiceState;
begin
  {ss := GetServiceStatusByName('','waptservice');
  case ss of
    ssUnknown:res:='UNKNOWN';
    ssStopped:res := 'SERVICE_STOPPED';
    ssStartPending:res :='SERVICE_START_PENDING';
    ssStopPending:res := 'SERVICE_STOP_PENDING';
    ssRunning:res := 'SERVICE_RUNNING';
    ssContinuePending:res := 'SERVICE_CONTINUE_PENDING';
    ssPausePending:res := 'SERVICE_PAUSE_PENDING';
    ssPaused:res := 'PAUSED';
  end;}
  ActServiceEnable.Checked :=  GetServiceStatusByName('','waptservice') <> ssStopped;
  if ActServiceEnable.Checked then
  begin
    res := Sto_RedirectedExecute('net stop waptservice');
    lastServiceMessage:=0;
    ActServiceEnable.Update;
  end
  else
  begin
    res := Sto_RedirectedExecute('net start waptservice');
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
  status:integer;
  res : WideString;
begin
  try
    res := Sto_RedirectedExecute( WaptgetPath+' session-setup ALL','',120*1000);
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

function TDMWaptTray.GetrayHint: WideString;
begin
  Result := UTF8Decode(TrayIcon1.Hint);
end;

procedure TDMWaptTray.Settasks(AValue: ISuperObject);
begin
  if Ftasks=AValue then Exit;
  Ftasks:=AValue;
end;

procedure TDMWaptTray.SettrayHint(AValue: WideString);
begin
  if TrayIcon1.Hint<>UTF8Encode(AValue) then
  begin
    TrayIcon1.Hint:= UTF8Encode(AValue);
    TrayIcon1.BalloonHint:=UTF8Encode(AValue);
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

