unit uDMWAPTTray;

// dans cet ordre impérativement
{$mode delphiunicode}
{$codepage UTF8}

interface

uses
  Classes, SysUtils, FileUtil, ExtCtrls, Menus, ActnList, Controls,
  uniqueinstance, zmqapi, LSControls;

type

  TTrayMode = (tmOK,tmRunning,tmUpgrades,tmErrors);

  { TDMWaptTray }
  TDMWaptTray = class(TDataModule)
    ActConfigure: TAction;
    ActForceRegister: TAction;
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
    MenuItem3: TMenuItem;
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
    UniqueInstance1:TUniqueInstance;
    procedure ActConfigureExecute(Sender: TObject);
    procedure ActForceRegisterExecute(Sender: TObject);
    procedure ActLaunchWaptConsoleExecute(Sender: TObject);
    procedure ActLocalInfoExecute(Sender: TObject);
    procedure ActQuitExecute(Sender: TObject);
    procedure ActSessionSetupExecute(Sender: TObject);
    procedure ActShowStatusExecute(Sender: TObject);
    procedure ActUpdateExecute(Sender: TObject);
    procedure ActUpgradeExecute(Sender: TObject);
    procedure ActWaptUpgradeExecute(Sender: TObject);
    procedure DataModuleCreate(Sender: TObject);
    procedure DataModuleDestroy(Sender: TObject);
    procedure PopupMenu1Popup(Sender: TObject);
    procedure TrayIcon1DblClick(Sender: TObject);
  private
    FtrayMode: TTrayMode;
    function GetrayHint: String;
    procedure SettrayHint(AValue: String);
    procedure SetTrayIcon(idx: integer);
    procedure SettrayMode(AValue: TTrayMode);
    function  WaptConsoleFileName: String;
    procedure pollerEvent(message:TStringList);
    { private declarations }
  public
    { public declarations }
    check_thread:TThread;
    checkinterval:Integer;
    property trayMode:TTrayMode read FtrayMode write SettrayMode;
    property trayHint:String read GetrayHint write SettrayHint;

  end;

var
  DMWaptTray: TDMWaptTray;

implementation
uses LCLIntf,Forms,dialogs,windows,superobject,graphics,tiscommon,waptcommon,tisinifiles,soutils,UnitRedirect;

{$R *.lfm}

type

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
  zmq_socket.RcvHWM:= 1000001;
  zmq_socket.connect( 'tcp://127.0.0.1:5000' );
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

procedure TDMWaptTray.ActUpdateExecute(Sender: TObject);
var
  res : String;
begin
  res := httpGetString(GetWaptLocalURL+'/update');
end;

procedure TDMWaptTray.ActUpgradeExecute(Sender: TObject);
var
  res : String;
begin
  res := httpGetString(GetWaptLocalURL+'/upgrade');
end;

procedure TDMWaptTray.ActWaptUpgradeExecute(Sender: TObject);
var
  res : String;
begin
  res := httpGetString(GetWaptLocalURL+'/waptupgrade');
end;

procedure TDMWaptTray.DataModuleCreate(Sender: TObject);
begin
  //UniqueInstance1.Enabled:=True;
  check_thread :=TZMQPollThread.Create(Self);
  check_thread.Start;
end;

procedure TDMWaptTray.DataModuleDestroy(Sender: TObject);
begin
  if Assigned(check_thread) then
  begin
    TerminateThread(check_thread.Handle,0);
    FreeAndNil(check_thread);
  end;
end;

procedure TDMWaptTray.PopupMenu1Popup(Sender: TObject);
begin
  MenuWaptVersion.Caption:=GetApplicationVersion(WaptgetPath);
end;

procedure TDMWaptTray.ActConfigureExecute(Sender: TObject);
begin
  OpenDocument(WaptIniFilename);
end;

procedure TDMWaptTray.ActForceRegisterExecute(Sender: TObject);
var
  res : String;
begin
  res := httpGetString(GetWaptLocalURL+'/register');
end;

procedure TDMWaptTray.ActLaunchWaptConsoleExecute(Sender: TObject);
var
  cmd:WideString;
begin
  cmd := WaptConsoleFileName;
  ShellExecuteW(0,Pchar('open'),PChar(cmd),Nil,Nil,0);
end;

function TDMWaptTray.WaptConsoleFileName: String;
begin
  result:=AppendPathDelim(ExtractFileDir(ParamStr(0)))+'waptconsole.exe';
end;

procedure TDMWaptTray.pollerEvent(message:TStringList);
var
  msg,msg_type,topic:String;
  bh:String;
  upgrade_status,running,upgrades,errors,taskresult : ISuperObject;
begin
  try
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
          TrayIcon1.ShowBalloonHint;
      end
      else
      if msg_type='STATUS' then
      begin
        upgrade_status := SO(msg);
        running := upgrade_status['running_tasks'];
        upgrades := upgrade_status['upgrades'];
        errors := upgrade_status['errors'];
        if (running<>Nil) and (running.AsArray.Length>0) then
        begin
          trayMode:=tmRunning;
          trayHint:=UTF8Encode('Installation en cours : '+running.AsString);
        end
        else
        if (errors<>Nil) and (errors.AsArray.Length>0) then
        begin
          trayHint:=UTF8Encode('Erreurs : '+#13#10+ Join(#13#10,errors));
          trayMode:=tmErrors;
        end
        else
        if (upgrades<>Nil) and (upgrades.AsArray.Length>0) then
        begin
          trayMode:=tmUpgrades;
          trayHint:=UTF8Encode('Mises à jour disponibles pour : '+#13#10+soutils.join(#13#10,upgrades));
        end
        else
        begin
          trayHint:='Système à jour';
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
        if topic='ERROR' then
        begin
          trayMode:= tmErrors;
          TrayIcon1.BalloonHint := UTF8Encode('Erreur pour '+taskresult.S['description']);
          TrayIcon1.BalloonFlags:=bfError;
          TrayIcon1.ShowBalloonHint;
        end
        else
        if topic='START' then
        begin
          trayMode:= tmRunning;
          TrayIcon1.BalloonHint := UTF8Encode(taskresult.S['description']+' démarré');
          TrayIcon1.BalloonFlags:=bfInfo;
          TrayIcon1.ShowBalloonHint;
        end
        else
        if topic='FINISH' then
        begin
          trayMode:= tmOK;
          TrayIcon1.BalloonHint := UTF8Encode(taskresult.S['description']+' terminé'+#13#10+taskresult.S['summary']);
          TrayIcon1.BalloonFlags:=bfInfo;
          TrayIcon1.ShowBalloonHint;
        end
        else
        if topic='CANCEL' then
        begin
          trayMode:= tmErrors;
          TrayIcon1.BalloonHint :=UTF8Encode('Annulation de '+taskresult.S['description']);
          TrayIcon1.BalloonFlags:=bfError;
          TrayIcon1.ShowBalloonHint;
        end;
      end;
    end;
  finally
  end;
end;

procedure TDMWaptTray.ActLocalInfoExecute(Sender: TObject);
begin
  ShowMessage(GetCurrentUserSid);
end;

procedure TDMWaptTray.ActQuitExecute(Sender: TObject);
begin
  if Assigned(check_thread) then
    check_thread.Terminate;
  Application.Terminate;
end;

procedure TDMWaptTray.ActSessionSetupExecute(Sender: TObject);
var
  status:integer;
  res : String;
begin
  try
    res := Sto_RedirectedExecute(WaptgetPath+' session-setup ALL','',120*1000);
    ShowMessage('Configuration des paquets pour la session utilisateur effectuée')
  except
    MessageDlg('Erreur','Erreur lors de la configuration des paquets pour la session utilisateur',mtError,[mbOK],0);
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
  Result := UTF8Decode(TrayIcon1.Hint);
end;

procedure TDMWaptTray.SettrayHint(AValue: String);
begin
  if TrayIcon1.Hint<>UTF8Encode(AValue) then
  begin
    TrayIcon1.Hint:= UTF8Encode(AValue);
    TrayIcon1.BalloonHint:=UTF8Encode(AValue);
    TrayIcon1.ShowBalloonHint;
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

procedure TDMWaptTray.TrayIcon1DblClick(Sender: TObject);
var
  res:String;
begin
  try
    res := httpGetString(GetWaptLocalURL+'/update');
    if pos('ERROR',uppercase(res))<=0 then
      TrayIcon1.BalloonHint:='Vérification en cours...'
    else
      TrayIcon1.BalloonHint:='Erreur au lancement de la vérification...';
  except
    on E:Exception do
      begin
        TrayIcon1.BalloonHint := E.Message;
        trayMode:=tmErrors;
      end;
  end;
  TrayIcon1.ShowBalloonHint;
end;

end.

