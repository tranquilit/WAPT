program waptget;
{ -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013  Tranquil IT Systems http://www.tranquil.it
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users PC.
#
#    WAPT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    WAPT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with WAPT.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------
}

{.$mode delphiunicode}
{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Classes, SysUtils, CustApp,
  { you can add units after this }
  Windows, PythonEngine, waptcommon, tiscommon, superobject,
  soutils, zmqapi, pl_indy;
type
  { pwaptget }

  pwaptget = class(TCustomApplication)
  private
    FRepoURL: String;
    FWaptDB: TWAPTDB;
    function GetRepoURL: String;
    function GetWaptDB: TWAPTDB;
    procedure SetRepoURL(AValue: String);
    procedure SetWaptDB(AValue: TWAPTDB);
  protected
    APythonEngine: TPythonEngine;


    procedure DoRun; override;
  public
    Action : String;
    check_thread:TThread;
    lock:TRTLCriticalSection;
    tasks:ISuperObject;
    lastMessageTime : TDateTime;
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure WriteHelp; virtual;
    property WaptDB:TWAPTDB read GetWaptDB write SetWaptDB;
    property RepoURL:String read GetRepoURL write SetRepoURL;
    procedure pollerEvent(message:TStringList);
    function remainingtasks:ISuperObject;
  end;



  { TZMQPollThread }
  TZMQPollThread = Class(TThread)
    procedure HandleMessage;

  public
    PollTimeout:Integer;
    zmq_context:TZMQContext;
    zmq_socket :TZMQSocket;

    message : TStringList;
    msg:Utf8String;
    app:pwaptget;

    constructor Create(anapp:pwaptget);
    destructor Destroy; override;
    procedure Execute; override;
end;

//#########################

{
function WAPTLocalJsonGet(action: String;user:AnsiString='';password:AnsiString='';timeout:integer=1000): ISuperObject;
var
  strresult : String;
begin
  if StrLeft(action,1)<>'/' then
    action := '/'+action;
  strresult := retrieve(GetWaptLocalURL+action);
  Result := SO(strresult);
end;
}

{ TZMQPollThread }

procedure TZMQPollThread.HandleMessage;
begin
  if Assigned(app) then
    app.pollerEvent(message);
end;

constructor TZMQPollThread.Create(anapp:pwaptget);
begin
  inherited Create(True);
  message := TStringList.Create;
  app := anapp;
  // create ZMQ context.
  zmq_context := TZMQContext.Create;

  zmq_socket := zmq_context.Socket( stSub );
  zmq_socket.RcvHWM:= 1000001;
  Logger('Connecting to Waptservice event queue...',DEBUG);
  zmq_socket.connect( 'tcp://127.0.0.1:5000' );
  zmq_socket.Subscribe('');
  Logger('Connected to Waptservice event queue',DEBUG);
end;

destructor TZMQPollThread.Destroy;
begin
  message.Free;
  Logger('Leaving Waptservice event queue',DEBUG);
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
  try
    while not Terminated and not  zmq_socket.context.Terminated do
    begin
      res := zmq_socket.recv(msg);
      while zmq_socket.RcvMore do
      begin
        res := zmq_socket.recv(part);
        msg:=msg+#13#10+part;
      end;
      message.Text:=msg;
      HandleMessage;
      if zmq_socket.context.Terminated then
      begin
        Writeln( 'W: interrupt received, killing server…');
        break;
      end;
    end;
  finally
    writeln('Stop listening to events');
  end;
end;

{ pwaptget }

var
  Application: pwaptget;

procedure pwaptget.SetWaptDB(AValue: TWAPTDB);
begin
  if FWaptDB=AValue then Exit;
  if Assigned(FWaptDB) then
    FreeAndNil(FWaptDB);
  FWaptDB:=AValue;
end;

function pwaptget.GetWaptDB: TWAPTDB;
begin
  if not Assigned(FWaptDB) then
  begin
    Fwaptdb := TWAPTDB.Create(WaptDBPath);
  end;
  Result := FWaptDB;
end;

function pwaptget.GetRepoURL: String;
begin
  if FRepoURL='' then
    FRepoURL:=GetMainWaptRepo;
  result := FRepoURL;
end;

procedure pwaptget.SetRepoURL(AValue: String);
begin
  if FRepoURL=AValue then Exit;
  FRepoURL:=AValue;
end;

procedure pwaptget.DoRun;
var
  MainModule : TStringList;
  logleveloption : String;
  Res,task:ISuperobject;
  i:integer;
  force:Boolean;
  packages:String;

  procedure SetFlag( AFlag: PInt; AValue : Boolean );
  begin
    if AValue then
      AFlag^ := 1
    else
      AFlag^ := 0;
  end;

begin
  {Action:='';
  packages:='';

  for i:=1 to ParamCount do
  begin
    if (Pos('-',Params[i])<>1) then
      if (action='') then
        Action := lowercase(Params[i])
      else
        if packages='' then
          Params[i]
        else
          packages:=packages+','+Params[i];
  end;}
  Action := Params[ParamCount];

  // parse parameters
  if HasOption('?') or HasOption('h','--help') then
  begin
    writeln(' -r --repo : URL of dependencies libs');
    writeln(' waptupgrade : upgrade wapt-get.exe and database');
  end;

  if HasOption('r','repo') then
    RepoURL := GetOptionValue('r','repo');

  if HasOption('l','loglevel') then
  begin
    logleveloption := UpperCase(GetOptionValue('l','loglevel'));
    if logleveloption = 'DEBUG' then
      currentLogLevel := DEBUG
    else if logleveloption = 'INFO' then
      currentLogLevel := INFO
    else if logleveloption = 'WARNING' then
      currentLogLevel := WARNING
    else if logleveloption = 'ERROR' then
      currentLogLevel := ERROR
    else if logleveloption = 'CRITICAL' then
      currentLogLevel := CRITICAL;
    Logger('Current loglevel : '+StrLogLevel[currentLogLevel],DEBUG);
  end;

  if HasOption('v','version') then
    writeln('Win32 Exe wrapper: '+ApplicationName+' '+GetApplicationVersion);

  if (action = 'waptupgrade') then
  begin
    if RepoURL='' then
      RepoURL:=GetMainWaptRepo;
    Writeln('WAPT-GET Upgrade using repository at '+RepoURL);
    UpdateApplication(RepoURL+'/waptsetup.exe','waptsetup.exe','/VERYSILENT','wapt-get.exe','');
    Terminate;
    Exit;
  end
  else
  if (action = 'dnsdebug') then
  begin
    WriteLn('DNS Server : '+GetDNSServer);
    WriteLn('DNS Domain : '+GetDNSDomain);
    repourl := GetMainWaptRepo;
    Writeln('Main repo url: '+RepoURL);

    Writeln('SRV: '+DNSSRVQuery('_wapt._tcp.'+GetDNSDomain).AsJSon(True));
    Writeln('CNAME: '+DNSCNAMEQuery('wapt.'+GetDNSDomain).AsJSon(True));
    Terminate;
    Exit;
  end
  else
  if not HasOption('D','direct') and StrIsOneOf(action,['update','upgrade','longtask','cancel','cancel-all','tasks'])
    and CheckOpenPort(waptservice_port,'127.0.0.1',100) then
  begin
    // launch task in waptservice, waits for its termination
    check_thread :=TZMQPollThread.Create(Self);
    check_thread.Start;
    tasks := TSuperObject.create(stArray);
    try
      res := Nil;
      //test longtask
      if action='longtask' then
      begin
        Logger('Call longtask URL...',DEBUG);
        res := WAPTLocalJsonGet('longtask.json');
        if res = Nil then
          WriteLn('Error launching longtask: '+res.S['message'])
        else
          tasks.AsArray.Add(res);
        Logger('Task '+res.S['id']+' added to queue',DEBUG);
      end
      else
      if action='tasks' then
      begin
        res := WAPTLocalJsonGet('tasks.json');
        if res = Nil then
          WriteLn('Error getting task list: '+res.S['message'])
        else
        begin
          if res['running'].DataType<>stNull then
            writeln(format('Running task %d: %s, status:%s',[ res['running'].I['id'],res['running'].S['description'],res['running'].S['runstatus']]))
          else
            writeln('No running tasks');
          if res['pending'].AsArray.length>0 then
            writeln('Pending : ');
            for task in res['pending'] do
              writeln('  '+task.S['id']+' '+task.S['description']);
        end;
      end
      else
      if action='cancel' then
      begin
        res := WAPTLocalJsonGet('cancel_running_task.json');
        if res = Nil then
          WriteLn('Error cancelling: '+res.S['message'])
        else
          if res.DataType<>stNull then
            writeln('Cancelled '+res.S['description'])
          else
            writeln('No running task');
      end
      else
      if (action='cancel-all') or (action='cancelall') then
      begin
        res := WAPTLocalJsonGet('cancel_all_tasks.json');
        if res = Nil then
          WriteLn('Error cancelling: '+res.S['message'])
        else
          if res.DataType<>stNull then
          begin
            for task in res do
              writeln('Cancelled '+task.S['description'])
          end
          else
            writeln('No running task');
      end
      else
      if action='update' then
      begin
        Logger('Call update URL...',DEBUG);
        res := WAPTLocalJsonGet('update.json?notify_user=0');
        if res = Nil then
          WriteLn('Error launching update: '+res.S['message'])
        else
          tasks.AsArray.Add(res);
        Logger('Task '+res.S['id']+' added to queue',DEBUG);
      end
      else
      if (action='install') or (action='remove') then
      begin
        Logger('Call '+action+'?package='+packages,DEBUG);
        if HasOption('f','force') then
          res := WAPTLocalJsonGet(Action+'.json?package='+packages+'&force=1&notify_user=0')
        else
          res := WAPTLocalJsonGet(Action+'.json?package='+packages+'&notify_user=0');
        if res = Nil then
          WriteLn('Error : '+res.S['message'])
        else
          tasks.AsArray.Add(res);
        Logger('Task '+res.S['id']+' added to queue',DEBUG);
      end
      else if action='upgrade' then
      begin
        Logger('Call upgrade URL...',DEBUG);
        res := WAPTLocalJsonGet('upgrade.json?notify_user=0');
        if res.S['result']<>'OK' then
          WriteLn('Error launching upgrade: '+res.S['message'])
        else
          for task in res['content'] do
            tasks.AsArray.Add(task);
            Logger('Task '+task.S['id']+' added to queue',DEBUG);
      end;

      while (tasks.AsArray.Length > 0) and not (Terminated) and not check_thread.Finished do
      try
        //if no message from service since more that 10 min, check if remaining tasks in queue...
        if (now-lastMessageTime>1*1/24/50) and (remainingtasks.AsArray.Length=0) then
          raise Exception.create('Timeout waiting for events')
        else
        begin
          Sleep(1000);
          write('.');
        end;
      except
        writeln('cancelled');
        for task in tasks do
            WAPTLocalJsonGet('cancel_task.json?id='+task.S['id']);
        break;
      end;

    finally
      for task in tasks do
          WAPTLocalJsonGet('cancel_task.json?id='+task.S['id']);
      if Assigned(check_thread) then
      begin
        TerminateThread(check_thread.Handle,0);
        FreeAndNil(check_thread);
      end;
    end;
  end
  else
  if Action = 'dumpdb' then
    writeln(WaptDB.dumpdb.AsJson(True))
  else
  begin
    // Running python stuff
    APythonEngine := TPythonEngine.Create(Self);
    with ApythonEngine do
    begin
      DllName := 'python27.dll';
      //APIVersion := 1013;
      RegVersion := '2.7';
      UseLastKnownVersion := False;
      Initialize;
      Py_SetProgramName(PAnsiChar(ParamStr(0)));
      SetFlag(Py_VerboseFlag,     False);
      SetFlag(Py_InteractiveFlag, True);
      SetFlag(Py_NoSiteFlag,      True);
      SetFlag(Py_IgnoreEnvironmentFlag, True);
    end;

    // Load main python application
    try
      MainModule:=TStringList.Create;
      MainModule.LoadFromFile(ExtractFilePath(ParamStr(0))+'wapt-get.py');
      APythonEngine.ExecStrings(MainModule);
    finally
      MainModule.Free;
    end;
  end;

  // stop program loop
  Terminate;
end;

constructor pwaptget.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  StopOnException:=True;
  InitializeCriticalSection(lock);

end;

destructor pwaptget.Destroy;
begin
  if Assigned(APythonEngine) then
    APythonEngine.Free;
  if assigned(waptdb) then
    waptdb.Free;
  DeleteCriticalSection(lock);
  inherited Destroy;
end;

procedure pwaptget.WriteHelp;
begin
  { add your help code here }
  writeln('Usage: ',ExeName,' -h');
  writeln('  install on c:\wapt : --setup -s');
end;

procedure pwaptget.pollerEvent(message: TStringList);
var
  msg:ISuperobject;
  status:String;

  //check if task with id id is in tasks list
  function isInTasksList(id:integer):boolean;
  var
    t:ISuperObject;
  begin
    //writeln('check '+IntToStr(id)+' in '+tasks.AsJSon());
    result := False;
    for t in tasks do
      if t.I['id'] = id then
      begin
        result := True;
        break;
      end;
  end;

  //remove task with id id from tasks list
  procedure removeTask(id:integer);
  var
    i:integer;
    t:ISuperObject;
  begin
    for i:=0 to tasks.AsArray.Length-1 do
      if tasks.AsArray[i].I['id'] = id then
      begin
        tasks.AsArray.Delete(i);
        break;
      end;
  end;

begin
  EnterCriticalSection(lock);
  try
    //writeln(message.Text);
    //display messages if event task is in my list

    lastMessageTime := Now;

    if message[0]='TASKS' then
    begin
      status := message[1];
      msg := SO(message[2]);
      //writeln(msg.asJson());
      if isInTasksList(msg.I['id']) then
      begin
        if (status = 'START') then
          writeln(msg.S['description']);
        if (status = 'PROGRESS') then
          write(format('%s : %.0f%% completed',[msg.S['runstatus'], msg.D['progress']])+#13);
        //catch finish of task
        if (status = 'FINISH') or (status = 'ERROR') or (status = 'CANCEL') then
        begin
          removeTask(msg.I['id']);
          WriteLn(msg.S['summary'])
        end;
      end;
    end
  finally
    LeaveCriticalSection(lock);
  end;
end;

function pwaptget.remainingtasks: ISuperObject;
var
  res:ISuperObject;
begin
  res := WAPTLocalJsonGet('tasks.json');
  Result := res['pending'];
  if res['running'] <> Nil then
    Result.AsArray.Add(res['running']);
end;

{$R *.res}

begin
  Application:=pwaptget.Create(nil);
  Application.Title:='wapt-get';
  Application.Run;
  Application.Free;
end.

