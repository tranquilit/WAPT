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
  Windows, PythonEngine, waptcommon, tiscommon,tisstrings,superobject,zmqapi;
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
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure WriteHelp; virtual;
    property WaptDB:TWAPTDB read GetWaptDB write SetWaptDB;
    property RepoURL:String read GetRepoURL write SetRepoURL;
    procedure pollerEvent(message:TStringList);
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
  Logger('Connecting to Waptservice event queue',DEBUG);
  zmq_socket.connect( 'tcp://127.0.0.1:5000' );
  zmq_socket.Subscribe('');
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
  while not Terminated do
  begin
    res := zmq_socket.recv(msg);
    while zmq_socket.RcvMore do
    begin
      res := zmq_socket.recv(part);
      msg:=msg+#13#10+part;
    end;
    message.Text:=msg;
    HandleMessage;
  end;
end;

{ pwaptget }

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

  Res:ISuperobject;

  procedure SetFlag( AFlag: PInt; AValue : Boolean );
  begin
    if AValue then
      AFlag^ := 1
    else
      AFlag^ := 0;
  end;

begin
  Action := lowercase(ParamStr(ParamCount));

  // parse parameters
  if HasOption('?') or HasOption('h','--help') then
  begin
    writeln(' -r --repo : URL of dependencies libs');
    writeln(' waptupgrade : upgrade wapt-get.exe and database');
    writeln(' waptsetup : install/reinstall dependencies (python libs)');
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
  {else
  if (CheckOpenPort(8088,'127.0.0.1',2)) and StrIsOneOf(action,['update','upgrade','install','remove']) then
  begin
    check_thread :=TZMQPollThread.Create(Self);
    check_thread.Start;
    try
      if action='update' then
      begin
        res := WAPTLocalJsonGet('update.json');
        if res.S['result']='OK' then
        begin
          WriteLn(res.AsJSon(True));
          readln();
        end
        else
          Writeln('Can not create an update task: ':);
        ExitProcess(0);
      end
      else if action='upgrade' then
      begin
        res := WAPTLocalJsonGet('upgrade.json');
        WriteLn(res.AsJSon(True));
        readln();
        ExitProcess(0);
      end;
    finally
      if Assigned(check_thread) then
      begin
        TerminateThread(check_thread.Handle,0);
        FreeAndNil(check_thread);
      end;
    end;
  end}
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
begin
  EnterCriticalSection(lock);
  try
    writeln(message.Text);
  finally
    LeaveCriticalSection(lock);
  end;
end;

var
  Application: pwaptget;

{$R *.res}

begin
  Application:=pwaptget.Create(nil);
  Application.Title:='wapt-get';
  Application.Run;
  Application.Free;
end.

