unit uWAPTPollThreads;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, SuperObject,Forms,IdAntiFreeze;

type

  { TCheckWaptservice }
  TCheckWaptservice = Class(TThread)
  private
    PollTimeout:Integer;
    FOnNotifyEvent: TNotifyEvent;
    procedure NotifyListener; Virtual;
    procedure SetOnNotifyEvent(AValue: TNotifyEvent);
  public
    IsWaptServiceRunning:Boolean;
    LastUpdateStatus : ISuperObject;
    Message: String;
    constructor Create(aNotifyEvent:TNotifyEvent;aPollTimeout:Integer=3000);
    procedure Execute; override;
    property OnNotifyEvent: TNotifyEvent read FOnNotifyEvent write SetOnNotifyEvent;
  end;


  { TCheckTasksThread }

  TCheckTasksThread = Class(TThread)
  private
    FOnNotifyEvent: TNotifyEvent;
    procedure SetOnNotifyEvent(AValue: TNotifyEvent);
    procedure NotifyListener; Virtual;
  public
    PollTimeout:Integer;

    Tasks: ISuperObject;
    LastReadEventId: Integer;
    WaptServiceRunning:Boolean;
    Message: String;

    property OnNotifyEvent: TNotifyEvent read FOnNotifyEvent write SetOnNotifyEvent;

    constructor Create(aNotifyEvent:TNotifyEvent;aPollTimeout:Integer=10000);
    destructor Destroy; override;
    procedure Execute; override;
  end;

  { TCheckTasksThread }

  TCheckEventsThread = Class(TThread)
  private
    FOnNotifyEvent: TNotifyEvent;
    procedure SetOnNotifyEvent(AValue: TNotifyEvent);
    procedure NotifyListener; Virtual;
  public
    PollTimeout:Integer;

    Events: ISuperObject;
    LastReadEventId: Integer;
    WaptServiceRunning:Boolean;
    Message: String;

    property OnNotifyEvent: TNotifyEvent read FOnNotifyEvent write SetOnNotifyEvent;

    constructor Create(aNotifyEvent:TNotifyEvent;aPollTimeout:Integer=3000);
    destructor Destroy; override;
    procedure Execute; override;
  end;

  { TRunWaptService }

  // A Thread to start or stop waptservice service in background

  TWaptServiceState = (wssStopped,wssStarting,wssRunning,wssStopping);

  TRunWaptService = Class(TThread)
  private
    FOnNotifyEvent: TNotifyEvent;
    procedure NotifyListener; Virtual;
    procedure SetOnNotifyEvent(AValue: TNotifyEvent);
  public
    State: TWaptServiceState;
    MustStartService:Boolean;

    property OnNotifyEvent:TNotifyEvent read FOnNotifyEvent write SetOnNotifyEvent;

    constructor Create(aNotifyEvent:TNotifyEvent;StartService:Boolean);
    procedure Execute; override;
  end;


implementation

uses LCLIntf,tiscommon,
    waptcommon,waptwinutils,soutils,tisstrings,IdException,IdTCPConnection, IdStack,
    IdExceptionCore;

{ TRunWaptService }

procedure TRunWaptService.NotifyListener;
begin
  If Assigned(FOnNotifyEvent) then
    FOnNotifyEvent(Self);
end;

procedure TRunWaptService.SetOnNotifyEvent(AValue: TNotifyEvent);
begin
  if FOnNotifyEvent=AValue then Exit;
  FOnNotifyEvent:=AValue;
end;

constructor TRunWaptService.Create(aNotifyEvent:TNotifyEvent;StartService:Boolean);
begin
  inherited Create(False);
  OnNotifyEvent:=aNotifyEvent;
  MustStartService:=StartService;
  FreeOnTerminate:=True;
end;

procedure TRunWaptService.Execute;
begin
  try
    if MustStartService then
    begin
      State:=wssStarting;
      Synchronize(@NotifyListener);
      run('net start waptservice');
      State:=wssRunning;
    end
    else
    begin
      State:=wssStopping;
      Synchronize(@NotifyListener);
      run('net stop waptservice');
      State:=wssStopped;
    end;
  except
    on E:Exception do
    begin
      WAPTLocalJsonGet('waptservicerestart.json');
    end;
  end;
  Synchronize(@NotifyListener);
end;

{ TCheckWaptservice }

procedure TCheckWaptservice.NotifyListener;
begin
  If Assigned(FOnNotifyEvent) then
    FOnNotifyEvent(Self);
end;

procedure TCheckWaptservice.SetOnNotifyEvent(AValue: TNotifyEvent);
begin
  if FOnNotifyEvent=AValue then Exit;
  FOnNotifyEvent:=AValue;
end;

constructor TCheckWaptservice.Create(aNotifyEvent:TNotifyEvent;aPollTimeout:Integer=3000);
begin
  inherited Create(False);
  OnNotifyEvent:=aNotifyEvent;
  PollTimeout:=aPollTimeout;
  FreeOnTerminate:=True;
end;

procedure TCheckWaptservice.Execute;
begin
  try
    LastUpdateStatus := WAPTLocalJsonGet('checkupgrades.json','','',PollTimeout);
    IsWaptServiceRunning:=True;
  except
    on E:EIdException do
    begin
      Message := E.Message;
      IsWaptServiceRunning:=False;
      LastUpdateStatus := Nil;
    end;
  end;
  Synchronize(@NotifyListener);
end;

{ TCheckTasksThread }

procedure TCheckTasksThread.NotifyListener;
begin
  if Assigned(FOnNotifyEvent) then
    FOnNotifyEvent(Self);
end;

procedure TCheckTasksThread.SetOnNotifyEvent(AValue: TNotifyEvent);
begin
  if FOnNotifyEvent=AValue then Exit;
  FOnNotifyEvent:=AValue;
end;

constructor TCheckTasksThread.Create(aNotifyEvent: TNotifyEvent; aPollTimeout: Integer = 10000);
begin
  inherited Create(True);
  OnNotifyEvent:=aNotifyEvent;
  LastReadEventId:=-1;
  PollTimeout:=aPollTimeout;
end;

destructor TCheckTasksThread.Destroy;
begin
  inherited Destroy;
end;

procedure TCheckTasksThread.Execute;
begin
  while not Terminated do
  try
    Tasks := WAPTLocalJsonGet(Format('tasks.json?last_event_id=%d&timeout=%d',[LastReadEventId,3]),'','',PollTimeout);
    if Assigned(Tasks) then
      LastReadEventId:=Tasks.I['last_event_id'];
    WaptServiceRunning:=True;
    Synchronize(@NotifyListener);
    if not Terminated then
      Sleep(200);
  except
    on E: EIdSocketError do
      begin
        // if we can't connect to the waptservice http port, waptservice is not running (properly).
        if e.LastError=10061 then // connection refused
        begin
          if WaptServiceRunning then
          begin
            Message := E.Message;
            WaptServiceRunning:=False;
            Tasks := Nil;
            Synchronize(@NotifyListener);
            break;
          end;
        end
        else
          // we stop..
          break;
      end;

    // long polling on waptservice raises a timeout when no event release the connection
    on E: EIdReadTimeout do
      begin
        if not Terminated then
          Sleep(200);
      end;

    on E: Exception do
      begin
        if WaptServiceRunning then
        begin
          Message := E.ClassName+' '+E.Message;
          WaptServiceRunning:=False;
          Tasks := Nil;
          Synchronize(@NotifyListener);
        end;
        // we stop
        break;
      end;
  end;
end;

{ TCheckEventsThread }

procedure TCheckEventsThread.NotifyListener;
begin
  if Assigned(FOnNotifyEvent) then
    FOnNotifyEvent(Self);
end;

procedure TCheckEventsThread.SetOnNotifyEvent(AValue: TNotifyEvent);
begin
  if FOnNotifyEvent=AValue then Exit;
  FOnNotifyEvent:=AValue;
end;

constructor TCheckEventsThread.Create(aNotifyEvent: TNotifyEvent; aPollTimeout: Integer = 3000);
begin
  inherited Create(True);
  OnNotifyEvent:=aNotifyEvent;
  LastReadEventId:=-1;
  PollTimeout:=aPollTimeout;
end;

destructor TCheckEventsThread.Destroy;
begin
  inherited Destroy;
end;

procedure TCheckEventsThread.Execute;
begin
  while not Terminated do
  try
    Message := 'Waiting for events';
    if LastReadEventId<0 then
      // first time, get just last event
      Events := WAPTLocalJsonGet(Format('events?max_count=1',[]),'','',PollTimeout)
    else
      Events := WAPTLocalJsonGet(Format('events?last_read=%d',[LastReadEventId]),'','',PollTimeout);
    if (Events <> Nil) and (Events.DataType=stArray) then
    begin
      If Events.AsArray.Length>0 then
        LastReadEventId := Events.AsArray.O[Events.AsArray.Length-1].I['id'];
    end;

    WaptServiceRunning:=True;
    Synchronize(@NotifyListener);
    if not Terminated then
      Sleep(200);

  except
    on E: EIdSocketError do
      begin
        if e.LastError=10061 then // connection refused
        begin
          if WaptServiceRunning then
          begin
            Message := E.Message;
            WaptServiceRunning:=False;
            Events := Nil;
            Synchronize(@NotifyListener);
            break;
          end;
        end
        else
        if not Terminated then
          Sleep(200);
      end;

    on E: EIdReadTimeout do
      begin
        if not Terminated then
          Sleep(200);
      end;

    on E: Exception do
      begin
        if WaptServiceRunning then
        begin
          Message := E.ClassName+' '+E.Message;
          WaptServiceRunning:=False;
          Events := Nil;
          Synchronize(@NotifyListener);
        end;
        break;
      end;
  end;
end;

end.

