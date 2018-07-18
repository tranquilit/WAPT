unit uvisloading;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ComCtrls,
  ExtCtrls, StdCtrls, Buttons, DefaultTranslator;

type

  EStopRequest = class(Exception);

  { TVisLoading }

  TVisLoading = class(TForm)
    AMessage: TLabel;
    AProgressBar: TProgressBar;
    BitBtn1: TBitBtn;
    Panel1: TPanel;
    procedure BitBtn1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    { private declarations }
    LastUpdate:TDateTime;
  public
    { public declarations }
    StopRequired : Boolean;
    OnStop :TNotifyEvent;
    ExceptionOnStop:Boolean;
    ShowCount:Integer;
    function ProgressForm:TVisLoading;
    procedure ProgressTitle(Title:String;ForceRefresh:Boolean=True);
    procedure ProgressStep(step,max:integer;ForceRefresh:Boolean=True);
    procedure Start(Max:Integer=100);
    procedure Finish;
    procedure DoProgress(Sender:TObject);
  end;

  procedure ShowLoadWait(Msg:String;Progress:Integer=0;MaxProgress:Integer = 100);
  procedure ShowProgress(Msg:String;Progress:Integer=0);
  procedure HideLoadWait(Force:Boolean=True);

var
  VisLoading: TVisLoading;

implementation
uses uWaptConsoleRes,uScaleDPI;



type
  TShowLoadWaitParams = record
    msg : String;
    progress : integer;
    maxprogress : integer;
  end;
  PShowLoadWaitParams = ^TShowLoadWaitParams;

  { TShowLoad }
  TShowLoad = class
    public
      procedure show( data : PtrInt );
      procedure hide( data : PtrInt );
  end;
const
  BOOL_TRUE : integer = 1;
var
  s_showload : TShowLoad;

procedure TShowLoad.show( data : PtrInt );
var
  p : PShowLoadWaitParams;
begin
  p := PShowLoadWaitParams(data);
  if p = nil then
    exit;
  if TThread.CurrentThread.ThreadID = 0 then
    ShowLoadWait( p^.msg, p^.progress, p^.maxprogress );
  Freemem(p);

end;

procedure TShowLoad.hide(data: PtrInt);
begin
  if TThread.CurrentThread.ThreadID = 0 then
    HideLoadWait( data = BOOL_TRUE );
end;



procedure ShowLoadWait(Msg: String; Progress: Integer; MaxProgress: Integer);
var
  p : PShowLoadWaitParams;
begin
  if TThread.CurrentThread.ThreadID <> 0 then
  begin
    p := GetMem( sizeof(TShowLoadWaitParams) );
    p^.msg := msg;
    p^.progress := Progress;
    p^.maxprogress := MaxProgress;
    Application.QueueAsyncCall( @s_showload.show, PtrInt(p) );
    exit;
  end;

  if VisLoading = Nil then
      VisLoading := TVisLoading.Create(Application);
  VisLoading.Show;
  inc(VisLoading.ShowCount);
  VisLoading.ProgressStep(Progress,MaxProgress);
  VisLoading.ProgressTitle(Msg);
end;

procedure ShowProgress(Msg: String; Progress: Integer);
begin
  if not VisLoading.Visible then
    ShowLoadWait(Msg,Progress)
  else
  begin
    VisLoading.ProgressTitle(Msg);
    VisLoading.ProgressStep(Progress,VisLoading.AProgressBar.Max);
  end;
end;

procedure HideLoadWait(Force:Boolean=True);
var
  i : PtrInt;
begin
  if TThread.CurrentThread.ThreadID <> 0 then
  begin
    if Force then
      i := BOOL_TRUE
    else
      i := 0;
    Application.QueueAsyncCall( @s_showload.hide, i );
    exit;
  end;

  if VisLoading<> Nil then
  begin
    Dec(VisLoading.ShowCount);
    VisLoading.Finish;
    if Force or (VisLoading.ShowCount<=0) then
    begin
      VisLoading.Close;
    end;
  end;
end;

{$R *.lfm}

{ TVisLoading }

procedure TVisLoading.BitBtn1Click(Sender: TObject);
begin
  StopRequired:=True;
  if Assigned(OnStop) then
    OnStop(Self);
end;

procedure TVisLoading.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
  AProgressBar.Min:=0;
end;

function TVisLoading.ProgressForm: TVisLoading;
begin
  result := Self;
end;

procedure TVisLoading.ProgressTitle(Title: String;ForceRefresh:Boolean=True);
begin
  AMessage.Caption := Title;
  if ForceRefresh or ((Now-LastUpdate)*3600*24>=0.5) then
  begin
    Application.ProcessMessages;
    ShowOnTop;
    LastUpdate:=Now;
  end;
end;

procedure TVisLoading.ProgressStep(step, max: integer;ForceRefresh:Boolean=True);
begin
  if Step <= 0 then
      StopRequired:=False;
  AProgressBar.Max:=Max;
  AProgressBar.position:=step;
  if ForceRefresh or ((Now-LastUpdate)*3600*24>=0.5) then
  begin
    ShowOnTop;
    Application.ProcessMessages;
    LastUpdate:=Now;
  end;
end;

procedure TVisLoading.Start(Max: Integer);
begin
  AProgressBar.position:=0;
  AProgressBar.Max:=Max;
  ShowOnTop;
  Application.ProcessMessages;
  LastUpdate:=Now;
end;

procedure TVisLoading.Finish;
begin
  AProgressBar.position:=AProgressBar.Max;
  ShowOnTop;
  Application.ProcessMessages;
  LastUpdate:=Now;
end;

procedure TVisLoading.DoProgress(Sender: TObject);
begin
  if StopRequired and ExceptionOnStop then
    Raise EStopRequest.CreateFmt(rsCanceledByUser,[AMessage.Caption]);

  // update screen only every half second
  if (Now-LastUpdate)*3600*24>=0.5 then
  begin
    if AProgressBar.position >= AProgressBar.Max then
        AProgressBar.position := AProgressBar.Min
    else
      AProgressBar.position := AProgressBar.position+1;
    ShowOnTop;
    Application.ProcessMessages;
    LastUpdate:=Now;
  end;
end;


initialization
  VisLoading := nil;
  s_showload := TShowLoad.Create;

finalization
  FreeAndNil(s_showload);

end.

