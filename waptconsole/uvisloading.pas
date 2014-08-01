unit uvisloading;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ComCtrls,
  ExtCtrls, StdCtrls, Buttons;

type

  EStopRequest = class(Exception);

  { TVisLoading }

  TVisLoading = class(TForm)
    BitBtn1: TBitBtn;
    AMessage: TLabel;
    AProgressBar: TProgressBar;
    procedure BitBtn1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
    StopRequired : Boolean;
    OnStop :TNotifyEvent;
    ExceptionOnStop:Boolean;
    function ProgressForm:TVisLoading;
    procedure ProgressTitle(Title:String);
    procedure ProgressStep(step,max:integer);
    procedure Start(Max:Integer=100);
    procedure Finish;
    procedure DoProgress(Sender:TObject);
  end;

var
  VisLoading: TVisLoading;

implementation

{$R *.lfm}

{ TVisLoading }

procedure TVisLoading.BitBtn1Click(Sender: TObject);
begin
  StopRequired:=True;
  if Assigned(OnStop) then
    OnStop(Self);
  if ExceptionOnStop then
    Raise EStopRequest.CreateFmt('Opération %s stoppée par l''utilisateur',[AMessage.Caption]);

end;

procedure TVisLoading.FormCreate(Sender: TObject);
begin
  AProgressBar.Min:=0;
end;

function TVisLoading.ProgressForm: TVisLoading;
begin
  result := Self;
end;

procedure TVisLoading.ProgressTitle(Title: String);
begin
  AMessage.Caption := Title;
  Application.ProcessMessages;
end;

procedure TVisLoading.ProgressStep(step, max: integer);
begin
  if Step <= 0 then
      StopRequired:=False;
  AProgressBar.Max:=Max;
  AProgressBar.position:=step;
  Application.ProcessMessages;
end;

procedure TVisLoading.Start(Max: Integer);
begin
  AProgressBar.position:=0;
  AProgressBar.Max:=Max;
  Application.ProcessMessages;

end;

procedure TVisLoading.Finish;
begin
  AProgressBar.position:=AProgressBar.Max;
  Application.ProcessMessages;
end;

procedure TVisLoading.DoProgress(Sender: TObject);
begin
  if AProgressBar.position >= AProgressBar.Max then
      AProgressBar.position := AProgressBar.Min
  else
    AProgressBar.position := AProgressBar.position+1;
  Application.ProcessMessages;
end;

end.

