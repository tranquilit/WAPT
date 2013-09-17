unit uvisloading;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ComCtrls,
  ExtCtrls, StdCtrls, Buttons;

type

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
    function ProgressForm:TVisLoading;
    procedure ProgressTitle(Title:String);
    procedure ProgressStep(step,max:integer);
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

end.

