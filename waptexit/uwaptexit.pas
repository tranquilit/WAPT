unit uwaptexit;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, ComCtrls, ActnList, Buttons;

type

  { TVisWaptExit }

  TVisWaptExit = class(TForm)
    actSkip: TAction;
    ActUpgrade: TAction;
    ActionList1: TActionList;
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    ImageList1: TImageList;
    Label1: TLabel;
    Memo1: TMemo;
    ProgressBar1: TProgressBar;
    Timer1: TTimer;
    procedure actSkipExecute(Sender: TObject);
    procedure ActUpgradeExecute(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisWaptExit: TVisWaptExit;

implementation

uses tiscommon,waptcommon,superobject,soutils;
{$R *.lfm}

{ TVisWaptExit }

procedure TVisWaptExit.ActUpgradeExecute(Sender: TObject);
var
  aso: ISuperObject;
begin
  Timer1.Enabled := False;
  aso := WAPTLocalJsonGet('upgrade');
  Memo1.Text:=aso.AsJSon();
end;

procedure TVisWaptExit.actSkipExecute(Sender: TObject);
begin
  Close;
end;

procedure TVisWaptExit.FormShow(Sender: TObject);
var
  aso: ISuperObject;
begin
  ActUpgrade.Enabled:=false;
  aso := WAPTLocalJsonGet('checkupgrades');
  if aso<>Nil then
  begin
    if aso['upgrades'].AsArray.Length = 0 then
    begin
      Memo1.Text:='Système à jour';
      //Close;
    end
    else
    begin
      ActUpgrade.Enabled:=True;
      Memo1.Text:= Join(#13#10, aso['upgrades']);
    end;
  end;
  Timer1.Enabled := True;
end;

procedure TVisWaptExit.Timer1Timer(Sender: TObject);
begin
  ProgressBar1.Position := ProgressBar1.Position+1;
  if ProgressBar1.Position>=ProgressBar1.Max then
    ActUpgrade.Execute;

end;

end.

