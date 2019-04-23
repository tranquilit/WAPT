unit uVisImpactedProcess;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  Buttons, StdCtrls;

type

  { TImpactedProcess }

  TImpactedProcess = class(TForm)
    BtnContinue: TBitBtn;
    BtnCancel: TBitBtn;
    PanelTextDialog: TPanel;
    PanelBtn: TPanel;
    StaticListProcesses: TStaticText;
    StaticWarning: TStaticText;
  private

  public
    procedure ShowListProcesses(ListProcesses : String);
  end;

var
  ImpactedProcess: TImpactedProcess;

implementation

{$R *.lfm}

{ TImpactedProcess }

procedure TImpactedProcess.ShowListProcesses(ListProcesses: String);
begin
  StaticListProcesses.Caption:=ListProcesses;
end;

end.

