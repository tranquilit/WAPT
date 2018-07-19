unit uwizardstepframeconsolefinished;

{$mode objfpc}{$H+}

interface

uses
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls;

type

  { TWizardStepFrameConsoleFinished }

  TWizardStepFrameConsoleFinished = class(TWizardStepFrame)
    cb_launch_console: TCheckBox;
  private

  public

  // TWizardStepFrame
  function wizard_validate() : integer;  override; final;
  procedure wizard_finish( var bClose : boolean ); override; final;

  end;

implementation

{$R *.lfm}

{ TWizardStepFrameConsoleFinished }

function TWizardStepFrameConsoleFinished.wizard_validate(): integer;
begin
  exit(0);
end;

procedure TWizardStepFrameConsoleFinished.wizard_finish(var bClose: boolean);
begin
  bClose:= true;
  self.m_data.B['launch_console'] := self.cb_launch_console.Checked;
end;


initialization

RegisterClass(TWizardStepFrameConsoleFinished);

end.

