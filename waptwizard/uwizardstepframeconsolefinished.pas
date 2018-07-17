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

  end;

implementation

{$R *.lfm}

{ TWizardStepFrameConsoleFinished }

function TWizardStepFrameConsoleFinished.wizard_validate(): integer;
begin
  exit(0);
end;


initialization

RegisterClass(TWizardStepFrameConsoleFinished);

end.

