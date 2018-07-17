unit uwizardstepframeconsolewelcome;

{$mode objfpc}{$H+}

interface

uses
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls;

type

  { TWizardStepFrameConsoleWelcome }

  TWizardStepFrameConsoleWelcome = class(TWizardStepFrame)
    lbl: TLabel;
  private

  public

  // TWizardStepFrame
  function wizard_validate() : integer;  override; final;

  end;

implementation

{$R *.lfm}

{ TWizardStepFrameConsoleWelcome }

function TWizardStepFrameConsoleWelcome.wizard_validate(): integer;
begin
  exit( 0 )
end;

initialization

RegisterClass(TWizardStepFrameConsoleWelcome);

end.

