unit uwizardconfigconsole_welcome;

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

  end;

implementation

{$R *.lfm}

{ TWizardStepFrameConsoleWelcome }

initialization

RegisterClass(TWizardStepFrameConsoleWelcome);

end.

