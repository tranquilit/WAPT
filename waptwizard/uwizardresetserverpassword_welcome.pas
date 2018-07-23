unit uwizardresetserverpassword_welcome;

{$mode objfpc}{$H+}

interface

uses
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls;

type

  { TWizardResetServerPasswordWelcome }

  TWizardResetServerPasswordWelcome = class(TWizardStepFrame)
    lbl: TLabel;
  private

  public

  end;

implementation

{$R *.lfm}

{ TWizardResetServerPasswordWelcome }

initialization

RegisterClass(TWizardResetServerPasswordWelcome);

end.

