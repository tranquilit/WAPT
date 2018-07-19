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
    function  wizard_validate() : integer; override; final;

  end;

implementation

{$R *.lfm}

{ TWizardResetServerPasswordWelcome }

function TWizardResetServerPasswordWelcome.wizard_validate(): integer;
begin
  exit(0);
end;

initialization

RegisterClass(TWizardResetServerPasswordWelcome);

end.

