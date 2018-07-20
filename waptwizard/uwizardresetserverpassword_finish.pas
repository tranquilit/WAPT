unit uwizardresetserverpassword_finish;

{$mode objfpc}{$H+}

interface

uses
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls;

type

  { TWizardResetServerPasswordFinish }

  TWizardResetServerPasswordFinish = class(TWizardStepFrame)
    lbl_center: TLabel;
  private

  public
    function  wizard_validate() : integer; override; final;

  end;

implementation

{$R *.lfm}


{ TWizardResetServerPasswordFinish }

function TWizardResetServerPasswordFinish.wizard_validate(): integer;
begin
  exit(0);
end;

initialization
RegisterClass(TWizardResetServerPasswordFinish);
end.

