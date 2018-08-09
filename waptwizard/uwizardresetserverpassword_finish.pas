unit uwizardresetserverpassword_finish;

{$mode objfpc}{$H+}

interface

uses
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, ExtCtrls;

type

  { TWizardResetServerPasswordFinish }

  TWizardResetServerPasswordFinish = class(TWizardStepFrame)
    lbl_center: TLabel;
  private

  public

  end;

implementation

{$R *.lfm}


{ TWizardResetServerPasswordFinish }

initialization
  RegisterClass(TWizardResetServerPasswordFinish);
end.

