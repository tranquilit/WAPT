unit uwizardconfigconsole_finished;

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
  procedure wizard_finish( var bClose : boolean ); override; final;

  end;

implementation

uses
    uwizardconfigconsole_data;


{$R *.lfm}

{ TWizardStepFrameConsoleFinished }

procedure TWizardStepFrameConsoleFinished.wizard_finish(var bClose: boolean);
begin
  bClose:= true;
  PWizardConfigConsoleData(m_wizard.data())^.launch_console := self.cb_launch_console.Checked;
end;


initialization

RegisterClass(TWizardStepFrameConsoleFinished);

end.

