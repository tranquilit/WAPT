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
    lbl_desc: TLabel;
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
var
  data : PWizardConfigConsoleData;
begin
  bClose:= true;
  data := m_wizard.data();
  data^.launch_console := self.cb_launch_console.Checked;
end;


initialization

RegisterClass(TWizardStepFrameConsoleFinished);

end.

