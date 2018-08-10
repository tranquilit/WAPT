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
  constructor Create( AOwner : TComponent );

  // TWizardStepFrame
  procedure wizard_show(); override; final;
  procedure wizard_finish( var bClose : boolean ); override; final;

  end;

implementation

uses
    uwizardconfigconsole_data;


{$R *.lfm}

{ TWizardStepFrameConsoleFinished }

constructor TWizardStepFrameConsoleFinished.Create(AOwner: TComponent);
begin
  inherited Create( AOwner, PAGE_FINISHED );
end;

procedure TWizardStepFrameConsoleFinished.wizard_show();
begin
  inherited wizard_show();
  m_wizard.m_can_close := true;
end;

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

