unit uwizardconfigserver_finish;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls;

type

  { TWizardConfigServer_Finish }

  TWizardConfigServer_Finish = class(TWizardStepFrame)
    cb_start_console: TCheckBox;
    lbl_desc: TLabel;
  private

  public

    // TWizardStepFrame
    procedure wizard_show(); override; final;
    procedure wizard_finish( var bClose : boolean ); override; final;

  end;

implementation

uses
uwizardconfigserver_data;

{$R *.lfm}

{ TWizardConfigServer_Finish }

procedure TWizardConfigServer_Finish.wizard_show();
begin
  inherited wizard_show();
  m_wizard.m_can_close := true;
end;

procedure TWizardConfigServer_Finish.wizard_finish(var bClose: boolean);
var
  data : PWizardConfigServerData;
begin
  data := m_wizard.data();
  data^.launch_console := self.cb_start_console.Checked;
  bClose := true;
end;


initialization

RegisterClass(TWizardConfigServer_Finish);


end.

