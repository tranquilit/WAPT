unit uwizardconfigserver_welcome;

{$mode objfpc}{$H+}

interface

uses
  uwizardstepframe,
  uwizard,
  superobject,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls;

type

  { TTWizardConfigServer_Welcome }

  TTWizardConfigServer_Welcome = class(TWizardStepFrame)
    m_label: TLabel;
  private

  public
    // TWizardStepFrame
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;
  end;

implementation


uses
  uwizardvalidattion;

{$R *.lfm}


{ TTWizardConfigServer_Welcome }



procedure TTWizardConfigServer_Welcome.wizard_show();
begin
  m_wizard.setFocus_async( m_wizard.WizardButtonPanel.NextButton );
  ;
end;

procedure TTWizardConfigServer_Welcome.wizard_next(var bCanNext: boolean);
begin
  bCanNext := false;

  if not wizard_validate_os_version_for_server( m_wizard, nil ) then
    exit;

  wizard_validate_waptserver_stop_services_no_fail( m_wizard, nil );

  bCanNext:= true;
  exit;
end;


initialization
  RegisterClass(TTWizardConfigServer_Welcome);

end.

