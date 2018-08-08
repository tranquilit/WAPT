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
  uwizard_strings,
  uwapt_services,
  tiscommon,
  uwizardutil,
  uwizardconfigserver_data,
  uwizardvalidattion;

{$R *.lfm}


{ TTWizardConfigServer_Welcome }



procedure TTWizardConfigServer_Welcome.wizard_show();
begin
  m_wizard.setFocus_async( m_wizard.WizardButtonPanel.NextButton );
end;

procedure TTWizardConfigServer_Welcome.wizard_next(var bCanNext: boolean);
var
  data : PWizardConfigServerData;
  i    : integer;
  msg : String;
  services : TStringArray;
begin
  bCanNext := false;
  data := PWizardConfigServerData( m_wizard.data() );


  if not wizard_validate_os_version_for_server( m_wizard, nil ) then
    exit;


  services := sa_flip(data^.services);
  for i := 0 to Length(services) -1 do
  begin
    msg := Format( MSG_STOPPING_SERVICE, [services[i]] );
    m_wizard.SetValidationDescription( msg );
    srv_stop( services[i] );
  end;

  m_wizard.ClearValidationDescription();

  bCanNext:= true;
  exit;
end;


initialization

RegisterClass(TTWizardConfigServer_Welcome);

end.

