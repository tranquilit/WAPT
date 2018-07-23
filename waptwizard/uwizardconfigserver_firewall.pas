unit uwizardconfigserver_firewall;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  WizardControls,
  Classes, SysUtils, FileUtil, Forms, Controls;

type

  { TWizardConfigServer_Firewall }

  TWizardConfigServer_Firewall = class( TWizardStepFrame )
  private
  public
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;

  end;

implementation


uses
  Dialogs,
  uwizardvalidattion,
  uwizardutil;

{$R *.lfm}



{ TWizardConfigServer_Firewall }

procedure TWizardConfigServer_Firewall.wizard_show();
begin
  inherited wizard_show();

  if m_show_count = 1 then
    m_wizard.WizardButtonPanel.NextButton.Click;

end;

procedure TWizardConfigServer_Firewall.wizard_next(var bCanNext: boolean);
var
  b : Boolean;
  r : integer;
begin
   bCanNext := false;

  //
  m_wizard.SetValidationDescription( 'Checking if firewall rules need to be added' );
  r := wapt_server_firewall_is_configured( b );
  if r <> 0 then
  begin
    m_wizard.show_validation_error( nil, 'Error while checking for firewall rules');
    exit;
  end;
  if not b then
  begin
    if mrYes = m_wizard.show_question( 'Do you want to add configure the firewall', mbYesNo ) then
    begin
      r := wapt_server_configure_firewall();
      if r <> 0 then
      begin
        m_wizard.show_validation_error( nil, 'Error while configuring firewall' );
        exit;
      end;
    end;
  end;


  //
  m_wizard.SetValidationDescription( 'Checking if port 80 and 443 are in use' );
  if not wizard_validate_net_local_port_is_closed( m_wizard, 80, nil ) then
    exit;

  if not wizard_validate_net_local_port_is_closed( m_wizard, 443, nil ) then
    exit;


  bCanNext := true;
end;



initialization
  RegisterClass(TWizardConfigServer_Firewall);


end.

