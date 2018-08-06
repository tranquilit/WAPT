unit uwizardconfigserver_start_services;

{$mode objfpc}{$H+}

interface

uses
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls;

type

  { TWizardConfigServer_StartServices }

  TWizardConfigServer_StartServices = class(TWizardStepFrame)
  private

  public

    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;

  end;

implementation

uses
  uwizardconfigserver_data,
  uwizardvalidattion,
  uwizardutil;

{$R *.lfm}

{ TWizardConfigServer_StartServices }


procedure TWizardConfigServer_StartServices.wizard_show();
begin
  inherited wizard_show();
  if m_show_count = 1 then
    self.m_wizard.click_next_async();
end;

procedure TWizardConfigServer_StartServices.wizard_next(var bCanNext: boolean);
var
  data : PWizardConfigServerData;
begin
  bCanNext := false;
  data := m_wizard.data();


  // Write setting
  data_write_ini_waptserver( m_wizard.data(), m_wizard );

  // Restart server
  if not wizard_validate_waptserver_start_services( m_wizard, nil ) then
    exit;

  // Restart local agent
  if data^.has_found_waptservice then
  begin
    Sleep( 1 * 1000 );
    self.m_wizard.SetValidationDescription( 'Register local machine');
    wapt_register();

    Sleep( 1 * 1000 );
    self.m_wizard.SetValidationDescription( 'Restarting local agent');
    wapt_service_restart();

    self.m_wizard.ClearValidationDescription();
  end;

  bCanNext := true;;
end;

initialization

RegisterClass(TWizardConfigServer_StartServices);

end.

