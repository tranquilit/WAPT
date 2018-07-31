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
  r : integer;
  s : String;
begin
  bCanNext := false;

  // Write setting
  TWizardConfigServerData_write_ini_waptserver( m_wizard.data(), m_wizard );

  // Restart server
  if not wizard_validate_waptserver_start_services( m_wizard, nil ) then
    exit;

  // Restart agent
  r := wapt_installpath_waptservice(s);
  if r = 0 then
  begin
    Sleep( 1 * 1000 );

    self.m_wizard.SetValidationDescription( 'Registration');
    r := wapt_register();

    self.m_wizard.SetValidationDescription( 'Restarting agent');
    wapt_service_restart();

    self.m_wizard.ClearValidationDescription();
  end;

  bCanNext := true;;
end;

initialization

RegisterClass(TWizardConfigServer_StartServices);

end.

