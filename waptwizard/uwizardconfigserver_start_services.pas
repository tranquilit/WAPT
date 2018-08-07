unit uwizardconfigserver_start_services;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, ExtCtrls, ComCtrls;

type

  { TWizardConfigServer_StartServices }

  TWizardConfigServer_StartServices = class(TWizardStepFrame)
    progress: TProgressBar;
  private

  public

    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;

  end;

implementation

uses
  dialogs,
  uwizardconfigserver_data,
  uwizardvalidattion,
  uwizardutil;



{$R *.lfm}


{ TWizardConfigServer_StartServices }

procedure TWizardConfigServer_StartServices.wizard_show();
begin
  inherited wizard_show();

  self.progress.Position := 0;

  if m_show_count = 1 then
    self.m_wizard.click_next_async();

end;

procedure TWizardConfigServer_StartServices.wizard_next(var bCanNext: boolean);
const
  GRACEFULL_TIME_MS : integer = 1 * 1000;
var
  data : PWizardConfigServerData;
  i : integer;
begin
  bCanNext := false;
  data := m_wizard.data();

  self.progress.Max := Length(WAPT_SERVICES);
  if data^.has_found_waptservice then
    self.progress.Max := self.progress.Max + 2;

  // Write setting
  data_write_ini_waptserver( m_wizard.data(), m_wizard );

  // Restart services
  for i := 0 to Length(WAPT_SERVICES) - 1 do
  begin
    if not wizard_validate_service_start( self.m_wizard, nil, WAPT_SERVICES[i] ) then
      exit;
    self.progress.Position := self.progress.Position + 1;
  end;

  // Restart local agent
  if data^.has_found_waptservice then
  begin
    Sleep( GRACEFULL_TIME_MS );
    self.m_wizard.SetValidationDescription( 'Register local machine');
    wapt_register();
    self.progress.Position := self.progress.Position + 1;

    Sleep( GRACEFULL_TIME_MS );
    self.m_wizard.SetValidationDescription( 'Restarting local agent');
    wapt_service_restart();
    self.progress.Position := self.progress.Position + 1;

    self.m_wizard.ClearValidationDescription();
  end;

  bCanNext := true;;
end;

initialization

RegisterClass(TWizardConfigServer_StartServices);

end.

