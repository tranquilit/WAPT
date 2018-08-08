unit uwizardconfigconsole_restartwaptservice;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls;

type

  { TWizardConfigConsole_RestartWaptService }

  TWizardConfigConsole_RestartWaptService = class(TWizardStepFrame)
  private

  public

    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;

  end;

implementation

uses
  uwapt_services,
  uwizardutil,
  uwizardconfigconsole_data;

{$R *.lfm}

{ TWizardConfigConsole_RestartWaptService }

procedure TWizardConfigConsole_RestartWaptService.wizard_show();
begin
  inherited wizard_show();
  m_wizard.click_next_async();
end;

procedure TWizardConfigConsole_RestartWaptService.wizard_next( var bCanNext: boolean);
var
  r : integer;
  data : PWizardConfigConsoleData;
begin

  bCanNext := false;
  data := m_wizard.data();

  // Write waptservice config
  self.m_wizard.SetValidationDescription('Writing WAPTService configuration');
  r := TWizardConfigConsoleData_write_ini_waptget( data, self.m_wizard );
  if r <> 0 then
    exit;

  // Force registration
  self.m_wizard.SetValidationDescription( 'Registering local machine' );
  r := wapt_register();
  if r <> 0 then
    exit;

  // Force restart wapt agent service
  self.m_wizard.SetValidationDescription( 'Restarting wapt agent service');
  if not srv_restart( WAPT_SERVICES_AGENT ) then
      exit;


  bCanNext := true;
end;


initialization

RegisterClass(TWizardConfigConsole_RestartWaptService);

end.

