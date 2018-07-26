unit uwizardconfigserver_restartwaptservice;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,

  Classes, SysUtils, FileUtil, Forms, Controls;

type

  { TWizardConfigServer_RestartWaptService }

  TWizardConfigServer_RestartWaptService = class(TWizardStepFrame)
  private

  public
    procedure wizard_show(); override; final;
    procedure wizard_next( var bCanNext : boolean ); override; final;

  end;

implementation

uses
  uwizardutil,
  uwizardconfigserver_data;


{$R *.lfm}

{ TWizardConfigServer_RestartWaptService }

procedure TWizardConfigServer_RestartWaptService.wizard_show();
begin
  inherited;
  if m_show_count = 1 then
    self.m_wizard.click_next_async();
end;

procedure TWizardConfigServer_RestartWaptService.wizard_next( var bCanNext: boolean);
var
  r : integer;
  data : PWizardConfigServerData;
begin
  bCanNext := false;
  data := m_wizard.data();

  // Write wapt-get.ini
  self.m_wizard.SetValidationDescription( 'Writing wapt service configuration file' );
  r := TWizardConfigServerData_write_ini_waptget( data, self.m_wizard );
  if r <> 0 then
    exit;

  // Force registration
  self.m_wizard.SetValidationDescription( 'Registering local machine' );
  r := wapt_register();
  if r <> 0 then
    exit;

  bCanNext := true;
end;

initialization

RegisterClass(TWizardConfigServer_RestartWaptService);


end.

