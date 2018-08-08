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
  uwapt_services,
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
var
  data      : PWizardConfigServerData;
  i         : integer;
begin
  bCanNext := false;
  data := m_wizard.data();

  self.progress.Position := 0;
  self.progress.Max := Length(data^.services);

  // Write setting
  data_write_ini_waptserver( m_wizard.data(), m_wizard );

  for i := 0 to Length(data^.services) - 1 do
  begin
    if not wizard_validate_service_start( self.m_wizard, nil, data^.services[i] ) then
      exit;
    self.progress.Position := self.progress.Position + 1;
  end;

  self.m_wizard.ClearValidationDescription();

  bCanNext := true;;
end;

initialization

RegisterClass(TWizardConfigServer_StartServices);

end.

