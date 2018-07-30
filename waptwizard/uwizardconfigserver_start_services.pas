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
begin
  bCanNext := false;

  if not wizard_validate_waptserver_start_services( m_wizard, nil ) then
    exit;

  bCanNext := true;;
end;

initialization

RegisterClass(TWizardConfigServer_StartServices);

end.

