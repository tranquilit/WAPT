unit uwizardconfigserver_mongodb;

{$mode objfpc}{$H+}

interface

uses
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls;

type

  { TWizardConfigServer_MongoDB }

  TWizardConfigServer_MongoDB = class(TWizardStepFrame)
  private

  function migration_needed() : boolean;

  public
  procedure wizard_show(); override; final;
  procedure wizard_next(var bCanNext: boolean); override; final;
  end;

implementation


uses
  uwizardvalidattion,
  uwizardutil;
{$R *.lfm}

{ TWizardConfigServer_MongoDB }

function TWizardConfigServer_MongoDB.migration_needed(): boolean;
begin
  result := FileExists('waptserver\mongodb\mongoexport.exe');
end;

procedure TWizardConfigServer_MongoDB.wizard_show();
begin
  inherited wizard_show();
  if self.m_show_count = 1 then
    m_wizard.click_next_async();
end;

procedure TWizardConfigServer_MongoDB.wizard_next(var bCanNext: boolean);
label
  LBL_SKIP;
var
  r : integer;
begin
  bCanNext := false;
  if not self.migration_needed() then
    goto LBL_SKIP;

  wizard_validate_waptserver_stop_services_no_fail( m_wizard, nil );

  m_wizard.SetValidationDescription( 'Migrating from MongoDB to Postgresql');
  r := wapt_server_mongodb_to_postgresql();
  if r <> 0 then
  begin
    m_wizard.show_validation_error( nil, 'An has occured while migrating from mogodb to postgresql' );
    exit;
  end;

  if not wizard_validate_waptserver_start_services( self.m_wizard, nil ) then
    exit;

LBL_SKIP:
  bCanNext := true;
end;


initialization

RegisterClass(TWizardConfigServer_MongoDB);

end.

