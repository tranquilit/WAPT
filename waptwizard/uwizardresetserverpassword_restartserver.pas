unit uwizardresetserverpassword_restartserver;

{$mode objfpc}{$H+}

interface

uses
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, EditBtn, StdCtrls;

type

  { TWizardResetServerPasswordRestartServer }

  TWizardResetServerPasswordRestartServer = class(TWizardStepFrame)
  private

  public
    procedure wizard_show(); override; final;
    function  wizard_validate() : integer; override; final;

  end;

implementation

uses
    DCPsha256,
  uwapt_ini,
  IniFiles,
  ucrypto_pbkdf2,
  tiscommon,
  uwizardutil;

{$R *.lfm}

{ TWizardResetServerPasswordRestartServer }

procedure TWizardResetServerPasswordRestartServer.wizard_show();
begin
  self.m_wizard.WizardButtonPanel.NextButton.Click;
end;

function TWizardResetServerPasswordRestartServer.wizard_validate(): integer;
var
  r : integer;
  s : String;
  ini : TIniFile;
begin

  // Stop serviceS
  m_wizard.SetValidationDescription( 'Stopping waptserver');
  r := wapt_server_set_state( ssStopped );
  if r <> 0 then
    exit(-1);

  //
  s := self.m_data.S['wapt_server_home'];
  wapt_ini_waptserver( s, s );
  try
    ini := TIniFile.Create(s);
    s := PBKDF2(s, random_alphanum(5), 29000, 32, TDCP_sha256);
    ini.WriteString( INI_OPTIONS, INI_WAPT_PASSWORD, s );
    FreeAndNil(ini);
  except on Ex : Exception do
  begin
    m_wizard.show_validation_error( nil, 'An error has occurred while writing password');
  end;
  end;
  // Starting serviceS
  m_wizard.SetValidationDescription( 'Restarting waptserver');
  r := wapt_server_set_state( ssRunning );
  if r <> 0 then
    exit(-1);

  m_wizard.ClearValidationDescription();
  exit(0);
end;

initialization

RegisterClass(TWizardResetServerPasswordRestartServer);
end.

