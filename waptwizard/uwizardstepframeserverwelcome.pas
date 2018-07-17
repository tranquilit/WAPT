unit uwizardstepframeserverwelcome;

{$mode objfpc}{$H+}

interface

uses
  uwizardstepframe,
  uwizard,
  superobject,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls;

type

  { TWizardStepFrameServerWelcome }

  TWizardStepFrameServerWelcome = class(TWizardStepFrame)
    m_label: TLabel;
  private

  public
    // TWizardStepFrame
    procedure wizard_load( w : TWizard; data : ISuperObject);  override; final;
    function wizard_validate() : integer;  override; final;
  end;

implementation


uses
  uwizardvalidattion;

{$R *.lfm}


{ TWizardStepFrameServerWelcome }


procedure TWizardStepFrameServerWelcome.wizard_load(w: TWizard; data: ISuperObject);
begin
  inherited wizard_load( w, data );



end;

function TWizardStepFrameServerWelcome.wizard_validate(): integer;
begin
  if not wizard_validate_os_version_for_server( m_wizard, nil ) then
    exit(-1);

  wizard_validate_waptserver_stop_services_no_fail( m_wizard, nil );
  exit(0);
end;


initialization
  RegisterClass(TWizardStepFrameServerWelcome);

end.

