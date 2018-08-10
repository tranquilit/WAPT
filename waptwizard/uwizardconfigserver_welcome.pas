unit uwizardconfigserver_welcome;

{$mode objfpc}{$H+}

interface

uses
  uwizardstepframe,
  uwizard,
  superobject,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, ExtCtrls;

type

  { TTWizardConfigServer_Welcome }

  TTWizardConfigServer_Welcome = class(TWizardStepFrame)
    image: TImage;
    m_label: TLabel;
  private

  public
    // TWizardStepFrame
    procedure wizard_load(w: TWizard); override; final;
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;
  end;

implementation


uses
  resources,
  LResources,
  uwizard_strings,
  uwapt_services,
  uwizardutil,
  uwizardconfigserver_data,
  uwizardvalidattion;

{$R *.lfm}


{ TTWizardConfigServer_Welcome }


procedure TTWizardConfigServer_Welcome.wizard_load(w: TWizard);
begin
  inherited wizard_load(w);

  self.image.Picture.LoadFromLazarusResource(RES_IMG_WAPT);
end;


procedure TTWizardConfigServer_Welcome.wizard_show();
begin
  m_wizard.setFocus_async( m_wizard.WizardButtonPanel.NextButton );
end;

procedure TTWizardConfigServer_Welcome.wizard_next(var bCanNext: boolean);
const
    STANDART_PORTS : array[0..1] of integer = (80,443);
var
  data : PWizardConfigServerData;
  i    : integer;
  msg : String;
  services : TStringArray;
begin
  bCanNext := false;
  data := PWizardConfigServerData( m_wizard.data() );


  // Validate os
  if not wizard_validate_os_version_for_server( m_wizard, nil ) then
    exit;

  // Stop services if present
  services := sa_flip(data^.services);
  for i := 0 to Length(services) -1 do
  begin
    msg := Format( MSG_STOPPING_SERVICE, [services[i]] );
    m_wizard.SetValidationDescription( msg );
    srv_stop( services[i] );
  end;

  // Skip port selection if
  i := net_port_is_close_on_all_interface( data^.has_standart_port_closed, PtrInt(@STANDART_PORTS[0]), Length(STANDART_PORTS) );
  if (i = 0) and data^.has_standart_port_closed then
    m_wizard.WizardManager.Pages.Delete( m_wizard.WizardManager.PageByName(PAGE_SERVER_OPTIONS).Index );

  // Skip mongo db if not present
  if not data^.has_found_mongodb then
    m_wizard.WizardManager.Pages.Delete( m_wizard.WizardManager.PageByName(PAGE_MONGODB).Index );



  m_wizard.ClearValidationDescription();

  bCanNext:= true;
  exit;
end;


initialization
RegisterClass(TTWizardConfigServer_Welcome);
end.

