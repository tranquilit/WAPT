unit uwizardconfigserver_start_services;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls;

type

  { TWizardConfigServer_StartServices }

  TWizardConfigServer_StartServices = class(TWizardStepFrame)
    ImageList1: TImageList;
  private

  public

    procedure wizard_load(w: TWizard); override; final;
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;

  end;

implementation

uses
  dialogs,
  ExtCtrls,
  uwizardconfigserver_data,
  uwizardvalidattion,
  uwizardutil;



{$R *.lfm}

const
  IMG_SUCCEED : integer = 0;
  IMG_FAILED  : integer = 1;


{ TWizardConfigServer_StartServices }

procedure TWizardConfigServer_StartServices.wizard_load(w: TWizard);
var
  i : integer;
  lbl : TLabel;
  img : TImage;
begin
  inherited wizard_load(w);

  for i := 0 to Length(WAPT_SERVICES) - 1 do
  begin
    lbl := TLabel.Create( self );
    lbl.Caption:= WAPT_SERVICES[i];
    lbl.Align:= alTop;
    lbl.Parent := self;

    img := Timage.Create( self );
    img.Align := alTop;
    self.ImageList1.GetBitmap( IMG_SUCCEED, img.Picture.Bitmap );
    img.Parent := self;
  end;

end;

procedure TWizardConfigServer_StartServices.wizard_show();
begin
  inherited wizard_show();
  if m_show_count = 1 then
    self.m_wizard.click_next_async();
end;

procedure TWizardConfigServer_StartServices.wizard_next(var bCanNext: boolean);
var
  data : PWizardConfigServerData;
begin
  bCanNext := false;
  data := m_wizard.data();


  // Write setting
  data_write_ini_waptserver( m_wizard.data(), m_wizard );

  // Restart server
  if not wizard_validate_waptserver_start_services( m_wizard, nil ) then
    exit;

  // Restart local agent
  if data^.has_found_waptservice then
  begin
    Sleep( 1 * 1000 );
    self.m_wizard.SetValidationDescription( 'Register local machine');
    wapt_register();

    Sleep( 1 * 1000 );
    self.m_wizard.SetValidationDescription( 'Restarting local agent');
    wapt_service_restart();

    self.m_wizard.ClearValidationDescription();
  end;

  bCanNext := true;;
end;

initialization

RegisterClass(TWizardConfigServer_StartServices);

end.

