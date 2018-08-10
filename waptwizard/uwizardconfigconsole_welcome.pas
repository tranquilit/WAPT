unit uwizardconfigconsole_welcome;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, ExtCtrls;

type

  { TWizardStepFrameConsoleWelcome }

  TWizardStepFrameConsoleWelcome = class(TWizardStepFrame)
    image: TImage;
    lbl: TLabel;
  private

  public
    constructor Create(AOwner: TComponent);
    procedure wizard_load(w: TWizard); override; final;

  end;

implementation

uses
  uwizardconfigconsole_data,
  LResources,
  resources;
{$R *.lfm}



{ TWizardStepFrameConsoleWelcome }

constructor TWizardStepFrameConsoleWelcome.Create( AOwner: TComponent );
begin
  inherited Create( AOwner, PAGE_WELCOME );
end;

procedure TWizardStepFrameConsoleWelcome.wizard_load( w: TWizard );
begin
  inherited wizard_load(w);

  self.image.Picture.LoadFromLazarusResource(RES_IMG_WAPT);

end;

initialization

RegisterClass(TWizardStepFrameConsoleWelcome);

end.

