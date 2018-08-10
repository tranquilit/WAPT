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

    procedure wizard_load(w: TWizard); override; final;

  end;

implementation

uses
  LResources,
  resources;
{$R *.lfm}



{ TWizardStepFrameConsoleWelcome }

procedure TWizardStepFrameConsoleWelcome.wizard_load( w: TWizard );
begin
  inherited wizard_load(w);

  self.image.Picture.LoadFromLazarusResource(RES_IMG_WAPT);

end;

initialization

RegisterClass(TWizardStepFrameConsoleWelcome);

end.

