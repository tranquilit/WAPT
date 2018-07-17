unit uwizardstepframeserverfinish;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  superobject,
  Classes, SysUtils, FileUtil, Forms, Controls;

type

  { TWizardStepFrameServerFinish }

  TWizardStepFrameServerFinish = class(TWizardStepFrame)
  private

  public

    // TWizardStepFrame
    procedure wizard_load( w : TWizard; data : ISuperObject );   override; final;
    function wizard_validate() : integer;  override; final;

  end;

implementation

{$R *.lfm}

{ TWizardStepFrameServerFinish }

procedure TWizardStepFrameServerFinish.wizard_load(w: TWizard; data: ISuperObject);
begin
  inherited wizard_load(w, data);
end;

function TWizardStepFrameServerFinish.wizard_validate(): integer;
begin
  exit(0);
end;


initialization

RegisterClass(TWizardStepFrameServerFinish);


end.

