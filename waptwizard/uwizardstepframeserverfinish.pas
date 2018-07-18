unit uwizardstepframeserverfinish;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  superobject,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls;

type

  { TWizardStepFrameServerFinish }

  TWizardStepFrameServerFinish = class(TWizardStepFrame)
    cb_start_console: TCheckBox;
  private

  public

    // TWizardStepFrame
    procedure wizard_load( w : TWizard; data : ISuperObject );   override; final;
    function wizard_validate() : integer;  override; final;
    procedure wizard_finish( var bClose : boolean ); override; final;

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

procedure TWizardStepFrameServerFinish.wizard_finish(var bClose: boolean);
begin
  self.m_data.B['launch_console'] := self.cb_start_console.Checked;
  bClose := true;
end;


initialization

RegisterClass(TWizardStepFrameServerFinish);


end.

