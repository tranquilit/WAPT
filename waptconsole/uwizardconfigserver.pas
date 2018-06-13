unit uwizardconfigserver;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, uwizard,
  ComCtrls, ExtCtrls, StdCtrls, PopupNotifier, WizardControls;

type
  TWizardConfigServerParams = record
  end;
  PWizardConfigServer = ^TWizardConfigServer;

  { TWizardConfigServer }

  TWizardConfigServer = class(TWizard)
    ts_finish: TTabSheet;
    ts_welcome: TTabSheet;
  private

  protected
    procedure register_steps(); override; final;
    procedure on_step_show( ts: TTabSheet); override; final;

  public
    procedure init( params : PWizardConfigServer );

  end;

var
  WizardConfigServer: TWizardConfigServer;

implementation

{$R *.lfm}

{ TWizardConfigServer }

procedure TWizardConfigServer.register_steps();
begin
  self.register_step( 'Welcome step title', 'Welcome step description', [wbNext,wbCancel], nil );
  self.register_step( 'Finish step title',  'Finish step description',  [wbFinish], nil  );
end;

procedure TWizardConfigServer.on_step_show( ts: TTabSheet);
begin
     if self.ts_welcome = ts then
     begin

       exit;
     end;

     if self.ts_finish = ts then
     begin

       exit;
     end;


end;



procedure TWizardConfigServer.init(params: PWizardConfigServer);
begin

end;

end.

