unit uwizardstepframe;

{$mode objfpc}{$H+}

interface

uses
  WizardControls,
  uwizard,
  Classes, SysUtils, FileUtil, Forms, Controls, ExtCtrls;

type

  { TWizardStepFrame }

  TWizardStepFrame = class( TFrame, IWizardPage )
    panel_frame: TPanel;

  protected
    m_wizard      : TWizard;
    m_show_count  : integer;

  public
    constructor Create( AOwner : TComponent ); override;


    procedure wizard_load( w : TWizard ); virtual;
    procedure wizard_show(); virtual;
    procedure wizard_hide(); virtual;
    procedure wizard_previous( var bCanPrevious : boolean ); virtual;
    procedure wizard_next(var bCanNext : boolean ); virtual;
    procedure wizard_finish( var bClose : boolean ); virtual;
    procedure wizard_cancel( var bClose : boolean ); virtual;
    procedure clear(); virtual;
    procedure GetPageInfo(var PageInfo: TWizardPageInfo); virtual;

  end;

implementation



{$R *.lfm}

{ TWizardStepFrame }

constructor TWizardStepFrame.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  self.panel_frame.Caption    := '';
  self.panel_frame.AutoSize   := false;
  self.panel_frame.BevelOuter := bvNone;
  self.AutoSize     := true;
  self.m_show_count := 0;
  self.m_wizard     := nil;
end;

procedure TWizardStepFrame.wizard_load( w: TWizard );
begin
  m_wizard := w;
end;

procedure TWizardStepFrame.wizard_show();
begin
  self.m_show_count := self.m_show_count + 1;
end;

procedure TWizardStepFrame.wizard_hide();
begin
end;

procedure TWizardStepFrame.wizard_previous(var bCanPrevious: boolean);
begin
end;

procedure TWizardStepFrame.wizard_next(var bCanNext: boolean);
begin
end;

procedure TWizardStepFrame.wizard_finish(var bClose: boolean);
begin
end;

procedure TWizardStepFrame.wizard_cancel(var bClose: boolean);
begin
end;

procedure TWizardStepFrame.clear();
begin
end;

procedure TWizardStepFrame.GetPageInfo(var PageInfo: TWizardPageInfo);
begin
end;

end.

