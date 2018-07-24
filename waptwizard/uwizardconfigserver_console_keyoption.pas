unit uwizardconfigserver_console_keyoption;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, ExtCtrls;

type

  { TWizardConfigServer_Console_KeyOption }

  TWizardConfigServer_Console_KeyOption = class(TWizardStepFrame)
    lbl_description: TLabel;
    rb_create_new_key: TRadioButton;
    rb_use_existing_key: TRadioButton;
  private

  public
  procedure wizard_load(w: TWizard); override; final;
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;

  end;

implementation

uses
  WizardControls;

{$R *.lfm}

{ TWizardConfigServer_Console_KeyOption }

procedure TWizardConfigServer_Console_KeyOption.wizard_load(w: TWizard);
begin
  inherited wizard_load(w);

  self.rb_use_existing_key.Checked := true;

end;

procedure TWizardConfigServer_Console_KeyOption.wizard_show();
begin
  inherited wizard_show();

  self.rb_use_existing_key.TabOrder                       := 0;
  self.rb_create_new_key.TabOrder                         := 1;

  self.m_wizard.WizardButtonPanel.NextButton.SetFocus;
end;

procedure TWizardConfigServer_Console_KeyOption.wizard_next(var bCanNext: boolean);
var
  p : TWizardPage;
begin
  bCanNext := false;

  if (not self.rb_create_new_key.Checked) and (not self.rb_use_existing_key.Checked) then
  begin
    self.m_wizard.show_validation_error( self.rb_create_new_key, 'You must choose');
    exit;
  end;

  p := self.m_wizard.WizardManager.Pages[self.m_wizard.WizardManager.PageIndex];
  if self.rb_use_existing_key.Checked then
    p.NextOffset := 2
  else
    p.NextOffset := 1;


  bCanNext := true;
end;

initialization

RegisterClass(TWizardConfigServer_Console_KeyOption);


end.

