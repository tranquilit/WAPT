unit uwizardconfigconsole_keyoption;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, ExtCtrls;

type

  { TWizardConfigConsole_KeyOption }

  TWizardConfigConsole_KeyOption = class(TWizardStepFrame)
    lbl_description: TLabel;
    rb_create_new_key: TRadioButton;
    rb_use_existing_key: TRadioButton;
  private

  public
    constructor Create( AOwner : TComponent );
    procedure wizard_load(w: TWizard); override; final;
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;

  end;

implementation

uses
  uwizardconfigconsole_data,
  WizardControls;

{$R *.lfm}

{ TWizardConfigConsole_KeyOption }

constructor TWizardConfigConsole_KeyOption.Create(AOwner: TComponent);
begin
  inherited Create( AOwner, PAGE_KEYOPTION );
end;

procedure TWizardConfigConsole_KeyOption.wizard_load(w: TWizard);
begin
  inherited wizard_load(w);

  self.rb_use_existing_key.Checked := true;

end;

procedure TWizardConfigConsole_KeyOption.wizard_show();
begin
  inherited wizard_show();

  self.rb_use_existing_key.TabOrder                       := 0;
  self.rb_create_new_key.TabOrder                         := 1;

  self.m_wizard.WizardButtonPanel.NextButton.SetFocus;
end;

procedure TWizardConfigConsole_KeyOption.wizard_next(var bCanNext: boolean);
var
  p_key_option                : TWizardPage;
  p_build_agent               : TWizardPage;
  p_package_create_new_key    : TWizardPage;
  p_package_use_existing_key  : TWizardPage;
begin
  bCanNext := false;

  if (not self.rb_create_new_key.Checked) and (not self.rb_use_existing_key.Checked) then
  begin
    self.m_wizard.show_validation_error( self.rb_create_new_key, 'You must choose');
    exit;
  end;


  p_key_option                := self.m_wizard.WizardManager.PageByName( PAGE_KEYOPTION );
  p_build_agent               := self.m_wizard.WizardManager.PageByName( PAGE_BUILD_AGENT );
  p_package_create_new_key    := self.m_wizard.WizardManager.PageByName( PAGE_PACKAGE_CREATE_NEW_KEY );
  p_package_use_existing_key  := self.m_wizard.WizardManager.PageByName( PAGE_PACKAGE_USE_EXISTING_KEY );


  if self.rb_use_existing_key.Checked then
  begin
    p_key_option.NextOffset       := p_package_use_existing_key.Index - p_key_option.Index;
    p_build_agent.PreviousOffset  := p_build_agent.Index - p_package_use_existing_key.Index;
  end
  else
  begin
    p_key_option.NextOffset       :=p_package_create_new_key.Index - p_key_option.Index;
    p_build_agent.PreviousOffset  := p_build_agent.Index - p_package_create_new_key.Index;
  end;


  bCanNext := true;
end;

initialization

RegisterClass(TWizardConfigConsole_KeyOption);


end.

