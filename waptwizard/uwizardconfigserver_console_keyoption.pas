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
  tisinifiles,
  uwapt_ini,
  uwizardutil,
  uwizardconfigserver_data,
  WizardControls;

{$R *.lfm}

{ TWizardConfigServer_Console_KeyOption }

procedure TWizardConfigServer_Console_KeyOption.wizard_load(w: TWizard);
var
  s : String;
  r : integer;

begin
  inherited wizard_load(w);

  self.rb_use_existing_key.Checked  := false;
  self.rb_create_new_key.Checked    := true;

  r := wapt_installpath_waptserver( s);
  if r <> 0 then
    exit;

  s := IncludeTrailingBackslash(s) +  'waptserver\repository\wapt\waptagent.exe';
  if  FileExists(s) then
  begin
    self.rb_use_existing_key.Checked := true;
    exit;
  end;


  r := wapt_ini_waptconsole(s);
  if r <>0  then
    exit;


  s := IniReadString( s, INI_GLOBAL, INI_PERSONAL_CERTIFICATE_PATH, '' );
  if not FileExists(s) then
    exit;

  s :=   ExtractFileNameWithoutExt(s) + '.pem';
  if not FileExists(s) then
    exit;


  self.rb_use_existing_key.Checked  := true;
  self.rb_create_new_key.Checked    := false;


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
  p_key_option                : TWizardPage;
  p_server_url                : TWizardPage;
begin
  bCanNext := false;

  if (not self.rb_create_new_key.Checked) and (not self.rb_use_existing_key.Checked) then
  begin
    self.m_wizard.show_validation_error( self.rb_create_new_key, 'You must choose');
    exit;
  end;


  p_key_option  := self.m_wizard.WizardManager.PageByName( WizardConfigServerPage_page_keyoption );
  p_server_url  := self.m_wizard.WizardManager.PageByName( WizardConfigServerPage_page_server_url );


  if self.rb_use_existing_key.Checked then
  begin
    p_key_option.NextOffset      := 2;
    p_server_url.PreviousOffset  := 1;
  end
  else
  begin
    p_key_option.NextOffset      := 1;
    p_server_url.PreviousOffset  := 2;
  end;


  bCanNext := true;
end;

initialization

RegisterClass(TWizardConfigServer_Console_KeyOption);


end.

