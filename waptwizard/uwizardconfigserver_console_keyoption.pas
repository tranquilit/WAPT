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
    Panel1: TPanel;
    rb_create_new_key: TRadioButton;
    rb_use_existing_key: TRadioButton;
  private

  public
    constructor Create(AOwner: TComponent);
    procedure wizard_load(w: TWizard); override; final;
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;

  end;

implementation

uses
  dialogs,
  tisinifiles,
  uwapt_ini,
  uwizardutil,
  uwizardconfigserver_data,
  WizardControls;

{$R *.lfm}

{ TWizardConfigServer_Console_KeyOption }

constructor TWizardConfigServer_Console_KeyOption.Create(AOwner: TComponent);
begin
  inherited Create( AOwner, PAGE_KEYOPTION );
end;

procedure TWizardConfigServer_Console_KeyOption.wizard_load(w: TWizard);
var
  s     : String;
  r     : integer;
  data  : PWizardConfigServerData;
  b     : boolean;
begin
  inherited wizard_load(w);

  data := m_wizard.data();

  b := FileExists(data^.package_certificate);
  self.rb_use_existing_key.Checked  := b;
  self.rb_create_new_key.Checked    := not b;
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
  p_key_option  : TWizardPage;
  p_server_url  : TWizardPage;
  data          : PWizardConfigServerData;
  msg           : String;
begin
  bCanNext := false;

  data := m_wizard.data();


  if (not self.rb_create_new_key.Checked) and (not self.rb_use_existing_key.Checked) then
  begin
    self.m_wizard.show_validation_error( self.rb_create_new_key, 'You must choose');
    exit;
  end;

  if self.rb_create_new_key.Checked and data^.has_found_waptagent then
  begin
    msg :=       'A download agent has been detected on the server ';
    msg := msg + 'Are you sure you want to create a new key ?';
    if mrNo = self.m_wizard.show_question( msg, mbYesNo ) then
      exit;
  end;



  p_key_option  := self.m_wizard.WizardManager.PageByName( PAGE_KEYOPTION );
  p_server_url  := self.m_wizard.WizardManager.PageByName( PAGE_SERVER_URL );


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

