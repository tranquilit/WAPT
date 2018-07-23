unit uwizardconfigserver_server;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,

  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, Menus, ExtCtrls;

type

  { TWizardConfigServer_Server }

  TWizardConfigServer_Server = class( TWizardStepFrame)
    cb_password_visible: TCheckBox;
    ed_password_1: TEdit;
    ed_password_2: TEdit;
    gb_admin_password: TGroupBox;
    lbl_password_1: TLabel;
    lbl_password_2: TLabel;
    rg_server_url: TRadioGroup;
    procedure cb_password_visibleChange(Sender: TObject);
  private

  public


  // TWizardStepFrame
  procedure clear();  override; final;
  procedure wizard_load( w : TWizard ); override; final;
  procedure wizard_show(); override; final;
  procedure wizard_next(var bCanNext: boolean); override; final;



  end;

implementation

uses
  uwizardconfigconsole_data,
  uwizardutil,
  uwizardvalidattion;

{$R *.lfm}

{ TWizardConfigServer_Server }

procedure TWizardConfigServer_Server.cb_password_visibleChange(Sender: TObject);
var
  c : Char;
begin
  if self.cb_password_visible.Checked then
    c := #0
  else
    c:= '*';

  self.ed_password_1.PasswordChar := c;
  self.ed_password_2.PasswordChar := c;
end;

procedure TWizardConfigServer_Server.clear();
begin
  self.ed_password_1.Clear;
  self.ed_password_2.Clear;
end;


procedure TWizardConfigServer_Server.wizard_load(w: TWizard);
var
  sl : TStringList;
  i : integer;
begin
  inherited wizard_load(w);

  // Server url
  self.rg_server_url .Items.Clear;
  sl := TStringList.Create;
  i := net_list_enable_ip( sl );
  if i = 0 then
  begin
    for i := 0 to sl.Count -1 do
    begin
      if 'localhost' = sl.Strings[i] then
        continue;
      self.rg_server_url.Items.AddObject( sl.Strings[i], sl.Objects[i] );
    end;
  end;

end;

procedure TWizardConfigServer_Server.wizard_show();
begin
  inherited wizard_show();


  self.gb_admin_password.TabOrder                         := 1;
  self.m_wizard.WizardButtonPanel.TabOrder                := 2;


  self.rg_server_url.TabOrder                             := 0;
  self.ed_password_1.TabOrder                             := 1;
  self.ed_password_2.TabOrder                             := 2;
  self.m_wizard.WizardButtonPanel.NextButton.TabOrder     := 3;
  self.m_wizard.WizardButtonPanel.PreviousButton.TabOrder := 4;
  self.m_wizard.WizardButtonPanel.CancelButton.TabOrder   := 5;

  self.ed_password_1.SetFocus;

end;



procedure TWizardConfigServer_Server.wizard_next(var bCanNext: boolean);
var
  ed : TEdit;
  s : String;
  data : PWizardConfigConsoleData;
begin
  bCanNext := false;

  data := m_wizard.data();

  // server_url
  if self.rg_server_url.ItemIndex = -1 then
  begin
    m_wizard.show_validation_error( self.rg_server_url, 'You must a valid server url' );
    exit;
  end;

  s := self.rg_server_url.Items[ self.rg_server_url.ItemIndex ];

  data^.wapt_server := 'https://' + s;
  data^.server_certificate := s  + '.crt';

  // admin password
  m_wizard.SetValidationDescription( 'Validating supplied passwords' );
  if not wizard_validate_str_length_not_zero( m_wizard, self.ed_password_1, 'Password cannot be empty' ) then
    exit;

  if self.ed_password_1.Focused then
    ed := self.ed_password_1
  else
    ed := self.ed_password_2;

  if not wizard_validate_str_password_are_equals( m_wizard, self.ed_password_1.Text, self.ed_password_2.Text, ed ) then
    exit;

  m_wizard.ClearValidationDescription();


  data^.wapt_user :=  'admin';
  data^.wapt_password := self.ed_password_1.Text;


  bCanNext := true;
end;




initialization
RegisterClass(TWizardConfigServer_Server);


end.

