unit uwizardconfigserver_password;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,

  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, Menus, ExtCtrls;

type

  { TWizardConfigServer_Password }

  TWizardConfigServer_Password = class( TWizardStepFrame)
    cb_password_visible: TCheckBox;
    ed_password_1: TEdit;
    ed_password_2: TEdit;
    gb_admin_password: TGroupBox;
    lbl_password_1: TLabel;
    lbl_password_2: TLabel;
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
  DCPsha256,
  ucrypto_pbkdf2,
  uwizardconfigserver_data,
  uwizardutil,
  uwizardvalidattion;

{$R *.lfm}

{ TWizardConfigServer_Password }

procedure TWizardConfigServer_Password.cb_password_visibleChange(Sender: TObject);
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

procedure TWizardConfigServer_Password.clear();
begin
  self.ed_password_1.Clear;
  self.ed_password_2.Clear;
end;


procedure TWizardConfigServer_Password.wizard_load(w: TWizard);
var
  sl : TStringList;
  i : integer;
begin
  inherited wizard_load(w);



end;

procedure TWizardConfigServer_Password.wizard_show();
begin
  inherited wizard_show();


  self.gb_admin_password.TabOrder                         := 0;
  self.m_wizard.WizardButtonPanel.TabOrder                := 1;


  self.ed_password_1.TabOrder                             := 1;
  self.ed_password_2.TabOrder                             := 2;
  self.cb_password_visible.TabOrder                       := 3;

  self.m_wizard.WizardButtonPanel.NextButton.TabOrder     := 0;
  self.m_wizard.WizardButtonPanel.PreviousButton.TabOrder := 1;
  self.m_wizard.WizardButtonPanel.CancelButton.TabOrder   := 2;

  self.ed_password_1.SetFocus;

end;



procedure TWizardConfigServer_Password.wizard_next(var bCanNext: boolean);
var
  ed : TEdit;
  s : String;
  data : PWizardConfigServerData;
begin
  bCanNext := false;

  data := m_wizard.data();



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

  data^.wapt_user     := 'admin';
  data^.wapt_password := self.ed_password_1.Text;
  data^.wapt_password_crypted := PBKDF2( self.ed_password_1.Text, random_alphanum(5), 29000, 32, TDCP_sha256);




  bCanNext := true;
end;




initialization
  RegisterClass(TWizardConfigServer_Password);
end.

