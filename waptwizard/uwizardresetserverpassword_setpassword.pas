unit uwizardresetserverpassword_setpassword;

{$mode objfpc}{$H+}

interface

uses
  uwizardstepframe,
  uwizard,
  superobject,
  Classes, SysUtils, FileUtil, Forms, Controls, EditBtn, StdCtrls;

type

  { TWizardResetServerPasswordSetPassword }

  TWizardResetServerPasswordSetPassword = class(TWizardStepFrame)
    cb_show_passwords: TCheckBox;
    ed_password_1: TEdit;
    ed_password_2: TEdit;
    ed_wapt_server_home: TDirectoryEdit;
    lbl_password_1: TLabel;
    lbl_password_2: TLabel;
    lbl_wapt_server_home: TLabel;
    procedure cb_show_passwordsChange(Sender: TObject);
  private

  public
    procedure wizard_load( w : TWizard; data : ISuperObject ); override; final;
    procedure wizard_show(); override; final;
    function  wizard_validate() : integer; override; final;

  end;

implementation

uses
  uwizardvalidattion,
  uwizardutil;


{$R *.lfm}


{ TWizardResetServerPasswordSetPassword }

procedure TWizardResetServerPasswordSetPassword.cb_show_passwordsChange( Sender: TObject);
var
  c : Char;
begin
  if self.cb_show_passwords.Checked then
    c := #0
  else
    c := '*';

  self.ed_password_1.PasswordChar := c;
  self.ed_password_2.PasswordChar := c;

end;

procedure TWizardResetServerPasswordSetPassword.wizard_load(w: TWizard; data: ISuperObject);
var
  r : integer;
  s : String;
begin
  inherited wizard_load(w, data );

  self.ed_wapt_server_home.Clear;
  self.ed_password_1.Clear;
  self.ed_password_2.Clear;


  r := wapt_server_installation( s );
  if r = 0 then
    self.ed_wapt_server_home.Text := s;

end;

procedure TWizardResetServerPasswordSetPassword.wizard_show();
begin
  inherited wizard_show();

  self.ed_wapt_server_home.SetFocus;

  self.ed_wapt_server_home.TabOrder                       := 0;
  self.ed_password_1.TabOrder                             := 1;
  self.ed_password_2.TabOrder                             := 2;
  self.m_wizard.WizardButtonPanel.NextButton.TabOrder     := 3;
  self.m_wizard.WizardButtonPanel.PreviousButton.TabOrder := 4;
  self.m_wizard.WizardButtonPanel.CancelButton.TabOrder   := 5;
end;

function TWizardResetServerPasswordSetPassword.wizard_validate(): integer;
begin

  if not wizard_validate_path_is_waptserver( self.m_wizard, self.ed_wapt_server_home, self.ed_wapt_server_home.Text ) then
    exit(-1);

  if not wizard_validate_str_length_not_zero( self.m_wizard, self.ed_password_1, 'Password cannot be empty' ) then
    exit(-1);

  if not wizard_validate_str_password_are_equals( self.m_wizard, self.ed_password_1.Text, self.ed_password_2.Text, self.ed_password_2 ) then
    exit(-1);

  self.m_data.S['wapt_server_home'] := self.ed_wapt_server_home.Text ;

  exit(0);
end;

initialization

RegisterClass(TWizardResetServerPasswordSetPassword);
end.

