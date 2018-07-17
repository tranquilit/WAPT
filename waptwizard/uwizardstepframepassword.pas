unit uwizardstepframepassword;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,

  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, Menus;

type

  { TWizardStepFramePassword }

  TWizardStepFramePassword = class( TWizardStepFrame)
    cb_password_visible: TCheckBox;
    ed_password_1: TEdit;
    ed_password_2: TEdit;
    lbl_password_1: TLabel;
    lbl_password_2: TLabel;
    procedure cb_password_visibleChange(Sender: TObject);
  private

  public

  // TWizardStepFrame
  function wizard_validate() : integer;  override; final;
  procedure wizard_show(); override; final;

  procedure clear();  override; final;


  end;

implementation

uses
  uwizardvalidattion;

{$R *.lfm}

{ TWizardStepFramePassword }

procedure TWizardStepFramePassword.cb_password_visibleChange(Sender: TObject);
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


function TWizardStepFramePassword.wizard_validate(): integer;
var
  ed : TEdit;
begin

  m_wizard.SetValidationDescription( 'Validating supplied passwords' );
  if not wizard_validate_str_length_not_zero( m_wizard, self.ed_password_1, 'Password cannot be empty' ) then
    exit(-1);

  if self.ed_password_1.Focused then
    ed := self.ed_password_1
  else
    ed := self.ed_password_2;

  if not wizard_validate_str_password_are_equals( m_wizard, self.ed_password_1.Text, self.ed_password_2.Text, ed ) then
    exit(-1);

  m_wizard.ClearValidationDescription();


  self.m_data.S['server_user'] := 'admin';
  self.m_data.S['server_password'] := self.ed_password_1.Text;

  exit(0);


end;

procedure TWizardStepFramePassword.wizard_show();
begin
  inherited wizard_show();
  self.ed_password_1.SetFocus;
end;

procedure TWizardStepFramePassword.clear();
begin
  self.ed_password_1.Clear;
  self.ed_password_2.Clear;
end;



initialization
RegisterClass(TWizardStepFramePassword);


end.

