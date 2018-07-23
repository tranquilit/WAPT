unit uwizardconfigconsole_server;

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
    procedure wizard_next(var bCanNext: boolean); override; final;
    procedure wizard_show(); override; final;

  procedure clear();  override; final;


  end;

implementation

uses
  uwizardresetserverpassword_data,
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


procedure TWizardStepFramePassword.wizard_next(var bCanNext: boolean);
var
  ed : TEdit;
  data : PWizardResetServerPasswordData;
begin
  bCanNext := false;


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


  data := PWizardResetServerPasswordData( self.m_wizard.data() );
  data^.wapt_user     := 'admin';
  data^.wapt_password := self.ed_password_2.Text;


  bCanNext := true;
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

