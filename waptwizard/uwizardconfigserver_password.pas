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
    lbl_password_1: TLabel;
    lbl_password_2: TLabel;
    Panel1: TPanel;
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
  uwizard_strings,
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

  self.cb_password_visible.Checked := false;
  self.cb_password_visibleChange( nil );

end;


procedure TWizardConfigServer_Password.wizard_load(w: TWizard);
begin
  inherited wizard_load(w);
end;

procedure TWizardConfigServer_Password.wizard_show();
begin
  inherited wizard_show();


  self.ed_password_1.TabOrder                             := 0;
  self.ed_password_2.TabOrder                             := 1;
  self.cb_password_visible.TabOrder                       := 2;

  self.ed_password_1.SetFocus;

end;



procedure TWizardConfigServer_Password.wizard_next(var bCanNext: boolean);
var
  ed : TEdit;
  data : PWizardConfigServerData;
begin
  bCanNext := false;

  data := m_wizard.data();


  // admin password
  if self.ed_password_1.Focused then
    ed := self.ed_password_1
  else
    ed := self.ed_password_2;

  if not wizard_validate_str_password_are_equals( m_wizard, self.ed_password_1.Text, self.ed_password_2.Text, ed ) then
    exit;

  if not wizard_validate_password( m_wizard, self.ed_password_1, self.ed_password_1.Text ) then
    exit;


  data^.wapt_user     := 'admin';
  data^.wapt_password := self.ed_password_1.Text;
  data^.wapt_password_crypted := PBKDF2( self.ed_password_1.Text );




  bCanNext := true;
end;




initialization
  RegisterClass(TWizardConfigServer_Password);
end.

