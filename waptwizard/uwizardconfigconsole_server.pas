unit uwizardconfigconsole_server;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,

  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, Menus;

type

  { TWizardConfigConsole_Server }

  TWizardConfigConsole_Server = class( TWizardStepFrame)
    cb_password_visible: TCheckBox;
    ed_password: TEdit;
    ed_server_url: TEdit;
    lbl_password: TLabel;
    lbl_server_url: TLabel;
    procedure cb_password_visibleChange(Sender: TObject);
  private

  public

  // TWizardStepFrame
    procedure wizard_load(w: TWizard); override; final;
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;
    procedure clear();  override; final;


  end;

implementation

uses
  tiscommon,
  tisinifiles,
  uwapt_ini,
  uwizardconfigconsole_data,
  uwizardvalidattion;

{$R *.lfm}

{ TWizardConfigConsole_Server }


procedure TWizardConfigConsole_Server.wizard_load(w: TWizard);
var
  r    : integer;
  s    : String;
begin
  inherited wizard_load(w);


  // Try from waptconsole.ini
  r := wapt_ini_waptconsole( s );
  if r = 0 then
    self.ed_server_url.Text := IniReadString( s, INI_GLOBAL, INI_WAPT_SERVER, '' );


  self.ed_server_url.TabOrder       := 0;
  self.ed_password.TabOrder         := 1;
  self.cb_password_visible.TabOrder := 2;

end;

procedure TWizardConfigConsole_Server.wizard_show();
  function tedit_is_empty( e : TEdit ) : boolean;
  begin
      result := 0 = Length(Trim(e.Text));
  end;
begin
  inherited wizard_show();

  self.ed_server_url.SetFocus;
  if not tedit_is_empty(self.ed_server_url) then
  begin
      self.ed_password.SetFocus;
      if not tedit_is_empty(self.ed_password) then
        self.m_wizard.WizardButtonPanel.NextButton.SetFocus;
  end;


end;


procedure TWizardConfigConsole_Server.wizard_next(var bCanNext: boolean);
var
  data : PWizardConfigConsoleData;
begin
  bCanNext := false;
  data := self.m_wizard.data();

  // Ping
  if not wizard_validate_waptserver_ping( self.m_wizard, self.ed_server_url.Text, self.ed_server_url ) then
    exit;

  {
  // Version
  if not wizard_validate_waptserver_version_not_less( self.m_wizard, self.ed_server_url.Text,   GetApplicationVersion(),  self.ed_server_url ) then
    exit;
  }

  // Login
  if not wizard_validate_waptserver_login( self.m_wizard, self.ed_server_url.Text, false, 'admin', self.ed_password.Text, self.ed_password ) then
    exit;

  data^.wapt_server   := self.ed_server_url.Text;
  data^.wapt_user     := 'admin';
  data^.wapt_password := self.ed_password.Text;

  bCanNext := true;
end;

procedure TWizardConfigConsole_Server.clear();
begin
  inherited clear();

  self.ed_server_url.Clear;
  self.ed_password.Clear;
  self.cb_password_visible.Checked := false;
  self.cb_password_visibleChange( nil );
end;

procedure TWizardConfigConsole_Server.cb_password_visibleChange(Sender: TObject );
var
  c : Char;
begin
  if self.cb_password_visible.Checked then
      c := #0
  else
      c := '*';
  self.ed_password.PasswordChar := c;
end;




initialization
  RegisterClass(TWizardConfigConsole_Server);
end.

