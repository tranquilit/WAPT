unit uwizardconfigserver_package_use_existing_key;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, ExtCtrls, StdCtrls, EditBtn;

type

  { TWizardConfigServer_PackageUseExistingKey }

  TWizardConfigServer_PackageUseExistingKey = class(TWizardStepFrame)
    cb_show_password: TCheckBox;
    ed_password: TEdit;
    ed_package_prefix: TEdit;
    ed_key: TFileNameEdit;
    gb_package_signing: TGroupBox;
    lbl_password: TLabel;
    lbl_package_prefix: TLabel;
    lbl_select_key: TLabel;
    gb_package: TGroupBox;
    procedure cb_show_passwordChange(Sender: TObject);
  private

  public
    procedure clear();  override; final;
    procedure wizard_load( w : TWizard ); override; final;
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;
  end;

implementation

uses
  IniFiles,
  uwapt_ini,
  uwizardutil,
  uwizardvalidattion
  ;

{$R *.lfm}

{ TWizardConfigServer_PackageUseExistingKey }

procedure TWizardConfigServer_PackageUseExistingKey.cb_show_passwordChange( Sender: TObject);
var
  c: Char;
begin
  if self.cb_show_password.Checked then
    c := #0
  else
    c := '*';
  self.ed_password.PasswordChar := c;
end;

procedure TWizardConfigServer_PackageUseExistingKey.clear();
begin
  inherited clear();
  self.ed_package_prefix.Clear;
  self.ed_key.Clear;
  self.ed_password.Clear;
  self.cb_show_password.Checked := false;
  self.cb_show_passwordChange( nil );
end;

procedure TWizardConfigServer_PackageUseExistingKey.wizard_load(w: TWizard);
var
  r   : integer;
  s   : String;
  ini : TIniFile;
begin
  inherited wizard_load(w );

  self.ed_package_prefix.Text := 'test';

  self.ed_key.Filter := 'Private key file|*.pem';

  // Fill from waptconsole.ini
  r := wapt_ini_waptconsole( s );
  if r = 0 then
  begin
    ini := TIniFile.Create( s );
    try
      self.ed_package_prefix.Text := ini.ReadString( INI_GLOBAL, INI_DEFAULT_PACKAGE_PREFIX, 'test' );
      s := ini.ReadString( INI_GLOBAL, INI_PERSONAL_CERTIFICATE_PATH, '' );
      s := ExtractFileNameWithoutExt(s) + '.pem';
      if FileExists(s) then
        self.ed_key.Text := s;
    finally
      FreeAndNil(ini);
    end;
  end;


end;

procedure TWizardConfigServer_PackageUseExistingKey.wizard_show();
begin
  inherited wizard_show();

  self.gb_package.TabOrder                                := 0;
  self.gb_package_signing.TabOrder                        := 1;
  self.m_wizard.WizardButtonPanel.TabOrder                := 2;

  self.ed_package_prefix.TabOrder                         := 0;
  self.ed_key.TabOrder                                    := 1;
  self.ed_password.TabOrder                               := 2;
  self.cb_show_password.TabOrder                          := 3;
  self.m_wizard.WizardButtonPanel.NextButton.TabOrder     := 4;
  self.m_wizard.WizardButtonPanel.PreviousButton.TabOrder := 5;
  self.m_wizard.WizardButtonPanel.CancelButton.TabOrder   := 6;

  self.ed_package_prefix.SetFocus;
end;

procedure TWizardConfigServer_PackageUseExistingKey.wizard_next( var bCanNext: boolean);
begin
  bCanNext := false;

  if not wizard_validate_package_prefix( m_wizard, self.ed_package_prefix, self.ed_package_prefix.Text ) then
    exit;

  if not FileExists( self.ed_key.Text ) then
  begin
    self.m_wizard.show_validation_error( self.ed_key, 'Key not found !');
    exit;
  end;

  if not wizard_validate_crypto_decrypt_key( m_wizard, self.ed_password, self.ed_key.Text, self.ed_password.Text) then
    exit;

  bCanNext := true;
end;

initialization
  RegisterClass(TWizardConfigServer_PackageUseExistingKey);
end.

