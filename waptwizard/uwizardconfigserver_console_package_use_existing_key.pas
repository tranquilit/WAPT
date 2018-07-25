unit uwizardconfigserver_console_package_use_existing_key;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, ExtCtrls, StdCtrls, EditBtn;

type

  { TWizardConfigServer_Console_PackageUseExistingKey }

  TWizardConfigServer_Console_PackageUseExistingKey = class(TWizardStepFrame)
    cb_show_password: TCheckBox;
    ed_certificate: TFileNameEdit;
    ed_password: TEdit;
    ed_package_prefix: TEdit;
    ed_key: TFileNameEdit;
    gb_package_signing: TGroupBox;
    lbl_password: TLabel;
    lbl_package_prefix: TLabel;
    lbl_select_key: TLabel;
    gb_package: TGroupBox;
    lbl_certificate: TLabel;
    procedure cb_show_passwordChange(Sender: TObject);
    procedure ed_certificateAcceptFileName(Sender: TObject; var Value: String);
    procedure ed_keyAcceptFileName(Sender: TObject; var Value: String);
  private

  public
    procedure clear();  override; final;
    procedure wizard_load( w : TWizard ); override; final;
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;
  end;

implementation

uses
  tiscommon,
  uwizardconfigserver_data,
  IniFiles,
  uwapt_ini,
  uwizardutil,
  uwizardvalidattion
  ;

{$R *.lfm}

{ TWizardConfigServer_Console_PackageUseExistingKey }

function certicate_filename( var crt : String; pem : String ) : integer;
begin
  crt := ExtractFileNameWithoutExt(pem) + '.crt';
  if not FileExists(crt) then
    exit(-1);
  exit(0);
end;

procedure TWizardConfigServer_Console_PackageUseExistingKey.cb_show_passwordChange( Sender: TObject);
var
  c: Char;
begin
  if self.cb_show_password.Checked then
    c := #0
  else
    c := '*';
  self.ed_password.PasswordChar := c;
end;

procedure TWizardConfigServer_Console_PackageUseExistingKey.ed_certificateAcceptFileName(Sender: TObject; var Value: String);
begin
  self.m_wizard.ClearValidationError();
  self.m_wizard.WizardButtonPanel.NextButton.SetFocus;
end;


procedure TWizardConfigServer_Console_PackageUseExistingKey.ed_keyAcceptFileName( Sender: TObject; var Value: String );
var
  crt : String;
  r : integer;
begin
  r := certicate_filename(crt, value );
  if r = 0 then
    self.ed_certificate.Text := crt
  else
    self.ed_certificate.InitialDir := ExtractFileDir(Value);

  self.m_wizard.ClearValidationError();
  self.ed_password.SetFocus;
end;

procedure TWizardConfigServer_Console_PackageUseExistingKey.clear();
begin
  inherited clear();
  self.ed_package_prefix.Clear;
  self.ed_key.Clear;
  self.ed_password.Clear;
  self.ed_certificate.Clear;
  self.cb_show_password.Checked := false;
  self.cb_show_passwordChange( nil );
end;

procedure TWizardConfigServer_Console_PackageUseExistingKey.wizard_load(w: TWizard);
var
  r   : integer;
  s   : String;
  ini : TIniFile;
begin
  inherited wizard_load(w );

  self.ed_package_prefix.Text := 'test';

  self.ed_key.Filter := 'Private key file|*.pem';
  self.ed_certificate.Filter := 'Certificate file|*.crt';

  // Fill from waptconsole.ini
  r := wapt_ini_waptconsole( s );
  if r = 0 then
  begin
    ini := TIniFile.Create( s );
    try
      self.ed_package_prefix.Text := ini.ReadString( INI_GLOBAL, INI_DEFAULT_PACKAGE_PREFIX, 'test' );
      s := ini.ReadString( INI_GLOBAL, INI_PERSONAL_CERTIFICATE_PATH, '' );
      if Length(s) > 0 then
      begin

        self.ed_certificate.Text := s;

        s := ExtractFileNameWithoutExt(s) + '.pem';
        if FileExists(s) then
          self.ed_key.Text := s;
      end;


    finally
      FreeAndNil(ini);
    end;
  end;


end;

procedure TWizardConfigServer_Console_PackageUseExistingKey.wizard_show();
begin
  inherited wizard_show();

  self.gb_package.TabOrder                                := 0;
  self.gb_package_signing.TabOrder                        := 1;
  self.m_wizard.WizardButtonPanel.TabOrder                := 2;

  self.ed_package_prefix.TabOrder                         := 0;
  self.ed_key.TabOrder                                    := 1;
  self.ed_password.TabOrder                               := 2;
  self.ed_certificate.TabOrder                            := 3;
  self.cb_show_password.TabOrder                          := 4;

  if Length(self.ed_package_prefix.Text) = 0 then
    self.ed_package_prefix.SetFocus
  else if Length(self.ed_key.Text) = 0 then
    self.ed_key.SetFocus
  else if Length(self.ed_password.Text) = 0 then
    self.ed_password.SetFocus
  else
    self.m_wizard.WizardButtonPanel.NextButton.SetFocus;

end;

procedure TWizardConfigServer_Console_PackageUseExistingKey.wizard_next( var bCanNext: boolean);
var
  data : PWizardConfigServerData;
begin
  bCanNext := false;
  data := m_wizard.data();

  //
  if not wizard_validate_package_prefix( m_wizard, self.ed_package_prefix, self.ed_package_prefix.Text ) then
    exit;

  //
  if not FileExists( self.ed_key.Text ) then
  begin
    self.m_wizard.show_validation_error( self.ed_key, 'Key not found !');
    exit;
  end;

  //
  if not wizard_validate_crypto_decrypt_key( m_wizard, self.ed_password, self.ed_key.Text, self.ed_password.Text) then
    exit;

  //
  if not wizard_validate_str_not_empty_when_trimmed( self.m_wizard, self.ed_certificate, 'A certificate filename is required' ) then
    exit;

  //
  self.m_wizard.SetValidationDescription( 'Validating certificate');
  if not FileExists(self.ed_certificate.Text) then
  begin
    self.m_wizard.show_validation_error( self.ed_certificate, 'Certficate doesn''t exist');
    exit;
  end;
  self.m_wizard.ClearValidationDescription();

  //
  if not wizard_validate_crypto_key_and_certificate_are_related( self.m_wizard, self.ed_certificate,  self.ed_key.Text, self.ed_certificate.Text ) then
    exit;



  data^.default_package_prefix      := self.ed_package_prefix.Text;
  data^.package_private_key         := self.ed_key.Text;
  data^.package_private_key_password:= self.ed_password.Text;
  data^.package_certificate         := self.ed_certificate.Text;

  bCanNext := true;
end;

initialization
  RegisterClass(TWizardConfigServer_Console_PackageUseExistingKey);
end.

