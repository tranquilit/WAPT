unit uwizardconfigconsole_package_create_new_key;

{$mode objfpc}{$H+}

interface

uses
  uwizard, uwizardstepframe, mysql57conn, Classes, SysUtils,
  FileUtil, Forms, Controls, StdCtrls, EditBtn, ComCtrls, ExtCtrls;

type



  { TWizardConfigConsole_PackageCreateNewKey }

  TWizardConfigConsole_PackageCreateNewKey = class(TWizardStepFrame)
    ed_package_prefix: TEdit;
    ed_private_key_directory: TDirectoryEdit;
    ed_private_key_name: TEdit;
    ed_private_key_password_1: TEdit;
    ed_private_key_password_2: TEdit;
    gb_package_signing: TGroupBox;
    lbl_package_prefix: TLabel;
    lbl_private_key_dir: TLabel;
    lbl_private_key_name: TLabel;
    lbl_private_key_password_1: TLabel;
    lbl_private_key_password_2: TLabel;
    Package: TGroupBox;
    Panel2: TPanel;
  private

    function validate_package_generation_options() : integer;
    function validate_package_signing() : integer;


  public

    constructor Create(AOwner: TComponent); override;

    // TWizardStepFrame
    procedure wizard_load( w : TWizard ); override; final;
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;
    procedure clear();  override; final;


    function package_private_key() : String;
    function package_certificate() : String;

  end;

implementation

uses
  dialogs,
  uwizardconfigserver_data,
  uwizardutil,
  uwizardvalidattion;

{$R *.lfm}

{ TWizardConfigConsole_PackageCreateNewKey }

constructor TWizardConfigConsole_PackageCreateNewKey.Create( AOwner: TComponent);
begin
  inherited Create( AOwner );

  // Hints ts_private
  self.ed_private_key_name.Hint        := 'The name the will be save';
  self.ed_private_key_directory.Hint   := 'This is the directory where the signing private key will be saved' + #13#10 + 'it should be a very secure location' ;
  self.ed_private_key_password_1.Hint  := 'Enter your private key password here';
  self.ed_private_key_password_2.Hint  := 'Confirm your private key password here';

  self.ed_private_key_directory.Text  := 'C:\private';


//  self.p_create_key.Top := self.p_select_key.Top;
//  self.p_create_key.Left := self.p_select_key.Left;
//  self.gb_package_signing.Height := self.gb_package_signing.Height - self.p_create_key.Height;


end;

procedure TWizardConfigConsole_PackageCreateNewKey.wizard_load(w: TWizard);
begin
  inherited wizard_load(w);


  // default
  self.ed_package_prefix.Text := 'test';
  self.ed_private_key_directory.Text := 'c:\private';


end;

procedure TWizardConfigConsole_PackageCreateNewKey.wizard_show();
begin
  inherited wizard_show();
  self.ed_package_prefix.SetFocus;

  // Tab order
  self.ed_package_prefix.TabOrder         := 0;
  self.ed_private_key_name.TabOrder       := 1;
  self.ed_private_key_password_1.TabOrder := 2;
  self.ed_private_key_password_2.TabOrder := 3;
  self.ed_private_key_directory.TabOrder  := 4;
  self.m_wizard.WizardButtonPanel.NextButton.TabOrder     := 5;
  self.m_wizard.WizardButtonPanel.PreviousButton.TabOrder := 6;
  self.m_wizard.WizardButtonPanel.CancelButton.TabOrder   := 7;

end;

procedure TWizardConfigConsole_PackageCreateNewKey.wizard_next( var bCanNext: boolean);
var
  r : integer;
begin
  bCanNext := false;

  r := self.validate_package_generation_options();
  if r <> 0 then
    exit;

  r := self.validate_package_signing();
  if r <> 0 then
    exit;

  bCanNext:= true;
end;

procedure TWizardConfigConsole_PackageCreateNewKey.clear();
begin
  self.ed_package_prefix.Clear;
  self.ed_private_key_name.Clear;
  self.ed_private_key_directory.Clear;
  self.ed_private_key_password_1.Clear;
  self.ed_private_key_password_2.Clear;
end;

function TWizardConfigConsole_PackageCreateNewKey.package_private_key(): String;
begin
  result := self.ed_private_key_name.text + '.pem';
end;

function TWizardConfigConsole_PackageCreateNewKey.package_certificate(): String;
begin
  result := self.ed_private_key_name.text + '.crt';
end;



function TWizardConfigConsole_PackageCreateNewKey.validate_package_generation_options(): integer;
begin
  // Validate not empty
  if not wizard_validate_str_not_empty_when_trimmed( m_wizard, self.ed_package_prefix, 'Package prefix cannot be empty') then
    exit( -1 );

  // Validate package prefix is alphanum
  if not wizard_validate_str_is_alphanum( m_wizard, self.ed_package_prefix.Text, self.ed_package_prefix ) then
    exit( -1 );

  exit(0);
end;

function TWizardConfigConsole_PackageCreateNewKey.validate_package_signing(): integer;
type
  TStep = ( sFieldsNotEmpty, sPasswordsEquals, sKeyIsAlphanum, sKeyExist, sKeyDestination, sCreatePrivateKey, sExistingKeyCheckPassword, sCheckExistingCertificate, sCopyCertToSSLDirectory, sFinish );
  TStepSet = set of TStep;
const
  valide_stepset_1 : TStepSet = [ sFieldsNotEmpty, sPasswordsEquals, sKeyIsAlphanum, sKeyDestination, sCreatePrivateKey, sCopyCertToSSLDirectory, sFinish ];
  valide_stepset_2 : TStepSet = [ sFieldsNotEmpty, sPasswordsEquals, sKeyIsAlphanum, sExistingKeyCheckPassword, sCheckExistingCertificate, sFinish ];
var
  s                 : String;
  msg               : String;
  r                 : integer;
  b                 : boolean;
  params            : PCreateSignedCertParams;
  step              : TStep;
  completed_steps   : TStepSet;
  pem               : String;
  crt               : String;
  data              : PWizardConfigServerData;
begin


  data := m_wizard.data();

  ed_private_key_name.Text:= ExcludeTrailingPathDelimiter( trim(ed_private_key_name.Text ) );
  ed_private_key_directory.Text := ExcludeTrailingPathDelimiter( trim(ed_private_key_directory.Text) );
  Application.ProcessMessages;


  pem := ed_private_key_name.Text + '.pem';
  crt := ed_private_key_name.Text + '.crt';

  step := sFieldsNotEmpty;
  completed_steps := [];

  while True do
  begin

    if completed_steps >= valide_stepset_1 then
      break;

    if completed_steps >= valide_stepset_2 then
      break;

    Include( completed_steps, step );

    case step of

      // Validate fields aren't empty
      sFieldsNotEmpty :
        begin
          if not wizard_validate_str_not_empty_when_trimmed( m_wizard, ed_private_key_name, 'Private key identifier cannot be empty' ) then
            exit(-1);
          if not wizard_validate_str_length_not_zero( m_wizard, ed_private_key_password_1, 'Private key password cannot be empty' ) then
            exit(-1);
          if not wizard_validate_str_length_not_zero( m_wizard, ed_private_key_password_2, 'Private key password cannot be empty' ) then
            exit(-1);
          if not wizard_validate_str_not_empty_when_trimmed( m_wizard, ed_private_key_directory, 'Private key destination directory cannot be empty' ) then
            exit(-1);
          inc(step);
        end;

      // Validate password and password confirm are equals
      sPasswordsEquals :
        begin
          if not wizard_validate_str_password_are_equals( m_wizard, ed_private_key_password_1.Text, ed_private_key_password_2.Text, ed_private_key_password_2 ) then
            exit(-1);

          inc(step);
        end;

      // Validate key name is alphanum  ( ie valid filename )
      sKeyIsAlphanum :
        begin
          if not wizard_validate_str_is_alphanum( m_wizard, ed_private_key_name.text, ed_private_key_name ) then
            exit(-1);

          inc(step);
        end;

      // Check if key exist
      sKeyExist:
        begin
          s := fs_path_concat( ed_private_key_directory.Text, pem );
          if FileExists( s ) then
            step := sExistingKeyCheckPassword
          else
            step := sKeyDestination;;
        end;

      // Private key destination directory exist and writable or parent dir is directory writable
      sKeyDestination :
        begin
          m_wizard.SetValidationDescription('Checking private key destination directory' );
          if not wizard_validate_fs_ensure_directory( m_wizard, ed_private_key_directory.Text, ed_private_key_directory ) then
            exit(-1);
          inc(step);
        end;



      // Validate private key creation
      sCreatePrivateKey :
      begin
        // TODO : Do you want to customize certificate default values
        m_wizard.SetValidationDescription( Format('Creating private key %s', [pem]) );

        params := GetMem( sizeof(TCreateSignedCertParams) );
        FillChar( params^, sizeof(TCreateSignedCertParams), 0 );

        params^.keyfilename           := UTF8Decode( fs_path_concat( ed_private_key_directory.Text, pem) );
        params^.crtbasename           := ''; // if empty, it will take key filename
        params^.destdir               := UTF8Decode( ed_private_key_directory.Text );
        params^.country               := 'FR';
        params^.locality              := '';
        params^.organization          := '';
        params^.orgunit               := '';
        params^.commonname            := UTF8Decode( ed_private_key_name.Text );
        params^.email                 := '';
        params^.keypassword           := UTF8Decode( ed_private_key_password_1.Text );
        params^.codesigning           := true;
        {$ifdef ENTERPRISE}
        params^.IsCACert              := false;
        params^.CACertificateFilename := '';
        params^.CAKeyFilename         := '';
        {$else}
        params^.IsCACert              := false;
        params^.CACertificateFilename := '';
        params^.CAKeyFilename         := '';
        {$endif}
        r := CreateSignedCertParams( params );
        if r <> 0 then
        begin
          m_wizard.show_validation_error( nil, params^._error_message );
          FreeMemAndNil( params );
          exit(-1);
        end;
        FreeMemAndNil( params );
        step := sCopyCertToSSLDirectory;
      end;

      // Validate check supplied password for existing key
      sExistingKeyCheckPassword :
        begin
          m_wizard.SetValidationDescription('Key exist, checking supplied password can decrypt' );
          r := crypto_check_key_password(b, s, ed_private_key_password_1.Text );
          if r <> 0 then
          begin
            m_wizard.show_validation_error( ed_private_key_password_1, 'A key with this name exist but an error has occured when checking password.' + #13#10 + 'Move or delete key manually to continue.' );
            exit(-1);
          end;

          if not b then
          begin
            m_wizard.show_validation_error( ed_private_key_password_1, 'A key with this name exist but supplied password is wrong.' + #13#10 + 'Check your password or move or delete key manually to continue.' );
            exit(-1);
          end;
          step := sCheckExistingCertificate;
        end;

      // Validate  certificate ...
      sCheckExistingCertificate :
        begin
          m_wizard.SetValidationDescription( 'Validing existing certificate' );
          s := fs_path_concat( 'ssl', crt );
          // A cert not exist in ssl dir ?
          if FileExists(s) then
          begin
            step := sFinish;
            Continue;
          end;

          // ... and not in private key dir ?
          s := fs_path_concat( ed_private_key_directory.Text, crt );
          if FileExists(s) then
          begin
            step := sCopyCertToSSLDirectory;
            Continue;
          end;

          msg :=       'The certificate %s corresponding' + #13#10;
          msg := msg + 'to this key cannot be find. You can either' + #13#10;
          msg := msg + 'recreate the key or place the certificate' + #13#10;
          msg := msg + 'in the private key directory';
          msg := Format( msg, [crt] );
          m_wizard.show_validation_error( ed_private_key_directory, s );
          exit(-1);
        end;

      // Copy certificate to authorized certificates directory
      sCopyCertToSSLDirectory :
      begin
        m_wizard.SetValidationDescription( 'Copying certificat to authorized certificate directory');

        s := fs_path_concat( 'ssl', crt );
        if FileExists( s ) then
        begin
          msg := 'A certificat with this name %s exist in the directory' + #13#10#13#10;
          msg := msg + '%s' + #13#10#13#10;
          msg := msg + 'Replace it with the new one ?';
          msg := Format( msg, [crt, fs_path_concat(GetCurrentDir(), 'ssl')] );
          if mrNo = m_wizard.show_question( msg, mbYesNo) then
          begin
            m_wizard.show_validation_error( nil, 'Certificate cannot be copied to authorized certificate directory' );
            exit(-1);
          end;

          if not DeleteFile(s) then
          begin
            msg := 'An error has occured when copying certificate to global authorized directory';
            m_wizard.show_validation_error( nil, s );
            exit( -1 );
          end;
        end;

        s := fs_path_concat( ed_private_key_directory.Text, crt );
        if not CopyFile(  s, fs_path_concat( 'ssl', crt ), true, false) then
        begin
          m_wizard.show_validation_error( nil, 'An error has occured while copying certificate into authorized certificates directory');
          exit(-1);
        end;

        step := sFinish;
      end;

      sFinish:
      begin
        // noop
      end;

    end;
  end;


//    debug_show_step;


  data^.default_package_prefix        := self.ed_package_prefix.Text;
  data^.package_certificate           := IncludeTrailingBackslash(self.ed_private_key_directory.Text) + crt;
  data^.package_private_key           := pem;
  data^.package_private_key_password  := self.ed_private_key_password_1.Text;

  m_wizard.ClearValidationDescription();
  exit(0);

end;

initialization

RegisterClass(TWizardConfigConsole_PackageCreateNewKey);

end.

