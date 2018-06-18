unit uwizardconfigconsole;

{$mode objfpc}{$H+}

interface

uses
  IdComponent,
  dmwaptpython,
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, uwizard,
  ComCtrls, ExtCtrls, StdCtrls, PopupNotifier, EditBtn, WizardControls;

type


  { TWizardConfigConsole }

  TWizardConfigConsole = class(TWizard)
    cb_launch_console: TCheckBox;
    ed_private_key_name: TEdit;
    ed_package_prefix: TEdit;
    ed_private_key_directory: TDirectoryEdit;
    ed_private_key_password_1: TEdit;
    ed_private_key_password_2: TEdit;
    ed_server_password: TEdit;
    ed_server_url: TEdit;
    ed_server_login: TEdit;
    Label1: TLabel;
    lbl_building_waptagent_info: TLabel;
    lbl_finished_congratulation: TLabel;
    lbl_private_key_name: TLabel;
    lbl_package_prefix: TLabel;
    lbl_private_key_dir: TLabel;
    lbl_private_key_password_1: TLabel;
    lbl_private_key_password_2: TLabel;
    lbl_server_password: TLabel;
    lbl_server_url: TLabel;
    lbl_server_login: TLabel;
    progress_building_waptagent: TProgressBar;
    ts_building_waptagent: TTabSheet;
    ts_finished: TTabSheet;
    ts_private_key_configuration: TTabSheet;
    ts_package_configuration: TTabSheet;
    ts_server_info: TTabSheet;
    ts_welcome: TTabSheet;
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
  private

  m_check_certificates_validity : boolean;


  protected
  procedure register_steps(); override; final;
  procedure on_wizard_start() ; override; final;
  procedure on_wizard_finish( var mr :TModalResult ); override; final;

  procedure on_step_show( ts : TTabSheet ); override; final;
  procedure on_step_taborder( ts : TTabSheet ); override; final;

  private
  function filename_private_key() : String;
  function filename_certificate_package() : String;
  function filename_certificate_server() : String;

  function config_verify_cert() : String;

  // Steps function
  function on_step_welcome( mode : TWizardStepFuncMode ) : integer;
  function on_step_server_info( mode : TWizardStepFuncMode ) : integer;
  function on_step_package_configuration( mode : TWizardStepFuncMode) : integer;
  function on_step_private_key_configuration( mode : TWizardStepFuncMode ) : integer;
  function on_step_building_waptagent( mode : TWizardStepFuncMode ) : integer;
  function on_step_finished( mode : TWizardStepFuncMode ) : integer;

  procedure on_building_waptagent_tick( sender : TObject );

  procedure init_hints();
  procedure init_defaults();
  procedure clear();



  procedure tick( data : PtrInt );
  procedure on_workevent( ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64);

  public


  end;

var
  WizardConfigConsole: TWizardConfigConsole;

implementation

uses
  tiscommon,
  waptcommon,
  uwizardutil,
  uwizardvalidattion,
  superobject,
  FileUtil,
  IniFiles;

{$R *.lfm}

const
  DEFAULT_COUNTRY_CODE: String = 'FR';

{ TWizardConfigConsole }

procedure TWizardConfigConsole.FormClose(Sender: TObject; var CloseAction: TCloseAction);
var
  r : integer;
begin
  if (self.PageControl.ActivePage = ts_finished) and self.cb_launch_console.Checked then
  begin
    r := process_launch( Application.ExeName );
    if r <> 0 then
      self.show_error( 'An error has occured while launching the console');
  end;
end;

procedure TWizardConfigConsole.register_steps();
const
  pnc : TWizardButtons = [ wbPrevious, wbNext, wbCancel ];
begin
  self.register_step( 'Welcome',                  'Welcome description',                  [wbNext,wbCancel], @on_step_welcome );
  self.register_step( 'Server information',       'Server information description',       pnc, @on_step_server_info);
  self.register_step( 'Package configuration',    'Package configuration description',    pnc, @on_step_package_configuration);
  self.register_step( 'Private key configuration','Private key configuration description',pnc, @on_step_private_key_configuration);
  self.register_step( 'Building waptagent',       'Building waptagent description',       pnc, @on_step_building_waptagent);
  self.register_step( 'Congratulation',           'Configuration terminated !',           [wbFinish], @on_step_finished );

end;


procedure TWizardConfigConsole.on_wizard_start();
begin
  self.Caption := 'Wapt console configuration';
  self.WizardProgressBar.Visible:= false;

  self.clear();
  self.init_hints();
  self.init_defaults();
end;

procedure TWizardConfigConsole.on_wizard_finish(var mr: TModalResult);
begin
end;


procedure TWizardConfigConsole.init_hints();
begin
  // Hints ts_server_info
  self.ed_server_url.Hint           := 'Url of the server';
  self.ed_server_login.Hint         := 'Server login';
  self.ed_server_password.Hint      := 'Server password';

  // Hints ts_package_prefix
  self.ed_package_prefix.Hint                  := 'When you pull or create a package, its name will be prefixed with your trigram/quadrigram to mark its provenance.' + #13#10 + 'Replace "test" with a trigram meaningful to your organisation (ex: tis standing for Tranquil IT Systems).';

  // Hints ts_private
  self.ed_private_key_name.Hint        := 'The name the will be save';
  self.ed_private_key_directory.Hint   := 'This is the directory where the signing private key will be saved' + #13#10 + 'it should be a very secure location' ;
  self.ed_private_key_password_1.Hint  := 'Enter your private key password here';
  self.ed_private_key_password_2.Hint  := 'Confirm your private key password here';

end;

procedure TWizardConfigConsole.init_defaults();
var
  i : LongWord;
  s : String;
begin

    m_check_certificates_validity := true;

    // ts_server_info
    self.ed_server_login.Text := 'admin';

    // ts_package_prefix
    self.ed_package_prefix.Text := 'test';

    // ts_private
    i := 50;
    {
    SetLength( s, i );
    if GetUserName( @s[1], i) and (i>0) then
      self.ed_private_key_name.Text := s;
    }
    self.ed_private_key_directory.Text  := 'C:\private';

end;


procedure TWizardConfigConsole.clear();
begin
  // ts_server_info
  self.ed_server_url.Clear;
  self.ed_server_login.Clear;
  self.ed_server_password.Clear;

  // ts_package_prefix
  self.ed_package_prefix.Clear;

  // ts_private_key_congiguration
  self.ed_private_key_name.Clear;
  self.ed_private_key_directory.Clear;
  self.ed_private_key_password_1.Clear;
  self.ed_private_key_password_2.Clear;

  // ts_building_waptagent

  // ts_finished


end;


function TWizardConfigConsole.filename_private_key(): String;
begin
  result := self.ed_private_key_name.Text + '.pem';
end;

function TWizardConfigConsole.filename_certificate_package(): String;
begin
  result := self.ed_private_key_name.Text + '.crt';
end;

function TWizardConfigConsole.filename_certificate_server(): String;
begin
  https_certificate_pinned_filename( result, self.ed_server_url.Text );
end;

function TWizardConfigConsole.config_verify_cert(): String;
begin
  // Check certficate CA
  result := '0';
{$ifdef ENTERPRISE}
  if self.m_check_certificates_validity then
    result := '1';
{$endif}
end;


procedure TWizardConfigConsole.on_step_show(ts: TTabSheet);
begin

end;
procedure TWizardConfigConsole.on_step_taborder(ts: TTabSheet);
begin
  if self.ts_welcome = ts then
  begin
    self.WizardButtonPanel.NextButton.TabOrder      := 0;
    self.WizardButtonPanel.CancelButton.TabOrder    := 1;
    exit;
  end;

  if self.ts_server_info = ts then
  begin
    self.ed_server_url.TabOrder                     := 0;
    self.ed_server_login.TabOrder                   := 1;
    self.ed_server_password.TabOrder                := 2;
    self.WizardButtonPanel.NextButton.TabOrder      := 3;
    self.WizardButtonPanel.PreviousButton.TabOrder  := 4;
    self.WizardButtonPanel.CancelButton.TabOrder    := 5;
    exit;
  end;

  if self.ts_package_configuration = ts then
  begin
    self.ed_package_prefix.TabOrder                 := 0;
    self.WizardButtonPanel.NextButton.TabOrder      := 1;
    self.WizardButtonPanel.PreviousButton.TabOrder  := 2;
    self.WizardButtonPanel.CancelButton.TabOrder    := 3;
    exit;
  end;

  if self.ts_private_key_configuration = ts then
  begin
    self.ed_private_key_name.TabOrder               := 0;
    self.ed_private_key_directory.TabOrder          := 1;
    self.ed_private_key_password_1.TabOrder         := 2;
    self.ed_private_key_password_2.TabOrder         := 3;
    self.WizardButtonPanel.NextButton.TabOrder      := 4;
    self.WizardButtonPanel.PreviousButton.TabOrder  := 5;
    self.WizardButtonPanel.CancelButton.TabOrder    := 6;
    exit;
  end;




end;




function TWizardConfigConsole.on_step_welcome(mode: TWizardStepFuncMode ): integer;
begin
  if wf_enter = mode then
    exit(0);

  if wf_validate = mode then
    exit(0);


end;




function TWizardConfigConsole.on_step_server_info(mode: TWizardStepFuncMode ): integer;

var
  hostname: String;
  s       : String;
  r       : integer;
  b       : boolean;
  i       : integer;
begin
  hostname := '';
  s := '';

  if wf_enter = mode then
    exit(0);

  if wf_validate = mode then
  begin
    m_check_certificates_validity := true;

    // Check fields content length
    SetValidationDescription( 'Checking fields validity' );
    if not wizard_validate_str_not_empty_when_trimmed( self, self.ed_server_url,     'Server url cannot be empty' ) then
      exit(-1);
    if not wizard_validate_str_not_empty_when_trimmed( self, self.ed_server_login,   'Username cannot be empty' ) then
      exit(-1);
    if not wizard_validate_str_length_not_zero( self, self.ed_server_password,'Password cannot be empty' ) then
      exit(-1);

    // Check ping
    if not wizard_validate_waptserver_ping( self, self.ed_server_url.Text , self.ed_server_url ) then
      exit(-1);

    // Get certificate hostname
    self.SetValidationDescription( 'Retrieving server certificate');
    r := https_certificate_extract_hostname( hostname, self.ed_server_url.Text );
    if r <> 0 then
    begin
      self.show_validation_error( self.ed_server_url, 'A problem has happenend while validating server certificat' );
      exit(-1);
    end;

    b := false;
    r := url_resolv_to_same_ip( b, self.ed_server_url.Text, hostname );
    if (r <> 0) or not b then
    begin
      s := 'Server certficate cannot be verified' + #13#10;
      s := s + 'Do you want to continue without certificate verification ?';
      if mrNo = self.show_question( s, mbYesNo ) then
      begin
        self.show_validation_error( self.ed_server_url, 'Certificate verification failed, try configure name resolution properly' );
        exit(-1);
      end;
      self.m_check_certificates_validity := false;

      hostname := url_hostname( self.ed_server_url.Text );
    end;


    self.ed_server_url.Text := 'https://' + hostname;
    Application.ProcessMessages;


    // Check version
    if not wizard_validate_waptserver_version_not_less( self, self.ed_server_url.Text, WAPTServerMinVersion, self.ed_server_url ) then
      exit(-1);

    if selF.m_check_certificates_validity then
    begin

      // Check certifcate validity
      self.SetValidationDescription( 'Validating certificate' );
      r := https_certificate_is_valid( b, self.ed_server_url.Text );
      if r <> 0 then
      begin
        self.show_error( 'A problem has occured while checking if certificat is valid' );
        exit(-1);
      end;
      if not b then
      begin
        // Was pinned ?
        r := https_certificate_is_pinned( b, self.ed_server_url.Text );
        if r <> 0 then
        begin
          self.show_error( 'A problem has occured while checking if certificat is pinned' );
          exit(-1);
        end;
        if b then
        begin
          self.show_validation_error( self.ed_server_url, 'Certificat is pinned but invalid' + #13#10 + 'Maybe you could try delete certificat first' );
          exit(-1);
        end;
        // Pin it ?
        if mrNo =  MessageDlg( 'Question', 'Certificate is not valided, do you want to pin it ?', mtConfirmation, mbYesNo, 0 ) then
        begin
          Self.show_validation_error( self.ed_server_url, 'A self signed certicate must be pinned to be verified' );
          exit(-1);
        end;
        // Pin it !
        r := https_certificate_pin( self.ed_server_url.Text );
        if r <> 0 then
        begin
          self.show_error( 'A problem has occured while pinning certificate' );
          exit(-1);
        end;
        // Re check certificate validity
        r := https_certificate_is_valid( b, self.ed_server_url.Text );
        if r <> 0 then
        begin
          self.show_error( 'A problem has occured while verified pinned certificat' );
          exit(-1);
        end;

        if not b then
        begin
          self.show_validation_error( self.ed_server_url, 'Pinned certificate  verification failed, cannot continue' );
          exit(-1);
        end;
      end;
    end;

    // Check Login
    if not wizard_validate_waptserver_login( self, self.ed_server_url.Text, self.m_check_certificates_validity, self.ed_server_login.Text, self.ed_server_password.Text, self.ed_server_password ) then
      exit(-1);

    self.ClearValidationDescription();
    exit( 0 );
  end;

end;


function TWizardConfigConsole.on_step_package_configuration( mode: TWizardStepFuncMode): integer;
begin

  if wf_enter = mode then
    exit(0);

  if wf_validate = mode then
  begin
    // Validate not empty
    if not wizard_validate_str_not_empty_when_trimmed( self, self.ed_package_prefix, 'Package prefix cannot be empty') then
      exit( -1 );

    // Validate package prefix is alphanum
    if not wizard_validate_str_is_alphanum( self, self.ed_package_prefix.Text, self.ed_package_prefix ) then
      exit( -1 );

    exit( 0 );
  end;

end;

function TWizardConfigConsole.on_step_private_key_configuration( mode: TWizardStepFuncMode): integer;
type
  TStep = ( sFieldsNotEmpty, sPasswordsEquals, sKeyIsAlphanum, sKeyExist, sKeyDestination, sCreatePrivateKey, sExistingKeyCheckPassword, sCheckExistingCertificate, sCopyCertToSSLDirectory, sFinish );
  TStepSet = set of TStep;
const
  valide_stepset_1 : TStepSet = [ sFieldsNotEmpty, sPasswordsEquals, sKeyIsAlphanum, sKeyDestination, sCreatePrivateKey, sCopyCertToSSLDirectory, sFinish ];
  valide_stepset_2 : TStepSet = [ sFieldsNotEmpty, sPasswordsEquals, sKeyIsAlphanum, sExistingKeyCheckPassword, sCheckExistingCertificate, sFinish ];
var
  s       : String;
  msg     : String;
  r       : integer;
  b       : boolean;
  params  : PCreateSignedCertParams;
  step    : TStep;
  completed_steps   : TStepSet;
procedure debug_show_step;
var
  s : String;
begin
  s := '';
  if sFieldsNotEmpty in completed_steps then
    s := s + 'sFieldsNotEmpty' + #13#10;
  if sPasswordsEquals in completed_steps then
    s := s + 'sPasswordsEquals' + #13#10;
  if sKeyIsAlphanum in completed_steps then
    s := s + 'sKeyIsAlphanum' + #13#10;
  if sKeyExist in completed_steps then
    s := s + 'sKeyExist' + #13#10;
  if sKeyDestination in completed_steps then
    s := s + 'sKeyDestination' + #13#10;
  if sCreatePrivateKey in completed_steps then
    s := s + 'sCreatePrivateKey' + #13#10;
  if sExistingKeyCheckPassword in completed_steps then
    s := s + 'sExistingKeyCheckPassword' + #13#10;
  if sCheckExistingCertificate in completed_steps then
    s := s + 'sCheckExistingCertificate' + #13#10;
  if sCopyCertToSSLDirectory in completed_steps then
    s := s + 'sCopyCertToSSLDirectory' + #13#10;
  if sFinish in completed_steps then
    s := s + 'sFinish' + #13#10;

  ShowMessage( s );
end;

begin

  if wf_enter = mode then
    exit(0);

  if wf_validate = mode then
  begin
    params := nil;
    self.ed_private_key_name.Text:= ExcludeTrailingPathDelimiter( trim(self.ed_private_key_name.Text ) );
    self.ed_private_key_directory.Text := ExcludeTrailingPathDelimiter( trim(self.ed_private_key_directory.Text) );
    Application.ProcessMessages;

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
            if not wizard_validate_str_not_empty_when_trimmed( self, self.ed_private_key_name, 'Private key identifier cannot be empty' ) then
              exit(-1);
            if not wizard_validate_str_not_empty_when_trimmed( self, self.ed_private_key_directory, 'Private key destination directory cannot be empty' ) then
              exit(-1);
            if not wizard_validate_str_length_not_zero( self, self.ed_private_key_password_1, 'Private key password cannot be empty' ) then
              exit(-1);
            if not wizard_validate_str_length_not_zero( self, self.ed_private_key_password_2, 'Private key password cannot be empty' ) then
              exit(-1);

            inc(step);
          end;

        // Validate password and password confirm are equals
        sPasswordsEquals :
          begin
            if not wizard_validate_str_password_are_equals( self, self.ed_private_key_password_1.Text, self.ed_private_key_password_2.Text, self.ed_private_key_password_2 ) then
              exit(-1);

            inc(step);
          end;

        // Validate key name is alphanum  ( ie valid filename )
        sKeyIsAlphanum :
          begin
            if not wizard_validate_str_is_alphanum( self, self.ed_private_key_name.text, self.ed_private_key_name ) then
              exit(-1);

            inc(step);
          end;

        // Check if key exist
        sKeyExist:
          begin
            s := fs_path_concat( self.ed_private_key_directory.Text, filename_private_key() );
            if FileExists( s ) then
              step := sExistingKeyCheckPassword
            else
              step := sKeyDestination;;
          end;

        // Private key destination directory exist and writable or parent dir is directory writable
        sKeyDestination :
          begin
            self.SetValidationDescription('Checking private key destination directory' );
            if not wizard_validate_fs_ensure_directory( self, self.ed_private_key_directory.Text, self.ed_private_key_directory ) then
              exit(-1);
            inc(step);
          end;



        // Validate private key creation
        sCreatePrivateKey :
        begin
          // TODO : Do you want to customize certificate default values
          self.SetValidationDescription( Format('Creating private key %s', [self.filename_private_key()]) );

          params := GetMem( sizeof(TCreateSignedCertParams) );
          FillChar( params^, sizeof(TCreateSignedCertParams), 0 );
          params^.keyfilename           := UTF8Decode( fs_path_concat( self.ed_private_key_directory.Text, self.filename_private_key()) );
          params^.crtbasename           := ''; // if empty, it will take key filename
          params^.destdir               := UTF8Decode( self.ed_private_key_directory.Text );
          params^.country               := UTF8Decode( DEFAULT_COUNTRY_CODE );
          params^.locality              := '';
          params^.organization          := '';
          params^.orgunit               := '';
          params^.commonname            := UTF8Decode( self.ed_private_key_name.Text );
          params^.email                 := '';
          params^.keypassword           := UTF8Decode( self.ed_private_key_password_1.Text );
          params^.codesigning           := false;
          params^.IsCACert              := false;
          params^.CACertificateFilename := '';
          params^.CAKeyFilename         := '';
          r := CreateSignedCertParams( params);
          if r <> 0 then
          begin
            self.show_validation_error( nil, params^._error_message );
            FreeMemAndNil( params );
            exit(-1);
          end;
          FreeMemAndNil( params );
          step := sCopyCertToSSLDirectory;
        end;

        // Validate check supplied password for existing key
        sExistingKeyCheckPassword :
          begin
            self.SetValidationDescription('Key exist, checking supplied password can decrypt' );
            r := crypto_check_key_password(b, s, self.ed_private_key_password_1.Text );
            if r <> 0 then
            begin
              self.show_validation_error( self.ed_private_key_password_1, 'A key with this name exist but an error has occured when checking password.' + #13#10 + 'Move or delete key manually to continue.' );
              exit(-1);
            end;

            if not b then
            begin
              self.show_validation_error( self.ed_private_key_password_1, 'A key with this name exist but supplied password is wrong.' + #13#10 + 'Check your password or move or delete key manually to continue.' );
              exit(-1);
            end;
            step := sCheckExistingCertificate;
          end;

        // Validate  certificate ...
        sCheckExistingCertificate :
          begin
            self.SetValidationDescription( 'Validing existing certificate' );
            s := fs_path_concat( 'ssl', filename_certificate_package() );
            // A cert not exist in ssl dir ?
            if FileExists(s) then
            begin
              step := sFinish;
              Continue;
            end;

            // ... and not in private key dir ?
            s := fs_path_concat( self.ed_private_key_directory.Text, filename_certificate_package() );
            if FileExists(s) then
            begin
              step := sCopyCertToSSLDirectory;
              Continue;
            end;

            msg :=       'The certificate %s corresponding' + #13#10;
            msg := msg + 'to this key cannot be find. You can either' + #13#10;
            msg := msg + 'recreate the key or place the certificate' + #13#10;
            msg := msg + 'in the private key directory';
            msg := Format( msg, [filename_certificate_package()] );
            self.show_validation_error( self.ed_private_key_directory, s );
            exit(-1);
          end;

        // Copy certificate to authorized certificates directory
        sCopyCertToSSLDirectory :
        begin
          self.SetValidationDescription( 'Copying certificat to authorized certificate directory');

          s := fs_path_concat( 'ssl', self.filename_certificate_package() );
          if FileExists( s ) then
          begin
            msg := 'A certificat with this name %s exist in the directory' + #13#10#13#10;
            msg := msg + '%s' + #13#10#13#10;
            msg := msg + 'Replace it with the new one ?';
            if mrNo = self.show_question( Format( msg, [ExtractFileName(params^._certificate),fs_path_concat(GetCurrentDir, 'ssl')]), mbYesNo) then
            begin
              self.show_validation_error( nil, 'Certificate cannot be copied to authorized certificate directory' );
              exit(-1);
            end;

            if not DeleteFile(s) then
            begin
              msg := 'An error has occured when copying certificate to global authorized directory';
              self.show_validation_error( nil, s );
              exit( -1 );
            end;
          end;

          s := fs_path_concat( self.ed_private_key_directory.Text, self.filename_certificate_package() );
          if not CopyFile(  s, fs_path_concat( 'ssl', self.filename_certificate_package() ), true, false) then
          begin
            self.show_validation_error( nil, 'An error has occured while copying certificate into authorized certificates directory');
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

    self.ClearValidationDescription();
    exit(0);
  end;



end;


procedure  CreateWaptSetupParamsWrapper( data : Pointer );
var
  r : integer;
  params : PCreateWaptSetupParams;
begin
  params := PCreateWaptSetupParams(data);
  r := CreateWaptSetupParams( params );
end;


function TWizardConfigConsole.on_step_building_waptagent( mode: TWizardStepFuncMode): integer;
  procedure building_init_ui( const s : String; max : integer );
  begin
    self.ClearValidationError();
    self.progress_building_waptagent.Visible := true;
    self.lbl_building_waptagent_info.Caption := s;
    self.progress_building_waptagent.Min := 0;
    self.progress_building_waptagent.Max := max;
    self.progress_building_waptagent.Position := 0;
    self.progress_building_waptagent.Style := pbstNormal;
    Application.ProcessMessages;
  end;

  procedure building_show_error( control : TControl; const msg : String );
  begin
    selF.progress_building_waptagent.Visible := false;
    self.show_validation_error( control, msg );
  end;

const
  MSG_BUILDING : String = 'Building waptagent   ';
  MSG_UPLOADING: String = 'Uploading waptagent to server';

var
  params  : PCreateWaptSetupParams;
  w : TThread;
  so : ISuperObject;
  s : String;
  r : integer;
  i : integer;
  j : integer;
begin
  if wf_enter = mode then
  begin
    self.WizardButtonPanel.NextButton.Click;
    exit(0);
  end;

  if wf_validate = mode then
  begin

    self.progress_building_waptagent.Visible := false;
    self.lbl_building_waptagent_info.Caption := 'Prepare building waptagent';

    // Check if waptagent already exist on server
    self.SetValidationDescription( 'Checking if waptagent exist on server' );
    s := url_concat( self.ed_server_url.Text, '/wapt/waptagent.exe' );
    r := -1;
    i := http_reponse_code( r, s );
    if i <> 0 then
    begin
      self.show_validation_error( nil, 'A Problem has occurred while checking if waptagent exist on server' + #13#10 + 'Server installation may be broken, you could try reinstall waptserver' );
      exit(-1);
    end;

    if r = 200 then
    begin
      s := 'Waptagent has been found on the server.'+ #13#10#13#10;
      s := s + 'Rebuild and overwrite it ?';
      if mrNo = self.show_question( s, mbYesNo ) then
        exit(0);
    end
    else if r <> 404 then
    begin
      s := 'A Problem has occurred while checking if waptagent exist on server' + #13#10;
      s := 'Server installation may be broken, you could try reinstall waptserver';
      self.show_validation_error( nil, s );
      exit(-1);
    end;
    self.ClearValidationDescription();


    // Check there is no other inno setup process running
    self.SetValidationDescription( 'Checking if there is no inno setup process running' );
    if not ensure_process_not_running('ISCC.exe') then
    begin
      self.show_validation_error( nil, 'A instance of ISCC as been found, cannot continue.');
      exit(-1);
    end;
    self.ClearValidationDescription();

    // Building waptagent
    building_init_ui( MSG_BUILDING, 100 );
    params := GetMem( sizeof(TCreateWaptSetupParams) );
    FillChar( params^, sizeof(TCreateWaptSetupParams), 0 );

    params^.default_public_cert       := fs_path_concat( 'ssl', self.filename_certificate_package() );
    params^.default_repo_url          := self.ed_server_url.Text + '/wapt';
    params^.default_wapt_server       := self.ed_server_url.Text;
    params^.destination               := GetTempDir(true);
    params^.company                   := '';
    params^.OnProgress                := @on_building_waptagent_tick;
    params^.WaptEdition               := 'waptagent';
    params^.VerifyCert                := config_verify_cert();
    params^.UseKerberos               := false;
    params^.CheckCertificatesValidity := true;
    params^.EnterpriseEdition         := DMPython.IsEnterpriseEdition;
    params^.OverwriteRepoURL          := true;
    params^.OverwriteWaptServerURL    := true;

    r := 0;
    j := 0;
    w := TThread.ExecuteInThread( @CreateWaptSetupParamsWrapper, Pointer(params), TNotifyCallBack(nil) );
    while not w.Finished do
    begin
      WaitForThreadTerminate( w.Handle, 33 ); // 30 FPS
      r := r + 33;
      if r > 330 then
      begin
        s := MSG_BUILDING;;
        r := 0;
        for i := 0 to j do
          s[Length(s)-2+i] := '.';
        self.lbl_building_waptagent_info.Caption := s;
        inc(j);
        if j > 2 then
          j := -1;
      end;
      Application.ProcessMessages;
    end;

    if params^._result <> 0 then
    begin
      building_show_error( nil, params^._err_message );
      FreeMemAndNil( params );
      exit(-1);
    end;


    //
    building_init_ui( 'Uploading to server...', FileSize(params^._agent_filename) );
    s := 'ssl\server\' + self.filename_certificate_server();
    if not FileExists(s) then
      s := '';
    try
      so := WAPTServerJsonMultipartFilePost(
        self.ed_server_url.Text,
        'upload_waptsetup',
        [],
        'file',
        params^._agent_filename,
        self.ed_server_login.Text,
        self.ed_server_password.Text,
        @on_workevent,
        s
        );
      if so.S['status'] <> 'OK' then
        Raise Exception.Create( UTF8Encode(so.S['message']) );
    except on Ex : Exception do
      begin
        building_show_error( nil, Ex.Message );
        FreeMemAndNil(params);
        exit(-1);
      end;
    end;

    self.SetValidationDescription( 'Deleting temp files');
    if not DeleteFile( params^._agent_filename ) then
    begin
      building_show_error( nil, 'An error has occured while deleting temp files');
      FreeMemAndNil(params);
      exit(-1);
    end;

    FreeMemAndNil(params);
    exit(0);

  end;



end;

function TWizardConfigConsole.on_step_finished(mode: TWizardStepFuncMode): integer;
const
  GLOBAL : String = 'global';
var
  ini : TIniFile;
  s : String;

  check_certificates_validity : String;
  repo_url                    : String;
  personal_certificate_path   : String;

begin
  if wf_enter = mode then
  begin
    self.SetValidationDescription( 'Writing configuration settings' );


    // Check certificate validity
    check_certificates_validity := '1';
    if not self.m_check_certificates_validity then
      check_certificates_validity := '0';


    // repo_url
    repo_url := url_concat( self.ed_server_url.Text, '/wapt') ;

    // personal_certificate_path
    personal_certificate_path := self.filename_certificate_package();

    // Now Writing settings
    try
      // wapt-get.ini
      s := 'wapt-get.ini';
      ini := TIniFile.Create( s );
      ini.WriteString( GLOBAL, 'check_certificates_validity', check_certificates_validity );
      ini.WriteString( GLOBAL, 'verify_cert',                  config_verify_cert() );
      ini.WriteString( GLOBAL, 'wapt_server',                 self.ed_server_url.Text );
      ini.WriteString( GLOBAL, 'repo_url',                    repo_url );
      ini.Free;

      // waptconsole.ini
      s := IncludeTrailingBackslash(ExtractFileDir(AppIniFilename())) + 'waptconsole.ini';
      ini := TIniFile.Create( s );
      ini.WriteString( GLOBAL, 'check_certificates_validity', check_certificates_validity );
      ini.WriteString( GLOBAL, 'verify_cert',                  config_verify_cert() );
      ini.WriteString( GLOBAL, 'wapt_server',                 self.ed_server_url.Text );
      ini.WriteString( GLOBAL, 'repo_url',                    repo_url );
      ini.WriteString( GLOBAL, 'default_package_prefix',      self.ed_package_prefix.Text );
      ini.WriteString( GLOBAL, 'personal_certificate_path',   personal_certificate_path );
      ini.Free;

      ini := nil;
      self.ClearValidationDescription();
    finally
      if Assigned(ini) then
        FreeAndNil(ini);
    end;
    // Writing some wapt-get settings
    exit(0);
  end;


  if wf_validate = mode then
    exit(0);
end;





procedure TWizardConfigConsole.on_building_waptagent_tick( sender: TObject );
begin
  Application.QueueAsyncCall( @tick, 0 );
end;

procedure TWizardConfigConsole.tick(data: PtrInt);
const
  sz_setup : Real = 1024 * 1024 * 23.5;
var
  sz : Real;
  max : Real;
  f : String;
begin
  f := IncludeTrailingPathDelimiter( GetTempDir(true) )+ 'waptagent.exe';
  if not fs_path_exists( f ) then
    exit;
  max := self.progress_building_waptagent.Max;
  sz := FileSize(f);
  sz := max * sz / sz_setup;
  if sz > 100 then
    sz := 100;
  self.progress_building_waptagent.Position := Round(sz);
end;

procedure TWizardConfigConsole.on_workevent(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64);
begin
  self.progress_building_waptagent.Position := AWorkCount;
end;






end.

