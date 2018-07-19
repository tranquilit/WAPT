unit uwizardstepframeconsoleserver;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  superobject,

  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls;

type

  { TWizardStepFrameConsoleServer }

  TWizardStepFrameConsoleServer = class(TWizardStepFrame)
    ed_server_password: TEdit;
    ed_server_url: TEdit;
    ed_server_username: TEdit;
    lbl_server_password: TLabel;
    lbl_server_url: TLabel;
    lbl_server_username: TLabel;
  private
    m_check_certificates_validity : boolean;

  public
  // TWizardStepFrame
  procedure wizard_load(w: TWizard; data: ISuperObject);  override; final;
  function wizard_validate() : integer;  override; final;
  procedure clear();  override; final;

  end;

implementation

uses
  uwapt_ini_conts,
  IniFiles,
  uwizardutil,
  uwizardvalidattion,
  Dialogs,
  waptcommon
  ;

{$R *.lfm}

{ TWizardStepFrameConsoleServer }

procedure TWizardStepFrameConsoleServer.wizard_load(w: TWizard; data: ISuperObject);
var
  r : integer;
  s : String;
  ini : TIniFile;
begin
  inherited wizard_load( w, data );

  self.ed_server_url.Text := '';
  self.ed_server_username.Text := 'admin';
  self.ed_server_password.Text := '';

  //
  ini := nil;
  r := wapt_ini_waptconsole(s);
  // r = 0 -> file exist
  if r = 0 then
  begin
    try
      ini := TIniFile.Create(s);
      self.ed_server_url.Text := ini.ReadString( INI_GLOBAL, INI_WAPT_SERVER, self.ed_server_url.Text );
    finally
      if Assigned(ini) then
        FreeAndNil(ini);
    end;
  end;



end;

function TWizardStepFrameConsoleServer.wizard_validate(): integer;
var
  hostname : String;
  r : integer;
  b : boolean;
  s : String;
begin

  m_check_certificates_validity := true;

  // Check fields content length
  m_wizard.SetValidationDescription( 'Checking fields validity' );
  if not wizard_validate_str_not_empty_when_trimmed( m_wizard, self.ed_server_url,  'Server url cannot be empty' ) then
    exit(-1);

  if not wizard_validate_str_not_empty_when_trimmed( m_wizard, self.ed_server_username,'Username cannot be empty' ) then
    exit(-1);

  if not wizard_validate_str_length_not_zero( m_wizard, self.ed_server_password,    'Password cannot be empty' ) then
    exit(-1);

  // Check ping
  if not wizard_validate_waptserver_ping( m_wizard, self.ed_server_url.Text , self.ed_server_url ) then
    exit(-1);

  // Get certificate hostname
  m_wizard.SetValidationDescription( 'Retrieving server certificate');
  r := https_certificate_extract_hostname( hostname, self.ed_server_url.Text );
  if r <> 0 then
  begin
    m_wizard.show_validation_error( self.ed_server_url, 'A problem has happenend while validating server certificat' );
    exit(-1);
  end;

  b := false;
  r := url_resolv_to_same_ip( b, self.ed_server_url.Text, hostname );
  if (r <> 0) or not b then
  begin
    s :=     'Server certficate cannot be verified' + #13#10;
    s := s + 'Do you want to continue without verification ?';
    if mrNo = m_wizard.show_question( s, mbYesNo ) then
    begin
      m_wizard.show_validation_error( self.ed_server_url, 'Certificate verification failed, try configure name resolution properly' );
      exit(-1);
    end;
    self.m_check_certificates_validity := false;

    hostname := url_hostname( self.ed_server_url.Text );
  end;


  self.ed_server_url.Text := 'https://' + hostname;
  Application.ProcessMessages;


  // Check version
  if not wizard_validate_waptserver_version_not_less( m_wizard, self.ed_server_url.Text, WAPTServerMinVersion, self.ed_server_url ) then
    exit(-1);

  if self.m_check_certificates_validity then
  begin

    // Check certifcate validity
    m_wizard.SetValidationDescription( 'Validating certificate' );
    r := https_certificate_is_valid( b, self.ed_server_url.Text );
    if r <> 0 then
    begin
      m_wizard.show_error( 'A problem has occured while checking if certificat is valid' );
      exit(-1);
    end;
    if not b then
    begin

      // Was pinned ?
      r := https_certificate_is_pinned( b, self.ed_server_url.Text );
      if r <> 0 then
      begin
        m_wizard.show_error( 'A problem has occured while checking if certificat is pinned' );
        exit(-1);
      end;
      if b then
      begin
        m_wizard.show_validation_error( self.ed_server_url, 'Certificat is pinned but invalid' + #13#10 + 'Maybe you could try delete certificat first' );
        exit(-1);
      end;


      // Pin it ?
      if mrNo =  MessageDlg( 'Question', 'Certificate is not valided, do you want to pin it ?', mtConfirmation, mbYesNo, 0 ) then
      begin
        m_wizard.show_validation_error( self.ed_server_url, 'A self signed certicate must be pinned to be verified' );
        exit(-1);
      end;

      // Pin it !
      r := https_certificate_pin( self.ed_server_url.Text );
      if r <> 0 then
      begin
        m_wizard.show_error( 'A problem has occured while pinning certificate' );
        exit(-1);
      end;

      // Re check certificate validity
      r := https_certificate_is_valid( b, self.ed_server_url.Text );
      if r <> 0 then
      begin
        m_wizard.show_error( 'A problem has occured while verified pinned certificat' );
        exit(-1);
      end;

      if not b then
      begin
        m_wizard.show_validation_error( self.ed_server_url, 'Pinned certificate  verification failed, cannot continue' );
        exit(-1);
      end;
    end;
  end;

  // Check Login
  if not wizard_validate_waptserver_login( m_wizard, self.ed_server_url.Text, self.m_check_certificates_validity, self.ed_server_username.Text, self.ed_server_password.Text, self.ed_server_password ) then
    exit(-1);

  m_wizard.ClearValidationDescription();
  exit( 0 );

end;

procedure TWizardStepFrameConsoleServer.clear();
begin
  inherited clear();
end;


initialization

RegisterClass(TWizardStepFrameConsoleServer);

end.

