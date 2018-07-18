unit uwizardconfigserver;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, uwizard,
  uwizardstepframeserverwelcome,
  uwizardstepframeservercertificate,
  uwizardstepframepackage,
  uwizardstepframepassword,
  uwizardstepframefirewall,
  uwizardstepframerunserverpostsetup,
  uwizardstepframebuildagent,
  uwizardstepframeserverfinish,

  ComCtrls, ExtCtrls, StdCtrls,
  WizardControls;

type

  { TWizardConfigServer }

  TWizardConfigServer = class(TWizard)
    frm_WizardStepFrameBuildAgent: TWizardStepFrameBuildAgent;
    frm_WizardStepFramePackage: TWizardStepFramePackage;
    frm_WizardStepFrameRunServerPostSetup: TWizardStepFrameRunServerPostSetup;
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject); override;
    procedure FormShow(Sender: TObject);

    procedure WizardManagerPageHide(Sender: TObject; Page: TWizardPage);
  private
    function write_configuration_file_waptserver() : integer;
    function write_configuration_file_waptconsole() : integer;
    function write_configuration_file_waptget() : integer;



  end;

var
  WizardConfigServer: TWizardConfigServer;

implementation

{$R *.lfm}

uses
  DCPsha256,
  IniFiles,
  ucrypto_pbkdf2,
  uwizardutil,
  waptcommon;



{ TWizardConfigServer }
procedure TWizardConfigServer.FormCreate(Sender: TObject);
begin
  inherited;
end;

procedure TWizardConfigServer.FormShow(Sender: TObject);
begin
  self.WizardButtonPanel.NextButton.SetFocus;

  self.m_data.S['check_certificates_validity'] := '0';
  self.m_data.S['verify_cert'] := '0';
  self.m_data.S['personal_certificate_path'] := '';

end;




procedure TWizardConfigServer.FormClose(Sender: TObject; var CloseAction: TCloseAction);
var
  r : integer;
begin
  if self.m_data.B['launch_console'] then
  begin
    r := process_launch( 'waptconsole.exe' );
    if r <> 0 then
      self.show_error( 'An error has occured while launching the console');
  end;
end;



function TWizardConfigServer.write_configuration_file_waptserver(): integer;
const
  OPTS : String = 'options';
var
  ini : TIniFile;
  r   : integer;
  s   : String;
begin
  ini := nil;

  self.SetValidationDescription( 'Writing wapt server configuration file' );
  try

    s := UTF8Encode( self.m_data.S['wapt_password'] );
    s := PBKDF2(s, random_alphanum(5), 29000, 32, TDCP_sha256);

    // waptserver.ini
    ini := TIniFile.Create( 'conf\waptserver.ini' );
    ini.WriteString( OPTS, 'db_name',       'wapt');
    ini.WriteString( OPTS, 'db_user',       'wapt' );
    ini.WriteString( OPTS, 'wapt_user',     'admin' );
    ini.WriteString( OPTS, 'wapt_password', s );
    ini.WriteString( OPTS, 'allow_unauthenticated_registration', 'True' );
//    ini.WriteString( OPTS, 'waptwua_folder', '' );
//    ini.WriteString( OPTS, 'secret_key', '' );
    r := Length( Trim(ini.ReadString( OPTS, 'server_uuid', '')) );
    if r = 0 then
      ini.WriteString( OPTS, 'server_uuid', random_server_uuid() );
    FreeAndNil( ini );


    result := 0;
  except on Ex : Exception do
    begin
      result := -1;
      self.SetValidationDescription( ex.Message );
    end;
  end;

  if Assigned(ini) then
    FreeAndNil(ini);

end;

function TWizardConfigServer.write_configuration_file_waptconsole(): integer;
const
  GLOB : String = 'global';
var
  ini : TIniFile;
  s   : String;
begin
  ini := nil;

  self.SetValidationDescription( 'Writing waptconsole configuration file' );
  try

    // waptconsole.ini
    s := ExtractFileDir(AppIniFilename() );
    s := ExtractFileDir(s);
    s := IncludeTrailingBackslash(s) + 'waptconsole';
    s := IncludeTrailingBackslash(s) + 'waptconsole.ini';
    ini := TIniFile.Create( s );
    ini.WriteString( GLOB, 'check_certificates_validity', UTF8Encode(self.m_data.S['check_certificates_validity']) );
    ini.WriteString( GLOB, 'verify_cert',                 UTF8Encode(self.m_data.S['verify_cert']) );
    ini.WriteString( GLOB, 'wapt_server',                 UTF8Encode(self.m_data.S['wapt_server']) );
    ini.WriteString( GLOB, 'repo_url',                    UTF8Encode(self.m_data.S['wapt_server']) + '/wapt');
    ini.WriteString( GLOB, 'default_package_prefix',      UTF8Encode(self.m_data.S['default_package_prefix']) );
    ini.WriteString( GLOB, 'personal_certificate_path',   UTF8Encode(self.m_data.S['personal_certificate_path']) );
    FreeAndNil( ini );

    result := 0;
  except on Ex : Exception do
    begin
      result := -1;
      self.SetValidationDescription( ex.Message );
    end;
  end;

  if Assigned(ini) then
    FreeAndNil(ini);

end;

function TWizardConfigServer.write_configuration_file_waptget(): integer;
const
  GLOB : String = 'global';
var
  ini : TIniFile;
begin
  ini := nil;

  self.SetValidationDescription( 'Writing wapt-get configuration file' );
  try

    // wapt-get.ini
    ini := TIniFile.Create('wapt-get.ini' );
    ini.WriteString( GLOB, 'check_certificates_validity', UTF8Encode(self.m_data.S['check_certificates_validity']) );
    ini.WriteString( GLOB, 'verify_cert',                 UTF8Encode(self.m_data.S['verify_cert']) );
    ini.WriteString( GLOB, 'wapt_server',                 UTF8Encode(self.m_data.S['wapt_server']) );
    ini.WriteString( GLOB, 'repo_url',                    UTF8Encode(self.m_data.S['wapt_server']) + '/wapt');
    ini.WriteString( GLOB, 'default_package_prefix',      UTF8Encode(self.m_data.S['default_package_prefix']) );
    ini.WriteString( GLOB, 'personal_certificate_path',   UTF8Encode(self.m_data.S['personal_certificate_path']));
    FreeAndNil( ini );

    result := 0;
  except on Ex : Exception do
    begin
      result := -1;
      self.SetValidationDescription( ex.Message );
    end;
  end;

  if Assigned(ini) then
    FreeAndNil(ini);

end;





procedure TWizardConfigServer.WizardManagerPageHide(Sender: TObject; Page: TWizardPage);
begin

  if 'TWizardStepFrameFirewall' = page.ControlClassName then
    self.write_configuration_file_waptserver()
  else if 'TWizardStepFramePackage' = page.ControlClassName then
  begin
    self.write_configuration_file_waptconsole();
    self.write_configuration_file_waptget();
  end;


end;



end.

