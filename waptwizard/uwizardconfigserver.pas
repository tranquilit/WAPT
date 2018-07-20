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
    function register_localhost(): integer;



  end;

var
  WizardConfigServer: TWizardConfigServer;

implementation

{$R *.lfm}

uses
  uwapt_ini,
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

  self.m_data.S[UTF8Decode(INI_CHECK_CERTIFICATES_VALIDITY)] := '0';
  self.m_data.S[UTF8Decode(INI_VERIFIY_CERT)] := '0';
  self.m_data.S[UTF8Decode(INI_PERSONAL_CERTIFICATE_PATH)] := '';

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
var
  ini : TIniFile;
  r   : integer;
  s   : String;
begin
  ini := nil;

  self.SetValidationDescription( 'Writing wapt server configuration file' );
  try

    s := UTF8Encode( self.m_data.S[ UTF8Decode(INI_WAPT_PASSWORD)] );
    s := PBKDF2(s, random_alphanum(5), 29000, 32, TDCP_sha256);

    // waptserver.ini
    ini := TIniFile.Create( 'conf\waptserver.ini' );
    ini.WriteString( INI_OPTIONS, INI_DB_NAME,       'wapt');
    ini.WriteString( INI_OPTIONS, INI_DB_USER,       'wapt' );
    ini.WriteString( INI_OPTIONS, INI_WAPT_USER,     'admin' );
    ini.WriteString( INI_OPTIONS, INI_WAPT_PASSWORD, s );
    ini.WriteString( INI_OPTIONS, INI_ALLOW_UNAUTHENTICATED_REGISTRATION, 'True' );
    r := Length( Trim(ini.ReadString( INI_OPTIONS, INI_SERVER_UUID, '')) );
    if r = 0 then
      ini.WriteString( INI_OPTIONS, INI_SERVER_UUID, random_server_uuid() );
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
var
  ini : TIniFile;
  s   : String;
begin
  ini := nil;

  self.SetValidationDescription( 'Writing waptconsole configuration file' );
  try

    // waptconsole.ini
    wapt_ini_waptconsole(s);
    ini := TIniFile.Create( s );
    ini.WriteString( INI_GLOBAL, INI_CHECK_CERTIFICATES_VALIDITY, UTF8Encode(self.m_data.S[UTF8decode(INI_CHECK_CERTIFICATES_VALIDITY)]) );
    ini.WriteString( INI_GLOBAL, INI_VERIFIY_CERT,                UTF8Encode(self.m_data.S[UTF8decode(INI_CHECK_CERTIFICATES_VALIDITY)]) );
    ini.WriteString( INI_GLOBAL, INI_WAPT_SERVER,                 UTF8Encode(self.m_data.S[UTF8decode(INI_WAPT_SERVER)]) );
    ini.WriteString( INI_GLOBAL, INI_REPO_URL,                    UTF8Encode(self.m_data.S[UTF8decode(INI_WAPT_SERVER)]) + '/wapt');
    ini.WriteString( INI_GLOBAL, INI_DEFAULT_PACKAGE_PREFIX,      UTF8Encode(self.m_data.S[UTF8decode(INI_DEFAULT_PACKAGE_PREFIX)]) );
    ini.WriteString( INI_GLOBAL, INI_PERSONAL_CERTIFICATE_PATH,   UTF8Encode(self.m_data.S[UTF8decode(INI_PERSONAL_CERTIFICATE_PATH)]) );
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
var
  ini : TIniFile;
begin
  ini := nil;

  self.SetValidationDescription( 'Writing wapt-get configuration file' );
  try

    // wapt-get.ini
    ini := TIniFile.Create('wapt-get.ini' );
    ini.WriteString( INI_GLOBAL, INI_CHECK_CERTIFICATES_VALIDITY, UTF8Encode(self.m_data.S[UTF8decode(INI_CHECK_CERTIFICATES_VALIDITY)]) );
    ini.WriteString( INI_GLOBAL, INI_VERIFIY_CERT,                UTF8Encode(self.m_data.S[UTF8decode(INI_CHECK_CERTIFICATES_VALIDITY)]) );
    ini.WriteString( INI_GLOBAL, INI_WAPT_SERVER,                 UTF8Encode(self.m_data.S[UTF8decode(INI_WAPT_SERVER)]) );
    ini.WriteString( INI_GLOBAL, INI_REPO_URL,                    UTF8Encode(self.m_data.S[UTF8decode(INI_WAPT_SERVER)]) + '/wapt');
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

function TWizardConfigServer.register_localhost(): integer;
var
  params : TRunParametersSync;
  r : integer;
begin
  self.SetValidationDescription( 'Register local machine');
  params.cmd_line    := 'wapt-get.exe --direct register';
  params.on_run_tick := nil;
  params.timout_ms   := 60*1000;
  r := run_sync( @params );
  if r <> 0 then
  begin
    self.SetValidationDescription( 'An occurred occure while registered local machine' );
    exit(r);
  end;
  exit(0);
end;


procedure TWizardConfigServer.WizardManagerPageHide(Sender: TObject; Page: TWizardPage);
begin
  if 'TWizardStepFrameFirewall' = page.ControlClassName then
    self.write_configuration_file_waptserver()
  else if 'TWizardStepFramePackage' = page.ControlClassName then
  begin
    self.write_configuration_file_waptconsole();
    self.write_configuration_file_waptget();
    wapt_service_restart();
    register_localhost();
  end;


end;



end.

