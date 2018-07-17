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




  private
    function write_configuration_files() : integer;

  public
    procedure WizardManagerPageShow(Sender: TObject; Page: TWizardPage); override; final;


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
  uwizardvalidattion,
  tiscommon,
  waptcommon,
  waptwinutils,
  uwizardstep;



{ TWizardConfigServer }
procedure TWizardConfigServer.FormClose(Sender: TObject; var CloseAction: TCloseAction);
var
  r : integer;
begin
  {
  if (self.PageControl.ActivePage = ts_finished) and self.cb_launch_console.Checked then
  begin
    r := process_launch( 'waptconsole.exe' );
    if r <> 0 then
      self.show_error( 'An error has occured while launching the console');
  end;
  }
end;

procedure TWizardConfigServer.FormCreate(Sender: TObject);
begin
  inherited;
end;

procedure TWizardConfigServer.FormShow(Sender: TObject);
begin
  self.WizardButtonPanel.NextButton.SetFocus;
end;



function TWizardConfigServer.write_configuration_files(): integer;
const
  OPTS : String = 'options';
  GLOB : String = 'global';
var
  ini : TIniFile;
  r   : integer;
  s   : String;
begin
  ini := nil;

  self.SetValidationDescription( 'Writing configuration' );
  try

    s := UTF8Encode( self.m_data.S['server_password'] );
    s := PBKDF2(s, random_alphanum(5), 29000, 32, TDCP_sha256);

    // waptserver.ini
    ini := TIniFile.Create( 'conf\waptserver.ini' );
    ini.WriteString( OPTS, 'db_name',       'wapt');
    ini.WriteString( OPTS, 'db_user',       'wapt' );
    ini.WriteString( OPTS, 'wapt_user',     'admin' );
    ini.WriteString( OPTS, 'wapt_password', s );
//    ini.WriteString( OPTS, 'allow_unauthenticated_registration', '' );
//    ini.WriteString( OPTS, 'waptwua_folder', '' );
//    ini.WriteString( OPTS, 'secret_key', '' );
    r := Length( Trim(ini.ReadString( OPTS, 'server_uuid', '')) );
    if r = 0 then
      ini.WriteString( OPTS, 'server_uuid', random_server_uuid() );
    FreeAndNil( ini );


    // waptconsole.ini
     s := IncludeTrailingBackslash(ExtractFileDir( AppIniFilename())) + 'waptconsole.ini';
    ini := TIniFile.Create( s );
    ini.WriteString( GLOB, 'check_certificates_validity', '0' );
    ini.WriteString( GLOB, 'verify_cert',                 '0' );
    ini.WriteString( GLOB, 'wapt_server',                 'https://localhost');
    ini.WriteString( GLOB, 'repo_url',                    'https://localhost/wapt' );
    ini.WriteString( GLOB, 'default_package_prefix',      'test');
    ini.WriteString( GLOB, 'personal_certificate_path',   'c:\private' );
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

procedure TWizardConfigServer.WizardManagerPageShow(Sender: TObject; Page: TWizardPage);
begin
  inherited WizardManagerPageShow(Sender, Page);

  if page.ControlClass = TWizardStepFrameRunServerPostSetup then
    self.write_configuration_files();

end;


end.

