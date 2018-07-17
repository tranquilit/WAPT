unit uwizardconfigconsole;

{$mode objfpc}{$H+}

interface

uses
  dmwaptpython, Classes, SysUtils, Forms, Controls, Graphics, Dialogs, uwizard,
  ComCtrls,ExtCtrls, StdCtrls, PopupNotifier, EditBtn, WizardControls;

type


  { TWizardConfigConsole }

  TWizardConfigConsole = class(TWizard)
    cb_launch_console: TCheckBox;
    ed_package_prefix: TEdit;
    ed_server_password: TEdit;
    ed_server_url: TEdit;
    ed_server_login: TEdit;
    Label1: TLabel;
    lbl_finished_congratulation: TLabel;
    lbl_package_prefix: TLabel;
    lbl_server_password: TLabel;
    lbl_server_url: TLabel;
    lbl_server_login: TLabel;
    ts_building_waptagent: TTabSheet;
    ts_finished: TTabSheet;
    ts_private_key_configuration: TTabSheet;
    ts_package_configuration: TTabSheet;
    ts_server_info: TTabSheet;
    ts_welcome: TTabSheet;
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);

  private

  m_check_certificates_validity : boolean;


  protected

  private
  function filename_certificate_server() : String;
  function config_verify_cert() : String;



  // Steps function
  function on_step_server_info( mode : TWizardStepFuncMode ) : integer;
  function on_step_building_waptagent( mode : TWizardStepFuncMode ) : integer;
  function on_step_finished( mode : TWizardStepFuncMode ) : integer;

  procedure clear();

  function write_configuration_files() : integer;



  public


  end;

var
  WizardConfigConsole: TWizardConfigConsole;

implementation

uses
  uwizardstepframeconsoleserver,
  uwizardstepframeconsolewelcome,
  uwizardstepframepackage,
  uwizardstepframebuildagent,
  uwizardstepframeconsolefinished,
  waptcommon,
  tiscommon,
  uwizardutil,
  uwizardvalidattion,
  uwizardstep,
  superobject,
  FileUtil,
  IniFiles;

{$R *.lfm}

const
  DEFAULT_COUNTRY_CODE: String = 'FR';

{
  self.register_step( 'Welcome',                  'Welcome description',                  [wbNext,wbCancel], @on_step_welcome );
  self.register_step( 'Server information',       'Server information description',       pnc, @on_step_server_info);
  self.register_step( 'Package configuration',    'Package configuration description',    pnc, @on_step_package_configuration);
  self.register_step( 'Building waptagent',       'Building waptagent description',       pnc, @on_step_building_waptagent);
  self.register_step( 'Congratulation',           'Configuration terminated !',           [wbFinish], @on_step_finished );
}

{ TWizardConfigConsole }

procedure TWizardConfigConsole.FormCreate(Sender: TObject);
begin
  inherited;
end;

procedure TWizardConfigConsole.FormShow(Sender: TObject);
begin
    self.WizardButtonPanel.NextButton.SetFocus;
end;

procedure TWizardConfigConsole.FormClose(Sender: TObject; var CloseAction: TCloseAction);
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


{
var
  i : LongWord;
  s : String;
begin

  self.Caption := 'Wapt console configuration';

  // Hints ts_server_info
  self.ed_server_url.Hint           := 'Url of the server';
  self.ed_server_login.Hint         := 'Server login';
  self.ed_server_password.Hint      := 'Server password';

  // Hints ts_package_prefix
  self.ed_package_prefix.Hint                  := 'When you pull or create a package, its name will be prefixed with your trigram/quadrigram to mark its provenance.' + #13#10 + 'Replace "test" with a trigram meaningful to your organisation (ex: tis standing for Tranquil IT Systems).';



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


}




procedure TWizardConfigConsole.clear();
begin
  // ts_server_info
  self.ed_server_url.Clear;
  self.ed_server_login.Clear;
  self.ed_server_password.Clear;

  // ts_package_prefix
  self.ed_package_prefix.Clear;


  // ts_building_waptagent

  // ts_finished


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





function TWizardConfigConsole.on_step_server_info(mode: TWizardStepFuncMode ): integer;

var
  hostname: String;
  s       : String;
  r       : integer;
  b       : boolean;
begin
  hostname := '';
  s := '';

  if wf_validate = mode then
  begin

  end;

end;










function TWizardConfigConsole.on_step_building_waptagent( mode: TWizardStepFuncMode): integer;
var
  r : integer;
begin
{
    if wf_enter = mode then
    begin
      // Writing configuration files
      self.SetValidationDescription( 'Witing configuration files');
      r := self.write_configuration_files();
      if r <> 0 then
      begin
        self.show_validation_error( nil, 'An error has occured while wrting configuration files' );
        exit(-1);
      end;


      r := self.frm_WizardStepFrameBuildAgent.wizard_enter( self, nil);
      exit(r)
    end;


    if wf_validate = mode then
    begin
      params := GetMem( sizeof(TWizardStepFrameBuildAgentParams) );
      FillChar( params^, sizeof(TWizardStepFrameBuildAgentParams), 0 );

      params^.server_url             := self.ed_server_url.Text;
      params^.server_certificate     := self.filename_certificate_server();
      params^.server_login           := self.ed_server_login.Text;
      params^.server_password        := self.ed_server_password.Text;
      params^.package_certificate    := self.frm_WizardStepFramePackage.package_certificate();
      params^.private_key_name       := self.frm_WizardStepFramePackage.package_private_key();
      params^.verify_cert            := config_verify_cert();
      params^.is_enterprise_edition  := DMPython.IsEnterpriseEdition;

      r := self.frm_WizardStepFrameBuildAgent.wizard_validate( self, params );

      FillChar( params^, sizeof(TWizardStepFrameBuildAgentParams), 0 );
      Freemem( params );
      exit(r)
    end;
}
end;




function TWizardConfigConsole.write_configuration_files(): integer;
const
  GLOBAL : String = 'global';
var
  ini : TIniFile;
  s : String;

  check_certificates_validity : String;
  repo_url                    : String;
  personal_certificate_path   : String;

begin
    // Check certificate validity
    check_certificates_validity := '1';
    if not self.m_check_certificates_validity then
      check_certificates_validity := '0';


    // repo_url
    repo_url := url_concat( self.ed_server_url.Text, '/wapt') ;

    // personal_certificate_path
//    personal_certificate_path :=  fs_path_concat('c:\private', self.frm_WizardStepFramePackage.package_certificate() );

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

end;



function TWizardConfigConsole.on_step_finished(mode: TWizardStepFuncMode): integer;
begin

  if wf_enter = mode then
    exit(0);


  if wf_validate = mode then
    exit(0);
end;













end.

