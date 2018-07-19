unit uwizardconfigconsole;

{$mode objfpc}{$H+}

interface

uses
  dmwaptpython, Classes, SysUtils, Forms, Controls, Graphics, Dialogs, uwizard,
  ComCtrls,ExtCtrls, StdCtrls, PopupNotifier, EditBtn, WizardControls;

type


  { TWizardConfigConsole }

  TWizardConfigConsole = class(TWizard)
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);


    procedure WizardManagerPageHide(Sender: TObject; Page: TWizardPage);

  private

  m_check_certificates_validity : boolean;

  private


  function write_configuration_files() : integer;



  public


  end;

var
  WizardConfigConsole: TWizardConfigConsole;

implementation

uses
  uwapt_ini,
  uwizardstepframeconsoleserver,
  uwizardstepframeconsolewelcome,
  uwizardstepframepackage,
  uwizardstepframebuildagent,
  uwizardstepframeconsolefinished,
  waptcommon,
  uwizardutil,
  superobject,
  FileUtil,
  IniFiles;

{$R *.lfm}

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
  if self.m_data.B['launch_console'] then
  begin
    r := process_launch( 'waptconsole.exe' );
    if r <> 0 then
      self.show_error( 'An error has occured while launching the console');
  end;
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








{
function TWizardConfigConsole.config_verify_cert(): String;
begin
  // Check certficate CA
  result := '0';
{$ifdef ENTERPRISE}
  if self.m_check_certificates_validity then
    result := '1';
{$endif}
end;
}







function TWizardConfigConsole.write_configuration_files(): integer;
var
  ini : TIniFile;
  s : String;
  r : integer;

  check_certificates_validity : String;
  repo_url                    : String;
  personal_certificate_path   : String;
  verify_cert : String;
  wapt_server : String;
  package_prefix : String;
begin
    // Check certificate validity
    check_certificates_validity := '1';
    if not self.m_check_certificates_validity then
      check_certificates_validity := '0';


    wapt_server     := UTF8Encode(self.m_data.S[UTF8Decode(INI_WAPT_SERVER)]);
    repo_url        := url_concat( wapt_server, '/wapt') ;
    package_prefix  := UTF8Encode(self.m_data.S[UTF8Decode(INI_DEFAULT_PACKAGE_PREFIX)]);
    personal_certificate_path := UTF8Encode(self.m_data.S[UTF8Decode(INI_PERSONAL_CERTIFICATE_PATH)]);

    r := https_certificate_pinned_filename( verify_cert, wapt_server );
    verify_cert := '0';

    // Now Writing settings
    try
      {
      // wapt-get.ini
      s := 'wapt-get.ini';
      ini := TIniFile.Create( s );
      ini.WriteString( INI_GLOBAL, INI_CHECK_CERTIFICATES_VALIDITY, check_certificates_validity );
      ini.WriteString( INI_GLOBAL, INI_VERIFIY_CERT,                verify_cert);
      ini.WriteString( INI_GLOBAL, INI_WAPT_SERVER,                 wapt_server);
      ini.WriteString( INI_GLOBAL, INI_REPO_URL,                    repo_url );
      ini.Free;
      }

      // waptconsole.ini
      wapt_ini_waptconsole(s);
      ini := TIniFile.Create( s );
      ini.WriteString( INI_GLOBAL, INI_CHECK_CERTIFICATES_VALIDITY, check_certificates_validity );
      ini.WriteString( INI_GLOBAL, INI_VERIFIY_CERT,                verify_cert);
      ini.WriteString( INI_GLOBAL, INI_WAPT_SERVER,                 wapt_server );
      ini.WriteString( INI_GLOBAL, INI_REPO_URL,                    repo_url );
      ini.WriteString( INI_GLOBAL, INI_DEFAULT_PACKAGE_PREFIX,      package_prefix );
      ini.WriteString( INI_GLOBAL, INI_PERSONAL_CERTIFICATE_PATH,   personal_certificate_path );
      ini.Free;

      ini := nil;
      self.ClearValidationDescription();
    finally
      if Assigned(ini) then
        FreeAndNil(ini);
    end;

end;

procedure TWizardConfigConsole.WizardManagerPageHide(Sender: TObject; Page: TWizardPage);
begin
    if 'TWizardStepFramePackage' = page.ControlClassName then
      self.write_configuration_files();
end;


end.

