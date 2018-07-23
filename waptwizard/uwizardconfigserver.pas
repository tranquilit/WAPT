unit uwizardconfigserver;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, uwizard,

  uwizardconfigserver_data,

  uwizardconfigserver_welcome,
  uwizardconfigserver_server,
  uwizardconfigserver_firewall,
  uwizardconfigserver_keyoption,
  uwizardconfigserver_package_use_existing_key,
  uwizardconfigserver_package_create_new_key,
  uwizardconfigserver_postsetup,
  uwizardconfigserver_buildagent,
  uwizardconfigserver_finish,


  ComCtrls, ExtCtrls, StdCtrls,
  WizardControls;


type


  { TWizardConfigServer }


  TWizardConfigServer = class(TWizard)
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject); override;
    procedure FormShow(Sender: TObject);

  private

    m_data : TWizardConfigServerData;

    function register_localhost(): integer;

  public

    function data() : Pointer; override; final;

  end;

var
  WizardConfigServer: TWizardConfigServer;

implementation

{$R *.lfm}

uses
  dmwaptpython,
  uwizardutil,
  waptcommon;



{ TWizardConfigServer }
procedure TWizardConfigServer.FormCreate(Sender: TObject);
begin
  inherited;

  FillChar( m_data, sizeof(TWizardConfigServerData), 0 );

  m_data.is_enterprise_edition := DMPython.IsEnterpriseEdition;
  m_data.check_certificates_validity := '0';
  m_data.verify_cert := '0';

end;

procedure TWizardConfigServer.FormShow(Sender: TObject);
begin
end;




procedure TWizardConfigServer.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin

  if self.m_data.launch_console then
    self.launch_console();
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

function TWizardConfigServer.data(): Pointer;
begin
  exit( @m_data );
end;



end.

