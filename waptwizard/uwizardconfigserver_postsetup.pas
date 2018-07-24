unit uwizardconfigserver_postsetup;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  Classes, SysUtils,  Controls, StdCtrls;

type

  { TWizardConfigServer_ServerPostSetup }

  TWizardConfigServer_ServerPostSetup = class( TWizardStepFrame )
    memo: TMemo;
  private
    procedure on_run_tick( sender : TObject );
  public
    constructor Create( AOwner : TComponent ); override;

    // TWizardStepFrame
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;
    procedure clear(); override; final;

  end;

implementation

uses
  dialogs,
  tiscommon,
  Forms,
  FileUtil,
  uwizardconfigserver_data,
  uwizardutil,
  uwizardvalidattion;

{$R *.lfm}

{ TWizardConfigServer_ServerPostSetup }

constructor TWizardConfigServer_ServerPostSetup.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  self.clear();
  self.memo.ReadOnly := true;
end;

procedure TWizardConfigServer_ServerPostSetup.wizard_show();
begin
  inherited wizard_show();
  self.Align := alClient;

  // Dont wait user to click on next to start
  // working
  m_wizard.click_next_async();


end;

procedure TWizardConfigServer_ServerPostSetup.on_run_tick(sender: TObject);
var
  ss : TStringStream;
begin
  ss := TStringStream(sender);
  self.memo.Text := ss.DataString;
  Application.ProcessMessages;
end;


procedure TWizardConfigServer_ServerPostSetup.wizard_next(var bCanNext: boolean );
const
  TIMEOUT_MS : integer = 15 * 60 * 1000;
var
  run_params : TRunParametersSync;
  r   : integer;
  s   : String;
  data : PWizardConfigServerData;
begin

  bCanNext := false;

  data := m_wizard.data();

  self.memo.Clear;

  // Stop server
  wizard_validate_waptserver_stop_services_no_fail( self.m_wizard, self.memo );

  // Write waptserver.ini
  r := TWizardConfigServerData_write_ini_waptserver( data, self.m_wizard );
  if r <> 0 then
    exit;

  // Write wapt-get.ini
  r := TWizardConfigServerData_write_ini_waptget( data, self.m_wizard );
  if r <> 0 then
    exit;



  //
  FillChar( run_params, sizeof(TRunParametersSync), 0 );
  run_params.cmd_line := 'waptpython.exe waptserver\winsetup.py all';
  run_params.timout_ms:= TIMEOUT_MS;
  run_params.on_run_tick := @on_run_tick;
  if not wizard_validate_run_command_sync( m_wizard, @run_params, 'Running post install scripts', 'Error while running post setup scripts', nil ) then
    exit;


  // Removing ssl\tranquilit.crt
  if FileExists('ssl\tranquilit.crt') then
    DeleteFile('ssl\tranquilit.crt' );

  // Start services
  m_wizard.SetValidationDescription( 'Starting wapt services' );
  r := service_set_state( WAPT_SERVICES, ssRunning, 60 );
  if r <> 0 then
  begin
    m_wizard.show_validation_error( nil, 'Failed to start services' );
    exit;
  end;


  // mongo DB -> postgresql
  if FileExists( 'waptserver\mongodb\mongoexport.exe') then
  begin
    m_wizard.SetValidationDescription( 'Migration from MongoDB required');
    s := 'Upgrade from mongodb to postgresql is required, continue ?';
    if mrYes = m_wizard.show_question( s , mbYesNo ) then
    begin
      r := wapt_server_mongodb_to_postgresql();
      if r <> 0 then
      begin
        m_wizard.show_validation_error( nil, 'An has occured while migrating from mogodb to postgresql' );
        exit;
      end;
    end;
  end;

  // ping
  if not wizard_validate_waptserver_ping( m_wizard, 'https://localhost', nil ) then
    exit;


  bCanNext := true;

end;

procedure TWizardConfigServer_ServerPostSetup.clear();
begin
  self.memo.Clear;
end;

initialization

  RegisterClass(TWizardConfigServer_ServerPostSetup);

end.

