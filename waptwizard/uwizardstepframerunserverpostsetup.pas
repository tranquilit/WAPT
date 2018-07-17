unit uwizardstepframerunserverpostsetup;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  Classes, SysUtils,  Controls, StdCtrls;

type

  { TWizardStepFrameRunServerPostSetup }

  TWizardStepFrameRunServerPostSetup = class( TWizardStepFrame )
    memo: TMemo;
  private
    procedure on_run_tick( sender : TObject );
  public
    constructor Create( AOwner : TComponent ); override;

    // TWizardStepFrame
    procedure wizard_show(); override; final;
    function wizard_validate() : Integer; override; final;
    procedure clear(); override; final;

  end;

implementation

uses
  dialogs,
  tiscommon,
  Forms,
  FileUtil,
  uwizardutil,
  uwizardvalidattion;

{$R *.lfm}

{ TWizardStepFrameRunServerPostSetup }

constructor TWizardStepFrameRunServerPostSetup.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  self.clear();
  self.memo.ReadOnly := true;
end;

procedure TWizardStepFrameRunServerPostSetup.wizard_show();
begin
  inherited wizard_show();
  self.Align := alClient;

  // Dont wait user to click on next to start
  // working
  m_wizard.click_next_async();

end;

procedure TWizardStepFrameRunServerPostSetup.on_run_tick(sender: TObject);
var
  ss : TStringStream;
begin
  ss := TStringStream(sender);
  self.memo.Text := ss.DataString;
  Application.ProcessMessages;
end;


function TWizardStepFrameRunServerPostSetup.wizard_validate(): Integer;
const
  TIMEOUT_MS : integer = 15 * 60 * 1000;
var
  run_params : TRunParametersSync;
  r   : integer;
  s   : String;
begin

  wizard_validate_waptserver_stop_services_no_fail( self.m_wizard, self.memo );

  Assert( self.m_data.O['server_hostname'] <> nil );

  //
  FillChar( run_params, sizeof(TRunParametersSync), 0 );
  run_params.cmd_line := 'waptpython.exe waptserver\winsetup.py all';
  run_params.timout_ms:= TIMEOUT_MS;
  run_params.on_run_tick := @on_run_tick;
  if not wizard_validate_run_command_sync( m_wizard, @run_params, 'Running post install scripts', 'Error while running post ', self.memo ) then
    exit( -1 );


  // Removing ssl\tranquilit.crt
  if FileExists('ssl\tranquilit.crt') then
    DeleteFile('ssl\tranquilit.crt' );

  // Start services
  m_wizard.SetValidationDescription( 'Starting wapt services' );
  r := service_set_state( WAPT_SERVICES, ssRunning, 60 );
  if r <> 0 then
  begin
    m_wizard.show_validation_error( nil, 'Failed to start services' );
    exit( -1 );
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
        exit( -1 );
      end;
    end;
  end;

  // ping
  s := UTF8Encode(self.m_data.S['wapt_server']);
  if not wizard_validate_waptserver_ping( m_wizard, s, nil ) then
    exit( -1 );


  exit( 0 );

end;

procedure TWizardStepFrameRunServerPostSetup.clear();
begin
  self.memo.Clear;
end;

initialization

  RegisterClass(TWizardStepFrameRunServerPostSetup);

end.

