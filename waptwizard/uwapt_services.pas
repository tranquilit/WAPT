unit uwapt_services;

{$mode objfpc}{$H+}

interface

uses
  tiscommon,
  Classes, SysUtils;


const
WAPT_SERVICE_WAPTPOSTGRESQL : String = 'WAPTPostgresql';
WAPT_SERVICE_WAPTTASKS      : String = 'WAPTtasks';
WAPT_SERVICE_WAPTSERVER     : String = 'WAPTServer';
WAPT_SERVICE_WAPTNGINX      : String = 'WAPTNginx';
WAPT_SERVICE_WAPTSERVICE    : String = 'WAPTService';

WAPT_SERVICES_AGENT  : array[0..0] of String = (  'WAPTService' );
{$ifdef ENTERPRISE}
WAPT_SERVICES_SERVER : array[0..3] of String = ( 'WAPTPostgresql', 'WAPTtasks', 'WAPTServer', 'WAPTNginx' );
WAPT_SERVICES_ALL    : array[0..4] of String = ( 'WAPTPostgresql', 'WAPTtasks', 'WAPTServer', 'WAPTNginx', 'WAPTService' );
{$else}
WAPT_SERVICES_SERVER : array[0..2] of String = ( 'WAPTPostgresql', 'WAPTServer','WAPTNginx' );
WAPT_SERVICES_ALL    : array[0..3] of String = ( 'WAPTPostgresql', 'WAPTServer','WAPTNginx', 'WAPTService' );
{$endif}


function  srv_set_state(const service : String; state : TServiceState; timeout_seconds : integer ) : integer;
function  srv_set_state( services : TStringArray; state : TServiceState; timeout_seconds : integer ) : integer;
function  srv_exist( const name : String ) : boolean;

function  srv_start( const name : String; timeout_seconds : integer = 15) : boolean;
function  srv_start( const services : TStringArray; timeout_seconds : integer = 15) : boolean;

function  srv_stop(  const name : String;  timeout_seconds : integer = 15) : boolean;
function  srv_stop(  const services : TStringArray; timeout_seconds : integer = 15 ) : boolean;

function  srv_restart(  const name : String;  timeout_seconds : integer = 15) : boolean;
function  srv_restart(  const services : TStringArray; timeout_seconds : integer = 15 ) : boolean;

function  srv_is_running( const name : String ) : boolean;

function srv_agent_restart_and_register(): integer;

// function wapt_srv_restart() : integer;
// function wapt_srv_restart_and_register() : integer;
// function wapt_srv_set_state( state: TServiceState ) : integer;
// function wapt_server_set_state( state : TServiceState ): integer;

implementation

uses
  forms,
  uwizardutil;

const
TIMEOUT_MS : integer = 5 * 1000;


function srv_set_state(const service: String; state: TServiceState; timeout_seconds: integer): integer;
var
    t       : integer;
    ss      : TServiceState;
    params  : TRunParametersSync;
begin
  if not ( state in [ssStopped,ssRunning] ) then
    exit( -1 );

  ss := GetServiceStatusByName('', service );
  if ssUnknown = ss then
  begin
    // No fail when service doesn't exist
    exit(0);
  end;


  params.on_run_tick:= nil;
  params.timout_ms:= timeout_seconds * 1000;

  // First Send command
  case state of

    ssRunning :
    begin
      if not ( ss in[ ssUnknown,ssStartPending,ssRunning] ) then
      begin
        params.cmd_line := Format( 'cmd /c net start %s', [LowerCase(service)] );
        run_sync( @params );
      end;
    end;

    ssStopped :
    begin
      if not ( ss in[ ssUnknown,ssStopPending,ssStopped] ) then
      begin
        params.cmd_line  := Format( 'cmd /c net stop %s', [LowerCase(service)] );
        run_sync( @params );
      end;
    end;

  end;


  // Wait for state unitl timeout
  t := timeout_seconds * 1000;
  while true do
  begin
    if state = GetServiceStatusByName( '', service ) then
      break;
    if t < 1 then
      exit( -1 );
    Sleep( 33 );
    dec( t, 33 );
    Application.ProcessMessages;
  end;

  exit(0);
end;

function srv_set_state( services: TStringArray; state: TServiceState; timeout_seconds: integer): integer;
var
    i : integer;
    r : integer;
begin
  for i := 0 to Length(services) -1 do
  begin
    r := srv_set_state( services[i], state, timeout_seconds );
    if r <> 0 then
      exit( r );
  end;
  exit( 0 );
end;

function srv_exist(const name: String): boolean;
var
  params : TRunParametersSync;
  r : integer;
begin
  FillChar( params, sizeof(PRunParamatersSync), 0 );

  params.cmd_line := 'sc query ' + name;
  params.on_run_tick := nil;
  params.timout_ms := TIMEOUT_MS;

  try
    run_sync( @params );
    exit( true );
  except on Ex : EOSError do
    exit( Pos(  '1060', ex.Message ) = 0 );
  end;

end;

function srv_start(const name: String; timeout_seconds: integer ): boolean;
begin
  Result := 0 = srv_set_state( name, ssRunning, timeout_seconds );
end;

function srv_start(const services: TStringArray; timeout_seconds: integer ): boolean;
var
  i : integer;
  b : boolean;
begin
  for i := 0 to Length(services) -1 do
  begin
    b := srv_start( services[i], timeout_seconds );
    result := result and b;
  end;
end;

function srv_stop(const name: String; timeout_seconds: integer ): boolean;
begin
  Result := 0 = srv_set_state( name, ssStopped, timeout_seconds );
end;

function srv_stop(const services: TStringArray; timeout_seconds: integer ): boolean;
var
  i : integer;
  b : boolean;
begin
  for i := 0 to Length(services) -1 do
  begin
    b := srv_stop( services[i], timeout_seconds );
    result := result and b;
  end;
end;

function srv_restart(const name: String; timeout_seconds: integer): boolean;
begin
  srv_stop( name, timeout_seconds );
  result := srv_start( name, timeout_seconds );
end;

function srv_restart(const services: TStringArray; timeout_seconds: integer ): boolean;
begin
  srv_stop( sa_flip(services), timeout_seconds );
  result := srv_start( services, timeout_seconds );
end;

procedure srv_stop_no_fail(services_names: TStringArray; timeout_seconds: integer );
var
  i : integer;
  m : integer;
begin
  m := Length(services_names) -1;
  for i := 0 to m do
  begin
    if not srv_exist( services_names[i] ) then
      continue;
    srv_set_state( services_names[i], ssStopped, timeout_seconds );
  end;
end;

function srv_is_running(const name: String): boolean;
var
    ss : TServiceState;
begin
  ss := GetServiceStatusByName( '', name );
  exit( ssRunning = ss );
end;

function srv_agent_restart_and_register(): integer;
var
  b : boolean;
begin
  srv_stop( sa_flip(WAPT_SERVICES_AGENT) );
  result := wapt_register();
  if Result <> 0 then
    exit;
  b := srv_start( WAPT_SERVICES_AGENT );
  if not b then
    exit(-1);

  exit(0);
end;


end.

