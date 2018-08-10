unit uwizardresetserverpassword_restartserver;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe, Classes, SysUtils, FileUtil, Forms, Controls, EditBtn,
  StdCtrls, ExtCtrls, ComCtrls;

type

  { TWizardResetServerPasswordRestartServer }

  TWizardResetServerPasswordRestartServer = class(TWizardStepFrame)
    progress: TProgressBar;
  private

  public
    procedure wizard_load(w: TWizard); override; final;
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext : boolean ); override; final;
  end;

implementation

uses
  uwizard_strings,
  DCPsha256,
  uwapt_ini,
  IniFiles,
  ucrypto_pbkdf2,
  uwapt_services,
  uwizardresetserverpassword_data,
  uwizardutil;

{$R *.lfm}

const
  STATE_STOP_SERVICES   : integer = 1;
  STATE_WRITE_CONFIG    : integer = 2;
  STATE_START_SERVICES  : integer = 3;

{ TWizardResetServerPasswordRestartServer }

procedure TWizardResetServerPasswordRestartServer.wizard_load( w: TWizard );
begin
  inherited wizard_load(w);

end;

procedure TWizardResetServerPasswordRestartServer.wizard_show();
begin
  self.m_wizard.click_next_async();
end;

procedure start_stop( p : Pointer );
var
  r : ^integer;
begin
  r := p;

  if (STATE_STOP_SERVICES  = r^) and  srv_stop(WAPT_SERVICE_WAPTSERVER) then
  begin
    r^ := 0;
    exit;
  end;

  if (STATE_START_SERVICES = r^) and  srv_start(WAPT_SERVICE_WAPTSERVER) then
  begin
    r^ := 0;
    exit;
  end;

  r^ := -1;

end;


procedure TWizardResetServerPasswordRestartServer.wizard_next( var bCanNext: boolean);
label
  LBL_LOOP;
var
  s : String;
  ini : TIniFile;
  data : PWizardResetServerPasswordData;
  msg : String;
  r : integer;
begin
  bCanNext := false;
  data := PWizardResetServerPasswordData( m_wizard.data() );
  self.progress.Position := 1;
  self.progress.Max := 3;

// TThread.ExecuteInThread( @start_stop, Pointer(0),
// Method : TThreadExecuteCallback; AData : Pointer; AOnTerminate : TNotifyCallback = Nil) : TThread;

LBL_LOOP:
  r := self.progress.Position;

  if STATE_STOP_SERVICES = r then
  begin
    msg := Format( MSG_STOPPING_SERVICE, [WAPT_SERVICE_WAPTSERVER] );
    m_wizard.SetValidationDescription( msg );
    TThread.ExecuteInThread( @start_stop, @r, nil);
  end

  else if STATE_WRITE_CONFIG = r then
  begin
    m_wizard.SetValidationDescription( MSG_WRITE_SERVER_CONFIGURATION );
    begin
      s :=UTF8Encode( data^.wapt_server_home );
      wapt_ini_waptserver( s, s );
      try
        ini := TIniFile.Create(s);
        s := PBKDF2( s );
        ini.WriteString( INI_OPTIONS, INI_WAPT_PASSWORD, s );
        FreeAndNil(ini);
        r := 0;
      except on Ex : Exception do
        begin
          msg := Format( MSG_UNEXPECTED_ERROR, [ex.Message] );
          m_wizard.show_validation_error( nil, msg );
          exit;
        end
      end;
    end;
  end

  else if STATE_START_SERVICES = r then
  begin
    msg := Format( MSG_STARTING_SERVICE, [WAPT_SERVICE_WAPTSERVER] );
    m_wizard.SetValidationDescription( msg );
    TThread.ExecuteInThread( @start_stop, @r, nil );
  end;


  while true do
  begin
    Application.ProcessMessages;

    if r = -1 then
      exit;

    if r = 0 then
    begin
      if self.progress.Position = STATE_START_SERVICES then
        break;
      self.progress.Position := self.progress.Position + 1;
      goto LBL_LOOP;
    end;


    Sleep( 20 );
  end;



  bCanNext := true;
end;




initialization

RegisterClass(TWizardResetServerPasswordRestartServer);
end.

