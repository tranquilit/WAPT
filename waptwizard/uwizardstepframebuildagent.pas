unit uwizardstepframebuildagent;

{$mode objfpc}{$H+}

interface

uses
  IdComponent,
  uwizard,
  uwizardstepframe,
  superobject,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, ComCtrls;

type



  { TWizardStepFrameBuildAgent }
  TWizardStepFrameBuildAgent = class( TWizardStepFrame )
    lbl: TLabel;
    progress: TProgressBar;
  private
    procedure Build( const target : String; func : Pointer; data : Pointer; callback : Tnotifycallback );
    procedure on_building_waptagent_tick( sender : TObject );
    procedure tick( data : PtrInt );
    procedure on_workevent( ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64);
    procedure building_init_ui( const s : String; max : integer );
    procedure building_show_error( w : TWizard; control : TControl; const msg : String );


  public

  // TWizardStepFrame
    procedure wizard_show(); override; final;
  procedure wizard_load( w : TWizard; data : ISuperObject ); override; final;
  function wizard_validate( ) : integer;  override; final;




  end;

implementation

uses
  waptcommon,
  dialogs,
  uwizardvalidattion,
  uwizardutil;

{$R *.lfm}

const
MSG_BUILDING : String = 'Building %s   ';
MSG_UPLOADING: String = 'Uploading waptagent to server';
MSG_CONFIRM_BUILDIND : String = '%s has been found on the server.' + #13#10#13#10 + 'Rebuild and overwrite it ?';
MSG_ERROR_CHECKING_NOT_404 : String = 'A Problem has occurred while checking if %s exist on server' + #13#10 + 'Server installation may be broken, you could try reinstall waptserver';


{ TWizardStepFrameBuildAgent }


procedure TWizardStepFrameBuildAgent.wizard_load(w: TWizard; data: ISuperObject);
begin
  inherited wizard_load(w, data);


end;

procedure TWizardStepFrameBuildAgent.wizard_show();
begin
  inherited wizard_show();
  self.m_wizard.WizardButtonPanel.NextButton.Click;
end;

function TWizardStepFrameBuildAgent.wizard_validate(): integer;
label
  LBL_BUILD_WAPTUPGRADE,
  LBL_BUILD_WAPTAGENT;
var
  params_waptagent  : TCreateSetupParams_waptagent;
  params_waptupgrade: TCreateSetupParams_waptupgrade;
  so : ISuperObject;
  s : String;
  r : integer;
  i : integer;


  server_url : String;
  verify_cert: String;
  package_certificate : String;
begin

  server_url := UTF8Encode(m_data.S['server_url']);
  Assert( Length(Trim(server_url)) > 0 ) ;
  verify_cert:= '0';
  package_certificate := UTF8Encode( m_data.S['package_certificate'] );




////////////////////// Building waptagent
LBL_BUILD_WAPTAGENT:
  progress.Visible := false;
  lbl.Caption := 'Prepare building waptagent';

  // Check if waptagent already exist on server
  m_wizard.SetValidationDescription( 'Checking if waptagent exist on server' );
  s := url_concat( server_url, '/wapt/waptagent.exe' );
  r := -1;
  i := http_reponse_code( r, s );
  if i <> 0 then
  begin
    m_wizard.show_validation_error( nil, 'A Problem has occurred while checking if waptagent exist on server' + #13#10 + 'Server installation may be broken, you could try reinstall waptserver' );
    exit(-1);
  end;

  if r = 200 then
  begin
    s := 'Waptagent has been found on the server.'+ #13#10#13#10;
    s := s + 'Rebuild and overwrite it ?';
    if mrNo = m_wizard.show_question( s, mbYesNo ) then
      exit(0);
  end
  else if r <> 404 then
  begin
    s := 'A Problem has occurred while checking if waptagent exist on server' + #13#10;
    s := 'Server installation may be broken, you could try reinstall waptserver';
    m_wizard.show_validation_error( nil, s );
    exit(-1);
  end;
  m_wizard.ClearValidationDescription();


  // Check there is no other inno setup process running
  if not wizard_validate_sys_no_innosetup_process( m_wizard ) then
    exit( -1 );

  building_init_ui( MSG_BUILDING, 100 );

  params_waptagent.default_public_cert       := fs_path_concat( 'ssl', package_certificate );
  params_waptagent.default_repo_url          := server_url + '/wapt';
  params_waptagent.default_wapt_server       := server_url;
  params_waptagent.destination               := GetTempDir(true);
  params_waptagent.company                   := '';
  params_waptagent.OnProgress                := @on_building_waptagent_tick;
  params_waptagent.WaptEdition               := 'waptagent';
  params_waptagent.VerifyCert                := UTF8Encode( verify_cert );
  params_waptagent.UseKerberos               := false;
  params_waptagent.CheckCertificatesValidity := true;
  params_waptagent.EnterpriseEdition         := m_data.B['is_enterprise_edition'];
  params_waptagent.OverwriteRepoURL          := true;
  params_waptagent.OverwriteWaptServerURL    := true;
  Build( 'Waptagent', @CreateSetupParams_waptagent, @params_waptagent, nil );

  if params_waptagent._result <> 0 then
  begin
    building_show_error( m_wizard, nil, params_waptagent._err_message );
    exit(-1);
  end;


  //
  building_init_ui( 'Uploading to server...', FileSize(params_waptagent._agent_filename) );
  s := 'ssl\server\' + UTF8Encode( m_data.S['server_certificate'] );
  if not FileExists(s) then
    s := '';
  try
    so := WAPTServerJsonMultipartFilePost(
      server_url,
      'upload_waptsetup',
      [],
      'file',
      params_waptagent._agent_filename,
      UTF8Encode(m_data.S['server_login']),
      UTF8Encode(m_data.S['server_password']),
      @on_workevent,
      s
      );
    if so.S['status'] <> 'OK' then
      Raise Exception.Create( UTF8Encode(so.S['message']) );
  except on Ex : Exception do
    begin
      building_show_error( m_wizard, nil, Ex.Message );
      exit(-1);
    end;
  end;

  m_wizard.SetValidationDescription( 'Deleting temp files');
  if not DeleteFile( params_waptagent._agent_filename ) then
  begin
    building_show_error( m_wizard, nil, 'An error has occured while deleting temp files');
    exit(-1);
  end;


////////////////////// Building waptupgrade
LBL_BUILD_WAPTUPGRADE:
  self.progress.Visible := false;
  self.lbl.Caption := 'Prepare building waptupgrade';


  // Check there is no other inno setup process running
  if not wizard_validate_sys_no_innosetup_process( m_wizard ) then
    exit( -1 );

  // Now building
  building_init_ui( MSG_BUILDING, 100 );
  params_waptupgrade.server_username := UTF8Encode( m_data.S['server_login'] );
  params_waptupgrade.server_password := UTF8Encode( m_data.S['server_password'] );
  params_waptupgrade.config_filename := IncludeTrailingBackslash(ExtractFileDir(AppIniFilename())) + 'waptconsole.ini';
  params_waptupgrade.dualsign        := false;
  params_waptupgrade.private_key_password := UTF8Encode( m_data.S['package_private_key_password'] );


  Build( 'waptupgrade', @CreateSetupParams_waptupgrade, @params_waptupgrade, nil);
  if params_waptupgrade._result <> 0 then
  begin
    building_show_error( m_wizard, nil, params_waptupgrade._err_message );
    exit(-1);
  end;


  exit(0);
end;





procedure TWizardStepFrameBuildAgent.on_building_waptagent_tick(sender: TObject );
begin
  Application.QueueAsyncCall( @tick, 0 );
end;

procedure TWizardStepFrameBuildAgent.tick(data: PtrInt);
const
  sz_setup : Real = 1024 * 1024 * 23.5;
var
  sz : Real;
  max : Real;
  f : String;
begin
  f := IncludeTrailingPathDelimiter( GetTempDir(true) )+ 'waptagent.exe';
  if not fs_path_exists( f ) then
    exit;
  max := self.progress.Max;
  sz := FileSize(f);
  sz := max * sz / sz_setup;
  if sz > 100 then
    sz := 100;
  self.progress.Position := Round(sz);
end;

procedure TWizardStepFrameBuildAgent.on_workevent(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64);
begin
  self.progress.Position := AWorkCount;
end;



procedure TWizardStepFrameBuildAgent.Build( const target : String; func : Pointer; data : Pointer; callback : Tnotifycallback );
var
  r : integer;
  j : integer;
  w : TThread;
  s : String;
  i : integer;
begin
  r := 0;
  j := 0;
  s := Format( MSG_BUILDING, [target] );
  lbl.Caption := s;
  w := TThread.ExecuteInThread( TThreadExecuteCallback(func), data, TNotifyCallBack(nil) );
  while not w.Finished do
  begin
    WaitForThreadTerminate( w.Handle, 33 ); // 30 FPS
    r := r + 33;
    if r > 330 then
    begin
      s := Format( MSG_BUILDING, [target] );
      r := 0;
      for i := 0 to j do
        s[Length(s)-2+i] := '.';
      lbl.Caption := s;
      inc(j);
      if j > 2 then
        j := -1;
    end;
    Application.ProcessMessages;
  end;
end;



procedure TWizardStepFrameBuildAgent.building_init_ui( const s : String; max : integer );
  begin
    progress.Visible := true;
    lbl.Caption := s;
    progress.Min := 0;
    progress.Max := max;
    progress.Position := 0;
    progress.Style := pbstNormal;
    Application.ProcessMessages;
  end;

    procedure TWizardStepFrameBuildAgent.building_show_error(w: TWizard; control: TControl; const msg: String);
  begin
    progress.Visible := false;
    w.show_validation_error( control, msg );
  end;






initialization

  RegisterClass(TWizardStepFrameBuildAgent);

end.

