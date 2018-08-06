unit uwizardconfigserver_console_buildagent;

{$mode objfpc}{$H+}

interface

uses
  IdComponent,
  uwizard,
  uwizardstepframe,
  PythonEngine,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, ComCtrls;

type



  { TWizardConfigServer_Console_BuildAgent }
  TWizardConfigServer_Console_BuildAgent = class( TWizardStepFrame )
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
    procedure on_python_update(Sender: TObject; PSelf, Args: PPyObject; var Result: PPyObject);

    // TWizardStepFrame
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;




  end;

implementation

uses
  superobject,
  dmwaptpython,
  uwapt_ini,
  waptcommon,
  dialogs,
  uwizardconfigserver_data,
  uwizardvalidattion,
  uwizardutil;

{$R *.lfm}

const
MSG_BUILDING : String = 'Building %s   ';


{ TWizardConfigServer_Console_BuildAgent }




procedure TWizardConfigServer_Console_BuildAgent.wizard_show();
begin
  inherited wizard_show();

  // Dont wait user to click on next to start
  // working
  m_wizard.click_next_async();

end;

procedure TWizardConfigServer_Console_BuildAgent.wizard_next( var bCanNext: boolean );
label
  LBL_BUILD_WAPTUPGRADE,
  LBL_BUILD_WAPTAGENT,
  LBL_SUCCESS;
var
  params_waptagent  : TCreateSetupParams_waptagent;
  params_waptupgrade: TCreateSetupParams_waptupgrade;
  so : ISuperObject;
  s : String;
  r : integer;
  i : integer;

  data : PWizardConfigServerData;


  old_pythonevent : TPythonEvent;
begin
  bCanNext :=  false;
  data := m_wizard.data();

  //
  r := data_write_ini_waptconsole( data, self.m_wizard );
  if r <> 0 then
    exit;

////////////////////// Building waptagent
LBL_BUILD_WAPTAGENT:
  progress.Visible := false;
  lbl.Caption := 'Prepare building waptagent';

  // Check if waptagent already exist on server
  m_wizard.SetValidationDescription( 'Checking if waptagent exist on server' );
  s := url_concat( data^.wapt_server, '/wapt/waptagent.exe' );
  r := -1;
  i := http_reponse_code( r, s );
  if i <> 0 then
  begin
    m_wizard.show_validation_error( nil, 'A Problem has occurred while checking if waptagent exist on server' + #13#10 + 'Server installation may be broken, you could try reinstall waptserver' );
    exit;
  end;

  if r = 200 then
  begin
    s := 'Waptagent has been found on the server.'+ #13#10#13#10;
    s := s + 'Rebuild and overwrite it ?';
    if mrNo = m_wizard.show_question( s, mbYesNo ) then
      goto LBL_SUCCESS;
  end
  else if r <> 404 then
  begin
    s := 'A Problem has occurred while checking if waptagent exist on server' + #13#10;
    s := 'Server installation may be broken, you could try reinstall waptserver';
    m_wizard.show_validation_error( nil, s );
    exit;
  end;
  m_wizard.ClearValidationDescription();


  // Check there is no other inno setup process running
  if not wizard_validate_sys_no_innosetup_process( m_wizard ) then
    exit;

  building_init_ui( MSG_BUILDING, 100 );

  params_waptagent.default_public_cert       := data^.package_certificate;
  params_waptagent.default_repo_url          := data^.wapt_server + '/wapt';
  params_waptagent.default_wapt_server       := data^.wapt_server;
  params_waptagent.destination               := GetTempDir(true);
  params_waptagent.company                   := '';
  params_waptagent.OnProgress                := @on_building_waptagent_tick;
  params_waptagent.WaptEdition               := 'waptagent';
  params_waptagent.VerifyCert                := data^.verify_cert;
  params_waptagent.UseKerberos               := false;
  params_waptagent.CheckCertificatesValidity := true;
  params_waptagent.EnterpriseEdition         := data^.is_enterprise_edition;
  params_waptagent.OverwriteRepoURL          := true;
  params_waptagent.OverwriteWaptServerURL    := true;
  Build( 'Waptagent', @CreateSetupParams_waptagent, @params_waptagent, nil );

  if params_waptagent._result <> 0 then
  begin
    building_show_error( m_wizard, nil, params_waptagent._err_message );
    self.m_wizard.show_error( params_waptagent._err_message );
    exit;
  end;


  //
  building_init_ui( 'Uploading to server...', FileSize(params_waptagent._agent_filename) );
  try
    so := WAPTServerJsonMultipartFilePost(
      data^.wapt_server,
      'upload_waptsetup',
      [],
      'file',
      params_waptagent._agent_filename,
      data^.wapt_user,
      data^.wapt_password,
      @on_workevent,
      ''
      );

    s := UTF8Encode( so.S['status'] );
    if s <> 'OK' then
    begin
      s := UTF8Encode( so.S['message'] );
      if Length(s) = 0 then
        s := UTF8Encode(so.AsJSon(false));
      Raise Exception.Create(s);
    end;
  except on Ex : Exception do
    begin
      building_show_error( m_wizard, nil, Ex.Message );
      exit;
    end;
  end;


  ////////////////////// Building waptupgrade
  LBL_BUILD_WAPTUPGRADE:
  self.progress.Visible := false;
  self.lbl.Caption := 'Prepare building waptupgrade';
  old_pythonevent := DMPython.PythonModuleDMWaptPython.Events.Items[1].OnExecute;
  DMPython.PythonModuleDMWaptPython.Events.Items[1].OnExecute := @on_python_update;


  // Check there is no other inno setup process running
  if not wizard_validate_sys_no_innosetup_process( m_wizard ) then
    exit;


  // Now building
  building_init_ui( MSG_BUILDING, 100 );
  r := wapt_ini_waptconsole( s );
  if r <> 0 then
  begin
    building_show_error( m_wizard, nil, 'configuration file waptconsole.ini have not been found, build cannot continue');
    exit;
  end;
  params_waptupgrade.server_username := data^.wapt_user;
  params_waptupgrade.server_password := data^.wapt_password;
  params_waptupgrade.config_filename := s;
  params_waptupgrade.dualsign        := false;
  params_waptupgrade.private_key_password := data^.package_private_key_password;
  Build( 'waptupgrade', @CreateSetupParams_waptupgrade, @params_waptupgrade, nil);
  if params_waptupgrade._result <> 0 then
  begin
    building_show_error( m_wizard, nil, params_waptupgrade._err_message );
    exit;
  end;
  DMPython.PythonModuleDMWaptPython.Events.Items[1].OnExecute := old_pythonevent;



  m_wizard.SetValidationDescription( 'Deleting temp files');
  if not DeleteFile( params_waptagent._agent_filename ) then
  begin
    building_show_error( m_wizard, nil, 'An error has occured while deleting temp files');
    exit;
  end;
  m_wizard.ClearValidationDescription();

LBL_SUCCESS:

  bCanNext:= true;
end;





procedure TWizardConfigServer_Console_BuildAgent.on_building_waptagent_tick(sender: TObject );
begin
  Application.QueueAsyncCall( @tick, 0 );
end;

procedure TWizardConfigServer_Console_BuildAgent.tick(data: PtrInt);
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

procedure TWizardConfigServer_Console_BuildAgent.on_workevent(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64);
begin
  self.progress.Position := AWorkCount;
end;



procedure TWizardConfigServer_Console_BuildAgent.Build( const target : String; func : Pointer; data : Pointer; callback : Tnotifycallback );
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
  m_wizard.TitleLabel.Caption := s;
  m_wizard.DescriptionLabel.Caption := '0 %';
  lbl.Caption := '';

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

      m_wizard.TitleLabel.Caption := s;
      m_wizard.DescriptionLabel.Caption := Format( '%s %%', [Inttostr( Round(Real(progress.Position) / Real(progress.Max) * 100.0) ) ] );
      inc(j);
      if j > 2 then
        j := -1;
    end;
    Application.ProcessMessages;
  end;
end;



procedure TWizardConfigServer_Console_BuildAgent.building_init_ui( const s : String; max : integer );
  begin
    progress.Visible := true;
    lbl.Caption := s;
    progress.Min := 0;
    progress.Max := max;
    progress.Position := 0;
    progress.Style := pbstNormal;
    Application.ProcessMessages;
  end;

procedure TWizardConfigServer_Console_BuildAgent.building_show_error(w: TWizard; control: TControl; const msg: String);
begin
  progress.Visible := false;
  w.show_validation_error( control, msg );
end;

procedure TWizardConfigServer_Console_BuildAgent.on_python_update(Sender: TObject; PSelf, Args: PPyObject; var Result: PPyObject);
begin
  Result:= DMPython.PythonEng.ReturnNone;
end;






initialization

  RegisterClass(TWizardConfigServer_Console_BuildAgent);

end.

