unit uvisconsolepostconf;

{$mode objfpc}{$H+}

interface

uses
  PythonEngine, Classes, SysUtils, FileUtil, LazFileUtils, LazUTF8, IpHtml,
  Forms, Controls, Graphics, Dialogs, ComCtrls, StdCtrls, ExtCtrls, Buttons,
  ActnList, IdHTTP, IdComponent, uvisLoading, DefaultTranslator, LCLTranslator,
  LCLProc, EditBtn, waptconsolepostconfres;

type

  { TVisWAPTConsolePostConf }

  TVisWAPTConsolePostConf = class(TForm)
    ActCheckDNS: TAction;
    ActCreateKey: TAction;
    ActCancel: TAction;
    ActBuildWaptsetup: TAction;
    actWriteConfStartServe: TAction;
    ActManual: TAction;
    ActNext: TAction;
    actPrevious: TAction;
    ActionList1: TActionList;
    ButCancel: TBitBtn;
    ButNext: TBitBtn;
    ButPrevious: TBitBtn;
    cbLaunchWaptConsoleOnExit: TCheckBox;
    cb_create_new_key_show_password: TCheckBox;
    cb_use_existing_key_show_password: TCheckBox;
    cb_wapt_server_show_password: TCheckBox;
    ed_package_prefix: TEdit;
    ed_wapt_server_password: TEdit;
    EdWAPTServerName: TEdit;
    ed_create_new_key_password_1: TEdit;
    ed_existing_key_certificat_filename: TFileNameEdit;
    ed_existing_key_password: TEdit;
    ed_create_new_key_password_2: TEdit;
    ed_create_new_key_key_name: TEdit;
    ed_create_new_key_private_directory: TDirectoryEdit;
    ed_existing_key_key_filename: TFileNameEdit;
    html_panel: TIpHtmlPanel;
    IdHTTP1: TIdHTTP;
    lbl_ed_package_prefix: TLabel;
    llb_wapt_server: TLabel;
    lbl_wapt_server_password: TLabel;
    lbl_ed_existing_key_password: TLabel;
    lbl_ed_existing_key_key_filename: TLabel;
    lbl_ed_create_new_key_directory: TLabel;
    lbl_ed_create_new_key_key_name: TLabel;
    lbl_ed_create_new_key_password_1: TLabel;
    lbl_ed_create_new_key_password_2: TLabel;
    lbl_ed_existing_key_cert_filename: TLabel;
    pg_agent_memo: TMemo;
    Memo7: TMemo;
    PagesControl: TPageControl;
    p_bottom: TPanel;
    Panel2: TPanel;
    panFinish: TPanel;
    pgParameters: TTabSheet;
    p_right: TPanel;
    ProgressBar1: TProgressBar;
    pgFinish: TTabSheet;
    pgKey: TTabSheet;
    pgBuildAgent: TTabSheet;
    rb_CreateKey: TRadioButton;
    rb_UseKey: TRadioButton;
    Splitter1: TSplitter;
    pgPackage: TTabSheet;
    procedure ActManualExecute(Sender: TObject);
    procedure ActNextExecute(Sender: TObject);
    procedure ActNextUpdate(Sender: TObject);
    procedure actPreviousExecute(Sender: TObject);
    procedure actPreviousUpdate(Sender: TObject);
    procedure ButCancelClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure html_panelHotClick(Sender: TObject);
    procedure IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64);
    procedure PagesControlChange(Sender: TObject);
    procedure on_private_key_radiobutton_change( Sender : TObject );
    procedure on_show_password_change( Sender : TObject );
    procedure on_create_setup_waptagent_tick( Sender : TObject );
    procedure on_upload( ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64 );
    procedure on_python_update(Sender: TObject; PSelf, Args: PPyObject; var Result: PPyObject);
    procedure p_rightClick(Sender: TObject);

  private
    m_skip_build_agent: boolean;

    CurrentVisLoading:TVisLoading;
    procedure OpenFirewall;
    { private declarations }

    procedure set_buttons_enable( enable : Boolean );
    procedure clear();
    procedure validate_page_parameters( var bContinue : boolean );
    procedure validate_page_package_name( var bContinue : boolean );
    procedure validate_page_package_key( var bContinue : boolean );
    procedure validate_page_agent( var bContinue : boolean );
    function  write_config( const package_certificate : String ) : integer;
    function  restart_waptservice_and_register() : integer;
    function  run_commands( const sl : TStrings ) : integer;

    procedure update_doc_html();
    function offset_language(): integer;
  public
    procedure show_validation_error( c : TControl; const msg : String );
  end;

var
  VisWAPTConsolePostConf: TVisWAPTConsolePostConf;

implementation

uses
  dmwaptpython,
  uutil,
  uvalidation,
  udefault,
  LCLIntf,
  Windows,
  waptcommon,
  waptwinutils,
  UScaleDPI,
  tisinifiles,
  superobject,
  tiscommon,
  IniFiles;

{$R *.lfm}



{ TVisWAPTConsolePostConf }

procedure TVisWAPTConsolePostConf.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96);
  //HTMLViewer1.DefFontSize := ScaleY(HTMLViewer1.DefFontSize,96);
  ReadWaptConfig(WaptBaseDir+'wapt-get.ini');
  PagesControl.ShowTabs:=False;
  PagesControl.ActivePageIndex:=0;


  self.clear();


  // fmor
//  self.PagesControl.PageIndex:= 3;

end;

procedure TVisWAPTConsolePostConf.FormShow(Sender: TObject);
begin
  EdWAPTServerName.Text:=LowerCase(GetComputerName)+'.'+GetDNSDomain;
  PagesControlChange(Self);
end;

procedure TVisWAPTConsolePostConf.html_panelHotClick(Sender: TObject);
var
  url : String;
begin
  url := self.html_panel.HotURL;
  if 0 = Length(url) then
    exit;
  OpenURL( url );
end;

procedure TVisWAPTConsolePostConf.IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64);
begin
  if CurrentVisLoading<>Nil then
    CurrentVisLoading.DoProgress(ASender)
  else
  begin
    if ProgressBar1.Position>=ProgressBar1.Max then
      ProgressBar1.Position:=0
    else
      ProgressBar1.Position := ProgressBar1.Position+1;
    Application.ProcessMessages;
  end;
end;

procedure TVisWAPTConsolePostConf.PagesControlChange(Sender: TObject);
var
  p : TTabSheet;
begin
  p := nil;

  // Update doc html
  self.update_doc_html();

  p := self.PagesControl.ActivePage;

  // Page specilic actions
  if pgBuildAgent = p then
  begin
    self.ButNext.Click;
  end;
end;

procedure TVisWAPTConsolePostConf.on_private_key_radiobutton_change( Sender: TObject);
var
  b : boolean;
begin
  // Enable
  b := self.rb_CreateKey.Checked;
  self.lbl_ed_create_new_key_directory.Enabled      := b;
  self.lbl_ed_create_new_key_key_name.Enabled       := b;
  self.lbl_ed_create_new_key_password_1.Enabled     := b;
  self.lbl_ed_create_new_key_password_2.Enabled     := b;
  self.ed_create_new_key_private_directory.Enabled  := b;
  self.ed_create_new_key_key_name.Enabled           := b;
  self.ed_create_new_key_password_1.Enabled         := b;
  self.ed_create_new_key_password_2.Enabled         := b;
  self.cb_create_new_key_show_password.Enabled      := b;

  b := not b;
  self.lbl_ed_existing_key_key_filename.Enabled     := b;
  self.lbl_ed_existing_key_cert_filename.Enabled    := b;
  self.lbl_ed_existing_key_password.Enabled         := b;
  self.ed_existing_key_key_filename.Enabled         := b;
  self.ed_existing_key_certificat_filename.Enabled  := b;
  self.ed_existing_key_password.Enabled             := b;
  self.cb_use_existing_key_show_password.Enabled    := b;

  // Taborder
  if self.rb_CreateKey.Checked then
  begin
    self.ed_package_prefix.TabOrder                   := 0;
    self.rb_CreateKey.TabOrder                        := 1;
    self.ed_create_new_key_private_directory.TabOrder := 2;
    self.ed_create_new_key_key_name.TabOrder          := 3;
    self.ed_create_new_key_password_1.TabOrder        := 4;
    self.ed_create_new_key_password_2.TabOrder        := 5;
  end
  else
  begin
    self.ed_package_prefix.TabOrder                   := 0;
    self.rb_UseKey.TabOrder                           := 1;
    self.ed_existing_key_key_filename.TabOrder        := 2;
    self.ed_existing_key_certificat_filename.TabOrder := 3;
    self.ed_existing_key_password.TabOrder            := 4;
  end;

  // Focus
  if self.Visible then
  begin
    if self.rb_CreateKey.Checked then
    begin
      if str_is_empty_when_trimmed(self.ed_create_new_key_password_2.Text) then
        self.ed_create_new_key_password_2.SetFocus;

      if str_is_empty_when_trimmed(self.ed_create_new_key_password_1.Text) then
        self.ed_create_new_key_password_1.SetFocus;

      if str_is_empty_when_trimmed(self.ed_create_new_key_key_name.Text) then
        self.ed_create_new_key_key_name.SetFocus;

      if str_is_empty_when_trimmed(self.ed_create_new_key_private_directory.Text) then
        self.ed_create_new_key_private_directory.SetFocus;
    end
    else
    begin
      if str_is_empty_when_trimmed(self.ed_existing_key_password.Text) then
        self.ed_existing_key_password.SetFocus;

      if str_is_empty_when_trimmed(self.ed_existing_key_certificat_filename.Text) then
        self.ed_existing_key_certificat_filename.SetFocus;

      if str_is_empty_when_trimmed(self.ed_existing_key_key_filename.Text) then
        self.ed_existing_key_key_filename.SetFocus;

    end;
  end;

end;

procedure TVisWAPTConsolePostConf.on_show_password_change( Sender: TObject);
var
  c : Char;
begin

  // Parameters
  if self.cb_wapt_server_show_password = Sender then
  begin
    if self.cb_wapt_server_show_password.Checked then
      c := #0
    else
      c := DEFAULT_PASSWORD_CHAR;
    self.ed_wapt_server_password.PasswordChar := c;
    exit;
  end;

  // Package create key
  if self.cb_create_new_key_show_password = Sender then
  begin
    if self.cb_create_new_key_show_password.Checked then
      c := #0
    else
      c := DEFAULT_PASSWORD_CHAR;
    self.ed_create_new_key_password_1.PasswordChar := c;
    self.ed_create_new_key_password_2.PasswordChar := c;
    exit;
  end;

  // Pacakge existing key
  if self.cb_use_existing_key_show_password = Sender then
  begin
    if self.cb_use_existing_key_show_password.Checked then
      c := #0
    else
      c := DEFAULT_PASSWORD_CHAR;
    self.ed_existing_key_password.PasswordChar := c;
    exit;
  end;

end;

procedure TVisWAPTConsolePostConf.on_create_setup_waptagent_tick(Sender: TObject );
var
  t : TRunReadPipeThread;
  sz : Real;
  max : Real;
  f : String;
begin
  if not Assigned(Sender) then
  begin
    Application.ProcessMessages;
    exit;
  end;

  t := TRunReadPipeThread(Sender);

  self.pg_agent_memo.Text:= t.Content;
  SendMessage(self.pg_agent_memo.Handle, EM_LINESCROLL, 0,self.pg_agent_memo.Lines.Count);

  f := IncludeTrailingPathDelimiter( GetTempDir(true) )+ 'waptagent.exe';
  if FileExists(f) then
  begin
    self.ProgressBar1.Position := FileSize(f);
  end;

  Application.ProcessMessages;
end;

procedure TVisWAPTConsolePostConf.on_upload(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64);
const
  WORK_FINISHED : integer = 62;
var
  l : integer;
  p : integer;
begin
  if self.pgBuildAgent = self.PagesControl.ActivePage then
  begin

    if WORK_FINISHED = AWorkCount then
    begin
      l := self.pg_agent_memo.Tag;
      self.pg_agent_memo.Lines[ l ] := Format( rs_upload_to_server, [100] );
      self.pg_agent_memo.Tag := 0;
      Application.ProcessMessages;
      exit;
    end;

    if self.pg_agent_memo.Tag = 0 then
    begin
      self.pg_agent_memo.Tag := self.pg_agent_memo.Lines.Count;
      self.pg_agent_memo.Append('');
      self.pg_agent_memo.Append('');
    end;
    l := self.pg_agent_memo.Tag;
    p := round(100 * AWorkCount / SETUP_AGENT_SIZE);
    self.pg_agent_memo.Lines[ l ] := Format( rs_upload_to_server, [p] );
    self.pg_agent_memo.Repaint;

    self.ProgressBar1.Position := SETUP_AGENT_SIZE + AWorkCount;
    Application.ProcessMessages;
  end;
end;

procedure TVisWAPTConsolePostConf.on_python_update(Sender: TObject; PSelf, Args: PPyObject; var Result: PPyObject);
begin
  Result:= DMPython.PythonEng.ReturnNone;
end;

procedure TVisWAPTConsolePostConf.p_rightClick(Sender: TObject);
begin

end;

procedure TVisWAPTConsolePostConf.OpenFirewall;
var
   output : String;
begin
  if GetServiceStatusByName('','SharedAccess') = ssRunning then
  begin
    output := Run('netsh firewall show portopening');
    if pos('waptserver 80',output)<=0 then
      Run(format('netsh.exe firewall add portopening name="waptserver %d" port=%d protocol=TCP',[waptserver_port,waptserver_port]));
    if pos('waptserver 443',output)<=0 then
      Run(format('netsh.exe firewall add portopening name="waptserver %d" port=%d protocol=TCP',[waptserver_sslport,waptserver_sslport]));
  end
  else if GetServiceStatusByName('','MpsSvc') = ssRunning then
  begin
    output:='';
    try
      output := Run(format('netsh advfirewall firewall show rule name="waptserver %d"',[waptserver_port]));
    except
    end;
    if pos('waptserver 80',output)<=0 then
      output := Run(format('netsh advfirewall firewall add rule name="waptserver %d" dir=in localport=%d protocol=TCP action=allow',[waptserver_port,waptserver_port]));
    try
      output := Run(format('netsh advfirewall firewall show rule name="waptserver %d"',[waptserver_sslport]));
    except
    end;
    if pos('waptserver 443',output)<=0 then
      output := Run(format('netsh advfirewall firewall add rule name="waptserver %d" dir=in localport=%d protocol=TCP action=allow',[waptserver_sslport,waptserver_sslport]));
  end;
end;

procedure TVisWAPTConsolePostConf.set_buttons_enable(enable: Boolean);
begin
  self.ButPrevious.Enabled := enable;
  self.ButNext.Enabled     := enable;
  self.ButCancel.Enabled   := enable;
end;

procedure TVisWAPTConsolePostConf.clear();
begin

  set_buttons_enable( true );

  self.m_skip_build_agent := false;

  // parameters
  self.EdWAPTServerName.Clear;
  self.ed_wapt_server_password.Clear;
  self.cb_wapt_server_show_password.Checked := false;
  self.on_show_password_change( self.cb_wapt_server_show_password );


  // Private key and certificate
  self.ed_package_prefix.Clear;
  self.ed_create_new_key_private_directory.Clear;
  self.ed_create_new_key_key_name.Clear;
  self.ed_create_new_key_password_1.Clear;
  self.ed_create_new_key_password_2.Clear;
  self.ed_existing_key_key_filename.Clear;
  self.ed_existing_key_certificat_filename.Clear;
  self.ed_existing_key_password.Clear;

  self.ed_create_new_key_password_1.PasswordChar  := DEFAULT_PASSWORD_CHAR;
  self.ed_create_new_key_password_2.PasswordChar  := DEFAULT_PASSWORD_CHAR;
  self.ed_existing_key_password.PasswordChar      := DEFAULT_PASSWORD_CHAR;
  self.cb_create_new_key_show_password.Checked    := false;
  self.cb_use_existing_key_show_password.Checked  := false;


  self.rb_CreateKey.Checked := true;
  self.on_private_key_radiobutton_change( nil );
  self.on_show_password_change( self.cb_create_new_key_show_password  );
  self.on_show_password_change( self.cb_use_existing_key_show_password  );

  self.ed_package_prefix.Text:= DEFAULT_PACKAGE_PREFIX;
  self.ed_create_new_key_private_directory.Text := DEFAULT_PRIVATE_KEY_DIRECTORY;

//  self.rb_UseKey.Checked :=;

end;

procedure TVisWAPTConsolePostConf.validate_page_parameters( var bContinue: boolean);
var
   url : String;
begin
  bContinue := false;

  if 0 = Length(Trim(self.EdWAPTServerName.Text)) then
  begin
    self.show_validation_error( self.EdWAPTServerName, rs_wapt_sever_url_is_invalid );
    exit;
  end;

  url := self.EdWAPTServerName.Text;

  if (Pos('http', url) = 0) and (Pos('https', url) = 0) then
    url := 'https://' + url;



  if not wizard_validate_waptserver_login( self, self.ed_wapt_server_password, url, 'admin', self.ed_wapt_server_password.Text ) then
    exit;

  self.EdWAPTServerName.Text := url;
  Application.ProcessMessages;


  bContinue := true;
end;

procedure TVisWAPTConsolePostConf.validate_page_package_name( var bContinue: boolean);
begin
  bContinue := false;

  if not wizard_validate_package_prefix( self, self.ed_package_prefix, self.ed_package_prefix.Text ) then
    exit;

  bContinue := true;
end;

procedure TVisWAPTConsolePostConf.validate_page_package_key( var bContinue: boolean);
var
   r                      : integer;
   msg                    : String;
   s                      : String;
   params                 : TCreate_signed_cert_params;
   package_certificate    : String;
begin

  bContinue := false;

  // Validate create key
  if self.rb_CreateKey.Checked then
  begin

    if not wizard_validate_waptserver_waptagent_is_not_present( self, nil, self.EdWAPTServerName.Text, r  ) then
    begin
      if HTTP_RESPONSE_CODE_OK <> r then
        exit;
      r := MessageDlg( Application.Name, rs_wapt_agent_has_been_found_on_server_confirm_create_package_key, mtConfirmation, mbYesNo, 0 );
      if mrNo = r then
        exit;
    end;


    if not DirectoryExists(self.ed_create_new_key_private_directory.Text) then
    begin
      msg := Format( rs_create_key_dir_not_exist, [self.ed_create_new_key_private_directory.Text] );
      r := MessageDlg( self.Name, msg,  mtConfirmation, mbYesNo, 0 );
      if mrNo = r then
      begin
        self.show_validation_error( self.ed_create_new_key_private_directory, rs_create_key_select_a_valide_private_key_directory );
        exit;
      end;

      if not CreateDir(self.ed_create_new_key_private_directory.Text ) then
      begin
        msg := Format( rs_create_key_dir_cannot_be_created, [self.ed_create_new_key_private_directory.Text] );
        self.show_validation_error( self.ed_create_new_key_private_directory, msg );
        exit;
      end;
    end;

    if not wizard_validate_key_name( self, self.ed_create_new_key_key_name, self.ed_create_new_key_key_name.Text ) then
      exit;

    s := IncludeTrailingBackslash(self.ed_create_new_key_private_directory.Text) + self.ed_create_new_key_key_name.Text + '.pem';
    if FileExists(s) then
    begin
      self.show_validation_error( self.ed_create_new_key_key_name, rs_create_key_a_key_with_this_name_exist );
      exit;
    end;

    s :=  IncludeTrailingBackslash(self.ed_create_new_key_private_directory.Text) + self.ed_create_new_key_key_name.Text + '.crt';
    if FileExists(s) then
    begin
      self.show_validation_error( self.ed_create_new_key_key_name, rs_create_key_a_certificat_this_key_name_exist );
      exit;
    end;

    if not wizard_validate_str_password_are_not_empty_and_equals( self, self.ed_create_new_key_password_2, self.ed_create_new_key_password_1.Text, self.ed_create_new_key_password_2.Text ) then
      exit;

    create_signed_cert_params_init( @params );
    params.destdir      := ExcludeTrailingPathDelimiter(self.ed_create_new_key_private_directory.Text);
    params.keypassword  := self.ed_create_new_key_password_1.Text;
    params.keyfilename  := IncludeTrailingPathDelimiter(self.ed_create_new_key_private_directory.Text) + self.ed_create_new_key_key_name.Text + '.' + EXTENSION_PRIVATE_KEY;
    params.commonname   := self.EdWAPTServerName.Text;

    r := create_signed_cert_params( @params );
    if r <> 0 then
    begin
      self.show_validation_error( nil, params._error_message );
      exit;
    end;

    package_certificate := params._certificate;
  end
  // Validate existing key
  else
  begin
    if str_is_empty_when_trimmed(self.ed_existing_key_key_filename.Text) then
    begin
      self.show_validation_error( self.ed_existing_key_key_filename, rs_key_filename_cannot_be_empty );
      exit;
    end;
    if str_is_empty_when_trimmed(self.ed_existing_key_certificat_filename.Text) then
    begin
      self.show_validation_error( self.ed_existing_key_certificat_filename, rs_certificate_filename_cannot_be_empty );
      exit;
    end;

    if not FileExists(self.ed_existing_key_key_filename.Text) then
    begin
      msg := Format( rs_key_filename_is_invalid, [self.ed_existing_key_key_filename.Text] );
      self.show_validation_error( self.ed_existing_key_key_filename, msg );
      exit;
    end;

    if not FileExists(self.ed_existing_key_certificat_filename.Text) then
    begin
      msg := Format( rs_certificate_filename_is_invalid, [self.ed_existing_key_certificat_filename] );
      self.show_validation_error( self.ed_existing_key_certificat_filename, msg );
      exit;
    end;

    if not wizard_validate_key_password( self, self.ed_existing_key_password, self.ed_existing_key_key_filename.Text, self.ed_existing_key_password.Text ) then
      exit;

    if not wizard_validate_waptserver_waptagent_is_not_present( self, nil, self.EdWAPTServerName.Text, r ) then
    begin
      if HTTP_RESPONSE_CODE_OK <> r then
        exit;
      r := MessageDlg( Application.Name, rs_wapt_agent_has_been_found_on_server_skip_build_agent, mtConfirmation, mbYesNo, 0 );
      self.m_skip_build_agent := mrYes = r;
    end;

    package_certificate := self.ed_existing_key_certificat_filename.Text;
  end;


  write_config( package_certificate );

  if self.m_skip_build_agent then
    self.PagesControl.ActivePage := self.pgFinish

  else if not wizard_validate_no_innosetup_process_running( self, self.ButNext ) then
    exit;

  bContinue := true;
end;

procedure TVisWAPTConsolePostConf.validate_page_agent(var bContinue: boolean);
label
  LBL_FAIL;
var
  params_agent  : Tcreate_setup_waptagent_params;
  r             : integer;
  so            : ISuperObject;
  s             : String;
  pe            : TPythonEvent;
  params_package: Tcreate_package_waptupgrade_params;
begin
  bContinue := false;


  self.ProgressBar1.Style := pbstNormal;
  self.ProgressBar1.Visible := true;
  self.pg_agent_memo.Clear;
  self.ProgressBar1.Position := 0;
  self.ProgressBar1.Max := SETUP_AGENT_SIZE * 3;
  Application.ProcessMessages;

  // Build agent
  create_setup_waptagent_params_init( @params_agent );

  params_agent.default_public_cert       := IniReadString( INI_FILE_WAPTCONSOLE, INI_GLOBAL, INI_PERSONAL_CERTIFICATE_PATH );
  params_agent.default_repo_url          := IniReadString( INI_FILE_WAPTCONSOLE, INI_GLOBAL, INI_REPO_URL );
  params_agent.default_wapt_server       := IniReadString( INI_FILE_WAPTCONSOLE, INI_GLOBAL, INI_WAPT_SERVER );
  params_agent.destination               := GetTempDir(true);
  params_agent.OnProgress                := @on_create_setup_waptagent_tick;

  r := create_setup_waptagent_params( @params_agent );
  if r <> 0 then
  begin
    self.show_validation_error( self.pg_agent_memo,  rs_compilation_failed );
    goto LBL_FAIL;
  end;
  self.ProgressBar1.Position := SETUP_AGENT_SIZE;
  Application.ProcessMessages;


  // Upload agent
  try
    so := WAPTServerJsonMultipartFilePost(
      params_agent.default_wapt_server,
      'upload_waptsetup',
      [],
      'file',
      params_agent._agent_filename,
      'admin',
      self.ed_wapt_server_password.Text,
      @on_upload,
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
      self.show_validation_error( nil, Ex.Message );
      self.ProgressBar1.Visible := false;
      exit;
    end;
  end;
  self.ProgressBar1.Position := SETUP_AGENT_SIZE * 2;

  // Build upload apt-upgrade
  if not wizard_validate_no_innosetup_process_running( self, nil ) then
    goto LBL_FAIL;

  pe :=  DMPython.PythonModuleDMWaptPython.Events.Items[1].OnExecute;
  DMPython.PythonModuleDMWaptPython.Events.Items[1].OnExecute := @on_python_update;


  params_package.server_username := 'admin';
  params_package.server_password := self.ed_wapt_server_password.Text;
  params_package.config_filename := INI_FILE_WAPTCONSOLE;
  params_package.dualsign        := false;
  if self.rb_CreateKey.Checked then
    params_package.private_key_password := self.ed_create_new_key_password_1.Text
  else
    params_package.private_key_password := self.ed_existing_key_password.Text;

  r := create_package_waptupgrade_params( @params_package );

  DMPython.PythonModuleDMWaptPython.Events.Items[1].OnExecute := pe;

  if r <> 0 then
  begin
    self.show_validation_error( nil, params_package._err_message );
    goto LBL_FAIL;
  end;
  self.ProgressBar1.Position :=  SETUP_AGENT_SIZE * 3;
  Application.ProcessMessages;
  Sleep( 2 * 1000 );


  self.ProgressBar1.Visible := false;
  bContinue := true;
  exit;

LBL_FAIL:
  self.ProgressBar1.Visible := false;
end;

function TVisWAPTConsolePostConf.write_config(const package_certificate: String ): integer;
var
   wapt_server : String;
   repo_url    : String;
   ini         : TIniFile;
   confs       : array of String;
   i           : integer;
   s           : String;
begin
  if 0 = Length(INI_FILE_WAPTCONSOLE) then
    exit(-1);
  if 0 = Length(INI_FILE_WAPTGET) then
    exit(-1);

  wapt_server := self.EdWAPTServerName.Text;
  repo_url    := wapt_server + '/wapt';

  SetLength( confs, 2 );
  confs[0] := INI_FILE_WAPTCONSOLE;
  confs[1] := INI_FILE_WAPTGET;

  for i:= 0 to Length(confs) -1  do
  begin
    result := -1;
    ini := TIniFile.Create( confs[i] );
    try
      ini.WriteString( INI_GLOBAL,        INI_DEFAULT_PACKAGE_PREFIX, self.ed_package_prefix.Text );
      ini.WriteString( INI_GLOBAL,        INI_PERSONAL_CERTIFICATE_PATH, package_certificate );
      ini.WriteString( INI_GLOBAL,        INI_WAPT_SERVER, wapt_server );
      ini.WriteString( INI_GLOBAL,        INI_REPO_URL, repo_url );
      ini.WriteString( INI_GLOBAL,        INI_CHECK_CERTIFICATES_VALIDITY, '0' );
      ini.WriteString( INI_GLOBAL,        INI_VERIFIY_CERT, '0' );
      ini.WriteString( INI_WAPTTEMPLATES, INI_REPO_URL, INI_WAPT_STORE_URL );
      ini.WriteString( INI_WAPTTEMPLATES, INI_VERIFIY_CERT, '1' );
      result := 0;
    finally
      ini.Free;
    end;
  end;

  // Copy certificate to
  s := IncludeTrailingPathDelimiter( WaptBaseDir ) + 'ssl' + PathDelim + ExtractFileName(package_certificate);
  if not FileUtil.CopyFile( package_certificate, s, false , false  ) then
    result := -1;

end;

function TVisWAPTConsolePostConf.restart_waptservice_and_register(): integer;
var
   waptget : String;
   sl : TStringList;
   r : integer;
begin
  waptget := IncludeTrailingPathDelimiter(WaptBaseDir) + 'wapt-get.exe';
  waptget := Format( '%s --wapt-server-user=admin --wapt-server-passwd=%s', [waptget, self.ed_wapt_server_password.Text] );


  sl := TStringList.Create;
  sl.Append( 'net stop  waptservice' );
  sl.Append( waptget + ' --direct register' );
  sl.Append( 'net start waptservice' );
  sl.Append( waptget + ' update' );


  r := run_commands( sl );
  sl.Free;

  exit(r);
end;

function TVisWAPTConsolePostConf.run_commands(const sl: TStrings): integer;
var
  i : integer;
  m : integer;
begin
  m := sl.Count;

  self.ProgressBar1.Visible := true;
  self.ProgressBar1.Position:= 0;
  self.ProgressBar1.Max := m;
  Application.ProcessMessages;

  dec(m);

  for i := 0 to m do
  begin
    self.ProgressBar1.Position := i + 1;
    Application.ProcessMessages;
    try
      Run( UTF8Decode(sl.Strings[i]) );
      result := 0;
    except on E : Exception do
      begin
        self.show_validation_error( nil, e.Message );
        result := -1;
        break;
      end;
    end;
  end;

  self.ProgressBar1.Visible := false;
  Application.ProcessMessages;
end;

procedure TVisWAPTConsolePostConf.update_doc_html();
label
  LBL_NO_DOC;
var
  p           : TTabSheet;
  str_index   : integer;
  buffer      : LPWSTR;
  r           : integer;
begin

  p := self.PagesControl.ActivePage;

  if pgParameters = p then
    str_index := 0
  else if pgPackage = p then
    str_index := 300
  else if pgKey = p then
    str_index := 200
  else if pgBuildAgent = p then
    str_index := 500
  else if pgFinish = p then
    str_index := 600
  else
    goto LBL_NO_DOC;


  buffer := nil;
  inc( str_index, offset_language() );
  r := Windows.LoadStringW( HINSTANCE(), str_index, @buffer, 0 );

  if r < 1 then
    goto LBL_NO_DOC;

  html_panel.SetHtmlFromStr( buffer );
  exit;

LBL_NO_DOC:
  html_panel.SetHtmlFromStr( HTML_NO_DOC );
end;






procedure TVisWAPTConsolePostConf.show_validation_error(c: TControl; const msg: String);
begin
  MessageDlg( self.Caption, msg,  mtError, [mbOK], 0 );
  if c is TWinControl and  TWinControl(c).Enabled then
    TWinControl(c).SetFocus;
end;

procedure TVisWAPTConsolePostConf.ActNextExecute(Sender: TObject);
label
  LBL_FAIL;
var
  bContinue : Boolean;
  p         : TTabSheet;
begin
  bContinue := false;

  set_buttons_enable( false );

  p := self.PagesControl.ActivePage;

  if pgParameters = p then
  begin
    self.validate_page_parameters( bContinue );
    if not bContinue then
      goto LBL_FAIL;
  end

  else if pgPackage = p then
  begin
    self.validate_page_package_name( bContinue );
    if not bContinue then
      goto LBL_FAIL;
  end

  else if pgKey = p then
  begin
    self.validate_page_package_key( bContinue );
    if not bContinue then
      goto LBL_FAIL;
  end

  else if pgBuildAgent = p then
  begin
    self.validate_page_agent(bContinue);
    if not bContinue then
      goto LBL_FAIL;
  end

  else if pgFinish = p then
  begin
    if cbLaunchWaptConsoleOnExit.Checked then
      launch_console();
    ExitProcess(0);
  end;


  self.PagesControl.ActivePageIndex := self.PagesControl.ActivePageIndex + 1;
  self.PagesControlChange(nil);
  set_buttons_enable( true );
  exit;

LBL_FAIL:
  set_buttons_enable( true );
end;

procedure TVisWAPTConsolePostConf.ActNextUpdate(Sender: TObject);
var
  ts : TTabSheet;
begin
  ts := self.PagesControl.Pages[ self.PagesControl.PageIndex ];

  if pgFinish = ts then
  begin
    actPrevious.Enabled := false;
    ActNext.Caption:= rsWaptSetupDone;
    exit;
  end;

  ActNext.Caption := rsWaptSetupnext;
end;

procedure TVisWAPTConsolePostConf.actPreviousExecute(Sender: TObject);
begin
  PagesControl.ActivePageIndex := PagesControl.ActivePageIndex - 1;
  self.PagesControlChange( nil );
end;

procedure TVisWAPTConsolePostConf.actPreviousUpdate(Sender: TObject);
begin
  actPrevious.Enabled:=(PagesControl.ActivePageIndex>0) and (PagesControl.ActivePageIndex<=PagesControl.PageCount-1);
end;



procedure TVisWAPTConsolePostConf.ButCancelClick(Sender: TObject);
begin
  if MessageDlg(rsConfirm,rsConfirmCancelPostConfig,mtConfirmation,mbYesNoCancel,0) = mrYes then
    Close;
end;

procedure TVisWAPTConsolePostConf.ActManualExecute(Sender: TObject);
begin
  ActManual.Checked := not ActManual.Checked;
end;


function TVisWAPTConsolePostConf.offset_language(): integer;
const
  PAGES_EN_OFFSET : integer =	0;
  PAGES_FR_OFFSET : integer =	1;
  PAGES_DE_OFFSET : integer =	2;
var
  Lang, FallbackLang: String;
  i : Integer;
begin
  { XXX This is not what I'd call clean language detection... }
  result := PAGES_EN_OFFSET;

  LazGetLanguageIDs(Lang, FallbackLang);
  if FallbackLang = 'fr' then
    result := PAGES_FR_OFFSET
  else if FallbackLang = 'de' then
    result := PAGES_DE_OFFSET;

  for i := 1 to ParamCount-1 do
  if ((ParamStr(i) = '-l') or (ParamStr(i) = '--lang')) and (i+1 <> ParamCount-1) then
  begin
    if ParamStr(i+1) = 'de' then
       result := PAGES_DE_OFFSET
    else
    if ParamStr(i+1) = 'fr' then
       result := PAGES_FR_OFFSET
    else
      result := PAGES_EN_OFFSET;
  end;
end;

end.

