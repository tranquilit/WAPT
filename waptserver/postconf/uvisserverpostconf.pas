unit uVisServerPostconf;

{$mode objfpc}{$H+}

interface

uses
  PythonEngine, Classes, SysUtils, FileUtil, LazFileUtils, LazUTF8, IpHtml,
  Forms, Controls, Graphics, Dialogs, ComCtrls, StdCtrls, ExtCtrls, Buttons,
  ActnList, IdHTTP, IdComponent, uvisLoading,
  DefaultTranslator, LCLTranslator, LCLProc, EditBtn, Menus, uWaptServerRes;

type

  { TVisWAPTServerPostConf }

  TVisWAPTServerPostConf = class(TForm)
    ActCheckDNS: TAction;
    ActCreateKey: TAction;
    ActCancel: TAction;
    ActBuildWaptsetup: TAction;
    ActionFindPrivateKey: TAction;
    actWriteConfStartServe: TAction;
    ActManual: TAction;
    ActNext: TAction;
    ActPrevious: TAction;
    ActionList1: TActionList;
    btn_check_dns_name: TBitBtn;
    btn_start_waptserver: TBitBtn;
    ButCancel: TBitBtn;
    ButNext: TBitBtn;
    ButPrevious: TBitBtn;
    btn_find_private_key: TButton;
    cbLaunchWaptConsoleOnExit: TCheckBox;
    CBOpenFirewall: TCheckBox;
    cb_configure_console_launch_console_on_exit: TCheckBox;
    cb_create_new_key_show_password: TCheckBox;
    cb_use_existing_key_show_password: TCheckBox;
    EdPwd1: TEdit;
    EdPwd2: TEdit;
    EdWaptServerIP: TEdit;
    EdWAPTServerName: TEdit;
    ed_create_new_key_key_name: TEdit;
    ed_create_new_key_password_1: TEdit;
    ed_create_new_key_password_2: TEdit;
    ed_create_new_key_private_directory: TDirectoryEdit;
    ed_existing_key_certificat_filename: TFileNameEdit;
    ed_existing_key_key_filename: TFileNameEdit;
    ed_existing_key_password: TEdit;
    ed_package_prefix: TEdit;
    html_panel: TIpHtmlPanel;
    lbl_ed_create_new_key_directory: TLabel;
    lbl_ed_create_new_key_key_name: TLabel;
    lbl_ed_create_new_key_password_1: TLabel;
    lbl_ed_create_new_key_password_2: TLabel;
    lbl_ed_existing_key_cert_filename: TLabel;
    lbl_ed_existing_key_key_filename: TLabel;
    lbl_ed_existing_key_password: TLabel;
    lbl_ed_package_prefix: TLabel;
    lbl_wapt_server_password_1: TLabel;
    lbl_wapt_server_password_2: TLabel;
    MainMenu1: TMainMenu;
    Panel1: TPanel;
    Panel3: TPanel;
    pg_package_key_page: TPageControl;
    PagesControl: TPageControl;
    Panel2: TPanel;
    panFinish: TPanel;
    pgBuildAgent: TTabSheet;
    pgConfigureConsoleOrFinish: TTabSheet;
    pgFinish: TTabSheet;
    pgPackageKey: TTabSheet;
    pgPackageName: TTabSheet;
    pgParameters: TTabSheet;
    pgPassword: TTabSheet;
    pgStartServices: TTabSheet;
    pg_agent_memo: TMemo;
    p_center: TPanel;
    p_right: TPanel;
    p_bottom: TPanel;
    ProgressBar1: TProgressBar;
    rb_configure_console_continue: TRadioButton;
    rb_configure_console_finish: TRadioButton;
    rb_CreateKey: TRadioButton;
    rb_UseKey: TRadioButton;
    sb_center: TScrollBox;
    Splitter1: TSplitter;
    pg_package_key_page_new_key: TTabSheet;
    pg_package_key_page_existing_key: TTabSheet;
    procedure ActCancelExecute(Sender: TObject);
    procedure ActCheckDNSExecute(Sender: TObject);
    procedure ActionFindPrivateKeyExecute(Sender: TObject);
    procedure ActManualExecute(Sender: TObject);
    procedure ActNextExecute(Sender: TObject);
    procedure ActNextUpdate(Sender: TObject);
    procedure ActPreviousExecute(Sender: TObject);
    procedure ActPreviousUpdate(Sender: TObject);
    procedure actWriteConfStartServeExecute(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure html_panelHotClick(Sender: TObject);
    procedure IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64);
    procedure on_private_key_radiobutton_change( Sender : TObject );
    procedure on_show_password_change( Sender : TObject );
    procedure on_create_setup_waptagent_tick( Sender : TObject );
    procedure on_upload( ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64 );
    procedure on_python_update(Sender: TObject; PSelf, Args: PPyObject; var Result: PPyObject);
    procedure on_configure_console_radiobutton_change(Sender : TObject );
    procedure on_accept_filename( Sender : TObject; var Value: String);
    procedure on_page_show( Sender : TObject );
    procedure on_key_press( Sender: TObject;  var Key: char);
    procedure async( data : PtrInt );
  private
    m_need_restart_waptserver : boolean;
    m_has_waptservice_installed : boolean;
    m_language_offset : integer;
    CurrentVisLoading:TVisLoading;
    procedure OpenFirewall;
    { private declarations }

    procedure set_buttons_enable( enable : Boolean );
    procedure clear();
    procedure load_config_if_exist();
    procedure validate_page_parameters( var bContinue : boolean );
    procedure validate_page_password( var bContinue : boolean );
    procedure validate_page_packge_name( var bContinue : boolean );
    procedure validate_page_package_key( var bContinue : boolean );
    procedure validate_page_agent( var bContinue : boolean );
    function  write_configs( const package_certificate : String ) : integer;
    function  restart_waptservice_and_register() : integer;
    function  run_commands( const sl : TStrings ) : integer;
    procedure update_doc_html();
  public
    procedure show_validation_error( c : TControl; const msg : String );
  end;

var
  VisWAPTServerPostConf: TVisWAPTServerPostConf;

implementation

uses
  dmwaptpython,
  uutil,
  uvalidation,
  udefault,
  LCLIntf, Windows, waptcommon, waptwinutils, tisinifiles,
  superobject, tiscommon, tisstrings, IniFiles,DCPsha256,dcpcrypt2,DCPbase64,Math;

{$R *.lfm}

const
  ASYNC_FOCUS_BTN_CHECKDNS : integer = 0;
  ASYNC_CLICK_NEXT         : integer = 1;
{ TVisWAPTServerPostConf }

procedure TVisWAPTServerPostConf.FormCreate(Sender: TObject);
begin
  preload_python(nil);

  // Page control
  self.PagesControl.ShowTabs:=False;
  self.pg_package_key_page.ShowTabs := false;
  remove_page_control_border( self.PagesControl.Handle );
  remove_page_control_border( self.pg_package_key_page.Handle );

  ReadWaptConfig( WaptBaseDir + 'wapt-get.ini' );


  self.clear();
  self.load_config_if_exist();

  self.PagesControl.ActivePageIndex := 0;
end;


procedure TVisWAPTServerPostConf.html_panelHotClick(Sender: TObject);
var
  url : String;
begin
  url := self.html_panel.HotURL;
  if 0 = Length(url) then
    exit;
  OpenURL( url );
end;


procedure TVisWAPTServerPostConf.IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64);
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

function GetString(const Index: integer) : string;
var
  buffer : array[0..8191] of char;
  ls : integer;
begin
  Result := '';
  ls := LoadString(hInstance,
                   Index,
                   buffer,
                   sizeof(buffer));
  if ls <> 0 then Result := buffer;
end;





procedure TVisWAPTServerPostConf.on_private_key_radiobutton_change( Sender: TObject);
var
  b : boolean;
begin

  b := self.rb_CreateKey.Checked;

  if b then
    self.pg_package_key_page.TabIndex := self.pg_package_key_page_new_key.TabIndex
  else
    self.pg_package_key_page.TabIndex := self.pg_package_key_page_existing_key.TabIndex;


  // Enable
  self.lbl_ed_create_new_key_directory.Enabled      := b;
  self.lbl_ed_create_new_key_key_name.Enabled       := b;
  self.lbl_ed_create_new_key_password_1.Enabled     := b;
  self.lbl_ed_create_new_key_password_2.Enabled     := b;
  self.ed_create_new_key_private_directory.Enabled  := b;
  self.ed_create_new_key_key_name.Enabled           := b;
  self.ed_create_new_key_password_1.Enabled         := b;
  self.ed_create_new_key_password_2.Enabled         := b;
  self.cb_create_new_key_show_password.Enabled      := b;

  self.ed_create_new_key_private_directory.TabStop  := b;
  self.ed_create_new_key_key_name.TabStop           := b;
  self.ed_create_new_key_password_1.TabStop         := b;
  self.ed_create_new_key_password_2.TabStop         := b;



  b := not b;
  self.lbl_ed_existing_key_key_filename.Enabled     := b;
  self.lbl_ed_existing_key_cert_filename.Enabled    := b;
  self.lbl_ed_existing_key_password.Enabled         := b;
  self.ed_existing_key_key_filename.Enabled         := b;
  self.ed_existing_key_certificat_filename.Enabled  := b;
  self.ed_existing_key_password.Enabled             := b;
  self.cb_use_existing_key_show_password.Enabled    := b;

  self.ed_existing_key_key_filename.TabStop         := b;
  self.ed_existing_key_certificat_filename.TabStop  := b;
  self.ed_existing_key_password.TabStop             := b;


  // Focus
  if not self.Visible then
    exit;

  if self.rb_CreateKey.Checked then
  begin
    if str_is_empty_when_trimmed(self.ed_create_new_key_password_2.Text) then
      set_focus_if_visible( self.ed_create_new_key_password_2 );

    if str_is_empty_when_trimmed(self.ed_create_new_key_password_1.Text) then
      set_focus_if_visible( self.ed_create_new_key_password_1 );

    if str_is_empty_when_trimmed(self.ed_create_new_key_key_name.Text) then
      set_focus_if_visible( self.ed_create_new_key_key_name );

    if str_is_empty_when_trimmed(self.ed_create_new_key_private_directory.Text) then
      set_focus_if_visible( self.ed_create_new_key_private_directory );
  end
  else
  begin
    if str_is_empty_when_trimmed(self.ed_existing_key_password.Text) then
      set_focus_if_visible( self.ed_existing_key_password );

    if str_is_empty_when_trimmed(self.ed_existing_key_certificat_filename.Text) then
      set_focus_if_visible( self.ed_existing_key_certificat_filename );

    if str_is_empty_when_trimmed(self.ed_existing_key_key_filename.Text) then
      set_focus_if_visible( self.ed_existing_key_key_filename );

  end;

end;

procedure TVisWAPTServerPostConf.on_show_password_change( Sender: TObject);
var
  c : Char;
begin
  if self.rb_CreateKey.Enabled then
  begin
    if self.cb_create_new_key_show_password.Checked then
      c := #0
    else
      c := DEFAULT_PASSWORD_CHAR;
    self.ed_create_new_key_password_1.PasswordChar := c;
    self.ed_create_new_key_password_2.PasswordChar := c;
  end;

  if self.cb_use_existing_key_show_password.Checked then
    c := #0
  else
    c := DEFAULT_PASSWORD_CHAR;
  self.ed_existing_key_password.PasswordChar := c;

end;

procedure TVisWAPTServerPostConf.on_create_setup_waptagent_tick(Sender: TObject );
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

procedure TVisWAPTServerPostConf.on_upload(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64);
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

procedure TVisWAPTServerPostConf.on_python_update(Sender: TObject; PSelf, Args: PPyObject; var Result: PPyObject);
begin
  Result:= DMPython.PythonEng.ReturnNone;
end;

procedure TVisWAPTServerPostConf.on_configure_console_radiobutton_change( Sender: TObject);
var
  b : boolean;
begin
  b := self.rb_configure_console_continue.Checked;


  b := not b;

  self.cb_configure_console_launch_console_on_exit.Enabled := b;
  self.cb_configure_console_launch_console_on_exit.TabStop := b;

  if b then
    self.ButNext.Caption := rsWaptSetupDone
  else
    self.ButNext.Caption := rsWaptSetupNext;


end;

procedure TVisWAPTServerPostConf.on_accept_filename(Sender: TObject; var Value: String);
var
  e1 : TFileNameEdit;
  e2 : TFileNameEdit;
  p : String;
begin
  if self.ed_existing_key_key_filename = Sender then
  begin
    e1 := self.ed_existing_key_key_filename;
    e2 := self.ed_existing_key_certificat_filename;
  end
  else
  begin
    e1 := self.ed_existing_key_certificat_filename;
    e2 := self.ed_existing_key_key_filename;
  end;

  p := ExtractFilePath(Value);
  e1.InitialDir := p;

  if FileExists(e2.Text) then
    e2.InitialDir := ExtractFilePath(e2.Text)
  else
    e2.InitialDir := e1.InitialDir;
end;

procedure TVisWAPTServerPostConf.on_page_show(Sender: TObject);
var
  p : TTabSheet;
begin
  p := self.PagesControl.ActivePage;

  set_buttons_enable( true );

  self.update_doc_html();

  if pgParameters = p then
  begin
    Application.QueueAsyncCall( @async, ASYNC_FOCUS_BTN_CHECKDNS  );
    self.ActPrevious.Enabled := false;
  end

  else if pgPassword = p then
  begin
    set_focus_if_visible( self.EdPwd1 );
  end

  else if pgStartServices = p then
  begin
    set_focus_if_visible( self.btn_start_waptserver );
  end

  else if pgConfigureConsoleOrFinish = p then
  begin
    set_focus_if_visible( self.rb_configure_console_continue );
  end

  else if pgPackageName = p then
  begin
    set_focus_if_visible( self.ed_package_prefix );
  end

  else if pgPackageKey = p then
  begin
    if self.rb_CreateKey.Checked then
    begin
      set_focus_if_visible( self.ed_create_new_key_key_name );
    end
    else if self.rb_UseKey.Checked then
    begin
      set_focus_if_visible( self.ed_existing_key_password );
    end;
  end

  else if pgBuildAgent = p then
  begin
    set_focus_if_visible( self.pg_agent_memo );
    Application.QueueAsyncCall( @async, ASYNC_CLICK_NEXT  );
  end
  else if pgFinish = p then
  begin
    self.ActPrevious.Enabled  := False;
    self.ActCancel.Enabled    := False;
    set_focus_if_visible( self.cb_configure_console_launch_console_on_exit );
  end;


end;

procedure TVisWAPTServerPostConf.on_key_press(Sender: TObject; var Key: char);
var
  r :integer;
begin

  if not (VK_RETURN = Integer(Key)) then
    exit;

  if self.EdWAPTServerName = Sender then
  begin
    self.ActCheckDNS.Execute;
    exit;
  end;

  if self.ed_existing_key_password = Sender then
  begin
    r := Length(self.ed_existing_key_key_filename.Text);
    if 0 = r then
    begin
      self.ActionFindPrivateKey.Execute;
      if not FileExists(self.ed_existing_key_key_filename.Text) then
        exit;
    end;
  end;


  self.ActNext.Execute;
end;

procedure TVisWAPTServerPostConf.async(data: PtrInt);
var
  i : integer;
begin
  i := Integer(data);
  if ASYNC_FOCUS_BTN_CHECKDNS = i then
    set_focus_if_visible( self.btn_check_dns_name )

  else if ASYNC_CLICK_NEXT = i then
    self.ActNext.Execute;


end;



procedure TVisWAPTServerPostConf.OpenFirewall;
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

procedure TVisWAPTServerPostConf.set_buttons_enable(enable: Boolean);
begin
  self.ActPrevious.Enabled := enable;
  self.ActNext.Enabled     := enable;
  self.ActCancel.Enabled   := enable;
end;

procedure TVisWAPTServerPostConf.clear();
var
   r : integer;
begin

  set_buttons_enable( true );


  r := srv_exist( m_has_waptservice_installed, WAPT_SERVICE_WAPTSERVICE );
  if r <> 0 then
    m_has_waptservice_installed := false;

  // pgParameters;
  self.EdWAPTServerName.Text:= LowerCase(GetComputerName)+'.'+GetDNSDomain;

  // Start
  m_need_restart_waptserver := true;

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


  self.rb_configure_console_continue.Checked := true;
  self.on_configure_console_radiobutton_change( nil );


  self.rb_CreateKey.Checked := true;
  self.on_private_key_radiobutton_change( nil );
  self.on_show_password_change( nil );

  self.ed_package_prefix.Text:= DEFAULT_PACKAGE_PREFIX;
  self.ed_create_new_key_private_directory.Text := DEFAULT_PRIVATE_KEY_DIRECTORY;


  self.ed_existing_key_key_filename.Filter := FILE_FILTER_PRIVATE_KEY;
  self.ed_existing_key_certificat_filename.Filter := FILE_FILTER_CERTIFICATE;

  self.ed_existing_key_key_filename.DialogOptions := self.ed_existing_key_key_filename.DialogOptions + [ofFileMustExist];
  self.ed_existing_key_certificat_filename.DialogOptions :=  self.ed_existing_key_certificat_filename.DialogOptions + [ofFileMustExist];


  self.m_language_offset := offset_language();


  self.ActPrevious.Enabled := true;
  self.ActCancel.Enabled   := true;
  self.ActNext.Enabled     := true;

end;

procedure TVisWAPTServerPostConf.load_config_if_exist();
var
  s       : String;
  i       : integer;
  j       : integer;
  configs : array of String;
  ini     : TIniFile;
  r       : integer;
  l       : integer;
  proto   : String;
begin
  ini := nil;

  SetLength( configs, 2 );
  configs[0] := INI_FILE_WAPTCONSOLE;
  configs[1] := INI_FILE_WAPTGET;

  for i := 0 to Length(configs) - 1 do
  begin
    if not FileExists( configs[i] ) then
      continue;
    ini := TIniFile.Create( configs[i] );

    s := ini.ReadString( INI_GLOBAL, INI_WAPT_SERVER, self.EdWAPTServerName.Text );
    for j := 0 to Length(WAPT_PROTOCOLS) -1 do
    begin
      proto := WAPT_PROTOCOLS[j] +'://';
      r := Pos( proto , s );
      if r = 0 then
        continue;
      l := Length(proto);
      s := Copy( s , r + l, Length(s) - r - l +1  );
      break;
    end;
    self.EdWAPTServerName.Text := s;


    self.ed_package_prefix.Text:= ini.ReadString( INI_GLOBAL, INI_DEFAULT_PACKAGE_PREFIX, self.ed_package_prefix.Text );




    self.ed_existing_key_certificat_filename.Text := ini.ReadString( INI_GLOBAL, INI_PERSONAL_CERTIFICATE_PATH, self.ed_existing_key_certificat_filename.Text );
    if Length( Trim(self.ed_existing_key_certificat_filename.Text) ) = 0 then
    begin
      self.rb_CreateKey.Checked := true;
      self.on_private_key_radiobutton_change( self.rb_CreateKey );
    end
    else
    begin
      self.ed_create_new_key_private_directory.Text := ExtractFilePath(self.ed_existing_key_certificat_filename.Text);
      self.ed_existing_key_key_filename.Text := ExtractFileNameWithoutExt(self.ed_existing_key_certificat_filename.Text) + '.' + EXTENSION_PRIVATE_KEY;
      self.rb_UseKey.Checked := true;
      self.on_private_key_radiobutton_change( self.rb_UseKey );
    end;

    ini.Free;
    ini := nil;
  end;

  if Assigned(ini) then
    ini.Free;

end;

procedure TVisWAPTServerPostConf.validate_page_parameters(var bContinue: boolean );
begin
  bContinue := true;
end;



procedure TVisWAPTServerPostConf.validate_page_password(var bContinue: boolean);
const
  VERSION_MINIMAL : String =   '1.4.0.0';
var
  r   : integer;
  v   : String;
  msg : String;
  ini : TIniFile;
begin
  bContinue := false;

  if not wizard_validate_password( self, self.EdPwd1, self.EdPwd1.Text ) then
    exit;

  if not (self.EdPwd1.Text = self.EdPwd2.Text) then
  begin
    self.show_validation_error( self.EdPwd2, rs_supplied_passwords_differs );
    exit;
  end;

  r := wapt_server_agent_version( v, self.EdWaptServerIP.Text , 'admin', self.EdPwd1.Text );
  if r = 0 then
  begin
    if CompareVersion( VERSION_MINIMAL, v ) > 0 then
    begin
      msg := Format( rs_you_wapt_agent_version_mismatch, [v] );
      self.show_validation_error( self.EdWaptServerIP, msg );
      exit;
    end;
  end;



  ini := TIniFile.Create( INI_FILE_WAPTGET ); 
  try
      ini.WriteString( INI_GLOBAL,        INI_WAPT_SERVER, 'https://' + self.EdWaptServerIP.Text );
      ini.WriteString( INI_GLOBAL,        INI_REPO_URL,    'https://' + self.EdWaptServerIP.Text + '/wapt' );
  finally
    ini.Free;
  end;      
 
  bContinue := true;
end;

procedure TVisWAPTServerPostConf.validate_page_packge_name( var bContinue: boolean);
begin
  bContinue := false;

  // Validate package name
  if not wizard_validate_package_prefix( self, self.ed_package_prefix, self.ed_package_prefix.Text ) then
    exit;

  bContinue := true;

end;

procedure TVisWAPTServerPostConf.validate_page_package_key(
  var bContinue: boolean);
var
   r    : integer;
   msg  : String;
   s    : String;
   params : TCreate_signed_cert_params;
   package_certificate : String;
   b    : boolean;
begin

  bContinue := false;


  // Validate create key
  if self.rb_CreateKey.Checked then
  begin
    if not DirectoryExists(self.ed_create_new_key_private_directory.Text) then
    begin
      msg := Format( rs_create_key_dir_not_exist, [self.ed_create_new_key_private_directory.Text] );
      r := MessageDlg( self.Name, msg,  mtConfirmation, mbYesNoCancel, 0 );
      if mrCancel = r then
        exit;

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

    if not wizard_validate_password( self, self.ed_create_new_key_password_1, self.ed_create_new_key_password_1.Text ) then
      exit;

    if not (self.ed_create_new_key_password_1.Text = self.ed_create_new_key_password_2.Text) then
    begin
      self.show_validation_error( self.ed_create_new_key_password_2, rs_supplied_passwords_differs );
      exit;
    end;

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

    package_certificate := self.ed_existing_key_certificat_filename.Text;
  end;

  write_configs( package_certificate );

  if m_has_waptservice_installed then
    self.restart_waptservice_and_register();

  if not wizard_validate_no_innosetup_process_running( self, self.ButNext ) then
    exit;


  bContinue := true;
end;

procedure TVisWAPTServerPostConf.validate_page_agent(var bContinue: boolean);
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
      self.EdPwd1.Text,
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
  params_package.server_password := self.EdPwd1.Text;
  params_package.config_filename := INI_FILE_WAPTCONSOLE;
  params_package.dualsign        := false;
  if self.rb_CreateKey.Checked then
    params_package.private_key_password := self.ed_create_new_key_password_1.Text
  else
    params_package.private_key_password := self.ed_existing_key_password.Text;

  r := create_package_waptupgrade_params( @params_package );

  DMPython.PythonModuleDMWaptPython.Events.Items[1].OnExecute := pe;

  if (r <> 0) or (params_package._result <> 0) then
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

function TVisWAPTServerPostConf.write_configs(const package_certificate: String ): integer;
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

  wapt_server := 'https://' + self.EdWAPTServerName.Text;
  repo_url    := wapt_server + '/wapt';

  SetLength( confs, 2 );
  confs[0] := INI_FILE_WAPTCONSOLE;
  confs[1] := INI_FILE_WAPTGET;

  for i:= 0 to 1 do
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

function TVisWAPTServerPostConf.restart_waptservice_and_register(): integer;
var
   waptget : String;
   sl : TStringList;
   r : integer;
begin
  waptget := IncludeTrailingPathDelimiter(WaptBaseDir) + 'wapt-get.exe';

  sl := TStringList.Create;
  sl.Append( 'net stop  waptservice' );
  sl.Append( waptget + ' --direct register' );
  sl.Append( 'net start waptservice' );
  sl.Append( waptget + ' update' );

  r := run_commands( sl );
  sl.Free;

  exit(r);
end;

function TVisWAPTServerPostConf.run_commands(const sl: TStrings): integer;
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
      Run( UTF8Decode(sl.Strings[i]), '', RUN_TIMEOUT_MS );
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

procedure TVisWAPTServerPostConf.update_doc_html();
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
  else if pgPassword = p then
    str_index := 100
  else if pgPackageName = p then
    str_index := 300
  else if pgPackageKey = p then
    str_index := 200
  else if pgStartServices = p then
    str_index := 400
  else if pgBuildAgent = p then
    str_index := 500
  else if pgFinish = p then
    str_index := 600
  else
    goto LBL_NO_DOC;


  buffer := nil;
  inc( str_index, self.m_language_offset );
  r := Windows.LoadStringW( HINSTANCE(), str_index, @buffer, 0 );

  if r < 1 then
    goto LBL_NO_DOC;

  html_panel.SetHtmlFromStr( buffer );
  exit;

LBL_NO_DOC:
  html_panel.SetHtmlFromStr( HTML_NO_DOC );
end;

procedure TVisWAPTServerPostConf.show_validation_error(c: TControl; const msg: String);
begin
  MessageDlg( self.Caption, msg,  mtError, [mbOK], 0 );
  if c is TWinControl and  TWinControl(c).Enabled then
    TWinControl(c).SetFocus;
end;

procedure TVisWAPTServerPostConf.ActNextExecute(Sender: TObject);
label
  LBL_FAIL;
var
  bContinue : Boolean;
  p         : TTabSheet;
begin
  bContinue := false;
  p := self.PagesControl.ActivePage;

  push_cursor( crHourGlass );

  set_buttons_enable( false );

  if pgParameters = p then
  begin
    self.validate_page_parameters( bContinue );
    if not bContinue then
      exit;
  end
  else if pgConfigureConsoleOrFinish = p then
  begin
    if self.rb_configure_console_finish.Checked then
    begin
      if self.cb_configure_console_launch_console_on_exit.Checked then
        launch_console();
      ExitProcess(0);
    end;
  end

  else if pgPassword = p then
  begin
    self.validate_page_password( bContinue );
    if not bContinue then
      goto LBL_FAIL;
    m_need_restart_waptserver := true;
  end

  else if pgStartServices = p then
  begin
    if m_need_restart_waptserver then
    begin
      self.show_validation_error( self.btn_start_waptserver, rs_click_restart_waptserver );
      goto LBL_FAIL;
    end;

    if not (ssRunning =  GetServiceStatusByName('','waptserver')) then
      goto LBL_FAIL;

  end

  else if pgPackageName = p then
  begin
    self.validate_page_packge_name( bContinue );
    if not bContinue then
      goto LBL_FAIL;
  end

  else if pgPackageKey = p then
  begin
    self.validate_page_package_key(bContinue);
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
  set_buttons_enable( true );
  pop_cursor();
  exit;

LBL_FAIL:
  set_buttons_enable( true );
  pop_cursor();
end;

procedure TVisWAPTServerPostConf.ActNextUpdate(Sender: TObject);
begin
  if PagesControl.ActivePage = pgParameters then
    ActNext.Enabled := EdWaptServerIP.Text<>''
  else if PagesControl.ActivePage = pgPassword then
    ActNext.Enabled := true
  else if PagesControl.ActivePage = pgPackageKey then
    ActNext.Enabled := true
  else if PagesControl.ActivePage = pgStartServices then
    ActNext.Enabled := true
  else
    ActNext.Enabled := PagesControl.ActivePageIndex<=PagesControl.PageCount-1;
  if PagesControl.ActivePageIndex=PagesControl.PageCount-1 then
    ActNext.Caption:= rsWaptSetupDone
  else
    ActNext.Caption:=rsWaptSetupnext;
end;

procedure TVisWAPTServerPostConf.ActPreviousExecute(Sender: TObject);
begin
  PagesControl.ActivePageIndex := PagesControl.ActivePageIndex - 1;
end;

procedure TVisWAPTServerPostConf.ActPreviousUpdate(Sender: TObject);
begin
  if PagesControl.ActivePage = pgParameters then
  begin
    ActPrevious.Enabled := False;
    exit;
  end;

  if PagesControl.ActivePage = pgFinish then
  begin
    ActPrevious.Enabled := False;
    exit;
  end;

  ActPrevious.Enabled := true;
end;

function runwapt(cmd:String):String;
begin
  StrReplace(cmd,'{app}',WaptBaseDir,[rfReplaceAll]);
  result := Run(cmd);
end;


function RPad(x: string; c: Char; s: Integer): string;
var
  i: Integer;
begin
  Result := x;
  if Length(x) < s then
    for i := 1 to s-Length(x) do
      Result := Result + c;
end;

function XorBlock(s, x: ansistring): ansistring; inline;
var
  i: Integer;
begin
  SetLength(Result, Length(s));
  for i := 1 to Length(s) do
    Result[i] := Char(Byte(s[i]) xor Byte(x[i]));
end;

function CalcDigest(text: string; dig: TDCP_hashclass): string;
var
  x: TDCP_hash;
begin
  x := dig.Create(nil);
  try
    x.Init;
    x.UpdateStr(text);
    SetLength(Result, x.GetHashSize div 8);
    x.Final(Result[1]);
  finally
    x.Free;
  end;
end;

function CalcHMAC(message, pgPackageKey: string; hash: TDCP_hashclass): string;
const
  blocksize = 64;
begin
  // Definition RFC 2104
  if Length(pgPackageKey) > blocksize then
    pgPackageKey := CalcDigest(pgPackageKey, hash);
  pgPackageKey := RPad(pgPackageKey, #0, blocksize);

  Result := CalcDigest(XorBlock(pgPackageKey, RPad('', #$36, blocksize)) + message, hash);
  Result := CalcDigest(XorBlock(pgPackageKey, RPad('', #$5c, blocksize)) + result, hash);
end;

function PBKDF1(pass, salt: ansistring; count: Integer; hash: TDCP_hashclass): ansistring;
var
  i: Integer;
begin
  Result := pass+salt;
  for i := 0 to count-1 do
    Result := CalcDigest(Result, hash);
end;

function PBKDF2(pass, salt: ansistring; count, kLen: Integer; hash: TDCP_hashclass): ansistring;

  function IntX(i: Integer): ansistring; inline;
  begin
    Result := Char(i shr 24) + Char(i shr 16) + Char(i shr 8) + Char(i);
  end;

var
  D, I, J: Integer;
  T, F, U: ansistring;
begin
  T := '';
  D := Ceil(kLen / (hash.GetHashSize div 8));
  for i := 1 to D do
  begin
    F := CalcHMAC(salt + IntX(i), pass, hash);
    U := F;
    for j := 2 to count do
    begin
      U := CalcHMAC(U, pass, hash);
      F := XorBlock(F, U);
    end;
    T := T + F;
  end;
  Result := '$pbkdf2-'+LowerCase(hash.GetAlgorithm)+'$'+IntToStr(count)+'$'+DCPbase64.Base64EncodeStr(salt)+'$'+DCPbase64.Base64EncodeStr(Copy(T, 1, kLen));
end;


function MakeRandomString(const ALength: Integer;
                          const ACharSequence: String = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'): String;
var
  C1, sequence_length: Integer;
begin
  sequence_length := Length(ACharSequence);
  SetLength(result, ALength);

  for C1 := 1 to ALength do
    result[C1] := ACharSequence[Random(sequence_length) + 1];
end;

function DigestToStr(Digest: array of byte): string;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to Length(Digest) -1 do
    Result := Result + LowerCase(IntToHex(Digest[i], 2));
end;

function GetStringHash(Source: string): string;
var
  Hash: TDCP_sha256;
  Digest: array[0..31] of Byte;
begin
  Hash := TDCP_sha256.Create(nil);
  Hash.Init;
  Hash.UpdateStr(Source);
  Hash.Final(Digest);
  Hash.Free;
  Result := DigestToStr(Digest);
end;

procedure TVisWAPTServerPostConf.actWriteConfStartServeExecute(Sender: TObject);
var
  retry:integer;
  GUID: TGuid;
  sores: ISuperobject;
  taskid:integer;
  done:boolean;
  sha: TDCP_sha256;
  dig:AnsiString;
begin

  CurrentVisLoading := TVisLoading.Create(Self);
  with CurrentVisLoading do
  try
    try
      ExceptionOnStop:=True;

      ProgressTitle(rsSettingServerPassword);
      ProgressStep(1,10);
      if (EdPwd1.Text<>'') then
        IniWriteString(WaptBaseDir+'\conf\waptserver.ini' ,'options','wapt_password',PBKDF2(EdPwd1.Text,MakeRandomString(5),29000,32,TDCP_sha256));

      if IniReadString(WaptBaseDir+'\conf\waptserver.ini' ,'options','server_uuid') = '' then
        iniWriteString(WaptBaseDir+'\conf\waptserver.ini','options', 'server_uuid', Lowercase(Copy(GUIDToString(GUID), 2, Length(GUIDToString(GUID)) - 2)));

      if (GetServiceStatusByName('','WAPTServer')= ssUnknown) or
         (GetServiceStatusByName('','waptpostgresql')= ssUnknown) or
         (GetServiceStatusByName('','waptnginx')= ssUnknown) then
      begin
        ProgressTitle(rsConfigurePostgreSQL);
        ProgressStep(2,10);
        runwapt(Format('"{app}waptpython.exe" "{app}waptserver\winsetup.py" all -c "%s"',[WaptBaseDir+'conf\waptserver.ini']));
      end;

      ProgressTitle(rsReplacingTIScertificate);
      ProgressStep(3,10);
      if FileExists(WaptBaseDir+'\ssl\tranquilit.crt') then
        DeleteFileUTF8(WaptBaseDir+'\ssl\tranquilit.crt');

      if CBOpenFirewall.Checked then
      begin
        ProgressTitle(rsOpeningFirewall);
        ProgressStep(4,10);
        OpenFirewall;
      end;

      ProgressStep(5,10);
      if GetServiceStatusByName('','waptpostgresql') in [ssStopped] then
      begin
        ProgressTitle(rsStartingPostgreSQL);
        Run('cmd /C net start waptpostgresql');
      end;

      ProgressStep(6,10);
      if GetServiceStatusByName('','waptserver') in [ssStopped] then
      begin
        ProgressTitle(rsStartingWaptServer);
        Run('cmd /C net start waptserver');
      end
      else
      if GetServiceStatusByName('','waptserver') in [ssRunning] then
      begin
        ProgressTitle(rsStoppingWaptServer);
        Run('cmd /C net stop waptserver');
        ProgressTitle(rsStartingWaptServer);
        Run('cmd /C net start waptserver');
      end;

      ProgressStep(7,10);
      if GetServiceStatusByName('','waptnginx') in [ssStopped] then
      begin
        ProgressTitle(rsStartingNGINX);
        Run('cmd /C net start waptnginx');
      end
      else
      if GetServiceStatusByName('','waptnginx') in [ssRunning] then
      begin
        ProgressTitle(rsStoppingNGINX);
        Run('cmd /C net stop waptnginx');
        ProgressTitle(rsStartingNGINX);
        Run('cmd /C net start waptnginx');
      end;

      if GetServiceStatusByName('','waptservice') in [ssRunning] then
      begin
        ProgressTitle(rsRestartingWaptService);
        Run('cmd /C net stop waptservice');
        Run('cmd /C net start waptservice');
      end;

      if FileExists(WaptBaseDir+'\waptserver\mongodb\mongoexport.exe') AND
        (Dialogs.MessageDlg(rsMongoDetect,rsRunMongo2Postgresql,mtInformation,mbYesNoCancel,0) = mrYes) then
      begin
        ProgressTitle(rsMigration15);
        ProgressStep(8,10);

        runwapt('"{app}\waptpython" {app}\waptserver\upgrade.py upgrade2postgres');

        if DirectoryExistsUTF8(WaptBaseDir+'\waptserver\mongodb') then
           fileutil.DeleteDirectory(WaptBaseDir+'\waptserver\mongodb', false);

        if DirectoryExistsUTF8(WaptBaseDir+'\waptserver\apache-win32') then
           fileutil.DeleteDirectory(WaptBaseDir+'\waptserver\apache-win32\', false);
      end;

      retry := 3;
      repeat
        ProgressTitle(rsCheckingWaptServer);
        ProgressStep(8,10);
        try
          sores := SO(IdhttpGetString('https://127.0.0.1/ping'));
        except
          sores := Nil;
        end;
        if sores<>Nil then
          ProgressTitle(sores.S['msg'])
        else
          sleep(2000);
        dec(Retry);
      until (retry<=0) or ((sores<>Nil) and sores.B['success']);
      Sleep(2000);
      m_need_restart_waptserver := false;
      ActNext.Execute;
    except
      on E:Exception do
      begin
        Dialogs.MessageDlg('Error','Error during post-config:'#13#10+E.Message,mtError,mbOKCancel,'');
        m_need_restart_waptserver := true;
      end;
    end;
  finally
    FreeAndNil(CurrentVisLoading);
  end;
end;





procedure TVisWAPTServerPostConf.ActManualExecute(Sender: TObject);
begin
  ActManual.Checked := not ActManual.Checked;
end;


procedure TVisWAPTServerPostConf.ActCheckDNSExecute(Sender: TObject);
var
  cnames,ips : ISuperObject;
begin
  push_cursor( crHourGlass );

  ips := Nil;
  cnames := DNSCNAMEQuery(EdWAPTServerName.Text);
  if (cnames<>Nil) and (cnames.AsArray.Length>0) then
    ips := DNSAQuery(cnames.AsArray[0].AsString)
  else
    ips := DNSAQuery(EdWAPTServerName.Text);

  if (ips<>Nil) and (ips.AsArray.Length>0) then
  begin
    self.EdWaptServerIP.SetFocus;
    EdWaptServerIP.text := ips.AsArray[0].AsString
  end
  else
  begin
    if Dialogs.MessageDlg(rsInvalidDNS,rsInvalidDNSfallback, mtConfirmation,mbYesNoCancel,0) = mrYes then
    begin
      EdWAPTServerName.Text := GetLocalIP;
      EdWaptServerIP.Text:= GetLocalIP;
    end
    else
      EdWaptServerIP.text := '';
  end;

  pop_cursor();
end;

procedure TVisWAPTServerPostConf.ActionFindPrivateKeyExecute(Sender: TObject);
label
  LBL_FAILED;
var
  s : String;
  r : integer;
begin
  push_cursor( crHourGlass );

  s := Trim(self.ed_existing_key_certificat_filename.Text);
  if 0 = Length(s) then
    goto LBL_FAILED;

  if not FileExists(s) then
    goto LBL_FAILED;

  r := find_private_key( s, s, self.ed_existing_key_password.Text );
  if r <> 0 then
    goto LBL_FAILED;

  self.ed_existing_key_key_filename.Text := s;

  pop_cursor();
  exit;

LBL_FAILED:
  MessageDlg( Application.Name, 'No private key has been found in certificate directory with this this password', mtInformation, [mbOK], 0 );
  pop_cursor();
end;

procedure TVisWAPTServerPostConf.ActCancelExecute(Sender: TObject);
var
  r : integer;
begin
  r := MessageDlg(rsConfirm, rsConfirmCancelPostConfig, mtConfirmation, mbYesNoCancel, 0);
  if mrYes = r then
    Close;
end;

function MakeIdent(st:String):String;
var
  i:integer;
begin
  result :='';
  for i := 1 to length(st) do
    if CharIsValidIdentifierLetter(st[i]) then
      result := Result+st[i];
end;


end.

