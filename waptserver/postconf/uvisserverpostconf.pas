unit uVisServerPostconf;

{$mode objfpc}{$H+}

interface

uses
  PythonEngine,
  Classes, SysUtils, FileUtil, LazFileUtils, LazUTF8, Forms, Controls, Graphics,
  Dialogs, ComCtrls, StdCtrls, ExtCtrls, Buttons, ActnList, htmlview, Readhtml,
  IdHTTP, IdComponent, uvisLoading, DefaultTranslator, LCLTranslator, LCLProc,
  EditBtn, uWaptServerRes;

type

  { TVisWAPTServerPostConf }

  TVisWAPTServerPostConf = class(TForm)
    ActCheckDNS: TAction;
    ActCreateKey: TAction;
    ActCancel: TAction;
    ActBuildWaptsetup: TAction;
    actWriteConfStartServe: TAction;
    ActManual: TAction;
    ActNext: TAction;
    actPrevious: TAction;
    ActionList1: TActionList;
    BitBtn4: TBitBtn;
    ButCancel: TBitBtn;
    BitBtn6: TBitBtn;
    ButNext: TBitBtn;
    ButPrevious: TBitBtn;
    cbLaunchWaptConsoleOnExit: TCheckBox;
    CBOpenFirewall: TCheckBox;
    cb_create_new_key_show_password: TCheckBox;
    cb_use_existing_key_show_password: TCheckBox;
    ed_package_prefix: TEdit;
    ed_create_new_key_password_1: TEdit;
    ed_existing_key_certificat_filename: TFileNameEdit;
    ed_existing_key_password: TEdit;
    ed_create_new_key_password_2: TEdit;
    ed_create_new_key_key_name: TEdit;
    ed_create_new_key_private_directory: TDirectoryEdit;
    EdPwd1: TEdit;
    EdPwd2: TEdit;
    EdWaptServerIP: TEdit;
    EdWAPTServerName: TEdit;
    ed_existing_key_key_filename: TFileNameEdit;
    Label1: TLabel;
    Label2: TLabel;
    lbl_ed_package_prefix: TLabel;
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
    Panel1: TPanel;
    Panel2: TPanel;
    Panel3: TPanel;
    Panel5: TPanel;
    panFinish: TPanel;
    pgParameters: TTabSheet;
    pgPassword: TTabSheet;
    ProgressBar1: TProgressBar;
    pgStartServices: TTabSheet;
    pgFinish: TTabSheet;
    pgPackagePrivateKey: TTabSheet;
    pgBuildAgent: TTabSheet;
    rb_CreateKey: TRadioButton;
    rb_UseKey: TRadioButton;
    procedure ActCheckDNSExecute(Sender: TObject);
    procedure ActManualExecute(Sender: TObject);
    procedure ActNextExecute(Sender: TObject);
    procedure ActNextUpdate(Sender: TObject);
    procedure actPreviousExecute(Sender: TObject);
    procedure actPreviousUpdate(Sender: TObject);
    procedure actWriteConfStartServeExecute(Sender: TObject);
    procedure ButCancelClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure HTMLViewer1HotSpotClick(Sender: TObject; const SRC: string; var Handled: boolean);
    procedure IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64);
    procedure PagesControlChange(Sender: TObject);
    procedure on_private_key_radiobutton_change( Sender : TObject );
    procedure on_show_password_change( Sender : TObject );
    procedure on_create_setup_waptagent_tick( Sender : TObject );
    procedure on_upload( ASender: TObject; AWorkMode: TWorkMode; AWorkCount: Int64 );
    procedure on_python_update(Sender: TObject; PSelf, Args: PPyObject; var Result: PPyObject);

  private
    CurrentVisLoading:TVisLoading;
    procedure OpenFirewall;
    { private declarations }

    procedure set_buttons_enable( enable : Boolean );
    procedure clear();
    procedure validate_page_package_and_private_key( var bContinue : boolean );
    procedure validate_page_agent( var bContinue : boolean );
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
  LCLIntf, Windows, waptcommon, waptwinutils, UScaleDPI, tisinifiles,
  superobject, tiscommon, tisstrings, IniFiles,DCPsha256,dcpcrypt2,DCPbase64,Math;

{$R *.lfm}



{ TVisWAPTServerPostConf }

procedure TVisWAPTServerPostConf.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96);
  //HTMLViewer1.DefFontSize := ScaleY(HTMLViewer1.DefFontSize,96);
  ReadWaptConfig(WaptBaseDir+'wapt-get.ini');
  PagesControl.ShowTabs:=False;
  PagesControl.ActivePageIndex:=0;


  self.clear();

  // fmor
//  self.PagesControl.PageIndex:= 2;

end;

procedure TVisWAPTServerPostConf.FormShow(Sender: TObject);
begin
  EdWAPTServerName.Text:=LowerCase(GetComputerName)+'.'+GetDNSDomain;
  PagesControlChange(Self);
end;

procedure TVisWAPTServerPostConf.HTMLViewer1HotSpotClick(Sender: TObject;
  const SRC: string; var Handled: boolean);
begin
  OpenURL(SRC);
  Handled:=True;
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



procedure TVisWAPTServerPostConf.PagesControlChange(Sender: TObject);
const
  PAGES_INDEX_STEP =  100; // cf. languages.rc
  PAGES_EN_OFFSET =		0;
  PAGES_FR_OFFSET =		1;
  PAGES_DE_OFFSET =		2;
var
  ini:TIniFile;
  Page: TMemoryStream;
  PageContent: AnsiString;
  Lang, FallbackLang: String;
  i, LangOffset: Integer;
begin
  { XXX This is not what I'd call clean language detection... }

  LazGetLanguageIDs(Lang, FallbackLang);
  LangOffset := PAGES_EN_OFFSET;
  if FallbackLang = 'fr' then
    LangOffset := PAGES_FR_OFFSET
  else if FallbackLang = 'de' then
    LangOffset := PAGES_DE_OFFSET;

  for i := 1 to ParamCount-1 do
    if ((ParamStr(i) = '-l') or (ParamStr(i) = '--lang')) and (i+1 <> ParamCount-1) then
    begin
      if ParamStr(i+1) = 'de' then
         LangOffset := PAGES_DE_OFFSET
      else
      if ParamStr(i+1) = 'fr' then
         LangOffset := PAGES_FR_OFFSET
      else
        LangOffset := PAGES_EN_OFFSET;
    end;

  {PageContent := GetString(langOffset + PagesControl.ActivePageIndex * PAGES_INDEX_STEP);
  Page := TMemoryStream.Create;
  Page.WriteAnsiString(PageContent);
  HTMLViewer1.LoadFromStream(Page);
  Page.Free;

  if PagesControl.ActivePage = pgFinish then
  begin
    HTMLViewer1.Parent := panFinish;
    HTMLViewer1.Align:=alClient;
  end
  }

  if self.PagesControl.ActivePage = pgBuildAgent then
    self.ButNext.Click;

end;

procedure TVisWAPTServerPostConf.on_private_key_radiobutton_change( Sender: TObject);
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
begin
  if AWorkCount <> 62 then
    self.ProgressBar1.Position := SETUP_AGENT_SIZE + AWorkCount;
  self.pg_agent_memo.Append( IntToStr(AWorkCount) + ' ' + IntToStr(self.ProgressBar1.Position) );
  Application.ProcessMessages;
end;

procedure TVisWAPTServerPostConf.on_python_update(Sender: TObject; PSelf, Args: PPyObject; var Result: PPyObject);
begin
  Result:= DMPython.PythonEng.ReturnNone;
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
  self.ButPrevious.Enabled := enable;
  self.ButNext.Enabled     := enable;
  self.ButCancel.Enabled   := enable;
end;

procedure TVisWAPTServerPostConf.clear();
begin

  set_buttons_enable( true );

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
  self.on_show_password_change( nil );

  self.ed_package_prefix.Text:= DEFAULT_PACKAGE_PREFIX;
  self.ed_create_new_key_private_directory.Text := DEFAULT_PRIVATE_KEY_DIRECTORY;

//  self.rb_UseKey.Checked :=;

end;

procedure TVisWAPTServerPostConf.validate_page_package_and_private_key( var bContinue: boolean);
  procedure write_config( const certificate : String );
  var
     wapt_server : String;
     repo_url    : String;
  begin
    if not str_is_empty_when_trimmed( self.EdWaptServerIP.Text ) then
      wapt_server := 'https://' + self.EdWaptServerIP.Text
    else
      wapt_server := 'https://' + self.EdWAPTServerName.Text;

    repo_url := wapt_server + '/wapt';

    IniWriteString(WaptBaseDir + '\waptconsole.ini',  INI_GLOBAL, INI_PERSONAL_CERTIFICATE_PATH, certificate );
    IniWriteString(WaptBaseDir + '\waptconsole.ini',  INI_GLOBAL, INI_WAPT_SERVER, wapt_server );
    iniWriteString(WaptBaseDir + '\waptconsole.ini',  INI_GLOBAL, INI_REPO_URL, repo_url );
    iniWriteString(WaptBaseDir + '\waptconsole.ini',  INI_GLOBAL, INI_CHECK_CERTIFICATES_VALIDITY, '0' );
    iniWriteString(WaptBaseDir + '\waptconsole.ini',  INI_GLOBAL, INI_VERIFIY_CERT, '0' );

    IniWriteString(WaptBaseDir + '\wapt-get.ini',     INI_GLOBAL, INI_PERSONAL_CERTIFICATE_PATH, certificate );
    IniWriteString(WaptBaseDir + '\wapt-get.ini',     INI_GLOBAL, INI_WAPT_SERVER, wapt_server );
    IniWriteString(WaptBaseDir + '\wapt-get.ini',     INI_GLOBAL, INI_REPO_URL, repo_url );
    iniWriteString(WaptBaseDir + '\wapt-get.ini',     INI_GLOBAL, INI_CHECK_CERTIFICATES_VALIDITY, '0' );
    iniWriteString(WaptBaseDir + '\wapt-get.ini',     INI_GLOBAL, INI_VERIFIY_CERT, '0' );

  end;

var
   r    : integer;
   msg  : String;
   s    : String;
   params : TCreate_signed_cert_params;
begin

  bContinue := false;

  // Validate package name
  if not wizard_validate_package_prefix( self, self.ed_package_prefix, self.ed_package_prefix.Text ) then
    exit;

  // Validate create key
  if self.rb_CreateKey.Checked then
  begin
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

    r := create_signed_cert_params( @params );
    if r <> 0 then
    begin
      self.show_validation_error( nil, params._error_message );
      exit;
    end;

    write_config( params._certificate );

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

    write_config( self.ed_existing_key_certificat_filename.Text );
  end;


  if not wizard_validate_no_innosetup_process_running( self, self.ButNext ) then
    exit;


  bContinue := true;
end;

procedure TVisWAPTServerPostConf.validate_page_agent(var bContinue: boolean);
label
  LBL_FAIL;
var
  cf            : String;
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
  cf := WaptBaseDir + '\waptconsole.ini';

  create_setup_waptagent_params_init( @params_agent );

  params_agent.default_public_cert       := IniReadString( cf, INI_GLOBAL, INI_PERSONAL_CERTIFICATE_PATH );
  params_agent.default_repo_url          := IniReadString( cf, INI_GLOBAL, INI_REPO_URL );
  params_agent.default_wapt_server       := IniReadString( cf, INI_GLOBAL, INI_WAPT_SERVER );
  params_agent.destination               := GetTempDir(true);
  params_agent.OnProgress                := @on_create_setup_waptagent_tick;

  r := create_setup_waptagent_params( @params_agent );
  if r <> 0 then
  begin
    self.show_validation_error( self.pg_agent_memo,  rs_compilation_failed );
    goto LBL_FAIL;
  end;

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

  // Build upload apt-upgrade
  if not wizard_validate_no_innosetup_process_running( self, nil ) then
    goto LBL_FAIL;

  pe :=  DMPython.PythonModuleDMWaptPython.Events.Items[1].OnExecute;
  DMPython.PythonModuleDMWaptPython.Events.Items[1].OnExecute := @on_python_update;


  params_package.server_username := 'admin';
  params_package.server_password := self.EdPwd1.Text;
  params_package.config_filename := cf;
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
  self.ProgressBar1.Position := self.ProgressBar1.Max;
  Application.ProcessMessages;
  Sleep( 1 * 1000 );


  self.ProgressBar1.Visible := false;
  bContinue := true;
  exit;

LBL_FAIL:
  self.ProgressBar1.Visible := false;
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
  cmd,param : WideString;
  bContinue : Boolean;
begin
  bContinue := false;

  set_buttons_enable( false );

  if pgPackagePrivateKey = PagesControl.ActivePage then
  begin
    self.validate_page_package_and_private_key(bContinue);
    if not bContinue then
      goto LBL_FAIL;
  end

  else if pgBuildAgent = PagesControl.ActivePage then
  begin
    self.validate_page_agent(bContinue);
    if not bContinue then
      goto LBL_FAIL;
  end

  else if pgFinish = PagesControl.ActivePage then
  begin
    cmd := WideString(WaptBaseDir)+ WideString('waptconsole.exe');
    param := '';
    //param := '-c';
    if cbLaunchWaptConsoleOnExit.Checked then
      ShellExecuteW(0,'open',PWidechar(cmd),PWidechar(param),Nil,SW_SHOW);
    ExitProcess(0);
  end;


  self.PagesControl.ActivePageIndex := self.PagesControl.ActivePageIndex + 1;
  self.PagesControlChange(nil);
  set_buttons_enable( true );
  exit;

LBL_FAIL:
  set_buttons_enable( true );
end;

procedure TVisWAPTServerPostConf.ActNextUpdate(Sender: TObject);
begin
  if PagesControl.ActivePage = pgParameters then
    ActNext.Enabled := EdWaptServerIP.Text<>''
  else if PagesControl.ActivePage = pgPassword then
    ActNext.Enabled := (EdPwd1.Text='') or (EdPwd1.Text = EdPwd2.Text)
  else if PagesControl.ActivePage = pgPackagePrivateKey then
    ActNext.Enabled := true
  else if PagesControl.ActivePage = pgStartServices then
    ActNext.Enabled := GetServiceStatusByName('','waptserver') = ssRunning
  else
    ActNext.Enabled := PagesControl.ActivePageIndex<=PagesControl.PageCount-1;
  if PagesControl.ActivePageIndex=PagesControl.PageCount-1 then
    ActNext.Caption:= rsWaptSetupDone
  else
    ActNext.Caption:=rsWaptSetupnext;
end;

procedure TVisWAPTServerPostConf.actPreviousExecute(Sender: TObject);
begin
  PagesControl.ActivePageIndex := PagesControl.ActivePageIndex - 1;
  self.PagesControlChange( nil );
end;

procedure TVisWAPTServerPostConf.actPreviousUpdate(Sender: TObject);
begin
  actPrevious.Enabled:=(PagesControl.ActivePageIndex>0) and (PagesControl.ActivePageIndex<=PagesControl.PageCount-1);
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

function CalcHMAC(message, pgPackagePrivateKey: string; hash: TDCP_hashclass): string;
const
  blocksize = 64;
begin
  // Definition RFC 2104
  if Length(pgPackagePrivateKey) > blocksize then
    pgPackagePrivateKey := CalcDigest(pgPackagePrivateKey, hash);
  pgPackagePrivateKey := RPad(pgPackagePrivateKey, #0, blocksize);

  Result := CalcDigest(XorBlock(pgPackagePrivateKey, RPad('', #$36, blocksize)) + message, hash);
  Result := CalcDigest(XorBlock(pgPackagePrivateKey, RPad('', #$5c, blocksize)) + result, hash);
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
      ActNext.Execute;

    except
      on E:Exception do
        Dialogs.MessageDlg('Error','Error during post-config:'#13#10+E.Message,mtError,mbOKCancel,'');
    end;
  finally
    FreeAndNil(CurrentVisLoading);
  end;
end;

procedure TVisWAPTServerPostConf.ButCancelClick(Sender: TObject);
begin
  if MessageDlg(rsConfirm,rsConfirmCancelPostConfig,mtConfirmation,mbYesNoCancel,0) = mrYes then
    Close;
end;

procedure TVisWAPTServerPostConf.ActManualExecute(Sender: TObject);
begin
  ActManual.Checked := not ActManual.Checked;
end;


procedure TVisWAPTServerPostConf.ActCheckDNSExecute(Sender: TObject);
var
  cnames,ips : ISuperObject;
begin
  ips := Nil;
  cnames := DNSCNAMEQuery(EdWAPTServerName.Text);
  if (cnames<>Nil) and (cnames.AsArray.Length>0) then
    ips := DNSAQuery(cnames.AsArray[0].AsString)
  else
    ips := DNSAQuery(EdWAPTServerName.Text);

  if (ips<>Nil) and (ips.AsArray.Length>0) then
  begin
    EdWaptServerIP.text := ips.AsArray[0].AsString
  end
  else
  begin
    if Dialogs.MessageDlg(rsInvalidDNS,rsInvalidDNSfallback,
        mtConfirmation,mbYesNoCancel,0) = mrYes then
    begin
      EdWAPTServerName.Text := GetLocalIP;
      EdWaptServerIP.Text:= GetLocalIP;
    end
    else
      EdWaptServerIP.text := '';
  end;
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

