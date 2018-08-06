unit uwizardconfigserver_console_server;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, ExtCtrls, StdCtrls, Menus;

type

  { TWizardConfigserver_Console_Server }

  TWizardConfigserver_Console_Server = class( TWizardStepFrame )
    ed_custom_server_url: TEdit;
    lbl_custom_server_url: TLabel;
    p_custom_server_url: TPanel;
    rg_server_url: TRadioGroup;
    procedure rg_server_urlSelectionChanged(Sender: TObject);
  private

    function is_custom_server_url_selected() : boolean;


    procedure init_server_url_callback(  data : PtrInt );

  public

    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override;
    procedure clear(); override; final;
  end;

implementation

uses
  uwizardconfigconsole_data,
  dialogs,
  uwapt_ini,
  IniFiles,
  uwizardvalidattion,
  uwizardconfigserver_data,
  tiscommon,
  uwizardutil;

{$R *.lfm}

{ TWizardConfigserver_Console_Server }


procedure TWizardConfigserver_Console_Server.rg_server_urlSelectionChanged( Sender: TObject);
begin
  self.p_custom_server_url.Visible := is_custom_server_url_selected();
end;

function TWizardConfigserver_Console_Server.is_custom_server_url_selected(): boolean;
begin
  result := (self.rg_server_url.Items.Count-1) = self.rg_server_url.ItemIndex;
end;






procedure init_server_url( data : Pointer );
const
  TO_EXCLUDE : array[0..1] of String = ('localhost', '127.0.0.1');
var
  sl : TStringList;
  i  : integer;
  r  : integer;
begin
  sl := TStringList.Create;
  net_list_enable_ip( sl );

  for i := 0 to Length(TO_EXCLUDE) -1 do
  begin
    r := sl.IndexOf( TO_EXCLUDE[i] );
    if r <> -1 then
      sl.Delete(r);
  end;

  Application.QueueAsyncCall( @TWizardConfigserver_Console_Server(data).init_server_url_callback, PtrInt(sl) );
end;



procedure TWizardConfigserver_Console_Server.init_server_url_callback( data : PtrInt );
var
  i   : integer;
  h   : String;
  sl  : TStringList;
  ini : TIniFile;
  r   : integer;
  s   : String;
  b_ini_wapt_server : Boolean;

  wdata : PWizardConfigServerData;
begin
  b_ini_wapt_server := false;

  wdata := m_wizard.data();



  h := LowerCase(GetComputerName);

  // Server url
  sl := TStringList(data);
  for i := 0 to sl.Count -1 do
  begin
   s := 'https://' + sl.Strings[i];
   if wdata^.nginx_https <> 443 then
     s := s + ':' + IntToStr(wdata^.nginx_https);
   self.rg_server_url.Items.AddObject( s, sl.Objects[i] );
   if Pos( h, s ) <> 0 then
     self.rg_server_url.ItemIndex := i;
  end;
  sl.Free;

  // Server url custom
  self.rg_server_url.Items.AddObject('Custom url', nil );
  if b_ini_wapt_server then
   self.rg_server_url.ItemIndex := self.rg_server_url.Items.Count -1;

  self.rg_server_urlSelectionChanged( nil );


  m_wizard.show_loading(false);

  if self.rg_server_url.ItemIndex <> -1 then
    self.m_wizard.WizardButtonPanel.NextButton.SetFocus;

end;

procedure TWizardConfigserver_Console_Server.wizard_show();
begin
  inherited;

  if m_show_count = 1 then
  begin
   self.clear();
   m_wizard.show_loading( true );
   TThread.ExecuteInThread( @init_server_url, self );
  end;

end;

procedure TWizardConfigserver_Console_Server.wizard_next(var bCanNext: boolean);
var
  s : String;
  data : PWizardConfigServerData;
  c : TControl;
begin

  bCanNext := false;

  data := self.m_wizard.data();

  if self.rg_server_url.ItemIndex = -1 then
  begin
    m_wizard.show_validation_error( self.rg_server_url, 'You must a valid server url' );
    exit;
  end;

  // custom ?
  if is_custom_server_url_selected() then
  begin
    s := self.ed_custom_server_url.Text;
    c := self.ed_custom_server_url;
    if not wizard_validate_str_not_empty_when_trimmed( self.m_wizard, self.ed_custom_server_url, 'Server url cannot be empty' ) then
      exit;
  end
  else
  begin
    s := self.rg_server_url.Items[ self.rg_server_url.ItemIndex ];
    c := self.rg_server_url;
  end;

  if not wizard_validate_waptserver_ping( self.m_wizard, s, c ) then
    exit;


  data^.wapt_server := s;
  data^.repo_url    := s + '/wapt' ;
//  data^.server_certificate := s  + '.crt';


  bCanNext := true;

end;
procedure TWizardConfigserver_Console_Server.clear();
begin
  self.p_custom_server_url.Caption := '';
  self.rg_server_url.ItemIndex:= -1;
  self.rg_server_url.Items.Clear;
  self.ed_custom_server_url.Clear;
  self.p_custom_server_url.Visible := false;
end;


initialization

  RegisterClass(TWizardConfigserver_Console_Server);

end.

