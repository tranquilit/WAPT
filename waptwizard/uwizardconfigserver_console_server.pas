unit uwizardconfigserver_console_server;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, ExtCtrls, StdCtrls;

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

  public

    procedure clear(); override; final;
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override;
  end;

implementation

uses
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

procedure TWizardConfigserver_Console_Server.clear();
begin
  self.p_custom_server_url.Caption := '';
  self.rg_server_url.ItemIndex:= -1;
  self.rg_server_url.Items.Clear;
  self.ed_custom_server_url.Clear;
  self.p_custom_server_url.Visible := false;
end;

procedure TWizardConfigserver_Console_Server.wizard_show();
var
  i   : integer;
  h   : String;
  sl  : TStringList;
  ini : TIniFile;
  r   : integer;
  s   : String;
  b_ini_wapt_server : boolean;
begin


  h := LowerCase(GetComputerName);

  // Try from waptconsole.ini
  r := wapt_ini_waptconsole( s );
  if r = 0 then
  begin
    ini := TIniFile.Create( s );
    try
      s := ini.ReadString( INI_GLOBAL, INI_WAPT_SERVER, '' );
      b_ini_wapt_server := Length(s) > 0;
      if b_ini_wapt_server then
      begin
        h := s;
        self.ed_custom_server_url.Text := s;
      end;
    finally
      FreeAndNil(ini);
    end;
  end;



  // Server url
  self.rg_server_url .Items.Clear;
  sl := TStringList.Create;
  i := net_list_enable_ip( sl );
  if i = 0 then
  begin
    for i := 0 to sl.Count -1 do
    begin

      if 'localhost' = sl.Strings[i] then
        continue;
      if '127.0.0.1' = sl.Strings[i] then
        continue;

      s := 'https://' + sl.Strings[i];
      self.rg_server_url.Items.AddObject( s, sl.Objects[i] );
      if Pos( h, s ) <> 0 then
        self.rg_server_url.ItemIndex := self.rg_server_url.Items.Count -1;
    end;
  end;
  sl.Free;

  // Server url custom
  self.rg_server_url.Items.AddObject('Custom url', nil );
  if b_ini_wapt_server then
    self.rg_server_url.ItemIndex := i;


  self.m_wizard.WizardButtonPanel.NextButton.SetFocus;

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
  data^.server_certificate := s  + '.crt';


  bCanNext := true;

end;


initialization

  RegisterClass(TWizardConfigserver_Console_Server);

end.

