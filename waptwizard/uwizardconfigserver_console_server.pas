unit uwizardconfigserver_console_server;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, ExtCtrls;

type

  { TWizardConfigserver_Console_Server }

  TWizardConfigserver_Console_Server = class( TWizardStepFrame )
    rg_server_url: TRadioGroup;
  private

  public

    procedure clear(); override; final;
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override;
  end;

implementation

uses
  uwapt_ini,
  IniFiles,
  uwizardconfigserver_data,
  tiscommon,
  uwizardutil;

{$R *.lfm}

{ TWizardConfigserver_Console_Server }

procedure TWizardConfigserver_Console_Server.clear();
begin
end;

procedure TWizardConfigserver_Console_Server.wizard_show();
var
  i   : integer;
  h   : String;
  sl  : TStringList;
  ini : TIniFile;
  r   : integer;
  s   : String;
begin


  h := LowerCase(GetComputerName);

  // Try from waptconsole.ini
  r := wapt_ini_waptconsole( s );
  if r = 0 then
  begin
    ini := TIniFile.Create( s );
    try
      s := ini.ReadString( INI_GLOBAL, INI_WAPT_SERVER, '' );
      if Length(s) > 0 then
        h := s;
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
      s := 'https://' + sl.Strings[i];
      self.rg_server_url.Items.AddObject( s, sl.Objects[i] );
      if Pos( h, s ) <> 0 then
        self.rg_server_url.ItemIndex := self.rg_server_url.Items.Count -1;
    end;
  end;
  sl.Free;


  self.rg_server_url.SetFocus;

end;

procedure TWizardConfigserver_Console_Server.wizard_next(var bCanNext: boolean);
var
  s : String;
  data : PWizardConfigServerData;
begin

  bCanNext := false;

  data := self.m_wizard.data();

  // server_url
  if self.rg_server_url.ItemIndex = -1 then
  begin
    m_wizard.show_validation_error( self.rg_server_url, 'You must a valid server url' );
    exit;
  end;

  s := self.rg_server_url.Items[ self.rg_server_url.ItemIndex ];
  data^.wapt_server := s;
  data^.repo_url    := s + '/wapt' ;
  data^.server_certificate := s  + '.crt';


  bCanNext := true;

end;


initialization

  RegisterClass(TWizardConfigserver_Console_Server);

end.

