unit uwizardconfigserver_console_server;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, ExtCtrls;

type

  { TWizardConfigserver_ConsoleServer }

  TWizardConfigserver_ConsoleServer = class( TWizardStepFrame )
    rg_server_url: TRadioGroup;
  private

  public

    procedure clear(); override; final;
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override;
  end;

implementation

uses
  uwizardconfigserver_data,
  tiscommon,
  uwizardutil;

{$R *.lfm}

{ TWizardConfigserver_ConsoleServer }

procedure TWizardConfigserver_ConsoleServer.clear();
begin
end;

procedure TWizardConfigserver_ConsoleServer.wizard_show();
var
  i   : integer;
  h   : String;
  sl  : TStringList;
begin

  h := GetComputerName;

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
      self.rg_server_url.Items.AddObject( sl.Strings[i], sl.Objects[i] );
      if Pos( h, sl.Strings[i] ) <> 0 then
        self.rg_server_url.ItemIndex := self.rg_server_url.Items.Count -1;
    end;
  end;
  sl.Free;


  self.rg_server_url.SetFocus;

end;

procedure TWizardConfigserver_ConsoleServer.wizard_next(var bCanNext: boolean);
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
  data^.wapt_server := 'https://' + s;
  data^.repo_url    := 'https://' + s + '/wapt' ;
  data^.server_certificate := s  + '.crt';


  bCanNext := true;

end;


initialization

  RegisterClass(TWizardConfigserver_ConsoleServer);

end.

