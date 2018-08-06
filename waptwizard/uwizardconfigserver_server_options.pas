unit uwizardconfigserver_server_options;

{$mode objfpc}{$H+}

interface

uses
  uwizard, uwizardstepframe, WizardControls, Classes, SysUtils, FileUtil, Forms,
  Controls, StdCtrls, ExtCtrls, EditBtn, Arrow, ValEdit, Menus;

type

  { TWizardConfigServer_ServerOptions }

  TWizardConfigServer_ServerOptions = class( TWizardStepFrame )
    ed_port_http: TEdit;
    ed_port_https: TEdit;
    Label1: TLabel;
    lbl_port_http: TLabel;
    lbl_port_https: TLabel;
  private
  public
    procedure clear(); override; final;
    procedure wizard_load(w: TWizard); override; final;
    procedure wizard_show(); override; final;
    procedure wizard_next(var bCanNext: boolean); override; final;

  end;

implementation


uses
  IdURI,
  uwizardconfigserver_data,
  Dialogs,
  uwizardvalidattion,
  uwizardutil;

{$R *.lfm}



{ TWizardConfigServer_ServerOptions }

procedure TWizardConfigServer_ServerOptions.clear();
begin
  inherited clear();
  self.ed_port_https.Clear;
  self.ed_port_http.Clear;
end;

procedure TWizardConfigServer_ServerOptions.wizard_load(w: TWizard);
begin
  inherited wizard_load(w);
  self.ed_port_http.NumbersOnly   := true;
  self.ed_port_http.MaxLength     := 5;

  self.ed_port_https.NumbersOnly  := true;
  self.ed_port_https.MaxLength    := 5;
end;

procedure TWizardConfigServer_ServerOptions.wizard_show();
var
  data : PWizardConfigServerData;
begin
  inherited wizard_show();

  data := m_wizard.data();

  self.ed_port_http.Text  := IntToStr( data^.nginx_http );
  self.ed_port_https.Text := IntToStr( data^.nginx_https );

  if m_show_count = 1 then
    self.ed_port_http.SetFocus;

end;


procedure TWizardConfigServer_ServerOptions.wizard_next(var bCanNext: boolean);
const
  RESERVED_PORTS : array [0..0] of integer = (8080);
  MSG_PORT_RESERVED : String = 'This port is reserved and cannot be use' ;
var
  b : Boolean;
  r : integer;
  msg : String;
  data : PWizardConfigServerData;
  nginx_http : integer;
  nginx_https: Integer;
  uri : TIdURI;
begin
   bCanNext := false;

   data := m_wizard.data();


  //
  if not wizard_validate_str_is_valid_port_number( self.m_wizard, self.ed_port_http, self.ed_port_http.Text) then
    exit;
  if not wizard_validate_str_is_valid_port_number( self.m_wizard, self.ed_port_https, self.ed_port_https.Text ) then
    exit;

  nginx_http := StrToInt(self.ed_port_http.Text);
  nginx_https:= StrToInt(self.ed_port_https.Text);

  //
  for r := 0 to Length(RESERVED_PORTS) - 1 do
  begin
    if nginx_http = RESERVED_PORTS[r] then
    begin
      m_wizard.show_validation_error( self.ed_port_http,  MSG_PORT_RESERVED);
      exit;
    end;

    if nginx_https = RESERVED_PORTS[r] then
    begin
      m_wizard.show_validation_error( self.ed_port_https,   MSG_PORT_RESERVED);
      exit;
    end;

  end;


  //
  if not wizard_validate_net_local_port_is_closed( m_wizard, nginx_http, self.ed_port_http ) then
    exit;
  if not wizard_validate_net_local_port_is_closed( m_wizard, nginx_https, self.ed_port_https ) then
    exit;



  //
  b := service_is_running('MpsSvc');
  if b then
  begin
    msg :=       'The firewall is activate, Rules can be added to' + #13#10;
    msg := msg + 'your configuration.' + #13#10;
    msg := msg + 'Proceed ?';
    if mrYes = m_wizard.show_question( msg, mbYesNo ) then
    begin
      r := wapt_server_configure_firewall( nginx_http, nginx_https );
      if r <> 0 then
      begin
        m_wizard.show_validation_error( nil, 'Error while configuring firewall' );
        exit;
      end;
    end;
  end;




  //
  data^.nginx_http := nginx_http;
  data^.nginx_https:= nginx_https;

  uri := TIdURI.Create();
  uri.URI := data^.wapt_server;
  uri.Protocol:= 'https';
  uri.Port:= '';
  if data^.nginx_https <> 443 then
    uri.Port:= IntTostr(data^.nginx_https);
  data^.wapt_server:= uri.URI;
  data^.repo_url   := uri.URI + 'wapt';
  uri.Free;

  // Write nginx.conf
  r := data_write_cnf_nginx( data, m_wizard );
  if r <> 0 then
    exit;


  bCanNext := true;
end;






initialization
  RegisterClass(TWizardConfigServer_ServerOptions);


end.

