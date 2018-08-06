unit uwizardconfigserver_server_options;

{$mode objfpc}{$H+}

interface

uses
  uwizard, uwizardstepframe, WizardControls, Classes, SysUtils, FileUtil, Forms,
  Controls, StdCtrls, ExtCtrls, EditBtn, Arrow, ValEdit, Menus;

type

  { TWizardConfigServer_ServerOptions }

  TWizardConfigServer_ServerOptions = class( TWizardStepFrame )
    cb_add_rule_to_firewall: TCheckBox;
    ed_port_http: TEdit;
    ed_port_https: TEdit;
    ImageList1: TImageList;
    img_firewall_rule_wapt_https: TImage;
    img_firewall_rule_wapt_http: TImage;
    llb_select_ports: TLabel;
    lbl_firewall_rule_wapt_https: TLabel;
    lbl_firewall_rule_wapt_http: TLabel;
    lbl_port_http: TLabel;
    lbl_port_https: TLabel;
    p_firewall: TPanel;
    procedure cb_add_rule_to_firewallChange(Sender: TObject);
  private
    function fw_add_rule( const rule_name : String; local_port : UInt16; b_is_http : boolean) : boolean;

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

const
  IMG_SUCCESS : integer = 0;
  IMG_FAILED  : integer = 1;


{ TWizardConfigServer_ServerOptions }

procedure TWizardConfigServer_ServerOptions.cb_add_rule_to_firewallChange( Sender: TObject);
begin
  self.p_firewall.Visible := self.cb_add_rule_to_firewall.Checked;
end;

function TWizardConfigServer_ServerOptions.fw_add_rule(const rule_name: String; local_port: UInt16; b_is_http: boolean): boolean;
const
  MSG_ADDING_RULE   : String = 'Adding rule ''%s'' to firewall';
var
  img : TImage;
  img_idx : integer;
  msg : String;
begin
  msg := Format( MSG_ADDING_RULE, [name] );
  self.m_wizard.SetValidationDescription( msg );
  result := firewall_add_rule_allow( rule_name, local_port );
  if b_is_http then
    img := self.img_firewall_rule_wapt_http
  else
    img := self.img_firewall_rule_wapt_https;

  if result then
    img_idx := IMG_SUCCESS
  else
    img_idx := IMG_FAILED;

  self.ImageList1.GetBitmap( img_idx, img.Picture.Bitmap );
  img.Visible := true;
  Application.ProcessMessages;
end;

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
  self.ed_port_http.Hint          := 'Wapt http server port';

  self.ed_port_https.NumbersOnly  := true;
  self.ed_port_https.MaxLength    := 5;
  self.ed_port_https.Hint         := 'Wapt https server port';

  self.lbl_firewall_rule_wapt_http.Caption := WAPT_FIREWALL_RULE_HTTP;
  self.lbl_firewall_rule_wapt_https.Caption:= WAPT_FIREWALL_RULE_HTTPS;

end;

procedure TWizardConfigServer_ServerOptions.wizard_show();
var
  data : PWizardConfigServerData;
  b : boolean;
begin
  inherited wizard_show();

  data := m_wizard.data();


  self.ed_port_http.Text  := IntToStr( data^.nginx_http );
  self.ed_port_https.Text := IntToStr( data^.nginx_https );

  // Firewall
  b := firewall_is_running();
  self.cb_add_rule_to_firewall.Enabled := b;
  self.cb_add_rule_to_firewall.Checked := b;
  self.p_firewall.Visible := b ;
  self.img_firewall_rule_wapt_http.Visible  := false;
  self.img_firewall_rule_wapt_https.Visible := false;

  if m_show_count = 1 then
    self.m_wizard.WizardButtonPanel.NextButton.SetFocus;



end;


procedure TWizardConfigServer_ServerOptions.wizard_next(var bCanNext: boolean);
const
  RESERVED_PORTS    : array [0..0] of integer = (8080);
  MSG_PORT_RESERVED : String = 'This port is reserved and cannot be use' ;
var
  b : Boolean;
  r : integer;
  data : PWizardConfigServerData;
  nginx_http : integer;
  nginx_https: Integer;
  uri : TIdURI;
begin
   bCanNext := false;

   data := m_wizard.data();

   self.img_firewall_rule_wapt_http.Visible := false;
   self.img_firewall_rule_wapt_https.Visible:= false;


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


  //  Firewall
  b := self.cb_add_rule_to_firewall.Enabled and self.cb_add_rule_to_firewall.Checked;
  if b then
  begin
    if not fw_add_rule( WAPT_FIREWALL_RULE_HTTP, nginx_http, true ) then
      exit;
    if not fw_add_rule( WAPT_FIREWALL_RULE_HTTPS, nginx_https, false ) then
      exit;
  end;

  // Ensure ports aren't filtered and used by another process
  if not wizard_validate_net_local_port_is_closed( m_wizard, nginx_http, self.ed_port_http ) then
    exit;
  if not wizard_validate_net_local_port_is_closed( m_wizard, nginx_https, self.ed_port_https ) then
    exit;


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
  data^.repo_url   := url_concat(uri.URI,'wapt');
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

