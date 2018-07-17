unit uwizardstepframeservercertificate;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardstepframe,
  superobject,
  Classes, SysUtils, FileUtil, Forms, Controls, ExtCtrls;

type

  { TWizardStepFrameServerCertificateVerification }

  TWizardStepFrameServerCertificate = class(TWizardStepFrame)
    rg_hostnames: TRadioGroup;
  private

  public

  // TWizardStepFrame
  procedure wizard_load( w : TWizard; data : ISuperObject );   override; final;
  function wizard_validate() : integer;  override; final;

  end;

implementation

uses
  uwizardutil;

{$R *.lfm}


{ TWizardStepFrameServerCertificate }

procedure TWizardStepFrameServerCertificate.wizard_load(w: TWizard; data: ISuperObject );
var
  sl : TStringList;
  i : integer;
begin
  inherited wizard_load(w, data);


  // Hostnames list
  self.rg_hostnames .Items.Clear;
  sl := TStringList.Create;
  i := net_list_enable_ip( sl );
  if i = 0 then
  begin
    for i := 0 to sl.Count -1 do
      self.rg_hostnames.Items.AddObject( sl.Strings[i], sl.Objects[i] );
  end;

end;

function TWizardStepFrameServerCertificate.wizard_validate(): integer;
var
  s: String;
begin

  if self.rg_hostnames.ItemIndex = -1 then
  begin
    m_wizard.show_validation_error( nil, 'You must select an interface' );
    exit(-1);
  end;

  s := self.rg_hostnames.Items[ self.rg_hostnames.ItemIndex ];
    self.m_data.S['server_hostname'] := UTF8Decode(s);
  self.m_data.S['wapt_server'] := UTF8Decode('https://' + s );
  self.m_data.S['server_certificate'] := UTF8Decode( s  + '.crt' );

  exit( 0 );
end;


initialization
  RegisterClass(TWizardStepFrameServerCertificate);

end.

