unit uwizardconfigconsole;

{$mode objfpc}{$H+}

interface

uses

  uwizardconfigconsole_data,

  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, uwizard,
  ComCtrls,ExtCtrls, StdCtrls, PopupNotifier, EditBtn, WizardControls;

type


  { TWizardConfigConsole }

  TWizardConfigConsole = class(TWizard)
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);



  private
    m_data : TWizardConfigConsoleData;
    m_check_certificates_validity : boolean;


  public
    function data() : Pointer; override; final;


  end;

var
  WizardConfigConsole: TWizardConfigConsole;

implementation

uses
  dmwaptpython,
  uwapt_ini,
  uwizardconfigconsole_server,
  uwizardconfigconsole_welcome,
  uwizardconfigconsole_package_create_new_key,
  uwizardconfigconsole_buildagent,
  uwizardconfigconsole_finished,
  waptcommon,
  uwizardutil,
  FileUtil,
  IniFiles;

{$R *.lfm}

{ TWizardConfigConsole }

procedure TWizardConfigConsole.FormCreate(Sender: TObject);
begin
  inherited;

  FillChar( m_data, sizeof(TWizardConfigConsoleData), 0 );
  m_data.is_enterprise_edition := DMPython.IsEnterpriseEdition;

end;

procedure TWizardConfigConsole.FormShow(Sender: TObject);
begin
    self.WizardButtonPanel.NextButton.SetFocus;
end;

procedure TWizardConfigConsole.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin
  if m_data.launch_console then
    self.launch_console();
end;

function TWizardConfigConsole.data(): Pointer;
begin
  exit( @m_data );
end;

end.

