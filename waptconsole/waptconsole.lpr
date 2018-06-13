program waptconsole;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Translations, LCLProc,

  sysutils,

  Interfaces, // this includes the LCL widgetset
  Forms, luicontrols, runtimetypeinfocontrols, memdslaz,
  uwaptconsole, uVisCreateKey, dmwaptpython, uVisEditPackage,
  uviscreatewaptsetup, uvislogin, uvisprivatekeyauth, uvisloading,
  uviswaptconfig, uvischangepassword, uvishostsupgrade, uVisAPropos,
  uVisImportPackage, uwaptconsoleres, uVisPackageWizard, uscaledpi,
  uVisChangeKeyPassword, uvisrepositories, uvisdisplaypreferences,
  uVisHostDelete,waptcommon,
  Dialogs,
  Controls,
  windows, uwizardconfigserver,
  uwizardconfigconsole,
  tiscommon
  ;

{$R *.res}

type
TCmdLineOptions = record
  start_configuration  : boolean;
  wapt_server_hostname : String;
  show_help            : boolean;
end;
PCmdLineOptions = ^TCmdLineOptions;


procedure InitCmdLineOptions( var options : TCmdLineOptions );
begin
  FillChar( options, sizeof(TCmdLineOptions), 0 );

  options.show_help             := Application.HasOption(     'h', 'help');
  options.start_configuration   := Application.HasOption(     'c', 'console' );
  options.wapt_server_hostname  := Application.GetOptionValue('s', 'server' );
end;


procedure show_help;
const
  msg : String ='-h  : Show help' + sLineBreak +
                '-c  : Start console easy configuration '  + sLineBreak +
                '-s  : Start server easy configuration ';
begin
  ShowMessage( msg );
end;

function start_configuration( options : PCmdLineOptions )  : TModalResult;
var
  ws        : TWizardConfigServer;
  ws_params : TWizardConfigServerParams;
  wc        : TWizardConfigConsole;
begin

  if not IsAdmin then
  begin
    MessageDlg( 'Error', 'Configuration helper need administrator priviliges', mtError, [mbOK], 0 );
    exit( mrAbort );
  end;


  // Config console
  wc := TWizardConfigConsole.create( nil );
  try
    result := wc.ShowModal;
    if result = mrClose then
      halt;
  finally
    wc.Free;
  end;

end;


procedure process_options;
var
  CmdLineOptions : TCmdLineOptions;
begin

  InitCmdLineOptions( CmdLineOptions );

  // option help
  if CmdLineOptions.show_help then
  begin
      show_help;
      halt(0);
  end;

  // option first time wizard
  if CmdLineOptions.start_configuration then
  begin
    if mrOK <> start_configuration( @CmdLineOptions ) then
        halt(0);
  end;

end;


begin


  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TDMPython, DMPython);
  process_options;
  DMPython.WaptConfigFileName := AppIniFilename;
  ReadWaptConfig(AppIniFilename);
  Application.CreateForm(TVisWaptGUI, VisWaptGUI);



  if not VisWaptGUI.Login then
     Halt;
  Application.Run;
end.

