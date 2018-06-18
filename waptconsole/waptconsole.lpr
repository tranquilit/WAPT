program waptconsole;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Translations, LCLProc,

  sysutils,
  process,

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
end;


procedure show_help;
const
  msg : String ='-h  : Show help' + sLineBreak +
                '-c  : Start console easy configuration '  + sLineBreak;
begin
  ShowMessage( msg );
end;





procedure start_configuration( options : PCmdLineOptions );
var
  w : TWizardConfigConsole;
begin

  if not IsAdmin then
  begin
    MessageDlg( ApplicationName, 'Configuration wizard need administrator priviliges', mtError, [mbOK], 0 );
    halt(0);
  end;

  // Start console config
  w := TWizardConfigConsole.create( nil );
  w.ShowModal;
  w.Free;
  halt(0);
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
    start_configuration( @CmdLineOptions );
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

