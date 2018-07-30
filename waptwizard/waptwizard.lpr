program waptwizard;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  sysutils,
  dynlibs,

  Classes,
  windows,
  Interfaces, // this includes the LCL widgetset
  tiscommon, uwizard, dmwaptpython, uvisloading, Dialogs, Forms,
  runtimetypeinfocontrols, luicontrols, uwizardresetserverpassword,
  uwizardconfigconsole, uwizardconfigserver, uwizardresetserverpassword_welcome,
  uwizardresetserverpassword_setpassword,
  uwizardresetserverpassword_restartserver, uwizardresetserverpassword_finish,
  uwapt_ini, uwizardconfigconsole_buildagent, uwizardconfigconsole_data,
  uwizardconfigconsole_finished, uwizardconfigconsole_server,
  uwizardconfigconsole_welcome, uwizardconfigserver_data,
  uwizardconfigserver_finish, uwizardconfigserver_firewall,
  uwizardconfigserver_postsetup, uwizardconfigserver_welcome,
  uwizardresetserverpassword_data, uwizardconfigserver_console,
  uwizardconfigserver_console_server,
  uwizardconfigconsole_package_create_new_key,
  uwizardconfigconsole_package_use_existing_key,
  uwizardconfigconsole_restartwaptservice,
  uwizardconfigserver_restartwaptservice, uwizardconfigserver_mongodb, uwizardconfigserver_start_services;

{$R *.res}


procedure show_help;
const
  msg : String ='-h  : Show help' + sLineBreak +
                '-c  : Start console easy configuration '  + sLineBreak +
                '-s  : Start server  easy configuration '  + sLineBreak +
                '-r  : Reset server password easy configuration '  + sLineBreak
                ;
begin
  ShowMessage( msg );
  halt(0);
end;

procedure ensure_prerequisites;
begin
  if not IsAdmin then
  begin
      MessageDlg( Application.Name, 'Administror privileges are required', mtError, [mbOK], 0 );
      halt(-1);
  end;

end;

begin
  RequireDerivedFormResource := True;
  Application.Initialize;

  Application.CreateForm(TDMPython, DMPython);

    // -c : config console
  if Application.HasOption('c') then
    Application.CreateForm( TWizardConfigConsole,  WizardConfigConsole )

  // -s : config server
  else if Application.HasOption('s') then
  Application.CreateForm( TWizardConfigServer,  WizardConfigServer )

  // -r : reset server password
  else if Application.HasOption('r') then
    Application.CreateForm( TWizardResetServerPassword, WizardResetServerPassword )

  else
    show_help;


  ensure_prerequisites;
  Application.Run;
end.

