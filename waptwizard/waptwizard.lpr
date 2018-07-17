program waptwizard;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Interfaces, // this includes the LCL widgetset

  tiscommon, uwizard, dmwaptpython,
  Dialogs, Forms, runtimetypeinfocontrols, luicontrols,
  uwizardresetserverpassword,
  uwizardconfigconsole,
  uwizardconfigserver;

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





procedure start_configuration_console();
var
  w : TWizardConfigConsole;
begin

  if not IsAdmin then
  begin
    MessageDlg( Application.Name, 'Console configuration wizard need administrator priviliges', mtError, [mbOK], 0 );
    halt(0);
  end;

  w := TWizardConfigConsole.create( nil );
  w.ShowModal;
  w.Free;
  halt(0);
end;

procedure start_configuration_server();
var
  w : TWizardConfigServer;
begin
  if not IsAdmin then
  begin
      MessageDlg( Application.Name, 'Server configuration wizard need administrator priviliges', mtError, [mbOK], 0 );
      halt(0);
  end;

  w := TWizardConfigServer.create( nil );
  w.ShowModal;
  w.Free;
  halt(0);
end;

procedure start_reset_password();
var
    w : TWizardResetServerPassword;
begin
  if not IsAdmin then
  begin
      MessageDlg( Application.Name, 'Reset password wizard need ', mtError, [mbOK], 0 );
      halt(0);
  end;

  w := TWizardResetServerPassword.create( nil );
  w.ShowModal;
  w.Free;
  halt(0);
end;

procedure process_options;
begin

  // -c : config console
  if Application.HasOption('c') then
    start_configuration_console();

  // -s : config server
  if Application.HasOption('s') then
    start_configuration_server();

  // -r : reset server password
  if Application.HasOption('r') then
    start_reset_password();

  show_help;
end;



begin
  Application.Title:='waptwizard';
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TDMPython, DMPython);
  process_options;
end.

