Program waptservice;

Uses
{$IFDEF UNIX}{$IFDEF UseCThreads}
  CThreads,
{$ENDIF}{$ENDIF}
  DaemonApp, lazdaemonapp, WaptMapper, WaptUnit, indylaz,interfaces;

{$R *.res}

begin
  Application.Initialize;
  Application.Run;
end.
