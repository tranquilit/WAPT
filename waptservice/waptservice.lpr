Program waptservice;

Uses
{$IFDEF UNIX}{$IFDEF UseCThreads}
  CThreads,
{$ENDIF}{$ENDIF}
  DaemonApp, lazdaemonapp, weblaz, WaptMapper, WaptUnit, waptcommon, indylaz,
  interfaces;

{$R *.res}

{$DEFINE svcdebug}

begin
  Application.Initialize;
  Application.Run;
end.
