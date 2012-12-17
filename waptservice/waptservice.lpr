Program waptservice;

Uses
{$IFDEF UNIX}{$IFDEF UseCThreads}
  CThreads,
{$ENDIF}{$ENDIF}
  DaemonApp, lazdaemonapp, WaptMapper, WaptUnit,
  waptcommon, superobject, interfaces, pl_indycomp;

{ $DEFINE svcdebug}

{$R *.res}

begin
  Application.Initialize;
  Application.Run;
end.
