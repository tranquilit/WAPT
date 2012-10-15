Program waptservice;

Uses
{$IFDEF UNIX}{$IFDEF UseCThreads}
  CThreads,
{$ENDIF}{$ENDIF}
  DaemonApp, lazdaemonapp, pl_indycomp, WaptMapper, WaptUnit,
  waptcommon, superobject, interfaces, waptwmi;

{$R *.res}

{$DEFINE svcdebug}

begin
  Application.Initialize;
  Application.Run;
end.
