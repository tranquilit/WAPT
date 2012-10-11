program appwaptservice;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Interfaces, // this includes the LCL widgetset
  Forms, pl_indycomp, lazdbexport, sqlite3laz, uVisAppWaptService, waptunit,
  superobject, waptcommon;

{$R *.res}

begin
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TVisAppWAPTService, VisAppWAPTService);
  Application.CreateForm(TWaptDaemon, WaptDaemon);
  Application.Run;
end.

