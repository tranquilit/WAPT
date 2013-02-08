program appwaptservice;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Interfaces, // this includes the LCL widgetset
  Forms,
  uVisAppWaptService, waptcommon,waptunit;

{$R *.res}

begin
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TWaptDaemon, WaptDaemon);
  Application.CreateForm(TVisAppWAPTService, VisAppWAPTService);
  Application.Run;
end.

