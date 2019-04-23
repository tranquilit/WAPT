program WaptSelf;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Interfaces, // this includes the LCL widgetset
  Forms, uviswaptself, uFrmPackage, uVisLogin, uVisImpactedProcess;

{$R *.res}

begin
  Application.Scaled:=True;
  RequireDerivedFormResource:=True;
  Application.Initialize;
  Application.CreateForm(TVisWaptSelf, VisWaptSelf);
  Application.CreateForm(TImpactedProcess, ImpactedProcess);
  Application.Run;
end.

