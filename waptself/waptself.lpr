program WaptSelf;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Interfaces, // this includes the LCL widgetset
  Forms, uviswaptself, uFrmPackage, uVisLogin, uWaptSelfRes, uFrmDetailsPackage;



begin
  {$ifdef ENTERPRISE }
  {$R waptself.res}
  {$endif}
  Application.Scaled:=True;
  RequireDerivedFormResource:=True;
  Application.Initialize;
  Application.CreateForm(TVisWaptSelf, VisWaptSelf);
  Application.Run;
end.

