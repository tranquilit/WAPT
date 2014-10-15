program waptexit;

{$mode objfpc}{$H+}

uses
  //heaptrc,
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Interfaces, // this includes the LCL widgetset
  Forms, pl_indy, uwaptexit;

{$R *.res}

begin
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TVisWaptExit, VisWaptExit);
  Application.Run;
end.

