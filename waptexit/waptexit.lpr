program waptexit;

{$mode objfpc}{$H+}

uses
  //heaptrc,
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Translations, LCLProc,
  Interfaces, // this includes the LCL widgetset
  Forms, uwaptexit, uwaptexitres,DefaultTranslator, uscaledpi;

{$R *.res}

begin
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TVisWaptExit, VisWaptExit);
  Application.Run;
end.

