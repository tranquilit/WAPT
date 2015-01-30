program waptserverpostconf;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Translations, LCLProc,

  Interfaces, // this includes the LCL widgetset
  Forms, pl_indy, uVisServerPostconf, uwaptserverres, waptcommon, uWaptRes,
  uvisloading,
  { you can add units after this }
  DefaultTranslator;


{$R *.res}
{$R tips_fr.rc}

begin
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TVisWAPTServerPostConf, VisWAPTServerPostConf);
  Application.Run;
end.

