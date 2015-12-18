program waptserverpostconf;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Translations, LCLProc,

  Interfaces, // this includes the LCL widgetset
  Forms, pl_indy, uVisServerPostconf, uwaptserverres,
  waptcommon, uvisloading, UScaleDPI,
  { you can add units after this }
  DefaultTranslator;

{$R *.res}
{$R languages.rc}

begin
  // we use wapt-get.ini global config
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TVisWAPTServerPostConf, VisWAPTServerPostConf);
  Application.Run;
end.

