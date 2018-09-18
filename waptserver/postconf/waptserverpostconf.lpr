program waptserverpostconf;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Translations, LCLProc,

  Interfaces, // this includes the LCL widgetset
  Forms, uVisServerPostconf, uwaptserverres,
  waptcommon, waptwinutils, uvisloading, UScaleDPI,
  { you can add units after this }
  DefaultTranslator, indylaz, uvalidation, dmwaptpython, uutil,
  udefault;

{$R *.res}
{$R languages.rc}

begin
  // we use wapt-get.ini global config
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TDMPython, DMPython);
  Application.CreateForm(TVisWAPTServerPostConf, VisWAPTServerPostConf);
  Application.Run;
end.

