program waptconsolepostconf;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Translations, LCLProc,

  Interfaces, // this includes the LCL widgetset
  Forms, uvisconsolepostconf, waptconsolepostconfres,
  waptcommon, waptwinutils, uvisloading, UScaleDPI,
  { you can add units after this }
  DefaultTranslator, indylaz, FrameViewer09, uvalidation, dmwaptpython, uutil,
  udefault;

{$R *.res}
{$R languages.rc}

begin
  // we use wapt-get.ini global config
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TDMPython, DMPython);
  Application.CreateForm(TVisWAPTConsolePostConf, VisWAPTConsolePostConf);
  Application.Run;
end.

