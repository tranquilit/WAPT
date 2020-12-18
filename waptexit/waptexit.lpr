program waptexit;

{$mode objfpc}{$H+}

uses
  //heaptrc,
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Translations, LCLProc,
  Interfaces, // this includes the LCL widgetset
  Forms, tiscommon, uwaptexit, uwaptexitres, DefaultTranslator, uWAPTPollThreads,
  Sysutils,LazFileUtils,UExceptionLogger;

{$R *.res}

begin
  if DirectoryIsWritable(Makepath([ExtractFilePath(ParamStr(0)),'log'])) then
    exceptionLogger.LogFileName := Makepath([ExtractFilePath(ParamStr(0)),'log',ExtractFileNameWithoutExt(ExtractFileNameOnly(ParamStr(0)))+'.log'])
  else
    exceptionLogger.LogFileName := MakePath([GetUserDir,ExtractFileNameWithoutExt(ExtractFileNameOnly(ParamStr(0)))+'.log']);

  Application.Scaled:=True;
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TVisWaptExit, VisWaptExit);
  Application.Run;
end.

