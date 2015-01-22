program waptserverpostconf;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Translations, LCLProc,

  Interfaces, // this includes the LCL widgetset
  Forms, pl_indy, uVisServerPostconf, waptcommon, uWaptRes, uvisloading,
  { you can add units after this }
  DefaultTranslator;


{$R *.res}

procedure TranslateLCL;
var
  PODirectory, Lang, FallbackLang: String;
  //poFile :TPOFile;

begin
  PODirectory:='C:\codetyphon\typhon\lcl\languages\';
  Lang:='fr';
  FallbackLang:='en';
  //LCLGetLanguageIDs(Lang,FallbackLang); // in unit LCLProc

  // ... add here a TranslateUnitResourceStrings call for every po file ...
  Translations.TranslateUnitResourceStrings(
      'LCLStrConsts',
      PODirectory+'lclstrconsts.%s.po',Lang,
      FallbackLang);
  Translations.TranslateUnitResourceStrings(
      'uWaptRes',
      'C:\tranquilit\wapt\languages\waptserverpostconf.%s.po',Lang,FallbackLang);
end;


begin
  TranslateLCL;
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TVisWAPTServerPostConf, VisWAPTServerPostConf);
  Application.Run;
end.

