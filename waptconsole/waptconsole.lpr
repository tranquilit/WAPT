program waptconsole;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Translations, LCLProc,

  Interfaces, // this includes the LCL widgetset
  Forms,
  pl_virtualtrees, pl_excontrols, uwaptconsole, uVisCreateKey,
  waptcommon, uwaptres, dmwaptpython, uVisEditPackage,
  uviscreatewaptsetup, uvislogin, uvisprivatekeyauth,
  uvisloading, uviswaptconfig, uvischangepassword, uviswaptdeploy, 
  uvishostsupgrade, uVisAPropos, uVisImportPackage;

{$R *.res}

procedure TranslateLCL;
var
  PODirectory, Lang, FallbackLang: String;
  res: TTranslateUnitResult;
begin
  PODirectory:='C:\codetyphon\typhon\lcl\languages\';
  Lang:='fr';
  FallbackLang:='en';
  //LCLGetLanguageIDs(Lang,FallbackLang); // in unit LCLProc
  res := Translations.TranslateUnitResourceStrings('LCLStrConsts',
                      PODirectory+'lclstrconsts.%s.po',Lang,FallbackLang);
  res := Translations.TranslateUnitResourceStrings('uWaptRes', 'C:\tranquilit\wapt\waptconsole.%s.po',Lang,FallbackLang);

  // ... add here a TranslateUnitResourceStrings call for every po file ...
end;

begin
  TranslateLCL;
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TDMPython, DMPython);
  Application.CreateForm(TVisWaptGUI, VisWaptGUI);
  Application.Run;
end.

