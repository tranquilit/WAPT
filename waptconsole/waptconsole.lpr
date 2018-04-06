program waptconsole;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Translations, LCLProc,

  Interfaces, // this includes the LCL widgetset
  Forms, luicontrols, runtimetypeinfocontrols, memdslaz,
  uwaptconsole, uVisCreateKey, dmwaptpython, uVisEditPackage,
  uviscreatewaptsetup, uvislogin, uvisprivatekeyauth, uvisloading,
  uviswaptconfig, uvischangepassword, uvishostsupgrade, uVisAPropos,
  uVisImportPackage, uwaptconsoleres, uVisPackageWizard, uscaledpi,
  uVisChangeKeyPassword, uvisrepositories, uvisdisplaypreferences,
  uVisHostDelete,waptcommon
  {$ifdef wsus},
  uVisWUAGroup,
  uVisWAPTWUAProducts, uviswuarules, uviswuapackageselect,
  uVisWUAClassificationsSelect
  {$endif}
  ;

{$R *.res}

begin
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TDMPython, DMPython);
  DMPython.WaptConfigFileName := AppIniFilename;
  ReadWaptConfig(AppIniFilename);
  Application.CreateForm(TVisWaptGUI, VisWaptGUI);

  if not VisWaptGUI.Login then
     Halt;
  Application.Run;
end.

