program waptconsole;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Translations, LCLProc,

  Interfaces, // this includes the LCL widgetset
  Forms, pl_indy, pl_rx, pl_exdesign, pl_bgrabitmap, uwaptconsole,
  uVisCreateKey, waptcommon, waptwinutils, dmwaptpython, uVisEditPackage,
  uviscreatewaptsetup, uvislogin, uvisprivatekeyauth, uvisloading,
  uviswaptconfig, uvischangepassword, uviswaptdeploy, uvishostsupgrade,
  uVisAPropos, uVisImportPackage, uwaptconsoleres, uVisWUAGroup,
  uVisWAPTWUAProducts, uviswuarules, uviswuapackageselect,
  uVisWUAClassificationsSelect, uVisPackageWizard, uscaledpi;

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

