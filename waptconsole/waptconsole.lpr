program waptconsole;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Translations, LCLProc,

  sysutils,
  process,

  Interfaces, // this includes the LCL widgetset
  Forms, Dialogs, Controls, {$IFDEF WINDOWS} windows, {$ENDIF}
  luicontrols, memdslaz,
  runtimetypeinfocontrols, uwaptconsole, uVisCreateKey, dmwaptpython,
  uVisEditPackage, uviscreatewaptsetup, uvislogin, uvisprivatekeyauth,
  uvisloading, uviswaptconfig, uvischangepassword, uvistriggerhostsaction,
  uVisAPropos, uVisImportPackage, uwaptconsoleres, uVisPackageWizard,
  uVisChangeKeyPassword, uvisrepositories, uvisdisplaypreferences,
  uVisHostDelete, waptcommon, tiscommon, uviswuadownloads,
  uvissoftwaresnormalization, uvisselfservicegroup, uviseditcreaterule,
  uVisErrorsRepos, uviswaptusers;

{$R *.res}

begin
  Application.Scaled:=True;
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

