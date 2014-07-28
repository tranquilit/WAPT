program waptconsole;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Interfaces, // this includes the LCL widgetset
  Forms,
  pl_virtualtrees, uwaptconsole, uVisCreateKey,
  waptcommon, dmwaptpython, uVisEditPackage,
  uviscreatewaptsetup, uvislogin, uvisprivatekeyauth,
  uvisloading, uviswaptconfig, uvischangepassword, uviswaptdeploy, 
uvishostsupgrade, uVisAPropos;

{$R *.res}

begin
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TDMPython, DMPython);
  Application.CreateForm(TVisWaptGUI, VisWaptGUI);
  Application.CreateForm(TVisApropos, VisApropos);
  Application.Run;
end.

