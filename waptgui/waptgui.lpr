program waptgui;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Interfaces, // this includes the LCL widgetset
  Forms, pl_luicontrols, pl_graphics32ext,
  runtimetypeinfocontrols, pl_virtualtrees, uwaptconsole,
  waptcommon,uviswaptconfig, uDMLocalWapt;

{$R *.res}

begin
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TVisWaptGUI, VisWaptGUI);
  Application.CreateForm(TDMLocalWapt, DMLocalWapt);
  Application.Run;
end.

