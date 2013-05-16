program waptgui;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Interfaces, // this includes the LCL widgetset
  Forms, pl_indycomp, uwaptgui, tisstrings,
  waptcommon, soutils, tiscommon, tisinifiles
  { you can add units after this };

{$R *.res}

begin
  Application.Title:='wapt-gui';
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TVisWaptGUI, VisWaptGUI);
  Application.Run;
end.

