program testwapt;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Interfaces, // this includes the LCL widgetset
  Forms, uvistestwapt, tisinstall, indylaz
  { you can add units after this };

{$R *.res}

begin
  Application.Title := 'TestWAPT';
  Application.Name := 'TestWAPT';
  Application.Initialize;
  If ParamStr(1) = 'uninstall' Then
    desinstaller
  else
    installer;

  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.

