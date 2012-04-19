unit uvistestwapt;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, PythonEngine, PythonGUIInputOutput, IdHTTPServer;

type

  { TForm1 }

  TForm1 = class(TForm)
    Button1: TButton;
    Memo1: TMemo;
    Memo2: TMemo;
    Panel2: TPanel;
    PythonEngine1: TPythonEngine;
    PythonGUIInputOutput1: TPythonGUIInputOutput;
    procedure Button1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure Panel2Click(Sender: TObject);
    procedure PythonEngine1AfterInit(Sender: TObject);
    procedure PythonEngine1PathInitialization(Sender: TObject; var Path: String
      );
    procedure PythonEngine1SysPathInit(Sender: TObject; PathList: PPyObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  Form1: TForm1; 

implementation
{$R *.lfm}

{ TForm1 }

procedure TForm1.FormCreate(Sender: TObject);
Begin
  PythonEngine1.DllPath:= ExtractFilePath(ParamStr(0));
End;

procedure TForm1.Panel2Click(Sender: TObject);
begin

end;

procedure TForm1.PythonEngine1AfterInit(Sender: TObject);
begin

end;

procedure TForm1.PythonEngine1PathInitialization(Sender: TObject;
  var Path: String);
begin

end;

procedure TForm1.PythonEngine1SysPathInit(Sender: TObject; PathList: PPyObject);
begin

end;

procedure TForm1.Button1Click(Sender: TObject);
begin
  PythonEngine1.ExecStrings( Memo2.Lines );
end;


end.

