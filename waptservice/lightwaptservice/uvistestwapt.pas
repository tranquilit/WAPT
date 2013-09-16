unit uvistestwapt;
{ -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013  Tranquil IT Systems http://www.tranquil.it
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users PC.
#
#    WAPT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    WAPT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with WAPT.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------
}

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

