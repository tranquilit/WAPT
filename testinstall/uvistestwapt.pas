unit uvistestwapt;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, IdHTTPServer;

type

  { TForm1 }

  TForm1 = class(TForm)
    IdHTTPServer1: TIdHTTPServer;
    procedure FormCreate(Sender: TObject);
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
End;


end.

