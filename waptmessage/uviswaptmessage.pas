unit uviswaptmessage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls;

type

  { TMsgForm }

  TMsgForm = class(TForm)
    Label1: TLabel;
    procedure FormShow(Sender: TObject);
  private

  public

  end;

var
  MsgForm: TMsgForm;

implementation

{$R *.lfm}

{ TMsgForm }

procedure TMsgForm.FormShow(Sender: TObject);
begin
  // TODO : -h
  // TODO -f file to read content
  if ParamCount = 1 then
     Label1.Caption := ParamStr(0);
end;

end.

