unit uviswaptmessage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls;

type

  { TMsgForm }

  TMsgForm = class(TForm)
    Button1: TButton;
    Button2: TButton;
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
  WriteLn('saucisson');
end;

end.

