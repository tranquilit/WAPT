unit uvispassword;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons;

type

  { TVisPassword }

  TVisPassword = class(TForm)
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    edPassword: TEdit;
    laPassword: TLabel;
    Panel1: TPanel;
    procedure edPasswordKeyPress(Sender: TObject; var Key: char);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisPassword: TVisPassword;

implementation

{$R *.lfm}

{ TVisPassword }

procedure TVisPassword.edPasswordKeyPress(Sender: TObject; var Key: char);
begin
  if Key=#13 then
  begin
     BitBtn1.Click;
  end;
end;

end.

