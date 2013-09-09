unit uvispassword;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons, ButtonPanel;

type

  { TVisPassword }

  TVisPassword = class(TForm)
    ButtonPanel1: TButtonPanel;
    edPassword: TEdit;
    edUser: TEdit;
    edWaptServerName: TEdit;
    Label1: TLabel;
    laPassword: TLabel;
    laPassword1: TLabel;
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
end;

end.

