unit uvisprivatekeyauth;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons, DefaultTranslator;

type

  { TVisPrivateKeyAuth }

  TVisPrivateKeyAuth = class(TForm)
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    edPasswordKey: TEdit;
    Label1: TLabel;
    laKeyPath: TLabel;
    laPassword: TLabel;
    Panel1: TPanel;
    Panel2: TPanel;
    procedure edPasswordKeyKeyPress(Sender: TObject; var Key: char);
    procedure FormCreate(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisPrivateKeyAuth: TVisPrivateKeyAuth;

implementation

uses uSCaleDPI;

{$R *.lfm}

{ TVisPrivateKeyAuth }

procedure TVisPrivateKeyAuth.edPasswordKeyKeyPress(Sender: TObject;
  var Key: char);
begin
  if Key=#13 then
  begin
     BitBtn1.Click;
  end;
end;

procedure TVisPrivateKeyAuth.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
end;

end.

