unit uvisprivatekeyauth;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons, DefaultTranslator;

type

  { TVisPrivateKeyAuth }

  TVisPrivateKeyAuth = class(TForm)
    BitBtnOk: TBitBtn;
    BitBtnCancel: TBitBtn;
    EdPasswordKey: TEdit;
    LabKey: TLabel;
    laKeyPath: TLabel;
    LabPassword: TLabel;
    Panel1: TPanel;
    Panel2: TPanel;
    procedure EdPasswordKeyKeyPress(Sender: TObject; var Key: char);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisPrivateKeyAuth: TVisPrivateKeyAuth;

implementation

{$R *.lfm}

{ TVisPrivateKeyAuth }

procedure TVisPrivateKeyAuth.EdPasswordKeyKeyPress(Sender: TObject;
  var Key: char);
begin
  if Key=#13 then
  begin
     BitBtnOk.Click;
  end;
end;

end.

