unit uVisLogin;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  Buttons;

type

  { TVisLogin }

  TVisLogin = class(TForm)
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    EdUsername: TEdit;
    EdPassword: TEdit;
    StaticText1: TStaticText;
    StaticText2: TStaticText;
    procedure FormShow(Sender: TObject);
  private

  public

  end;

var
  VisLogin: TVisLogin;

implementation

{$R *.lfm}

{ TVisLogin }

procedure TVisLogin.FormShow(Sender: TObject);
begin
  MakeFullyVisible();
  EdPassword.SetFocus;
end;

end.

