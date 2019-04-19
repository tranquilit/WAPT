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
  private

  public

  end;

var
  VisLogin: TVisLogin;

implementation

{$R *.lfm}

end.

