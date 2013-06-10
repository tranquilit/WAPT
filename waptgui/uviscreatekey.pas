unit uVisCreateKey;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  StdCtrls, Buttons;

type

  { TVisCreateKey }

  TVisCreateKey = class(TForm)
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    EdOrgName: TEdit;
    Label1: TLabel;
    Panel1: TPanel;
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisCreateKey: TVisCreateKey;

implementation

{$R *.lfm}

end.

