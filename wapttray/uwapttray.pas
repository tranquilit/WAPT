unit uwapttray;

{$mode objfpc}{$H+}

interface

uses
  Forms, ComCtrls, DefaultTranslator;

type

  { TVisWAPTTray }

  TVisWAPTTray = class(TForm)
    pages: TPageControl;
    pgStatus: TTabSheet;
    TabSheet2: TTabSheet;
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisWAPTTray: TVisWAPTTray;

implementation


{$R *.lfm}

{ TVisWAPTTray }


end.

