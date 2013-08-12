unit uvisloading;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ComCtrls,
  ExtCtrls, StdCtrls;

type

  { Tvisloading }

  Tvisloading = class(TForm)
    Chargement: TLabel;
    ProgressBar1: TProgressBar;
    Timer1: TTimer;
    procedure Timer1Timer(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  visloading: Tvisloading;

implementation

{$R *.lfm}

{ Tvisloading }


procedure Tvisloading.Timer1Timer(Sender: TObject);
begin
  ProgressBar1.Position := (ProgressBar1.Position + 1) mod ProgressBar1.Max;
end;

end.

