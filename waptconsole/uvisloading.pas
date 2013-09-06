unit uvisloading;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ComCtrls,
  ExtCtrls, StdCtrls,uwaptconsole;

type

  { Tvisloading }

  Tvisloading = class(TForm)
    btCancel: TButton;
    Chargement: TLabel;
    ProgressBar1: TProgressBar;
    procedure btCancelClick(Sender: TObject);
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

procedure Tvisloading.btCancelClick(Sender: TObject);
begin
    uwaptconsole.VisWaptGUI.stopDownload(True);
end;

end.

