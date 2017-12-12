unit uVisAPropos;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  StdCtrls, DefaultTranslator;

type

  { TVisApropos }

  TVisApropos = class(TForm)
    Button1: TButton;
    Image1: TImage;
    LabInfos: TLabel;
    procedure Button1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure Image1Click(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisApropos: TVisApropos;

implementation
uses uWaptConsoleRes,tiscommon,waptcommon,LCLIntf,UScaleDPI,uwaptconsole;
{$R *.lfm}

{ TVisApropos }

procedure TVisApropos.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
  if VisWaptGUI.ActProprietary.Checked then
    VisWaptGUI.plStatusBar1.Panels[0].Text := ApplicationName+' '+GetApplicationVersion+' WAPT Community Edition, (c) 2012-2017 Tranquil IT Systems. (Configuration:'+AppIniFilename+')'
  else
    VisWaptGUI.plStatusBar1.Panels[0].Text := ApplicationName+' '+GetApplicationVersion+' WAPT Enterprise Edition, (c) 2012-2017 Tranquil IT Systems. (Configuration:'+AppIniFilename+')';

  LabInfos.Caption := VisWaptGUI.plStatusBar1.Panels[0].Text;
end;

procedure TVisApropos.Image1Click(Sender: TObject);
begin
  OpenDocument('http://www.tranquil.it');
end;

procedure TVisApropos.Button1Click(Sender: TObject);
begin
  Close;

end;

end.

