unit uFrmPackage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, ExtCtrls, BCListBox,
  BCLabel,BCMaterialDesignButton, BGRAImageList, FXProgressBar;

type

  { TFrmPackage }

  TFrmPackage = class(TFrame)
    BCMaterialDesignButton1: TBCMaterialDesignButton;
    BCPaperPanel1: TBCPaperPanel;
    FXProgressBar1: TFXProgressBar;
    ImgPackage: TImage;
    LabDescription: TBCLabel;
    Label2: TBCLabel;
    LabInstallVersion: TBCLabel;
    LabMaintainer: TBCLabel;
    LabPackageName: TBCLabel;
    LabVersion: TBCLabel;
    Timer1: TTimer;
    procedure BCMaterialDesignButton1Click(Sender: TObject);
    procedure Timer1StartTimer(Sender: TObject);
    procedure Timer1StopTimer(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
  private

  public
    constructor Create(TheOwner: TComponent); override;
    procedure AdjustFont(ALabel:TBCLabel);
  end;

implementation
uses Graphics,BCTools;
{$R *.lfm}

{ TFrmPackage }

procedure TFrmPackage.BCMaterialDesignButton1Click(Sender: TObject);
begin
  Timer1.Enabled:=True;
end;

procedure TFrmPackage.Timer1StartTimer(Sender: TObject);
begin
  FXProgressBar1.Value:=0;
  BCMaterialDesignButton1.Caption:='Installing';
  BCMaterialDesignButton1.NormalColor:=clRed;
  FXProgressBar1.Show;
  Label2.Show;
end;

procedure TFrmPackage.Timer1StopTimer(Sender: TObject);
begin
  Label2.Hide;
  FXProgressBar1.Hide;
  BCMaterialDesignButton1.Caption:='Installed';
  BCMaterialDesignButton1.NormalColor:=clGreen;
end;

procedure TFrmPackage.Timer1Timer(Sender: TObject);
begin
  if FXProgressBar1.Value<FXProgressBar1.MaxValue then
    FXProgressBar1.Value := FXProgressBar1.Value + 10
  else
    Timer1.Enabled:=False;
  Label2.Caption:=IntToStr(FXProgressBar1.Value) + '%';
end;

constructor TFrmPackage.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  FXProgressBar1.Hide;
end;

type TBCLabelHack = class(TCustomBCLabel);

procedure TFrmPackage.AdjustFont(ALabel: TBCLabel);
var
  PreferredWidth, PreferredHeight: integer;
  newfs:Integer;
begin
  With ALabel  do
  begin
    CalculateTextSize(Caption, FontEx, PreferredWidth, PreferredHeight);
    if FontEx.WordBreak then
    begin
      if (PreferredHeight > Height) then
        newfs := (Height  * FontEx.Height) div PreferredHeight
      else
        newfs := FontEx.Height;
    end
    else
    begin
      if (PreferredWidth > Width) then
        newfs := (Width  * FontEx.Height) div PreferredWidth
      else
        newfs := FontEx.Height;
    end;

    if newfs <> FontEx.Height then
      FontEx.Height := newfs;
  end;
end;

end.

