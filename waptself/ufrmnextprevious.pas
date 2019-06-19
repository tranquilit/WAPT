unit uFrmNextPrevious;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, ExtCtrls;

type

  { TFrmNextPrevious }

  TFrmNextPrevious = class(TFrame)
    LabPage: TLabel;
    LogoNext: TImage;
    LogoPrev: TImage;
    PanelNextOrev: TPanel;
    procedure LogoNextClick(Sender: TObject);
    procedure LogoNextMouseEnter(Sender: TObject);
    procedure LogoNextMouseLeave(Sender: TObject);
    procedure LogoPrevClick(Sender: TObject);
    procedure LogoPrevMouseEnter(Sender: TObject);
    procedure LogoPrevMouseLeave(Sender: TObject);
  private

  public
    constructor Create(TheOwner: TComponent); override;
  end;

implementation

uses
  Graphics, uVisWaptSelf;

{$R *.lfm}

{ TFrmNextPrevious }

procedure TFrmNextPrevious.LogoNextClick(Sender: TObject);
begin
  VisWaptSelf.TimerNextFrames.Enabled:=true;
end;

procedure TFrmNextPrevious.LogoNextMouseEnter(Sender: TObject);
begin
  Screen.Cursor:=crHandPoint;
end;

procedure TFrmNextPrevious.LogoNextMouseLeave(Sender: TObject);
begin
  Screen.Cursor:=crDefault;
end;

procedure TFrmNextPrevious.LogoPrevClick(Sender: TObject);
begin
  VisWaptSelf.TimerPreviousFrames.Enabled:=true;
end;

procedure TFrmNextPrevious.LogoPrevMouseEnter(Sender: TObject);
begin
  Screen.Cursor:=crHandPoint;
end;

procedure TFrmNextPrevious.LogoPrevMouseLeave(Sender: TObject);
begin
  Screen.Cursor:=crDefault;
end;

constructor TFrmNextPrevious.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  if Screen.PixelsPerInch <> 96 then
    begin
       LogoNext.AutoSize:=false;
       LogoNext.AntialiasingMode:=amOn;
       LogoPrev.AutoSize:=false;
       LogoPrev.AntialiasingMode:=amOn;
    end;
end;

{ TFrmNextPrevious }


end.

