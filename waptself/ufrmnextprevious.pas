unit uFrmNextPrevious;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, ExtCtrls;

type

  { TFrmNextPrevious }

  TFrmNextPrevious = class(TFrame)
    LogoNextPrev: TImage;
    procedure LogoNextPrevClick(Sender: TObject);
    procedure LogoNextPrevMouseEnter(Sender: TObject);
    procedure LogoNextPrevMouseLeave(Sender: TObject);
  private

  public
    isNext:Boolean;
  end;

implementation

uses
  uVisWaptSelf;

{$R *.lfm}

{ TFrmNextPrevious }

procedure TFrmNextPrevious.LogoNextPrevClick(Sender: TObject);
begin
  if isNext then
    VisWaptSelf.TimerNextFrames.Enabled:=true
  else
    VisWaptSelf.TimerPreviousFrames.Enabled:=true;
end;

procedure TFrmNextPrevious.LogoNextPrevMouseEnter(Sender: TObject);
begin
  if isNext then
    LogoNextPrev.Picture.LoadFromResourceName(HINSTANCE,'FLECHE-BAS-BLEUE-100PX')
  else
    LogoNextPrev.Picture.LoadFromResourceName(HINSTANCE,'FLECHE-HAUT-BLEUE-100PX');
end;

procedure TFrmNextPrevious.LogoNextPrevMouseLeave(Sender: TObject);
begin
  if isNext then
    LogoNextPrev.Picture.LoadFromResourceName(HINSTANCE,'FLECHE-BAS-BLANC-100PX')
  else
    LogoNextPrev.Picture.LoadFromResourceName(HINSTANCE,'FLECHE-HAUT-BLANC-100PX');
end;

{ TFrmNextPrevious }


end.

