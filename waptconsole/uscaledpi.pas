unit UScaleDPI;

{$mode objfpc}{$H+}

interface

uses
  Forms, Controls, ComCtrls;

procedure HighDPI(FromDPI: Integer);
procedure ScaleDPI(Control: TControl; FromDPI: Integer);
procedure ScaleImageList(ImgList: TImageList; FromDPI: Integer);
function DoScaleX(Size: Integer; FromDPI: Integer): integer;
function DoScaleY(Size: Integer; FromDPI: Integer): integer;

implementation

uses Classes, Graphics, sogrid,vte_json;

procedure HighDPI(FromDPI: Integer);
var
  i: Integer;
begin
  for i:=0 to Screen.FormCount-1 do begin
    ScaleDPI(Screen.Forms[i],FromDPI);
  end;
end;

procedure ResizeBitmap(Bitmap: TBitmap; Width, Height: Integer; Background: TColor);
var
  R: TRect;
  B: TBitmap;
  X, Y: Integer;
begin
  if assigned(Bitmap) then begin
    B:= TBitmap.Create;
    try
      if Bitmap.Width > Bitmap.Height then begin
        R.Right:= Width;
        R.Bottom:= ((Width * Bitmap.Height) div Bitmap.Width);
        X:= 0;
        Y:= (Height div 2) - (R.Bottom div 2);
      end else begin
        R.Right:= ((Height * Bitmap.Width) div Bitmap.Height);
        R.Bottom:= Height;
        X:= (Width div 2) - (R.Right div 2);
        Y:= 0;
      end;
      R.Left:= 0;
      R.Top:= 0;
      B.PixelFormat:= Bitmap.PixelFormat;
      B.Width:= Width;
      B.Height:= Height;
      B.Canvas.Brush.Color:= Background;
      B.Canvas.FillRect(B.Canvas.ClipRect);
      B.Canvas.StretchDraw(R, Bitmap);
      Bitmap.Width:= Width;
      Bitmap.Height:= Height;
      Bitmap.Canvas.Brush.Color:= Background;
      Bitmap.Canvas.FillRect(Bitmap.Canvas.ClipRect);
      Bitmap.Canvas.Draw(X, Y, B);
    finally
      B.Free;
    end;
  end;
end;


procedure ScaleImageList(ImgList: TImageList; FromDPI: Integer);
var
  TempBmp: TBitmap;
  TempBGRA: array of TBitmap;
  NewWidth,NewHeight: integer;
  i: Integer;

begin
  if Screen.PixelsPerInch <= FromDPI*1.1 then exit;

  NewWidth := ScaleX(ImgList.Width,FromDPI);
  NewHeight := ScaleY(ImgList.Height,FromDPI);

  setlength(TempBGRA, ImgList.Count);
  for i := 0 to ImgList.Count-1 do
  begin
    TempBmp := TBitmap.Create;
    ImgList.GetBitmap(i,TempBmp);
    ResizeBitmap(TempBmp,NewWidth,NewHeight,clWhite);
    TempBGRA[i] := TempBmp;
  end;

  ImgList.Clear;
  ImgList.Width:= NewWidth;
  ImgList.Height:= NewHeight;

  for i := 0 to high(TempBGRA) do
  begin
    ImgList.Add(TempBGRA[i],nil);
    TempBGRA[i].Free;
  end;
end;

function DoScaleX(Size: Integer; FromDPI: Integer): integer;
begin
  if Screen.PixelsPerInch <= FromDPI then
    result := Size
  else
    result := ScaleX(Size, FromDPI);
end;

function DoScaleY(Size: Integer; FromDPI: Integer): integer;
begin
  if Screen.PixelsPerInch <= FromDPI then
    result := Size
  else
    result := ScaleY(Size, FromDPI);
end;

procedure ScaleDPI(Control: TControl; FromDPI: Integer);
var
  i,n: Integer;
  WinControl: TWinControl;
  ToolBarControl: TToolBar;
begin
  if Screen.PixelsPerInch <= FromDPI then exit;

  with Control do begin
    Left:=ScaleX(Left,FromDPI);
    Top:=ScaleY(Top,FromDPI);
    Width:=ScaleX(Width,FromDPI);
    Height:=ScaleY(Height,FromDPI);
    {$IFDEF LCL Qt}
      Font.Size := 0;
    {$ELSE}
      Font.Height := ScaleY(Font.GetTextHeight('Hg'),FromDPI);
    {$ENDIF}
  end;

  if Control is TToolBar then begin
    ToolBarControl:=TToolBar(Control);
    with ToolBarControl do begin
      ButtonWidth:=ScaleX(ButtonWidth,FromDPI);
      ButtonHeight:=ScaleY(ButtonHeight,FromDPI);
    end;
  end;

  if Control is TSOGrid then
  begin
    With Control as TSOGrid do
    begin
      DefaultNodeHeight := ScaleY(DefaultNodeHeight,FromDPI);
      Header.MinHeight:=ScaleY(Header.MinHeight,FromDPI);;
      Header.MaxHeight:=ScaleY(Header.MaxHeight,FromDPI);;
      Header.Height:=ScaleY(Header.Height,FromDPI);;
      Font.Height := 0;
      for i := 0 to header.Columns.Count-1 do
      begin
        header.Columns[i].MinWidth:=ScaleX(header.Columns[i].MinWidth,FromDPI);
        header.Columns[i].MaxWidth:=ScaleX(header.Columns[i].MaxWidth,FromDPI);
        header.Columns[i].Width:=ScaleX(header.Columns[i].Width,FromDPI);
      end;
    end;
  end;

  if Control is TVirtualJSONTreeView then
  begin
    With Control as TVirtualJSONTreeView do
    begin
      DefaultNodeHeight := ScaleY(DefaultNodeHeight,FromDPI);
      Header.MinHeight:=ScaleY(Header.MinHeight,FromDPI);;
      Header.MaxHeight:=ScaleY(Header.MaxHeight,FromDPI);;
      Header.Height:=ScaleY(Header.Height,FromDPI);;
      Font.Height := 0;
      for i := 0 to header.Columns.Count-1 do
      begin
        header.Columns[i].MinWidth:=ScaleX(header.Columns[i].MinWidth,FromDPI);
        header.Columns[i].MaxWidth:=ScaleX(header.Columns[i].MaxWidth,FromDPI);
        header.Columns[i].Width:=ScaleX(header.Columns[i].Width,FromDPI);
      end;
    end;
  end;

  if Control is TVirtualJSONInspector then
  begin
    With Control as TVirtualJSONInspector do
    begin
      DefaultNodeHeight := ScaleY(DefaultNodeHeight,FromDPI);
      Header.MinHeight:=ScaleY(Header.MinHeight,FromDPI);;
      Header.MaxHeight:=ScaleY(Header.MaxHeight,FromDPI);;
      Header.Height:=ScaleY(Header.Height,FromDPI);;
      Font.Height := 0;
      for i := 0 to header.Columns.Count-1 do
      begin
        header.Columns[i].MinWidth:=ScaleX(header.Columns[i].MinWidth,FromDPI);
        header.Columns[i].MaxWidth:=ScaleX(header.Columns[i].MaxWidth,FromDPI);
        header.Columns[i].Width:=ScaleX(header.Columns[i].Width,FromDPI);
      end;
    end;
  end;

  if Control is TVirtualJSONListView then
  begin
    With Control as TVirtualJSONListView do
    begin
      DefaultNodeHeight := ScaleY(DefaultNodeHeight,FromDPI);
      Header.MinHeight:=ScaleY(Header.MinHeight,FromDPI);;
      Header.MaxHeight:=ScaleY(Header.MaxHeight,FromDPI);;
      Header.Height:=ScaleY(Header.Height,FromDPI);;
      Font.Height := 0;
      for i := 0 to header.Columns.Count-1 do
      begin
        header.Columns[i].MinWidth:=ScaleX(header.Columns[i].MinWidth,FromDPI);
        header.Columns[i].MaxWidth:=ScaleX(header.Columns[i].MaxWidth,FromDPI);
        header.Columns[i].Width:=ScaleX(header.Columns[i].Width,FromDPI);
      end;
    end;
  end;


  if Control is TWinControl then begin
    WinControl:=TWinControl(Control);
    if WinControl.ControlCount > 0 then begin
      for n:=0 to WinControl.ControlCount-1 do begin
        if WinControl.Controls[n] is TControl then begin
          ScaleDPI(WinControl.Controls[n],FromDPI);
        end;
      end;
    end;
  end;
end;

end.
