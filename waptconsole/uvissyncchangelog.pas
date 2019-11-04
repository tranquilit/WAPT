unit uvissyncchangelog;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  StdCtrls, vte_json, sogrid, VirtualTrees, jsonparser;

type

  { TVisSyncChangelog }

  TVisSyncChangelog = class(TForm)
    GridChangelog: TSOGrid;
    GridJSONViewChangelog: TVirtualJSONInspector;
    Splitter1: TSplitter;
    procedure FormShow(Sender: TObject);
    procedure GridChangelogChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
  private

  public

  end;

var
  VisSyncChangelog: TVisSyncChangelog;

implementation

{$R *.lfm}

{ TVisSyncChangelog }

procedure TVisSyncChangelog.GridChangelogChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
var
  jsp:TJSONParser;
begin
  if Assigned(GridChangelog.FocusedRow) then
  begin
    try
       GridJSONViewChangelog.Clear;
       GridJSONViewChangelog.BeginUpdate;
       jsp := TJSONParser.Create(UTF8Encode(GridChangelog.FocusedRow.O['changelog'].AsJSon));
       if assigned(GridJSONViewChangelog.RootData) then
          GridJSONViewChangelog.rootdata.Free;
       GridJSONViewChangelog.rootData := jsp.Parse;
       jsp.Free;
    finally
       GridJSONViewChangelog.EndUpdate;
    end;
    GridJSONViewChangelog.FullExpand();
  end;
end;

procedure TVisSyncChangelog.FormShow(Sender: TObject);
begin
  if Screen.PixelsPerInch<>96 then
  begin
    GridJSONViewChangelog.Header.DefaultHeight:=trunc((GridJSONViewChangelog.Header.DefaultHeight*Screen.PixelsPerInch)/96);
    GridChangelog.Header.DefaultHeight:=trunc((GridChangelog.Header.DefaultHeight*Screen.PixelsPerInch)/96);
  end;
  MakeFullyVisible();
end;

end.

