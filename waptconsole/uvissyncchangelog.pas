unit uvissyncchangelog;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  StdCtrls, sogrid, VirtualTrees;

type

  { TVisSyncChangelog }

  TVisSyncChangelog = class(TForm)
    Memo1: TMemo;
    GridChangelog: TSOGrid;
    Splitter1: TSplitter;
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
begin
  if Assigned(GridChangelog.FocusedRow) then
     Memo1.Caption:=GridChangelog.FocusedRow.O['changelog'].AsJSon(true,true);
end;

end.

