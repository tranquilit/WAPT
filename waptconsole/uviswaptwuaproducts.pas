unit uVisWAPTWUAProducts;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  Buttons, ActnList, StdCtrls, superobject,sogrid, VirtualTrees;

type

  { TVisWUAProducts }

  TVisWUAProducts = class(TForm)
    ActSave: TAction;
    ActionList1: TActionList;
    ButCancel: TBitBtn;
    ButSave: TBitBtn;
    cbOnlySelected: TCheckBox;
    EdKeywords: TEdit;
    GridData: TSOGrid;
    Label1: TLabel;
    Panel1: TPanel;
    Panel4: TPanel;
    procedure ActSaveExecute(Sender: TObject);
    procedure ActSaveUpdate(Sender: TObject);
    procedure EdKeywordsChange(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure GridDataChecked(Sender: TBaseVirtualTree; Node: PVirtualNode);
    procedure GridDataPaintText(Sender: TBaseVirtualTree;
      const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
      TextType: TVSTTextType);
  private
    FData: ISuperObject;
    function GetData: ISuperObject;
    procedure LoadSelection;
    procedure SaveData;
    procedure SetData(AValue: ISuperObject);
    procedure UpdateCheckbox;
    { private declarations }
  public
    { public declarations }
    Modified: Boolean;
    property Data:ISuperObject read GetData write SetData;
    function FilterData(FullData: ISuperObject): ISuperObject;
    procedure LoadData;
  end;

var
  VisWUAProducts: TVisWUAProducts;

implementation
uses waptcommon,soutils;
{$R *.lfm}

{ TVisWUAProducts }

procedure TVisWUAProducts.SetData(AValue: ISuperObject);
begin
  if FData=AValue then Exit;
  FData:=AValue;
end;

procedure TVisWUAProducts.ActSaveExecute(Sender: TObject);
begin
  SaveData;
  if not Modified then
    ModalResult:=mrOk;
end;

procedure TVisWUAProducts.ActSaveUpdate(Sender: TObject);
begin
  ActSave.Enabled:=Modified;
end;

procedure TVisWUAProducts.EdKeywordsChange(Sender: TObject);
begin
  GridData.Data := FilterData(data);
  UpdateCheckbox;
end;

procedure TVisWUAProducts.FormShow(Sender: TObject);
begin
  LoadData;
end;

procedure TVisWUAProducts.GridDataChecked(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
var
  row:ISuperObject;
  nodes:TNodeArray;
begin
  Modified:=True;
  if Node^.CheckState = csCheckedNormal then
  begin
    if GridData.SelectedCount=0 then
    begin
      row := GridData.GetNodeSOData(Node);
      if row<>Nil then
        row.B['selected'] := True;
    end
    else
    for row in GridData.SelectedRows do
    begin
      row.B['selected'] := true;
      GridData.InvalidateFordata(row);
    end;
  end
  else
  begin
    if GridData.SelectedCount=0 then
    begin
      row := GridData.GetNodeSOData(Node);
      if row<>Nil then
        row.delete('selected');
    end
    else
    for row in GridData.SelectedRows do
    begin
      row.Delete('selected');
      GridData.InvalidateFordata(row);
    end;
  end;
  UpdateCheckbox;
end;

procedure TVisWUAProducts.GridDataPaintText(Sender: TBaseVirtualTree;
  const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
  TextType: TVSTTextType);
begin
  if Node^.CheckState = csCheckedNormal then
    TargetCanvas.Font.Style:=TargetCanvas.Font.Style+[fsBold];
end;

function TVisWUAProducts.GetData: ISuperObject;
begin
  if FData = Nil then
  begin
    FData := TSuperObject.Create(stArray);
  end;
  Result := FData;
end;

function TVisWUAProducts.FilterData(FullData: ISuperObject): ISuperObject;
var
  row: ISuperObject;
  accept: boolean;
  nodes : TNodeArray;
begin
  Result := TSuperObject.Create(stArray);
  if (FullData = nil) or (FullData.AsArray = Nil) then
    Exit;
  for row in FullData do
  begin
    Accept := ((EdKeywords.Text='') or (pos(LowerCase(EdKeywords.Text),LowerCase(row.S['title']))>0)) and (not cbOnlySelected.Checked or row.B['selected']) ;
    if Accept then
      Result.AsArray.Add(row);
  end;

end;


procedure TVisWUAProducts.UpdateCheckbox;
var
  row,res,selection:ISuperObject;
  Nodes:TNodeArray;
begin
  for row in GridData.Data do
  begin
    nodes := GridData.NodesForData(row);
    if length(nodes)>0 then
      if row.B['selected'] then
        nodes[0]^.CheckState := csCheckedNormal
      else
        nodes[0]^.CheckState := csUncheckedNormal;
  end;
end;


procedure TVisWUAProducts.LoadSelection;
var
  row,res,selection:ISuperObject;
  Nodes:TNodeArray;
begin
  res := WAPTServerJsonGet('api/v2/windows_updates_options?key=products_selection',[]);
  if res.B['success'] and (res.A['result'].Length>0) then
    selection := res.A['result'][0]['value']
  else
    selection := TSuperObject.Create(stArray);

  for row in Data do
    if StrIn(row.S['product'],selection) then
      row.B['selected'] := True;

  Modified:=False;
end;

procedure TVisWUAProducts.LoadData;
var
  row,res,selection:ISuperObject;
begin
  Data.Clear;
  Data.Merge(WAPTServerJsonGet('api/v2/windows_products',[])['result']);
  GridData.Data := FilterData(Data);
  LoadSelection;
  UpdateCheckbox;
end;

procedure TVisWUAProducts.SaveData;
var
  row,res,selection: ISUperObject;
begin
  selection := TSuperObject.Create(stArray);
  for row in GridData.CheckedRows do
    selection.AsArray.Add(row['product']);
  Res := WAPTServerJsonPost('api/v2/windows_updates_options?key=products_selection',[],selection);
  if res.B['success'] then
    Modified := False;
end;


end.

