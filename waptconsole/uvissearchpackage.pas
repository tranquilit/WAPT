unit uvissearchpackage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, memds, BufDataset, FileUtil, SynHighlighterPython, SynEdit,
  SynMemo, vte_edittree, vte_json, LSControls, Forms,
  Controls, Graphics, Dialogs, ExtCtrls, StdCtrls, ComCtrls, ActnList, Menus,
  EditBtn, Buttons, process, fpJson, jsonparser,
  superobject, UniqueInstance, VirtualTrees,VarPyth, types, ActiveX;

type

  { TVisSearchPackage }

  TVisSearchPackage = class(TForm)
    ActExecCode: TAction;
    ActBuildUpload: TAction;
    ActEditSearch: TAction;
    ActEditRemove: TAction;
    ActEditSavePackage: TAction;
    ActSearchPackage: TAction;
    ActionList1: TActionList;
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    butSearchPackages1: TButton;
    cbOnlyGroup: TCheckBox;
    cbShowLog: TCheckBox;
    EdSearch: TEdit;
    GridPackages: TVirtualJSONListView;
    MemoLog: TMemo;
    MenuItem4: TMenuItem;
    Panel3: TPanel;
    Panel4: TPanel;
    Panel7: TPanel;
    Panel8: TPanel;
    Panel9: TPanel;
    PopupMenuEditDepends: TPopupMenu;
    Splitter1: TSplitter;
    Splitter2: TSplitter;
    jsonlog: TVirtualJSONInspector;
    procedure ActBuildUploadExecute(Sender: TObject);
    procedure ActEditRemoveExecute(Sender: TObject);
    procedure ActEditSavePackageExecute(Sender: TObject);
    procedure ActEditSavePackageUpdate(Sender: TObject);
    procedure ActEditSearchExecute(Sender: TObject);
    procedure ActExecCodeExecute(Sender: TObject);
    procedure ActSearchPackageExecute(Sender: TObject);
    procedure cbShowLogClick(Sender: TObject);
    procedure EdSearchKeyPress(Sender: TObject; var Key: char);
    procedure EdSectionChange(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure GridDependsDragDrop(Sender: TBaseVirtualTree; Source: TObject;
      DataObject: IDataObject; Formats: TFormatArray; Shift: TShiftState;
      const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
    procedure GridDependsDragOver(Sender: TBaseVirtualTree; Source: TObject;
      Shift: TShiftState; State: TDragState; const Pt: TPoint; Mode: TDropMode;
      var Effect: DWORD; var Accept: Boolean);
    procedure GridPackagesCompareNodes(Sender: TBaseVirtualTree; Node1,
      Node2: PVirtualNode; Column: TColumnIndex; var Result: Integer);
    procedure GridPackagesHeaderClick(Sender: TVTHeader;
      HitInfo: TVTHeaderHitInfo);
  private
  private
  private
    { private declarations }
    procedure GridLoadData(grid: TVirtualJSONListView; jsondata: String);
    procedure TreeLoadData(tree: TVirtualJSONInspector; jsondata: String);
  public
    { public declarations }
  end;

var
  VisSearchPackage: TVisSearchPackage;

implementation
uses LCLIntf,tisstrings,soutils,waptcommon,dmwaptpython,jwawinuser;
{$R *.lfm}

{ TVisSearchPackage }
procedure TVisSearchPackage.cbShowLogClick(Sender: TObject);
begin
  if cbShowLog.Checked then
    DMPython.PythonEng.ExecString('logger.setLevel(logging.DEBUG)')
  else
    DMPython.PythonEng.ExecString('logger.setLevel(logging.WARNING)');
end;

procedure TVisSearchPackage.EdSearchKeyPress(Sender: TObject; var Key: char);
begin
 if Key=#13 then
  begin
    EdSearch.SelectAll;
    ActSearchPackage.Execute;
  end;
end;

procedure TVisSearchPackage.EdSectionChange(Sender: TObject);
begin
end;

procedure TVisSearchPackage.FormCloseQuery(Sender: TObject; var CanClose: boolean
  );
begin
end;

function GetValue(ListView:TVirtualJSONListView;N:PVirtualNode;FieldName:String;Default:String=''):String;
begin
  result := TJSONObject(ListView.GetData(N)).get(FieldName,Default);
end;

procedure SetValue(ListView:TVirtualJSONListView;N:PVirtualNode;FieldName:String;Value:String);
var
  js : TJSONData;
begin
  TJSONObject(ListView.GetData(N)).Add(FieldName,Value);
end;

function gridFind(grid:TVirtualJSONListView;Fieldname,AText:String):PVirtualNode;
var
  n : PVirtualNode;
begin
  result := Nil;
  n := grid.GetFirst;
  while n<>Nil do
  begin
    if GetValue(grid,n,Fieldname)=AText then
    begin
      Result := n;
      Break;
    end;
    n := grid.GetNext(n);
  end;
end;

procedure TVisSearchPackage.GridDependsDragDrop(Sender: TBaseVirtualTree;
  Source: TObject; DataObject: IDataObject; Formats: TFormatArray;
  Shift: TShiftState; const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
begin
end;

procedure TVisSearchPackage.GridDependsDragOver(Sender: TBaseVirtualTree;
  Source: TObject; Shift: TShiftState; State: TDragState; const Pt: TPoint;
  Mode: TDropMode; var Effect: DWORD; var Accept: Boolean);
begin
  Accept := Source = GridPackages;
end;

procedure TVisSearchPackage.ActEditRemoveExecute(Sender: TObject);
begin
end;

procedure TVisSearchPackage.ActEditSavePackageExecute(Sender: TObject);
begin
end;

procedure TVisSearchPackage.ActEditSavePackageUpdate(Sender: TObject);
begin
end;

procedure TVisSearchPackage.ActEditSearchExecute(Sender: TObject);
begin
end;

procedure TVisSearchPackage.ActBuildUploadExecute(Sender: TObject);
begin
end;

procedure TVisSearchPackage.ActExecCodeExecute(Sender: TObject);
begin
end;

procedure TVisSearchPackage.ActSearchPackageExecute(Sender: TObject);
var
  expr,res:UTF8String;
  packages,package:ISuperObject;
  jsp : TJSONParser;
begin
  expr := format('mywapt.search("%s".split())',[EdSearch.Text]);
  packages := DMPython.RunJSON(expr);
  GridLoadData(GridPackages,packages.AsJSon);
end;

procedure TVisSearchPackage.FormCreate(Sender: TObject);
begin
  GridPackages.Clear;
  MemoLog.Clear;
end;

procedure TVisSearchPackage.GridLoadData(grid:TVirtualJSONListView;jsondata:string);
var
  jsp : TJSONParser;
begin
  grid.Clear;
  if (jsondata<>'')  then
  try
    grid.BeginUpdate;
    jsp := TJSONParser.Create(jsondata);
    if assigned(grid.Data) then
       grid.data.Free;
    grid.Data := jsp.Parse;
    grid.LoadData;
    grid.Header.AutoFitColumns;
    jsp.Free;
  finally
    grid.EndUpdate;
  end;
end;

procedure TVisSearchPackage.TreeLoadData(tree:TVirtualJSONInspector;jsondata:String);
var
  jsp : TJSONParser;

begin
  tree.Clear;
  if (jsondata<>'')  then
  try
    tree.BeginUpdate;
    jsp := TJSONParser.Create(jsondata);
    if assigned(tree.RootData) then
       tree.rootdata.Free;
    tree.rootData := jsp.Parse;
    jsp.Free;
  finally
    tree.EndUpdate;
  end;
end;



function CompareVersion(v1,v2:String):integer;
begin
end;

procedure TVisSearchPackage.GridPackagesCompareNodes(Sender: TBaseVirtualTree; Node1,
  Node2: PVirtualNode; Column: TColumnIndex; var Result: Integer);
var
  propname : String;
begin
  if column>=0 then
    propname := TVirtualJSONListViewColumn(TVirtualJSONListView(Sender).Header.Columns[Column]).PropertyName
  else
    propname := 'name';
  Result := CompareText(
  GetValue(TVirtualJSONListView(Sender),Node1,propname),
  GetValue(TVirtualJSONListView(Sender),Node2,propname));
end;

procedure TVisSearchPackage.GridPackagesHeaderClick(Sender: TVTHeader;
  HitInfo: TVTHeaderHitInfo);
begin
  if Sender.SortColumn <> HitInfo.Column then
    Sender.SortColumn := HitInfo.Column
  else
    if Sender.SortDirection=sdAscending then
      Sender.SortDirection:=sdDescending
    else
      Sender.SortDirection:=sdAscending;
  Sender.Treeview.Invalidate;
end;

end.

