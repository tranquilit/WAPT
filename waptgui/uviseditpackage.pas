unit uviseditpackage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, memds, BufDataset, FileUtil, SynHighlighterPython, SynEdit,
  SynMemo, vte_edittree, vte_json, LSControls, Forms,
  Controls, Graphics, Dialogs, ExtCtrls, StdCtrls, ComCtrls, ActnList, Menus,
  EditBtn, Buttons, process, fpJson, jsonparser,
  superobject, UniqueInstance, VirtualTrees,VarPyth, types, ActiveX;

type

  { TVisEditPackage }

  TVisEditPackage = class(TForm)
    ActExecCode: TAction;
    ActBuildUpload: TAction;
    ActEditSearch: TAction;
    ActEditRemove: TAction;
    ActEditSavePackage: TAction;
    ActSearchPackage: TAction;
    ActionList1: TActionList;
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    butInitWapt: TButton;
    butSearchPackages1: TButton;
    Button3: TButton;
    Button4: TButton;
    Button5: TButton;
    cbShowLog: TCheckBox;
    Eddescription: TEdit;
    EdPackage: TEdit;
    EdSearch: TEdit;
    EdSection: TComboBox;
    EdSourceDir: TEdit;
    EdVersion: TEdit;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    GridDepends: TVirtualJSONListView;
    GridPackages: TVirtualJSONListView;
    MemoLog: TMemo;
    MenuItem4: TMenuItem;
    PageControl1: TPageControl;
    Panel1: TPanel;
    Panel2: TPanel;
    Panel3: TPanel;
    Panel4: TPanel;
    Panel7: TPanel;
    Panel8: TPanel;
    Panel9: TPanel;
    PopupMenuEditDepends: TPopupMenu;
    Splitter1: TSplitter;
    Splitter2: TSplitter;
    Splitter3: TSplitter;
    SynPythonSyn1: TSynPythonSyn;
    TabSheet1: TTabSheet;
    pgEditPackage: TTabSheet;
    EdSetupPy: TSynEdit;
    jsonlog: TVirtualJSONInspector;
    procedure ActBuildUploadExecute(Sender: TObject);
    procedure ActCreateCertificateExecute(Sender: TObject);
    procedure ActCreateWaptSetupExecute(Sender: TObject);
    procedure ActEditHostPackageExecute(Sender: TObject);
    procedure ActEditpackageExecute(Sender: TObject);
    procedure ActEditRemoveExecute(Sender: TObject);
    procedure ActEditSavePackageExecute(Sender: TObject);
    procedure ActEditSearchExecute(Sender: TObject);
    procedure ActEvaluateExecute(Sender: TObject);
    procedure ActEvaluateVarExecute(Sender: TObject);
    procedure ActExecCodeExecute(Sender: TObject);
    procedure actHostSelectAllExecute(Sender: TObject);
    procedure ActInstallExecute(Sender: TObject);
    procedure ActRegisterHostExecute(Sender: TObject);
    procedure ActRemoveExecute(Sender: TObject);
    procedure ActSearchHostExecute(Sender: TObject);
    procedure ActSearchPackageExecute(Sender: TObject);
    procedure ActUpdateExecute(Sender: TObject);
    procedure ActUpgradeExecute(Sender: TObject);
    procedure cbShowLogClick(Sender: TObject);
    procedure EdRunKeyPress(Sender: TObject; var Key: char);
    procedure EdSearchKeyPress(Sender: TObject; var Key: char);
    procedure FormCreate(Sender: TObject);
    procedure GridHostsChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
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
    procedure GridPackagesPaintText(Sender: TBaseVirtualTree;
      const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
      TextType: TVSTTextType);
  private
    FPackageRequest: String;
    FSourcePath: String;
    { private declarations }
    procedure GridLoadData(grid: TVirtualJSONListView; jsondata: String);
    procedure PythonOutputSendData(Sender: TObject; const Data: AnsiString);
    procedure SetPackageRequest(AValue: String);
    procedure SetSourcePath(AValue: String);
    procedure TreeLoadData(tree: TVirtualJSONInspector; jsondata: String);
  public
    { public declarations }
    waptpath:String;
    PackageEdited:ISuperObject;
    procedure EditPackage;
    procedure PostPackage;
    property SourcePath:String read FSourcePath write SetSourcePath;
    property PackageRequest:String read FPackageRequest write SetPackageRequest;
  end;

var
  VisEditPackage: TVisEditPackage;

implementation
uses LCLIntf,tisstrings,soutils,waptcommon,dmwaptpython;
{$R *.lfm}

{ TVisEditPackage }
procedure TVisEditPackage.cbShowLogClick(Sender: TObject);
begin
  if cbShowLog.Checked then
    DMPython.PythonEng.ExecString('logger.setLevel(logging.DEBUG)')
  else
    DMPython.PythonEng.ExecString('logger.setLevel(logging.WARNING)');

end;

procedure TVisEditPackage.EdRunKeyPress(Sender: TObject; var Key: char);
begin
end;

procedure TVisEditPackage.EdSearchKeyPress(Sender: TObject; var Key: char);
begin
 if Key=#13 then
  begin
    EdSearch.SelectAll;
    ActSearchPackage.Execute;
  end;
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

procedure TVisEditPackage.ActInstallExecute(Sender: TObject);
begin
end;

procedure TVisEditPackage.ActRegisterHostExecute(Sender: TObject);
begin
end;

procedure TVisEditPackage.ActEditpackageExecute(Sender: TObject);
begin
end;

procedure TVisEditPackage.EditPackage;
var
  dependencies:ISuperObject;
  dep:String;
begin
  EdSourceDir.Text:=PackageEdited.S['target'];
  EdPackage.Text:=PackageEdited['package'].S['package'];
  EdVersion.Text:=PackageEdited['package'].S['version'];
  EdDescription.Text:=PackageEdited['package'].S['description'];
  EdSection.Text:=PackageEdited['package'].S['section'];
  dep := PackageEdited.S['package.depends'];
  //FillEditLstDepends(PackageEdited.S['package.depends']);
  dependencies := DMPython.RunJSON(format('mywapt.get_package_entries("%s")',[EdPackage.Text]));
  GridLoadData(GridDepends,dependencies['packages'].AsJSon);
end;

procedure TVisEditPackage.PostPackage;
begin

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

procedure TVisEditPackage.GridDependsDragDrop(Sender: TBaseVirtualTree;
  Source: TObject; DataObject: IDataObject; Formats: TFormatArray;
  Shift: TShiftState; const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
var
  i:integer;
  li : TListItem;
  jsonObject:TJSONObject;
begin
  {for i:=0 to GridPackages.Items.Count-1 do
  begin
    if GridPackages.Items[i].Selected then
    begin
      if gridFind(GridDepends,'package',GridPackages.Items[i].Caption)=Nil then
      begin
        jsonObject := TJSONObject.Create([
          'package',GridPackages.Items[i].Caption,
          'description',GridPackages.Items[i].SubItems[1],
          'depends',GridPackages.Items[i].SubItems[2]
          ]);
        TJSONArray(GridDepends.Data).Add(jsonObject);
      end;
    end;
  end;}
  GridDepends.LoadData;
end;

procedure TVisEditPackage.GridDependsDragOver(Sender: TBaseVirtualTree;
  Source: TObject; Shift: TShiftState; State: TDragState; const Pt: TPoint;
  Mode: TDropMode; var Effect: DWORD; var Accept: Boolean);
begin
  Accept := Source = GridPackages;
end;

procedure TVisEditPackage.ActEditRemoveExecute(Sender: TObject);
begin
  GridDepends.DeleteSelectedNodes;
end;

procedure TVisEditPackage.ActEditSavePackageExecute(Sender: TObject);
var
  Depends:String;
  i:integer;
  n:PVirtualNode;
begin
  Screen.Cursor:=crHourGlass;
  try
    PackageEdited.S['package.package'] := EdPackage.Text;
    PackageEdited.S['package.version'] := EdVersion.Text;
    PackageEdited.S['package.description'] := EdDescription.Text;
    PackageEdited.S['package.section'] := EdSection.Text;
    Depends:='';
    n := GridDepends.GetFirst;
    while (n<>Nil) do
    begin
      if Depends<>'' then
        Depends:=Depends+','+GetValue(GridDepends,n,'package')
      else
        Depends:=GetValue(GridDepends,n,'package');
      n := GridDepends.GetNextSelected(n)
    end;

    PackageEdited.S['package.depends'] := depends;
    DMPython.PythonEng.ExecString('p = PackageEntry()');
    DMPython.PythonEng.ExecString(format('p.load_control_from_dict(json.loads(''%s''))',[PackageEdited['package'].AsJson]));
    DMPython.PythonEng.ExecString(format('p.save_control_to_wapt(r''%s'')',[EdSourceDir.Text]));
  finally
    Screen.Cursor:=crDefault;
  end;
end;

procedure TVisEditPackage.ActEditSearchExecute(Sender: TObject);
begin
end;

procedure TVisEditPackage.ActBuildUploadExecute(Sender: TObject);
var
  expr,res:String;
  package:String;
  result:ISuperObject;
begin
  ActEditSavePackage.Execute;
  result := DMPython.RunJSON(format('mywapt.build_upload(r"%s")',[EdSourceDir.Text]),jsonlog);

end;

procedure TVisEditPackage.ActCreateCertificateExecute(Sender: TObject);
begin
end;

procedure TVisEditPackage.ActCreateWaptSetupExecute(Sender: TObject);
begin
end;

procedure TVisEditPackage.ActEditHostPackageExecute(Sender: TObject);
begin
end;

procedure TVisEditPackage.ActEvaluateExecute(Sender: TObject);
begin
end;

procedure TVisEditPackage.ActEvaluateVarExecute(Sender: TObject);
begin
end;

procedure TVisEditPackage.ActExecCodeExecute(Sender: TObject);
begin
  MemoLog.Clear;
  DMPython.PythonEng.ExecString(EdSetupPy.Lines.Text);
end;

procedure TVisEditPackage.actHostSelectAllExecute(Sender: TObject);
begin
end;

procedure TVisEditPackage.ActRemoveExecute(Sender: TObject);
begin
end;

procedure TVisEditPackage.ActSearchHostExecute(Sender: TObject);
begin
end;

procedure TVisEditPackage.ActSearchPackageExecute(Sender: TObject);
var
  expr,res:UTF8String;
  packages,package:ISuperObject;
  jsp : TJSONParser;
begin
  expr := format('mywapt.search("%s".split())',[EdSearch.Text]);
  packages := DMPython.RunJSON(expr);
  GridLoadData(GridPackages,packages.AsJSon);
end;

procedure TVisEditPackage.ActUpdateExecute(Sender: TObject);
begin
end;

procedure TVisEditPackage.ActUpgradeExecute(Sender: TObject);
begin
end;


procedure TVisEditPackage.FormCreate(Sender: TObject);
begin
  GridPackages.Clear;
  MemoLog.Clear;

  GridDepends.Clear;
end;

procedure TVisEditPackage.GridLoadData(grid:TVirtualJSONListView;jsondata:string);
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

procedure TVisEditPackage.TreeLoadData(tree:TVirtualJSONInspector;jsondata:String);
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


procedure TVisEditPackage.GridHostsChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
end;

procedure TVisEditPackage.PythonOutputSendData(Sender: TObject; const Data: AnsiString
  );
begin
end;

procedure TVisEditPackage.SetPackageRequest(AValue: String);
begin
  if FPackageRequest=AValue then Exit;
  FPackageRequest:=AValue;
  PackageEdited := DMPython.RunJSON(format('mywapt.edit_package("%s")',[AValue]))['package'];
  EditPackage;
end;

procedure TVisEditPackage.SetSourcePath(AValue: String);
begin
  if FSourcePath=AValue then Exit;
  FSourcePath:=AValue;
  PackageEdited := DMPython.RunJSON(format('mywapt.edit_package("%s")',[FSourcePath]))['package'];
  EditPackage;
end;

function CompareVersion(v1,v2:String):integer;
begin
end;

procedure TVisEditPackage.GridPackagesCompareNodes(Sender: TBaseVirtualTree; Node1,
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

procedure TVisEditPackage.GridPackagesHeaderClick(Sender: TVTHeader;
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

procedure TVisEditPackage.GridPackagesPaintText(Sender: TBaseVirtualTree;
  const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
  TextType: TVSTTextType);
begin
end;


end.

