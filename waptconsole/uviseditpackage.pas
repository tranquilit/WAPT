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
    FIsUpdated: Boolean;
    function CheckUpdated: Boolean;
    procedure SetIsUpdated(AValue: Boolean);
    function GetIsUpdated: Boolean;
  private
    FDepends: String;
    function GetDepends: String;
    property IsUpdated: Boolean read GetIsUpdated write SetIsUpdated;
    procedure SetDepends(AValue: String);
  private
    FPackageRequest: String;
    FSourcePath: String;
    { private declarations }
    procedure GridLoadData(grid: TVirtualJSONListView; jsondata: String);
    procedure SetPackageRequest(AValue: String);
    procedure SetSourcePath(AValue: String);
    procedure TreeLoadData(tree: TVirtualJSONInspector; jsondata: String);
    property Depends:String read GetDepends write SetDepends;
  public
    { public declarations }
    waptpath:String;
    IsHost:Boolean;
    PackageEdited:ISuperObject;
    procedure EditPackage;
    property SourcePath:String read FSourcePath write SetSourcePath;
    property PackageRequest:String read FPackageRequest write SetPackageRequest;
  end;

function EditPackage(packagename:String):ISuperObject;
function EditHost(hostname:String):ISuperObject;

var
  VisEditPackage: TVisEditPackage;
  privateKeyPassword: String = '';
  waptServerPassword: String = '';
  waptServerUser: String = '';

implementation
uses LCLIntf,tisstrings,soutils,waptcommon,dmwaptpython,jwawinuser, uvisprivatekeyauth, strutils;
{$R *.lfm}

function EditPackage(packagename:String):ISuperObject;
begin
  with TVisEditPackage.Create(Nil) do
  try
    PackageRequest := packagename;
    if ShowModal=mrOK then
      result := PackageEdited
    else
      result := Nil;
  finally
    Free;
  end;
end;

function EditHost(hostname:String):ISuperObject;
begin
  with TVisEditPackage.Create(Nil) do
  try
    IsHost:=True;
    PackageRequest := hostname;
    if ShowModal=mrOK then
      result := PackageEdited
    else
      result := Nil;
  finally
    Free;
  end;
end;


{ TVisEditPackage }
procedure TVisEditPackage.cbShowLogClick(Sender: TObject);
begin
  if cbShowLog.Checked then
    DMPython.PythonEng.ExecString('logger.setLevel(logging.DEBUG)')
  else
    DMPython.PythonEng.ExecString('logger.setLevel(logging.WARNING)');
end;

procedure TVisEditPackage.EdSearchKeyPress(Sender: TObject; var Key: char);
begin
 if Key=#13 then
  begin
    EdSearch.SelectAll;
    ActSearchPackage.Execute;
  end;
end;

procedure TVisEditPackage.EdSectionChange(Sender: TObject);
begin
  FIsUpdated:=True;
end;

procedure TVisEditPackage.FormCloseQuery(Sender: TObject; var CanClose: boolean
  );
begin
  CanClose := CheckUpdated;

end;

function TVisEditPackage.CheckUpdated:Boolean;
var
  Rep,i: Integer;
  dsnames,msg:String;
begin
  Result := not IsUpdated ;
  if not Result then
  begin
    msg := 'Sauvegarder les modifications ?';
  	Rep := Application.MessageBox(pchar(msg), 'Confirmer',
  								 MB_APPLMODAL+MB_ICONQUESTION+MB_YESNOCANCEL);
  	if (Rep = IdYes) then
  		Result := ActEditSavePackage.Execute
  	else
  	  if (Rep = IdNo) then
  		  Result := True
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

procedure TVisEditPackage.EditPackage;
begin
  EdSourceDir.Text:=FSourcePath;
  EdPackage.Text:=PackageEdited.S['package'];
  EdVersion.Text:=PackageEdited.S['version'];
  EdDescription.Text:=PackageEdited.S['description'];
  EdSection.Text:=PackageEdited.S['section'];
  // get a list of package entries given a
  Depends:=PackageEdited.S['depends'];
  EdSetupPy.Lines.LoadFromFile(AppendPathDelim(FSourcePath)+'setup.py');
  IsUpdated := False;
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
  sel : TNodeArray;
  olddepends :ISuperObject;
  package : String;
begin
  olddepends := Split(Depends,',');
  sel := GridPackages.GetSortedSelection(False);
  for i:=0 to length(sel)-1 do
  begin
    package := GetValue(GridPackages,sel[i],'package');
    if not StrIn(package,olddepends) then
      olddepends.AsArray.Add(package);
  end;
  Depends:=Join(',',olddepends);
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
  Depends:=Depends;
end;

procedure TVisEditPackage.ActEditSavePackageExecute(Sender: TObject);
var
  i:integer;
  n:PVirtualNode;
begin
  Screen.Cursor:=crHourGlass;
  try
    PackageEdited.S['package'] := EdPackage.Text;
    PackageEdited.S['version'] := EdVersion.Text;
    PackageEdited.S['description'] := EdDescription.Text;
    PackageEdited.S['section'] := EdSection.Text;
    PackageEdited.S['depends'] := Depends;
    DMPython.PythonEng.ExecString('p = PackageEntry()');
    DMPython.PythonEng.ExecString(format('p.load_control_from_dict(json.loads(''%s''))',[PackageEdited.AsJson]));
    DMPython.PythonEng.ExecString(format('p.save_control_to_wapt(r''%s'')',[EdSourceDir.Text]));
    EdSetupPy.Lines.SaveToFile(AppendPathDelim(FSourcePath)+'setup.py');
    IsUpdated:=False;
  finally
    Screen.Cursor:=crDefault;
  end;
end;

procedure TVisEditPackage.ActEditSavePackageUpdate(Sender: TObject);
begin
  ActEditSavePackage.Enabled:=IsUpdated;
end;

function TVisEditPackage.GetIsUpdated:Boolean;
begin
   Result := FIsUpdated or EdPackage.Modified or EdVersion.Modified or EdSetupPy.Modified or EdSourceDir.Modified or Eddescription.Modified;
end;

procedure TVisEditPackage.ActEditSearchExecute(Sender: TObject);
var
  expr:UTF8String;
  packages:ISuperObject;
begin
  expr := format('mywapt.search("%s".split())',[EdSearch.Text]);
  packages := DMPython.RunJSON(expr);
  GridLoadData(GridPackages,packages.AsJSon);
end;

procedure TVisEditPackage.ActBuildUploadExecute(Sender: TObject);
var
  expr,res:String;
  package:String;
  result:ISuperObject;
  done : Boolean=False;
begin
  ActEditSavePackage.Execute;
  if privateKeyPassword = '' then
  begin
    With TvisPrivateKeyAuth.Create(Self) do
    try
      laKeyPath.Caption:= GetWaptPrivateKey;
      repeat
        if ShowModal=mrOk then
        begin
          privateKeyPassword := edPasswordKey.Text;
          done := True;
        end;
      until done;
    finally
      Free;
    end;
  end;
  result := DMPython.RunJSON(format('mywapt.build_upload(r"%s",r"%s",r"%s",r"%s")',[FSourcePath,privateKeyPassword,waptServerUser,waptServerPassword]),jsonlog);
  ModalResult:= mrOk;
end;

procedure TVisEditPackage.ActExecCodeExecute(Sender: TObject);
begin
  MemoLog.Clear;
  DMPython.PythonEng.ExecString(EdSetupPy.Lines.Text);
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


procedure TVisEditPackage.SetPackageRequest(AValue: String);
var
  res:ISuperObject;
begin
  if FPackageRequest=AValue then Exit;
  Screen.Cursor:=crHourGlass;
  try
    FPackageRequest:=AValue;
    if IsHost then
      res := DMPython.RunJSON(format('mywapt.edit_host("%s")',[FPackageRequest]))
    else
      res := DMPython.RunJSON(format('mywapt.edit_package("%s")',[FPackageRequest]));
    FSourcePath:= res.S['source_dir'];
    PackageEdited := res['package'];
  finally
    Screen.Cursor:=crDefault;
  end;
  EditPackage;
end;

procedure TVisEditPackage.SetSourcePath(AValue: String);
var
  res:ISuperObject;
begin
  if FSourcePath=AValue then Exit;
  FSourcePath:=AValue;
  try
    res := DMPython.RunJSON(format('mywapt.edit_package("%s")',[FSourcePath]));
    PackageEdited := res['package'];
  finally
    Screen.Cursor:=crDefault;
  end;
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

procedure TVisEditPackage.SetIsUpdated(AValue: Boolean);
begin
  FIsUpdated:=AValue;
  if not AValue then
  begin
    EdPackage.Modified:=False;
    Eddescription.Modified:=False;
    EdVersion.Modified:=False;
    EdSourceDir.Modified:=False;
    EdSetupPy.Modified:=False;
  end;
end;

procedure TVisEditPackage.SetDepends(AValue: String);
var
  dependencies:ISuperObject;
begin
  FDepends:=AValue;
  dependencies := DMPython.RunJSON(format('mywapt.get_package_entries("%s")',[FDepends]));
  GridLoadData(GridDepends,dependencies['packages'].AsJSon);
  if dependencies['missing'].AsArray.Length>0 then
    ShowMessageFmt('Attention, les paquets %s ont été ignorés car introuvables',[dependencies.S['missing']]);
  FIsUpdated:=True;
end;

function TVisEditPackage.GetDepends: String;
var
  n:PVirtualNode;
begin
  FDepends:='';
  n := GridDepends.GetFirst;
  while (n<>Nil) do
  begin
    if FDepends<>'' then
      FDepends:=FDepends+','+GetValue(GridDepends,n,'package')
    else
      FDepends:=GetValue(GridDepends,n,'package');
    n := GridDepends.GetNext(n)
  end;
  Result := FDepends;
end;

end.

