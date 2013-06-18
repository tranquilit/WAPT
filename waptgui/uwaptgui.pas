unit uwaptgui;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, memds, BufDataset, FileUtil, SynHighlighterPython, SynEdit,
  SynMemo, vte_edittree, vte_json, LSControls, Forms,
  Controls, Graphics, Dialogs, ExtCtrls, StdCtrls, ComCtrls, ActnList, Menus,
  EditBtn, process, fpJson, jsonparser,
  superobject, UniqueInstance, VirtualTrees,VarPyth, types, ActiveX;

type

  { TVisWaptGUI }

  TVisWaptGUI = class(TForm)
    ActInstall: TAction;
    ActEditpackage: TAction;
    ActExecCode: TAction;
    ActEvaluate: TAction;
    ActBuildUpload: TAction;
    ActEditSearch: TAction;
    ActEditRemove: TAction;
    ActEditSavePackage: TAction;
    ActCreateCertificate: TAction;
    ActCreateWaptSetup: TAction;
    ActEvaluateVar: TAction;
    ActEditHostPackage: TAction;
    ActRegisterHost: TAction;
    ActSearchHost: TAction;
    ActUpgrade: TAction;
    ActUpdate: TAction;
    ActRemove: TAction;
    ActSearchPackage: TAction;
    ActionList1: TActionList;
    BufDataset1: TBufDataset;
    butInitWapt: TButton;
    butRun: TButton;
    butSearchPackages: TButton;
    butSearchPackages1: TButton;
    Button1: TButton;
    Button2: TButton;
    Button3: TButton;
    Button4: TButton;
    Button5: TButton;
    Button6: TButton;
    Button7: TButton;
    Button8: TButton;
    cbShowLog: TCheckBox;
    CheckBox1: TCheckBox;
    CheckBox2: TCheckBox;
    EdSearchHost: TEdit;
    EdSection: TComboBox;
    Eddescription: TEdit;
    EdSearch1: TEdit;
    EdSourceDir: TEdit;
    EdPackage: TEdit;
    EdVersion: TEdit;
    EdRun: TEdit;
    EdSearch: TEdit;
    GridHosts: TVirtualJSONListView;
    GridhostAttribs: TVirtualJSONInspector;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    lstPackages1: TListView;
    lstDepends: TVirtualJSONListView;
    MainMenu1: TMainMenu;
    Memo1: TMemo;
    MenuItem1: TMenuItem;
    MenuItem10: TMenuItem;
    MenuItem11: TMenuItem;
    MenuItem12: TMenuItem;
    MenuItem13: TMenuItem;
    MenuItem14: TMenuItem;
    MenuItem15: TMenuItem;
    MenuItem16: TMenuItem;
    MenuItem17: TMenuItem;
    MenuItem18: TMenuItem;
    MenuItem2: TMenuItem;
    MenuItem3: TMenuItem;
    MenuItem4: TMenuItem;
    MenuItem5: TMenuItem;
    MenuItem6: TMenuItem;
    MenuItem7: TMenuItem;
    MenuItem8: TMenuItem;
    MenuItem9: TMenuItem;
    PageControl1: TPageControl;
    HostPages: TPageControl;
    Panel1: TPanel;
    Panel10: TPanel;
    Panel2: TPanel;
    Panel3: TPanel;
    Panel4: TPanel;
    Panel7: TPanel;
    Panel8: TPanel;
    Panel9: TPanel;
    PopupMenuHosts: TPopupMenu;
    PopupMenuPackages: TPopupMenu;
    PopupMenuEditDepends: TPopupMenu;
    Splitter1: TSplitter;
    Splitter2: TSplitter;
    Splitter3: TSplitter;
    Splitter4: TSplitter;
    SynPythonSyn1: TSynPythonSyn;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    pgEditPackage: TTabSheet;
    pgInventory: TTabSheet;
    pgPackages: TTabSheet;
    pgSoftwares: TTabSheet;
    pgHostPackage: TTabSheet;
    testedit: TSynEdit;
    jsonlog: TVirtualJSONInspector;
    UniqueInstance1: TUniqueInstance;
    lstPackages: TVirtualJSONListView;
    GridHostPackages: TVirtualJSONListView;
    GridHostSoftwares: TVirtualJSONListView;
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
    procedure ActInstallExecute(Sender: TObject);
    procedure ActRegisterHostExecute(Sender: TObject);
    procedure ActRemoveExecute(Sender: TObject);
    procedure ActSearchHostExecute(Sender: TObject);
    procedure ActSearchPackageExecute(Sender: TObject);
    procedure ActUpdateExecute(Sender: TObject);
    procedure ActUpgradeExecute(Sender: TObject);
    procedure cbShowLogClick(Sender: TObject);
    procedure EdRunKeyPress(Sender: TObject; var Key: char);
    procedure EdSearch1KeyPress(Sender: TObject; var Key: char);
    procedure EdSearchKeyPress(Sender: TObject; var Key: char);
    procedure FormCreate(Sender: TObject);
    procedure GridHostsChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
    procedure lstDependsDragDrop(Sender: TBaseVirtualTree; Source: TObject;
      DataObject: IDataObject; Formats: TFormatArray; Shift: TShiftState;
      const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
    procedure lstDependsDragOver(Sender: TBaseVirtualTree; Source: TObject;
      Shift: TShiftState; State: TDragState; const Pt: TPoint; Mode: TDropMode;
      var Effect: DWORD; var Accept: Boolean);
    procedure lstPackagesCompareNodes(Sender: TBaseVirtualTree; Node1,
      Node2: PVirtualNode; Column: TColumnIndex; var Result: Integer);
    procedure lstPackagesHeaderClick(Sender: TVTHeader;
      HitInfo: TVTHeaderHitInfo);
    procedure lstPackagesPaintText(Sender: TBaseVirtualTree;
      const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
      TextType: TVSTTextType);
  private
    { private declarations }
    procedure EditPackage(PackageEntry:ISuperObject);
    procedure GridLoadData(grid: TVirtualJSONListView; jsondata: String);
    procedure PythonOutputSendData(Sender: TObject; const Data: AnsiString);
    procedure TreeLoadData(tree: TVirtualJSONInspector; jsondata: String);
  public
    { public declarations }
    PackageEdited:ISuperObject;
    waptpath:String;
  end;

var
  VisWaptGUI: TVisWaptGUI;

implementation
uses LCLIntf,tisstrings,soutils,waptcommon,uVisCreateKey,dmwaptpython;
{$R *.lfm}

{ TVisWaptGUI }
function StrToken(var S: string; Separator: Char): string;
var
  I: SizeInt;
begin
  I := Pos(Separator, S);
  if I <> 0 then
  begin
    Result := Copy(S, 1, I - 1);
    Delete(S, 1, I);
  end
  else
  begin
    Result := S;
    S := '';
  end;
end;



procedure TVisWaptGUI.cbShowLogClick(Sender: TObject);
begin
  if cbShowLog.Checked then
    DMPython.PythonEng.ExecString('logger.setLevel(logging.DEBUG)')
  else
    DMPython.PythonEng.ExecString('logger.setLevel(logging.WARNING)');

end;

procedure TVisWaptGUI.EdRunKeyPress(Sender: TObject; var Key: char);
begin
  if Key=#13 then
    ActEvaluate.Execute;
end;

procedure TVisWaptGUI.EdSearch1KeyPress(Sender: TObject; var Key: char);
begin
  if Key=#13 then
   begin
     EdSearch1.SelectAll;
     ActEditSearch.Execute;
   end;
end;

procedure TVisWaptGUI.EdSearchKeyPress(Sender: TObject; var Key: char);
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

procedure TVisWaptGUI.ActInstallExecute(Sender: TObject);
var
  expr,res:String;
  package:String;
  i:integer;
  N : PVirtualNode;
begin
  if lstPackages.Focused then
  begin
    N := lstPackages.GetFirstSelected;
    while N<>Nil do
    begin
      package := GetValue(lstPackages,N,'package')+' (='+GetValue(lstPackages,N,'version')+')';
      DMPython.RunJSON(format('mywapt.install("%s")',[package]),jsonlog);
      N := lstPackages.GetNextSelected(N);
    end;
    ActSearchPackage.Execute;
  end;
end;

procedure TVisWaptGUI.ActRegisterHostExecute(Sender: TObject);
begin
  DMPython.RunJSON('mywapt.register_computer()',jsonlog);
end;

procedure TVisWaptGUI.ActEditpackageExecute(Sender: TObject);
var
  expr,res,depends,dep:String;
  package:String;
  result:ISuperObject;
  N : PVirtualNode;
begin
  if lstPackages.Focused then
  begin
    N := lstPackages.GetFirstSelected;
    package := GetValue(lstPackages,N,'package');
    result := DMPython.RunJSON(format('mywapt.edit_package("%s")',[package]),jsonlog);
    EditPackage(result);
    PageControl1.ActivePage := pgEditPackage;
  end;
end;

procedure TVisWaptGUI.EditPackage(PackageEntry:ISuperObject);
var
  dependencies:ISuperObject;
  dep:String;
begin
  PackageEdited := PackageEntry;
  EdSourceDir.Text:=PackageEdited.S['target'];
  EdPackage.Text:=PackageEdited['package'].S['package'];
  EdVersion.Text:=PackageEdited['package'].S['version'];
  EdDescription.Text:=PackageEdited['package'].S['description'];
  EdSection.Text:=PackageEdited['package'].S['section'];
  dep := PackageEdited.S['package.depends'];
  //FillEditLstDepends(PackageEdited.S['package.depends']);
  dependencies := DMPython.RunJSON(format('mywapt.dependencies("%s")',[EdPackage.Text]));
  GridLoadData(lstDepends,dependencies.AsJSon);

end;

{
procedure TVisWaptGUI.lstDependsDragDrop(Sender, Source: TObject; X, Y: Integer
  );
var
  i:integer;
  li : TListItem;
begin
  for i:=0 to lstPackages1.Items.Count-1 do
  begin
    if lstPackages1.Items[i].Selected then
    begin
      li := lstDepends.Items.FindCaption(0,lstPackages1.Items[i].Caption,False,False,False);
      if li=Nil then
      begin
        li := lstDepends.Items.Add;
        li.Caption:=lstPackages1.Items[i].Caption;
        li.SubItems.Append(lstPackages1.Items[i].SubItems[0]);
        li.SubItems.Append(lstPackages1.Items[i].SubItems[1]);
        li.SubItems.Append(lstPackages1.Items[i].SubItems[2]);
      end;
      li.Selected:=True;
    end;
  end;
end;

}

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

procedure TVisWaptGUI.lstDependsDragDrop(Sender: TBaseVirtualTree;
  Source: TObject; DataObject: IDataObject; Formats: TFormatArray;
  Shift: TShiftState; const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
var
  i:integer;
  li : TListItem;
  jsonObject:TJSONObject;

begin
  for i:=0 to lstPackages1.Items.Count-1 do
  begin
    if lstPackages1.Items[i].Selected then
    begin
      if gridFind(lstDepends,'package',lstPackages1.Items[i].Caption)=Nil then
      begin
        jsonObject := TJSONObject.Create([
          'package',lstPackages1.Items[i].Caption,
          'description',lstPackages1.Items[i].SubItems[1],
          'depends',lstPackages1.Items[i].SubItems[2]
          ]);
        TJSONArray(lstDepends.Data).Add(jsonObject);
      end;
    end;
  end;
  lstDepends.LoadData;
end;

procedure TVisWaptGUI.lstDependsDragOver(Sender: TBaseVirtualTree;
  Source: TObject; Shift: TShiftState; State: TDragState; const Pt: TPoint;
  Mode: TDropMode; var Effect: DWORD; var Accept: Boolean);
begin
  Accept := Source = lstPackages1;
end;

procedure TVisWaptGUI.ActEditRemoveExecute(Sender: TObject);
begin
  lstDepends.DeleteSelectedNodes;
end;

procedure TVisWaptGUI.ActEditSavePackageExecute(Sender: TObject);
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
    n := lstDepends.GetFirst;
    while (n<>Nil) do
    begin
      if Depends<>'' then
        Depends:=Depends+','+GetValue(lstDepends,n,'package')
      else
        Depends:=GetValue(lstDepends,n,'package');
      n := lstDepends.GetNextSelected(n)
    end;

    PackageEdited.S['package.depends'] := depends;
    DMPython.PythonEng.ExecString('p = PackageEntry()');
    DMPython.PythonEng.ExecString(format('p.load_control_from_dict(json.loads(''%s''))',[PackageEdited['package'].AsJson]));
    DMPython.PythonEng.ExecString(format('p.save_control_to_wapt(r''%s'')',[EdSourceDir.Text]));
  finally
    Screen.Cursor:=crDefault;
  end;
end;

procedure TVisWaptGUI.ActEditSearchExecute(Sender: TObject);
var
  expr,res:UTF8String;
  packages,package:ISuperObject;
  item : TListItem;
begin
  lstPackages1.Clear;
  expr := format('mywapt.search("%s".split())',[EdSearch1.Text]);
  packages := DMPython.RunJSON(expr);
  if packages<>Nil then
  try
    lstPackages1.BeginUpdate;
    if packages.DataType = stArray then
    begin
      for package in packages do
      begin
        item := lstPackages1.Items.Add;
        item.Caption:=package.S['package'];
        item.SubItems.Add(package.S['version']);
        item.SubItems.Add(package.S['description']);
        item.SubItems.Add(package.S['depends']);
      end;
    end;

  finally
    lstPackages1.EndUpdate;
  end;
end;

procedure TVisWaptGUI.ActBuildUploadExecute(Sender: TObject);
var
  expr,res:String;
  package:String;
  result:ISuperObject;
begin
  ActEditSavePackage.Execute;
  result := DMPython.RunJSON(format('mywapt.build_upload(r"%s")',[EdSourceDir.Text]),jsonlog);

end;

procedure TVisWaptGUI.ActCreateCertificateExecute(Sender: TObject);
var
  params:String;
  result:ISuperObject;
  done : Boolean;
begin
  With TVisCreateKey.Create(Self) do
  try
    repeat
      if ShowModal=mrOk then
      try
        params :='';
        params := params+format('orgname="%s",',[edOrgName.text]);
        params := params+format('destdir="%s",',[DirectoryCert.Directory]);
        params := params+format('country="%s",',[edCountry.Text]);
        params := params+format('locality="%s",',[edLocality.Text]);
        params := params+format('organization="%s",',[edOrganization.Text]);
        params := params+format('unit="%s",',[edUnit.Text]);
        params := params+format('commonname="%s",',[edCommonName.Text]);
        params := params+format('email="%s",',[edEmail.Text]);
        result := DMPython.RunJSON(format('mywapt.create_self_signed_key(%s)',[params]),jsonlog);
        done := FileExists(result.S['pem_filename']);
        if done then
           ShowMessageFmt('La clé %s a été créée avec succès',[result.S['pem_filename']]);
      except
        on e:Exception do
        begin
             ShowMessage('Erreur à la création de la clé : '+e.Message);
             done := False;
        end;
      end
      else
          done := True;
    until done ;
  finally
    Free;
  end;
end;

procedure TVisWaptGUI.ActCreateWaptSetupExecute(Sender: TObject);
begin
end;

procedure TVisWaptGUI.ActEditHostPackageExecute(Sender: TObject);
var
  package : String;
  result : ISuperObject;
begin
  package := GetValue(GridHosts,GridHosts.FocusedNode,'name');
  result := DMPython.RunJSON(format('mywapt.edit_host("%s")',[package]),jsonlog);
  EditPackage(result);
  PageControl1.ActivePage := pgEditPackage;
end;

procedure TVisWaptGUI.ActEvaluateExecute(Sender: TObject);
var
  res:String;
  o,sob:ISuperObject;
begin
  Memo1.Clear;
  if cbShowLog.Checked then
  begin
    Memo1.Lines.Add('');
    Memo1.Lines.Add('########## Start of Output of """'+EdRun.Text+'""" : ########');
  end;

  sob := DMPython.RunJSON(EdRun.Text,jsonlog);
end;

procedure TVisWaptGUI.ActEvaluateVarExecute(Sender: TObject);
var
  res,r,myiter,w:Variant;
  i:integer;
begin
  {w := MainModule.Wapt(config_filename:='c:\wapt\wapt-get.ini');
  res := w.update(NOARGS);
  ShowMessage(res.getitem('added'));
  res :=  MainModule.installed_softwares('office');
  myiter:=iter(res);
  for i:=0 to len(res)-1 do
  begin
    r := myiter.next(NOARGS);
    //r := res.GetItem(i);
    showmessage(inttostr(len(r)));
    showmessage(r.Keys(NOARGS).getitem(0));
    showmessage(r.Getitem('publisher'));
  end;}
end;

procedure TVisWaptGUI.ActExecCodeExecute(Sender: TObject);
begin
  Memo1.Clear;
  DMPython.PythonEng.ExecString(testedit.Lines.Text);
end;

procedure TVisWaptGUI.ActRemoveExecute(Sender: TObject);
var
  expr,res:String;
  package:String;
  i:integer;
  N : PVirtualNode;
begin
  if lstPackages.Focused then
  begin
    N := lstPackages.GetFirstSelected;
    while N<>Nil do
    begin
      package := GetValue(lstPackages,N,'package');
      DMPython.RunJSON(format('mywapt.remove("%s")',[package]),jsonlog);
      N := lstPackages.GetNextSelected(N);
    end;
    ActSearchPackage.Execute;
  end;
end;

procedure TVisWaptGUI.ActSearchHostExecute(Sender: TObject);
var
  hosts:String;
begin
  hosts := WAPTServerJsonGet('json/host_list',[]).AsJson;
  GridLoadData(GridHosts,hosts);
end;

procedure TVisWaptGUI.ActSearchPackageExecute(Sender: TObject);
var
  expr,res:UTF8String;
  packages,package:ISuperObject;
  jsp : TJSONParser;
begin
  expr := format('mywapt.search("%s".split())',[EdSearch.Text]);
  packages := DMPython.RunJSON(expr);
  GridLoadData(lstPackages,packages.AsJSon);
end;

procedure TVisWaptGUI.ActUpdateExecute(Sender: TObject);
var
  res : Variant;
begin
  res := MainModule.mywapt.update(NOARGS);
  ShowMessage(res);
end;

procedure TVisWaptGUI.ActUpgradeExecute(Sender: TObject);
begin
  DMPython.RunJSON('mywapt.upgrade()',jsonlog);
end;


procedure TVisWaptGUI.FormCreate(Sender: TObject);
begin
  waptpath := ExtractFileDir(paramstr(0));
  //butInitWapt.Click;

  DMPython.WaptConfigFileName:=waptpath+'\wapt-get.ini';
  DMPython.PythonOutput.OnSendData:=@PythonOutputSendData;

  lstPackages.Clear;
  Memo1.Clear;

  lstDepends.Clear;
  lstPackages1.Clear;


end;

procedure TVisWaptGUI.GridLoadData(grid:TVirtualJSONListView;jsondata:string);
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

procedure TVisWaptGUI.TreeLoadData(tree:TVirtualJSONInspector;jsondata:String);
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


procedure TVisWaptGUI.GridHostsChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
var
  currhost,attribs_json,packages_json,softwares_json:String;
begin
  if Node<>Nil then
  begin
    currhost := GetValue(GridHosts,Node,'name');
    if HostPages.ActivePage=pgPackages then
    begin
      packages_json:=GetValue(GridHosts,Node,'packages');
      if packages_json='' then
      begin
        packages_json := WAPTServerJsonGet('client_package_list/%s',[currhost]).AsJSon();
        SetValue(GridHosts,Node,'packages',packages_JSon);
      end;
      GridLoadData(GridHostPackages,packages_json);
    end
    else if HostPages.ActivePage=pgSoftwares then
    begin
      softwares_json:=GetValue(GridHosts,Node,'softwares');
      if softwares_json='' then
      begin
        softwares_json := WAPTServerJsonGet('client_software_list/%s',[currhost]).AsJSon();
        SetValue(GridHosts,Node,'softwares',softwares_json);
      end;
      GridLoadData(GridHostSoftwares,softwares_json);
    end
    else if HostPages.ActivePage=pgHostPackage then
    begin
      attribs_json := GetValue(GridHosts,Node,'attributes');
      TreeLoadData(GridhostAttribs,attribs_json);
    end;
  end
  else
  begin
    GridHostPackages.Clear;
    GridHostSoftwares.Clear;
    GridhostAttribs.Clear;
  end;
end;

procedure TVisWaptGUI.PythonOutputSendData(Sender: TObject; const Data: AnsiString
  );
begin
  Memo1.Lines.Add(Data);
end;



function CompareVersion(v1,v2:String):integer;
var
  vtok1,vtok2:String;

begin
  Result := CompareText(v1,v2);
end;

procedure TVisWaptGUI.lstPackagesCompareNodes(Sender: TBaseVirtualTree; Node1,
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

procedure TVisWaptGUI.lstPackagesHeaderClick(Sender: TVTHeader;
  HitInfo: TVTHeaderHitInfo);
begin
  Sender.SortColumn := HitInfo.Column;
  Sender.Treeview.Invalidate;
end;

procedure TVisWaptGUI.lstPackagesPaintText(Sender: TBaseVirtualTree;
  const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
  TextType: TVSTTextType);
begin
  if StrIsOneOf(GetValue(lstPackages,Node,'status'),['I','U']) then
    TargetCanvas.Font.style := TargetCanvas.Font.style + [fsBold]
  else
    TargetCanvas.Font.style := TargetCanvas.Font.style - [fsBold]

end;


end.

