unit uwaptgui;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, SynHighlighterPython, SynEdit,
  vte_json, LSControls, Forms,
  Controls, Graphics, Dialogs, ExtCtrls, StdCtrls, ComCtrls, ActnList, Menus,
  EditBtn, fpJson, jsonparser, superobject,
  UniqueInstance, VirtualTrees, VarPyth;

type

  { TVisWaptGUI }

  TVisWaptGUI = class(TForm)
    ActInstall: TAction;
    ActEditpackage: TAction;
    ActExecCode: TAction;
    ActEvaluate: TAction;
    ActBuildUpload: TAction;
    ActCreateCertificate: TAction;
    ActCreateWaptSetup: TAction;
    ActEvaluateVar: TAction;
    ActEditHostPackage: TAction;
    actHostSelectAll: TAction;
    ActAddRemoveOptionIniFile: TAction;
    ActRegisterHost: TAction;
    ActSearchHost: TAction;
    ActUpgrade: TAction;
    ActUpdate: TAction;
    ActRemove: TAction;
    ActSearchPackage: TAction;
    ActionList1: TActionList;
    butInitWapt: TButton;
    butRun: TButton;
    butSearchPackages: TButton;
    butSearchPackages2: TButton;
    Button1: TButton;
    Button2: TButton;
    Button6: TButton;
    Button7: TButton;
    Button8: TButton;
    cbShowLog: TCheckBox;
    CheckBox1: TCheckBox;
    CheckBox2: TCheckBox;
    EdSearch2: TEdit;
    EdSearchHost: TEdit;
    EdRun: TEdit;
    EdSearch: TEdit;
    GridHostPackages1: TVirtualJSONListView;
    GridHostPackages2: TVirtualJSONListView;
    GridHosts: TVirtualJSONListView;
    GridhostAttribs: TVirtualJSONInspector;
    Label5: TLabel;
    LabHostCnt: TLabel;
    MainMenu1: TMainMenu;
    MemoLog: TMemo;
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
    MenuItem19: TMenuItem;
    MenuItem2: TMenuItem;
    MenuItem20: TMenuItem;
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
    Panel11: TPanel;
    Panel3: TPanel;
    Panel4: TPanel;
    Panel5: TPanel;
    Panel7: TPanel;
    PopupMenuHosts: TPopupMenu;
    PopupMenuPackages: TPopupMenu;
    PopupMenuEditDepends: TPopupMenu;
    Splitter1: TSplitter;
    Splitter2: TSplitter;
    Splitter4: TSplitter;
    SynPythonSyn1: TSynPythonSyn;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    pgInventory: TTabSheet;
    pgPackages: TTabSheet;
    pgSoftwares: TTabSheet;
    pgHostPackage: TTabSheet;
    TabSheet3: TTabSheet;
    TabSheet4: TTabSheet;
    testedit: TSynEdit;
    jsonlog: TVirtualJSONInspector;
    UniqueInstance1: TUniqueInstance;
    GridPackages: TVirtualJSONListView;
    GridHostPackages: TVirtualJSONListView;
    GridHostSoftwares: TVirtualJSONListView;
    procedure ActAddRemoveOptionIniFileExecute(Sender: TObject);
    procedure ActCreateCertificateExecute(Sender: TObject);
    procedure ActCreateWaptSetupExecute(Sender: TObject);
    procedure ActEditHostPackageExecute(Sender: TObject);
    procedure ActEditpackageExecute(Sender: TObject);
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
    procedure GridHostsGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Data: TJSONData; Column: TColumnIndex; TextType: TVSTTextType;
      var CellText: String);
    procedure GridPackagesCompareNodes(Sender: TBaseVirtualTree; Node1,
      Node2: PVirtualNode; Column: TColumnIndex; var Result: Integer);
    procedure GridPackagesHeaderClick(Sender: TVTHeader;
      HitInfo: TVTHeaderHitInfo);
    procedure GridPackagesPaintText(Sender: TBaseVirtualTree;
      const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
      TextType: TVSTTextType);
    procedure HostPagesChange(Sender: TObject);
  private
    { private declarations }
    procedure GridLoadData(grid: TVirtualJSONListView; jsondata: String);
    procedure PythonOutputSendData(Sender: TObject; const Data: AnsiString);
    procedure TreeLoadData(tree: TVirtualJSONInspector; jsondata: String);
    procedure UpdateHostPages(Sender: TObject);
  public
    { public declarations }
    PackageEdited:ISuperObject;
    waptpath:String;
  end;

var
  VisWaptGUI: TVisWaptGUI;

implementation
uses LCLIntf,tisstrings,soutils,waptcommon,uVisCreateKey,uVisCreateWaptSetup,uvisOptionIniFile,dmwaptpython,uviseditpackage;
{$R *.lfm}

{ TVisWaptGUI }

function GetValue(ListView:TVirtualJSONListView;N:PVirtualNode;FieldName:String;Default:String=''):String;
var
  js : ISuperObject;
begin
  js := SO(ListView.GetData(N).AsJSON);
  if FieldName='' then
    result := js.AsJSon
  else
    result := js.S[FieldName];
end;

procedure SetValue(ListView:TVirtualJSONListView;N:PVirtualNode;FieldName:String;Value:String);
var
  js : TJSONData;
begin
  TJSONObject(ListView.GetData(N)).Add(FieldName,Value);
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

procedure TVisWaptGUI.EdSearchKeyPress(Sender: TObject; var Key: char);
begin
 if Key=#13 then
  begin
    EdSearch.SelectAll;
    ActSearchPackage.Execute;
  end;

end;

procedure TVisWaptGUI.UpdateHostPages(Sender: TObject);
var
  currhost,attribs_json,packages_json,softwares_json:String;
  node:PVirtualNode;
begin
  LabHostCnt.Caption := format('Nombre d''enregistrements : %d',[GridHosts.SelectedCount]);
  Node := GridHosts.FocusedNode;
  if Node<>Nil then
  begin
    currhost := GetValue(GridHosts,Node,'uuid');
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
      attribs_json := GetValue(GridHosts,Node,'');
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

procedure TVisWaptGUI.ActInstallExecute(Sender: TObject);
var
  expr,res:String;
  package:String;
  i:integer;
  N : PVirtualNode;
begin
  if GridPackages.Focused then
  begin
    N := GridPackages.GetFirstSelected;
    while N<>Nil do
    begin
      package := GetValue(GridPackages,N,'package')+' (='+GetValue(GridPackages,N,'version')+')';
      DMPython.RunJSON(format('mywapt.install("%s")',[package]),jsonlog);
      N := GridPackages.GetNextSelected(N);
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
  Selpackage:String;
  result:ISuperObject;
  N : PVirtualNode;
begin
  if GridPackages.Focused then
  begin
    N := GridPackages.GetFirstSelected;
    Selpackage := GetValue(GridPackages,N,'package');
    if EditPackage(Selpackage)<>Nil then
      ActSearchPackage.Execute;
  end;
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
        DMPython.PythonEng.ExecString('import waptdevutils');
        params :='';
        params := params+format('orgname="%s",',[edOrgName.text]);
        params := params+format('destdir="%s",',[DirectoryCert.Directory]);
        params := params+format('country="%s",',[edCountry.Text]);
        params := params+format('locality="%s",',[edLocality.Text]);
        params := params+format('organization="%s",',[edOrganization.Text]);
        params := params+format('unit="%s",',[edUnit.Text]);
        params := params+format('commonname="%s",',[edCommonName.Text]);
        params := params+format('email="%s",',[edEmail.Text]);
        result := DMPython.RunJSON(format('waptdevutils.create_self_signed_key(mywapt,%s)',[params]),jsonlog);
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

procedure TVisWaptGUI.ActAddRemoveOptionIniFileExecute(Sender: TObject);
begin
  with TVisOptionIniFile.Create(self) do
  try
    if ShowModal=mrOK then
    try

    except
    end;

  finally
  end;
end;

procedure TVisWaptGUI.ActCreateWaptSetupExecute(Sender: TObject);
var
  params:String;
  result:ISuperObject;
  done : Boolean;
begin
  with TVisCreateWaptSetup.Create(self) do
  try
    repeat
      if ShowModal=mrOK then
      begin
        try
          DMPython.PythonEng.ExecString('import waptdevutils');
          params :='';
          params := params+format('default_public_cert="%s",',[fnPublicCert.FileName]);
          params := params+format('default_repo_url="%s",',[edRepoUrl.text]);
          params := params+format('company="%s",',[edOrgName.Text]);
          result := DMPython.RunJSON(format('waptdevutils.create_wapt_setup(mywapt,%s)',[params]),jsonlog);
          done := FileExists(result.S['pem_filename']);
        except
          on e:Exception do
          begin
            ShowMessage('Erreur à la création du waptsetup.exe: '+e.Message);
            done := False;
          end;
        end;
      end
      else
        done := True;
      until done;
    finally
      free;
    end;
end;

procedure TVisWaptGUI.ActEditHostPackageExecute(Sender: TObject);
var
  hostname : String;
  result : ISuperObject;
begin
  hostname := GetValue(GridHosts,GridHosts.FocusedNode,'host.computer_fqdn');
  if EditHost(hostname)<>Nil then
    ActSearchHost.Execute;
end;

procedure TVisWaptGUI.ActEvaluateExecute(Sender: TObject);
var
  res:String;
  o,sob:ISuperObject;
begin
  MemoLog.Clear;
  if cbShowLog.Checked then
  begin
    MemoLog.Lines.Add('');
    MemoLog.Lines.Add('########## Start of Output of """'+EdRun.Text+'""" : ########');
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
  MemoLog.Clear;
  DMPython.PythonEng.ExecString(testedit.Lines.Text);
end;

procedure TVisWaptGUI.actHostSelectAllExecute(Sender: TObject);
begin
  TVirtualJSONListView(GridHosts).SelectAll(False);
end;

procedure TVisWaptGUI.ActRemoveExecute(Sender: TObject);
var
  expr,res:String;
  package:String;
  i:integer;
  N : PVirtualNode;
begin
  if GridPackages.Focused then
  begin
    N := GridPackages.GetFirstSelected;
    while N<>Nil do
    begin
      package := GetValue(GridPackages,N,'package');
      DMPython.RunJSON(format('mywapt.remove("%s")',[package]),jsonlog);
      N := GridPackages.GetNextSelected(N);
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
  GridLoadData(GridPackages,packages.AsJSon);
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

  GridPackages.Clear;
  MemoLog.Clear;

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
begin
  UpdateHostPages(Sender);
end;

procedure TVisWaptGUI.GridHostsGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Data: TJSONData; Column: TColumnIndex;
  TextType: TVSTTextType; var CellText: String);
var
  js : ISuperObject;
begin
  js := SO(Data.AsJSON);
  CellText:=js.S[TVirtualJSONListViewColumn(GridHosts.Header.Columns[column]).PropertyName];
end;

procedure TVisWaptGUI.PythonOutputSendData(Sender: TObject; const Data: AnsiString
  );
begin
  MemoLog.Lines.Add(Data);
end;

function CompareVersion(v1,v2:String):integer;
var
  vtok1,vtok2:String;
begin
  Result := CompareText(v1,v2);
end;

procedure TVisWaptGUI.GridPackagesCompareNodes(Sender: TBaseVirtualTree; Node1,
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

procedure TVisWaptGUI.GridPackagesHeaderClick(Sender: TVTHeader;
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

procedure TVisWaptGUI.GridPackagesPaintText(Sender: TBaseVirtualTree;
  const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
  TextType: TVSTTextType);
begin
  if StrIsOneOf(GetValue(GridPackages,Node,'status'),['I','U']) then
    TargetCanvas.Font.style := TargetCanvas.Font.style + [fsBold]
  else
    TargetCanvas.Font.style := TargetCanvas.Font.style - [fsBold]
end;

procedure TVisWaptGUI.HostPagesChange(Sender: TObject);
begin
  UpdateHostPages(Sender);
end;
end.

