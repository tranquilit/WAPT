unit uwaptgui;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, memds, BufDataset, FileUtil, SynHighlighterPython, SynEdit,
  SynMemo, vte_edittree, LSControls, Forms, Controls, Graphics, Dialogs,
  ExtCtrls, StdCtrls, ComCtrls, ActnList, Menus, AtomPythonEngine,
  PythonGUIInputOutput;

type

  { TVisWaptGUI }

  TVisWaptGUI = class(TForm)
    ActInstall: TAction;
    ActSearchPackage: TAction;
    ActionList1: TActionList;
    BufDataset1: TBufDataset;
    butInitWapt: TButton;
    butRun: TButton;
    butSearchPackages: TButton;
    cbShowLog: TCheckBox;
    EdRun: TEdit;
    EdSearch: TEdit;
    jsonmemo: TMemo;
    ListBox1: TListBox;
    lstPackages: TListView;
    Memo1: TMemo;
    MenuItem1: TMenuItem;
    PageControl1: TPageControl;
    Panel1: TPanel;
    Panel2: TPanel;
    Panel3: TPanel;
    Panel4: TPanel;
    PopupMenuPackages: TPopupMenu;
    PythonEngine1: TAtomPythonEngine;
    PythonGUIInputOutput1: TPythonGUIInputOutput;
    SynPythonSyn1: TSynPythonSyn;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    TabSheet3: TTabSheet;
    TabSheet4: TTabSheet;
    testedit: TSynEdit;
    VirtualEditTree1: TVirtualEditTree;
    procedure ActInstallExecute(Sender: TObject);
    procedure ActSearchPackageExecute(Sender: TObject);
    procedure butInitWaptClick(Sender: TObject);
    procedure butRunClick(Sender: TObject);
    procedure cbShowLogClick(Sender: TObject);
    procedure EdRunKeyPress(Sender: TObject; var Key: char);
    procedure EdSearchKeyPress(Sender: TObject; var Key: char);
    procedure FormCreate(Sender: TObject);
    procedure PythonEngine1AfterInit(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisWaptGUI: TVisWaptGUI;

implementation
uses superobject;
{$R *.lfm}

{ TVisWaptGUI }

procedure TVisWaptGUI.cbShowLogClick(Sender: TObject);
begin
  if cbShowLog.Checked then
    PythonGUIInputOutput1.Output := Memo1
  else
    PythonGUIInputOutput1.Output := Nil;

end;

procedure TVisWaptGUI.EdRunKeyPress(Sender: TObject; var Key: char);
begin
  if Key=#13 then
    butRun.Click;
end;

procedure TVisWaptGUI.EdSearchKeyPress(Sender: TObject; var Key: char);
begin
 if Key=#13 then
  begin
    EdSearch.SelectAll;
    ActSearchPackage.Execute;
  end;

end;

procedure TVisWaptGUI.butInitWaptClick(Sender: TObject);
begin
  PythonEngine1.ExecString(testedit.Lines.Text);
end;

procedure TVisWaptGUI.ActInstallExecute(Sender: TObject);
var
  expr,res:String;
  package:String;
begin
  if lstPackages.Focused then
  begin
    package := lstPackages.Selected.Caption+' (='+lstPackages.Selected.SubItems[1]+')';
    expr := format('jsondump(mywapt.install("%s"))',[package]);
    res := PythonEngine1.EvalStringAsStr(expr);
    ActSearchPackage.Execute;
  end;
end;

procedure TVisWaptGUI.ActSearchPackageExecute(Sender: TObject);
var
  expr,res:UTF8String;
  packages,package:ISuperObject;
  item : TListItem;
begin
  lstPackages.Clear;
  expr := format('jsondump(mywapt.search("%s".split()))',[EdSearch.Text]);
  Memo1.Lines.Append(expr);
  res := PythonEngine1.EvalStringAsStr(expr);
  Memo1.Lines.Append(res);
  packages := SO( UTF8Decode(res) );
  if packages<>Nil then
  try
    lstPackages.BeginUpdate;
    if packages.DataType = stArray then
    begin
      for package in packages do
      begin
        item := lstPackages.Items.Add;
        item.Caption:=package.S['package'];
        item.SubItems.Add(package.S['status']);
        item.SubItems.Add(package.S['version']);
        item.SubItems.Add(package.S['description']);
        item.SubItems.Add(package.S['depends']);
        if package.S['status']='I' then
          item.Checked:=True;
      end;
    end;

  finally
    lstPackages.EndUpdate;
  end;
end;


procedure TVisWaptGUI.butRunClick(Sender: TObject);
var
  res:String;
  o,sob:ISuperObject;
begin
  Memo1.Lines.Add('');
  Memo1.Lines.Add('########## Start of Output of """'+EdRun.Text+'""" : ########');
  res := PythonEngine1.EvalStringAsStr(EdRun.Text);
  Memo1.Lines.Add('########## Run results : ########');
  Memo1.Lines.Add(res);
  sob := SO(res);
  jsonmemo.Lines.Text:=sob.AsJSon(True);
  if sob.DataType = stArray then
  begin
    ListBox1.Clear;
    for o in sob do
      ListBox1.Items.Add(o.AsJson());
  end;
end;

procedure TVisWaptGUI.FormCreate(Sender: TObject);
begin
  with pythonEngine1 do
  begin
    DllName := 'python27.dll';
    RegVersion := '2.7';
    UseLastKnownVersion := False;
    LoadDLL;
    Py_SetProgramName(PAnsiChar(ParamStr(0)));
  end;
  butInitWapt.Click;

  lstPackages.Clear;
end;

procedure TVisWaptGUI.PythonEngine1AfterInit(Sender: TObject);
begin

end;

end.

