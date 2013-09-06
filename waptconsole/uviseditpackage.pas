unit uviseditpackage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, memds, BufDataset, FileUtil, SynHighlighterPython, SynEdit,
  SynMemo, LSControls, Forms, Controls, Graphics,
  Dialogs, ExtCtrls, StdCtrls, ComCtrls, ActnList, Menus, EditBtn, Buttons,
  process, superobject, UniqueInstance, VirtualTrees,
  VarPyth, types, ActiveX, LMessages, LCLIntf, LCL, sogrid, vte_json, jsonparser;

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
    BitBtn2: TBitBtn;
    butInitWapt: TButton;
    butSearchPackages1: TButton;
    Button3: TButton;
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
    ProgressBar: TProgressBar;
    GridDepends: TSOGrid;
    GridPackages: TSOGrid;
    MemoLog: TMemo;
    MenuItem4: TMenuItem;
    PageControl1: TPageControl;
    Panel1: TPanel;
    Panel2: TPanel;
    PanelDevlop: TPanel;
    Panel4: TPanel;
    Panel7: TPanel;
    Panel8: TPanel;
    Panel9: TPanel;
    PopupMenuEditDepends: TPopupMenu;
    Splitter1: TSplitter;
    Splitter2: TSplitter;
    Splitter3: TSplitter;
    SynPythonSyn1: TSynPythonSyn;
    pgDevelop: TTabSheet;
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
    procedure EdSearchKeyDown(Sender: TObject; var Key: word; Shift: TShiftState);
    procedure EdSectionChange(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure GridDependsDragDrop(Sender: TBaseVirtualTree; Source: TObject;
      DataObject: IDataObject; Formats: TFormatArray; Shift: TShiftState;
      const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
    procedure GridDependsDragOver(Sender: TBaseVirtualTree; Source: TObject;
      Shift: TShiftState; State: TDragState; const Pt: TPoint;
      Mode: TDropMode; var Effect: DWORD; var Accept: boolean);
  private
    FIsUpdated: boolean;
    GridDependsUpdated: boolean;
    function CheckUpdated: boolean;
    procedure SetIsUpdated(AValue: boolean);
    function GetIsUpdated: boolean;
  private
    FDepends: string;
    function GetDepends: string;
    property IsUpdated: boolean read GetIsUpdated write SetIsUpdated;
    procedure SetDepends(AValue: string);
  private
    FPackageRequest: string;
    FSourcePath: string;
    { private declarations }
    procedure SetPackageRequest(AValue: string);
    procedure SetSourcePath(AValue: string);
    procedure TreeLoadData(tree: TVirtualJSONInspector; jsondata: string);
    property Depends: string read GetDepends write SetDepends;
    function updateprogress(current, total: integer): boolean;
  public
    { public declarations }
    waptpath: string;
    IsHost: boolean;
    IsNewPackage: boolean;
    PackageEdited: ISuperObject;
    isAdvancedMode: boolean;
    procedure EditPackage;
    property SourcePath: string read FSourcePath write SetSourcePath;
    property PackageRequest: string read FPackageRequest write SetPackageRequest;
  end;

function EditPackage(packagename: string; advancedMode: boolean): ISuperObject;
function CreatePackage(packagename: string; advancedMode: boolean): ISuperObject;
function EditHost(hostname: string; advancedMode: boolean): ISuperObject;


var
  downloadStopped: boolean;
  VisEditPackage: TVisEditPackage;
  privateKeyPassword: string = '';
  waptServerPassword: string = '';
  waptServerUser: string = 'admin';

implementation

uses tisstrings, soutils, LCLType, waptcommon, dmwaptpython, jwawinuser, uvisloading,
  uvisprivatekeyauth, strutils, uwaptconsole, tiscommon;

{$R *.lfm}

function EditPackage(packagename: string; advancedMode: boolean): ISuperObject;
begin
  with TVisEditPackage.Create(nil) do
    try
      isAdvancedMode := advancedMode;
      PackageRequest := packagename;
      if ShowModal = mrOk then
        Result := PackageEdited
      else
        Result := nil;
    finally
      Free;
    end;
end;

function CreatePackage(packagename: string; advancedMode: boolean): ISuperObject;
begin
  with TVisEditPackage.Create(nil) do
    try
      isAdvancedMode := advancedMode;
      IsNewPackage := True;
      PackageRequest := packagename;
      EdSection.ItemIndex := 4;
      if ShowModal = mrOk then
        Result := PackageEdited
      else
        Result := nil;
    finally
      Free;
    end;
end;

function EditHost(hostname: string; advancedMode: boolean): ISuperObject;
begin
  with TVisEditPackage.Create(nil) do
    try
      isAdvancedMode := advancedMode;
      IsHost := True;
      PackageRequest := hostname;
      if ShowModal = mrOk then
        Result := PackageEdited
      else
        Result := nil;
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

procedure TVisEditPackage.EdSearchKeyDown(Sender: TObject; var Key: word;
  Shift: TShiftState);
begin
  if Key = VK_RETURN then
  begin
    EdSearch.SelectAll;
    ActSearchPackage.Execute;
  end;

end;

procedure TVisEditPackage.EdSectionChange(Sender: TObject);
begin
  FIsUpdated := True;
end;

procedure TVisEditPackage.FormCloseQuery(Sender: TObject; var CanClose: boolean);
begin
  CanClose := CheckUpdated;

end;

function TVisEditPackage.CheckUpdated: boolean;
var
  Rep, i: integer;
  dsnames, msg: string;
begin
  Result := not IsUpdated;
  if not Result then
  begin
    msg := 'Sauvegarder les modifications ?';
    Rep := Application.MessageBox(PChar(msg), 'Confirmer', MB_APPLMODAL +
      MB_ICONQUESTION + MB_YESNOCANCEL);
    if (Rep = idYes) then
      Result := ActEditSavePackage.Execute
    else
    if (Rep = idNo) then
      Result := True;
  end;
end;

procedure TVisEditPackage.EditPackage;
begin
  EdSourceDir.Text := FSourcePath;
  EdPackage.Text := PackageEdited.S['package'];
  EdVersion.Text := PackageEdited.S['version'];
  EdDescription.Text := UTF8Encode(PackageEdited.S['description']);
  EdSection.Text := PackageEdited.S['section'];
  // get a list of package entries given a
  Depends := PackageEdited.S['depends'];
  EdSetupPy.Lines.LoadFromFile(AppendPathDelim(FSourcePath) + 'setup.py');
  IsUpdated := False;
end;

function gridFind(grid: TSOGrid; Fieldname, AText: string): PVirtualNode;
var
  n: PVirtualNode;
begin
  Result := nil;
  n := grid.GetFirst;
  while n <> nil do
  begin
    if grid.GetColumnValue(n, Fieldname) = AText then
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
  i: integer;
  sel: TNodeArray;
  olddepends: ISuperObject;
  package: string;
begin
  olddepends := Split(Depends, ',');
  sel := GridPackages.GetSortedSelection(False);
  for i := 0 to length(sel) - 1 do
  begin
    package := GridPackages.GetColumnValue(sel[i], 'package');
    if not StrIn(package, olddepends) then
      olddepends.AsArray.Add(package);
  end;
  Depends := Join(',', olddepends);
end;

procedure TVisEditPackage.GridDependsDragOver(Sender: TBaseVirtualTree;
  Source: TObject; Shift: TShiftState; State: TDragState; const Pt: TPoint;
  Mode: TDropMode; var Effect: DWORD; var Accept: boolean);
begin
  Accept := Source = GridPackages;
end;

procedure TVisEditPackage.ActEditRemoveExecute(Sender: TObject);
begin
  GridDepends.DeleteSelectedNodes;
  Depends := Depends;
end;

procedure TVisEditPackage.ActEditSavePackageExecute(Sender: TObject);
var
  i: integer;
  n: PVirtualNode;
  res: ISuperObject;
begin
  Screen.Cursor := crHourGlass;
  try
    if IsNewPackage then
    begin
      res := DMPython.RunJSON(
        format('mywapt.make_group_template(packagename="%s",depends="%s",description="%s")', [Trim(EdPackage.Text), Depends, Eddescription.Text]));
      FSourcePath := res.S['source_dir'];
      PackageEdited := res['package'];
    end
    else
    begin
      PackageEdited.S['package'] := EdPackage.Text;
      PackageEdited.S['version'] := EdVersion.Text;
      PackageEdited.S['description'] := EdDescription.Text;
      PackageEdited.S['section'] := EdSection.Text;
      PackageEdited.S['depends'] := Depends;
      DMPython.PythonEng.ExecString('p = PackageEntry()');
      DMPython.PythonEng.ExecString(
        format('p.load_control_from_dict(json.loads(''%s''))', [PackageEdited.AsJson]));
      DMPython.PythonEng.ExecString(
        format('p.save_control_to_wapt(r''%s'')', [EdSourceDir.Text]));
      EdSetupPy.Lines.SaveToFile(AppendPathDelim(FSourcePath) + 'setup.py');
    end;
    IsUpdated := False;
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TVisEditPackage.ActEditSavePackageUpdate(Sender: TObject);
begin
  ActEditSavePackage.Enabled := IsUpdated;
end;

function TVisEditPackage.GetIsUpdated: boolean;
begin
  Result := FIsUpdated or EdPackage.Modified or EdVersion.Modified or
    EdSetupPy.Modified or EdSourceDir.Modified or Eddescription.Modified or
    GridDependsUpdated;
end;

procedure TVisEditPackage.ActEditSearchExecute(Sender: TObject);
var
  expr: UTF8String;
  packages: ISuperObject;
begin
  expr := format('mywapt.search("%s".split())', [EdSearch.Text]);
  packages := DMPython.RunJSON(expr);
  GridPackages.Data := packages;
end;

procedure TVisEditPackage.ActBuildUploadExecute(Sender: TObject);
var
  expr, res: string;
  package: string;
  Result: ISuperObject;
  done: boolean = False;
  isEncrypt: boolean;
begin
  ActEditSavePackage.Execute;
  isEncrypt := StrToBool(DMPython.RunJSON(
    format('waptdevutils.is_encrypt_private_key(r"%s")', [GetWaptPrivateKey])).AsString);
  if (privateKeyPassword = '') and (isEncrypt) then
  begin
    with TvisPrivateKeyAuth.Create(Self) do
      try
        laKeyPath.Caption := GetWaptPrivateKey;
        repeat
          if ShowModal = mrOk then
          begin
            privateKeyPassword := edPasswordKey.Text;
            if StrToBool(DMPython.RunJSON(
              format('waptdevutils.is_match_password(r"%s","%s")',
              [GetWaptPrivateKey, privateKeyPassword])).AsString) then
              done := True;
          end
          else
            Exit;
        until done;
      finally
        Free;
      end;
  end;
  with  Tvisloading.Create(Self) do
    try
      Chargement.Caption := 'Upload en cours';
      Application.ProcessMessages;
      Result := DMPython.RunJSON(format(
        'mywapt.build_upload(r"%s",r"%s",r"%s",r"%s",True)',
        [FSourcePath, privateKeyPassword, waptServerUser, waptServerPassword]), jsonlog);

    finally
    end;
  ModalResult := mrOk;
end;

procedure TVisEditPackage.ActExecCodeExecute(Sender: TObject);
begin
  MemoLog.Clear;
  DMPython.PythonEng.ExecString(EdSetupPy.Lines.Text);
end;

procedure TVisEditPackage.ActSearchPackageExecute(Sender: TObject);
var
  expr, res: UTF8String;
  packages: ISuperObject;
begin
  expr := format('mywapt.search("%s".split())', [EdSearch.Text]);
  packages := DMPython.RunJSON(expr);
  GridPackages.Data := packages;
end;

procedure TVisEditPackage.FormCreate(Sender: TObject);
begin
  waptpath := ExtractFileDir(ParamStr(0));

  GridPackages.Clear;
  MemoLog.Clear;

  GridDepends.Clear;

end;

procedure TVisEditPackage.FormShow(Sender: TObject);
begin
  // Advance mode in mainWindow -> tools => advance
  PanelDevlop.Visible := isAdvancedMode;
  Label5.Visible := isAdvancedMode;
  EdSection.Visible := isAdvancedMode;
  Label4.Visible := isAdvancedMode;
  EdSourceDir.Visible := isAdvancedMode;
  cbShowLog.Visible := isAdvancedMode;
  pgDevelop.TabVisible := isAdvancedMode;

end;

procedure TVisEditPackage.TreeLoadData(tree: TVirtualJSONInspector; jsondata: string);
var
  jsp: TJSONParser;

begin
  tree.Clear;
  if (jsondata <> '') then
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


procedure TVisEditPackage.SetPackageRequest(AValue: string);
var
  res: ISuperObject;
  n: PVirtualNode;
  filename, filePath: string;
  grid: TSOGrid;
begin
  if FPackageRequest = AValue then
    Exit;
  Screen.Cursor := crHourGlass;
  try
    FPackageRequest := AValue;
    if not IsNewPackage then
    begin
      if IsHost then
        res := DMPython.RunJSON(format('mywapt.edit_host("%s")', [FPackageRequest]))
      else
      begin
        with  Tvisloading.Create(Self) do
          try
            ProgressBar := ProgressBar1;
            Chargement.Caption := 'Téléchargement en cours';
            downloadStopped := False;
            grid := uwaptconsole.VisWaptGUI.GridPackages;
            n := grid.GetFirstSelected();
            if n <> nil then
              try
                filename := grid.GetColumnValue(n, 'filename');
                filePath := waptpath + '\cache\' + filename;
                if not FileExists(filePath) then
                  Wget(GetWaptRepoURL + '/' + filename, filePath, @updateprogress);
              except
                ShowMessage('Téléchargement annulé')
              end;


            res := DMPython.RunJSON(format('mywapt.edit_package(r"%s")',
              [filePath]));
          finally
            Free;
          end;

      end;
      FSourcePath := res.S['source_dir'];
      PackageEdited := res['package'];
    end;
  finally
    Screen.Cursor := crDefault;
  end;
  if not IsNewPackage then
    EditPackage;
end;

procedure TVisEditPackage.SetSourcePath(AValue: string);
var
  res: ISuperObject;
begin
  if FSourcePath = AValue then
    Exit;
  FSourcePath := AValue;
  try
    res := DMPython.RunJSON(format('mywapt.edit_package("%s")', [FSourcePath]));
    PackageEdited := res['package'];
  finally
    Screen.Cursor := crDefault;
  end;
  EditPackage;
end;

procedure TVisEditPackage.SetIsUpdated(AValue: boolean);
begin
  FIsUpdated := AValue;
  if not AValue then
  begin
    EdPackage.Modified := False;
    Eddescription.Modified := False;
    EdVersion.Modified := False;
    EdSourceDir.Modified := False;
    EdSetupPy.Modified := False;
    GridDependsUpdated := False;
  end;
end;

procedure TVisEditPackage.SetDepends(AValue: string);
var
  dependencies: ISuperObject;
begin
  if AValue = '' then
    Exit;
  FDepends := AValue;
  dependencies := DMPython.RunJSON(
    format('mywapt.get_package_entries("%s")', [FDepends]));
  GridDepends.Data := dependencies['packages'];
  if dependencies['missing'].AsArray.Length > 0 then
  begin
    ShowMessageFmt('Attention, les paquets %s ont été ignorés car introuvables',
      [dependencies.S['missing']]);
    GridDependsUpdated := True;

  end;
  FIsUpdated := True;
end;

function TVisEditPackage.GetDepends: string;
var
  n: PVirtualNode;
begin
  FDepends := '';
  n := GridDepends.GetFirst;
  while (n <> nil) do
  begin
    if FDepends <> '' then
      FDepends := FDepends + ',' + GridDepends.GetColumnValue(n, 'package')
    else
      FDepends := GridDepends.GetColumnValue(n, 'package');
    n := GridDepends.GetNext(n);
  end;
  Result := FDepends;
end;

function TVisEditPackage.updateprogress(current, total: integer): boolean;
begin

  ProgressBar.Max := total;
  ProgressBar.Position := current;
  Application.ProcessMessages;
  Result := not downloadStopped;
end;

end.
