unit uviseditpackage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, SynHighlighterPython, SynEdit,
  SynMemo, Forms, Controls, Graphics,
  Dialogs, ExtCtrls, StdCtrls, ComCtrls, ActnList, Menus, EditBtn, Buttons,
  process, superobject, VirtualTrees,
  VarPyth, types, ActiveX, LMessages, LCLIntf, LCL, sogrid, vte_json;

type

  { TVisEditPackage }

  TVisEditPackage = class(TForm)
    ActExecCode: TAction;
    ActBuildUpload: TAction;
    ActEditSearch: TAction;
    ActEditRemoveDepends: TAction;
    ActEditSavePackage: TAction;
    ActAdvancedMode: TAction;
    ActAddDepends: TAction;
    ActBUApply: TAction;
    ActEditRemoveConflicts: TAction;
    ActAddConflicts: TAction;
    ActSearchPackage: TAction;
    ActionList1: TActionList;
    BitBtn2: TBitBtn;
    butInitWapt: TButton;
    butSearchPackages1: TButton;
    Button3: TButton;
    Button5: TButton;
    butBUApply: TButton;
    cbShowLog: TCheckBox;
    Eddescription: TLabeledEdit;
    EdPackage: TLabeledEdit;
    EdSearch: TEdit;
    EdSection: TComboBox;
    EdSourceDir: TEdit;
    EdVersion: TLabeledEdit;
    GridConflicts: TSOGrid;
    GridPackages: TSOGrid;
    Label2: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    GridDepends: TSOGrid;
    MemoLog: TMemo;
    MenuItem1: TMenuItem;
    MenuItem2: TMenuItem;
    MenuItem4: TMenuItem;
    MenuItem5: TMenuItem;
    PageControl1: TPageControl;
    Panel1: TPanel;
    Panel2: TPanel;
    Panel8: TPanel;
    Panel9: TPanel;
    PanelDevlop: TPanel;
    Panel4: TPanel;
    Panel7: TPanel;
    PopupMenu1: TPopupMenu;
    PopupMenuEditConflicts: TPopupMenu;
    PopupPackages: TPopupMenu;
    PopupMenuEditDepends: TPopupMenu;
    Splitter1: TSplitter;
    Splitter2: TSplitter;
    Splitter3: TSplitter;
    SynPythonSyn1: TSynPythonSyn;
    pgDevelop: TTabSheet;
    pgEditPackage: TTabSheet;
    EdSetupPy: TSynEdit;
    jsonlog: TVirtualJSONInspector;
    pgConflicts: TTabSheet;
    procedure ActAddConflictsExecute(Sender: TObject);
    procedure ActAddConflictsUpdate(Sender: TObject);
    procedure ActAddDependsExecute(Sender: TObject);
    procedure ActAddDependsUpdate(Sender: TObject);
    procedure ActAdvancedModeExecute(Sender: TObject);
    procedure ActBUApplyExecute(Sender: TObject);
    procedure ActBuildUploadExecute(Sender: TObject);
    procedure ActEditRemoveConflictsExecute(Sender: TObject);
    procedure ActEditRemoveConflictsUpdate(Sender: TObject);
    procedure ActEditRemoveDependsExecute(Sender: TObject);
    procedure ActEditRemoveDependsUpdate(Sender: TObject);
    procedure ActEditSavePackageExecute(Sender: TObject);
    procedure ActEditSavePackageUpdate(Sender: TObject);
    procedure ActEditSearchExecute(Sender: TObject);
    procedure ActExecCodeExecute(Sender: TObject);
    procedure ActSearchPackageExecute(Sender: TObject);
    procedure cbShowLogClick(Sender: TObject);
    procedure EdPackageKeyPress(Sender: TObject; var Key: char);
    procedure EdSearchKeyDown(Sender: TObject; var Key: word; Shift: TShiftState);
    procedure EdSectionChange(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure GridConflictsDragDrop(Sender: TBaseVirtualTree; Source: TObject;
      DataObject: IDataObject; Formats: TFormatArray; Shift: TShiftState;
      const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
    procedure GridDependsDragDrop(Sender: TBaseVirtualTree; Source: TObject;
      DataObject: IDataObject; Formats: TFormatArray; Shift: TShiftState;
      const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
    procedure GridDependsDragOver(Sender: TBaseVirtualTree; Source: TObject;
      Shift: TShiftState; State: TDragState; const Pt: TPoint;
      Mode: TDropMode; var Effect: DWORD; var Accept: boolean);
  private
    FisAdvancedMode: boolean;
    FisTempSourcesDir: boolean;
    { private declarations }
    FPackageRequest: string;
    FSourcePath: string;
    FIsUpdated: boolean;
    GridDependsUpdated: boolean;
    GridConflictsUpdated: boolean;
    FDepends: string;
    FConflicts: string;
    procedure AddDepends(Sender: TObject);
    procedure AddConflicts(Sender: TObject);
    function CheckUpdated: boolean;
    procedure SetisAdvancedMode(AValue: boolean);
    procedure SetIsUpdated(AValue: boolean);
    function GetIsUpdated: boolean;
    function GetDepends: string;
    function GetConflicts: string;
    property IsUpdated: boolean read GetIsUpdated write SetIsUpdated;
    procedure SetDepends(AValue: string);
    procedure SetConflicts(AValue: string);
    procedure SetPackageRequest(AValue: string);
    procedure SetSourcePath(AValue: string);
    property Depends: string read GetDepends write SetDepends;
    property Conflicts: string read GetConflicts write SetConflicts;
    function updateprogress(receiver: TObject; current, total: integer): boolean;
  public
    { public declarations }
    waptpath: string;
    IsHost: boolean;
    isGroup: boolean;
    IsNewPackage: boolean;
    PackageEdited: ISuperObject;
    ApplyUpdatesImmediately:Boolean;
    property isAdvancedMode: boolean read FisAdvancedMode write SetisAdvancedMode;
    procedure EditPackage;
    property SourcePath: string read FSourcePath write SetSourcePath;
    property PackageRequest: string read FPackageRequest write SetPackageRequest;
  end;

function EditPackage(packagename: string; advancedMode: boolean): ISuperObject;
function CreatePackage(packagename: string; advancedMode: boolean): ISuperObject;
function CreateGroup(packagename: string; advancedMode: boolean): ISuperObject;
function EditHost(hostname: ansistring; advancedMode: boolean;currentip:ansiString=''): ISuperObject;
function EditHostDepends(hostname: string; newDependsStr: string): ISuperObject;
function EditGroup(group: string; advancedMode: boolean): ISuperObject;


var
  VisEditPackage: TVisEditPackage;

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

function CreateGroup(packagename: string; advancedMode: boolean): ISuperObject;
begin
  with TVisEditPackage.Create(nil) do
    try
      Caption:='Editer le groupe';
      EdPackage.EditLabel.Caption := 'Groupe';
      pgEditPackage.Caption := 'Paquets devant être présents dans le groupe';

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

function EditHost(hostname: ansistring; advancedMode: boolean;currentip:ansiString=''): ISuperObject;
var
  res:ISuperObject;
begin
  with TVisEditPackage.Create(nil) do
    try
      IsHost := True;
      isAdvancedMode := advancedMode;
      PackageRequest := hostname;
      Caption:='Editer la machine';
      ActBUApply.Enabled:=currentip<>'';
      if ShowModal = mrOk then
      begin
        Result := PackageEdited;
        if (result<>Nil) and ApplyUpdatesImmediately and (currentip<>'')  then
        begin
          res := WAPTServerJsonGet('upgrade_host/'+currentip, [],
            WaptUseLocalConnectionProxy,
            waptServerUser, waptServerPassword);
          if (res.S['result'] = 'OK') or (res.S['status'] = 'OK') then
            ShowMessage('Upgrade lancée')
          else
            ShowMessage('Impossible de lancer l''upgrade sur la machine: '+res.S['message']);
        end;
      end
      else
        Result := nil;
    finally
      Free;
    end;
end;

function EditGroup(group: string; advancedMode: boolean): ISuperObject;
begin
  with TVisEditPackage.Create(nil) do
    try
      isGroup := True;
      isAdvancedMode := advancedMode;
      PackageRequest := group;

      Caption:='Editer le groupe';
      EdPackage.EditLabel.Caption := 'Groupe';
      pgEditPackage.Caption := 'Paquets devant être présents dans le groupe';

      if ShowModal = mrOk then
        Result := PackageEdited
      else
        Result := nil;
    finally
      Free;
    end;
end;

function EditHostDepends(hostname: string; newDependsStr: string): ISuperObject;
var
  oldDepends, newDepends: ISuperObject;
  i: word;
begin
  with TVisEditPackage.Create(nil) do
    try
      IsHost := True;
      PackageRequest := hostname;

      oldDepends := Split(Depends, ',');
      newDepends := Split(newDependsStr, ',');
      for i := 0 to newDepends.AsArray.Length - 1 do
      begin
        if not StrIn(newDepends.AsArray.S[i], olddepends) then
          olddepends.AsArray.Add(newDepends.AsArray.S[i]);
      end;
      Depends := Join(',', olddepends);

      Result := PackageEdited;
      if Result<>Nil then
        ActBuildUploadExecute(nil);
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

procedure TVisEditPackage.EdPackageKeyPress(Sender: TObject; var Key: char);
begin

  key := lowerCase(key);
  if not (key in ['a'..'z','0'..'9','-',#8,#9]) then
      Key:=#0;
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
  if FisTempSourcesDir and DirectoryExists(FSourcePath) then
    FileUtil.DeleteDirectory(FSourcePath, False);

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

procedure TVisEditPackage.SetisAdvancedMode(AValue: boolean);
begin
  if FisAdvancedMode = AValue then
    Exit;
  FisAdvancedMode := AValue;
  // Advance mode in mainWindow -> tools => advance
  PanelDevlop.Visible := isAdvancedMode;
  Label5.Visible := isAdvancedMode;
  EdSection.Visible := isAdvancedMode;
  Label4.Visible := isAdvancedMode;
  EdSourceDir.Visible := isAdvancedMode;
  cbShowLog.Visible := isAdvancedMode;
  pgDevelop.TabVisible := isAdvancedMode;
  Eddescription.Visible := not IsHost or isAdvancedMode;

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
  Conflicts := PackageEdited.S['conflicts'];
  EdSetupPy.Lines.LoadFromFile(AppendPathDelim(FSourcePath) + 'setup.py');
  IsUpdated := False;
  butBUApply.Visible:=IsHost;
end;

function gridFind(grid: TSOGrid; Fieldname, AText: string): PVirtualNode;
var
  n: PVirtualNode;
begin
  Result := nil;
  n := grid.GetFirst;
  while n <> nil do
  begin
    if grid.GetCellStrValue(n, Fieldname) = AText then
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
begin
  AddDepends(Sender);
end;

procedure TVisEditPackage.AddDepends(Sender: TObject);
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
    package := GridPackages.GetCellStrValue(sel[i], 'package');
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

procedure TVisEditPackage.ActEditRemoveDependsExecute(Sender: TObject);
begin
  GridDepends.DeleteSelectedNodes;
  Depends := Depends;
  GridDependsUpdated := True;
end;

procedure TVisEditPackage.ActEditRemoveDependsUpdate(Sender: TObject);
begin
  ActEditRemoveDepends.Enabled:=GridDepends.SelectedCount>0;
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
        format('mywapt.make_group_template(packagename="%s",depends="%s",description=r"%s".decode(''utf8''))', [Trim(EdPackage.Text), Depends, Eddescription.Text]));
      FSourcePath := res.S['source_dir'];
      PackageEdited := res['package'];
    end
    else
    begin
      PackageEdited.S['package'] := EdPackage.Text;
      PackageEdited.S['version'] := EdVersion.Text;
      PackageEdited.S['description'] := UTF8Decode(EdDescription.Text);
      PackageEdited.S['section'] := EdSection.Text;
      PackageEdited.S['depends'] := Depends;
      PackageEdited.S['conflicts'] := Conflicts;
      DMPython.PythonEng.ExecString('p = waptpackage.PackageEntry()');
      DMPython.PythonEng.ExecString(
        format('p.load_control_from_dict(json.loads(r''%s''))', [PackageEdited.AsJson]));
      DMPython.PythonEng.ExecString(
        format('p.save_control_to_wapt(r''%s''.decode(''utf8''))', [EdSourceDir.Text]));
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
    GridDependsUpdated or GridConflictsUpdated;
end;

procedure TVisEditPackage.ActEditSearchExecute(Sender: TObject);
var
  expr: UTF8String;
  packages: ISuperObject;
begin
  expr := format('mywapt.search(r"%s".decode(''utf8'').split())', [EdSearch.Text]);
  packages := DMPython.RunJSON(expr);
  GridPackages.Data := packages;
  GridPackages.Header.AutoFitColumns(False);
end;

procedure TVisEditPackage.ActBuildUploadExecute(Sender: TObject);
var
  expr, res: string;
  package: string;
  Result: ISuperObject;
begin
  Result := Nil;

  ActEditSavePackage.Execute;

  if not FileExists(GetWaptPrivateKeyPath) then
  begin
    ShowMessage('La clé privée n''existe pas: ' + GetWaptPrivateKeyPath);
    exit;
  end;

  with TVisLoading.Create(Self) do
  try
    ProgressTitle('Upload en cours');
    Application.ProcessMessages;
    try
      Result := DMPython.RunJSON(format(
        'mywapt.build_upload(r"%s".decode(''utf8''),r"%s",r"%s",r"%s",True)',
        [FSourcePath, privateKeyPassword, waptServerUser, waptServerPassword]), jsonlog);
      if FisTempSourcesDir then
      begin
        FileUtil.DeleteDirectory(FSourcePath, False);
        if Result.AsArray <> nil then
          FileUtil.DeleteFileUTF8(Result.AsArray[0].S['filename']);
      end;
    except
      on E:Exception do
      begin
        ShowMessage('Problème lors de la création du paquet: '+E.Message);
        Result := Nil;
        ModalResult:=mrNone;
        Abort;
      end;
    end;
  finally
    Free;
  end;

  if (Result<>Nil) and (Result.AsArray <> nil) and (Result.AsArray[0]['filename']<>Nil) then
    ModalResult := mrOk
end;

procedure TVisEditPackage.ActEditRemoveConflictsExecute(Sender: TObject);
begin
  GridConflicts.DeleteSelectedNodes;
  Conflicts := Conflicts;
  GridConflictsUpdated := True;
end;

procedure TVisEditPackage.ActEditRemoveConflictsUpdate(Sender: TObject);
begin
  ActEditRemoveConflicts.Enabled:=GridConflicts.SelectedCount>0
end;

procedure TVisEditPackage.ActAdvancedModeExecute(Sender: TObject);
begin
  isAdvancedMode := ActAdvancedMode.Checked;
end;

procedure TVisEditPackage.ActBUApplyExecute(Sender: TObject);
begin
  ApplyUpdatesImmediately := True;
  ActBuildUpload.Execute;
  ModalResult:=mrOK;
end;

procedure TVisEditPackage.ActAddDependsUpdate(Sender: TObject);
begin
  ActAddDepends.Enabled := GridPackages.SelectedCount > 0;
end;

procedure TVisEditPackage.ActAddDependsExecute(Sender: TObject);
begin
  AddDepends(Sender);
end;

procedure TVisEditPackage.ActAddConflictsUpdate(Sender: TObject);
begin
    ActAddConflicts.Enabled := GridPackages.SelectedCount > 0;
end;

procedure TVisEditPackage.ActAddConflictsExecute(Sender: TObject);
begin
  AddConflicts(Sender);
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
  expr := format('mywapt.search(r"%s".decode(''utf8'').split())', [EdSearch.Text]);
  packages := DMPython.RunJSON(expr);
  GridPackages.Data := packages;
  GridPackages.Header.AutoFitColumns(False);
end;

procedure TVisEditPackage.FormCreate(Sender: TObject);
begin
  waptpath := ExtractFileDir(ParamStr(0));

  GridPackages.Clear;
  MemoLog.Clear;

  GridDepends.Clear;
  GridConflicts.Clear;

end;

procedure TVisEditPackage.FormShow(Sender: TObject);
begin
  ActEditSearch.Execute;
  EdPackage.SetFocus;
end;

procedure TVisEditPackage.GridConflictsDragDrop(Sender: TBaseVirtualTree;
  Source: TObject; DataObject: IDataObject; Formats: TFormatArray;
  Shift: TShiftState; const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
begin
  AddConflicts(Sender);
end;

procedure TVisEditPackage.AddConflicts(Sender: TObject);
var
  i: integer;
  sel: TNodeArray;
  oldconflicts: ISuperObject;
  package: string;
begin
  oldconflicts := Split(Conflicts, ',');
  sel := GridPackages.GetSortedSelection(False);
  for i := 0 to length(sel) - 1 do
  begin
    package := GridPackages.GetCellStrValue(sel[i], 'package');
    if not StrIn(package, oldConflicts) then
      oldConflicts.AsArray.Add(package);
  end;
  Conflicts := Join(',', oldConflicts);
end;


function MkTempDir(prefix: string = ''): string;
var
  i: integer;
begin
  if prefix = '' then
    prefix := 'wapt';
  i := 0;
  repeat
    Inc(i);
    Result := GetTempDir(False) + prefix + FormatFloat('0000', i);
  until not DirectoryExists(Result);
  MkDir(Result);
end;

procedure TVisEditPackage.SetPackageRequest(AValue: string);
var
  res: ISuperObject;
  n: PVirtualNode;
  filename, filePath, target_directory: string;
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
      begin
        target_directory := MkTempDir();
        FisTempSourcesDir := True;
        res := DMPython.RunJSON(
          format('mywapt.edit_host("%s",target_directory=r"%s".decode(''utf8''),use_local_sources=False)',
          [FPackageRequest, target_directory]));
        EdPackage.EditLabel.Caption := 'Machine';
        Caption := 'Modifier la configuration de la machine';
        pgEditPackage.Caption := 'Paquets devant être présents sur la machine';
        EdVersion.Parent := Panel4;
        EdVersion.Top := 5;
      end
      else
      begin
        with  TVisLoading.Create(Self) do
          try
            ProgressTitle('Téléchargement en cours');
            Application.ProcessMessages;
            if isGroup then
            begin
              Caption := 'Modifier la configuration du groupe';
              grid := uwaptconsole.VisWaptGUI.GridGroups;
            end
            else
              grid := uwaptconsole.VisWaptGUI.GridPackages;
            n := grid.GetFirstSelected();
            if n <> nil then
              try
                filename := grid.GetCellStrValue(n, 'filename');
                filePath := AppLocalDir + 'cache\' + filename;
                if not DirectoryExists(AppLocalDir + 'cache') then
                  mkdir(AppLocalDir + 'cache');
                // la gestion du cache implique de lire la version di paquet WAPT dans le fichier control.
                // (paquets de groupe et paquets host)
                //if not FileExists(filePath) then
                Wget(GetWaptRepoURL + '/' + filename, filePath,
                  ProgressForm, @updateprogress, WaptUseLocalConnectionProxy);
              except
                ShowMessage('Téléchargement annulé');
                if FileExists(filePath) then
                  DeleteFile(filePath);
                exit;
              end;

            res := DMPython.RunJSON(format('mywapt.edit_package(r"%s")', [filePath]));
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
    GridConflictsUpdated := False;
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
  GridDepends.Header.AutoFitColumns(False);
  if dependencies['missing'].AsArray.Length > 0 then
  begin
    ShowMessageFmt('Attention, les paquets %s ont été ignorés car introuvables',
      [dependencies.S['missing']]);
    GridDependsUpdated := True;
  end;
  FIsUpdated := True;
end;

procedure TVisEditPackage.SetConflicts(AValue: string);
var
  aconflicts: ISuperObject;
begin
  if AValue = '' then
    Exit;
  FConflicts := AValue;
  aconflicts := DMPython.RunJSON(
    format('mywapt.get_package_entries("%s")', [FConflicts]));
  GridConflicts.Data := aconflicts['packages'];
  GridConflicts.Header.AutoFitColumns(False);
  if aconflicts['missing'].AsArray.Length > 0 then
  begin
    ShowMessageFmt('Attention, les paquets %s ont été ignorés des paquets interdits car introuvables',
      [aconflicts.S['missing']]);
    GridConflictsUpdated := True;
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
      FDepends := FDepends + ',' + GridDepends.GetCellStrValue(n, 'package')
    else
      FDepends := GridDepends.GetCellStrValue(n, 'package');
    n := GridDepends.GetNext(n);
  end;
  Result := FDepends;
end;

function TVisEditPackage.GetConflicts: string;
var
  n: PVirtualNode;
begin
  FConflicts := '';
  n := GridConflicts.GetFirst;
  while (n <> nil) do
  begin
    if FConflicts <> '' then
      FConflicts := FConflicts + ',' + GridConflicts.GetCellStrValue(n, 'package')
    else
      FConflicts := GridConflicts.GetCellStrValue(n, 'package');
    n := GridConflicts.GetNext(n);
  end;
  Result := FConflicts;
end;


function TVisEditPackage.updateprogress(receiver: TObject;
  current, total: integer): boolean;
begin
  if receiver <> nil then
    with (receiver as TVisLoading) do
    begin
      ProgressStep(current, total);
      Result := not StopRequired;
    end
  else
    Result := True;
end;

end.
