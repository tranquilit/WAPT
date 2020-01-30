unit uviseditpackage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, LazUTF8, SynHighlighterPython, SynEdit, Forms, Controls,
  Graphics, Dialogs, ExtCtrls, StdCtrls, ComCtrls, ActnList, Menus, Buttons,
  superobject, VirtualTrees, VarPyth, PythonEngine, types, ActiveX, LCLIntf,
  LCL, sogrid, vte_json, DefaultTranslator, SearchEdit;

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
    ActionsImages: TImageList;
    ActSearchPackage: TAction;
    ActionList1: TActionList;
    ButAddPackages: TBitBtn;
    butBUApply1: TBitBtn;
    ButCancel: TBitBtn;
    butInitWapt: TBitBtn;
    butSearchPackages1: TBitBtn;
    butBUApply: TBitBtn;
    cbShowLog: TCheckBox;
    EdDescription: TEdit;
    EdPackage: TEdit;
    EdSearch: TSearchEdit;
    EdSection: TComboBox;
    EdVersion: TLabeledEdit;
    GridConflicts: TSOGrid;
    GridPackages: TSOGrid;
    LabDescription: TLabel;
    labPackage: TLabel;
    Label2: TLabel;
    GridDepends: TSOGrid;
    LabSection: TLabel;
    MemoLog: TMemo;
    MenuItem1: TMenuItem;
    MenuAddPackages: TMenuItem;
    MenuItem4: TMenuItem;
    MenuItem5: TMenuItem;
    PageControl1: TPageControl;
    Panel1: TPanel;
    Panel2: TPanel;
    Panel3: TPanel;
    PanRight: TPanel;
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
    pgDepends: TTabSheet;
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
    procedure cbShowLogClick(Sender: TObject);
    procedure EdPackageExit(Sender: TObject);
    procedure EdPackageKeyPress(Sender: TObject; var Key: char);
    procedure EdSearchExecute(Sender: TObject);
    procedure EdSearchKeyDown(Sender: TObject; var Key: word; Shift: TShiftState);
    procedure EdSectionChange(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    function GridConflictsBeforePaste(Sender: TSOGrid; Row: ISuperObject
      ): boolean;
    procedure GridConflictsDragDrop(Sender: TBaseVirtualTree; Source: TObject;
      DataObject: IDataObject; Formats: TFormatArray; Shift: TShiftState;
      const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
    procedure GridConflictsNodesDelete(Sender: TSOGrid; Rows: ISuperObject);
    function GridDependsBeforePaste(Sender: TSOGrid; Row: ISuperObject
      ): boolean;
    procedure GridDependsDragDrop(Sender: TBaseVirtualTree; Source: TObject;
      DataObject: IDataObject; Formats: TFormatArray; Shift: TShiftState;
      const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
    procedure GridDependsDragOver(Sender: TBaseVirtualTree; Source: TObject;
      Shift: TShiftState; State: TDragState; const Pt: TPoint;
      Mode: TDropMode; var Effect: DWORD; var Accept: boolean);
    procedure GridDependsNodesDelete(Sender: TSOGrid; Rows: ISuperObject);
    procedure GridPackagesGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      RowData, CellData: ISuperObject; Column: TColumnIndex;
      TextType: TVSTTextType; var CellText: string);
    procedure PageControl1Change(Sender: TObject);
  private
    FisAdvancedMode: boolean;
    FisTempSourcesDir: boolean;
    { private declarations }
    FPackageRequest: string;
    FIsUpdated: boolean;
    GridDependsUpdated: boolean;
    GridConflictsUpdated: boolean;
    FDepends: string;
    FConflicts: string;
    procedure AddDepends(Sender: TObject);
    procedure AddConflicts(Sender: TObject);
    function CheckUpdated: boolean;
    function GetSourcePath: string;
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
    IsNewPackage: boolean;
    PackageEdited: Variant;
    ApplyUpdatesImmediately:Boolean;
    CurrentHost: ISuperObject;
    HostCapabilities: Variant;
    property isAdvancedMode: boolean read FisAdvancedMode write SetisAdvancedMode;
    procedure EditPackage;
    property SourcePath: string read GetSourcePath write SetSourcePath;
    property PackageRequest: string read FPackageRequest write SetPackageRequest;
  end;

function EditPackage(packagename: string; advancedMode: boolean): ISuperObject;
function CreatePackage(packagename: string; advancedMode: boolean): ISuperObject;
function CreateGroup(packagename: string; advancedMode: boolean=False; section: String ='group'): ISuperObject;
function EditHost(host: ISuperObject; advancedMode: boolean; var ApplyUpdates:Boolean; ForceMinVersion:String=''): Variant;

function EditGroup(group: string; advancedMode: boolean; section:String = 'group';description:String=''): ISuperObject;


var
  VisEditPackage: TVisEditPackage;

implementation

uses uWaptConsoleRes,soutils, LCLType, Variants, waptcommon, dmwaptpython, jwawinuser, uvisloading,
  uvisprivatekeyauth, uwaptconsole, tiscommon, uWaptRes,tisinifiles,tisstrings,
  LazFileUtils, FileUtil, uWaptPythonUtils;

{$R *.lfm}

function EditPackage(packagename: string; advancedMode: boolean): ISuperObject;
begin
  with TVisEditPackage.Create(nil) do
    try
      isAdvancedMode := advancedMode;
      PackageRequest := packagename;
      if ShowModal = mrOk then
        Result := PyVarToSuperObject(PackageEdited.as_dict('--noarg--'))
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
      EdSection.Enabled:=advancedMode;
      EdSection.ItemIndex := EdSection.Items.IndexOf('group');
      EdVersion.Enabled:=advancedMode;
      EdVersion.ReadOnly:=not advancedMode;
      if ShowModal = mrOk then
        Result := PyVarToSuperObject(PackageEdited.as_dict('--noarg--'))
      else
        Result := nil;
    finally
      Free;
    end;
end;

function CreateGroup(packagename: string; advancedMode: boolean=False; section: String ='group'): ISuperObject;
begin
  with TVisEditPackage.Create(nil) do
    try
      if section='group' then
        Caption:= rsEditBundle
      else if section='unit' then
        Caption:= rsEditUnitBundle
      else if section='profile' then
        Caption:= rsEditHostProfile;


      LabPackage.Caption := rsEdPackage;
      pgDepends.Caption := rsPackagesNeededCaption;

      isAdvancedMode := advancedMode;
      IsNewPackage := True;
      PackageRequest := packagename;
      EdSection.Text:=section;
      EdSection.ItemIndex := EdSection.Items.IndexOf(section);
      ActBUApply.Visible:=False;
      EdVersion.Enabled:=advancedMode;
      EdVersion.ReadOnly:=not advancedMode;
      if ShowModal = mrOk then
        Result := PyVarToSuperObject(PackageEdited.as_dict('--noarg--'))
      else
        Result := nil;
    finally
      Free;
    end;
end;

function EditHost(host: ISuperObject; advancedMode: boolean;var ApplyUpdates:Boolean;
      ForceMinVersion:String=''): Variant;
var
  hostuuid,description,computer_fqdn_hint: String;
begin
  with TVisEditPackage.Create(nil) do
    try
      CurrentHost := Host;
      computer_fqdn_hint := UTF8Encode(host.S['computer_fqdn']);
      hostuuid := UTF8Encode(host.S['uuid']);
      description := UTF8Encode(host.S['description']);

      // TO filter out available packages and rights
      HostCapabilities := SuperObjectToPyVar(host['host_capabilities']);

      EdSection.Text:='host';
      Result := Nil;
      isAdvancedMode := advancedMode;
      PackageRequest := hostuuid;
      if (ForceMinVersion<>'') and (CompareVersion(EdVersion.Text,ForceMinVersion)<0) then
      begin
        EdVersion.Text:=ForceMinVersion;
        IsUpdated:=True;
      end;

      if computer_fqdn_hint<>'' then
        Caption:= Format(rsEditHostCaption,[computer_fqdn_hint])
      else
        Caption:= Format(rsEditHostCaption,[hostuuid]);

      EdVersion.Enabled:=advancedMode;
      EdVersion.ReadOnly:=not advancedMode;

      if description<>'' then
      begin
        Eddescription.Text := description;
        if computer_fqdn_hint<>'' then
          EdDescription.Text := EdDescription.Text+' ('+computer_fqdn_hint+')';
      end
      else
        EdDescription.Text := computer_fqdn_hint;

      EdPackage.ReadOnly:=True;
      EdPackage.ParentColor:=True;

      ActBUApply.Visible := host.S['reachable'] = 'OK';

      if ShowModal = mrOk then
      try
        Result := PackageEdited;
        ApplyUpdates:=ApplyUpdatesImmediately;
      except
        on E:Exception do
          ShowMessageFmt('Error editing host %s',[e.Message]);
      end
      else
        Result := None();
    finally
      Free;
    end;
end;

function EditGroup(group: string; advancedMode: boolean; section:String = 'group';description:String=''): ISuperObject;
begin
  with TVisEditPackage.Create(nil) do
    try
      EdSection.Text:=section;
      isAdvancedMode := advancedMode;
      PackageRequest := group;
      EdVersion.Enabled:=advancedMode;
      EdVersion.ReadOnly:=not advancedMode;
      if EdVersion.ReadOnly then
        EdVersion.ParentColor:=True;

      EdPackage.ReadOnly:=not IsNewPackage and not advancedMode;
      if EdPackage.ReadOnly then
        EdPackage.ParentColor:=True;

      Caption:=rsEditBundle;
      LabPackage.Caption := rsEdPackage;
      pgDepends.Caption := rsPackagesNeededCaption;

      if description<>'' then
        EdDescription.Text:=description;

      if ShowModal = mrOk then
        Result := PyVarToSuperObject(PackageEdited.as_dict('--noarg--'))
      else
        Result := nil;
    finally
      Free;
    end;
end;

function EditOrgUnit(OrgUnit: string; advancedMode: boolean): ISuperObject;
begin
  with TVisEditPackage.Create(nil) do
    try
      EdSection.Text:='unit';
      isAdvancedMode := advancedMode;
      PackageRequest := OrgUnit;
      EdVersion.Enabled:=advancedMode;
      EdVersion.ReadOnly:=not advancedMode;
      if EdVersion.ReadOnly then
        EdVersion.ParentColor:=True;

      EdPackage.ReadOnly:=not IsNewPackage and not advancedMode;
      if EdPackage.ReadOnly then
        EdPackage.ParentColor:=True;

      Caption:=rsEditUnitBundle;
      LabPackage.Caption := rsEdPackage;
      pgDepends.Caption := rsPackagesNeededCaption;

      if ShowModal = mrOk then
        Result := PyVarToSuperObject(PackageEdited.as_dict('--noarg--'))
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

procedure TVisEditPackage.EdPackageExit(Sender: TObject);
begin
  EdPackage.Text:=MakeValidPackageName(EdPackage.Text);
end;

procedure TVisEditPackage.EdPackageKeyPress(Sender: TObject; var Key: char);
begin
  if not (lowercase(key) in ['a'..'z','0'..'9','-',#8,#9]) then
      Key:=#0;
end;

procedure TVisEditPackage.EdSearchExecute(Sender: TObject);
begin
  if EdSearch.Modified then
    ActEditSearchExecute(Sender);
end;

procedure TVisEditPackage.EdSearchKeyDown(Sender: TObject; var Key: word;
  Shift: TShiftState);
begin
  if Key = VK_RETURN then
  begin
    EdSearch.SelectAll;
    ActEditSearch.Execute;
  end;

end;

procedure TVisEditPackage.EdSectionChange(Sender: TObject);
begin
  FIsUpdated := True;
end;

procedure TVisEditPackage.FormClose(Sender: TObject;
  var CloseAction: TCloseAction);
begin
  IniWriteInteger(Appuserinipath,Name,'Top',Top);
  IniWriteInteger(Appuserinipath,Name,'Left',Left);
  IniWriteInteger(Appuserinipath,Name,'Width',Width);
  IniWriteInteger(Appuserinipath,Name,'Height',Height);
  IniWriteInteger(Appuserinipath,Name,PanRight.Name+'.Width',PanRight.Width);

  GridConflicts.SaveSettingsToIni(Appuserinipath);
  GridDepends.SaveSettingsToIni(Appuserinipath);
  GridPackages.SaveSettingsToIni(Appuserinipath);;

end;

procedure TVisEditPackage.FormCloseQuery(Sender: TObject; var CanClose: boolean);
begin
  CanClose := CheckUpdated;
  if FisTempSourcesDir and DirectoryExists(SourcePath) then
    FileUtil.DeleteDirectory(SourcePath, False);
end;

function TVisEditPackage.CheckUpdated: boolean;
var
  Rep: integer;
  msg: string;
begin
  Result := not IsUpdated;
  if not Result then
  begin
    msg := rsSaveMods;
    Rep := Application.MessageBox(PChar(msg), PChar(rsConfirmCaption), MB_APPLMODAL +
      MB_ICONQUESTION + MB_YESNOCANCEL);
    if (Rep = idYes) then
      Result := ActBuildUpload.Execute
    else
    if (Rep = idNo) then
      Result := True;
  end;
end;

function TVisEditPackage.GetSourcePath: string;
begin
  if not VarIsEmpty(PackageEdited.sourcespath) and not VarIsNone(PackageEdited.sourcespath) and (VarPythonAsString(PackageEdited.sourcespath)<>'') then
    Result := VarPythonAsString(PackageEdited.sourcespath)
  else
    Result := '';
end;

procedure TVisEditPackage.SetisAdvancedMode(AValue: boolean);
begin
  if FisAdvancedMode = AValue then
    Exit;
  FisAdvancedMode := AValue;
  // Advance mode in mainWindow -> tools => advance
  PanelDevlop.Visible := isAdvancedMode;
  LabSection.Visible := isAdvancedMode;
  EdSection.Visible := isAdvancedMode;
  cbShowLog.Visible := isAdvancedMode;
  if isAdvancedMode then
    pgDevelop.TabVisible := True;
  Eddescription.Visible := (EdSection.Text<>'host') or isAdvancedMode;

end;

procedure TVisEditPackage.EditPackage;
var
  setuppypath:String;
begin
  EdPackage.Text := UTF8Encode(StrReplaceChar(VarPythonAsString(PackageEdited.package),',','_'));
  EdVersion.Text := UTF8Encode(StrReplaceChar(VarPythonAsString(PackageEdited.version),',','_'));
  EdDescription.Text := UTF8Encode(VarPythonAsString(PackageEdited.description));
  EdSection.Text := UTF8Encode(VarPythonAsString(PackageEdited.section));
  IsUpdated := False;
  // get a list of package entries given a
  Depends := UTF8Encode(VarPythonAsString(PackageEdited.depends));
  Conflicts := UTF8Encode(VarPythonAsString(PackageEdited.conflicts));
  if VarPythonAsString(PackageEdited.sourcespath) <> '' then
  begin
    setuppypath := VarPythonAsString(PackageEdited.sourcespath) + '\setup.py';
    if FileExistsUTF8(setuppypath) then
    begin
      EdSetupPy.Lines.LoadFromFile(setuppypath);
      pgDevelop.TabVisible := True;
    end
    else
      EdSetupPy.Lines.Clear;
  end;
  butBUApply.Visible:=EdSection.Text='host';
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

procedure RemoveString(List:ISuperObject;St:string);
var
  i:Integer;
  it:ISuperObject;
begin
  if List <>Nil then
    for i :=0 to List.AsArray.Length-1 do
    begin
      it := List.AsArray[i];
      if (it.DataType=stString) and (it.AsString=Utf8Decode(St)) then
      begin
        List.AsArray.Delete(i);
        Exit;
      end;
    end;
end;

procedure TVisEditPackage.AddDepends(Sender: TObject);
var
  row,olddepends,oldconflicts: ISuperObject;
  package: string;
begin
  olddepends := Split(Depends, ',');
  oldconflicts := Split(Conflicts, ',');
  for row in GridPackages.SelectedRows do
  begin
    package := UTF8Encode(row.S['package']);
    if not StrIn(package, olddepends) then
    begin
      olddepends.AsArray.Add(utf8Decode(package));
      GridDependsUpdated:=True;
    end;
    RemoveString(oldconflicts,package);
    GridConflictsUpdated :=True;
  end;
  Depends := UTF8Encode(soutils.Join(',', olddepends));
  Conflicts := UTF8Encode(soutils.Join(',', oldconflicts));
end;

procedure TVisEditPackage.GridDependsDragOver(Sender: TBaseVirtualTree;
  Source: TObject; Shift: TShiftState; State: TDragState; const Pt: TPoint;
  Mode: TDropMode; var Effect: DWORD; var Accept: boolean);
begin
  Accept := Source = GridPackages;
end;

procedure TVisEditPackage.GridDependsNodesDelete(Sender: TSOGrid;
  Rows: ISuperObject);
begin
  GridDependsUpdated := True;
end;

procedure TVisEditPackage.GridPackagesGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; RowData, CellData: ISuperObject; Column: TColumnIndex;
  TextType: TVSTTextType; var CellText: string);
var
  colname: String;
begin
  if celltext<>'' then
  begin
    colname := ((Sender as TSOGrid).Header.Columns[Column] as TSOGridColumn).PropertyName;
    if  (colname = 'depends') or (colname = 'conflicts') then
      StrReplace(CellText, ',', #13#10, [rfReplaceAll]);

    if (CellData <> nil) and (CellData.DataType = stArray) then
      CellText := soutils.Join(#13#10, CellData)
    else
    begin
      if StrIsOneOf(colname,['size','installed_size']) then
        CellText := FormatFloat('# ##0 kB',StrToInt64(CellText) div 1024);

      if StrIsOneOf(colname,['description','description_fr','description_en','description_en']) then
        CellText := UTF8Encode(Celltext);

      if StrIsOneOf(colname,['install_date','last_audit_on','signature_date','next_audit_on','created_on','updated_on']) then
          CellText := Copy(StrReplaceChar(CellText,'T',' '),1,16);
    end;
  end;
end;

procedure TVisEditPackage.PageControl1Change(Sender: TObject);
begin
  if PageControl1.ActivePage = pgDepends then
  begin
    ButAddPackages.Action := ActAddDepends;
    MenuAddPackages.Action := ActAddDepends;
  end
  else
  begin
    ButAddPackages.Action := ActAddConflicts;
    MenuAddPackages.Action := ActAddConflicts;
  end;
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
  vpackagename,vdescription,vsection,vversion,vdepends,vconflicts:Variant;
begin
  Screen.Cursor := crHourGlass;
  try
    vpackagename:=PyUTF8Decode(MakeValidPackageName(EdPackage.Text));
    vversion:=PyUTF8Decode(Trim(EdVersion.Text));
    vdepends:=PyUTF8Decode(Depends);
    vconflicts:=PyUTF8Decode(Conflicts);
    vsection := PyUTF8Decode(EdSection.Text);
    vdescription:=PyUTF8Decode(trim(Eddescription.Text));

    PackageEdited.package := vpackagename;
    PackageEdited.version := vversion;
    PackageEdited.depends := vdepends;
    PackageEdited.conflicts := vconflicts;
    PackageEdited.description := vdescription;
    PackageEdited.section := vsection;

    if SourcePath<>'' then
    begin
      PackageEdited.save_control_to_wapt('--noarg--');
      if EdSetupPy.Lines.Count>0 then
        EdSetupPy.Lines.SaveToFile(AppendPathDelim(SourcePath) + 'setup.py')
      else
        DeleteFile(AppendPathDelim(SourcePath) + 'setup.py');
    end;
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TVisEditPackage.ActEditSavePackageUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled := (EdPackage.Text<>'') and IsUpdated and
     DMPython.UserCertAllowedOnHost(CurrentHost);
end;

function TVisEditPackage.GetIsUpdated: boolean;
begin
  Result := FIsUpdated or EdPackage.Modified or EdVersion.Modified or
    EdSetupPy.Modified or Eddescription.Modified or
    GridDependsUpdated or GridConflictsUpdated;
end;

procedure TVisEditPackage.ActEditSearchExecute(Sender: TObject);
begin
  EdSearch.Modified:=False;
  GridPackages.Data := PyVarToSuperObject(DMPython.MainWaptRepo.search(
    searchwords := EdSearch.Text, newest_only := True,description_locale := Language,
    exclude_sections := 'host,unit,profile',
    host_capabilities := HostCapabilities));
end;

procedure TVisEditPackage.ActBuildUploadExecute(Sender: TObject);
var
  vprivatekeypassword, VWaptServerPassword, vbuildfilename,vsourcepath,packages: Variant;
  res: ISuperObject;

begin
  Res := Nil;
  ActEditSavePackage.Execute;

  if not FileExistsUTF8(WaptPersonalCertificatePath) then
  begin
    ShowMessageFmt(rsPrivateKeyDoesntExist, [WaptPersonalCertificatePath]);
    exit;
  end;

  with TVisLoading.Create(Self) do
  try
    ProgressTitle(rsUploading);
    Application.ProcessMessages;
    try
      { TODO : Remove use of WAPT instance, use waptpackage.PackageEntry instead }
      if SourcePath<>'' then
        vbuildfilename := PackageEdited.build_package('--noarg--')
      else
        vbuildfilename := PackageEdited.build_management_package('--noarg--');

      vprivatekeypassword := PyUTF8Decode(dmpython.privateKeyPassword);
      PackageEdited.inc_build('--noarg--');
      PackageEdited.sign_package(
        certificate := DMPython.WAPT.personal_certificate('--noarg--'),
        private_key := DMPython.WAPT.private_key(private_key_password := vprivatekeypassword));

      VWaptServerPassword := PyUTF8Decode(WaptServerPassword);
      packages := VarPythonCreate([PackageEdited]);
      res := PyVarToSuperObject(DMPython.WAPT.http_upload_package(
          packages := packages,
          wapt_server_user := waptServerUser,
          wapt_server_passwd := VWaptServerPassword));

      if (res=Nil) or not Res.B['success']  then
        raise Exception.Create('Error when uploading package');

      if FisTempSourcesDir then
        FileUtil.DeleteDirectory(SourcePath, False);
      if FileExistsUTF8(vbuildfilename) then
        DeleteFileUTF8(vbuildfilename);

      IsUpdated := False;
    except
      on E:Exception do
      begin
        ShowMessageFmt(rsPackageCreationError, [E.Message]);
        Res := Nil;
        ModalResult:=mrNone;
        Abort;
      end;
    end;
  finally
    Free;
  end;
  if (res<>Nil) and Res.B['success'] then
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

procedure TVisEditPackage.FormCreate(Sender: TObject);
begin
  GridPackages.Clear;
  MemoLog.Clear;

  GridDepends.Clear;
  GridConflicts.Clear;

  HostCapabilities := None();
end;

procedure TVisEditPackage.FormShow(Sender: TObject);
begin
  Top :=  IniReadInteger(Appuserinipath,Name,'Top',Top);
  Left := IniReadInteger(Appuserinipath,Name,'Left',Left);
  Width := IniReadInteger(Appuserinipath,Name,'Width',Width);
  Height := IniReadInteger(Appuserinipath,Name,'Height',Height);

  if Screen.PixelsPerInch <> 96 then
  begin
    GridConflicts.Header.Height:=trunc((GridConflicts.Header.MinHeight*Screen.PixelsPerInch)/96);
    GridPackages.Header.Height:=trunc((GridPackages.Header.MinHeight*Screen.PixelsPerInch)/96);
    GridDepends.Header.Height:=trunc((GridDepends.Header.MinHeight*Screen.PixelsPerInch)/96);
    jsonlog.Header.Height:=trunc((jsonlog.Header.MinHeight*Screen.PixelsPerInch)/96);
  end;

  MakeFullyVisible();

  PanRight.Width:=IniReadInteger(Appuserinipath,Name,PanRight.Name+'.Width',PanRight.Width);
  GridConflicts.LoadSettingsFromIni(Appuserinipath);
  GridDepends.LoadSettingsFromIni(Appuserinipath);
  GridPackages.LoadSettingsFromIni(Appuserinipath);;

  ActEditSearch.Execute;
  EdPackage.SetFocus;
end;

function TVisEditPackage.GridConflictsBeforePaste(Sender: TSOGrid;
  Row: ISuperObject): boolean;
begin
  Result := SOArrayFindFirst(Row,GridConflicts.data,['package']) = Nil;
  GridConflictsUpdated := True;
end;

procedure TVisEditPackage.GridConflictsDragDrop(Sender: TBaseVirtualTree;
  Source: TObject; DataObject: IDataObject; Formats: TFormatArray;
  Shift: TShiftState; const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
begin
  AddConflicts(Sender);
end;

procedure TVisEditPackage.GridConflictsNodesDelete(Sender: TSOGrid;
  Rows: ISuperObject);
begin
  GridConflictsUpdated := True;
end;

function TVisEditPackage.GridDependsBeforePaste(Sender: TSOGrid;
  Row: ISuperObject): boolean;
begin
  Result := SOArrayFindFirst(Row,GridDepends.data,['package']) = Nil;
  GridDependsUpdated := True;
end;

procedure TVisEditPackage.AddConflicts(Sender: TObject);
var
  row,olddepends,oldconflicts: ISuperObject;
  package: string;
begin
  olddepends := Split(Depends, ',');
  oldconflicts := Split(Conflicts, ',');
  for row in GridPackages.SelectedRows do
  begin
    package := UTF8Encode(row.S['package']);
    if not StrIn(package, oldconflicts) then
    begin
      oldconflicts.AsArray.Add(UTF8Decode(package));
      GridConflictsUpdated:=True;
    end;
    RemoveString(olddepends,package);
    GridDependsUpdated:=True;
  end;
  Depends := soutils.Join(',', olddepends);
  Conflicts := soutils.Join(',', oldconflicts);
end;


function UniqueTempDir(prefix: string = ''): string;
begin
  if prefix = '' then
    prefix := 'wapt';
  repeat
    Result := GetTempDir(False) + prefix + IntToStr(Random(maxint));
  until not DirectoryExistsUTF8(Result) and not FileExistsUTF8(Result);
end;

procedure TVisEditPackage.SetPackageRequest(AValue: string);
var
  filename, filePath, proxy: string;
  vFilePath: Variant;
  PackagesCount: Integer;
  PyNone,repo,packages,cabundle,VWaptIniFilename: Variant;
begin
  if FPackageRequest = AValue then
    Exit;
  if AValue='' then
    raise Exception.Create('Can not edit an Empty package name');

  Screen.Cursor := crHourGlass;
  try
    FPackageRequest := AValue;
    cabundle := DMPython.WAPT.cabundle;

    VWaptIniFilename := PyUTF8Decode(WaptIniFilename);
    if EdSection.text='host' then
    begin
      LabPackage.Caption := 'UUID';
      Caption := rsHostConfigEditCaption;

      pgDepends.Caption := rsPackagesNeededOnHostCaption;
      repo := DMPython.WaptHostRepo;
      repo.host_id := FPackageRequest;
      PackageEdited := repo.get(FPackageRequest);
      // clear cache
      PyNone := None;
      repo.host_id := PyNone;
      IsNewPackage:=VarIsEmpty(PackageEdited) or VarIsNone(PackageEdited);
      if IsNewPackage then
        PackageEdited := DMPython.waptpackage.PackageEntry(package := FPackageRequest,version := String('0'),section := 'host')
    end
    else
    begin
      repo := DMPython.MainWaptRepo;
      Proxy := repo.http_proxy;

      packages := repo.packages_matching(FPackageRequest);
      PackagesCount := Varpyth.len(packages);
      IsNewPackage := PackagesCount <= 0;
      if not IsNewPackage then
        PackageEdited := packages.__getitem__(-1)
      else
        PackageEdited := DMPython.waptpackage.PackageEntry(package := FPackageRequest,version := String('0'),section := EdSection.Text);

      {$ifdef ENTERPRISE}
      EdSection.Enabled:=IsNewPackage;
      {$endif}
    end;

    if not IsNewPackage
        and (VarPythonAsString(PackageEdited.section) <> 'host')
        and  (VarPythonAsString(PackageEdited.section) <> 'unit')
        and  (VarPythonAsString(PackageEdited.section) <> 'group') then
      with  TVisLoading.Create(Self) do
      try
        ProgressTitle('Téléchargement en cours');
        Application.ProcessMessages;
        if StrIsOneOf(EdSection.Text,['group','profile','unit']) then
          Caption := rsBundleConfigEditCaption;

        try
          filename := PackageEdited.filename;
          filePath := AppLocalDir + 'cache\' + filename;
          if not DirectoryExists(AppLocalDir + 'cache') then
            mkdir(AppLocalDir + 'cache');

          if not IdWget(VarPythonAsString(PackageEdited.download_url), filePath,
              ProgressForm, @updateprogress, Proxy,
              DefaultUserAgent,GetWaptServerCertificateFilename(),Nil,
              WaptClientCertFilename,WaptClientKeyFilename) then
            Raise Exception.CreateFmt('Unable to download %s',[PackageEdited.download_url]);

          vFilePath := PyUTF8Decode(filePath);
          PackageEdited := DMPython.waptpackage.PackageEntry(waptfile := vFilePath);
          PackageEdited.unzip_package(cabundle := cabundle);

          FisTempSourcesDir := True;
        except
          ShowMessage(rsDlCanceled);
          if FileExistsUTF8(filePath) then
            DeleteFileUTF8(filePath);
          raise;
        end;

    finally
      Free;
    end;

  finally
    Screen.Cursor := crDefault;
  end;
  EditPackage;
end;

procedure TVisEditPackage.SetSourcePath(AValue: string);
var
  vSourcePath: Variant;
begin
  if GetSourcePath = AValue then
    Exit;
  try
    { TODO : Remove use of WAPT instance, use waptpackage.PackageEntry instead }
    vSourcePath := PyUTF8Decode(AValue);
    PackageEdited := DMPython.waptpackage.PackageEntry(waptfile := vSourcePath);
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
    EdSetupPy.Modified := False;
    GridDependsUpdated := False;
    GridConflictsUpdated := False;
  end;
end;

procedure TVisEditPackage.SetDepends(AValue: string);
var
  dependencies: ISuperObject;
  VDepends:Variant;
begin
  FDepends := AValue;
  if FDepends<>'' then
  begin
    vDepends := PyUTF8Decode(FDepends);
    dependencies := PyVarToSuperObject(DMPython.MainWaptRepo.get_package_entries(vDepends));
    GridDepends.Data := dependencies['packages'];
    if dependencies['missing'].AsArray.Length > 0 then
    begin
      ShowMessageFmt(rsIgnoredPackages,
        [dependencies.S['missing']]);
      GridDependsUpdated := True;
    end;
  end
  else
    GridDepends.Data := Nil;
end;

procedure TVisEditPackage.SetConflicts(AValue: string);
var
  aconflicts: ISuperObject;
  VConflicts:Variant;
begin
  FConflicts := AValue;
  if FConflicts<>'' then
  begin
    vConflicts := PyUTF8Decode(FConflicts);
    aconflicts := PyVarToSuperObject(DMPython.MainWaptRepo.get_package_entries(vconflicts));
    GridConflicts.Data := aconflicts['packages'];
    if aconflicts['missing'].AsArray.Length > 0 then
    begin
      ShowMessageFmt(rsIgnoredConfictingPackages,
        [aconflicts.S['missing']]);
      GridConflictsUpdated := True;
    end
  end
  else
    GridConflicts.Data := Nil;
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
