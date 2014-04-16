unit uwaptconsole;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, SynEdit, SynHighlighterPython,
  vte_json, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  StdCtrls, ComCtrls, ActnList, Menus, jsonparser, superobject,
  VirtualTrees, VarPyth, Windows, ImgList, Buttons, SOGrid, types, ActiveX;

type

  { TVisWaptGUI }

  TVisWaptGUI = class(TForm)
    ActCancelRunningTask: TAction;
    ActRemoveFromGroup: TAction;
    ActRDP: TAction;
    ActVNC: TAction;
    ActPackageInstall: TAction;
    ActPackageRemove: TAction;
    ActLocalhostInstall: TAction;
    ActEditpackage: TAction;
    ActExecCode: TAction;
    ActEvaluate: TAction;
    ActBuildUpload: TAction;
    ActCreateCertificate: TAction;
    ActCreateWaptSetup: TAction;
    ActEvaluateVar: TAction;
    ActEditHostPackage: TAction;
    ActAddRemoveOptionIniFile: TAction;
    ActHostSearchPackage: TAction;
    ActHostsAddPackages: TAction;
    ActHostsDelete: TAction;
    ActDeletePackage: TAction;
    ActAdvancedMode: TAction;
    ActChangePassword: TAction;
    ActGotoHost: TAction;
    ActHostWaptUpgrade: TAction;
    ActHostUpgrade: TAction;
    ActAddToGroup: TAction;
    ActEditGroup: TAction;
    ActDeleteGroup: TAction;
    ActDeployWapt: TAction;
    ActSearchGroups: TAction;
    ActWAPTLocalConfig: TAction;
    ActUpdateWaptGetINI: TAction;
    actRefresh: TAction;
    actQuit: TAction;
    ActPackageGroupAdd: TAction;
    ActPackageDuplicate: TAction;
    ActRegisterHost: TAction;
    ActSearchHost: TAction;
    ActLocalhostUpgrade: TAction;
    ActPackagesUpdate: TAction;
    ActLocalhostRemove: TAction;
    ActSearchPackage: TAction;
    ActionList1: TActionList;
    btAddGroup: TButton;
    butInitWapt: TButton;
    butRun: TButton;
    butSearchPackages: TButton;
    butSearchExternalPackages: TButton;
    butSearchGroups: TButton;
    Button1: TButton;
    Button2: TButton;
    Button3: TButton;
    Button4: TButton;
    Changer: TButton;
    Button7: TButton;
    Button8: TButton;
    cbSearchDMI: TCheckBox;
    cbSearchHost: TCheckBox;
    cbSearchPackages: TCheckBox;
    cbSearchSoftwares: TCheckBox;
    cbShowLog: TCheckBox;
    cbSearchAll: TCheckBox;
    cbShowHostPackagesSoft: TCheckBox;
    cbShowHostPackagesGroup: TCheckBox;
    CheckBoxMaj: TCheckBox;
    CheckBox_error: TCheckBox;
    EdRunningStatus: TEdit;
    EdSearchGroups: TEdit;
    GridGroups: TSOGrid;
    GridHostTasksPending: TSOGrid;
    GridHostTasksDone: TSOGrid;
    GridHostTasksErrors: TSOGrid;
    Label10: TLabel;
    Label11: TLabel;
    Label12: TLabel;
    HostRunningTask: TLabeledEdit;
    HostRunningTaskLog: TMemo;
    Label13: TLabel;
    LabelComputersNumber: TLabel;
    labSelected: TLabel;
    MemoGroupeDescription: TMemo;
    MenuItem19: TMenuItem;
    MenuItem20: TMenuItem;
    MenuItem28: TMenuItem;
    MenuItem33: TMenuItem;
    MenuItem34: TMenuItem;
    MenuItem35: TMenuItem;
    MenuItem36: TMenuItem;
    MenuItem37: TMenuItem;
    MenuItem38: TMenuItem;
    MenuItem39: TMenuItem;
    MenuItem40: TMenuItem;
    MenuItem41: TMenuItem;
    PageControl1: TPageControl;
    Panel11: TPanel;
    Panel2: TPanel;
    PopupHostPackages: TPopupMenu;
    PopupMenuGroups: TPopupMenu;
    ProgressBar: TProgressBar;
    EdHostname: TEdit;
    EdDescription: TEdit;
    EdOS: TEdit;
    EdIPAddress: TEdit;
    EdManufacturer: TEdit;
    EdModelName: TEdit;
    EdUpdateDate: TEdit;
    EdUser: TEdit;
    EdSearch1: TEdit;
    EdSearchHost: TEdit;
    EdRun: TEdit;
    EdSearch: TEdit;
    GridHosts: TSOGrid;
    GridhostInventory: TVirtualJSONInspector;
    GridExternalPackages: TSOGrid;
    ImageList1: TImageList;
    Label1: TLabel;
    pgGroups: TTabSheet;
    HostTaskRunningProgress: TProgressBar;
    Splitter3: TSplitter;
    pgTasks: TTabSheet;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    TabSheet3: TTabSheet;
    TimerTasks: TTimer;
    urlExternalRepo: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    Label6: TLabel;
    Label7: TLabel;
    Label8: TLabel;
    Label9: TLabel;
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
    MenuItem2: TMenuItem;
    MenuItem21: TMenuItem;
    MenuItem22: TMenuItem;
    MenuItem23: TMenuItem;
    MenuItem24: TMenuItem;
    MenuItem25: TMenuItem;
    MenuItem26: TMenuItem;
    MenuItem27: TMenuItem;
    MenuItem29: TMenuItem;
    MenuItem3: TMenuItem;
    MenuItem30: TMenuItem;
    MenuItem31: TMenuItem;
    MenuItem32: TMenuItem;
    MenuItem4: TMenuItem;
    MenuItem5: TMenuItem;
    MenuItem6: TMenuItem;
    MenuItem7: TMenuItem;
    MenuItem8: TMenuItem;
    MenuItem9: TMenuItem;
    MainPages: TPageControl;
    HostPages: TPageControl;
    Panel1: TPanel;
    Panel10: TPanel;
    Panel3: TPanel;
    Panel4: TPanel;
    Panel7: TPanel;
    Panel8: TPanel;
    Panel9: TPanel;
    PopupMenuHosts: TPopupMenu;
    PopupMenuPackages: TPopupMenu;
    PopupMenuEditDepends: TPopupMenu;
    PopupMenuPackagesTIS: TPopupMenu;
    Splitter1: TSplitter;
    Splitter2: TSplitter;
    Splitter4: TSplitter;
    SynPythonSyn1: TSynPythonSyn;
    pgSources: TTabSheet;
    pgPrivateRepo: TTabSheet;
    pgInventory: TTabSheet;
    pgPackages: TTabSheet;
    pgSoftwares: TTabSheet;
    pgHostPackage: TTabSheet;
    pgExternalRepo: TTabSheet;
    testedit: TSynEdit;
    jsonlog: TVirtualJSONInspector;
    GridPackages: TSOGrid;
    GridHostPackages: TSOGrid;
    GridHostSoftwares: TSOGrid;
    procedure ActAddRemoveOptionIniFileExecute(Sender: TObject);
    procedure ActAddToGroupExecute(Sender: TObject);
    procedure ActAdvancedModeExecute(Sender: TObject);
    procedure ActCancelRunningTaskExecute(Sender: TObject);
    procedure ActChangePasswordExecute(Sender: TObject);
    procedure ActCreateCertificateExecute(Sender: TObject);
    procedure ActCreateWaptSetupExecute(Sender: TObject);
    procedure ActDeleteGroupExecute(Sender: TObject);
    procedure ActDeletePackageExecute(Sender: TObject);
    procedure ActDeletePackageUpdate(Sender: TObject);
    procedure ActDeployWaptExecute(Sender: TObject);
    procedure ActEditGroupExecute(Sender: TObject);
    procedure ActEditHostPackageExecute(Sender: TObject);
    procedure ActGotoHostExecute(Sender: TObject);
    procedure ActPackageRemoveExecute(Sender: TObject);
    procedure ActRDPExecute(Sender: TObject);
    procedure ActRDPUpdate(Sender: TObject);
    procedure ActRemoveFromGroupExecute(Sender: TObject);
    procedure ActSearchGroupsExecute(Sender: TObject);
    procedure ActHostUpgradeExecute(Sender: TObject);
    procedure ActHostUpgradeUpdate(Sender: TObject);
    procedure ActHostWaptUpgradeExecute(Sender: TObject);
    procedure ActHostWaptUpgradeUpdate(Sender: TObject);
    procedure ActPackageEdit(Sender: TObject);
    procedure ActEditpackageUpdate(Sender: TObject);
    procedure ActEvaluateExecute(Sender: TObject);
    procedure ActExecCodeExecute(Sender: TObject);
    procedure ActHostsCopyExecute(Sender: TObject);
    procedure ActHostsDeleteExecute(Sender: TObject);
    procedure actHostSelectAllExecute(Sender: TObject);
    procedure ActLocalhostInstallExecute(Sender: TObject);
    procedure ActLocalhostInstallUpdate(Sender: TObject);
    procedure ActPackageDuplicateExecute(Sender: TObject);
    procedure ActPackageGroupAddExecute(Sender: TObject);
    procedure actQuitExecute(Sender: TObject);
    procedure actRefreshExecute(Sender: TObject);
    procedure ActRegisterHostExecute(Sender: TObject);
    procedure ActLocalhostRemoveExecute(Sender: TObject);
    procedure ActLocalhostRemoveUpdate(Sender: TObject);
    procedure ActSearchHostExecute(Sender: TObject);
    procedure ActSearchPackageExecute(Sender: TObject);
    procedure ActPackagesUpdateExecute(Sender: TObject);
    procedure ActUpdateWaptGetINIExecute(Sender: TObject);
    procedure ActLocalhostUpgradeExecute(Sender: TObject);
    procedure ActVNCExecute(Sender: TObject);
    procedure ActVNCUpdate(Sender: TObject);
    procedure ActWAPTLocalConfigExecute(Sender: TObject);
    procedure butSearchExternalPackagesClick(Sender: TObject);
    procedure cbSearchAllChange(Sender: TObject);
    procedure cbShowLogClick(Sender: TObject);
    procedure ChangerClick(Sender: TObject);
    procedure CheckBoxMajChange(Sender: TObject);
    procedure CheckBoxMajClick(Sender: TObject);
    procedure CheckBox_errorChange(Sender: TObject);
    procedure EdRunKeyPress(Sender: TObject; var Key: char);
    procedure EdSearch1KeyPress(Sender: TObject; var Key: char);
    procedure EdSearchHostKeyPress(Sender: TObject; var Key: char);
    procedure EdSearchKeyPress(Sender: TObject; var Key: char);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure GridGroupsColumnDblClick(Sender: TBaseVirtualTree;
      Column: TColumnIndex; Shift: TShiftState);
    procedure GridHostPackagesGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: boolean; var ImageIndex: integer;
      var ImageList: TCustomImageList);
    procedure GridHostsChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
    procedure GridHostsColumnDblClick(Sender: TBaseVirtualTree;
      Column: TColumnIndex; Shift: TShiftState);
    procedure GridHostsCompareNodes(Sender: TBaseVirtualTree; Node1,
      Node2: PVirtualNode; Column: TColumnIndex; var Result: Integer);
    procedure GridHostsDragDrop(Sender: TBaseVirtualTree; Source: TObject;
      DataObject: IDataObject; Formats: TFormatArray; Shift: TShiftState;
      const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
    procedure GridHostsDragOver(Sender: TBaseVirtualTree; Source: TObject;
      Shift: TShiftState; State: TDragState; const Pt: TPoint; Mode: TDropMode;
      var Effect: DWORD; var Accept: Boolean);
    procedure GridHostsEditing(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; var Allowed: Boolean);
    procedure GridHostsGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: boolean; var ImageIndex: integer;
      var ImageList: TCustomImageList);
    procedure GridHostsGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      RowData, CellData: ISuperObject; Column: TColumnIndex;
      TextType: TVSTTextType; var CellText: string);
    procedure GridPackagesChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
    procedure GridPackagesColumnDblClick(Sender: TBaseVirtualTree;
      Column: TColumnIndex; Shift: TShiftState);
    procedure GridPackagesPaintText(Sender: TBaseVirtualTree;
      const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
      TextType: TVSTTextType);

    procedure HostPagesChange(Sender: TObject);
    procedure MenuItem20Click(Sender: TObject);
    procedure MenuItem27Click(Sender: TObject);
    procedure MainPagesChange(Sender: TObject);
    procedure InstallPackage(Grid: TSOGrid);
    procedure TimerTasksTimer(Sender: TObject);
  private
    { private declarations }
    procedure GridLoadData(grid: TSOGrid; jsondata: string);
    function Login:Boolean;
    procedure PythonOutputSendData(Sender: TObject; const Data: ansistring);
    procedure TreeLoadData(tree: TVirtualJSONInspector; jsondata: string);
    procedure UpdateHostPages(Sender: TObject);
  public
    { public declarations }
    PackageEdited: ISuperObject;
    waptpath: string;
    function EditIniFile: boolean;
    function updateprogress(receiver: TObject; current, total: integer): boolean;
  end;

var
  VisWaptGUI: TVisWaptGUI;

implementation

uses LCLIntf, LCLType,IniFiles, uvisprivatekeyauth, uvisloading, tisstrings, soutils,
  waptcommon, tiscommon, uVisCreateKey, uVisCreateWaptSetup, uvisOptionIniFile,
  dmwaptpython, uviseditpackage, uvislogin, uviswaptconfig, uvischangepassword,
  uvisgroupchoice, uviseditgroup, uviswaptdeploy, uvishostsupgrade,
  PythonEngine,Clipbrd;

{$R *.lfm}

{ TVisWaptGUI }


procedure TVisWaptGUI.cbShowLogClick(Sender: TObject);
begin
  DMPython.PythonOutput.OnSendData := @PythonOutputSendData;
  if cbShowLog.Checked then
    DMPython.PythonEng.ExecString('logger.setLevel(logging.DEBUG)')
  else
    DMPython.PythonEng.ExecString('logger.setLevel(logging.WARNING)');

end;

procedure TVisWaptGUI.ChangerClick(Sender: TObject);
begin
  ActWAPTLocalConfigExecute(self);
  urlExternalRepo.Caption := 'Url: ' + WaptExternalRepo;
end;

procedure TVisWaptGUI.CheckBoxMajChange(Sender: TObject);
begin
  ActHostSearchPackage.Execute;
end;

procedure TVisWaptGUI.CheckBoxMajClick(Sender: TObject);
begin
  Gridhosts.Clear;
end;

procedure TVisWaptGUI.CheckBox_errorChange(Sender: TObject);
begin
  ActHostSearchPackage.Execute;
end;

procedure TVisWaptGUI.EdRunKeyPress(Sender: TObject; var Key: char);
begin
  if Key = #13 then
    ActEvaluate.Execute;
end;

procedure TVisWaptGUI.EdSearch1KeyPress(Sender: TObject; var Key: char);
begin
  if Key = #13 then
  begin
    EdSearch1.SelectAll;
    butSearchExternalPackages.Click;
  end;
end;

procedure TVisWaptGUI.EdSearchHostKeyPress(Sender: TObject; var Key: char);
begin
  if Key = #13 then
  begin
    EdSearchHost.SelectAll;
    ActSearchHost.Execute;
  end;
end;

procedure TVisWaptGUI.EdSearchKeyPress(Sender: TObject; var Key: char);
begin
  if Key = #13 then
  begin
    EdSearch.SelectAll;
    ActSearchPackage.Execute;
  end;

end;

procedure TVisWaptGUI.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin
  Gridhosts.SaveSettingsToIni(Appuserinipath) ;
  GridPackages.SaveSettingsToIni(Appuserinipath) ;
  GridGroups.SaveSettingsToIni(Appuserinipath) ;
  GridExternalPackages.SaveSettingsToIni(Appuserinipath) ;
  GridHostPackages.SaveSettingsToIni(Appuserinipath) ;
  GridHostSoftwares.SaveSettingsToIni(Appuserinipath) ;

end;

procedure TVisWaptGUI.UpdateHostPages(Sender: TObject);
var
  currhost,currip: Ansistring;
  RowSO,attribs, packages, softwares,tasks,tasksresult,running: ISuperObject;
begin
  TimerTasks.Enabled:=False;
  RowSO := Gridhosts.FocusedRow;
  if (RowSO <> nil) then
  begin
    currhost := RowSO.S['uuid'];
    currip := RowSO.S['host.connected_ips'];
    if HostPages.ActivePage = pgPackages then
    begin
      packages := RowSO['packages'];
      if (packages = nil) or (packages.AsArray = nil) then
      try
        packages := WAPTServerJsonGet('client_package_list/%s',
          [currhost],
          WaptUseLocalConnectionProxy,
          waptServerUser, waptServerPassword);
        RowSO['packages'] := packages;
      except
        RowSO['packages'] := Nil;
      end;
      EdHostname.Text := RowSO.S['host.computer_name'];
      EdDescription.Text := RowSO.S['host.description'];
      EdOS.Text := RowSO.S['host.windows_product_infos.version'];
      EdIPAddress.Text := RowSO.S['host.connected_ips'];
      EdManufacturer.Text := RowSO.S['host.system_manufacturer'];
      EdModelName.Text := RowSO.S['host.system_productname'];
      EdUpdateDate.Text := RowSO.S['last_query_date'];
      EdUser.Text := RowSO.S['host.current_user'];
      EdRunningStatus.Text:=RowSO.S['update_status.runstatus'];
      GridHostPackages.Data := packages;
    end
    else if HostPages.ActivePage = pgSoftwares then
    begin
      softwares := RowSO['softwares'];
      if (softwares = nil) or (softwares.AsArray = nil) then
      begin
        softwares := WAPTServerJsonGet('client_software_list/%s', [currhost],
            WaptUseLocalConnectionProxy,
            waptServerUser, waptServerPassword);
        RowSO['softwares'] := softwares;
      end;
      GridHostSoftwares.Data := softwares;
    end
    else if HostPages.ActivePage = pgHostPackage then
      TreeLoadData(GridhostInventory, RowSO.AsJSon())
    else if HostPages.ActivePage = pgTasks then
    begin
      try
        tasks := WAPTServerJsonGet('host_tasks?host=%s&uuid=%s', [currip,currhost],
              WaptUseLocalConnectionProxy,
              waptServerUser, waptServerPassword);
        if tasks.S['status']='OK' then
        begin
          HostRunningTaskLog.Text:= tasks.AsJSon(True);
          with HostRunningTaskLog do
          begin
            selstart := GetTextLen; // MUCH more efficient then Length(text)!
            SelLength:=0;
            Perform( EM_SCROLLCARET, 0, 0 );
          end;

          tasksresult := tasks['message'];
          if tasksresult['done'] =Nil then
            tasksresult := tasks['result'];
          if tasksresult<>Nil then
          begin
            running := tasksresult['running'];
            GridHostTasksPending.Data := tasksresult['pending'];
            GridHostTasksDone.Data := tasksresult['done'];
            GridHostTasksErrors.Data := tasksresult['errors'];
            if running<>Nil then
            begin
              HostTaskRunningProgress.Position :=running.I['progress'];
              HostRunningTask.Text:=running.S['description'];
              HostRunningTaskLog.Text := running.S['logs'];
            end
            else
            begin
              HostTaskRunningProgress.Position :=0;
              HostRunningTask.Text:='Idle';
              HostRunningTaskLog.Clear;
            end
          end;
        end
        else
        begin
          HostRunningTask.Text:='... Impossible de récupérer l''action';
          HostTaskRunningProgress.Position := 0;
          HostRunningTaskLog.Clear;
          GridHostTasksPending.Data := Nil;
        end;
      finally
        TimerTasks.Enabled:=True;
      end;
    end
  end
  else
  begin
    GridHostPackages.Clear;
    GridHostSoftwares.Clear;
    GridhostInventory.Clear;
  end;
end;

procedure TVisWaptGUI.ActLocalhostInstallExecute(Sender: TObject);
begin
  if GridPackages.Focused then
  begin
    InstallPackage(GridPackages);
    ActSearchPackage.Execute;
  end;
end;

procedure TVisWaptGUI.InstallPackage(Grid: TSOGrid);
var
  package: string;
  i: integer = 0;
  selects: integer;
  N: PVirtualNode;
  res : ISuperObject;
begin
  N := Grid.GetFirstSelected;
  selects := Grid.SelectedCount;

  with  TVisLoading.Create(Self) do
    try
      Self.Enabled := False;
      while (N <> nil) and not StopRequired do
      begin
        package := Grid.GetCellStrValue(N, 'package') + ' (=' +
          Grid.GetCellStrValue(N, 'version') + ')';
        ProgressTitle(
          'Installation de ' + Grid.GetCellStrValue(N, 'package') +
          ' en cours ...');
        ProgressStep(trunc((i / selects) * 100), 100);
        i := i + 1;
         //DMPython.RunJSON(format('mywapt.install("%s")', [package]), jsonlog);
        res := WAPTLocalJsonGet(format('install?package=%s',[package]));
        N := Grid.GetNextSelected(N);
      end;
    finally
      Self.Enabled := True;
      Free;
    end;

end;

procedure TVisWaptGUI.TimerTasksTimer(Sender: TObject);
begin
  if HostPages.ActivePage = pgTasks then
    UpdateHostPages(Self);
end;

procedure TVisWaptGUI.ActLocalhostInstallUpdate(Sender: TObject);
begin
  ActLocalhostInstall.Enabled := GridPackages.SelectedCount > 0;
end;

procedure TVisWaptGUI.ActPackageDuplicateExecute(Sender: TObject);
var
  target,sourceDir: string;
  package,uploadResult, FileName, FileNames, listPackages,Sources: ISuperObject;

begin
  if not FileExists(GetWaptPrivateKeyPath) then
  begin
    ShowMessage('la clé privée n''existe pas: ' + GetWaptPrivateKeyPath);
    exit;
  end;

  listPackages := TSuperObject.create(stArray);
  for package in GridExternalPackages.SelectedRows do
    listPackages.AsArray.Add(package.S['package']+'(='+package.S['version']+')');
  //calcule liste de tous les fichiers wapt nécessaires y compris les dépendances
  FileNames := DMPython.RunJSON(format('waptdevutils.get_packages_filenames(r"%s".decode(''utf8''),"%s")',
        [AppIniFilename,Join(',',listPackages)]));

  if MessageDlg('Confirmer la duplication', format('Etes vous sûr de vouloir dupliquer'#13#10'%s'#13#10' dans votre dépot ?', [Join(',', FileNames)]),
        mtConfirmation, mbYesNoCancel, 0) <> mrYes then
    Exit;

  if not DirectoryExists(AppLocalDir + 'cache') then
    mkdir(AppLocalDir + 'cache');


  with  TVisLoading.Create(Self) do
  try
    //Téléchargement en batchs
    for Filename in FileNames do
    begin
      Application.ProcessMessages;
      ProgressTitle(
        'Téléchargement en cours de ' + Filename.AsString);
      target := AppLocalDir + 'cache\' + Filename.AsString;
      try
        if not FileExists(target) then
          Wget(WaptExternalRepo + '/' + FileName.AsString,
            target, ProgressForm, @updateprogress, True);
      except
        ShowMessage('Téléchargement annulé');
        exit;
      end;
    end;

    Sources := TSuperObject.Create(stArray) ;
    for Filename in FileNames do
    begin
      ProgressTitle('Duplication de '+FileName.AsString);
      Application.ProcessMessages;
      sourceDir := DMPython.RunJSON(
        Format('waptdevutils.duplicate_from_external_repo(r"%s",r"%s")',
        [AppIniFilename,AppLocalDir + 'cache\' + Filename.AsString])).AsString;
      sources.AsArray.Add('r"'+sourceDir+'"');
    end;

    ProgressTitle('Upload en cours de '+IntToStr(Sources.AsArray.Length)+' paquets');
    Application.ProcessMessages;

    uploadResult := DMPython.RunJSON(
      format('mywapt.build_upload([%s],private_key_passwd=r"%s",wapt_server_user=r"%s",wapt_server_passwd=r"%s",inc_package_release=False)',
      [Join(',',sources) , privateKeyPassword, waptServerUser, waptServerPassword]),
      jsonlog);
    if (uploadResult <> Nil) and (uploadResult.AsArray.length=Sources.AsArray.Length) then
    begin
      ActPackagesUpdate.Execute;
      ShowMessage(format('%s dupliqué(s) avec succès.', [ Join(',', listPackages)])) ;
      MainPages.ActivePage := pgPrivateRepo;
      ModalResult := mrOk;
    end
    else
      ShowMessage('Erreur lors de la duplication.');
  finally
    Free;
  end;

end;

procedure TVisWaptGUI.ActPackageGroupAddExecute(Sender: TObject);
begin
  CreateGroup('agroup', ActAdvancedMode.Checked);
  ActPackagesUpdate.Execute;
end;

procedure TVisWaptGUI.actQuitExecute(Sender: TObject);
begin
  Close;
end;

procedure TVisWaptGUI.actRefreshExecute(Sender: TObject);
begin
  Screen.Cursor := crHourGlass;
  try
    if MainPages.ActivePage = pgInventory then
      ActSearchHost.Execute
    else
    if MainPages.ActivePage = pgPackages then
    begin
      ActPackagesUpdate.Execute;
      ActSearchPackage.Execute;
    end
    else
    if MainPages.ActivePage = pgGroups then
      ActSearchGroups.Execute;
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TVisWaptGUI.ActRegisterHostExecute(Sender: TObject);
begin
  DMPython.RunJSON('mywapt.register_computer()', jsonlog);
end;

procedure TVisWaptGUI.ActPackageEdit(Sender: TObject);
var
  Selpackage: string;
  res : ISUperObject;
begin
  if GridPackages.FocusedNode<>Nil then
  begin
    Selpackage := format('%s(=%s)',[GridPackages.GetCellStrValue(GridPackages.FocusedNode, 'package'),GridPackages.GetCellStrValue(GridPackages.FocusedNode, 'version')]);
    res := DMPython.RunJSON( format('mywapt.edit_package("%s")',[SelPackage]));
    DMPython.RunJSON( format('waptdevutils.wapt_sources_edit(r"%s")',[res.S['target']]));
    //if EditPackage(Selpackage, ActAdvancedMode.Checked) <> nil then
    //  ActPackagesUpdate.Execute;
  end;
end;

procedure TVisWaptGUI.ActEditpackageUpdate(Sender: TObject);
begin
  ActEditpackage.Enabled := GridPackages.SelectedCount > 0;
end;

procedure TVisWaptGUI.ActCreateCertificateExecute(Sender: TObject);
var
  params, certFile, privateKey: string;
  Result: ISuperObject;
  done: boolean;
  INI: TINIFile;
begin
  with TVisCreateKey.Create(Self) do
    try
      repeat
        if ShowModal = mrOk then
          try
            DMPython.PythonEng.ExecString('import common');
            params := '';
            params := params + format('orgname=r"%s",', [edOrgName.Text]);
            params := params + format('destdir=r"%s",', [DirectoryCert.Directory]);
            params := params + format('country=r"%s".decode(''utf8''),', [edCountry.Text]);
            params := params + format('locality=r"%s".decode(''utf8''),', [edLocality.Text]);
            params := params + format('organization=r"%s".decode(''utf8''),', [edOrganization.Text]);
            params := params + format('unit=r"%s".decode(''utf8''),', [edUnit.Text]);
            params := params + format('commonname=r"%s",', [edCommonName.Text]);
            params := params + format('email=r"%s",', [edEmail.Text]);
            params := params + format('wapt_base_dir=r"%s",', [waptpath]);
            Result := DMPython.RunJSON(
              format('common.create_self_signed_key(%s)',
              [params]), jsonlog);
            done := FileExists(Result.S['pem_filename']);
            if done then
            begin
              ShowMessageFmt('La clé %s a été créée avec succès',
                [Result.S['pem_filename']]);
              certFile := Result.S['pem_filename'];
              StrReplace(certFile, '.pem', '.crt');
              if not CopyFile(PChar(certFile),
                PChar(waptpath + '\ssl\' + ExtractFileName(certFile)), True) then
                ShowMessage('Erreur lors de la copie de la clé publique');

              with TINIFile.Create(AppIniFilename) do
                try
                  WriteString('global', 'private_key', Result.S['pem_filename']);
                finally
                  Free;
                end;

              ActUpdateWaptGetINIExecute(self);
            end;

          except
            on e: Exception do
            begin
              ShowMessage('Erreur à la création de la clé : ' + e.Message);
              done := False;
            end;
          end
        else
          done := True;
      until done;
    finally
      Free;
    end;
end;

procedure TVisWaptGUI.ActAddRemoveOptionIniFileExecute(Sender: TObject);
begin
  with TVisOptionIniFile.Create(self) do
    try
      if ShowModal = mrOk then
        try

        except
        end;

    finally
    end;
end;

procedure TVisWaptGUI.ActAddToGroupExecute(Sender: TObject);
var
  Res, packages, host, hosts: ISuperObject;
  N:PVirtualNode;
  PackagesList, args: AnsiString;
begin
  if GridHosts.Focused then
  begin
    with TvisGroupChoice.Create(self) do
    try
      Caption:='Choix des groupes à ajouter aux postes sélectionnés';
      ActSearchGroupsExecute(self);
      if groupGrid.Data.AsArray.Length = 0 then
      begin
        ShowMessage('Il n''y a aucuns groupes.');
        Exit;
      end;
      if ShowModal = mrOk then
      begin
        packages := TSuperObject.Create(stArray);
        N := groupGrid.GetFirstChecked();
        while N <> nil do
        begin
          packages.AsArray.Add(groupGrid.GetCellStrValue(N, 'package'));
          N := groupGrid.GetNextChecked(N);
        end;
      end;
    finally
      Free;
    end;
    if (packages = nil) or (packages.AsArray.Length = 0) then
      Exit;

    Hosts := TSuperObject.Create(stArray);
    for host in GridHosts.SelectedRows do
      hosts.AsArray.Add(host.S['host.computer_fqdn']);

    //edit_hosts_depends(waptconfigfile,hosts_list,appends,removes,key_password=None,wapt_server_user=None,wapt_server_passwd=None)
    args := '';
    args := args + format('waptconfigfile = r"%s".decode(''utf8''),',[AppIniFilename]);
    args := args + format('hosts_list = r"%s".decode(''utf8''),',[Join(',',hosts)]);
    args := args + format('appends = r"%s".decode(''utf8''),',[Join(',',packages)]);
    args := args + format('removes = [],',[]);
    if privateKeyPassword<>'' then
      args := args + format('key_password = "%s".decode(''utf8''),',[privateKeyPassword]);
    args := args + format('wapt_server_user = r"%s".decode(''utf8''),',[waptServerUser]);
    args := args + format('wapt_server_passwd = r"%s".decode(''utf8''),',[waptServerPassword]);
    res := DMPython.RunJSON(format('waptdevutils.edit_hosts_depends(%s)',[args]));
    ShowMessage(IntToStr(res.AsArray.Length)+' postes modifiés');
  end;
end;

procedure TVisWaptGUI.ActAdvancedModeExecute(Sender: TObject);
begin
  ActAdvancedMode.Checked := not ActAdvancedMode.Checked;
  pgSources.TabVisible := ActAdvancedMode.Checked;
  Panel3.Visible := ActAdvancedMode.Checked;
end;

procedure TVisWaptGUI.ActCancelRunningTaskExecute(Sender: TObject);
var
  res : ISuperObject;
  currip,currhost:AnsiString;
begin
  currhost := GridHosts.FocusedRow.S['uuid'];
  currip := GridHosts.FocusedRow.S['host.connected_ips'];

  res := WAPTServerJsonGet('host_taskkill?host=%s&uuid=%s', [currip,currhost],
        WaptUseLocalConnectionProxy,
        waptServerUser, waptServerPassword);
  if res.S['status']='OK' then
    ShowMessage('Tâche annulée')
  else
    ShowMessage('Impossible d''annuler: '+res.S['message']);
end;

procedure TVisWaptGUI.ActChangePasswordExecute(Sender: TObject);
var
  newPass, Result: string;
begin
  with TvisChangePassword.Create(self) do
    try
      if ShowModal = mrOk then
      begin
        newPass := edNewPassword2.Text;
        Result := DMPython.RunJSON(
          format('waptdevutils.login_to_waptserver("%s","%s","%s","%s")',
          [GetWaptServerURL + '/login', waptServerUser, waptServerPassword,
          newPass])).AsString;

        if Result = 'True' then
        begin
          waptServerPassword := newPass;
          ShowMessage('Le mot de passe a été changé avec succès !');
        end;
      end;
    finally
      Free;
    end;
end;

procedure TVisWaptGUI.ActCreateWaptSetupExecute(Sender: TObject);
var
  params, waptsetupPath: string;
  done: boolean;
  ini: TIniFile;
  SORes:ISuperObject;
begin
  with TVisCreateWaptSetup.Create(self) do
    try
      ini := TIniFile.Create(AppIniFilename);
      try
        repeat
          edWaptServerUrl.Text := ini.ReadString('global', 'wapt_server', '');
          edRepoUrl.Text := ini.ReadString('global', 'repo_url', '');
          if DirectoryExists(IncludeTrailingPathDelimiter(waptpath) +
            'waptserver\repository\wapt') then
            fnWaptDirectory.Directory :=
              IncludeTrailingPathDelimiter(waptpath) + 'waptserver\repository\wapt';
          if ShowModal = mrOk then
          begin
            try
              Screen.Cursor := crHourGlass;
              DMPython.PythonEng.ExecString('import waptdevutils');
              params := '';
              params := params + format('default_public_cert=r"%s",',
                [fnPublicCert.FileName]);
              params := params + format('default_repo_url=r"%s",', [edRepoUrl.Text]);
              params := params + format('default_wapt_server=r"%s",',
                [edWaptServerUrl.Text]);
              params := params + format('destination=r"%s",',
                [ExcludeTrailingBackslash(fnWaptDirectory.Directory)]);
              params := params + format('company=r"%s",', [edOrgName.Text]);
              with  TVisLoading.Create(Self) do
                try
                  ProgressTitle('Création en cours');
                  Application.ProcessMessages;
                  waptsetupPath :=
                    DMPython.RunJSON(
                    format('waptdevutils.create_wapt_setup(mywapt,%s)', [params]),
                    jsonlog).AsString;
                  if FileExists(waptsetupPath) then
                  begin
                    ProgressStep(1, 2);
                    ProgressTitle('Dépôt sur le serveur WAPT en cours');
                    SORes :=
                      DMPython.RunJSON(format(
                      'waptdevutils.upload_wapt_setup(mywapt,r"%s","%s","%s")',
                      [waptsetupPath, waptServerUser, waptServerPassword]));
                    if SORes.S['status'] = 'OK' then
                    begin
                      ShowMessage('Waptsetup envoyé avec succès');
                      done := True;
                    end
                    else
                      ShowMessage('Erreur lors de l''envoi de waptsetup: ' + SORes.S['message']);
                  end;
                finally
                  Free;
                end;
              if done then
              begin
                Screen.Cursor := crDefault;
                ShowMessage('waptsetup.exe créé avec succès: ' + waptsetupPath);
              end;
            except
              on e: Exception do
              begin
                ShowMessage('Erreur à la création du waptsetup.exe: ' + e.Message);
                done := False;
              end;
            end;
          end
          else
            done := True;
        until done;
        Screen.Cursor := crDefault;
      finally
        ini.Free;
      end;
    finally
      Free;
    end;
end;

procedure TVisWaptGUI.ActDeleteGroupExecute(Sender: TObject);
var
  message: string = 'Etes vous sûr de vouloir supprimer ce groupe du serveur ?';
  res: ISuperObject;
  group: string;
  i: integer;
  N: PVirtualNode;
begin
  if GridGroups.SelectedCount > 1 then
    message := 'Etes vous sûr de vouloir supprimer ces groupes du serveur ?';

  if MessageDlg('Confirmer la suppression', message, mtConfirmation,
    mbYesNoCancel, 0) = mrYes then

    with TVisLoading.Create(Self) do
      try
        ProgressTitle('Suppression des packages...');
        N := GridGroups.GetFirstSelected;
        i := 0;
        while (N <> nil) and not StopRequired do
        begin
          Inc(i);
          group := GridPackages.GetCellStrValue(N, 'filename');
          ProgressTitle('Suppression de ' + group);
          res := WAPTServerJsonGet('/delete_package/' + group, [],
              WaptUseLocalConnectionProxy,
              waptServerUser, waptServerPassword);
          if not ObjectIsNull(res['error']) then
            raise Exception.Create(res.S['error']);
          N := GridGroups.GetNextSelected(N);
          ProgressStep(i, GridGroups.SelectedCount);
        end;
        ProgressTitle('Mise à jour de la liste des groupes');
        ActPackagesUpdate.Execute;
        ProgressTitle('Affichage');
        ActSearchGroups.Execute;
      finally
        Free;
      end;
end;

procedure TVisWaptGUI.ActDeletePackageExecute(Sender: TObject);
var
  message: string = 'Etes vous sûr de vouloir supprimer ce package du serveur ?';
  res: ISuperObject;
  package: string;
  i: integer;
  N: PVirtualNode;
begin
  if GridPackages.SelectedCount > 1 then
    message := 'Etes vous sûr de vouloir supprimer ces packages du serveur ?';

  if MessageDlg('Confirmer la suppression', message, mtConfirmation,
    mbYesNoCancel, 0) = mrYes then

    with TVisLoading.Create(Self) do
      try
        ProgressTitle('Suppression des packages...');
        N := GridPackages.GetFirstSelected;
        i := 0;
        while (N <> nil) and not StopRequired do
        begin
          Inc(i);
          package := GridPackages.GetCellStrValue(N, 'filename');
          ProgressTitle('Suppression de ' + package);
          res := WAPTServerJsonGet('/delete_package/' + package, [],
              WaptUseLocalConnectionProxy,
              waptServerUser, waptServerPassword);
          if not ObjectIsNull(res['error']) then
            raise Exception.Create(res.S['error']);
          N := GridPackages.GetNextSelected(N);
          ProgressStep(i, GridPackages.SelectedCount);
        end;
        ProgressTitle('Mise à jour de la liste des paquets');
        ActPackagesUpdate.Execute;
        ProgressTitle('Affichage');
        ActSearchPackage.Execute;
      finally
        Free;
      end;
end;

procedure TVisWaptGUI.ActDeletePackageUpdate(Sender: TObject);
begin
  ActDeletePackage.Enabled := GridPackages.SelectedCount > 0;
end;

procedure TVisWaptGUI.ActDeployWaptExecute(Sender: TObject);
begin
    with Tviswaptdeploy.Create(self) do
    try
      if ShowModal = mrOk then
        actRefresh.Execute;
    finally
        Free;
    end;
end;

procedure TVisWaptGUI.ActEditGroupExecute(Sender: TObject);
var
  expr, res, depends, dep: string;
  Selpackage: string;
  Result: ISuperObject;
  N: PVirtualNode;
begin
  if GridGroups.Focused then
  begin
    N := GridGroups.GetFirstSelected;
    Selpackage := GridGroups.GetCellStrValue(N, 'package');
    if EditGroup(Selpackage, ActAdvancedMode.Checked) <> nil then
      ActPackagesUpdate.Execute;
  end;
end;

procedure TVisWaptGUI.ActEditHostPackageExecute(Sender: TObject);
var
  hostname,ip: Ansistring;
  Result: ISuperObject;
begin
  hostname := GridHosts.GetCellStrValue(GridHosts.FocusedNode, 'host.computer_fqdn');
  ip := GridHosts.GetCellStrValue(GridHosts.FocusedNode, 'host.connected_ips');
  if EditHost(hostname, ActAdvancedMode.Checked,ip) <> nil then
    ActSearchHost.Execute;
end;

procedure TVisWaptGUI.ActGotoHostExecute(Sender: TObject);
begin
  EdSearchHost.SetFocus;
  EdSearchHost.SelectAll;
end;

procedure TVisWaptGUI.ActPackageRemoveExecute(Sender: TObject);
var
  sel,package,res:ISuperObject;
begin
  if GridHostPackages.Focused then
  begin
    sel := GridHostPackages.SelectedRows;
    if Dialogs.MessageDlg('Confirmer','Confirmez-vous la désinstallation de '+intToStr(sel.AsArray.Length)+' packages du poste '+GridHosts.FocusedRow.S['host.computer_fqdn']+' ?',mtConfirmation,mbYesNoCancel,0) = mrYes then
    begin
      for package in sel do
      begin
        res :=  WAPTServerJsonGet(
          '/remove_package.json?host=%s&package=%s&uuid=%s',[GridHosts.FocusedRow.S['host.connected_ips'],package.S['package'],GridHosts.FocusedRow.S['uuid']],
          WaptUseLocalConnectionProxy,
          waptServerUser,
          waptServerPassword);
        if res.S['status']<>'OK' then
          ShowMessage(Format('Erreur pour le package %s',[package.S['package'],res.S['message']]));
      end;
    end;
    UpdateHostPages(Sender);
  end;

end;

procedure TVisWaptGUI.ActRDPExecute(Sender: TObject);
var
  ip:AnsiString;
begin
  if (Gridhosts.FocusedRow<>Nil) and (Gridhosts.FocusedRow.S['host.connected_ips']<>'') then
  begin
    ip := Gridhosts.FocusedRow.S['host.connected_ips'];
    ShellExecute(0,'',PAnsiChar('mstsc'),PAnsichar('/v:'+ip),Nil,SW_SHOW);
  end;
end;

procedure TVisWaptGUI.ActRDPUpdate(Sender: TObject);
begin
  try
    ActRDP.Enabled := (Gridhosts.FocusedRow<>Nil) and (Gridhosts.FocusedRow.S['host.connected_ips']<>'');
  except
    ActRDP.Enabled := False;
  end;

end;

procedure TVisWaptGUI.ActRemoveFromGroupExecute(Sender: TObject);
var
  Res, packages, host, hosts: ISuperObject;
  N:PVirtualNode;
  PackagesList, args: AnsiString;
begin
  if GridHosts.Focused then
  begin
    with TvisGroupChoice.Create(self) do
    try
      Caption:='Choix des groupes à enlever des postes sélectionnés';
      ActSearchGroupsExecute(self);
      if groupGrid.Data.AsArray.Length = 0 then
      begin
        ShowMessage('Il n''y a aucuns groupes.');
        Exit;
      end;
      if ShowModal = mrOk then
      begin
        packages := TSuperObject.Create(stArray);
        N := groupGrid.GetFirstChecked();
        while N <> nil do
        begin
          packages.AsArray.Add(groupGrid.GetCellStrValue(N, 'package'));
          N := groupGrid.GetNextChecked(N);
        end;
      end;
    finally
      Free;
    end;
    if (packages = nil) or (packages.AsArray.Length = 0) then
      Exit;

    Hosts := TSuperObject.Create(stArray);
    for host in GridHosts.SelectedRows do
      hosts.AsArray.Add(host.S['host.computer_fqdn']);

    //edit_hosts_depends(waptconfigfile,hosts_list,appends,removes,key_password=None,wapt_server_user=None,wapt_server_passwd=None)
    args := '';
    args := args + format('waptconfigfile = r"%s".decode(''utf8''),',[AppIniFilename]);
    args := args + format('hosts_list = r"%s".decode(''utf8''),',[Join(',',hosts)]);
    args := args + format('appends = [],',[]);
    args := args + format('removes = r"%s".decode(''utf8''),',[Join(',',packages)]);
    if privateKeyPassword<>'' then
      args := args + format('key_password = "%s".decode(''utf8''),',[privateKeyPassword]);
    args := args + format('wapt_server_user = r"%s".decode(''utf8''),',[waptServerUser]);
    args := args + format('wapt_server_passwd = r"%s".decode(''utf8''),',[waptServerPassword]);
    res := DMPython.RunJSON(format('waptdevutils.edit_hosts_depends(%s)',[args]));
    ShowMessage(IntToStr(res.AsArray.Length)+' postes modifiés');

  end;
end;

procedure TVisWaptGUI.ActSearchGroupsExecute(Sender: TObject);
var
  expr: UTF8String;
  groups: ISuperObject;
begin
  expr := format('mywapt.search(r"%s".decode(''utf8'').split(),section_filter="group")',
    [EdSearchGroups.Text]);
  groups := DMPython.RunJSON(expr);
  GridGroups.Data := groups;
end;

procedure TVisWaptGUI.ActHostUpgradeExecute(Sender: TObject);
begin
  with TVisHostsUpgrade.Create(Self) do
  try
    action := 'upgrade_host';
    hosts:=Gridhosts.SelectedRows;

    if ShowModal=mrOK then
      actRefresh.Execute;
  finally
    Free;
  end;
end;

procedure TVisWaptGUI.ActHostUpgradeUpdate(Sender: TObject);
begin
  ActHostUpgrade.Enabled := GridHosts.SelectedCount > 0;
end;

procedure TVisWaptGUI.ActHostWaptUpgradeExecute(Sender: TObject);
begin
  with TVisHostsUpgrade.Create(Self) do
  try
    action := 'waptupgrade_host';
    caption := 'Mise à jour du client WAPT sur les postes';
    hosts:=Gridhosts.SelectedRows;
    if ShowModal=mrOK then
      actRefresh.Execute;
  finally
    Free;
  end;
end;

procedure TVisWaptGUI.ActHostWaptUpgradeUpdate(Sender: TObject);
begin
  ActHostWaptUpgrade.Enabled := GridHosts.SelectedCount > 0;
end;

procedure TVisWaptGUI.ActEvaluateExecute(Sender: TObject);
var
  o, sob: ISuperObject;
begin
  MemoLog.Clear;
  if cbShowLog.Checked then
  begin
    MemoLog.Lines.Add('');
    MemoLog.Lines.Add('########## Start of Output of """' + EdRun.Text +
      '""" : ########');
  end;

  sob := DMPython.RunJSON(EdRun.Text, jsonlog);
end;

procedure TVisWaptGUI.ActExecCodeExecute(Sender: TObject);
begin
  MemoLog.Clear;
  DMPython.PythonEng.ExecString(testedit.Lines.Text);
end;

procedure TVisWaptGUI.ActHostsCopyExecute(Sender: TObject);
var
  fmt :  TClipboardFormat;
begin
  //GridHosts.CopyToClipBoard;
  Clipboard.AsText:=GridHosts.ContentToUTF8(tstSelected,';');
end;

procedure TVisWaptGUI.ActHostsDeleteExecute(Sender: TObject);
var
  sel,host : ISuperObject;
begin
  if GridHosts.Focused then
  begin
    sel := GridHosts.SelectedRows;
    if Dialogs.MessageDlg('Confirmer','Confirmez-vous la suppression de '+intToStr(sel.AsArray.Length)+' postes de la liste ?',mtConfirmation,mbYesNoCancel,0) = mrYes then
    begin
      for host in sel do
        WAPTServerJsonGet('/delete_host/' + host.S['uuid'], [],
          WaptUseLocalConnectionProxy,
          waptServerUser, waptServerPassword);
      ActSearchHost.Execute;
    end;
  end;
end;

procedure TVisWaptGUI.actHostSelectAllExecute(Sender: TObject);
begin
  TSOGrid(GridHosts).SelectAll(False);
end;

procedure TVisWaptGUI.ActLocalhostRemoveExecute(Sender: TObject);
var
  package: Ansistring;
  i: integer = 0;
  selects: integer;
  N: PVirtualNode;
begin
  if GridPackages.Focused then
  begin
    N := GridPackages.GetFirstSelected;
    selects := GridPackages.SelectedCount;
    with  TVisLoading.Create(Self) do
      try
        while (N <> nil) and not StopRequired do
        begin
          package := GridPackages.GetCellStrValue(N, 'package');
          ProgressTitle('Désinstallation de ' + package + ' en cours ...');
          ProgressStep(trunc((i / selects) * 100), 100);
          Application.ProcessMessages;
          i := i + 1;
          DMPython.RunJSON(format('mywapt.remove("%s")', [package]), jsonlog);
          N := GridPackages.GetNextSelected(N);
        end;
      finally
        Free;
      end;
    ActSearchPackage.Execute;
  end;
end;

procedure TVisWaptGUI.ActLocalhostRemoveUpdate(Sender: TObject);
begin
  ActLocalhostRemove.Enabled := GridPackages.SelectedCount > 0;
end;

procedure TVisWaptGUI.ActSearchHostExecute(Sender: TObject);
var
  req, filter: string;
  urlParams,Node,Hosts: ISuperObject;
  previous_uuid: String;
const
  url: string = 'json/host_list';
begin

  urlParams := TSuperObject.Create(stArray);

  if CheckBox_error.Checked = True then
    urlParams.AsArray.Add('package_error=true');

  if CheckBoxMaj.Checked = True then
    urlParams.AsArray.Add('need_upgrade=true');

  if EdSearchHost.Text <> '' then
    urlParams.AsArray.Add('q=' + EdSearchHost.Text);

  if cbSearchAll.Checked = False then
  begin
    if cbSearchHost.Checked = True then
      filter := filter + 'host,';

    if cbSearchDMI.Checked = True then
      filter := filter + 'dmi,';

    if cbSearchSoftwares.Checked = True then
      filter := filter + 'softwares,';

    if cbSearchPackages.Checked = True then
      filter := filter + 'packages,';

    urlParams.AsArray.Add('filter=' + filter);
  end;

  req := url + '?' + Join('&', urlParams);
  if GridHosts.FocusedRow<>Nil then
    previous_uuid := GridHosts.FocusedRow.S['uuid']
  else
    previous_uuid:='';
  hosts := WAPTServerJsonGet(req, [],
      WaptUseLocalConnectionProxy,
      waptServerUser, waptServerPassword);
  GridHosts.Data := hosts;
  LabelComputersNumber.Caption := IntToStr(hosts.AsArray.Length);
  for node in GridHosts.data do
  begin
    if node.S['uuid'] = previous_uuid then
    begin
      GridHosts.FocusedRow := node;
      Break;
    end;
  end;
end;

procedure TVisWaptGUI.ActSearchPackageExecute(Sender: TObject);
var
  expr: UTF8String;
  packages: ISuperObject;
begin
  //packages := VarPythonEval(Format('"%s".split()',[EdSearch.Text]));
  //packages := MainModule.mywapt.search(VarPythonEval(Format('"%s".split()',[EdSearch.Text])));
  expr := format('mywapt.search(r"%s".decode(''utf8'').split(),section_filter="base")', [EdSearch.Text]);
  packages := DMPython.RunJSON(expr);

  GridPackages.Data := packages;
end;

procedure TVisWaptGUI.ActPackagesUpdateExecute(Sender: TObject);
var
  res:Variant;
begin
  //test avec un variant ;)
  res := MainModule.mywapt.update(Register := False);

  ActSearchPackage.Execute;
  ActSearchGroups.Execute;
end;

procedure TVisWaptGUI.ActUpdateWaptGetINIExecute(Sender: TObject);
begin
  DMPython.RunJSON('mywapt.load_config()', jsonlog);
  urlExternalRepo.Caption := 'Url: ' + WaptExternalRepo;
end;

procedure TVisWaptGUI.ActLocalhostUpgradeExecute(Sender: TObject);
begin
  DMPython.RunJSON('mywapt.upgrade()', jsonlog);
end;

procedure TVisWaptGUI.ActVNCExecute(Sender: TObject);
var
  ip:AnsiString;
begin
  if (Gridhosts.FocusedRow<>Nil) and (Gridhosts.FocusedRow.S['host.connected_ips']<>'') then
  begin
    ip := Gridhosts.FocusedRow.S['host.connected_ips'];
    ShellExecute(0,'',PAnsiChar('C:\Program Files\TightVNC\tvnviewer.exe'),PAnsichar(ip),Nil,SW_SHOW);
  end;
end;

procedure TVisWaptGUI.ActVNCUpdate(Sender: TObject);
begin
  try
    ActVNC.Enabled := (Gridhosts.FocusedRow<>Nil) and (Gridhosts.FocusedRow.S['host.connected_ips']<>'')
        and FileExists('C:\Program Files\TightVNC\tvnviewer.exe') ;
  except
    ActVNC.Enabled := False;
  end;
end;

procedure TVisWaptGUI.ActWAPTLocalConfigExecute(Sender: TObject);
begin
  if EditIniFile then
  begin
    ActUpdateWaptGetINI.Execute;
    ActPackagesUpdate.Execute;
    GridPackages.Clear;
    GridGroups.Clear;
    GridExternalPackages.Clear;
    MainPagesChange(MainPages);

  end;
end;

function TVisWaptGUI.EditIniFile: boolean;
var
  inifile: TIniFile;
begin
  Result := False;
  inifile := TIniFile.Create(AppIniFilename);
  try

    with TVisWAPTConfig.Create(self) do
      try
        //wapt := VarPyth.VarPythonEval('mywapt') ;
        //conf := wapt.config;

        edrepo_url.Text := inifile.ReadString('global', 'repo_url', '');
        edhttp_proxy.Text := inifile.ReadString('global', 'http_proxy', '');
        //edrepo_url.text := VarPythonAsString(conf.get('global','repo_url'));
        eddefault_package_prefix.Text :=
          inifile.ReadString('global', 'default_package_prefix', '');
        edwapt_server.Text := inifile.ReadString('global', 'wapt_server', '');
        eddefault_sources_root.Text :=
          inifile.ReadString('global', 'default_sources_root', '');
        edprivate_key.Text := inifile.ReadString('global', 'private_key', '');
        edtemplates_repo_url.Text :=
          inifile.readString('global', 'templates_repo_url', '');
        cbProxyLocalConnection.Checked:= ( inifile.readString('global', 'use_local_connection_proxy', '') = 'True' );
        //eddefault_sources_root.Directory := inifile.ReadString('global','default_sources_root','');
        //eddefault_sources_url.text = inifile.ReadString('global','default_sources_url','https://srvdev/sources/%(packagename)s-wapt/trunk');

        if ShowModal = mrOk then
        begin
          inifile.WriteString('global', 'repo_url', edrepo_url.Text);
          inifile.WriteString('global', 'http_proxy', edhttp_proxy.Text);
          inifile.WriteString('global', 'default_package_prefix',
            eddefault_package_prefix.Text);
          inifile.WriteString('global', 'wapt_server', edwapt_server.Text);
          inifile.WriteString('global', 'default_sources_root',
            eddefault_sources_root.Text);
          inifile.WriteString('global', 'private_key', edprivate_key.Text);
          inifile.WriteString('global', 'templates_repo_url', edtemplates_repo_url.Text);
          inifile.WriteString('global', 'default_sources_root',
            eddefault_sources_root.Text);
          inifile.WriteString('global', 'use_local_connection_proxy',
                      BoolToStr(cbProxyLocalConnection.Checked, True));
          //inifile.WriteString('global','default_sources_url',eddefault_sources_url.text);
          Result := True;
        end;
      finally
        Free;
      end;

  finally
    inifile.Free;
  end;
end;

procedure TVisWaptGUI.butSearchExternalPackagesClick(Sender: TObject);
var
  expr: UTF8String;
  packages: ISuperObject;
begin
  expr := format('waptdevutils.update_tis_repo(r"%s","%s")',
    [AppIniFilename, EdSearch1.Text]);
  packages := DMPython.RunJSON(expr);
  GridExternalPackages.Data := packages;
end;

procedure TVisWaptGUI.cbSearchAllChange(Sender: TObject);
begin
  cbSearchDMI.Checked := cbSearchAll.Checked;
  cbSearchDMI.Enabled := not cbSearchAll.Checked;

  cbSearchSoftwares.Checked := cbSearchAll.Checked;
  cbSearchSoftwares.Enabled := not cbSearchAll.Checked;

  cbSearchPackages.Checked := cbSearchAll.Checked;
  cbSearchPackages.Enabled := not cbSearchAll.Checked;

  cbSearchHost.Checked := cbSearchAll.Checked;
  cbSearchHost.Enabled := not cbSearchAll.Checked;
end;

function checkReadWriteAccess(dir: string): boolean;
var
  fn: string;
begin
  try
    fn := FileUtil.GetTempFilename(dir, 'test');
    StringToFile(fn, '');
    FileUtil.DeleteFileUTF8(fn);
    Result := True;
  except
    Result := False;
  end;
end;

procedure TVisWaptGUI.FormCreate(Sender: TObject);
begin
  waptpath := ExtractFileDir(ParamStr(0));
end;

function TVisWaptGUI.Login:Boolean;
var
  resp: ISuperObject;
  localfn: string;

begin
  Result := False;
  // Initialize user local config file with global wapt settings
  localfn := GetAppConfigDir(False) + GetApplicationName + '.ini';
  if not FileExists(localfn) then
  begin
    if not DirectoryExists(GetAppConfigDir(False)) then
      MkDir(GetAppConfigDir(False));
    FileUtil.CopyFile(WaptIniFilename, localfn, True);
  end;

  while (GetWaptServerURL = '') do
  begin
    if EditIniFile then
      ActUpdateWaptGetINI.Execute
    else
      Halt;
  end;

  while not Result do
  begin
    with TVisLogin.Create(Self) do
    try
      edWaptServerName.Text := GetWaptServerURL;
      if ShowModal = mrOk then
      begin
        waptServerPassword := edPassword.Text;
        waptServerUser := edUser.Text;
        try
          resp := DMPython.RunJSON(
            format('waptdevutils.login_to_waptserver("%s","%s","%s")',
            [GetWaptServerURL + '/login', waptServerUser, waptServerPassword]));
        except
          on E: Exception do
          begin
            ShowMessage('Erreur: ' + UTF8Encode(E.Message));
            Result := False;
          end;
        end;
        try
          Result := StrToBool(resp.AsString);
          if not Result then
            ShowMessage('Mauvais mot de passe');
        except
          ShowMessage(UTF8Encode(resp.AsString));
          Result := False;
        end;
      end
      else
      begin
        Result := False;
        Exit;
      end;
    finally
      if not Result then
      begin
        waptServerUser := '';
        waptServerPassword := '';
      end;
      Free;
    end;
  end;
end;

procedure TVisWaptGUI.FormShow(Sender: TObject);
begin
  MemoLog.Clear;
  DMPython.WaptConfigFileName := AppIniFilename;
  DMPython.PythonOutput.OnSendData := @PythonOutputSendData;
  //ActUpdateWaptGetINIExecute(Self);
  if not Login then
    Halt;

  MainPages.ActivePage := pgInventory;
  MainPagesChange(Sender);

  Gridhosts.LoadSettingsFromIni(Appuserinipath);
  GridPackages.LoadSettingsFromIni(Appuserinipath) ;
  GridGroups.LoadSettingsFromIni(Appuserinipath) ;
  GridExternalPackages.LoadSettingsFromIni(Appuserinipath) ;
  GridHostPackages.LoadSettingsFromIni(Appuserinipath) ;
  GridHostSoftwares.LoadSettingsFromIni(Appuserinipath) ;

end;

procedure TVisWaptGUI.GridGroupsColumnDblClick(Sender: TBaseVirtualTree;
  Column: TColumnIndex; Shift: TShiftState);
begin
  {if GridGroups.Focused and (Shift=[ssLeft]) then
  begin
    N := GridGroups.GetFirstSelected;
    selgroup := GridGroups.GetCellStrValue(N, 'package');
    if selgroup<>'' then
      with TVisEditGroup.Create(self) do
      try
        group := selgroup;
        if ShowModal = mrOk then
          ActSearchGroups.Execute;
      finally
        Free;
      end;
  end;}
  ActEditGroup.Execute;
end;

procedure TVisWaptGUI.GridHostPackagesGetImageIndexEx(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
  var Ghosted: boolean; var ImageIndex: integer; var ImageList: TCustomImageList);
var
  install_status: ISuperObject;
begin
  if Column = 0 then
  begin
    install_status := GridHostPackages.GetCellData(Node,'install_status',Nil);
    if (install_status <> nil) then
    begin
      case install_status.AsString of
        'OK': ImageIndex := 0;
        'ERROR': ImageIndex := 2;
        'NEED-UPGRADE': ImageIndex := 1;
      end;
    end;
  end;
end;

procedure TVisWaptGUI.GridHostsChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  UpdateHostPages(Sender);
  labSelected.Caption:= IntToStr(GridHosts.SelectedCount);
end;

procedure TVisWaptGUI.GridHostsColumnDblClick(Sender: TBaseVirtualTree;
  Column: TColumnIndex; Shift: TShiftState);
begin
  ActEditHostPackage.Execute;
end;

procedure TVisWaptGUI.GridHostsCompareNodes(Sender: TBaseVirtualTree; Node1,
  Node2: PVirtualNode; Column: TColumnIndex; var Result: Integer);
var
  n1, n2, d1, d2: ISuperObject;
  propname: string;
  compresult : TSuperCompareResult;
begin
  Result := 0;
  n1 := GridHosts.GetNodeSOData(Node1);
  n2 := GridHosts.GetNodeSOData(Node2);

  if (Column >= 0) and (n1 <> nil) and (n2 <> nil) then
  begin
    propname := TSOGridColumn(GridHosts.Header.Columns[column]).PropertyName;
    d1 := n1[propname];
    d2 := n2[propname];
    if d1=nil then d1:=SO('""');
    if d2=nil then d2:=SO('""');
    if (d1 <> nil) and (d2 <> nil) then
    begin
      if (pos('version',propname)>0) or (pos('connected_ips',propname)>0) then
        Result:=CompareVersion(d1.AsString,d2.AsString)
      else
      if (pos('host.mac',propname)>0) then
        Result:=CompareStr(d1.AsString,d2.AsString)
      else
      begin
        CompResult := d1.Compare(d2);
        case compresult of
          cpLess : Result := -1;
          cpEqu  : Result := 0;
          cpGreat : Result := 1;
          cpError :Result := strcompare(n1.S[propname],n2.S[propname]);
        end;
      end;
    end
    else
      Result := -1;
  end
  else
    Result := 0;
end;

procedure TVisWaptGUI.GridHostsDragDrop(Sender: TBaseVirtualTree;
  Source: TObject; DataObject: IDataObject; Formats: TFormatArray;
  Shift: TShiftState; const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
var
  propname : String;
  col : TSOGridColumn;
begin
  if (Source = GridhostInventory) then
  begin
    // drop d'un nouvel attribut
    propname := GridhostInventory.Path(GridhostInventory.FocusedNode,0,ttNormal,'.');
    propname := copy(propname,1,length(propname)-1);
    col := Gridhosts.FindColumnByPropertyName(propname);
    if col = Nil then
    begin
      col :=Gridhosts.Header.Columns.Add as TSOGridColumn;
      col.Text:=propname;
      col.PropertyName:=propname;
      col.Width:= 100;
    end;
  end;
end;

procedure TVisWaptGUI.GridHostsDragOver(Sender: TBaseVirtualTree;
  Source: TObject; Shift: TShiftState; State: TDragState; const Pt: TPoint;
  Mode: TDropMode; var Effect: DWORD; var Accept: Boolean);
var
  propname : String;
begin
  // dragDrop d'un attribut pour enrichir la grille des hosts
  if (Source = GridhostInventory) then
  begin
    propname := GridhostInventory.Path(GridhostInventory.FocusedNode,0,ttNormal,'.');
    propname := copy(propname,1,length(propname)-1);

    Accept := (GridHosts.FindColumnByPropertyName(propname)=Nil);
  end;
end;

procedure TVisWaptGUI.GridHostsEditing(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; var Allowed: Boolean);
begin
  Allowed:=False;
end;

procedure TVisWaptGUI.GridLoadData(grid: TSOGrid; jsondata: string);
begin
  if (jsondata <> '') then
    try
      Grid.Data := SO(jsondata);
    finally
    end;
end;

procedure TVisWaptGUI.TreeLoadData(tree: TVirtualJSONInspector; jsondata: string);
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

procedure TVisWaptGUI.GridHostsGetImageIndexEx(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
  var Ghosted: boolean; var ImageIndex: integer; var ImageList: TCustomImageList);
var
  RowSO, update_status, upgrades, errors: ISuperObject;
begin
  if GridHosts.Header.Columns[Column].Text='Status' then
  begin
    RowSO :=GridHosts.GetNodeSOData(Node);
    if RowSO<>Nil then
    begin
      update_status := RowSO['update_status'];
      if (update_status <> nil) then
      begin
        ImageList := ImageList1;
        errors := update_status['errors'];
        upgrades := update_status['upgrades'];
        if (errors <> nil) and (errors.AsArray.Length > 0) then
          ImageIndex := 2
        else
        if (upgrades <> nil) and (upgrades.AsArray.Length > 0) then
          ImageIndex := 1
        else
          ImageIndex := 0;
      end;
    end;
  end;
end;

procedure TVisWaptGUI.GridHostsGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; RowData, CellData: ISuperObject; Column: TColumnIndex;
  TextType: TVSTTextType; var CellText: string);
var
  RowSO,update_status,errors,Upgrades : ISuperObject;
begin
  if Node=Nil then
    CellText := ''
  else
  begin
    if (CellData <> nil) and (CellData.DataType = stArray) then
      CellText := Join(',', CellData);
    if GridHosts.Header.Columns[Column].Text='Status' then
    begin
      RowSO := GridHosts.GetNodeSOData(Node);
      if RowSO<>Nil then
      begin
        update_status := RowSO['update_status'];
        if (update_status <> nil) then
        begin
          errors := update_status['errors'];
          upgrades := update_status['upgrades'];
          if (errors <> nil) and (errors.AsArray.Length > 0) then
            CellText:='ERROR'
          else
          if (upgrades <> nil) and (upgrades.AsArray.Length > 0) then
            CellText:='TO-UPGRADE'
          else
            CellText:='OK';
        end;
      end
      else
        CellText:='';
    end;
  end;
end;

procedure TVisWaptGUI.GridPackagesChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  MemoGroupeDescription.Lines.Text:= GridPackages.GetCellStrValue(Node,'description');
end;

procedure TVisWaptGUI.GridPackagesColumnDblClick(Sender: TBaseVirtualTree;
  Column: TColumnIndex; Shift: TShiftState);
begin
  ActEditpackage.Execute;
end;

procedure TVisWaptGUI.PythonOutputSendData(Sender: TObject; const Data: ansistring);
begin
  MemoLog.Lines.Add(Data);
end;

procedure TVisWaptGUI.GridPackagesPaintText(Sender: TBaseVirtualTree;
  const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
  TextType: TVSTTextType);
begin
  if StrIsOneOf(GridPackages.GetCellStrValue(Node, 'status'), ['I', 'U']) then
    TargetCanvas.Font.style := TargetCanvas.Font.style + [fsBold]
  else
    TargetCanvas.Font.style := TargetCanvas.Font.style - [fsBold];
end;

procedure TVisWaptGUI.HostPagesChange(Sender: TObject);
begin
  UpdateHostPages(Sender);
end;

procedure TVisWaptGUI.MenuItem20Click(Sender: TObject);
var
  package:AnsiString;
begin
  //package:=;
end;

procedure TVisWaptGUI.MenuItem27Click(Sender: TObject);
begin
  ShowMessage('Tranquil IT Systems: http://www.tranquil-it-systems.fr/'+#13#10+'Version Waptconsole:'+GetApplicationVersion+#13#10+'Version Wapt-get:'+GetApplicationVersion(WaptgetPath));
end;

procedure CopyMenu(menuItemSource: TPopupMenu; menuItemTarget: TMenuItem);
var
  i: integer;
  mi: TMenuItem;
begin
  menuItemTarget.Clear;
  for i := 0 to menuItemSource.Items.Count - 1 do
  begin
    mi := TMenuItem.Create(menuItemTarget);
    mi.Action := menuItemSource.Items[i].Action;
    menuItemTarget.Add(mi);
  end;
end;

procedure TVisWaptGUI.MainPagesChange(Sender: TObject);
begin
  if MainPages.ActivePage = pgInventory then
  begin
    CopyMenu(PopupMenuHosts, MenuItem24);
    if GridHosts.Data = nil then
      ActSearchHost.Execute;
  end
  else if MainPages.ActivePage = pgPrivateRepo then
  begin
    CopyMenu(PopupMenuPackages, MenuItem24);
    if GridPackages.Data = nil then
      ActSearchPackage.Execute;
  end
  else if MainPages.ActivePage = pgExternalRepo then
  begin
    CopyMenu(PopupMenuPackagesTIS, MenuItem24);
    if GridExternalPackages.Data = nil then
      butSearchExternalPackages.Click;
  end
  else if MainPages.ActivePage = pgGroups then
  begin
    CopyMenu(PopupMenuGroups, MenuItem24);
    if GridGroups.Data = nil then
      ActSearchGroups.Execute;
  end;
end;

function TVisWaptGUI.updateprogress(receiver: TObject;
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
