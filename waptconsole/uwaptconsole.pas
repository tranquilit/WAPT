unit uwaptconsole;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Windows, ActiveX, Types, Forms, Controls, Graphics,
  Dialogs, Buttons, FileUtil, SynEdit, SynHighlighterPython, TplStatusBarUnit,
  vte_json, ExtCtrls, StdCtrls, ComCtrls, ActnList, Menus, jsonparser,
  superobject, VirtualTrees, VarPyth, ImgList, SOGrid, uvisloading, IdComponent,
  DefaultTranslator, GetText, uWaptConsoleRes;

type

  { TVisWaptGUI }

  TVisWaptGUI = class(TForm)
    ActCancelRunningTask: TAction;
    ActCreateWaptSetupPy: TAction;
    ActForgetPackages: TAction;
    ActAddConflicts: TAction;
    ActHelp: TAction;
    ActImportFromRepo: TAction;
    ActImportFromFile: TAction;
    ActCreateWaptSetup: TAction;
    ActFrench: TAction;
    ActEnglish: TAction;
    ActCleanCache: TAction;
    ActAddADSGroups: TAction;
    ActHostsDeleteHostPackage: TAction;
    ActWSUSDowloadWSUSScan: TAction;
    ActTriggerWaptwua_install: TAction;
    ActTriggerWaptwua_download: TAction;
    ActTriggerWaptwua_scan: TAction;
    ActWSUSRefreshCabHistory: TAction;
    BitBtn10: TBitBtn;
    BitBtn9: TBitBtn;
    cbForcedWSUSscanDownload: TCheckBox;
    GridWSUSScn: TSOGrid;
    wsusResult: TMemo;
    MenuItem70: TMenuItem;
    MenuItem71: TMenuItem;
    MenuItem72: TMenuItem;
    MenuItem73: TMenuItem;
    pgWindowsUpdates: TTabSheet;
    WSUSActions: TActionList;
    ActWUANewGroup: TAction;
    ActWUAProductsSelection: TAction;
    ActWUAEditGroup: TAction;
    ActWUALoadGroups: TAction;
    ActWUAProductShow: TAction;
    ActWUAProductHide: TAction;
    ActWUADownloadSelectedUpdate: TAction;
    ActWUAAllowSelectedUpdates: TAction;
    ActWUAForbidSelectedUpdates: TAction;
    ActWUAProductForbidSeverity: TAction;
    ActWUAProductForbid: TAction;
    ActWUAProductAllowSeverity: TAction;
    ActWUAProductAllow: TAction;
    ActRefreshHostInventory: TAction;
    ActWUAResetSelectedUpdates: TAction;
    ActWUASaveUpdatesGroup: TAction;
    ActWUALoadUpdates: TAction;
    ActPackageInstall: TAction;
    ActRestoreDefaultLayout: TAction;
    ActTriggerHostUpdate: TAction;
    ActTriggerHostsListening: TAction;
    ActRemoveConflicts: TAction;
    ActSearchSoftwares: TAction;
    ActRemoveDepends: TAction;
    ActRDP: TAction;
    ActVNC: TAction;
    ActPackageRemove: TAction;
    ActLocalhostInstall: TAction;
    ActEditpackage: TAction;
    ActExecCode: TAction;
    ActEvaluate: TAction;
    ActBuildUpload: TAction;
    ActCreateCertificate: TAction;
    ActEvaluateVar: TAction;
    ActEditHostPackage: TAction;
    ActHostSearchPackage: TAction;
    ActHostsAddPackages: TAction;
    ActHostsDelete: TAction;
    ActDeletePackage: TAction;
    ActAdvancedMode: TAction;
    ActChangePassword: TAction;
    ActGotoHost: TAction;
    ActHostWaptUpgrade: TAction;
    ActTriggerHostUpgrade: TAction;
    ActAddPackageGroup: TAction;
    ActEditGroup: TAction;
    ActDeleteGroup: TAction;
    ActDeployWapt: TAction;
    ActSearchGroups: TAction;
    ActWAPTLocalConfig: TAction;
    ActReloadConfig: TAction;
    actRefresh: TAction;
    actQuit: TAction;
    ActAddGroup: TAction;
    ActSearchHost: TAction;
    ActLocalhostUpgrade: TAction;
    ActPackagesUpdate: TAction;
    ActLocalhostRemove: TAction;
    ActSearchPackage: TAction;
    ActionList1: TActionList;
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    btAddGroup: TBitBtn;
    butInitWapt: TBitBtn;
    butRun: TBitBtn;
    butSearchPackages: TBitBtn;
    butSearchGroups: TBitBtn;
    ButCancelHostTask: TBitBtn;
    ButHostSearch: TBitBtn;
    ButPackagesUpdate: TBitBtn;
    cbSearchDMI: TCheckBox;
    cbSearchHost: TCheckBox;
    cbSearchPackages: TCheckBox;
    cbSearchSoftwares: TCheckBox;
    cbSearchAll: TCheckBox;
    cbShowHostPackagesSoft: TCheckBox;
    cbShowHostPackagesGroup: TCheckBox;
    cbMaskSystemComponents: TCheckBox;
    cbShowLog: TCheckBox;
    cbNeedUpgrade: TCheckBox;
    cbHasErrors: TCheckBox;
    cbGroups: TComboBox;
    cbWUACriticalOnly: TCheckBox;
    cbWUAInstalled: TCheckBox;
    cbWUAPending: TCheckBox;
    cbWUADiscarded: TCheckBox;
    EdSoftwaresFilter: TEdit;
    EdRunningStatus: TEdit;
    EdSearchGroups: TEdit;
    GridGroups: TSOGrid;
    GridHostWinUpdates: TSOGrid;
    GridHostTasksPending: TSOGrid;
    GridHostTasksDone: TSOGrid;
    GridHostTasksErrors: TSOGrid;
    HostRunningTaskLog: TMemo;
    ActionsImages: TImageList;
    Image1: TImage;
    Label10: TLabel;
    Label11: TLabel;
    Label12: TLabel;
    HostRunningTask: TLabeledEdit;
    Label13: TLabel;
    Label14: TLabel;
    Label15: TLabel;
    LabelComputersNumber: TLabel;
    labSelected: TLabel;
    MemoTaskLog: TMemo;
    MemoInstallOutput: TMemo;
    MemoGroupeDescription: TMemo;
    MenuItem17: TMenuItem;
    MenuItem19: TMenuItem;
    MenuItem20: TMenuItem;
    MenuItem25: TMenuItem;
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
    MenuItem42: TMenuItem;
    MenuItem43: TMenuItem;
    MenuItem44: TMenuItem;
    MenuItem45: TMenuItem;
    MenuItem46: TMenuItem;
    MenuItem47: TMenuItem;
    MenuItem48: TMenuItem;
    MenuItem49: TMenuItem;
    MenuItem50: TMenuItem;
    MenuItem51: TMenuItem;
    MenuItem52: TMenuItem;
    MenuItem53: TMenuItem;
    MenuItem54: TMenuItem;
    MenuItem55: TMenuItem;
    MenuItem56: TMenuItem;
    MenuItem57: TMenuItem;
    MenuItem58: TMenuItem;
    MenuItem59: TMenuItem;
    MenuItem60: TMenuItem;
    MenuItem61: TMenuItem;
    MenuItem62: TMenuItem;
    MenuItem63: TMenuItem;
    MenuItem64: TMenuItem;
    MenuItem65: TMenuItem;
    MenuItem66: TMenuItem;
    MenuItem67: TMenuItem;
    MenuItem68: TMenuItem;
    MenuItem69: TMenuItem;
    OpenDialogWapt: TOpenDialog;
    PageControl1: TPageControl;
    Panel11: TPanel;
    Panel12: TPanel;
    PopupWUAProducts: TPopupMenu;
    Panel2: TPanel;
    Panel3: TPanel;
    Panel5: TPanel;
    Panel6: TPanel;
    plStatusBar1: TplStatusBar;
    PopupHostPackages: TPopupMenu;
    PopupWUAUpdates: TPopupMenu;
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
    EdSearchHost: TEdit;
    EdRun: TEdit;
    EdSearch: TEdit;
    GridHosts: TSOGrid;
    GridhostInventory: TVirtualJSONInspector;
    ImageList1: TImageList;
    Label1: TLabel;
    pgGroups: TTabSheet;
    HostTaskRunningProgress: TProgressBar;
    ProgressBar1: TProgressBar;
    Splitter3: TSplitter;
    pgTasks: TTabSheet;
    Splitter5: TSplitter;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    TabSheet3: TTabSheet;
    pgHostWUA: TTabSheet;
    TimerWUALoadWinUpdates: TTimer;
    TimerTasks: TTimer;
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
    MenuItem18: TMenuItem;
    MenuItem2: TMenuItem;
    MenuItem21: TMenuItem;
    MenuItem22: TMenuItem;
    MenuItem23: TMenuItem;
    MenuItem24: TMenuItem;
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
    PanDebug: TPanel;
    Panel4: TPanel;
    Panel7: TPanel;
    Panel9: TPanel;
    PopupMenuHosts: TPopupMenu;
    PopupMenuPackages: TPopupMenu;
    PopupMenuEditDepends: TPopupMenu;
    Splitter1: TSplitter;
    Splitter2: TSplitter;
    Splitter4: TSplitter;
    SynPythonSyn1: TSynPythonSyn;
    pgSources: TTabSheet;
    pgPrivateRepo: TTabSheet;
    pgInventory: TTabSheet;
    pgPackages: TTabSheet;
    pgSoftwares: TTabSheet;
    pgHostInventory: TTabSheet;
    testedit: TSynEdit;
    jsonlog: TVirtualJSONInspector;
    GridPackages: TSOGrid;
    GridHostPackages: TSOGrid;
    GridHostSoftwares: TSOGrid;
    ToolBar1: TToolBar;
    ToolButton1: TToolButton;
    ToolButton2: TToolButton;
    ToolButton3: TToolButton;
    ToolButton4: TToolButton;
    ToolButton5: TToolButton;
    ToolButton6: TToolButton;
    ToolButton7: TToolButton;
    procedure ActAddADSGroupsExecute(Sender: TObject);
    procedure ActAddConflictsExecute(Sender: TObject);
    procedure ActAddPackageGroupExecute(Sender: TObject);
    procedure ActAdvancedModeExecute(Sender: TObject);
    procedure ActCancelRunningTaskExecute(Sender: TObject);
    procedure ActChangePasswordExecute(Sender: TObject);
    procedure ActCleanCacheExecute(Sender: TObject);
    procedure ActCreateCertificateExecute(Sender: TObject);
    procedure ActCreateWaptSetupExecute(Sender: TObject);
    procedure ActDeleteGroupExecute(Sender: TObject);
    procedure ActDeleteGroupUpdate(Sender: TObject);
    procedure ActDeletePackageExecute(Sender: TObject);
    procedure ActDeletePackageUpdate(Sender: TObject);
    procedure ActDeployWaptExecute(Sender: TObject);
    procedure ActTriggerWaptwua_downloadExecute(Sender: TObject);
    procedure ActTriggerWaptwua_installExecute(Sender: TObject);
    procedure ActTriggerWaptwua_scanExecute(Sender: TObject);
    procedure ActWSUSDowloadWSUSScanExecute(Sender: TObject);
    procedure ActWSUSRefreshCabHistoryExecute(Sender: TObject);
    procedure ActWUADownloadSelectedUpdateUpdate(Sender: TObject);
    procedure ActEditGroupExecute(Sender: TObject);
    procedure ActEditHostPackageExecute(Sender: TObject);
    procedure ActEnglishExecute(Sender: TObject);
    procedure ActEnglishUpdate(Sender: TObject);
    procedure ActForgetPackagesExecute(Sender: TObject);
    procedure ActFrenchExecute(Sender: TObject);
    procedure ActFrenchUpdate(Sender: TObject);
    procedure ActGotoHostExecute(Sender: TObject);
    procedure ActHelpExecute(Sender: TObject);
    procedure ActHostsActionsUpdate(Sender: TObject);
    procedure ActImportFromFileExecute(Sender: TObject);
    procedure ActImportFromRepoExecute(Sender: TObject);
    procedure ActWUALoadUpdatesExecute(Sender: TObject);
    procedure ActWUALoadUpdatesUpdate(Sender: TObject);
    procedure ActPackageInstallExecute(Sender: TObject);
    procedure ActPackageRemoveExecute(Sender: TObject);
    procedure ActRDPExecute(Sender: TObject);
    procedure ActRDPUpdate(Sender: TObject);
    procedure ActRefreshHostInventoryExecute(Sender: TObject);
    procedure ActRemoveConflictsExecute(Sender: TObject);
    procedure ActRemoveDependsExecute(Sender: TObject);
    procedure ActWUANewGroupExecute(Sender: TObject);
    procedure ActWUAProductHideExecute(Sender: TObject);
    procedure ActWUAProductShowExecute(Sender: TObject);
    procedure ActWUAProductsSelectionExecute(Sender: TObject);
    procedure ActRestoreDefaultLayoutExecute(Sender: TObject);
    procedure ActSearchGroupsExecute(Sender: TObject);
    procedure ActTriggerHostUpdateExecute(Sender: TObject);
    procedure ActTriggerHostUpgradeExecute(Sender: TObject);
    procedure ActTriggerHostUpgradeUpdate(Sender: TObject);
    procedure ActHostWaptUpgradeExecute(Sender: TObject);
    procedure ActPackageEdit(Sender: TObject);
    procedure ActEditpackageUpdate(Sender: TObject);
    procedure ActEvaluateExecute(Sender: TObject);
    procedure ActExecCodeExecute(Sender: TObject);
    procedure ActHostsCopyExecute(Sender: TObject);
    procedure ActHostsDeleteExecute(Sender: TObject);
    procedure actHostSelectAllExecute(Sender: TObject);
    procedure ActLocalhostInstallExecute(Sender: TObject);
    procedure ActLocalhostInstallUpdate(Sender: TObject);
    procedure ActAddGroupExecute(Sender: TObject);
    procedure actQuitExecute(Sender: TObject);
    procedure actRefreshExecute(Sender: TObject);
    procedure ActLocalhostRemoveExecute(Sender: TObject);
    procedure ActLocalhostRemoveUpdate(Sender: TObject);
    procedure ActSearchHostExecute(Sender: TObject);
    procedure ActSearchPackageExecute(Sender: TObject);
    procedure ActPackagesUpdateExecute(Sender: TObject);
    procedure ActReloadConfigExecute(Sender: TObject);
    procedure ActTriggerHostsListeningExecute(Sender: TObject);
    procedure ActVNCExecute(Sender: TObject);
    procedure ActVNCUpdate(Sender: TObject);
    procedure ActWAPTLocalConfigExecute(Sender: TObject);
    procedure cbGroupsDropDown(Sender: TObject);
    procedure cbGroupsSelect(Sender: TObject);
    procedure cbMaskSystemComponentsClick(Sender: TObject);
    procedure cbShowLogClick(Sender: TObject);
    procedure cbWUAPendingChange(Sender: TObject);
    procedure cbWUCriticalClick(Sender: TObject);
    procedure CBWUProductsShowAllClick(Sender: TObject);
    procedure CheckBoxMajChange(Sender: TObject);
    procedure cbNeedUpgradeClick(Sender: TObject);
    procedure CheckBox_errorChange(Sender: TObject);
    procedure EdRunKeyPress(Sender: TObject; var Key: char);
    procedure EdSearchHostKeyPress(Sender: TObject; var Key: char);
    procedure EdSearchKeyPress(Sender: TObject; var Key: char);
    procedure EdSoftwaresFilterChange(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure GridGroupsColumnDblClick(Sender: TBaseVirtualTree;
      Column: TColumnIndex; Shift: TShiftState);
    procedure GridGroupsGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      RowData, CellData: ISuperObject; Column: TColumnIndex;
      TextType: TVSTTextType; var CellText: string);
    procedure GridGroupsInitNode(Sender: TBaseVirtualTree;
      ParentNode, Node: PVirtualNode; var InitialStates: TVirtualNodeInitStates);
    procedure GridGroupsMeasureItem(Sender: TBaseVirtualTree;
      TargetCanvas: TCanvas; Node: PVirtualNode; var NodeHeight: integer);
    procedure GridHostPackagesChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
    procedure GridHostPackagesGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: boolean; var ImageIndex: integer;
      var ImageList: TCustomImageList);
    procedure GridHostsChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
    procedure GridHostsColumnDblClick(Sender: TBaseVirtualTree;
      Column: TColumnIndex; Shift: TShiftState);
    procedure GridHostsCompareNodes(Sender: TBaseVirtualTree;
      Node1, Node2: PVirtualNode; Column: TColumnIndex; var Result: integer);
    procedure GridHostsDragDrop(Sender: TBaseVirtualTree; Source: TObject;
      DataObject: IDataObject; Formats: TFormatArray; Shift: TShiftState;
      const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
    procedure GridHostsDragOver(Sender: TBaseVirtualTree; Source: TObject;
      Shift: TShiftState; State: TDragState; const Pt: TPoint;
      Mode: TDropMode; var Effect: DWORD; var Accept: boolean);
    procedure GridHostsEditing(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; var Allowed: boolean);
    procedure GridHostsGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: boolean; var ImageIndex: integer;
      var ImageList: TCustomImageList);
    procedure GridHostsGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      RowData, CellData: ISuperObject; Column: TColumnIndex;
      TextType: TVSTTextType; var CellText: string);
    procedure GridHostsHeaderDblClick(Sender: TVTHeader; HitInfo: TVTHeaderHitInfo);
    procedure GridHostTasksPendingChange(Sender: TBaseVirtualTree;
      Node: PVirtualNode);
    procedure GridHostWinUpdatesGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: Boolean; var ImageIndex: Integer;
      var ImageList: TCustomImageList);
    procedure GridHostWinUpdatesGetText(Sender: TBaseVirtualTree;
      Node: PVirtualNode; RowData, CellData: ISuperObject;
      Column: TColumnIndex; TextType: TVSTTextType; var CellText: string);
    procedure GridPackagesChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
    procedure GridPackagesColumnDblClick(Sender: TBaseVirtualTree;
      Column: TColumnIndex; Shift: TShiftState);
    procedure GridPackagesPaintText(Sender: TBaseVirtualTree;
      const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
      TextType: TVSTTextType);
    procedure GridWinproductsChange(Sender: TBaseVirtualTree; Node: PVirtualNode
      );
    procedure GridWinUpdatesGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: Boolean; var ImageIndex: Integer;
      var ImageList: TCustomImageList);
    procedure HostPagesChange(Sender: TObject);
    procedure Image1Click(Sender: TObject);
    procedure MainPagesChange(Sender: TObject);
    procedure InstallPackage(Grid: TSOGrid);
    procedure MenuItem27Click(Sender: TObject);
    procedure TimerWUALoadWinUpdatesTimer(Sender: TObject);
    procedure TimerTasksTimer(Sender: TObject);
  private
    CurrentVisLoading: TVisLoading;
    procedure DoProgress(ASender: TObject);
    procedure FillcbGroups;
    function FilterSoftwares(softs: ISuperObject): ISuperObject;
    function FilterHostWinUpdates(wua: ISuperObject): ISuperObject;
    function FilterWindowsUpdate(wua: ISuperObject): ISuperObject;
    function FilterWinProducts(products: ISuperObject): ISuperObject;
    { private declarations }
    procedure GridLoadData(grid: TSOGrid; jsondata: string);
    procedure IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: int64);
    procedure PythonOutputSendData(Sender: TObject; const Data: ansistring);
    procedure TreeLoadData(tree: TVirtualJSONInspector; jsondata: string);
    procedure UpdateHostPages(Sender: TObject);
  public
    { public declarations }
    PackageEdited: ISuperObject;
    waptpath: string;

    MainRepoUrl, WAPTServer, TemplatesRepoUrl: string;

    WUAProducts : ISuperObject;
    WUAWinUpdates : ISuperObject;

    constructor Create(TheOwner: TComponent); override;

    function Login: boolean;
    function EditIniFile: boolean;
    function updateprogress(receiver: TObject; current, total: integer): boolean;
  end;

var
  VisWaptGUI: TVisWaptGUI;

implementation

uses LCLIntf, LCLType, IniFiles, uvisprivatekeyauth, tisstrings, soutils,
  waptcommon, tiscommon, uVisCreateKey, uVisCreateWaptSetup, dmwaptpython,
  uviseditpackage, uvislogin, uviswaptconfig, uvischangepassword,
  uvisgroupchoice, uviswaptdeploy, uvishostsupgrade, uVisAPropos,
  uVisImportPackage, uVisWUAGroup, uVisWAPTWUAProducts, PythonEngine, Clipbrd,
  RegExpr, tisinifiles;

{$R *.lfm}

{ TVisWaptGUI }


procedure TVisWaptGUI.DoProgress(ASender: TObject);
begin
  if CurrentVisLoading <> nil then
    CurrentVisLoading.DoProgress(ASender)
  else
  begin
    if ProgressBar1.Position >= ProgressBar1.Max then
      ProgressBar1.Position := 0
    else
      ProgressBar1.Position := ProgressBar1.Position + 1;
    Application.ProcessMessages;
  end;
end;


procedure TVisWaptGUI.IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode;
  AWorkCount: int64);
begin
  if CurrentVisLoading <> nil then
    CurrentVisLoading.DoProgress(ASender)
  else
  begin
    if ProgressBar1.Position >= ProgressBar1.Max then
      ProgressBar1.Position := 0
    else
      ProgressBar1.Position := ProgressBar1.Position + 1;
    Application.ProcessMessages;
  end;
end;

procedure TVisWaptGUI.cbShowLogClick(Sender: TObject);
begin
  DMPython.PythonOutput.OnSendData := @PythonOutputSendData;
  if cbShowLog.Checked then
    DMPython.PythonEng.ExecString('logger.setLevel(logging.DEBUG)')
  else
    DMPython.PythonEng.ExecString('logger.setLevel(logging.WARNING)');

end;

procedure TVisWaptGUI.cbWUAPendingChange(Sender: TObject);
begin
  if (Gridhosts.FocusedRow <> nil) then
    GridHostWinUpdates.Data := FilterHostWinUpdates(Gridhosts.FocusedRow['waptwua.updates']);
end;

procedure TVisWaptGUI.cbWUCriticalClick(Sender: TObject);
begin
  //ActWUALoadUpdates.Execute;
  TimerWUALoadWinUpdatesTimer(sender);
end;

procedure TVisWaptGUI.CBWUProductsShowAllClick(Sender: TObject);
begin
  //GridWinproducts.Data := FilterWinProducts(WUAProducts);
end;

procedure TVisWaptGUI.CheckBoxMajChange(Sender: TObject);
begin
  ActHostSearchPackage.Execute;
end;

procedure TVisWaptGUI.cbNeedUpgradeClick(Sender: TObject);
begin
  Gridhosts.Clear;
  if (sender = cbSearchAll) then
  begin
    if cbSearchAll.Checked then
    begin
      cbSearchDMI.Checked := True;
      cbSearchSoftwares.Checked := True;
      cbSearchPackages.Checked := True;
      cbSearchHost.Checked := True;
    end
  end
  else
    cbSearchAll.Checked:= cbSearchDMI.Checked and cbSearchSoftwares.Checked and cbSearchPackages.Checked and cbSearchHost.Checked;
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

procedure TVisWaptGUI.EdSoftwaresFilterChange(Sender: TObject);
begin
  if (Gridhosts.FocusedRow <> nil) then
    GridHostSoftwares.Data := FilterSoftwares(Gridhosts.FocusedRow['softwares']);

end;

procedure TVisWaptGUI.FormClose(Sender: TObject; var CloseAction: TCloseAction);
var
  ini : TIniFile;
  last_usage_report : TDateTime;
  stats: ISuperObject;
  stats_report_url:String;
begin
  Gridhosts.SaveSettingsToIni(Appuserinipath);
  GridPackages.SaveSettingsToIni(Appuserinipath);
  GridGroups.SaveSettingsToIni(Appuserinipath);
  GridHostPackages.SaveSettingsToIni(Appuserinipath);
  GridHostSoftwares.SaveSettingsToIni(Appuserinipath);
  ini := TIniFile.Create(AppIniFilename);
  try
    if ini.ReadBool('Global','send_usage_report',True) then
    begin
      last_usage_report:=ini.ReadDateTime('Global','last_usage_report',0);
      if now - last_usage_report >= 1 then
      try
        stats_report_url:=ini.ReadString('Global','usage_report_url',rsDefaultUsageStatsURL);
        stats := WAPTServerJsonGet('api/v1/usage_statistics',[])['result'];
        IdHttpPostData(stats_report_url,stats.AsJSon,waptcommon.UseProxyForTemplates);
        ini.WriteDateTime('Global','last_usage_report',Now);
      except
        ini.WriteDateTime('Global','last_usage_report',Now);
      end;
    end;
    ini.WriteString('Global','language',DMPython.Language);
  finally
    ini.Free;
  end;
end;

function TVisWaptGUI.FilterSoftwares(softs: ISuperObject): ISuperObject;
var
  soft: ISuperObject;
  accept: boolean;
  reg: string;
begin
  if (EdSoftwaresFilter.Text = '') and not cbMaskSystemComponents.Checked then
    Result := softs
  else
  begin
    Result := TSuperObject.Create(stArray);
    if softs = nil then
      Exit;
    for soft in softs do
    begin
      Accept := True;
      accept := accept and (not cbMaskSystemComponents.Checked or
        (soft.I['system_component'] <> 1));
      if EdSoftwaresFilter.Text = '' then
        reg := '.*'
      else
        reg := EdSoftwaresFilter.Text;
      reg := '(?i)' + reg;

      accept := accept and (ExecRegExpr(reg, soft.S['name']) or
        ExecRegExpr(reg, soft.S['key']));
      {accept:= accept and ((EdSoftwaresFilter.Text='') or
                      (pos(LowerCase(EdSoftwaresFilter.Text),LowerCase(soft.S['name']))>0) or
                      (pos(LowerCase(EdSoftwaresFilter.Text),LowerCase(soft.S['key']))>0));
      }
      if accept then
        Result.AsArray.Add(soft);
    end;
  end;
end;

function TVisWaptGUI.FilterHostWinUpdates(wua: ISuperObject): ISuperObject;
var
  wupdate: ISuperObject;
  accept: boolean;
  reg: string;
begin
  Result := TSuperObject.Create(stArray);
  if (wua = nil) or (wua.AsArray = Nil) then
    Exit;
  for wupdate in wua do
  begin
    Accept := False;

    if cbWUADiscarded.Checked then
      accept := accept or (wupdate.B['hidden'] and not wupdate.B['installed']);

    if cbWUAInstalled.Checked then
      accept := accept or ( wupdate.B['installed']);

    if cbWUAPending.Checked then
      accept := accept or ( not wupdate.B['installed'] and not wupdate.B['hidden']);

    accept := accept and (not cbWUACriticalOnly.Checked or (wupdate.S['severity'] ='Critical'));
    if accept then
      Result.AsArray.Add(wupdate);
  end;
end;

function TVisWaptGUI.FilterWindowsUpdate(wua: ISuperObject
  ): ISuperObject;
var
  wupdate: ISuperObject;
  accept: boolean;
  reg: string;
begin
  Result := TSuperObject.Create(stArray);
  if (wua = nil) or (wua.AsArray = Nil) then
    Exit;
  for wupdate in wua do
  begin
    Accept := False;

    if cbWUADiscarded.Checked then
      accept := accept or (wupdate.B['hidden']);

    if cbWUAInstalled.Checked then
      accept := accept or ( wupdate.B['installed']);

    if cbWUAPending.Checked then
      accept := accept or ( not wupdate.B['installed'] and not wupdate.B['hidden']);

    accept := accept and (not cbWUACriticalOnly.Checked or (wupdate.S['severity'] ='Critical'));
    if accept then
      Result.AsArray.Add(wupdate);
  end;
end;

function TVisWaptGUI.FilterWinProducts(products: ISuperObject): ISuperObject;
var
  wproduct: ISuperObject;
  accept: boolean;
begin
  {Result := TSuperObject.Create(stArray);
  if (products = nil) or (products.AsArray = Nil) then
    Exit;
  for wproduct in products do
  begin
    Accept := CBWUProductsShowAll.Checked or wproduct.B['favourite'];
    if accept then
      Result.AsArray.Add(wproduct);
  end;}
end;


procedure TVisWaptGUI.UpdateHostPages(Sender: TObject);
var
  currhost,packagename : ansistring;
  RowSO, package,packagereq, packages, softwares, waptwua,dmi,tasksresult, running,sores,additional,upgrades: ISuperObject;
begin
  TimerTasks.Enabled := False;
  RowSO := Gridhosts.FocusedRow;
  if (RowSO <> nil) then
  begin
    currhost := RowSO.S['uuid'];
    if HostPages.ActivePage = pgPackages then
    begin
      packages := RowSO['packages'];
      if (packages = nil) or (packages.AsArray = nil) then
      try
        sores := WAPTServerJsonGet('api/v1/host_data?field=packages&uuid=%s',[currhost]);
        if sores.B['success'] then
        begin
          RowSO['packages'] := sores['result'];
          // add missing packages
          additional := RowSO['update_status.pending.additional'];
          if (additional<>Nil) and (additional.AsArray.Length>0) then
          begin
            for packagereq in additional do
            begin
              package := TSuperObject.Create();
              package['package'] := packagereq;
              package.S['install_status'] := 'MISSING';
              RowSO.A['packages'].Add(package);
            end;
          end;
          upgrades := RowSO['update_status.pending.upgrade'];
          if (upgrades<>Nil) and (upgrades.AsArray.Length>0) then
          begin
            for package in RowSO['packages'] do
            begin
              for packagereq in upgrades do
              begin
                packagename:= Trim(copy(packagereq.AsString,1,pos('(',packagereq.AsString)-1));
                if package.S['package'] = packagename then
                  package.S['install_status'] := 'NEED-UPGRADE';
              end;
            end;
          end;
        end
        else
          RowSO['packages'] := nil;
      except
        RowSO['packages'] := nil;
      end;
      EdHostname.Text := UTF8Encode(RowSO.S['host.computer_name']);
      EdDescription.Text := UTF8Encode(RowSO.S['host.description']);
      EdOS.Text := RowSO.S['host.windows_product_infos.version'];
      if RowSO['host.connected_ips'].DataType=stArray then
        EdIPAddress.Text := soutils.join(',',RowSO['host.connected_ips'])
      else
        EdIPAddress.Text := RowSO.S['host.connected_ips'];
      EdManufacturer.Text := UTF8Encode(RowSO.S['host.system_manufacturer']);
      EdModelName.Text := UTF8Encode(RowSO.S['host.system_productname']);
      EdUpdateDate.Text := UTF8Encode(RowSO.S['last_query_date']);
      If RowSO['host.current_user'].DataType=stArray then
        EdUser.Text := UTF8Encode(soutils.join(',',RowSO['host.current_user']))
      else
        EdUser.Text := UTF8Encode(RowSO.S['host.current_user']);
      EdRunningStatus.Text := UTF8Encode(RowSO.S['update_status.runstatus']);
      GridHostPackages.Data := RowSO['packages'];
    end
    else if HostPages.ActivePage = pgSoftwares then
    begin
      //Cache collection in grid data
      softwares := RowSO['softwares'];
      if (softwares = nil) or (softwares.AsArray = nil) then
      try
        sores := WAPTServerJsonGet('api/v1/host_data?field=softwares&uuid=%s',[currhost]);
        if sores.B['success'] then
          softwares := sores['result']
        else
          softwares := nil;
      except
        softwares := nil;
      end;
      RowSO['softwares'] := softwares;
      GridHostSoftwares.Data := FilterSoftwares(softwares);
    end
    else if HostPages.ActivePage = pgHostWUA then
    begin
      //Cache collection in grid data
      waptwua := RowSO['waptwua'];
      if (waptwua = nil) or (waptwua.AsArray = nil) then
      try
        sores := WAPTServerJsonGet('api/v1/host_data?field=waptwua&uuid=%s',[currhost]);
        if sores.B['success'] then
          waptwua := sores['result']
        else
          waptwua := nil;
      except
        waptwua := nil;
      end;
      RowSO['waptwua'] := waptwua;
      if waptwua<>Nil then
        GridHostWinUpdates.Data := FilterHostWinUpdates(waptwua['updates'])
      else
        GridHostWinUpdates.Data := Nil;

    end
    else if HostPages.ActivePage = pgHostInventory then
    begin
      try
        sores := WAPTServerJsonGet('api/v1/host_data?field=dmi&uuid=%s',[currhost]);
        if sores.B['success'] then
          dmi := sores['result']
        else
          dmi := nil;
      except
        dmi := nil;
      end;
      RowSO['dmi'] := dmi;
      try
        sores := WAPTServerJsonGet('api/v1/host_data?field=waptwua&uuid=%s',[currhost]);
        if sores.B['success'] then
          waptwua := sores['result']
        else
          waptwua := nil;
      except
        waptwua := nil;
      end;
      RowSO['waptwua'] := waptwua;
      TreeLoadData(GridhostInventory, RowSO.AsJSon());
    end
    else if HostPages.ActivePage = pgTasks then
    begin
      try
        try
          sores := WAPTServerJsonGet('api/v1/host_tasks_status?uuid=%s', [currhost]);
          if sores.B['success'] then
          begin
            tasksresult := sores['result'];
            if tasksresult <> nil then
            begin
              running := tasksresult['running'];
              if not GridHostTasksPending.Focused then
                GridHostTasksPending.Data := tasksresult['pending'];
              if not GridHostTasksDone.Focused then
                GridHostTasksDone.Data := tasksresult['done'];
              if not GridHostTasksErrors.Focused then
                GridHostTasksErrors.Data := tasksresult['errors'];
              if running <> nil then
              begin
                if running['description'] <> Nil then
                   ActCancelRunningTask.Enabled:=True;

                HostTaskRunningProgress.Position := running.I['progress'];
                HostRunningTask.Text := UTF8Encode(running.S['description']);
                if not HostRunningTaskLog.Focused then
                  HostRunningTaskLog.Text := UTF8Encode(running.S['logs']);
              end
              else
              begin
                ActCancelRunningTask.Enabled:=False;
                HostTaskRunningProgress.Position := 0;
                HostRunningTask.Text := 'Idle';
                if not HostRunningTaskLog.Focused then
                  HostRunningTaskLog.Clear;
              end;

              with HostRunningTaskLog do
              begin
                selstart := GetTextLen; // MUCH more efficient then Length(text)!
                SelLength := 0;
                ScrollBy(0, 65535);
              end;
            end
          end
          else
          begin
            HostRunningTask.Text := rsFatalError+' '+sores.S['msg'];
            HostTaskRunningProgress.Position := 0;
            HostRunningTaskLog.Clear;
            GridHostTasksPending.Data := nil;
            GridHostTasksDone.Data := nil;
            GridHostTasksErrors.Data := nil;
          end;
        except
          on E:Exception do
            HostRunningTask.Text := rsFatalError+' '+E.Message;
        end
      finally
        TimerTasks.Enabled := True;
      end;
    end;
  end
  else
  begin
    HostRunningTask.Text := '';
    HostTaskRunningProgress.Position := 0;
    GridHostPackages.Clear;
    GridHostSoftwares.Clear;
    HostRunningTaskLog.Clear;
    GridHostTasksPending.Data := nil;
    GridHostTasksDone.Data := nil;
    GridHostTasksErrors.Data := nil;
  end;
end;

constructor TVisWaptGUI.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
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
  res: ISuperObject;
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
        ProgressTitle(format(
          rsInstalling, [Grid.GetCellStrValue(N, 'package')]));
        ProgressStep(trunc((i / selects) * 100), 100);
        i := i + 1;
        //DMPython.RunJSON(format('mywapt.install("%s")', [package]), jsonlog);
        res := WAPTLocalJsonGet(format('install?package=%s', [package]));
        N := Grid.GetNextSelected(N);
      end;
    finally
      Self.Enabled := True;
      Free;
    end;

end;

procedure TVisWaptGUI.MenuItem27Click(Sender: TObject);
begin
  with TVisApropos.Create(Self) do
    ShowModal;
end;

procedure TVisWaptGUI.TimerWUALoadWinUpdatesTimer(Sender: TObject);
begin
  TimerWUALoadWinUpdates.Enabled:=False;
  ActWUALoadUpdates.Execute;
end;

procedure TVisWaptGUI.TimerTasksTimer(Sender: TObject);
begin
  if (HostPages.ActivePage = pgTasks) and (MainPages.ActivePage=pgInventory) then
    UpdateHostPages(Self);
end;

procedure TVisWaptGUI.ActLocalhostInstallUpdate(Sender: TObject);
begin
  //ActLocalhostInstall.Enabled := GridPackages.SelectedCount > 0;
  ActLocalhostInstall.Enabled := False;
end;


procedure TVisWaptGUI.ActAddGroupExecute(Sender: TObject);
begin
  if IniReadString(AppIniFilename,'Global','default_sources_root')<>'' then
  begin
    CreateGroup('agroup', ActAdvancedMode.Checked);
    ActPackagesUpdate.Execute;
  end
  else
    ShowMessage(rsDefineWaptdevPath);
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
    begin
      //update groups filter combobox
      if cbGroups.ItemIndex>=0 then
        FillcbGroups;
      ActSearchHost.Execute
    end
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

procedure TVisWaptGUI.ActPackageEdit(Sender: TObject);
var
  Selpackage,DevPath: string;
  res: ISuperObject;
begin
  if GridPackages.FocusedNode <> nil then
  begin
    if IniReadString(AppIniFilename,'Global','default_sources_root')<>'' then
    begin
      Selpackage := format('%s(=%s)', [GridPackages.GetCellStrValue(
        GridPackages.FocusedNode, 'package'), GridPackages.GetCellStrValue(
        GridPackages.FocusedNode, 'version')]);
      try
        DevPath:=DMPython.RunJSON(format('mywapt.get_default_development_dir("%s")', [SelPackage])).AsString;
        if DirectoryExistsUTF8(DevPath) then
          DevPath:=DevPath+'.'+GridPackages.GetCellStrValue(GridPackages.FocusedNode, 'version');
        res := DMPython.RunJSON(format('mywapt.edit_package(r"%s",target_directory=r"%s",auto_inc_version=False)', [SelPackage,DevPath]));
      except
        on E:Exception do
        begin
          ShowMessageFmt(rsErrorWithMessage,[e.Message]);
          exit;
        end;
      end;
      DMPython.RunJSON(format('waptdevutils.wapt_sources_edit(r"%s")', [res.S['target']]));
      //if EditPackage(Selpackage, ActAdvancedMode.Checked) <> nil then
      //  ActPackagesUpdate.Execute;
    end
    else
      ShowMessage(rsDefineWaptdevPath);
  end
end;

procedure TVisWaptGUI.ActEditpackageUpdate(Sender: TObject);
begin
  ActEditpackage.Enabled := GridPackages.SelectedCount > 0;
end;

procedure TVisWaptGUI.ActCreateCertificateExecute(Sender: TObject);
var
  params, certFile: string;
  Result: ISuperObject;
  done: boolean;
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
            params := params + format('country=r"%s".decode(''utf8''),',
              [edCountry.Text]);
            params := params + format('locality=r"%s".decode(''utf8''),',
              [edLocality.Text]);
            params := params + format('organization=r"%s".decode(''utf8''),',
              [edOrganization.Text]);
            params := params + format('unit=r"%s".decode(''utf8''),', [edUnit.Text]);
            params := params + format('commonname=r"%s",', [edCommonName.Text]);
            params := params + format('email=r"%s",', [edEmail.Text]);
            params := params + format('wapt_base_dir=r"%s",', [waptpath]);
            Result := DMPython.RunJSON(
              format('common.create_self_signed_key(%s)', [params]),
              jsonlog);
            done := FileExists(Result.S['pem_filename']);
            if done then
            begin
              ShowMessageFmt(rsPublicKeyGenSuccess,
                [Result.S['pem_filename']]);
              certFile := Result.S['pem_filename'];
              StrReplace(certFile, '.pem', '.crt');
              if not CopyFile(PChar(certFile),
                PChar(waptpath + '\ssl\' + ExtractFileName(certFile)), True) then
                ShowMessage(rsPublicKeyGenFailure);

              with TINIFile.Create(AppIniFilename) do
                try
                  WriteString('global', 'private_key', Result.S['pem_filename']);
                finally
                  Free;
                end;

              ActReloadConfigExecute(self);
            end;

          except
            on e: Exception do
            begin
              ShowMessage(format(rsPublicKeyGenError, [e.Message]));
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

procedure TVisWaptGUI.ActCreateWaptSetupExecute(Sender: TObject);
var
  waptsetupPath, buildDir: string;
  ini: TIniFile;
  SORes: ISuperObject;
begin
  with TVisCreateWaptSetup.Create(self) do
    try
      ini := TIniFile.Create(AppIniFilename);
      fnPublicCert.Text := ChangeFileExt(ini.ReadString('global', 'private_key', ''), '.crt');
      if not FileExists(fnPublicCert.Text) then
        fnPublicCert.Clear;
      edWaptServerUrl.Text := ini.ReadString('global', 'wapt_server', '');
      edRepoUrl.Text := ini.ReadString('global', 'repo_url', '');
      fnWaptDirectory.Directory := GetTempDir(False);
      if ShowModal = mrOk then
      begin
        CurrentVisLoading := TVisLoading.Create(Self);
        with CurrentVisLoading do
          try
            ExceptionOnStop := True;
            Screen.Cursor := crHourGlass;
            ProgressTitle(rsCreationInProgress);
            Start;
            // create waptupgrade package
            ProgressTitle(rsCreationInProgress);
            try
              buildDir := GetTempDir(False);
              if RightStr(buildDir,1) = '\' then
                buildDir := copy(buildDir,1,length(buildDir)-1);
              SORes := DMPython.RunJSON(format('mywapt.build_upload(r"%s",private_key_passwd="%s",wapt_server_user="%s",wapt_server_passwd="%s",inc_package_release=True,target_directory=r"%s")',[
                  waptpath+'\waptupgrade',privateKeyPassword,WaptServerUser,WaptServerPassword,buildDir]));
              if FileExists(SORes.AsArray[0].S['filename']) then
              begin
                ProgressTitle(rsWaptUpgradePackageBuilt);
                DeleteFileUTF8(SORes.AsArray[0].S['filename']);
              end;
            except
              On E:Exception do
                ShowMessage(rsWaptUpgradePackageBuildError+#13#10+E.Message);
            end;
            Application.ProcessMessages;
            waptsetupPath := '';
            try
              ProgressTitle(rsCreationInProgress);
              waptsetupPath := CreateWaptSetup(fnPublicCert.FileName,
                edRepoUrl.Text, GetWaptServerURL, fnWaptDirectory.Directory, edOrgName.Text, @DoProgress, 'waptagent');

            except
              on E:Exception do
              begin
                ShowMessageFmt(rsWaptAgentSetupError,[E.Message]);
                exit;
              end;
            end;
            Finish;
            if FileExists(waptsetupPath) then
              try
                Start;
                ProgressTitle(rsProgressTitle);
                SORes := WAPTServerJsonMultipartFilePost(
                  GetWaptServerURL, 'upload_waptsetup', [], 'file', waptsetupPath,
                  WaptServerUser, WaptServerPassword, @IdHTTPWork);
                Finish;
                if SORes.S['status'] = 'OK' then
                begin
                  ShowMessage(format(rsWaptSetupUploadSuccess, []));
                  DeleteFileUTF8(waptsetupPath);
                end
                else
                  ShowMessage(format(rsWaptUploadError, [SORes.S['message']]));
              except
                on e: Exception do
                begin
                  ShowMessage(format(rsWaptSetupError, [e.Message]));
                  Finish;
                end;
              end;
          finally
            Finish;
            Screen.Cursor := crDefault;
            FreeAndNil(CurrentVisLoading);
          end;
      end;
    finally
      ini.Free;
      Free;
    end;
end;

procedure TVisWaptGUI.ActAddConflictsExecute(Sender: TObject);
var
  Res, packages, host, hosts: ISuperObject;
  N: PVirtualNode;
  args: ansistring;
begin
  if GridHosts.Focused then
  begin
    with TvisGroupChoice.Create(self) do
      try
        Caption := rsForcedUninstallPackages;
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

    CurrentVisLoading := TVisLoading.Create(Self);
    with CurrentVisLoading do
    try
      Hosts := TSuperObject.Create(stArray);
      for host in GridHosts.SelectedRows do
        hosts.AsArray.Add(host.S['host.computer_fqdn']);
      Start(GridHosts.SelectedRows.AsArray.Length);
      ProgressTitle(rsCreationInProgress);

      //edit_hosts_depends(waptconfigfile,hosts_list,appends,removes,key_password=None,wapt_server_user=None,wapt_server_passwd=None)
      args := '';
      args := args + format('waptconfigfile = r"%s".decode(''utf8''),', [AppIniFilename]);
      args := args + format('hosts_list = r"%s".decode(''utf8''),',
        [soutils.Join(',', hosts)]);
      args := args + format('append_depends = "",', []);
      args := args + format('remove_depends = "",', []);
      args := args + format('append_conflicts = r"%s".decode(''utf8''),',
        [soutils.Join(',', packages)]);
      args := args + format('remove_conflicts = "",', []);
      if privateKeyPassword <> '' then
        args := args + format('key_password = "%s".decode(''utf8''),',
          [privateKeyPassword]);
      args := args + format('wapt_server_user = r"%s".decode(''utf8''),', [waptServerUser]);
      args := args + format('wapt_server_passwd = r"%s".decode(''utf8''),',
        [waptServerPassword]);
      res := DMPython.RunJSON(format('waptdevutils.edit_hosts_depends(%s)', [args]));
    finally
      Finish;
      Free;
    end;
    ShowMessageFmt(rsNbModifiedHosts, [IntToStr(res.AsArray.Length)]);
  end;
end;

procedure TVisWaptGUI.ActAddADSGroupsExecute(Sender: TObject);
var
  Res, host, hosts: ISuperObject;
  args: ansistring;
begin
  if GridHosts.Focused and (MessageDlg(rsAddADSGroups, mtConfirmation, [mbYes, mbNo, mbCancel],0) = mrYes) then
  try

    Screen.Cursor := crHourGlass;
    Hosts := TSuperObject.Create(stArray);

    for host in GridHosts.SelectedRows do
      hosts.AsArray.Add(host.S['host.computer_fqdn']);

    //edit_hosts_depends(waptconfigfile,hosts_list,appends,removes,key_password=None,wapt_server_user=None,wapt_server_passwd=None)
    args := '';
    args := args + format('waptconfigfile = r"%s".decode(''utf8''),', [AppIniFilename]);
    args := args + format('hosts_list = r"%s".decode(''utf8''),',
      [soutils.Join(',', hosts)]);
    if privateKeyPassword <> '' then
      args := args + format('key_password = "%s".decode(''utf8''),',
        [privateKeyPassword]);
    args := args + format('wapt_server_user = r"%s".decode(''utf8''),', [waptServerUser]);
    args := args + format('wapt_server_passwd = r"%s".decode(''utf8''),',
      [waptServerPassword]);
    res := DMPython.RunJSON(format('waptdevutils.add_ads_groups(%s)', [args]));
    ShowMessageFmt(rsNbModifiedHosts, [IntToStr(res.AsArray.Length)]);
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TVisWaptGUI.ActAddPackageGroupExecute(Sender: TObject);
var
  Res, packages, host, hosts: ISuperObject;
  N: PVirtualNode;
  args: ansistring;
begin
  if GridHosts.Focused then
  begin
    with TvisGroupChoice.Create(self) do
      try
        Caption := rsDependencies;
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

    try
      Screen.Cursor := crHourGlass;
      Hosts := TSuperObject.Create(stArray);
      for host in GridHosts.SelectedRows do
        hosts.AsArray.Add(host.S['host.computer_fqdn']);

      //edit_hosts_depends(waptconfigfile,hosts_list,appends,removes,key_password=None,wapt_server_user=None,wapt_server_passwd=None)
      args := '';
      args := args + format('waptconfigfile = r"%s".decode(''utf8''),', [AppIniFilename]);
      args := args + format('hosts_list = r"%s".decode(''utf8''),',
        [soutils.Join(',', hosts)]);
      args := args + format('append_depends = r"%s".decode(''utf8''),',
        [soutils.Join(',', packages)]);
      args := args + format('remove_depends = "",', []);
      args := args + format('append_conflicts = "",', []);
      args := args + format('remove_conflicts = "",', []);
      if privateKeyPassword <> '' then
        args := args + format('key_password = "%s".decode(''utf8''),',
          [privateKeyPassword]);
      args := args + format('wapt_server_user = r"%s".decode(''utf8''),', [waptServerUser]);
      args := args + format('wapt_server_passwd = r"%s".decode(''utf8''),',
        [waptServerPassword]);
      res := DMPython.RunJSON(format('waptdevutils.edit_hosts_depends(%s)', [args]));
    finally
      Screen.Cursor := crDefault;
    end;

    ShowMessageFmt(rsNbModifiedHosts, [IntToStr(res.AsArray.Length)]);
  end;
end;

procedure TVisWaptGUI.ActAdvancedModeExecute(Sender: TObject);
begin
  ActAdvancedMode.Checked := not ActAdvancedMode.Checked;
  pgSources.TabVisible := ActAdvancedMode.Checked;
  PanDebug.Visible := ActAdvancedMode.Checked;
end;

procedure TVisWaptGUI.ActCancelRunningTaskExecute(Sender: TObject);
var
  sores,taskresult: ISuperObject;
  currhost: ansistring;
begin
  currhost := GridHosts.FocusedRow.S['uuid'];

  sores := WAPTServerJsonGet('api/v1/host_cancel_task?uuid=%s', [currhost]);
  if sores.B['success'] then
  begin
    taskresult := sores['result'];
    ShowMessage(rsTaskCanceled)
  end
  else
    ShowMessageFmt(rsFailedToCancel, [sores.S['msg']]);
end;

procedure TVisWaptGUI.ActChangePasswordExecute(Sender: TObject);
var
  cred,resp:ISuperObject;
begin
  with TvisChangePassword.Create(self) do
  try
    if ShowModal = mrOk then
    begin
      cred := SO();
      cred.S['username'] := waptServerUser;
      cred.S['password'] := UTF8Decode(WaptServerPassword);
      cred.S['newPass'] := UTF8Decode(EdNewPassword1.Text);
      try
        resp := WAPTServerJsonPost('login', [], cred);
        try
          if not StrToBool(resp.AsString) then
            ShowMessage(rsIncorrectPassword)
          else
          begin
            waptServerPassword := EdNewPassword1.Text;
            ShowMessage(rsPasswordChangeSuccess);
          end;
        except
          ShowMessage(UTF8Encode(resp.AsString));
        end;
      except
        on E: Exception do
          ShowMessageFmt(rsPasswordChangeError, [UTF8Encode(E.Message)]);
      end;
    end;
  finally
    Free;
  end;
end;

procedure TVisWaptGUI.ActCleanCacheExecute(Sender: TObject);
var
  waptpackages:TStringList;
  fn:Utf8String;
begin
  waptpackages := FindAllFiles(AppLocalDir + 'cache','*.wapt',False);
  try
    for fn in waptpackages do
    try
      DeleteFileUTF8(fn);
    except
    end;
  finally
    waptpackages.Free;
  end;
end;

procedure TVisWaptGUI.ActDeleteGroupExecute(Sender: TObject);
var
  message: string = rsConfirmRmOnePackage;
  res: ISuperObject;
  group: string;
  i: integer;
  N: PVirtualNode;
begin
  if GridGroups.SelectedCount > 1 then
    message := format(rsConfirmRmMultiplePackages,[GridGroups.SelectedCount]);

  if MessageDlg(rsConfirmRmPackageCaption, message, mtConfirmation,
    mbYesNoCancel, 0) = mrYes then

    with TVisLoading.Create(Self) do
      try
        ProgressTitle(rsDeletionInProgress);
        N := GridGroups.GetFirstSelected;
        i := 0;
        while (N <> nil) and not StopRequired do
        begin
          Inc(i);
          group := GridPackages.GetCellStrValue(N, 'filename');
          ProgressTitle(format(rsDeletingElement, [group]));
          res := WAPTServerJsonGet('delete_package/%s',[group]);
          if not ObjectIsNull(res['error']) then
            raise Exception.Create(res.S['error']);
          N := GridGroups.GetNextSelected(N);
          ProgressStep(i, GridGroups.SelectedCount);
        end;
        ProgressTitle(rsUpdatingPackageList);
        ActPackagesUpdate.Execute;
        ProgressTitle(rsDisplaying);
        ActSearchGroups.Execute;
      finally
        Free;
      end;
end;

procedure TVisWaptGUI.ActDeleteGroupUpdate(Sender: TObject);
begin
  ActDeleteGroup.Enabled := GridGroups.Focused and (GridGroups.SelectedCount>0);
end;

procedure TVisWaptGUI.ActDeletePackageExecute(Sender: TObject);
var
  message: string = rsConfirmRmOnePackage;
  res: ISuperObject;
  package: string;
  i: integer;
  N: PVirtualNode;
begin
  if GridPackages.SelectedCount > 1 then
    message := Format(rsConfirmRmMultiplePackages,[GridPackages.SelectedCount]);

  if MessageDlg(rsConfirmDeletion, message, mtConfirmation,
    mbYesNoCancel, 0) = mrYes then

    with TVisLoading.Create(Self) do
      try
        ProgressTitle(rsDeletionInProgress);
        N := GridPackages.GetFirstSelected;
        i := 0;
        while (N <> nil) and not StopRequired do
        begin
          Inc(i);
          package := GridPackages.GetCellStrValue(N, 'filename');
          ProgressTitle(format(rsDeletingElement, [package]));
          res := WAPTServerJsonGet('delete_package/%s',[package]);
          if not ObjectIsNull(res['error']) then
            raise Exception.Create(res.S['error']);
          N := GridPackages.GetNextSelected(N);
          ProgressStep(i, GridPackages.SelectedCount);
        end;
        ProgressTitle(rsUpdatingPackageList);
        ActPackagesUpdate.Execute;
        ProgressTitle(rsDisplaying);
        ActSearchPackage.Execute;
      finally
        Free;
      end;
end;

procedure TVisWaptGUI.ActDeletePackageUpdate(Sender: TObject);
begin
  ActDeletePackage.Enabled := GridPackages.Focused and (GridPackages.SelectedCount > 0);
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

procedure TVisWaptGUI.ActTriggerWaptwua_downloadExecute(Sender: TObject);
begin
    with TVisHostsUpgrade.Create(Self) do
    try
      Caption:= rsTriggerWAPTWUA_Scan;
      action := 'api/v2/trigger_waptwua_download';
      hosts := Gridhosts.SelectedRows;

      if ShowModal = mrOk then
        actRefresh.Execute;
    finally
      Free;
    end;

end;

procedure TVisWaptGUI.ActTriggerWaptwua_installExecute(Sender: TObject);
begin
    with TVisHostsUpgrade.Create(Self) do
    try
      Caption:= rsTriggerWAPTWUA_Scan;
      action := 'api/v2/trigger_waptwua_install';
      hosts := Gridhosts.SelectedRows;

      if ShowModal = mrOk then
        actRefresh.Execute;
    finally
      Free;
    end;

end;

procedure TVisWaptGUI.ActTriggerWaptwua_scanExecute(Sender: TObject);
begin
  with TVisHostsUpgrade.Create(Self) do
    try
      Caption:= rsTriggerWAPTWUA_Scan;
      action := 'api/v2/trigger_waptwua_scan';
      hosts := Gridhosts.SelectedRows;

      if ShowModal = mrOk then
        actRefresh.Execute;
    finally
      Free;
    end;

end;

procedure TVisWaptGUI.ActWSUSDowloadWSUSScanExecute(Sender: TObject);
var
  res:ISuperObject;
  skipped:Boolean;
  cabsize,forced:Integer;
  cabdate:String;
begin
  forced := 0;
  if cbForcedWSUSscanDownload.Checked then
    forced:=1;
  res := WAPTServerJsonGet('api/v2/download_wsusscan?force=%d',[forced]);
  skipped := res.B['skipped'];
  if skipped then
    wsusResult.Text := 'Download skipped'
  else
  begin
    cabsize := res.I['result.file_size'];
    cabdate := DateTimeToStr(FileDateToDateTime(res.I['result.file_timestamp']));
    wsusResult.Text := res.S['result.status']+' started on '+res.S['result.run_date']+' file size:'+IntToStr(cabsize)+' wsusscan date:'+cabdate;
  end;
end;

procedure TVisWaptGUI.ActWSUSRefreshCabHistoryExecute(Sender: TObject);
var
  res:ISuperObject;
begin
  res := WAPTServerJsonGet('api/v2/wsusscan2_history?limit=20&skipped=0',[]);
  if res.B['success'] then
    GridWSUSScn.Data := res['result']
  else
    GridWSUSScn.Data := Nil;
end;

procedure TVisWaptGUI.ActWUADownloadSelectedUpdateUpdate(Sender: TObject);
begin
  //(Sender as TAction).Enabled:=GridWinUpdates.SelectedCount>0;
end;

procedure TVisWaptGUI.ActEditGroupExecute(Sender: TObject);
var
  Selpackage: string;
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
  hostname,uuid,desc: ansistring;
begin
  if GridHosts.FocusedRow<>Nil then
  begin
    hostname := GridHosts.FocusedRow.S['host.computer_fqdn'];
    uuid := GridHosts.FocusedRow.S['uuid'];
    desc := GridHosts.FocusedRow.S['host.description'];

    if EditHost(hostname, ActAdvancedMode.Checked, uuid,desc) <> nil then
      ActSearchHost.Execute;
  end;
end;

procedure TVisWaptGUI.ActEnglishExecute(Sender: TObject);
begin
  DMPython.Language:='en';
end;

procedure TVisWaptGUI.ActEnglishUpdate(Sender: TObject);
begin
  ActEnglish.Checked := DMPython.Language='en';
end;

procedure TVisWaptGUI.ActForgetPackagesExecute(Sender: TObject);
var
  uuid,sel, package, res, packages : ISuperObject;
begin
  if GridHostPackages.Focused then
  begin
    sel := GridHostPackages.SelectedRows;
    if Dialogs.MessageDlg(
       rsConfirmCaption,
       format(rsConfirmHostForgetsPackages, [IntToStr(sel.AsArray.Length), GridHosts.FocusedRow.S['host.computer_fqdn']]),
       mtConfirmation,
       mbYesNoCancel,
       0) = mrYes then
    begin
      packages := TSuperObject.Create(stArray);
      for package in sel do
        packages.AsArray.Add(package.S['package']);

      uuid := GridHosts.FocusedRow['uuid'];
      if (uuid<>Nil) and (packages.AsArray.Length>0) then
      try
          res := WAPTServerJsonGet(
            'api/v1/host_forget_packages?uuid=%s&packages=%s',
            [uuid.asString, Join(',',packages)]);
          if not res.B['success'] then
            Raise Exception.Create(res.S['msg']);
      except
        on E:Exception do
          ShowMessage(Format(rsForgetPackageError,
              [ Join(',',packages),e.Message]));
      end;
    end;
    UpdateHostPages(Sender);
  end;
end;


procedure TVisWaptGUI.ActFrenchExecute(Sender: TObject);
begin
  DMPython.Language := 'fr';
end;

procedure TVisWaptGUI.ActFrenchUpdate(Sender: TObject);
begin
  ActFrench.Checked := DMPython.Language='fr';
end;

procedure TVisWaptGUI.ActGotoHostExecute(Sender: TObject);
begin
  EdSearchHost.SetFocus;
  EdSearchHost.SelectAll;
end;

procedure TVisWaptGUI.ActHelpExecute(Sender: TObject);
begin
  OpenDocument('http://dev.tranquil.it/index.php/WAPT_-_apt-get_pour_Windows');
end;

procedure TVisWaptGUI.ActHostsActionsUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled:=GridHosts.Focused and (GridHosts.SelectedCount>0);
end;

procedure TVisWaptGUI.ActImportFromFileExecute(Sender: TObject);
var
  i: integer;
  sourceDir: string;
  uploadResult, Sources: ISuperObject;

begin
  if not FileExists(GetWaptPrivateKeyPath) then
  begin
    ShowMessageFmt(rsPrivateKeyDoesntExist, [GetWaptPrivateKeyPath]);
    exit;
  end;

  if OpenDialogWapt.Execute then
  begin
    if MessageDlg(rsConfirmImportCaption,
      format(rsConfirmImport,
      [OpenDialogWapt.Files.Text]), mtConfirmation, mbYesNoCancel, 0) <> mrYes then
      Exit;

    with  TVisLoading.Create(Self) do
      try
        Sources := TSuperObject.Create(stArray);
        for i := 0 to OpenDialogWapt.Files.Count - 1 do
        begin
          ProgressTitle(format(rsImportingFile, [OpenDialogWapt.Files[i]]));
          ProgressStep(i, OpenDialogWapt.Files.Count - 1);
          Application.ProcessMessages;
          sourceDir := DMPython.RunJSON(
            Format('waptdevutils.duplicate_from_external_repo(r"%s",(r"%s").decode("utf8"))', [AppIniFilename, OpenDialogWapt.Files[i]])).AsString;
          sources.AsArray.Add('r"' + sourceDir + '"');
        end;

        ProgressTitle(format(rsUploadingPackagesToWaptSrv, [IntToStr(Sources.AsArray.Length)]));
        Application.ProcessMessages;

        uploadResult := DMPython.RunJSON(
          format(
          'mywapt.build_upload([%s],private_key_passwd=r"%s",wapt_server_user=r"%s",wapt_server_passwd=r"%s",inc_package_release=False)',
          [soutils.Join(',', sources), privateKeyPassword, waptServerUser,
          waptServerPassword]), VisWaptGUI.jsonlog);
        if (uploadResult <> nil) and
          (uploadResult.AsArray.length = Sources.AsArray.Length) then
        begin
          ShowMessage(format(rsSuccessfullyImported,
            [soutils.Join(',', Sources)]));
          ModalResult := mrOk;
          ActPackagesUpdate.Execute;
          ActSearchPackage.Execute;
        end
        else
          ShowMessage(rsFailedImport);
      finally
        Free;
      end;
  end;
end;

procedure TVisWaptGUI.ActImportFromRepoExecute(Sender: TObject);
begin
  with TVisImportPackage.Create(Self) do
  begin
    if ShowModal = mrOk then
    begin
      ActPackagesUpdate.Execute;
      ActSearchPackage.Execute;
    end;
  end;
end;

procedure TVisWaptGUI.ActWUALoadUpdatesExecute(Sender: TObject);
var
  soresult,winupdates,winupdate,urlParams,product,products,idx,severities: ISuperObject;
  update_id:String;
begin
  {Screen.Cursor:=crHourGlass;
  if GridWinproducts.SelectedCount>0 then
  try
    urlParams := TSuperObject.Create(stArray);
    urlParams.AsArray.Add('has_kb=1');

    products := TSuperObject.Create(stArray);
    for product in GridWinproducts.SelectedRows do
      products.AsArray.Add(product.S['product']);

    if products.AsArray.Length>0 then
      urlParams.AsArray.Add(Format('products=%s',[soutils.Join(',',products)]));

    severities := TSuperObject.Create(stArray);

    if cbWUCritical.Checked then
      severities.AsArray.Add('Critical');
    if cbWUImportant.Checked then
      severities.AsArray.Add('Important');
    if cbWUModerate.Checked then
      severities.AsArray.Add('Moderate');
    if cbWULow.Checked then
      severities.AsArray.Add('Low');
    if cbWUOther.Checked then
      severities.AsArray.Add('null');
    if severities.AsArray.Length>0 then
      urlParams.AsArray.Add('severity='+Join(',',severities));

    soresult := WAPTServerJsonGet('api/v2/windows_updates?%s',[soutils.Join('&', urlParams)]);
    winupdates := soResult['result'];

    GridWinUpdates.Data := winupdates;

  finally
    Screen.Cursor:=crDefault;
  end;}
end;

procedure TVisWaptGUI.ActWUALoadUpdatesUpdate(Sender: TObject);
begin
  //ActWUALoadUpdates.Enabled:=GridWinproducts.SelectedCount>0;
end;

procedure TVisWaptGUI.ActPackageInstallExecute(Sender: TObject);
var
  uuid,sel, package, res, packages : ISuperObject;
begin
  if GridHostPackages.Focused then
  begin
    sel := GridHostPackages.SelectedRows;
    if Dialogs.MessageDlg(
       rsConfirmCaption,
       format(rsConfirmPackageInstall, [IntToStr(sel.AsArray.Length), GridHosts.FocusedRow.S['host.computer_fqdn']]),
       mtConfirmation,
       mbYesNoCancel,
       0) = mrYes then
    begin
      packages := TSuperObject.Create(stArray);
      for package in sel do
        packages.AsArray.Add(package.S['package']);

      uuid := GridHosts.FocusedRow['uuid'];
      if (uuid<>Nil) and (packages.AsArray.Length>0) then
      try
          res := WAPTServerJsonGet(
            'api/v1/host_install_packages?uuid=%s&packages=%s',
            [uuid.asString, Join(',',packages)]);
          if not res.B['success'] then
            Raise Exception.Create(res.S['msg']);
      except
        on E:Exception do
          ShowMessage(Format(rsPackageInstallError,
              [ Join(',',packages),e.Message]));
      end;
    end;
    UpdateHostPages(Sender);
  end;
end;

procedure TVisWaptGUI.ActPackageRemoveExecute(Sender: TObject);
var
  uuid,sel, package, res, packages : ISuperObject;
begin
  if GridHostPackages.Focused then
  begin
    sel := GridHostPackages.SelectedRows;
    if Dialogs.MessageDlg(
       rsConfirmCaption,
       format(rsConfirmRmPackagesFromHost, [IntToStr(sel.AsArray.Length), GridHosts.FocusedRow.S['host.computer_fqdn']]),
       mtConfirmation,
       mbYesNoCancel,
       0) = mrYes then
    begin
      packages := TSuperObject.Create(stArray);
      for package in sel do
        packages.AsArray.Add(package.S['package']);

      uuid := GridHosts.FocusedRow['uuid'];
      if (uuid<>Nil) and (packages.AsArray.Length>0) then
      try
          res := WAPTServerJsonGet(
            'api/v1/host_remove_packages?uuid=%s&packages=%s',
            [uuid.asString, Join(',',packages)]);
          if not res.B['success'] then
            Raise Exception.Create(res.S['msg']);
      except
        on E:Exception do
          ShowMessage(Format(rsPackageRemoveError,
              [ Join(',',packages),e.Message]));
      end;
    end;
    UpdateHostPages(Sender);
  end;
end;

procedure TVisWaptGUI.ActRDPExecute(Sender: TObject);
var
  ip: ansistring;
begin
  if (Gridhosts.FocusedRow <> nil) and
    (Gridhosts.FocusedRow.S['host.connected_ips'] <> '') then
  begin
    ip := GetReachableIP(Gridhosts.FocusedRow['host.connected_ips'],3389);
    if ip <> '' then
      ShellExecute(0, '', PAnsiChar('mstsc'), PAnsichar('/v:' + ip), nil, SW_SHOW)
    else
      ShowMessage(rsNoreachableIP);
  end;
end;

procedure TVisWaptGUI.ActRDPUpdate(Sender: TObject);
begin
  try
    ActRDP.Enabled := (Gridhosts.FocusedRow <> nil) and (Gridhosts.FocusedRow.S['host.connected_ips']<>'');
  except
    ActRDP.Enabled := False;
  end;

end;

procedure TVisWaptGUI.ActRefreshHostInventoryExecute(Sender: TObject);
begin
  with TVisHostsUpgrade.Create(Self) do
  try
    Caption:= rsTriggerHostsUpdate;
    action := 'api/v2/trigger_host_inventory';
    hosts := Gridhosts.SelectedRows;

    if ShowModal = mrOk then
      actRefresh.Execute;
  finally
    Free;
  end;
end;

procedure TVisWaptGUI.ActRemoveConflictsExecute(Sender: TObject);
var
  Res, packages, host, hosts: ISuperObject;
  N: PVirtualNode;
  args: ansistring;
begin
  if GridHosts.Focused then
  begin
    with TvisGroupChoice.Create(self) do
      try
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
    args := args + format('waptconfigfile = r"%s".decode(''utf8''),', [AppIniFilename]);
    args := args + format('hosts_list = r"%s".decode(''utf8''),',
      [soutils.Join(',', hosts)]);
    args := args + format('append_depends = "",', []);
    args := args + format('remove_depends = "",', []);
    args := args + format('append_conflicts = "",', []);
    args := args + format('remove_conflicts = r"%s".decode(''utf8''),',
      [soutils.Join(',', packages)]);
    if privateKeyPassword <> '' then
      args := args + format('key_password = "%s".decode(''utf8''),',
        [privateKeyPassword]);
    args := args + format('wapt_server_user = r"%s".decode(''utf8''),', [waptServerUser]);
    args := args + format('wapt_server_passwd = r"%s".decode(''utf8''),',
      [waptServerPassword]);
    res := DMPython.RunJSON(format('waptdevutils.edit_hosts_depends(%s)', [args]));
    ShowMessage(IntToStr(res.AsArray.Length) + ' postes modifiés');
  end;
end;

procedure TVisWaptGUI.ActRemoveDependsExecute(Sender: TObject);
var
  Res, packages, host, hosts: ISuperObject;
  N: PVirtualNode;
  args: ansistring;
begin
  if GridHosts.Focused then
  begin
    with TvisGroupChoice.Create(self) do
      try
        Caption := rsRmBundleFromHosts;
        ActSearchExecute(self);
        if groupGrid.Data.AsArray.Length = 0 then
        begin
          ShowMessage(rsNoBundle);
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
    args := args + format('waptconfigfile = r"%s".decode(''utf8''),', [AppIniFilename]);
    args := args + format('hosts_list = r"%s".decode(''utf8''),',
      [soutils.Join(',', hosts)]);
    args := args + format('append_depends = [],', []);
    args := args + format('remove_depends = r"%s".decode(''utf8''),',
      [soutils.Join(',', packages)]);
    if privateKeyPassword <> '' then
      args := args + format('key_password = "%s".decode(''utf8''),',
        [privateKeyPassword]);
    args := args + format('wapt_server_user = r"%s".decode(''utf8''),', [waptServerUser]);
    args := args + format('wapt_server_passwd = r"%s".decode(''utf8''),',
      [waptServerPassword]);
    res := DMPython.RunJSON(format('waptdevutils.edit_hosts_depends(%s)', [args]));
    ShowMessageFmt(rsNbModifiedHosts, [IntToStr(res.AsArray.Length)]);
  end;
end;

procedure TVisWaptGUI.ActWUANewGroupExecute(Sender: TObject);
begin
  With TVisWUAGroup.Create(Self) do
  try
    WUAGroup:='';
    if ShowModal = mrOK then
      ActWUALoadGroups.Execute;
  finally
    Free;
  end;
end;

procedure TVisWaptGUI.ActWUAProductHideExecute(Sender: TObject);
var
  wproduct:ISuperobject;
begin
  {for wproduct in GridWinproducts.SelectedRows do
    wproduct.B['favourite'] := False;
  GridWinproducts.Data := FilterWinProducts(WUAProducts);}
end;

procedure TVisWaptGUI.ActWUAProductShowExecute(Sender: TObject);
var
  wproduct:ISuperobject;
begin
  {for wproduct in GridWinproducts.SelectedRows do
    wproduct.B['favourite'] := True;
  GridWinproducts.Data := FilterWinProducts(WUAProducts);}
end;

procedure TVisWaptGUI.ActWUAProductsSelectionExecute(Sender: TObject);
begin
  With TVisWUAProducts.Create(self) do
  try
    if ShowModal = mrOk then
      ActWUALoadGroups.Execute;
  finally
    Free;
  end;
end;

procedure TVisWaptGUI.ActRestoreDefaultLayoutExecute(Sender: TObject);
begin
  Gridhosts.LoadSettingsFromIni(Appuserinipath+'.default');
  GridPackages.LoadSettingsFromIni(Appuserinipath+'.default');
  GridGroups.LoadSettingsFromIni(Appuserinipath+'.default');
  GridHostPackages.LoadSettingsFromIni(Appuserinipath+'.default');
  GridHostSoftwares.LoadSettingsFromIni(Appuserinipath+'.default');
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

procedure TVisWaptGUI.ActTriggerHostUpdateExecute(Sender: TObject);
begin
  with TVisHostsUpgrade.Create(Self) do
    try
      Caption:= rsTriggerHostsUpdate;
      action := 'api/v1/trigger_update';
      hosts := Gridhosts.SelectedRows;

      if ShowModal = mrOk then
        actRefresh.Execute;
    finally
      Free;
    end;
end;

procedure TVisWaptGUI.ActTriggerHostUpgradeExecute(Sender: TObject);
begin
  with TVisHostsUpgrade.Create(Self) do
    try
      Caption:= rsTriggerHostsUpgrade;
      action := 'api/v1/trigger_upgrade';
      hosts := Gridhosts.SelectedRows;

      if ShowModal = mrOk then
        actRefresh.Execute;
    finally
      Free;
    end;
end;

procedure TVisWaptGUI.ActTriggerHostUpgradeUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled := GridHosts.SelectedCount > 0;
end;

procedure TVisWaptGUI.ActHostWaptUpgradeExecute(Sender: TObject);
begin
  with TVisHostsUpgrade.Create(Self) do
    try
      action := 'waptupgrade_host';
      Caption := rsWaptClientUpdateOnHosts;
      hosts := Gridhosts.SelectedRows;
      if ShowModal = mrOk then
        actRefresh.Execute;
    finally
      Free;
    end;
end;

procedure TVisWaptGUI.ActEvaluateExecute(Sender: TObject);
var
  sob: ISuperObject;
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
begin
  Clipboard.AsText := GridHosts.ContentToUTF8(tstSelected, ';');
end;

function ExtractField(SOList:ISuperObject;fieldname:String):ISuperObject;
var
  item:ISuperObject;
begin
  Result := TSuperObject.Create(stArray);
  for item in SOList do
     Result.AsArray.Add(item[fieldname]);
end;

procedure TVisWaptGUI.ActHostsDeleteExecute(Sender: TObject);
var
  sel, res: ISuperObject;
  msg,uuids : String;
begin
  if GridHosts.Focused then
  begin
    sel := GridHosts.SelectedRows;

    if Sender = ActHostsDeleteHostPackage then
      msg := format(rsConfirmRmHostsPackagesFromList, [IntToStr(sel.AsArray.Length)])
    else
      msg := format(rsConfirmRmHostsFromList, [IntToStr(sel.AsArray.Length)]);


    if Dialogs.MessageDlg(rsConfirmCaption,
      msg,
      mtConfirmation,
      mbYesNoCancel,
      0) = mrYes then
    begin
      uuids := Join(',',ExtractField(sel,'uuid'));
      if Sender = ActHostsDeleteHostPackage then
        res := WAPTServerJsonGet('api/v1/hosts_delete?uuid=%s&delete_packages=1',[uuids])
      else
        res := WAPTServerJsonGet('api/v1/hosts_delete?uuid=%s',[uuids]);
      if res.B['success'] then
        ShowMessageFmt('%s',[res.S['msg']])
      else
        ShowMessageFmt('Unable to remove hosts from DB: %s',[res.S['msg']]);
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
  package: ansistring;
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
          ProgressTitle(format(rsUninstallingPackage, [package]));
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
  //ActLocalhostRemove.Enabled := GridPackages.SelectedCount > 0;
  ActLocalhostRemove.Enabled := False;
end;

procedure TVisWaptGUI.ActSearchHostExecute(Sender: TObject);
var
  soresult,columns,urlParams, Node, Hosts,fields: ISuperObject;
  previous_uuid: string;
  i: integer;
begin
  columns := TSuperObject.Create(stArray);
  for i:=0 to GridHosts.Header.Columns.Count-1 do
    if coVisible in GridHosts.Header.Columns[i].Options then
      columns.AsArray.Add(TSOGridColumn(GridHosts.Header.Columns[i]).PropertyName);

  try
    Screen.cursor := crHourGlass;

    urlParams := TSuperObject.Create(stArray);

    fields := TSuperObject.Create(stArray);
    if EdSearchHost.Text <> '' then
    begin
      if cbSearchHost.Checked = True then
      begin
        fields.AsArray.Add('host.computer_fqdn');
        fields.AsArray.Add('host.description');
        fields.AsArray.Add('host.system_manufacturer');
        fields.AsArray.Add('host.computer_name');
        fields.AsArray.Add('host.system_productname');
        fields.AsArray.Add('host.connected_ips');
        fields.AsArray.Add('host.mac');
        fields.AsArray.Add('host.current_user');
        fields.AsArray.Add('dmi.Chassis_Information.Serial_Number');
      end;

      if cbSearchDMI.Checked = True then
        fields.AsArray.Add('dmi');

      if cbSearchSoftwares.Checked = True then
      begin
        fields.AsArray.Add('softwares.name');
        fields.AsArray.Add('softwares.key');
      end;

      if cbSearchPackages.Checked = True then
      begin
        fields.AsArray.Add('packages.package');
      end;
      urlParams.AsArray.Add(format('filter=%s:%s',[join(',',fields),EdSearchHost.Text]));
    end;

    if cbHasErrors.Checked then
      urlParams.AsArray.Add('has_errors=1');

    if cbNeedUpgrade.Checked then
      urlParams.AsArray.Add('need_upgrade=1');

    if cbGroups.ItemIndex>0 then
      urlParams.AsArray.Add(Format('groups=%s',[cbGroups.Text]));

    urlParams.AsArray.Add('columns='+join(',',columns));

    if GridHosts.FocusedRow <> nil then
      previous_uuid := GridHosts.FocusedRow.S['uuid']
    else
      previous_uuid := '';

    soresult := WAPTServerJsonGet('api/v1/hosts?%s',[soutils.Join('&', urlParams)]);
    if soresult.B['success'] then
    begin
      hosts := soresult['result'];
      GridHosts.Data := hosts;
      if (hosts <> nil) and (hosts.AsArray <> nil) then
      begin
        LabelComputersNumber.Caption := IntToStr(hosts.AsArray.Length);
        for node in GridHosts.Data do
        begin
          if node.S['uuid'] = previous_uuid then
          begin
            GridHosts.FocusedRow := node;
            Break;
          end;
        end;
      end;
    end
    else
    begin
      GridHosts.Data := Nil;
      ShowMessageFmt('Unable to get hosts list : %s',[soresult.S['msg']]);
    end;
  finally
    Screen.Cursor:=crDefault;
  end;
end;

procedure TVisWaptGUI.ActSearchPackageExecute(Sender: TObject);
var
  expr: UTF8String;
  packages: ISuperObject;
begin
  //packages := VarPythonEval(Format('"%s".split()',[EdSearch.Text]));
  //packages := MainModule.mywapt.search(VarPythonEval(Format('"%s".split()',[EdSearch.Text])));
  expr := format('mywapt.search(r"%s".decode(''utf8'').split(),section_filter="base")',
    [EdSearch.Text]);
  packages := DMPython.RunJSON(expr);

  GridPackages.Data := packages;
end;

procedure TVisWaptGUI.ActPackagesUpdateExecute(Sender: TObject);
var
  res: variant;
begin
  //test avec un variant ;)
  res := MainModule.mywapt.update(Register := False);

  ActSearchPackage.Execute;
  ActSearchGroups.Execute;

  //update groups filter combobox
  if cbGroups.ItemIndex>=0 then
    FillcbGroups;
end;

procedure TVisWaptGUI.ActReloadConfigExecute(Sender: TObject);
begin
  dmpython.WaptConfigFileName:='';
  CacheWaptServerUrl := 'None';
  waptcommon.ReadWaptConfig(AppIniFilename);
  dmpython.WaptConfigFileName:=AppIniFilename;
end;

procedure TVisWaptGUI.ActTriggerHostsListeningExecute(Sender: TObject);
var
  res:ISuperObject;
begin
  try
    res := WAPTServerJsonGet('api/v1/trigger_reachable_discovery',[]);
    if res.B['success'] then
      ShowMessageFmt('%s',[res.S['msg']])
    else
      ShowMessageFmt('Unable to trigger discovery of listening IP on wapt server: %s',[res.S['msg']]);
  except
    on E:Exception do
      ShowMessageFmt('Unable to trigger discovery of listening IP on wapt server: %s',[UTF8Encode(E.Message)]);
  end;

end;

procedure TVisWaptGUI.ActVNCExecute(Sender: TObject);
var
  ip: ansistring;
begin
  if (Gridhosts.FocusedRow <> nil) and
    (Gridhosts.FocusedRow.S['host.connected_ips'] <> '') then
  begin
    ip := GetReachableIP(Gridhosts.FocusedRow['host.connected_ips'],5900);
    if ip<>'' then
      ShellExecute(0, '', PAnsiChar('C:\Program Files\TightVNC\tvnviewer.exe'),
        PAnsichar(ip), nil, SW_SHOW)
    else
      ShowMessage(rsNoReachableIP);
  end;
end;

procedure TVisWaptGUI.ActVNCUpdate(Sender: TObject);
begin
  try
    ActVNC.Enabled := (Gridhosts.FocusedRow <> nil) and
      (Gridhosts.FocusedRow.S['host.connected_ips'] <> '') and
      FileExists('C:\Program Files\TightVNC\tvnviewer.exe');
  except
    ActVNC.Enabled := False;
  end;
end;

procedure TVisWaptGUI.ActWAPTLocalConfigExecute(Sender: TObject);
begin
  if EditIniFile then
  begin
    ActReloadConfig.Execute;
    ActPackagesUpdate.Execute;
    GridPackages.Clear;
    GridGroups.Clear;
    GridHosts.Clear;
    GridhostInventory.Clear;
    GridHostPackages.Clear;
    GridHostSoftwares.Clear;
    DMPython.WAPT.update(register:=False);
    // put somewhere else
    MainPagesChange(MainPages);
  end;
end;

procedure TVisWaptGUI.cbGroupsDropDown(Sender: TObject);
begin
  if cbGroups.ItemIndex<0 then
    FillCBGroups;
end;

procedure TVisWaptGUI.cbGroupsSelect(Sender: TObject);
begin
  ActSearchHost.Execute;
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
        cbUseProxyForTemplate.Checked :=
          inifile.ReadBool('global', 'use_http_proxy_for_templates', edhttp_proxy.Text <> '');
        cbUseProxyForServer.Checked :=
          inifile.ReadBool('global', 'use_http_proxy_for_server', edhttp_proxy.Text <> '');
        cbUseProxyForRepo.Checked :=
          inifile.ReadBool('global', 'use_http_proxy_for_repo', edhttp_proxy.Text <> '');
        cbSendStats.Checked :=
          inifile.ReadBool('global', 'send_usage_report', True);
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
          inifile.WriteBool('global', 'use_http_proxy_for_templates',
            cbUseProxyForTemplate.Checked);
          inifile.WriteBool('global', 'use_http_proxy_for_server',
            cbUseProxyForServer.Checked);
          inifile.WriteBool('global', 'use_http_proxy_for_repo',
            cbUseProxyForRepo.Checked);
          inifile.WriteBool('global', 'send_usage_report',
            cbSendStats.Checked);
          inifile.WriteString('global', 'default_sources_root',
            eddefault_sources_root.Text);
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

procedure TVisWaptGUI.cbMaskSystemComponentsClick(Sender: TObject);
begin
  GridHostSoftwares.Data := FilterSoftwares(Gridhosts.FocusedRow['softwares']);
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
  DMPython.PythonOutput.OnSendData := @PythonOutputSendData;
end;

function TVisWaptGUI.Login: boolean;
var
  cred, resp, sores: ISuperObject;
  localfn: string;
begin
  Result := False;
  // Initialize user local config file with global wapt settings
  localfn := GetAppConfigDir(False) + ApplicationName + '.ini';
  if not FileExists(localfn) then
  begin
    if not DirectoryExists(GetAppConfigDir(False)) then
      MkDir(GetAppConfigDir(False));
    FileUtil.CopyFile(WaptIniFilename, localfn, True);
  end;

  ActReloadConfig.Execute;

  while (GetWaptServerURL = '') do
  begin
    if EditIniFile then
      ActReloadConfig.Execute
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
          try
              sores := WAPTServerJsonGet('ping', []);
              try
                if sores.B['success'] and (CompareVersion(sores['result'].S['version'],WAPTServerMinVersion)<0) then
                  ShowMessageFmt(rsWaptServerOldVersion,[sores['result'].S['version'],WAPTServerMinVersion]);
              except
                  on E:Exception do
                    ShowMessageFmt(rsWaptServerOldVersion,[rsUnknownVersion,WAPTServerMinVersion]);
              end;
          except
            on E:Exception do
              ShowMessageFmt(rsWaptServerError,[e.Message]);
          end;
          waptServerPassword := edPassword.Text;
          waptServerUser := edUser.Text;
          cred := SO();
          cred.S['username'] := waptServerUser;
          cred.S['password'] := UTF8Decode(WaptServerPassword);

          try
            resp := WAPTServerJsonPost('login', [], cred);
            try
              Result := StrToBool(resp.AsString);
              if not Result then
                ShowMessage(rsIncorrectPassword);
            except
              ShowMessage(UTF8Encode(resp.AsString));
              Result := False;
            end;
          except
            on E: Exception do
            begin
              ShowMessageFmt(rsPasswordChangeError, [UTF8Encode(E.Message)]);
              Result := False;
            end;
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
  ActPackagesUpdate.Execute;

  MainPages.ActivePage := pgInventory;
  MainPagesChange(Sender);

  HostPages.ActivePage := pgPackages;

  // saves default initial config...
  Gridhosts.SaveSettingsToIni(Appuserinipath+'.default');
  GridPackages.SaveSettingsToIni(Appuserinipath+'.default');
  GridGroups.SaveSettingsToIni(Appuserinipath+'.default');
  GridHostPackages.SaveSettingsToIni(Appuserinipath+'.default');
  GridHostSoftwares.SaveSettingsToIni(Appuserinipath+'.default');


  Gridhosts.LoadSettingsFromIni(Appuserinipath);
  GridPackages.LoadSettingsFromIni(Appuserinipath);
  GridGroups.LoadSettingsFromIni(Appuserinipath);
  GridHostPackages.LoadSettingsFromIni(Appuserinipath);
  GridHostSoftwares.LoadSettingsFromIni(Appuserinipath);

  plStatusBar1.Panels[0].Text :=ApplicationName+' '+GetApplicationVersion;
end;

procedure TVisWaptGUI.GridGroupsColumnDblClick(Sender: TBaseVirtualTree;
  Column: TColumnIndex; Shift: TShiftState);
begin
  ActEditGroup.Execute;
end;

procedure TVisWaptGUI.GridGroupsGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; RowData, CellData: ISuperObject; Column: TColumnIndex;
  TextType: TVSTTextType; var CellText: string);
begin
  if ((Sender as TSOGrid).Header.Columns[Column] as TSOGridColumn).PropertyName =
    'depends' then
    StrReplace(CellText, ',', #13#10, [rfReplaceAll]);
end;

procedure TVisWaptGUI.GridGroupsInitNode(Sender: TBaseVirtualTree;
  ParentNode, Node: PVirtualNode; var InitialStates: TVirtualNodeInitStates);
begin
  InitialStates := InitialStates + [ivsMultiline];
end;

procedure TVisWaptGUI.GridGroupsMeasureItem(Sender: TBaseVirtualTree;
  TargetCanvas: TCanvas; Node: PVirtualNode; var NodeHeight: integer);
var
  i, maxheight, cellheight: integer;
begin
  maxheight := (Sender as TSOGrid).DefaultNodeHeight;
  if Sender.MultiLine[Node] then
  begin
    for i := 0 to (Sender as TSOGrid).Header.Columns.Count - 1 do
    begin
      if (coVisible in (Sender as TSOGrid).Header.Columns[i].Options) then
      begin
        CellHeight := (Sender as TSOGrid).ComputeNodeHeight(TargetCanvas, Node, i);
        if cellheight > maxheight then
          maxheight := cellheight;
      end;
    end;
  end;
  NodeHeight := maxheight;
end;

procedure TVisWaptGUI.GridHostPackagesChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  if (GridHostPackages.FocusedRow <> nil) then
  begin
    MemoInstallOutput.Text := GridHostPackages.FocusedRow.S['install_output'];
    MemoInstallOutput.CaretPos := Point(1, 65535);
    MemoInstallOutput.SelStart := 65535;
    MemoInstallOutput.SelLength := 0;
    MemoInstallOutput.ScrollBy(0, 65535);
  end
  else
    MemoInstallOutput.Clear;
end;

procedure TVisWaptGUI.GridHostPackagesGetImageIndexEx(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
  var Ghosted: boolean; var ImageIndex: integer; var ImageList: TCustomImageList);
var
  install_status: ISuperObject;
begin
  if Column = 0 then
  begin
    install_status := GridHostPackages.GetCellData(Node, 'install_status', nil);
    if (install_status <> nil) then
    begin
      case install_status.AsString of
        'OK': ImageIndex := 0;
        'ERROR': ImageIndex := 2;
        'NEED-UPGRADE': ImageIndex := 1;
        'MISSING': ImageIndex := 7;
      end;
    end;
  end;
end;

procedure TVisWaptGUI.GridHostsChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
begin
  UpdateHostPages(Sender);
  labSelected.Caption := IntToStr(GridHosts.SelectedCount);
end;

procedure TVisWaptGUI.GridHostsColumnDblClick(Sender: TBaseVirtualTree;
  Column: TColumnIndex; Shift: TShiftState);
begin
  ActEditHostPackage.Execute;
end;

procedure TVisWaptGUI.GridHostsCompareNodes(Sender: TBaseVirtualTree;
  Node1, Node2: PVirtualNode; Column: TColumnIndex; var Result: integer);
var
  n1, n2, d1, d2: ISuperObject;
  propname: string;
  compresult: TSuperCompareResult;
begin
  Result := 0;
  n1 := GridHosts.GetNodeSOData(Node1);
  n2 := GridHosts.GetNodeSOData(Node2);

  if (Column >= 0) and (n1 <> nil) and (n2 <> nil) then
  begin
    propname := TSOGridColumn(GridHosts.Header.Columns[column]).PropertyName;
    d1 := n1[propname];
    d2 := n2[propname];
    if d1 = nil then
      d1 := SO('""');
    if d2 = nil then
      d2 := SO('""');
    if (d1 <> nil) and (d2 <> nil) then
    begin
      if (pos('version', propname) > 0) then
        Result := CompareVersion(d1.AsString, d2.AsString)
      else if (pos('connected_ips', propname) > 0) then
          Result := CompareVersion(Join('-',d1),Join('-',d2))
      else
      if (pos('host.mac', propname) > 0) then
        Result := CompareStr(d1.AsString, d2.AsString)
      else
      begin
        CompResult := d1.Compare(d2);
        case compresult of
          cpLess: Result := -1;
          cpEqu: Result := 0;
          cpGreat: Result := 1;
          cpError: Result := strcompare(n1.S[propname], n2.S[propname]);
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
  propname: string;
  col: TSOGridColumn;
begin
  if (Source = GridhostInventory) then
  begin
    // drop d'un nouvel attribut
    propname := GridhostInventory.Path(GridhostInventory.FocusedNode, 0, ttNormal, '.');
    propname := copy(propname, 1, length(propname) - 1);
    col := Gridhosts.FindColumnByPropertyName(propname);
    if col = nil then
    begin
      col := Gridhosts.Header.Columns.Add as TSOGridColumn;
      col.Text := propname;
      col.PropertyName := propname;
      col.Width := 100;
    end;
  end;
end;

procedure TVisWaptGUI.GridHostsDragOver(Sender: TBaseVirtualTree;
  Source: TObject; Shift: TShiftState; State: TDragState; const Pt: TPoint;
  Mode: TDropMode; var Effect: DWORD; var Accept: boolean);
var
  propname: string;
begin
  // dragDrop d'un attribut pour enrichir la grille des hosts
  if (Source = GridhostInventory) then
  begin
    propname := GridhostInventory.Path(GridhostInventory.FocusedNode, 0, ttNormal, '.');
    propname := copy(propname, 1, length(propname) - 1);

    Accept := (GridHosts.FindColumnByPropertyName(propname) = nil);
  end;
end;

procedure TVisWaptGUI.GridHostsEditing(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; var Allowed: boolean);
begin
  Allowed := False;
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
  RowSO, status,
  reachable,timestamp: ISuperObject;
begin
  if TSOGridColumn(GridHosts.Header.Columns[Column]).PropertyName = 'host_status' then
  begin
    RowSO := GridHosts.GetNodeSOData(Node);
    if RowSO <> nil then
    begin
      status := RowSO['host_status'];
      if (status <> nil) then
      begin
        ImageList := ImageList1;
        if status.AsString = 'ERROR' then
          ImageIndex := 2
        else if status.AsString = 'TO-UPGRADE' then
          ImageIndex := 1
        else
          ImageIndex := 0;
      end;
    end;
  end
  else if TSOGridColumn(GridHosts.Header.Columns[Column]).PropertyName = 'reachable' then
  begin
    ImageIndex:=-1;
    reachable := GridHostPackages.GetCellData(Node, 'wapt.listening_address.address', Nil);
    timestamp := GridHostPackages.GetCellData(Node, 'wapt.listening_address.timestamp', Nil);
    if (reachable<>Nil) and (timestamp<>Nil) then
    begin
      if (reachable.AsString <> '') and (timestamp.AsString <> '') then
        ImageIndex := 4
      else if (reachable.AsString = '') and (timestamp.AsString <> '') then
        ImageIndex := 5
      else if (timestamp.AsString = '') then
        ImageIndex := 6
    end
  end;
end;

procedure TVisWaptGUI.GridHostsGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; RowData, CellData: ISuperObject; Column: TColumnIndex;
  TextType: TVSTTextType; var CellText: string);

begin
  if Node = nil then
    CellText := ''
  else
  begin
    if (CellData <> nil) and (CellData.DataType = stArray) then
      CellText := soutils.Join(',', CellData);

    if (TSOGridColumn(GridHosts.Header.Columns[Column]).PropertyName='last_query_date') or (TSOGridColumn(GridHosts.Header.Columns[Column]).PropertyName='wapt.listening_address.timestamp') then
        CellText := Copy(StrReplaceChar(CellText,'T',' '),1,19);
  end;
end;

procedure TVisWaptGUI.GridHostsHeaderDblClick(Sender: TVTHeader;
  HitInfo: TVTHeaderHitInfo);
begin
  exit;
end;

procedure TVisWaptGUI.GridHostTasksPendingChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  if (Sender as TSOGrid).FocusedRow <> nil then
  begin
    MemoTaskLog.Text := (Sender as TSOGrid).FocusedRow.S['logs'];
    MemoTaskLog.SelStart := 65535;
    MemoTaskLog.ScrollBy(0, 65535);
  end
  else
    MemoTaskLog.Clear;
end;

procedure TVisWaptGUI.GridHostWinUpdatesGetImageIndexEx(
  Sender: TBaseVirtualTree; Node: PVirtualNode; Kind: TVTImageKind;
  Column: TColumnIndex; var Ghosted: Boolean; var ImageIndex: Integer;
  var ImageList: TCustomImageList);
var
  row: ISuperObject;
begin
  if Column = 0 then
  begin
    row := GridHostPackages.GetNodeSOData(Node);
    if row.B['installed'] then
      ImageIndex := 0
    else
    if not row.B['installed'] and not row.B['hidden'] then
      ImageIndex := 7
    else
      ImageIndex := 8
  end;
end;

procedure TVisWaptGUI.GridHostWinUpdatesGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; RowData, CellData: ISuperObject; Column: TColumnIndex;
  TextType: TVSTTextType; var CellText: string);
begin
  if Node = nil then
    CellText := ''
  else
  begin
    if (TSOGridColumn(TSOGrid(Sender).Header.Columns[Column]).PropertyName='changetime') then
        CellText := Copy(StrReplaceChar(CellText,'T',' '),1,19);

    if (TSOGridColumn(TSOGrid(Sender).Header.Columns[Column]).PropertyName='kbids') then
      CellText := 'KB'+soutils.Join(',KB', CellData);

    {if (CellData <> nil) and (CellData.DataType = stArray) then
      CellText := soutils.Join(',', CellData);}

  end;

end;

procedure TVisWaptGUI.GridPackagesChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
begin
  MemoGroupeDescription.Lines.Text := GridPackages.GetCellStrValue(Node, 'description');
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

procedure TVisWaptGUI.GridWinproductsChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  {GridWinUpdates.Data := Nil;
  TimerWUALoadWinUpdates.Enabled:=False;
  TimerWUALoadWinUpdates.Enabled:=True;}
end;

procedure TVisWaptGUI.GridWinUpdatesGetImageIndexEx(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
  var Ghosted: Boolean; var ImageIndex: Integer; var ImageList: TCustomImageList
  );
var
  row: ISuperObject;
begin
  if Column = 0 then
  begin
    row := (Sender as TSOGrid).GetNodeSOData(Node);
    case row.S['status'] of
      'ALLOWED': ImageIndex := 0;
      'FORBIDDEN': ImageIndex := 8;
    else
      ImageIndex := -1;
    end;
  end;
end;

procedure TVisWaptGUI.HostPagesChange(Sender: TObject);
begin
  UpdateHostPages(Sender);
end;

procedure TVisWaptGUI.Image1Click(Sender: TObject);
begin
  OpenDocument('http://www.tranquil.it');
end;

procedure CopyMenu(menuItemSource: TPopupMenu; menuItemTarget: TMenuItem);
var
  i: integer;
  mi: TMenuItem;
begin
  menuItemTarget.Clear;
  for i := 0 to menuItemSource.Items.Count - 1 do
  begin
    if menuItemSource.Items[i].Action <> Nil then
    begin
      mi := TMenuItem.Create(menuItemTarget);
      mi.Action := menuItemSource.Items[i].Action;
      menuItemTarget.Add(mi);
    end;
  end;
end;

procedure TVisWaptGUI.FillcbGroups;
var
  Group,Groups:ISuperObject;
  oldSelect:String;
begin
  try
    Screen.Cursor:=crHourGlass;

    oldSelect:=cbGroups.Text;
    cbGroups.Items.Clear;
    cbGroups.Items.Add(rsFilterAll);

    Groups := WAPTServerJsonGet('api/v1/groups',[])['result'];
    if Groups<>Nil then
    begin
      SortByFields(Groups,['package']);
      for Group in Groups do
        cbGroups.Items.Add(group.S['package']);
    end;
    cbGroups.Text := oldSelect;

  finally
    Screen.Cursor:=crdefault;
  end;
end;

procedure TVisWaptGUI.MainPagesChange(Sender: TObject);
var
  wsus_restrictions,wsus_rules:ISuperObject;
begin
  if MainPages.ActivePage = pgInventory then
  try
    Screen.Cursor:=crHourGlass;

    CopyMenu(PopupMenuHosts, MenuItem24);
    if GridHosts.Data = nil then
      ActSearchHost.Execute;

  finally
    Screen.Cursor:=crDefault;
  end
  else if MainPages.ActivePage = pgPrivateRepo then
  begin
    CopyMenu(PopupMenuPackages, MenuItem24);
    if GridPackages.Data = nil then
      ActSearchPackage.Execute;
  end
  else if MainPages.ActivePage = pgGroups then
  begin
    CopyMenu(PopupMenuGroups, MenuItem24);
    if GridGroups.Data = nil then
      ActSearchGroups.Execute;
  end
  {else if MainPages.ActivePage = pgWUAProducts then
  begin
    WUAProducts := WAPTServerJsonGet('api/v2/windows_products',[])['result'];
    GridWinproducts.Data := FilterWinproducts(WUAProducts);
    ActWUALoadUpdates.Execute;
  end}
{  else if MainPages.ActivePage = pgWUABundles then
  begin
      wsus_rules := WAPTServerJsonGet('api/v2/windows_updates_rules',[])['result'];
      GridWUAGroups.data := wsus_rules;
  end}

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
