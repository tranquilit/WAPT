unit uwaptconsole;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Windows, ActiveX, Types, Forms, Controls, Graphics,
  Dialogs, Buttons, FileUtil, LazFileUtils, LazUTF8, SynEdit,
  SynHighlighterPython, LSControls, TplStatusBarUnit, vte_json, ExtCtrls,
  StdCtrls, ComCtrls, ActnList, Menus, jsonparser, superobject, VirtualTrees,
  VarPyth, ImgList, SOGrid, uvisloading, IdComponent, DefaultTranslator,
  IniPropStorage, GetText, uWaptConsoleRes, SearchEdit, MenuButton;

type

  { TVisWaptGUI }

  TVisWaptGUI = class(TForm)
    ActCancelRunningTask: TAction;
    ActDisplayPreferences: TAction;
    ActExternalRepositoriesSettings: TAction;
    ActAddHWPropertyToGrid: TAction;
    ActDisplayUserMessage: TAction;
    ActLaunchGPUpdate: TAction;
    ActLaunchWaptExit: TAction;
    ActTriggerBurstUpgrades: TAction;
    ActPackagesForceInstall: TAction;
    ActProprietary: TAction;
    ActPackagesForget: TAction;
    ActAddConflicts: TAction;
    ActHelp: TAction;
    ActImportFromRepo: TAction;
    ActImportFromFile: TAction;
    ActCreateWaptSetup: TAction;
    ActFrench: TAction;
    ActEnglish: TAction;
    ActCleanCache: TAction;
    ActAddADSGroups: TAction;
    ActGerman: TAction;
    ActComputerMgmt: TAction;
    ActComputerUsers: TAction;
    ActComputerServices: TAction;
    ActChangePrivateKeypassword: TAction;
    ActTISHelp: TAction;
    ActRevokeCert: TAction;
    ActmakePackageTemplate: TAction;
    ActRemoteAssist: TAction;
    ActTriggerWakeOnLan: TAction;
    ActWSUSSaveBuildRules: TAction;
    ActWUAAddForbiddenUpdate: TAction;
    ActWUAAddAllowedUpdate: TAction;
    ActWUAAddAllowedClassification: TAction;
    ActWSUSDowloadWSUSScan: TAction;
    ActTriggerWaptwua_install: TAction;
    ActTriggerWaptwua_download: TAction;
    ActTriggerWaptwua_scan: TAction;
    ActWSUSRefreshCabHistory: TAction;
    ApplicationProperties1: TApplicationProperties;
    BitBtn1: TBitBtn;
    BitBtn10: TBitBtn;
    BitBtn11: TBitBtn;
    BitBtn13: TBitBtn;
    BitBtn15: TBitBtn;
    BitBtn2: TBitBtn;
    BitBtn9: TBitBtn;
    btAddGroup: TBitBtn;
    ButHostSearch: TBitBtn;
    ButHostSearch1: TBitBtn;
    ButPackagesUpdate: TBitBtn;
    ButPackagesUpdate1: TBitBtn;
    butSearchGroups: TBitBtn;
    Button1: TButton;
    cbAdvancedSearch: TCheckBox;
    cbForcedWSUSscanDownload: TCheckBox;
    cbGroups: TComboBox;
    cbHasErrors: TCheckBox;
    CBInverseSelect: TCheckBox;
    cbMaskSystemComponents: TCheckBox;
    cbNeedUpgrade: TCheckBox;
    cbReachable: TCheckBox;
    cbSearchAll: TCheckBox;
    cbSearchDMI: TCheckBox;
    cbSearchHost: TCheckBox;
    cbSearchPackages: TCheckBox;
    cbSearchSoftwares: TCheckBox;
    cbADSite: TComboBox;
    cbADOU: TComboBox;
    cbNewestOnly: TCheckBox;
    EdDescription: TEdit;
    EdHardwareFilter: TEdit;
    EdHostname: TEdit;
    EdUUID: TEdit;
    EdIPAddress: TEdit;
    EdManufacturer: TEdit;
    EdModelName: TEdit;
    EdOS: TEdit;
    EdRunningStatus: TEdit;
    EdSearchGroups: TSearchEdit;
    EdSearchHost: TSearchEdit;
    EdSoftwaresFilter: TEdit;
    EdUpdateDate: TEdit;
    EdUser: TEdit;
    GridhostInventory: TVirtualJSONInspector;
    GridHosts: TSOGrid;
    GridWSUSAllowedWindowsUpdates: TSOGrid;
    GridWSUSScan: TSOGrid;
    GridWSUSAllowedClassifications: TSOGrid;
    GridWSUSForbiddenWindowsUpdates: TSOGrid;
    ActionsImages24: TImageList;
    Image1: TImage;
    Image2: TImage;
    Image3: TImage;
    Image4: TImage;
    Label1: TLabel;
    Label10: TLabel;
    Label11: TLabel;
    Label12: TLabel;
    Label15: TLabel;
    Label16: TLabel;
    Label17: TLabel;
    Label18: TLabel;
    Label19: TLabel;
    Label2: TLabel;
    Label20: TLabel;
    Label21: TLabel;
    Label23: TLabel;
    Label3: TLabel;
    Label5: TLabel;
    LabUser: TLabel;
    Label6: TLabel;
    Label7: TLabel;
    Label8: TLabel;
    Label9: TLabel;
    LabelComputersNumber: TLabel;
    LabErrorRegHardware: TLabel;
    MenuItem1: TMenuItem;
    MenuItem17: TMenuItem;
    MenuExternalTools: TMenuItem;
    MenuItem2: TMenuItem;
    MenuItem23: TMenuItem;
    MenuItem31: TMenuItem;
    MenuItem33: TMenuItem;
    MenuItem50: TMenuItem;
    MenuItem51: TMenuItem;
    MenuItem53: TMenuItem;
    MenuItem57: TMenuItem;
    MenuItem74: TMenuItem;
    MenuItem75: TMenuItem;
    MenuItem76: TMenuItem;
    MenuItem77: TMenuItem;
    MenuItem78: TMenuItem;
    MenuItem79: TMenuItem;
    MenuItem80: TMenuItem;
    MenuItem81: TMenuItem;
    MenuItem82: TMenuItem;
    MenuItem83: TMenuItem;
    MenuItem84: TMenuItem;
    MenuItem85: TMenuItem;
    MenuItem86: TMenuItem;
    MenuItem87: TMenuItem;
    odSelectInstaller: TOpenDialog;
    PanTopHosts: TPanel;
    panFilterStatus: TPanel;
    PanHostsFilters: TPanel;
    Panel14: TPanel;
    Panel15: TPanel;
    Panel16: TPanel;
    PanFilterGroups: TPanel;
    PanHostsSubFilters: TPanel;
    PanLeft: TPanel;
    PanSearch: TPanel;
    PanSearchIn: TPanel;
    PopupGridWSUSScan: TPopupMenu;
    MenuItem70: TMenuItem;
    MenuItem71: TMenuItem;
    MenuItem72: TMenuItem;
    MenuItem73: TMenuItem;
    pgWindowsUpdates: TTabSheet;
    PopupDelete: TPopupMenu;
    ProgressBar1: TProgressBar;
    Splitter6: TSplitter;
    TimerWUALoadWinUpdates: TTimer;
    ToolBar1: TToolBar;
    ToolButtonUpgrade: TToolButton;
    ToolButton2: TToolButton;
    ToolButtonRefresh: TToolButton;
    ToolButtonUpdate: TToolButton;
    ToolButton6: TToolButton;
    ToolButtonSep1: TToolButton;
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
    ActPackagesInstall: TAction;
    ActRestoreDefaultLayout: TAction;
    ActTriggerHostUpdate: TAction;
    ActRemoveConflicts: TAction;
    ActSearchSoftwares: TAction;
    ActRemoveDepends: TAction;
    ActRDP: TAction;
    ActVNC: TAction;
    ActPackagesRemove: TAction;
    ActEditpackage: TAction;
    ActExecCode: TAction;
    ActEvaluate: TAction;
    ActCreateCertificate: TAction;
    ActEvaluateVar: TAction;
    ActEditHostPackage: TAction;
    ActHostSearchPackage: TAction;
    ActHostsAddPackages: TAction;
    ActDeleteHostsPackageAndInventory: TAction;
    ActDeletePackage: TAction;
    ActChangePassword: TAction;
    ActGotoHost: TAction;
    ActTriggerHostUpgrade: TAction;
    ActAddDepends: TAction;
    ActEditGroup: TAction;
    ActDeleteGroup: TAction;
    ActSearchGroups: TAction;
    ActWAPTConsoleConfig: TAction;
    ActReloadConfig: TAction;
    actRefresh: TAction;
    actQuit: TAction;
    ActAddGroup: TAction;
    ActSearchHost: TAction;
    ActPackagesUpdate: TAction;
    ActSearchPackage: TAction;
    ActionList1: TActionList;
    butInitWapt: TBitBtn;
    butRun: TBitBtn;
    butSearchPackages: TBitBtn;
    ButCancelHostTask: TBitBtn;
    cbShowHostPackagesSoft: TCheckBox;
    cbShowHostPackagesGroup: TCheckBox;
    cbShowLog: TCheckBox;
    cbWUACriticalOnly: TCheckBox;
    cbWUAInstalled: TCheckBox;
    cbWUAPending: TCheckBox;
    cbWUADiscarded: TCheckBox;
    GridGroups: TSOGrid;
    GridHostWinUpdates: TSOGrid;
    GridHostTasksPending: TSOGrid;
    GridHostTasksDone: TSOGrid;
    GridHostTasksErrors: TSOGrid;
    HostRunningTaskLog: TMemo;
    HostRunningTask: TLabeledEdit;
    Label14: TLabel;
    MemoTaskLog: TMemo;
    MemoInstallOutput: TMemo;
    MenuItem19: TMenuItem;
    MenuItem20: TMenuItem;
    MenuItem25: TMenuItem;
    MenuItem28: TMenuItem;
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
    MenuItem52: TMenuItem;
    MenuItem54: TMenuItem;
    MenuItem55: TMenuItem;
    MenuItem56: TMenuItem;
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
    Panel3: TPanel;
    Panel5: TPanel;
    Panel6: TPanel;
    plStatusBar1: TplStatusBar;
    PopupHostPackages: TPopupMenu;
    PopupWUAUpdates: TPopupMenu;
    PopupMenuGroups: TPopupMenu;
    ProgressBar: TProgressBar;
    EdRun: TEdit;
    EdSearchPackage: TSearchEdit;
    ImageList1: TImageList;
    pgGroups: TTabSheet;
    HostTaskRunningProgress: TProgressBar;
    Splitter3: TSplitter;
    pgTasks: TTabSheet;
    Splitter5: TSplitter;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    TabSheet3: TTabSheet;
    pgHostWUA: TTabSheet;
    TimerTasks: TTimer;
    MainMenu1: TMainMenu;
    MemoLog: TMemo;
    MenuItem10: TMenuItem;
    MenuItem11: TMenuItem;
    MenuItem12: TMenuItem;
    MenuItem13: TMenuItem;
    MenuItem14: TMenuItem;
    MenuItem15: TMenuItem;
    MenuItem16: TMenuItem;
    MenuItem18: TMenuItem;
    MenuItem21: TMenuItem;
    MenuItem22: TMenuItem;
    MenuItem24: TMenuItem;
    MenuItem26: TMenuItem;
    MenuItem27: TMenuItem;
    MenuItem29: TMenuItem;
    MenuItem3: TMenuItem;
    MenuItem30: TMenuItem;
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
    PanDebug: TPanel;
    Panel4: TPanel;
    Panel7: TPanel;
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
    procedure ActAddADSGroupsExecute(Sender: TObject);
    procedure ActAddConflictsExecute(Sender: TObject);
    procedure ActAddDependsExecute(Sender: TObject);
    procedure ActAddDependsUpdate(Sender: TObject);
    procedure ActAddHWPropertyToGridExecute(Sender: TObject);
    procedure ActAddHWPropertyToGridUpdate(Sender: TObject);
    procedure ActCancelRunningTaskExecute(Sender: TObject);
    procedure ActChangePasswordExecute(Sender: TObject);
    procedure ActChangePasswordUpdate(Sender: TObject);
    procedure ActChangePrivateKeypasswordExecute(Sender: TObject);
    procedure ActChangePrivateKeypasswordUpdate(Sender: TObject);
    procedure ActCleanCacheExecute(Sender: TObject);
    procedure ActComputerMgmtExecute(Sender: TObject);
    procedure ActComputerMgmtUpdate(Sender: TObject);
    procedure ActComputerServicesExecute(Sender: TObject);
    procedure ActComputerServicesUpdate(Sender: TObject);
    procedure ActComputerUsersExecute(Sender: TObject);
    procedure ActComputerUsersUpdate(Sender: TObject);
    procedure ActCreateCertificateExecute(Sender: TObject);
    procedure ActCreateCertificateUpdate(Sender: TObject);
    procedure ActCreateWaptSetupExecute(Sender: TObject);
    procedure ActCreateWaptSetupUpdate(Sender: TObject);
    procedure ActDeleteGroupExecute(Sender: TObject);
    procedure ActDeleteGroupUpdate(Sender: TObject);
    procedure ActDeletePackageExecute(Sender: TObject);
    procedure ActDeletePackageUpdate(Sender: TObject);
    procedure ActDisplayPreferencesExecute(Sender: TObject);
    procedure ActDisplayUserMessageExecute(Sender: TObject);
    procedure ActEditGroupUpdate(Sender: TObject);
    procedure ActEditHostPackageUpdate(Sender: TObject);
    procedure ActForgetPackagesUpdate(Sender: TObject);
    procedure ActGermanExecute(Sender: TObject);
    procedure ActGermanUpdate(Sender: TObject);
    procedure ActHostsDeletePackageUpdate(Sender: TObject);
    procedure ActHostsDeleteUpdate(Sender: TObject);
    procedure ActLaunchGPUpdateExecute(Sender: TObject);
    procedure ActLaunchWaptExitExecute(Sender: TObject);
    procedure ActmakePackageTemplateExecute(Sender: TObject);
    procedure ActPackagesForceInstallExecute(Sender: TObject);
    procedure ActPackagesInstallUpdate(Sender: TObject);
    procedure ActPackagesRemoveUpdate(Sender: TObject);
    procedure ActPackagesUpdateUpdate(Sender: TObject);
    procedure ActProprietaryExecute(Sender: TObject);
    procedure ActRemoteAssistExecute(Sender: TObject);
    procedure ActRemoteAssistUpdate(Sender: TObject);
    procedure ActExternalRepositoriesSettingsExecute(Sender: TObject);
    procedure ActTISHelpExecute(Sender: TObject);
    procedure ActTISHelpUpdate(Sender: TObject);
    procedure ActTriggerBurstUpdatesExecute(Sender: TObject);
    procedure ActTriggerBurstUpgradesExecute(Sender: TObject);
    procedure ActTriggerWakeOnLanExecute(Sender: TObject);
    procedure ActTriggerWaptwua_downloadExecute(Sender: TObject);
    procedure ActTriggerWaptwua_installExecute(Sender: TObject);
    procedure ActTriggerWaptwua_scanExecute(Sender: TObject);
    procedure ActWSUSDowloadWSUSScanExecute(Sender: TObject);
    procedure ActWSUSRefreshCabHistoryExecute(Sender: TObject);
    procedure ActWSUSSaveBuildRulesExecute(Sender: TObject);
    procedure ActWSUSSaveBuildRulesUpdate(Sender: TObject);
    procedure ActWUAAddAllowedClassificationExecute(Sender: TObject);
    procedure ActWUAAddAllowedUpdateExecute(Sender: TObject);
    procedure ActWUAAddForbiddenUpdateExecute(Sender: TObject);
    procedure ActWUADownloadSelectedUpdateUpdate(Sender: TObject);
    procedure ActEditGroupExecute(Sender: TObject);
    procedure ActEditHostPackageExecute(Sender: TObject);
    procedure ActEnglishExecute(Sender: TObject);
    procedure ActEnglishUpdate(Sender: TObject);
    procedure ActPackagesForgetExecute(Sender: TObject);
    procedure ActFrenchExecute(Sender: TObject);
    procedure ActFrenchUpdate(Sender: TObject);
    procedure ActGotoHostExecute(Sender: TObject);
    procedure ActHelpExecute(Sender: TObject);
    procedure ActHostsActionsUpdate(Sender: TObject);
    procedure ActImportFromFileExecute(Sender: TObject);
    procedure ActImportFromRepoExecute(Sender: TObject);
    procedure ActWUALoadUpdatesExecute(Sender: TObject);
    procedure ActWUALoadUpdatesUpdate(Sender: TObject);
    procedure ActPackagesInstallExecute(Sender: TObject);
    procedure ActPackagesRemoveExecute(Sender: TObject);
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
    procedure ActEditPackageExecute(Sender: TObject);
    procedure ActEditpackageUpdate(Sender: TObject);
    procedure ActEvaluateExecute(Sender: TObject);
    procedure ActExecCodeExecute(Sender: TObject);
    procedure ActHostsCopyExecute(Sender: TObject);
    procedure ActDeleteHostsPackageAndInventoryExecute(Sender: TObject);
    procedure actHostSelectAllExecute(Sender: TObject);
    procedure ActAddGroupExecute(Sender: TObject);
    procedure actQuitExecute(Sender: TObject);
    procedure actRefreshExecute(Sender: TObject);
    procedure ActSearchHostExecute(Sender: TObject);
    procedure ActSearchPackageExecute(Sender: TObject);
    procedure ActPackagesUpdateExecute(Sender: TObject);
    procedure ActReloadConfigExecute(Sender: TObject);
    procedure ActVNCExecute(Sender: TObject);
    procedure ActVNCUpdate(Sender: TObject);
    procedure ActWAPTConsoleConfigExecute(Sender: TObject);
    procedure ApplicationProperties1Exception(Sender: TObject; E: Exception);
    procedure cbADOUSelect(Sender: TObject);
    procedure cbADSiteSelect(Sender: TObject);
    procedure cbAdvancedSearchClick(Sender: TObject);
    procedure cbGroupsDropDown(Sender: TObject);
    procedure cbGroupsSelect(Sender: TObject);
    procedure CBInverseSelectClick(Sender: TObject);
    procedure cbMaskSystemComponentsClick(Sender: TObject);
    procedure cbNewestOnlyClick(Sender: TObject);
    procedure cbADOUDropDown(Sender: TObject);
    procedure cbSearchAllClick(Sender: TObject);
    procedure cbShowLogClick(Sender: TObject);
    procedure cbADSiteDropDown(Sender: TObject);
    procedure cbWUAPendingChange(Sender: TObject);
    procedure cbWUCriticalClick(Sender: TObject);
    procedure CBWUProductsShowAllClick(Sender: TObject);
    procedure CheckBoxMajChange(Sender: TObject);
    procedure cbNeedUpgradeClick(Sender: TObject);
    procedure CheckBox_errorChange(Sender: TObject);
    procedure EdDescriptionExit(Sender: TObject);
    procedure EdDescriptionKeyPress(Sender: TObject; var Key: char);
    procedure EdHardwareFilterChange(Sender: TObject);
    procedure EdRunKeyPress(Sender: TObject; var Key: char);
    procedure EdSearchPackageExecute(Sender: TObject);
    procedure EdSearchGroupsExecute(Sender: TObject);
    procedure EdSearchGroupsKeyPress(Sender: TObject; var Key: char);
    procedure EdSearchHostExecute(Sender: TObject);
    procedure EdSearchHostKeyPress(Sender: TObject; var Key: char);
    procedure EdSoftwaresFilterChange(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure FormDragOver(Sender, Source: TObject; X, Y: Integer;
      State: TDragState; var Accept: Boolean);
    procedure FormDropFiles(Sender: TObject; const FileNames: array of String);
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
    procedure GridHostPackagesGetText(Sender: TBaseVirtualTree;
      Node: PVirtualNode; RowData, CellData: ISuperObject;
      Column: TColumnIndex; TextType: TVSTTextType; var CellText: string);
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
    procedure GridHostsGetHint(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; var LineBreakStyle: TVTTooltipLineBreakStyle;
      var HintText: String);
    procedure GridHostsGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: boolean; var ImageIndex: integer;
      var ImageList: TCustomImageList);
    procedure GridHostsGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      RowData, CellData: ISuperObject; Column: TColumnIndex;
      TextType: TVSTTextType; var CellText: string);
    procedure GridHostsHeaderDblClick(Sender: TVTHeader; HitInfo: TVTHeaderHitInfo);
    procedure GridHostsNewText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; const NewText: String);
    procedure GridHostTasksPendingChange(Sender: TBaseVirtualTree;
      Node: PVirtualNode);
    procedure GridHostWinUpdatesGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: Boolean; var ImageIndex: Integer;
      var ImageList: TCustomImageList);
    procedure GridHostWinUpdatesGetText(Sender: TBaseVirtualTree;
      Node: PVirtualNode; RowData, CellData: ISuperObject;
      Column: TColumnIndex; TextType: TVSTTextType; var CellText: string);
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
    procedure GridWSUSAllowedClassificationsFreeNode(Sender: TBaseVirtualTree;
      Node: PVirtualNode);
    procedure GridWSUSAllowedWindowsUpdatesFreeNode(Sender: TBaseVirtualTree;
      Node: PVirtualNode);
    procedure GridWSUSForbiddenWindowsUpdatesFreeNode(Sender: TBaseVirtualTree;
      Node: PVirtualNode);
    procedure HostPagesChange(Sender: TObject);
    procedure Image1Click(Sender: TObject);
    procedure MainPagesChange(Sender: TObject);
    procedure MenuItem27Click(Sender: TObject);
    procedure MenuItem74Click(Sender: TObject);
    procedure TimerWUALoadWinUpdatesTimer(Sender: TObject);
    procedure TimerTasksTimer(Sender: TObject);
  private
    { private declarations }
    CurrentVisLoading: TVisLoading;
    procedure DoProgress(ASender: TObject);
    procedure FillcbADOUDropDown;
    procedure FillcbADSiteDropDown;
    procedure FillcbGroups;
    function FilterSoftwares(softs: ISuperObject): ISuperObject;
    function FilterHardware(data: ISuperObject): ISuperObject;
    function FilterHostWinUpdates(wua: ISuperObject): ISuperObject;
    function FilterWindowsUpdate(wua: ISuperObject): ISuperObject;
    function FilterWinProducts(products: ISuperObject): ISuperObject;
    function OneHostHasConnectedIP: Boolean;
    function OneHostIsConnected: Boolean;
    procedure SetIsEnterpriseEdition(AValue: Boolean);
    function GetIsEnterpriseEdition: Boolean;
    function GetSelectedUUID: ISuperObject;
    procedure GridLoadData(grid: TSOGrid; jsondata: string);
    procedure HandleServerResult(ServerResult: ISuperObject);
    procedure IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: int64);
    function InventoryData(uuid: String): ISuperObject;
    procedure MakePackageTemplate(AInstallerFileName: String);
    function TriggerChangeHostDescription(uuid, description: String): Boolean;
    procedure UpdateHostPages(Sender: TObject);
    procedure UpdateSelectedHostsActions(Sender: TObject);
    procedure PythonOutputSendData(Sender: TObject; const Data: ansistring);
    procedure TreeLoadData(tree: TVirtualJSONInspector; jsondata: ISuperObject);
  public
    { public declarations }
    PackageEdited: ISuperObject;

    MainRepoUrl, WAPTServer, TemplatesRepoUrl: string;

    {$ifdef wsus}
    WUAProducts : ISuperObject;
    WUAWinUpdates : ISuperObject;
    windows_updates_rulesUpdated: Boolean;
    {$endif}

    HostsLimit: Integer;

    AppLoading:Boolean;

    constructor Create(TheOwner: TComponent); override;

    function Login: boolean;
    function EditIniFile: boolean;
    function updateprogress(receiver: TObject; current, total: integer): boolean;
    function TriggerActionOnHosts(uuids: ISuperObject;AAction:String;Args:ISuperObject;title,errortitle:String;Force:Boolean=False;NotifyServer:Boolean=True):ISuperObject;
    procedure TriggerActionOnHostPackages(AAction, title, errortitle: String;Force:Boolean=False);

    property IsEnterpriseEdition:Boolean read GetIsEnterpriseEdition write SetIsEnterpriseEdition;

  end;

var
  VisWaptGUI: TVisWaptGUI;

implementation

uses LCLIntf, LCLType, IniFiles, variants, uvisprivatekeyauth, tisstrings, soutils,
  waptcommon, waptwinutils, tiscommon, uVisCreateKey, uVisCreateWaptSetup,
  dmwaptpython, uviseditpackage, uvislogin, uviswaptconfig, uvischangepassword,
  uvisgroupchoice, uvishostsupgrade, uVisAPropos,
  uVisImportPackage, PythonEngine, Clipbrd, RegExpr, tisinifiles, IdURI,
  uScaleDPI, uVisPackageWizard, uVisChangeKeyPassword, uVisDisplayPreferences,
  uvisrepositories, uVisHostDelete, windirs
  {$ifdef wsus}
  ,uVisWUAGroup, uVisWAPTWUAProducts, uviswuapackageselect,
  uVisWUAClassificationsSelect
  {$endif};

{$R *.lfm}

{ TVisWaptGUI }

type TComponentsArray=Array of TComponent;

function VarArrayOf(items: Array of const):TComponentsArray;
var
  i:integer;
begin
  SetLength(result,Length(items));
  for i:=0 to length(items)-1 do
    result[i] := TComponent(items[i].VObject);

end;

function ProgramFilesX86:String;
begin
  result := SysUtils.GetEnvironmentVariable('PROGRAMFILES(X86)');
  if result = '' then
    result := SysUtils.GetEnvironmentVariable('PROGRAMFILES')
end;

function GetTisSupportPath:String;
begin
  result := AppendPathDelim(ProgramFilesX86)+'tishelp\tissupport.exe';
end;

function GetVNCViewerPath:String;
const
  vncpathes: Array[0..2] of String = ('C:\Program Files\TightVNC\tvnviewer.exe','C:\Program Files\TightVNC\tvnviewer64.exe',
    'C:\Program Files (x86)\TightVNC\tvnviewer.exe');
var
  p:String;
begin
  for p in vncpathes do
    if FileExists(p) then
    begin
      Result := p;
      Break;
    end;
end;


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

procedure TVisWaptGUI.CheckBoxMajChange(Sender: TObject);
begin
  ActHostSearchPackage.Execute;
end;

procedure TVisWaptGUI.cbNeedUpgradeClick(Sender: TObject);
begin
  Gridhosts.Clear;
  if ((length(EdSearchHost.Text)>5)  and
    (cbSearchDMI.Checked or cbSearchSoftwares.Checked or cbSearchPackages.Checked or cbSearchHost.Checked)) or
    (cbHasErrors.Checked or cbNeedUpgrade.Checked or cbReachable.Checked) then
        ActSearchHostExecute(Sender);
end;

procedure TVisWaptGUI.CheckBox_errorChange(Sender: TObject);
begin
  ActHostSearchPackage.Execute;
end;

procedure TVisWaptGUI.EdDescriptionExit(Sender: TObject);
begin
  if GridHosts.FocusedRow<>Nil then
    EdDescription.Text:=UTF8Encode(GridHosts.FocusedRow.S['description']);
end;

procedure TVisWaptGUI.EdDescriptionKeyPress(Sender: TObject; var Key: char);
begin
  if (Key=#13) then
    if GridHosts.FocusedRow<>Nil then
    begin
       if TriggerChangeHostDescription(GridHosts.FocusedRow.S['uuid'],UTF8Decode(EdDescription.Text)) then
       begin
          GridHosts.FocusedRow.S['description'] := UTF8Decode(EdDescription.Text);
          GridHosts.InvalidateFordata(GridHosts.FocusedRow);
       end
       else
          EdDescription.Text := UTF8Encode(GridHosts.FocusedRow.S['description']);
    end;
end;

procedure TVisWaptGUI.EdHardwareFilterChange(Sender: TObject);
var
  data : ISuperObject;
begin
  if (Gridhosts.FocusedRow <> nil) then
  begin
    data := Gridhosts.FocusedRow['_host_infos'];
    if data = Nil then
    begin
      data := InventoryData(GridHosts.FocusedRow.S['uuid']);
      Gridhosts.FocusedRow['_host_infos'] := data;
    end;
    TreeLoadData(GridhostInventory, FilterHardware(data));
    GridhostInventory.FullExpand;
  end;
end;

procedure TVisWaptGUI.EdRunKeyPress(Sender: TObject; var Key: char);
begin
  if Key = #13 then
    ActEvaluate.Execute;
end;

procedure TVisWaptGUI.EdSearchPackageExecute(Sender: TObject);
begin
  if EdSearchPackage.Modified then
    ActSearchPackageExecute(Sender);
end;

procedure TVisWaptGUI.EdSearchGroupsExecute(Sender: TObject);
begin
  if EdSearchGroups.Modified then
    ActSearchGroupsExecute(Sender);
end;

procedure TVisWaptGUI.EdSearchGroupsKeyPress(Sender: TObject; var Key: char);
begin
  if key=#13 then
  begin
    EdSearchGroups.SelectAll;
    ActSearchGroups.Execute;
  end;
end;

procedure TVisWaptGUI.EdSearchHostExecute(Sender: TObject);
begin
  if EdSearchHost.Modified then
    ActSearchHostExecute(Sender);
end;

procedure TVisWaptGUI.EdSearchHostKeyPress(Sender: TObject; var Key: char);
begin
  if key = #13 then
    ActSearchHost.execute
  else
    if CharIsAlphaNum(Key) then
      Gridhosts.Clear;

end;

procedure TVisWaptGUI.EdSoftwaresFilterChange(Sender: TObject);
begin
  if (Gridhosts.FocusedRow <> nil) then
    GridHostSoftwares.Data := FilterSoftwares(Gridhosts.FocusedRow['installed_softwares']);

end;


procedure TVisWaptGUI.FormClose(Sender: TObject; var CloseAction: TCloseAction);
var
  ini : TIniFile;
  last_usage_report : TDateTime;
  stats: ISuperObject;
  stats_report_url,proxy:String;
  CB: TComponent;
begin
  Gridhosts.SaveSettingsToIni(Appuserinipath);
  GridPackages.SaveSettingsToIni(Appuserinipath);
  GridGroups.SaveSettingsToIni(Appuserinipath);
  GridHostPackages.SaveSettingsToIni(Appuserinipath);
  GridHostSoftwares.SaveSettingsToIni(Appuserinipath);

  // %APPDATA%\waptconsole\waptconsole.ini
  ini := TIniFile.Create(Appuserinipath);
  try
    for CB in VarArrayOf([cbAdvancedSearch,cbSearchAll,cbSearchDMI,cbSearchHost,cbSearchPackages,cbSearchSoftwares,cbReachable]) do
      ini.WriteBool(self.name,CB.Name,TCheckBox(CB).Checked);

    ini.WriteInteger(self.name,'HostsLimit',HostsLimit);
    ini.WriteInteger(self.name,HostPages.Name+'.width',HostPages.Width);

    ini.WriteInteger(self.name,'WindowState',Integer(Self.WindowState));

    ini.WriteInteger(self.name,'Left',Self.Left);
    ini.WriteInteger(self.name,'Top',Self.Top);
    ini.WriteInteger(self.name,'Width',Self.Width);
    ini.WriteInteger(self.name,'Height',Self.Height);

    ini.WriteString(self.name,cbGroups.Text,'cbGroups.Text');

    {$ifdef ENTERPRISE}
    ini.WriteString(self.name,cbADSite.Text,'cbADSite.Text');
    ini.WriteString(self.name,cbADOU.Text,'cbADOU.Text');
    {$endif}

    ini.WriteString(self.name,'waptconsole.version',GetApplicationVersion);

  finally
    ini.Free;
  end;

  // %LOCALAPPDATA%\waptconsole\waptconsole.ini
  // global settings, not per cert
  ini := TIniFile.Create(AppIniFilename);
  try
    if ini.ReadBool('global','send_usage_report',True) then
    begin
      Proxy:=Ini.ReadString('wapt-templates','http_proxy','');
      if Proxy = '' then
        Proxy:=Ini.ReadString('global','http_proxy','');
      last_usage_report:=ini.ReadDateTime('global','last_usage_report',0);
      if now - last_usage_report >= 0.5 then
      try
        stats_report_url:=ini.ReadString('global','usage_report_url',rsDefaultUsageStatsURL);
        stats := WAPTServerJsonGet('api/v1/usage_statistics',[])['result'];
        IdHttpPostData(stats_report_url,stats.AsJSon,Proxy,4000,60000,60000,'','','Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko');
        ini.WriteDateTime('global','last_usage_report',Now);

      except
        ini.WriteDateTime('global','last_usage_report',Now);
      end;
    end;
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

function TVisWaptGUI.FilterHardware(data: ISuperObject): ISuperObject;

  function SelectedProps(item:ISuperObject):ISuperObject;
  var
    k,v: ISuperObject;
    res, child,newchild:ISuperObject;
  begin
    if item.DataType = stArray then
    begin
      res := TSuperObject.Create(stArray);
      for child in item do
      begin
        newchild := SelectedProps(child);
        if newchild <> Nil then
          res.AsArray.Add(newchild);
      end;
      if res.AsArray.Length=0 then
        res := Nil;
    end
    else
    if item.DataType = stObject then
    begin
      res := TSuperObject.Create(stObject);
      for k in item.AsObject.GetNames do
      begin
        try
          if ExecRegExpr('(?i)' +EdHardwareFilter.Text, k.AsString) then
            res[k.AsString] := item[k.AsString]
          else
          begin
            // we check if some items are matching
            v := SelectedProps(item[k.AsString]);
            if v<>Nil then
              res[k.AsString] := v;
          end;
        except
            on E: ERegExpr do begin LabErrorRegHardware.Caption :=  E.Message; end;
        end;
      end;
      if res.AsObject.Count=0 then
        res := Nil;
    end
    else
      res := Nil;
    Result := res;
  end;

begin
  LabErrorRegHardware.Caption := '';
  if (EdHardwareFilter.Text = '')then
    Result := data
  else
    Result := SelectedProps(Data);
end;

function TVisWaptGUI.GetIsEnterpriseEdition: Boolean;
begin
  {$ifdef ENTERPRISE}
  Result := DMPython.IsEnterpriseEdition;
  {$else}
  Result := False;
  {$endif}
end;


function TVisWaptGUI.InventoryData(uuid:String):ISuperObject;
var
  sores:ISuperObject;
begin
  try
    sores := WAPTServerJsonGet('api/v1/hosts?columns=dmi,wmi,host_info&uuid=%S',[uuid]);
    if (sores<>nil) and sores.B['success'] then
    begin
      if sores['result'].AsArray.Length>0 then
        result := sores.A['result'][0]
    end
    else
      result := nil;
  except
    result := nil;
  end;
end;

procedure TVisWaptGUI.UpdateHostPages(Sender: TObject);
var
  currhost,packagename : ansistring;
  RowSO, package,packagereq, packages, softwares, waptwua,tasksresult, running,sores,all_missing,pending_install,additional,upgrades,errors: ISuperObject;
begin
  TimerTasks.Enabled := False;
  RowSO := Gridhosts.FocusedRow;

  if (RowSO <> nil) then
  begin
    currhost := RowSO.S['uuid'];
    pgTasks.TabVisible := RowSO.S['reachable'] = 'OK';
    if not pgTasks.TabVisible and (HostPages.ActivePage = pgTasks) then
      HostPages.ActivePage := pgPackages;

    if HostPages.ActivePage = pgPackages then
    begin
      GridHostPackages.Clear;
      packages := RowSO['installed_packages'];
      if (packages = nil) or (packages.AsArray = nil) then
      try
        sores := WAPTServerJsonGet('api/v1/host_data?field=installed_packages&uuid=%S',[currhost]);
        if sores.B['success'] then
        begin
          RowSO['installed_packages'] := sores['result'];
          // add missing packages
          all_missing := TSuperObject.Create(stArray);
          additional :=   RowSO['last_update_status.pending.additional'];
          pending_install := RowSO['last_update_status.pending.install'];
          if pending_install <> Nil then
            for package in pending_install do
              all_missing.AsArray.Add(package);
          if (additional<>Nil) and (additional.AsArray.Length>0) then
            for package in additional do
              all_missing.AsArray.Add(package);


          for packagereq in all_missing do
          begin
            package := TSuperObject.Create();
            package['package'] := packagereq;
            package.S['install_status'] := 'MISSING';
            RowSO.A['installed_packages'].Add(package);
          end;

          upgrades := RowSO['last_update_status.pending.upgrade'];
          if (upgrades<>Nil) and (upgrades.AsArray.Length>0) then
          begin
            for package in RowSO['installed_packages'] do
            begin
              for packagereq in upgrades do
              begin
                packagename:= Trim(copy(packagereq.AsString,1,pos('(',packagereq.AsString)-1));
                if package.S['package'] = packagename then
                  package.S['install_status'] := 'NEED-UPGRADE';
              end;
            end;
          end;

          errors := RowSO['last_update_status.errors'];
          if (errors<>Nil) and (errors.AsArray.Length>0) then
          begin
            for package in RowSO['installed_packages'] do
            begin
              for packagereq in errors do
              begin
                packagename:= Trim(copy(packagereq.AsString,1,pos('(',packagereq.AsString)-1));
                if package.S['package'] = packagename then
                  package.S['install_status'] := 'ERROR-UPGRADE';
              end;
            end;
          end;
        end
        else
          RowSO['installed_packages'] := nil;
      except
        RowSO['installed_packages'] := nil;
      end;
      EdUUID.Text := UTF8Encode(RowSO.S['uuid']);
      EdHostname.Text := UTF8Encode(RowSO.S['computer_name']);
      EdDescription.Text := UTF8Encode(RowSO.S['description']);
      EdOS.Text := RowSO.S['os_name'];
      if RowSO['connected_ips'].DataType=stArray then
        EdIPAddress.Text := soutils.join(',',RowSO['connected_ips'])
      else
        EdIPAddress.Text := RowSO.S['connected_ips'];
      EdManufacturer.Text := UTF8Encode(RowSO.S['manufacturer']);
      EdModelName.Text := UTF8Encode(RowSO.S['productname']);
      EdUpdateDate.Text :=  UTF8Encode(Copy(StrReplaceChar(RowSO.S['last_seen_on'],'T',' '),1,16));
      If RowSO['connected_users'].DataType=stArray then
        EdUser.Text := UTF8Encode(soutils.join(',',RowSO['connected_users']))
      else
        EdUser.Text := UTF8Encode(RowSO.S['connected_users']);
      If EdUser.Text = '' then
      begin
        EdUser.Text:= UTF8Encode(RowSO.S['last_logged_on_user']);
        LabUser.Caption := 'Last logged on user';
      end
      else
      begin
        LabUser.Caption := 'Logged in users';
      end;
      EdRunningStatus.Text := UTF8Encode(RowSO.S['last_update_status.runstatus']);
      GridHostPackages.Data := RowSO['installed_packages'];
    end
    else if HostPages.ActivePage = pgSoftwares then
    begin
      GridHostSoftwares.Clear;
      //Cache collection in grid data
      softwares := RowSO['installed_softwares'];
      if (softwares = nil) or (softwares.AsArray = nil) then
      try
        sores := WAPTServerJsonGet('api/v1/host_data?field=installed_softwares&uuid=%S',[currhost]);
        if sores.B['success'] then
          softwares := sores['result']
        else
          softwares := nil;
      except
        softwares := nil;
      end;
      RowSO['installed_softwares'] := softwares;
      GridHostSoftwares.Data := FilterSoftwares(softwares);
    end
    else if HostPages.ActivePage = pgHostWUA then
    begin
      //Cache collection in grid data
      waptwua := RowSO['waptwua'];
      if (waptwua = nil) or (waptwua.AsArray = nil) then
      try
        sores := WAPTServerJsonGet('api/v1/host_data?field=waptwua&uuid=%S',[currhost]);
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
      GridhostInventory.Clear;
      if GridHosts.FocusedRow <> Nil then
        EdHardwareFilterChange(EdHardwareFilter)
    end
    else if HostPages.ActivePage = pgTasks then
    begin
      try
        try
          sores := WAPTServerJsonGet('api/v3/host_tasks_status?uuid=%S', [currhost]);
          if sores.B['success'] then
          begin
            tasksresult := sores['result'];
            if tasksresult <> nil then
            begin
              running := tasksresult['running'];
              if not GridHostTasksPending.Focused and not MemoTaskLog.Focused then
                GridHostTasksPending.Data := tasksresult['pending'];
              if not GridHostTasksDone.Focused and not MemoTaskLog.Focused then
                GridHostTasksDone.Data := tasksresult['done'];
              if not GridHostTasksErrors.Focused and not MemoTaskLog.Focused then
                GridHostTasksErrors.Data := tasksresult['errors'];
              if running <> nil then
              begin
                ActCancelRunningTask.Enabled:= running['description'] <> Nil;

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

procedure TVisWaptGUI.UpdateSelectedHostsActions(Sender: TObject);
var
  OneIsFocused,
  OneIsConnected,
  OneHasConnectedIP:Boolean;
begin
  OneIsConnected:=OneHostIsConnected;
  OneHasConnectedIP:=OneHostHasConnectedIP;
  OneIsFocused:=(Gridhosts.FocusedRow <> nil);

  ActTriggerHostUpdate.Visible := not HideUnavailableActions or (OneIsFocused  and OneIsConnected);
  ActTriggerHostUpgrade.Visible := not HideUnavailableActions or (OneIsFocused  and OneIsConnected);
  ActPackagesInstall.Visible := not HideUnavailableActions or (OneIsFocused  and OneIsConnected);
  ActPackagesRemove.Visible := not HideUnavailableActions or (OneIsFocused  and OneIsConnected);
  ActPackagesForget.Visible := not HideUnavailableActions or (OneIsFocused  and OneIsConnected);
  ActRefreshHostInventory.Visible := not HideUnavailableActions or (OneIsFocused  and OneIsConnected);

  ActAddADSGroups.Visible := OneIsFocused  and EnableExternalTools;

  ActRDP.Visible := OneIsFocused  and OneHasConnectedIP and EnableExternalTools;
  ActVNC.Visible := OneIsFocused  and OneHasConnectedIP and FileExists(GetVNCViewerPath) and EnableExternalTools;
  ActComputerServices.Visible := OneIsFocused  and OneHasConnectedIP and EnableExternalTools;
  ActComputerUsers.Visible := OneIsFocused  and OneHasConnectedIP and EnableExternalTools;
  ActComputerMgmt.Visible := OneIsFocused  and OneHasConnectedIP and EnableExternalTools;
  ActRemoteAssist.Visible := OneIsFocused  and OneHasConnectedIP and EnableExternalTools;

  ActTriggerWakeOnLan.Visible := OneIsFocused  and OneHasConnectedIP and EnableExternalTools;

  ActCreateCertificate.Visible := not HideUnavailableActions or ActCreateCertificate.Enabled;
  ActChangePassword.Visible := not HideUnavailableActions or ActChangePassword.Enabled;
  ActCreateWaptSetup.Visible := not HideUnavailableActions or ActCreateWaptSetup.Enabled;

  MenuExternalTools.Visible := EnableExternalTools;
end;

constructor TVisWaptGUI.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
end;

procedure TVisWaptGUI.MenuItem27Click(Sender: TObject);
begin
  with TVisApropos.Create(Self) do
    ShowModal;
end;

procedure TVisWaptGUI.MenuItem74Click(Sender: TObject);
var
  node,args,ids,res:ISuperObject;
begin
  args := TSuperObject.Create;
  ids := TSuperObject.Create(stArray);
  for node in GridWSUSScan.SelectedRows do
    ids.AsArray.Add(node['uuid']);

  args['ids'] := ids;
  res := WAPTServerJsonGet('api/v2/wsusscan2_history?uuid=%S',[Join(',',ids)],'DELETE');
  if res.B['success'] then
    ActWSUSRefreshCabHistory.Execute
  else
    ShowMessageFmt(rsErrorWithMessage,[res.S['error']]);
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

procedure TVisWaptGUI.ActAddGroupExecute(Sender: TObject);
begin
  if WaptIniReadString(AppIniFilename,'global','default_sources_root')<>'' then
  begin
    CreateGroup('agroup', AdvancedMode);
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
    if MainPages.ActivePage = pgPrivateRepo then
      ActPackagesUpdate.Execute
    else
    if MainPages.ActivePage = pgGroups then
      ActPackagesUpdate.Execute;
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TVisWaptGUI.ActEditPackageExecute(Sender: TObject);
var
  res_var : Variant;
  Selpackage: string;
  Devpath : UnicodeString;
  res: ISuperObject;
begin
  if GridPackages.FocusedNode <> nil then
  begin
    if IniReadString(AppIniFilename,'global','default_sources_root')<>'' then
    begin
      Selpackage := format('%s(=%s)', [GridPackages.GetCellStrValue(
        GridPackages.FocusedNode, 'package'), GridPackages.GetCellStrValue(
        GridPackages.FocusedNode, 'version')]);
      try
        { TODO : Remove use of WAPT instance, use waptpackage.PackageEntry instead }
        DevPath := VarPythonAsString(DMPython.WAPT.get_default_development_dir(SelPackage));
        if DirectoryExistsUTF8(DevPath) then
          DevPath:=DevPath+'.'+GridPackages.GetCellStrValue(GridPackages.FocusedNode, 'version');
        { TODO : Remove use of WAPT instance, use waptpackage.PackageEntry instead }
        DMPython.WAPT.update(force := True,register := False,filter_on_host_cap := False);
        res := PyVarToSuperObject(DMPython.WAPT.edit_package(
          packagerequest := Selpackage,
          target_directory:=DevPath,
          auto_inc_version:=False));

        if not DirectoryExists(res.S['sourcespath']) then
          raise Exception.Create('Unable to edit package. Development directory '+res.S['sourcespath']+' does not exist');
        DMPython.common.wapt_sources_edit( wapt_sources_dir := DevPath);
      except
        on E:Exception do
        begin
          ShowMessageFmt(rsErrorWithMessage,[e.Message]);
          exit;
        end;
      end;
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
begin
  with TVisCreateKey.Create(Self) do
  try
    if ShowModal = mrOk then
    begin
      with TINIFile.Create(AppIniFilename) do
      try
        if GetWaptPersonalCertificatePath = '' then
        // first use...
          WriteString('global', 'personal_certificate_path', CertificateFilename);

        if EdCAKeyFilename.Text <> '' then
          WriteString('global', 'default_ca_key_path', EdCAKeyFilename.Text);
        if EdCACertificate.Text <> '' then
          WriteString('global', 'default_ca_cert_path', EdCACertificate.Text);
      finally
        Free;
      end;

      // If this a CA cert, we should perhaps take it in account right now...
      if CBIsCA.Checked and (MessageDlg(Format(rsWriteCertOnLocalMachine,[AppendPathDelim(WaptBaseDir)+'ssl']), mtConfirmation, [mbYes, mbNo],0) = mrYes) then
      begin
        if CopyFile(PChar(CertificateFilename),
          PChar(WaptBaseDir() + '\ssl\' + ExtractFileName(CertificateFilename)), True) then
        begin
          CurrentVisLoading := TVisLoading.Create(Self);
          with CurrentVisLoading do
          try
            ProgressTitle(rsReloadWaptserviceConfig);
            Start(3);
            ActReloadConfigExecute(self);
            ProgressStep(1,3);
            ProgressTitle(rsReloadWaptserviceConfig);
            try
              Run('cmd /C net stop waptservice');
              ProgressStep(2,3);
              Run('cmd /C net start waptservice');
              ProgressStep(3,3);
            except
            end;

          finally
            Finish;
            FreeAndNil(CurrentVisLoading);
          end;
        end
      end
    end
  finally
    Free;
  end;
end;

procedure TVisWaptGUI.ActCreateCertificateUpdate(Sender: TObject);
begin
  ActCreateCertificate.Enabled := (WaptServerUser='admin') and EnableManagementFeatures;
end;

procedure TVisWaptGUI.ActCreateWaptSetupExecute(Sender: TObject);
var
  waptsetupPath, buildDir, SignDigests: string;
  ini: TIniFile;
  SORes: ISuperObject;
  FatUpgrade:Boolean;
  BuildRes:Variant;
begin
  FatUpgrade := True;
  if (waptcommon.DefaultPackagePrefix = '') then
  begin
    ShowMessage(rsWaptPackagePrefixMissing);
    ActWAPTConsoleConfig.Execute;
    exit;
  end;

  if not FileExists(GetWaptPersonalCertificatePath) then
  begin
    ShowMessageFmt(rsPrivateKeyDoesntExist, [GetWaptPersonalCertificatePath]);
    exit;
  end;

  with TVisCreateWaptSetup.Create(self) do
    try
      ini := TIniFile.Create(AppIniFilename);
      if ini.ReadString('global', 'default_ca_cert_path', '') <> '' then
        fnPublicCert.Text := ini.ReadString('global', 'default_ca_cert_path', '')
      else
        fnPublicCert.Text := ini.ReadString('global', 'personal_certificate_path', '');

      if not FileExists(fnPublicCert.Text) then
        fnPublicCert.Clear;
      edWaptServerUrl.Text := ini.ReadString('global', 'wapt_server', '');
      edRepoUrl.Text := ini.ReadString('global', 'repo_url', '');
      EdServerCertificate.Text := ini.ReadString('global', 'verify_cert', '0'); ;
      CBUseKerberos.Checked:=ini.ReadBool('global', 'use_kerberos', False );
      CBCheckCertificatesValidity.Checked:=ini.ReadBool('global', 'check_certificates_validity',True );
      CBDualSign.Checked:= (ini.ReadString('global', 'sign_digests','') = 'sha256,sha1');
      if FatUpgrade then
        // include waptagent.exe in waptupgrade package...
        fnWaptDirectory.Directory := WaptBaseDir()+'\waptupgrade'
      else
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
            waptsetupPath := '';

            if CBDualSign.Checked then
              SignDigests := 'sha256,sha1'
            else
              SignDigests := 'sha256';

            try
              ProgressTitle(rsCreationInProgress);
              waptsetupPath := CreateWaptSetup(fnPublicCert.FileName,
                edRepoUrl.Text, edWaptServerUrl.Text, fnWaptDirectory.Directory, edOrgName.Text, @DoProgress, 'waptagent',
                EdServerCertificate.Text,
                CBUseKerberos.Checked,
                CBCheckCertificatesValidity.Checked
                );

            except
              on E:Exception do
              begin
                ShowMessageFmt(rsWaptAgentSetupError,[E.Message]);
                exit;
              end;
            end;
            Application.ProcessMessages;

            // create waptupgrade package (after waptagent as we need the updated waptagent.sha1 file)
            ProgressTitle(rsCreationInProgress);
            try
              buildDir := GetTempDir(False);
              if RightStr(buildDir,1) = '\' then
                buildDir := copy(buildDir,1,length(buildDir)-1);
              BuildRes := DMPython.waptdevutils.build_waptupgrade_package(
                  waptconfigfile := AppIniFilename(),
                  wapt_server_user := WaptServerUser,
                  wapt_server_passwd := WaptServerPassword,
                  key_password := dmpython.privateKeyPassword,
                  sign_digests := SignDigests
                  );

              if FileExists(VarToStr(BuildRes.get('localpath'))) then
              begin
                ProgressTitle(rsWaptUpgradePackageBuilt);
                DeleteFileUTF8(VarToStr(BuildRes.get('localpath')));
              end;

            except
              On E:Exception do
                ShowMessage(rsWaptUpgradePackageBuildError+#13#10+E.Message);
            end;
            ActPackagesUpdate.Execute;
            Finish;
            if FileExists(waptsetupPath) then
              try
                Start;
                ProgressTitle(rsProgressTitle);
                SORes := WAPTServerJsonMultipartFilePost(
                  GetWaptServerURL, 'upload_waptsetup', [], 'file', waptsetupPath,
                  WaptServerUser, WaptServerPassword, @IdHTTPWork,GetWaptServerCertificateFilename);
                Finish;
                if SORes.S['status'] = 'OK' then
                begin
                  ShowMessage(format(rsWaptSetupUploadSuccess, []));
                  if not FatUpgrade then
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

procedure TVisWaptGUI.ActCreateWaptSetupUpdate(Sender: TObject);
begin
  ActCreateWaptSetup.Enabled:= DMPython.CertificateIsCodeSigning(GetWaptPersonalCertificatePath) and EnableManagementFeatures;
end;

procedure TVisWaptGUI.ActAddConflictsExecute(Sender: TObject);
var
  Res, packages, hosts: ISuperObject;
  ResVar,VarHosts,VarPackages: Variant;
begin
  if GridHosts.Focused then
  begin
    with TvisGroupChoice.Create(self) do
    try
      Caption := rsSelectAddConflicts;
      res := TSuperObject.Create(stArray);

      if ShowModal = mrOk then
      try
        Screen.Cursor := crHourGlass;
        packages := SelectedPackages;
        Hosts := ExtractField(GridHosts.SelectedRows,'uuid');

        VarHosts := SuperObjectToPyVar(Hosts);
        VarPackages := SuperObjectToPyVar(packages);

        resVar := DMPython.waptdevutils.edit_hosts_depends(
           waptconfigfile := AppIniFilename(),
           hosts_list := VarHosts,
           append_conflicts := VarPackages,
           key_password := dmpython.privateKeyPassword,
           wapt_server_user := waptServerUser,
           wapt_server_passwd := waptServerPassword
           );

        res := PyVarToSuperObject(ResVar);

      finally
        Screen.cursor := crDefault;
        ShowMessageFmt(rsNbModifiedHosts, [res.A['updated'].Length,res.A['discarded'].Length,res.A['unchanged'].Length]);
      end;
    finally
      Free;
    end;
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
      hosts.AsArray.Add(host.S['uuid']);

    //edit_hosts_depends(waptconfigfile,hosts_list,appends,removes,key_password=None,wapt_server_user=None,wapt_server_passwd=None)
    args := '';
    args := args + format('waptconfigfile = r"%s".decode(''utf8''),', [AppIniFilename]);
    args := args + format('hosts_list = r"%s".decode(''utf8''),',
      [soutils.Join(',', hosts)]);
    if dmpython.privateKeyPassword <> '' then
      args := args + format('key_password = "%s".decode(''utf8''),',
        [dmpython.privateKeyPassword]);
    args := args + format('wapt_server_user = r"%s".decode(''utf8''),', [waptServerUser]);
    args := args + format('wapt_server_passwd = r"%s".decode(''utf8''),',
      [waptServerPassword]);
    res := DMPython.RunJSON(format('waptdevutils.add_ads_groups(%s)', [args]));
    ShowMessageFmt(rsNbModifiedHosts, [IntToStr(res.AsArray.Length)]);
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TVisWaptGUI.ActAddDependsExecute(Sender: TObject);
var
  Res, packages, hosts: ISuperObject;
  ResVar,VarHosts,VarPackages: Variant;
begin
  if GridHosts.Focused then
  begin
    with TvisGroupChoice.Create(self) do
    try
      Caption := rsSelectAddDepends;
      res := Nil;

      if ShowModal = mrOk then
      try
        Screen.Cursor := crHourGlass;
        packages := SelectedPackages;
        Hosts := ExtractField(GridHosts.SelectedRows,'uuid');

        VarHosts := SuperObjectToPyVar(Hosts);
        VarPackages := SuperObjectToPyVar(packages);

        resVar := DMPython.waptdevutils.edit_hosts_depends(
           waptconfigfile := AppIniFilename(),
           hosts_list := VarHosts,
           append_depends := VarPackages,
           key_password := dmpython.privateKeyPassword,
           wapt_server_user := waptServerUser,
           wapt_server_passwd := waptServerPassword
           );

        res := PyVarToSuperObject(ResVar);
        ShowMessageFmt(rsNbModifiedHosts, [res.A['updated'].Length,res.A['discarded'].Length,res.A['unchanged'].Length]);
      finally
        Screen.cursor := crDefault;
      end;
    finally
      Free;
    end;
  end;
end;

procedure TVisWaptGUI.ActAddDependsUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled:=(GridHosts.SelectedCount>0);
end;

procedure TVisWaptGUI.ActAddHWPropertyToGridExecute(Sender: TObject);
var
  propname: string;
  col: TSOGridColumn;
begin
  // drop d'un nouvel attribut
  propname := GridhostInventory.Path(GridhostInventory.FocusedNode, 0, ttNormal, '/');
  propname := copy(propname, 1, length(propname) - 1);
  col := Gridhosts.FindColumnByPropertyName(propname);
  if col = nil then
  begin
    col := Gridhosts.Header.Columns.Add as TSOGridColumn;
    col.Text := propname;
    col.PropertyName := propname;
    col.Width := 100;
    GridHosts.FocusedColumn :=  col.Index;
    ActSearchHost.Execute;
    GridHosts.SetFocus;
  end;
end;

procedure TVisWaptGUI.ActAddHWPropertyToGridUpdate(Sender: TObject);
var
  propname: string;
begin
  propname := GridhostInventory.Path(GridhostInventory.FocusedNode, 0, ttNormal, '/');
  propname := copy(propname, 1, length(propname) - 1);

  ActAddHWPropertyToGrid.Enabled := (propname <>'') and (GridHosts.FindColumnByPropertyName(propname) = nil);
end;

procedure TVisWaptGUI.ActCancelRunningTaskExecute(Sender: TObject);
var
  uuids: ISuperObject;
  currhost: ansistring;
begin
  if GridHosts.FocusedRow<>Nil then
  begin
    uuids := TSuperObject.Create(stArray);;
    currhost := GridHosts.FocusedRow.S['uuid'];
    uuids.AsArray.Add(currhost);
    TriggerActionOnHosts(uuids,'trigger_cancel_all_tasks',Nil,'Cancel all tasks','Error cancelling tasks');
  end;
end;

procedure TVisWaptGUI.ActChangePasswordExecute(Sender: TObject);
var
  cred,sores:ISuperObject;
begin
  with TvisChangePassword.Create(self) do
  try
    if ShowModal = mrOk then
    begin
      cred := SO();
      cred.S['user'] := waptServerUser;
      cred.S['password'] := UTF8Decode(WaptServerPassword);
      cred.S['new_password'] := UTF8Decode(EdNewPassword1.Text);
      try
        sores := WAPTServerJsonPost('api/v3/change_password', [], cred);
        if sores.B['success'] then
        begin
          waptServerPassword := EdNewPassword1.Text;
          if Assigned(WaptServerSession) then
            FreeAndNil(WaptServerSession);
          ShowMessage(rsPasswordChangeSuccess);
        end
        else
          ShowMessageFmt(rsPasswordChangeError, [UTF8Encode(sores.S['msg'])]);
      except
        on E: Exception do
          ShowMessageFmt(rsPasswordChangeError, [UTF8Encode(E.Message)]);
      end;
    end;
  finally
    Free;
  end;
end;

procedure TVisWaptGUI.ActChangePasswordUpdate(Sender: TObject);
begin
  ActChangePassword.Enabled :=  (WaptServerUser='admin') and EnableManagementFeatures;
end;

procedure TVisWaptGUI.ActChangePrivateKeypasswordExecute(Sender: TObject);
begin
  with TVisChangeKeyPassword.Create(self) do
  try
    ShowModal;
  finally
    Free;
  end;
end;

procedure TVisWaptGUI.ActChangePrivateKeypasswordUpdate(Sender: TObject);
begin
  ActChangePrivateKeypassword.Enabled := FileExists(GetWaptPersonalCertificatePath);
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

procedure TVisWaptGUI.ActComputerMgmtExecute(Sender: TObject);
var
  ip: ansistring;
begin
  if (Gridhosts.FocusedRow <> nil) and
    (Gridhosts.FocusedRow.S['connected_ips'] <> '') then
  begin
    ip := GetReachableIP(Gridhosts.FocusedRow['connected_ips'],135);
    if ip <> '' then
      ShellExecute(0, '', PAnsiChar('compmgmt.msc'), PAnsichar(' -a /computer=' + ip), nil, SW_SHOW)
    else
      ShowMessage(rsNoreachableIP);
  end;
end;

procedure TVisWaptGUI.ActComputerMgmtUpdate(Sender: TObject);
begin
  try
    ActComputerMgmt.Enabled := (Gridhosts.FocusedRow <> nil) and (Gridhosts.FocusedRow.S['connected_ips']<>'');
  except
    ActComputerMgmt.Enabled := False;
  end;

end;

procedure TVisWaptGUI.ActComputerServicesExecute(Sender: TObject);
var
  ip: ansistring;
begin
  if (Gridhosts.FocusedRow <> nil) and
    (Gridhosts.FocusedRow.S['connected_ips'] <> '') then
  begin
    ip := GetReachableIP(Gridhosts.FocusedRow['connected_ips'],135);
    if ip <> '' then
      ShellExecute(0, '', PAnsiChar('services.msc'), PAnsichar(' -a /computer=' + ip), nil, SW_SHOW)
    else
      ShowMessage(rsNoreachableIP);
  end;
end;

procedure TVisWaptGUI.ActComputerServicesUpdate(Sender: TObject);
begin
  try
    ActComputerServices.Enabled := (Gridhosts.FocusedRow <> nil) and (Gridhosts.FocusedRow.S['connected_ips']<>'');
  except
   ActComputerServices.Enabled := False;
  end;

end;

procedure TVisWaptGUI.ActComputerUsersExecute(Sender: TObject);
var
  ip: ansistring;
begin
  if (Gridhosts.FocusedRow <> nil) and
    (Gridhosts.FocusedRow.S['connected_ips'] <> '') then
  begin
    ip := GetReachableIP(Gridhosts.FocusedRow['connected_ips'],135);
    if ip <> '' then
      ShellExecute(0, '', PAnsiChar('Lusrmgr.msc'), PAnsichar(' -a /computer=' + ip), nil, SW_SHOW)
    else
      ShowMessage(rsNoreachableIP);
  end;
end;

procedure TVisWaptGUI.ActComputerUsersUpdate(Sender: TObject);
begin
  try
    ActComputerUsers.Enabled := (Gridhosts.FocusedRow <> nil) and (Gridhosts.FocusedRow.S['connected_ips']<>'');
  except
    ActComputerUsers.Enabled := False;
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
          res := WAPTServerJsonGet('delete_package/%S',[group]);
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
  packages,res: ISuperObject;
begin
  if GridPackages.SelectedCount > 1 then
    message := Format(rsConfirmRmMultiplePackages,[GridPackages.SelectedCount]);

  if MessageDlg(rsConfirmDeletion, message, mtConfirmation,
    mbYesNoCancel, 0) = mrYes then

  with TVisLoading.Create(Self) do
    try
      ProgressTitle(rsDeletionInProgress);
      packages := soutils.ExtractField(GridPackages.SelectedRows,'filename');
      ProgressTitle(format(rsDeletingElement, [Join(',',packages) ]));
      res := WAPTServerJsonPost('/api/v3/packages_delete',[],packages);
      if not res.B['success'] then
         ShowMessageFmt('Error deleting packages: %S',[UTF8Encode(res.S['msg'])]);
      ProgressTitle(rsUpdatingPackageList);
      ActPackagesUpdate.Execute;
      ProgressTitle(rsDisplaying);
    finally
      Free;
    end;
end;

procedure TVisWaptGUI.ActDeletePackageUpdate(Sender: TObject);
begin
  ActDeletePackage.Enabled := GridPackages.Focused and (GridPackages.SelectedCount > 0);
end;

procedure TVisWaptGUI.ActDisplayPreferencesExecute(Sender: TObject);
var
  inifile: TIniFile;
  lang:String;
  oldlimit:Integer;
begin
  inifile := TIniFile.Create(AppIniFilename);
  try
    With TVisDisplayPreferences.Create(self) do
    try
      EdHostsLimit.Text := IntToStr(HostsLimit);
      oldlimit:=HostsLimit;
      cbEnableExternalTools.Checked :=
        inifile.ReadBool('global', 'enable_external_tools', EnableExternalTools);

      cbEnableManagementFeatures.Checked :=
        inifile.ReadBool('global', 'enable_management_features', EnableManagementFeatures);

      cbHideUnavailableActions.Checked :=
        inifile.ReadBool('global', 'hide_unavailable_actions', HideUnavailableActions);

      cbDebugWindow.Checked:= inifile.ReadBool('global','advanced_mode',AdvancedMode);

      lang := inifile.ReadString('global','language','en');
      if lang='en' then
        cbLanguage.ItemIndex:=0
      else if lang='fr' then
        cbLanguage.ItemIndex:=1
      else if lang='de' then
        cbLanguage.ItemIndex:=2
      else
        cbLanguage.ItemIndex:=0;

      if ShowModal = mrOk then
      begin
        if EdHostsLimit.Text='' then EdHostsLimit.Text:='1000';
        HostsLimit:=StrToInt(EdHostsLimit.Text);

        inifile.WriteBool('global', 'enable_external_tools',
          cbEnableExternalTools.Checked);

        inifile.WriteBool('global', 'enable_management_features',
          cbEnableManagementFeatures.Checked);

        inifile.WriteBool('global', 'hide_unavailable_actions',
          cbHideUnavailableActions.Checked);

        if cbLanguage.ItemIndex=0 then
          DMPython.Language := 'en'
        else if cbLanguage.ItemIndex=1 then
          DMPython.Language := 'fr'
        else if cbLanguage.ItemIndex=2 then
          DMPython.Language := 'de'
        else
          DMPython.Language := '';

        inifile.WriteString('global','language',DMPython.Language);

        inifile.WriteBool('global', 'advanced_mode',cbDebugWindow.Checked);

        AdvancedMode := cbDebugWindow.Checked;
        pgSources.TabVisible := AdvancedMode;
        PanDebug.Visible := AdvancedMode;

        Gridhosts.ShowAdvancedColumnsCustomize:= AdvancedMode;
        GridGroups.ShowAdvancedColumnsCustomize:=AdvancedMode;
        GridPackages.ShowAdvancedColumnsCustomize:=AdvancedMode;
        GridHostPackages.ShowAdvancedColumnsCustomize:=AdvancedMode;


        EnableExternalTools := cbEnableExternalTools.Checked;
        EnableManagementFeatures := cbEnableManagementFeatures.Checked;
        HideUnavailableActions := cbHideUnavailableActions.Checked;

        if HostsLimit>oldlimit then
          ActSearchHost.Execute;
      end;
    finally
      Free;
    end;

  finally
    inifile.Free;
  end;
end;

procedure TVisWaptGUI.ActDisplayUserMessageExecute(Sender: TObject);
var
  AMessage: String;
  DisplayTime:Integer;
  args:ISuperObject;
begin
  if (GridHosts.SelectedCount>=1) then
  begin
    AMessage := InputBox(rsShowMessageForUsers,rsMessageToSend,'');
    if AMessage <> '' then
    begin
      Args := SO();
      Args.S['msg'] := UTF8Decode(AMessage);
      Args.I['display_time'] := 30;
      TriggerActionOnHosts(ExtractField(GridHosts.SelectedRows,'uuid'),'show_message',Args,rsShowMessageForUsers,'Error displaying message to users',True,False)
    end;
  end;

end;

procedure TVisWaptGUI.ActEditGroupUpdate(Sender: TObject);
begin
  ActEditGroup.Enabled:=GridGroups.SelectedCount=1;
end;

procedure TVisWaptGUI.ActEditHostPackageUpdate(Sender: TObject);
begin
  ActEditHostPackage.Enabled:=(GridHosts.SelectedCount=1);
end;

procedure TVisWaptGUI.ActForgetPackagesUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled:=OneHostIsConnected;
end;

procedure TVisWaptGUI.ActGermanExecute(Sender: TObject);
begin
  DMPython.Language:='de';
end;

procedure TVisWaptGUI.ActGermanUpdate(Sender: TObject);
begin
  ActGerman.Checked := DMPython.Language='de';
end;

procedure TVisWaptGUI.ActHostsDeletePackageUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled:=(GridHosts.SelectedCount>0);
end;

procedure TVisWaptGUI.ActHostsDeleteUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled:=(GridHosts.SelectedCount>0);

end;

procedure TVisWaptGUI.ActLaunchGPUpdateExecute(Sender: TObject);
begin
  if (GridHosts.SelectedCount>=1) and
    (MessageDlg(Format(rsConfirmGPUpdate,[GridHosts.SelectedCount]),mtConfirmation,mbYesNoCancel, 0) = mrYes) then
      TriggerActionOnHosts(ExtractField(GridHosts.SelectedRows,'uuid'),'trigger_gpupdate',Nil,rsRunningGPUpdate,'Error updating Group Policies',True,False)
end;

procedure TVisWaptGUI.ActLaunchWaptExitExecute(Sender: TObject);
begin
  if (GridHosts.SelectedCount>=1) and
    (MessageDlg(Format(rsConfirmWaptExit,[GridHosts.SelectedCount]),mtConfirmation,mbYesNoCancel, 0) = mrYes) then
      TriggerActionOnHosts(ExtractField(GridHosts.SelectedRows,'uuid'),'start_waptexit',Nil,rsUpgradingHost,'Error starting waptexit.exe',True,False)

end;

procedure TVisWaptGUI.ActmakePackageTemplateExecute(Sender: TObject);
begin
  MakePackageTemplate('');
end;

procedure TVisWaptGUI.ActPackagesForceInstallExecute(Sender: TObject);
begin
  TriggerActionOnHostPackages('trigger_install_packages',rsConfirmPackageInstall,rsPackageInstallError,True);
end;

procedure TVisWaptGUI.ActPackagesInstallUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled:=OneHostIsConnected;
end;

procedure TVisWaptGUI.ActPackagesRemoveUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled:=OneHostIsConnected and FileExists(GetWaptPersonalCertificatePath);
end;

procedure TVisWaptGUI.ActPackagesUpdateUpdate(Sender: TObject);
begin
  ActPackagesUpdate.Enabled:=FileExists(GetWaptPersonalCertificatePath);
end;

procedure TVisWaptGUI.ActProprietaryExecute(Sender: TObject);
begin
  {$ifdef ENTERPRISE}
  IsEnterpriseEdition := not IsEnterpriseEdition;
  ActProprietary.Checked := IsEnterpriseEdition;
  {$endif}
end;

procedure TVisWaptGUI.ActRemoteAssistExecute(Sender: TObject);
var
  ip: ansistring;
begin
  if (Gridhosts.FocusedRow <> nil) and
    (Gridhosts.FocusedRow.S['connected_ips'] <> '') then
  begin
    ip := GetReachableIP(Gridhosts.FocusedRow['connected_ips'],3389);
    if ip <> '' then
      ShellExecute(0, '', PAnsiChar('msra'), PAnsichar('/offerRA ' + ip), nil, SW_SHOW)
    else
      ShowMessage(rsNoreachableIP);
  end;
end;

procedure TVisWaptGUI.ActRemoteAssistUpdate(Sender: TObject);
begin
  try
    ActRemoteAssist.Enabled := (Gridhosts.FocusedRow <> nil) and (Gridhosts.FocusedRow.S['connected_ips']<>'');
  except
    ActRemoteAssist.Enabled := False;
  end;

end;

procedure TVisWaptGUI.ActExternalRepositoriesSettingsExecute(Sender: TObject);
begin
  With TVisRepositories.Create(Self) do
  try
    if ShowModal = mrOk then
      actRefresh.Execute;
  finally
    Free;
  end;
end;

function TVisWaptGUI.OneHostHasConnectedIP:Boolean;
var
  host : ISuperObject;
begin
  Result:=False;
  for host in GridHosts.SelectedRows do
  begin
    if Host.S['connected_ips'] <> '' then
    begin
      Result := True;
      Break
    end;
  end;
end;

procedure TVisWaptGUI.ActTISHelpUpdate(Sender: TObject);
begin
  ActTISHelp.Enabled:=FileExists(GetTisSupportPath) and OneHostHasConnectedIP;
end;

procedure TVisWaptGUI.ActTriggerBurstUpdatesExecute(Sender: TObject);
begin
  if (GridHosts.SelectedCount>=1) and
    (MessageDlg(Format(rsConfirmBurstUpdate,[GridHosts.SelectedCount]),mtConfirmation,mbYesNoCancel, 0) = mrYes) then
      TriggerActionOnHosts(ExtractField(GridHosts.SelectedRows,'uuid'),'trigger_host_update',Nil,rsTriggerHostsUpdate,'Error checking for updates',True)
end;

procedure TVisWaptGUI.ActTriggerBurstUpgradesExecute(Sender: TObject);
begin
  if (GridHosts.SelectedCount>=1) and
    (MessageDlg(Format(rsConfirmBurstUpgrades,[GridHosts.SelectedCount]),mtConfirmation,mbYesNoCancel, 0) = mrYes) then
      TriggerActionOnHosts(ExtractField(GridHosts.SelectedRows,'uuid'),'trigger_host_upgrade',Nil,rsUpgradingHost,'Error applying upgrades',True)

end;

procedure TVisWaptGUI.ActTriggerWakeOnLanExecute(Sender: TObject);
var
  data: ISuperObject;
begin
  data := SO();
  data['uuids'] := GetSelectedUUID;
  HandleServerResult(WAPTServerJsonPost('api/v3/trigger_wakeonlan',[],data));
end;

procedure TVisWaptGUI.ActTriggerWaptwua_downloadExecute(Sender: TObject);
begin
    with TVisHostsUpgrade.Create(Self) do
    try
      Caption:= rsTriggerWAPTWUA_Scan;
      action := 'api/v3/trigger_waptwua_download';
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
      action := 'api/v3/trigger_waptwua_install';
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
      action := 'api/v3/trigger_waptwua_scan';
      hosts := Gridhosts.SelectedRows;

      if ShowModal = mrOk then
        actRefresh.Execute;
    finally
      Free;
    end;

end;

procedure TVisWaptGUI.ActWSUSDowloadWSUSScanExecute(Sender: TObject);
{$ifdef wsus}
var
  res:ISuperObject;
  skipped:Boolean;
  cabsize,forced:Integer;
  cabdate:String;
{$endif wsus}
begin
  {$ifdef wsus}
  forced := 0;
  if cbForcedWSUSscanDownload.Checked then
    forced:=1
  else
  begin
    res := WAPTServerJsonGet('api/v2/wsusscan2_history?limit=1&skipped=0',[]);
    if res.B['success'] and (res.A['result'].Length>0) and not StrIsOneOf(res.S['result[0].status'],['finished','error'],False) then
    begin
      if MessageDlg(rsConfirmCaption,'A download task is already in progress, do you still want to append a task ?',mtConfirmation, mbYesNoCancel,0) <> mrYes then
        Exit;
    end;
  end;
  res := WAPTServerJsonGet('api/v2/download_wsusscan?force=%D',[forced]);
  ActWSUSRefreshCabHistory.Execute;
  skipped := res.B['result.skipped'];
  if skipped then
    wsusResult.Text := 'Download skipped'
  else
  begin
    cabsize := res.I['result.file_size'];
    cabdate := DateTimeToStr(FileDateToDateTime(res.I['result.file_timestamp']));
    wsusResult.Text := res.S['result.status']+' started on '+res.S['result.run_date']+' file size:'+IntToStr(cabsize)+' wsusscan date:'+cabdate;
  end;
  {$endif wsus}
end;

procedure TVisWaptGUI.ActWSUSRefreshCabHistoryExecute(Sender: TObject);
{$ifdef wsus}
var
  res,wuares:ISuperObject;
  {$endif wsus}
begin
  {$ifdef wsus}
  res := WAPTServerJsonGet('api/v2/wsusscan2_history?limit=30',[]);
  if res.B['success'] then
  begin
    Clipboard.AsText:=res['result'].AsJSon(True);
    GridWSUSScan.Data := res['result']
  end
  else
    GridWSUSScan.Data := Nil;

  if not windows_updates_rulesUpdated then
  begin
    res := WAPTServerJsonGet('api/v2/windows_updates_rules?group=default',[]);
    if res.B['success'] and (res.A['result']<>Nil) and (res.A['result'].Length>0) then
    begin
      GridWSUSAllowedClassifications.Data := WAPTServerJsonGet('api/v2/windows_updates_classifications?id=%s',[join(',',res.A['result'][0]['rules.allowed_classifications'])])['result'];
      GridWSUSAllowedWindowsUpdates.Data := WAPTServerJsonGet('api/v2/windows_updates?update_ids=%s',[join(',',res.A['result'][0]['rules.allowed_windows_updates'])])['result'];
      GridWSUSForbiddenWindowsUpdates.Data := WAPTServerJsonGet('api/v2/windows_updates?update_ids=%s',[join(',',res.A['result'][0]['rules.forbidden_windows_updates'])])['result'];
      windows_updates_rulesUpdated := False;
    end
    else
    begin
      GridWSUSAllowedClassifications.Data := Nil;
      GridWSUSAllowedWindowsUpdates.Data := Nil;
      GridWSUSForbiddenWindowsUpdates.Data := Nil;
      windows_updates_rulesUpdated := False;
    end;
  end
  else
    ShowMessage('Warning : Windows updates rules not saved');
  {$endif wsus}
end;

procedure TVisWaptGUI.ActWSUSSaveBuildRulesExecute(Sender: TObject);
{$ifdef wsus}
var
  wsus_rules,WUAGroupRules,res,sores :ISuperObject;
  args:AnsiString;
  {$endif wsus}
begin
  {$ifdef wsus}
  wsus_rules := TSuperObject.Create();
  WUAGroupRules := TSuperObject.Create();
  WUAGroupRules['allowed_classifications'] := ExtractField(GridWSUSAllowedClassifications.Data,'id');
  WUAGroupRules['allowed_windows_updates'] := ExtractField(GridWSUSAllowedWindowsUpdates.Data,'update_id');
  WUAGroupRules['forbidden_windows_updates'] := ExtractField(GridWSUSForbiddenWindowsUpdates.Data,'update_id');
  wsus_rules.S['group'] := 'default';//WUAGroup;
  wsus_rules['rules']   := WUAGroupRules;
  res := WAPTServerJsonPost('api/v2/windows_updates_rules?group=%s',[wsus_rules.S['group']],wsus_rules);

  windows_updates_rulesUpdated := not res.B['success'];

  if res.B['success'] then
  //update the wua package...
  try
    Screen.Cursor := crHourGlass;
    //edit_hosts_depends(waptconfigfile,hosts_list,appends,removes,key_password=None,wapt_server_user=None,wapt_server_passwd=None)
    args := '';
    args := args + format('waptconfigfile = r"%s".decode(''utf8''),', [AppIniFilename]);
    args := args + format('wuagroup = r"%s".decode(''utf8''),',
      ['default']);
    if dmpython.privateKeyPassword <> '' then
      args := args + format('key_password = "%s".decode(''utf8''),',
        [dmpython.privateKeyPassword]);
    args := args + format('wapt_server_user = r"%s".decode(''utf8''),', [waptServerUser]);
    args := args + format('wapt_server_passwd = r"%s".decode(''utf8''),',
      [waptServerPassword]);
    res := DMPython.RunJSON(format('waptdevutils.create_waptwua_package(%s)', [args]));
    ShowMessage('WUA Package properly created');
  finally
    Screen.Cursor := crDefault;
  end
  else
  begin
    ShowMessageFmt('Unable to save Windows Updates Rules : %s'#13#10'data:%s',[res.B['error'],wsus_rules.AsJSon(True)]);
    Clipboard.AsText:=wsus_rules.AsJSon(True);
  end;
  {$endif wsus}
end;

procedure TVisWaptGUI.ActWSUSSaveBuildRulesUpdate(Sender: TObject);
begin
  {$ifdef wsus}
  ActWSUSSaveBuildRules.Enabled := windows_updates_rulesUpdated;
  {$endif wsus}
end;

procedure TVisWaptGUI.ActWUAAddAllowedClassificationExecute(Sender: TObject);
{$ifdef wsus}
var
  r:ISuperObject;
  {$endif wsus}
begin
  {$ifdef wsus}
  With TVisWUAClassificationsSelect.Create(Self) do
  try
    if ShowModal = mrOk then
    begin
      if GridWSUSAllowedClassifications.Data = Nil then
        GridWSUSAllowedClassifications.Data :=  TSuperObject.Create(stArray);
      for r in GridWinClassifications.SelectedRows do
      begin
        if SOArrayFindFirst(r,GridWSUSAllowedClassifications.Data,['id']) = Nil then
        begin
          GridWSUSAllowedClassifications.Data.AsArray.Add(r);
          windows_updates_rulesUpdated := True;
        end;
      end;
    end;
  finally
    GridWSUSAllowedClassifications.LoadData;
    Free;
  end;
  {$endif wsus}
end;


procedure TVisWaptGUI.ActWUAAddAllowedUpdateExecute(Sender: TObject);
{$ifdef wsus}
var
  r:ISuperObject;
  {$endif wsus}
begin
  {$ifdef wsus}
  With TVisWUAPackageSelect.Create(Self) do
  try
    if ShowModal = mrOk then
    begin
      if GridWSUSAllowedWindowsUpdates.Data = Nil then
        GridWSUSAllowedWindowsUpdates.Data :=  TSuperObject.Create(stArray);
      for r in GridWinUpdates.SelectedRows do
      begin
        if SOArrayFindFirst(r,GridWSUSAllowedWindowsUpdates.Data,['update_id']) = Nil then
        begin
          GridWSUSAllowedWindowsUpdates.Data.AsArray.Add(r);
          windows_updates_rulesUpdated := True;
        end;
      end;
    end;
  finally
    GridWSUSAllowedWindowsUpdates.LoadData;
    Free;
  end;
  {$endif wsus}
end;

procedure TVisWaptGUI.ActWUAAddForbiddenUpdateExecute(Sender: TObject);
{$ifdef wsus}
var
  r:ISuperObject;
  {$endif wsus}
begin
  {$ifdef wsus}
  With TVisWUAPackageSelect.Create(Self) do
  try
    if ShowModal = mrOk then
    begin
      if GridWSUSForbiddenWindowsUpdates.Data = Nil then
        GridWSUSForbiddenWindowsUpdates.Data :=  TSuperObject.Create(stArray);
      for r in GridWinUpdates.SelectedRows do
      begin
        if SOArrayFindFirst(r,GridWSUSForbiddenWindowsUpdates.Data,['update_id']) = Nil then
        begin
          GridWSUSForbiddenWindowsUpdates.Data.AsArray.Add(r);
          windows_updates_rulesUpdated := True;
        end;
      end;
    end;
  finally
    GridWSUSForbiddenWindowsUpdates.LoadData;
    Free;
  end;
  {$endif wsus}
end;


procedure TVisWaptGUI.ActWUADownloadSelectedUpdateUpdate(Sender: TObject);
begin
  {$ifdef wsus}
  (Sender as TAction).Enabled:=GridWSUSAllowedWindowsUpdates.SelectedCount>0;
  {$endif wsus}
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
    if EditGroup(Selpackage, AdvancedMode) <> nil then
      ActPackagesUpdate.Execute;
  end;
end;

procedure TVisWaptGUI.ActEditHostPackageExecute(Sender: TObject);
var
  hostname,uuid,desc,HostPackageVersion: String;
  uuids,result: ISuperObject;
  ApplyUpdatesImmediately:Boolean;
  Host: ISuperObject;
  Package,HostPackages:ISuperObject;
begin
  if GridHosts.FocusedRow<>Nil then
  try
    host := GridHosts.FocusedRow;
    hostname := host.S['computer_fqdn'];
    uuid := host.S['uuid'];
    desc := host.S['description'];
    uuids := TSuperobject.create(stArray);
    uuids.AsArray.Add(uuid);

    HostPackageVersion :='';
    HostPackages := host['installed_packages'];
    if HostPackages <> Nil then
    begin
      for Package in HostPackages do
      begin
        if Package.S['package'] = uuid then
        begin
          HostPackageVersion := Package.S['version'];
          break;
        end;
      end;
    end;

    result := EditHost(uuid, AdvancedMode, ApplyUpdatesImmediately, UTF8Encode(desc),host.S['reachable'] = 'OK',hostname,HostPackageVersion);
    if (result<>Nil) and ApplyUpdatesImmediately and (uuid<>'')  then
      result := TriggerActionOnHosts(uuids,'trigger_host_upgrade',Nil,rsUpgradingHost,rsErrorLaunchingUpgrade);

  except
    on E:Exception do
      ShowMessageFmt(rsEditHostError+#13#10#13#10+e.Message,[hostname]);
  end;
end;

procedure TVisWaptGUI.ActEnglishExecute(Sender: TObject);
begin
  DMPython.Language:='en';
end;

procedure TVisWaptGUI.HandleServerResult(ServerResult:ISuperObject);
begin
  if (ServerResult<>Nil) and ServerResult.AsObject.Exists('success') then
  begin
    MemoLog.Append(ServerResult.AsString);
    if ServerResult.AsObject.Exists('msg') then
      ShowMessage(ServerResult.S['msg']);
  end
  else
    if not ServerResult.B['success'] or (ServerResult['result'].A['errors'].Length>0) then
      Raise Exception.Create(ServerResult.S['msg']);
end;

procedure TVisWaptGUI.ActEnglishUpdate(Sender: TObject);
begin
  ActEnglish.Checked := DMPython.Language='en';
end;

function TVisWaptGUI.TriggerActionOnHosts(uuids: ISuperObject;AAction:String;Args:ISuperObject;title,errortitle:String;Force:Boolean=False;NotifyServer:Boolean=True):ISuperObject;
var
  host_uuid,ArgKey : ISuperObject;
  SOAction, SOActions:ISuperObject;
  actions_json,
  signed_actions_json:String;
begin
  try
    Screen.Cursor:=crHourGlass;
    try
      SOActions := TSuperObject.Create(stArray);

      for host_uuid in uuids do
      begin
        SOAction := SO();
        SOAction.S['action'] := AAction;
        SOAction.S['uuid'] := host_uuid.AsString;
        SOAction.B['notify_server'] := NotifyServer;
        SOAction.B['force'] := Force;
        if Args<>Nil then
          for ArgKey in Args.AsObject.GetNames() do
            SOAction[ArgKey.AsString] := Args[ArgKey.AsString];
        SOActions.AsArray.Add(SOAction);
      end;

      //transfer actions as json string to python
      actions_json := SOActions.AsString;
      signed_actions_json := VarPythonAsString(DMPython.waptdevutils.sign_actions(
        actions:=actions_json, certfilename:=GetWaptPersonalCertificatePath(),key_password:= dmpython.privateKeyPassword));
      SOActions := SO(signed_actions_json);

      result := WAPTServerJsonPost('/api/v3/trigger_host_action?timeout=%D',[waptservice_timeout],SOActions);
      if (result<>Nil) and result.AsObject.Exists('success') then
      begin
        MemoLog.Append(result.AsString);
        if result.AsObject.Exists('msg') and (title<>'') then
        begin
          ShowMessage(copy(result.S['msg'],1,250));
        end;
      end
      else
        if not result.B['success'] or (result['result'].A['errors'].Length>0) then
          Raise Exception.Create(result.S['msg']);
    except
      on E:Exception do
        ShowMessage(Format(errortitle,
            [ e.Message]));
    end;

  finally
    Screen.Cursor:=crDefault;
  end;
end;


procedure TVisWaptGUI.TriggerActionOnHostPackages(AAction,title,errortitle:String;Force:Boolean=False);
var
  sel, packages : ISuperObject;
  SOAction, SOActions,res,host:ISuperObject;
  actions_json,
  keypassword:String;
  signed_actions_json:String;
begin
  if GridHostPackages.Focused and (GridHosts.FocusedRow <> Nil) then
  begin
    sel := GridHostPackages.SelectedRows;
    if Dialogs.MessageDlg(
       rsConfirmCaption,
       format(title, [IntToStr(sel.AsArray.Length), Join(',',ExtractField(GridHosts.SelectedRows,'computer_fqdn'))]),
       mtConfirmation,
       mbYesNoCancel,
       0) = mrYes then
    begin
      packages := ExtractField(sel,'package');
      try
        SOActions := TSuperObject.Create(stArray);
        for host in GridHosts.SelectedRows do
        begin
          SOAction := SO();
          SOAction.S['action'] := AAction;
          SOAction.S['uuid'] := host.S['uuid'];
          SOAction.B['notify_server'] := True;
          SOAction.B['force'] := Force;
          SOAction['packages'] := packages;
          SOActions.AsArray.Add(SOAction);
        end;

        //transfer actions as json string to python
        actions_json := SOActions.AsString;
        keypassword := dmpython.privateKeyPassword;
        signed_actions_json := VarPythonAsString(DMPython.waptdevutils.sign_actions(
          actions:=actions_json, certfilename:=GetWaptPersonalCertificatePath(),key_password:=keypassword));
        SOActions := SO(signed_actions_json);

        res := WAPTServerJsonPost('/api/v3/trigger_host_action?timeout=%D',[waptservice_timeout],SOActions);
        if (res<>Nil) and res.AsObject.Exists('success') then
        begin
          MemoLog.Append(res.AsString);
          if res.AsObject.Exists('msg') then
            ShowMessage(res.S['msg']);
        end
        else
          if not res.B['success'] or (res['result'].A['errors'].Length>0) then
            Raise Exception.Create(res.S['msg']);
      except
        on E:Exception do
          ShowMessage(Format(errortitle,
              [ Join(',',packages),e.Message]));
      end;
    end;
    UpdateHostPages(Nil);
  end;
end;

procedure TVisWaptGUI.ActPackagesForgetExecute(Sender: TObject);
begin
  TriggerActionOnHostPackages('trigger_forget_packages',rsConfirmHostForgetsPackages,rsForgetPackageError);
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
  OpenDocument('https://wapt.fr/fr/doc-1.5/');
end;


function TVisWaptGUI.OneHostIsConnected:Boolean;
var
  host : ISuperObject;
begin
  Result:=False;
  for host in GridHosts.SelectedRows do
  begin
    if Host.S['reachable'] = 'OK' then
    begin
      Result := True;
      Break;
    end;
  end;
end;


procedure TVisWaptGUI.ActHostsActionsUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled:= (GridHosts.SelectedCount>0) and OneHostIsConnected and FileExists(GetWaptPersonalCertificatePath);
end;

procedure TVisWaptGUI.ActImportFromFileExecute(Sender: TObject);
var
  i: integer;
  sourceDir: string;
  Sources, uploadResult: ISuperObject;
  SourcesVar: Variant;

begin
  if not FileExists(GetWaptPersonalCertificatePath) then
  begin
    ShowMessageFmt(rsPrivateKeyDoesntExist, [GetWaptPersonalCertificatePath]);
    exit;
  end;

  if DefaultPackagePrefix='' then
  begin
    ShowMessage(rsWaptPackagePrefixMissing);
    ActWAPTConsoleConfig.Execute;
    Exit;
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
          sourceDir := VarPythonAsString(DMPython.waptdevutils.duplicate_from_file(
            package_filename := OpenDialogWapt.Files[i],new_prefix:=DefaultPackagePrefix));
          //sources.AsArray.Add('r"' + sourceDir + '"');
          sources.AsArray.Add(sourceDir);
        end;

        ProgressTitle(format(rsUploadingPackagesToWaptSrv, [IntToStr(Sources.AsArray.Length)]));
        Application.ProcessMessages;

        SourcesVar := SuperObjectToPyVar(sources);
        { TODO : Remove use of WAPT instance, use waptpackage.PackageEntry instead }
        uploadResult := PyVarToSuperObject(DMPython.WAPT.build_upload(
          sources_directories := SourcesVar,
          private_key_passwd := dmpython.privateKeyPassword,
          wapt_server_user := waptServerUser,
          wapt_server_passwd := waptServerPassword,
          inc_package_release := False));

        if (uploadResult <> nil) and
          (uploadResult.AsArray.length = Sources.AsArray.Length) then
        begin
          ShowMessage(format(rsSuccessfullyImported,
            [soutils.Join(',', Sources)]));
          ModalResult := mrOk;
          ActPackagesUpdate.Execute;
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
  try
    if ShowModal = mrOk then
    begin
      ActPackagesUpdate.Execute;
    end;
  finally
    Free;
  end;
end;

procedure TVisWaptGUI.ActWUALoadUpdatesExecute(Sender: TObject);
{$ifdef wsus}
var
  soresult,winupdates,winupdate,urlParams,product,products,idx,severities: ISuperObject;
  update_id:String;
{$endif wsus}
begin
  {$ifdef wsus}
  Screen.Cursor:=crHourGlass;
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

    GridWSUSAllowedWindowsUpdates.Data := winupdates;

  finally
    Screen.Cursor:=crDefault;
  end;
  {$endif wsus}
end;

procedure TVisWaptGUI.ActWUALoadUpdatesUpdate(Sender: TObject);
begin
  {$ifdef wsus}
  ActWUALoadUpdates.Enabled:=GridWinproducts.SelectedCount>0;
  {$endif wsus}
end;

procedure TVisWaptGUI.ActPackagesInstallExecute(Sender: TObject);
begin
  TriggerActionOnHostPackages('trigger_install_packages',rsConfirmPackageInstall,rsPackageInstallError);
end;

procedure TVisWaptGUI.ActPackagesRemoveExecute(Sender: TObject);
begin
  TriggerActionOnHostPackages('trigger_remove_packages',rsConfirmRmPackagesFromHost,rsPackageRemoveError);
end;

procedure TVisWaptGUI.ActRDPExecute(Sender: TObject);
var
  ip: ansistring;
begin
  if (Gridhosts.FocusedRow <> nil) and
    (Gridhosts.FocusedRow.S['connected_ips'] <> '') then
  begin
    ip := GetReachableIP(Gridhosts.FocusedRow['connected_ips'],3389);
    if ip <> '' then
      ShellExecute(0, '', PAnsiChar('mstsc'), PAnsichar('/v:' + ip), nil, SW_SHOW)
    else
      ShowMessage(rsNoreachableIP);
  end;
end;

procedure TVisWaptGUI.ActRDPUpdate(Sender: TObject);
begin
  try
    ActRDP.Enabled := (Gridhosts.FocusedRow <> nil) and (Gridhosts.FocusedRow.S['connected_ips']<>'');
  except
    ActRDP.Enabled := False;
  end;

end;

procedure TVisWaptGUI.ActRefreshHostInventoryExecute(Sender: TObject);
begin
  with TVisHostsUpgrade.Create(Self) do
  try
    Caption:= rsTriggerHostsUpdate;
    action := 'trigger_host_register';
    hosts := Gridhosts.SelectedRows;

    if ShowModal = mrOk then
      actRefresh.Execute;
  finally
    Free;
  end;
end;

procedure TVisWaptGUI.ActRemoveConflictsExecute(Sender: TObject);
var
  Res, packages, hosts: ISuperObject;
  ResVar,VarHosts,VarPackages: Variant;
begin
  if GridHosts.Focused then
  begin
    with TvisGroupChoice.Create(self) do
    try
      Caption := rsSelectRemoveConflicts;
      res := TSuperObject.Create(stArray);

      if ShowModal = mrOk then
      try
        Screen.Cursor := crHourGlass;
        packages := SelectedPackages;
        Hosts := ExtractField(GridHosts.SelectedRows,'uuid');

        VarHosts := SuperObjectToPyVar(Hosts);
        VarPackages := SuperObjectToPyVar(packages);

        resVar := DMPython.waptdevutils.edit_hosts_depends(
           waptconfigfile := AppIniFilename(),
           hosts_list := VarHosts,
           remove_conflicts := VarPackages,
           key_password := dmpython.privateKeyPassword,
           wapt_server_user := waptServerUser,
           wapt_server_passwd := waptServerPassword
           );

        res := PyVarToSuperObject(ResVar);

      finally
        Screen.cursor := crDefault;
        ShowMessageFmt(rsNbModifiedHosts, [res.A['updated'].Length,res.A['discarded'].Length,res.A['unchanged'].Length]);
      end;
    finally
      Free;
    end;
  end;
end;

procedure TVisWaptGUI.ActRemoveDependsExecute(Sender: TObject);
var
  Res, packages, hosts: ISuperObject;
  ResVar,VarHosts,VarPackages: Variant;
begin
  if GridHosts.Focused then
  begin
    with TvisGroupChoice.Create(self) do
    try
      Caption := rsSelectRemoveDepends;
      res := TSuperObject.Create(stArray);

      if ShowModal = mrOk then
      try
        Screen.Cursor := crHourGlass;
        packages := SelectedPackages;
        Hosts := ExtractField(GridHosts.SelectedRows,'uuid');

        VarHosts := SuperObjectToPyVar(Hosts);
        VarPackages := SuperObjectToPyVar(packages);

        resVar := DMPython.waptdevutils.edit_hosts_depends(
           waptconfigfile := AppIniFilename(),
           hosts_list := VarHosts,
           remove_depends := VarPackages,
           key_password := dmpython.privateKeyPassword,
           wapt_server_user := waptServerUser,
           wapt_server_passwd := waptServerPassword
           );

        res := PyVarToSuperObject(ResVar);

      finally
        Screen.cursor := crDefault;
        ShowMessageFmt(rsNbModifiedHosts, [res.A['updated'].Length,res.A['discarded'].Length,res.A['unchanged'].Length]);
      end;
    finally
      Free;
    end;
  end;
end;

procedure TVisWaptGUI.ActWUANewGroupExecute(Sender: TObject);
begin
  {$ifdef wsus}
  With TVisWUAGroup.Create(Self) do
  try
    WUAGroup:='';
    if ShowModal = mrOK then
      ActWUALoadGroups.Execute;
  finally
    Free;
  end;
  {$endif wsus}
end;

procedure TVisWaptGUI.ActWUAProductHideExecute(Sender: TObject);
{$ifdef wsus}
var
  wproduct:ISuperobject;
{$endif wsus}
begin
  {$ifdef wsus}
  for wproduct in GridWinproducts.SelectedRows do
    wproduct.B['favourite'] := False;
  GridWinproducts.Data := FilterWinProducts(WUAProducts);
  {$endif wsus}
end;

procedure TVisWaptGUI.ActWUAProductShowExecute(Sender: TObject);
{$ifdef wsus}
var
  wproduct:ISuperobject;
{$endif wsus}
begin
  {$ifdef wsus}
  for wproduct in GridWinproducts.SelectedRows do
    wproduct.B['favourite'] := True;
  GridWinproducts.Data := FilterWinProducts(WUAProducts);
  {$endif wsus}
end;

procedure TVisWaptGUI.ActWUAProductsSelectionExecute(Sender: TObject);
begin
  {$ifdef wsus}
  With TVisWUAProducts.Create(self) do
  try
    if ShowModal = mrOk then
      ActWUALoadGroups.Execute;
  finally
    Free;
  end;
  {$endif wsus}
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
begin
  EdSearchGroups.Modified := False;
  GridGroups.Data := PyVarToSuperObject(DMPython.MainWaptRepo.search(searchwords := EdSearchGroups.Text, sections := 'group'));
end;

procedure TVisWaptGUI.ActTriggerHostUpdateExecute(Sender: TObject);
begin
  if (GridHosts.SelectedCount>=1) and (GridHosts.SelectedCount<=5) then
    TriggerActionOnHosts(ExtractField(GridHosts.SelectedRows,'uuid'),'trigger_host_update',Nil,rsTriggerHostsUpdate,'Error checking for updates',True)
  else
    with TVisHostsUpgrade.Create(Self) do
      try
        Caption:= rsTriggerHostsUpdate;
        action := 'trigger_host_update';
        notifyServer := True;
        hosts := Gridhosts.SelectedRows;

         if ShowModal = mrOk then;
        //  actRefresh.Execute;
      finally
        Free;
      end;
end;

function TVisWaptGUI.GetSelectedUUID:ISuperObject;
var
  host:ISuperObject;
begin
  result := TSuperObject.Create(stArray);
  for host in GridHosts.SelectedRows do
    result.AsArray.Add(host.S['uuid']);
end;

procedure TVisWaptGUI.ActTriggerHostUpgradeExecute(Sender: TObject);
begin
  with TVisHostsUpgrade.Create(Self) do
    try
      Caption:= rsTriggerHostsUpgrade;
      action := 'trigger_host_upgrade';
      hosts := Gridhosts.SelectedRows;

      if ShowModal = mrOk then
        actRefresh.Execute;
    finally
      Free;
    end;
end;

procedure TVisWaptGUI.ActEvaluateExecute(Sender: TObject);
begin
  MemoLog.Clear;
  if cbShowLog.Checked then
  begin
    MemoLog.Lines.Add('');
    MemoLog.Lines.Add('########## Start of Output of """' + EdRun.Text +
      '""" : ########');
  end;
  DMPython.RunJSON(EdRun.Text, jsonlog);
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

procedure TVisWaptGUI.ActDeleteHostsPackageAndInventoryExecute(Sender: TObject);
var
  sel, res, postdata: ISuperObject;
begin
  if GridHosts.Focused then
  begin
    sel := GridHosts.SelectedRows;
    with TVisHostDelete.Create(Self) do
    try
      LabMessage.Caption := format(rsConfirmRmHostsFromList, [IntToStr(sel.AsArray.Length)]);
      if ShowModal=mrOk then
      begin
        postdata := SO();
        postdata['uuids'] := ExtractField(sel,'uuid');
        postdata.B['delete_packages'] := CBDeleteHostConfiguration.Checked;
        postdata.B['delete_inventory'] := CBDeleteHostInventory.Checked;
        res := WAPTServerJsonPost('api/v3/hosts_delete',[],PostData);
        if res.B['success'] then
          ShowMessageFmt('%s',[res.S['msg']])
        else
          ShowMessageFmt('Unable to remove %s: %s',[(Sender as TAction).Caption, res.S['msg']]);
        ActSearchHost.Execute;
      end;
    finally
      Free;
    end;
  end;
end;

procedure TVisWaptGUI.actHostSelectAllExecute(Sender: TObject);
begin
  TSOGrid(GridHosts).SelectAll(False);
end;

procedure TVisWaptGUI.ActSearchHostExecute(Sender: TObject);
var
  soresult,columns,urlParams, Node, Hosts,fields: ISuperObject;
  previous_uuid,prop: string;
  i: integer;
const
  DefaultColumns:Array[0..13] of String = ('uuid','os_name','connected_ips','computer_fqdn',
    'computer_name','manufacturer','description','productname','serialnr','mac_addresses','connected_users','last_logged_on_user','computer_ad_ou','computer_ad_site');
begin
  if AppLoading then
    Exit;

  EdSearchHost.Modified:=False;
  columns := TSuperObject.Create(stArray);
  for i:=0 to GridHosts.Header.Columns.Count-1 do
    if coVisible in GridHosts.Header.Columns[i].Options then
      columns.AsArray.Add(TSOGridColumn(GridHosts.Header.Columns[i]).PropertyName);

  for prop in DefaultColumns do
  begin
    if not StrIn(prop,Columns) then
      columns.AsArray.Add(prop);
	end;

  try
    Screen.cursor := crHourGlass;

    urlParams := TSuperObject.Create(stArray);
    fields := TSuperObject.Create(stArray);

    if EdSearchHost.Text <> '' then
    begin
      if cbSearchHost.Checked = True then
      begin
        fields.AsArray.Add('computer_fqdn');
        fields.AsArray.Add('description');
        fields.AsArray.Add('manufacturer');
        fields.AsArray.Add('computer_name');
        fields.AsArray.Add('productname');
        fields.AsArray.Add('connected_ips');
        fields.AsArray.Add('mac_addresses');
        fields.AsArray.Add('connected_users');
        fields.AsArray.Add('serialnr');
      end;

      if cbSearchDMI.Checked = True then
      begin
        fields.AsArray.Add('dmi');
        fields.AsArray.Add('wmi');
      end;

      if cbSearchSoftwares.Checked = True then
      begin
        fields.AsArray.Add('installed_softwares.key');
        fields.AsArray.Add('installed_softwares.name');
      end;

      if cbSearchPackages.Checked = True then
        fields.AsArray.Add('installed_packages.name');

      urlParams.AsArray.Add(format('filter=%s:%s',[join(',',fields),EncodeURIComponent(EdSearchHost.Text)]));

      if CBInverseSelect.Checked then
        urlParams.AsArray.Add(format('not_filter=1',[]));
    end;

    if cbHasErrors.Checked then
      urlParams.AsArray.Add('has_errors=1');

    if cbReachable.Checked then
      urlParams.AsArray.Add('reachable=1');

    if cbNeedUpgrade.Checked then
      urlParams.AsArray.Add('need_upgrade=1');

    if cbGroups.ItemIndex>0 then
      urlParams.AsArray.Add(Format('groups=%s',[cbGroups.Text]));

    {$ifdef ENTERPRISE }
    if cbADOU.ItemIndex>0 then
      urlParams.AsArray.Add(Format('organizational_unit=%s',[cbADOU.Text]));

    if cbADSite.ItemIndex>0 then
      urlParams.AsArray.Add(Format('ad_site=%s',[cbADSite.Text]));
    {$endif}

    urlParams.AsArray.Add('columns='+join(',',columns));
    urlParams.AsArray.Add(Format('limit=%d',[HostsLimit]));

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
begin
  EdSearchPackage.Modified:=False;
  GridPackages.Data := PyVarToSuperObject(DMPython.MainWaptRepo.search(searchwords := EdSearchPackage.Text, sections := 'base,restricted', newest_only := cbNewestOnly.Checked));
end;

procedure TVisWaptGUI.ActPackagesUpdateExecute(Sender: TObject);
begin
  try
    ShowLoadWait('Loading packages',0,4);
    dmpython.MainWaptRepo := Unassigned;
    ShowProgress('Filter packages',2);
    ActSearchPackage.Execute;
    ShowProgress('Filter groups',3);
    ActSearchGroups.Execute;
  finally
    HideLoadWait;
  end;
end;

procedure TVisWaptGUI.ActReloadConfigExecute(Sender: TObject);
begin
  dmpython.WaptConfigFileName:='';
  waptcommon.ReadWaptConfig(AppIniFilename);
  dmpython.WaptConfigFileName:=AppIniFilename;
  pgSources.TabVisible := AdvancedMode;
  PanDebug.Visible := AdvancedMode;
  Gridhosts.ShowAdvancedColumnsCustomize:= AdvancedMode;
  GridGroups.ShowAdvancedColumnsCustomize:=AdvancedMode;
  GridPackages.ShowAdvancedColumnsCustomize:=AdvancedMode;
  GridHostPackages.ShowAdvancedColumnsCustomize:=AdvancedMode;

  //ActPackagesUpdate.Execute;
  GridPackages.Data := Nil;
  GridGroups.Data := Nil;
  GridHosts.Data := Nil;
end;

procedure TVisWaptGUI.ActVNCExecute(Sender: TObject);
var
  ip: ansistring;
begin
  if (Gridhosts.FocusedRow <> nil) and
    (Gridhosts.FocusedRow.S['connected_ips'] <> '') then
  begin
    ip := GetReachableIP(Gridhosts.FocusedRow['connected_ips'],5900);
    if ip<>'' then
      ShellExecute(0, '', PAnsiChar(GetVNCViewerPath),
        PAnsichar(ip), nil, SW_SHOW)
    else
      ShowMessage(rsNoReachableIP);
  end;
end;

procedure TVisWaptGUI.ActVNCUpdate(Sender: TObject);
begin
  try
    ActVNC.Enabled := (Gridhosts.FocusedRow <> nil) and
      (Gridhosts.FocusedRow.S['connected_ips'] <> '') and
      FileExists(GetVNCViewerPath);
  except
    ActVNC.Enabled := False;
  end;
end;

procedure TVisWaptGUI.ActWAPTConsoleConfigExecute(Sender: TObject);
begin
  if EditIniFile then
  begin
    ActReloadConfig.Execute;
    GridPackages.Clear;
    GridGroups.Clear;
    GridHosts.Clear;
    GridhostInventory.Clear;
    GridHostPackages.Clear;
    GridHostSoftwares.Clear;
    { TODO : Remove use of WAPT instance, use waptpackage.PackageEntry instead }
    if not VarIsEmpty(DMPython.WAPT) then
      DMPython.WAPT.update(register:=False);
    // put somewhere else
    MainPagesChange(MainPages);
  end;
end;

procedure TVisWaptGUI.ApplicationProperties1Exception(Sender: TObject;
  E: Exception);
begin
  MessageDlg('Error in application','An unhandled exception has occured'#13#10#13#10+E.Message,mtError,[mbOK],'');
end;

procedure TVisWaptGUI.cbADOUSelect(Sender: TObject);
begin
  {$ifdef ENTERPRISE}
  ActSearchHost.Execute;
  {$endif}
end;

procedure TVisWaptGUI.cbADSiteSelect(Sender: TObject);
begin
  {$ifdef ENTERPRISE}
  ActSearchHost.Execute;
  {$endif}
end;

procedure TVisWaptGUI.cbAdvancedSearchClick(Sender: TObject);
begin
  PanSearchIn.Visible:=cbAdvancedSearch.Checked;
  PanFilterGroups.Visible:=cbAdvancedSearch.Checked;
  CBInverseSelect.Visible:=cbAdvancedSearch.Checked;

  if not cbAdvancedSearch.Checked then
  begin
    //PanHostsFilters.Parent := panToolBar;
    cbSearchAll.Checked:=False;
    cbSearchHost.Checked:=True;
    cbSearchDMI.Checked:=False;
    cbSearchPackages.Checked:=False;
    cbSearchSoftwares.Checked:=False;

    cbGroups.ItemIndex:=-1;

    {$ifdef ENTERPRISE}
    cbADSite.ItemIndex:=-1;
    cbADOU.ItemIndex:=-1;
    {$endif}

    panFilterStatus.ChildSizing.ControlsPerLine:=6;
  end
  else
  begin
    //PanHostsFilters.Parent := pgInventory;
    panFilterStatus.ChildSizing.ControlsPerLine:=2;
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

type
  THackSearchEdit=class(TSearchEdit);

procedure TVisWaptGUI.CBInverseSelectClick(Sender: TObject);
begin
  Gridhosts.Clear;
  EdSearchHost.Modified := True;
  THackSearchEdit(EdSearchHost).Change;
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

        EdServerCertificate.FileName:=inifile.ReadString('global','verify_cert','');

        edhttp_proxy.Text := inifile.ReadString('global', 'http_proxy', '');
        cbUseProxyForServer.Checked :=
          inifile.ReadBool('global', 'use_http_proxy_for_server', edhttp_proxy.Text <> '');
        cbUseProxyForRepo.Checked :=
          inifile.ReadBool('global', 'use_http_proxy_for_repo', edhttp_proxy.Text <> '');

        //edrepo_url.text := VarPythonAsString(conf.get('global','repo_url'));
        eddefault_package_prefix.Text :=
          inifile.ReadString('global', 'default_package_prefix', '');
        edwapt_server.Text := inifile.ReadString('global', 'wapt_server', '');

        eddefault_sources_root.Text :=
          inifile.ReadString('global', 'default_sources_root', 'c:\waptdev');

        edPersonalCertificatePath.Text := inifile.ReadString('global', 'personal_certificate_path', '');
        if edPersonalCertificatePath.text = '' then
          edPersonalCertificatePath.InitialDir:=GetUserDir
        else
          edPersonalCertificatePath.InitialDir:=ExtractFileDir(edPersonalCertificatePath.text);

        cbSendStats.Checked :=
          inifile.ReadBool('global', 'send_usage_report', True);
        //eddefault_sources_root.Directory := inifile.ReadString('global','default_sources_root','');
        //eddefault_sources_url.text = inifile.ReadString('global','default_sources_url','https://srvdev/sources/%(packagename)s-wapt/trunk');

        if ShowModal = mrOk then
        begin
          inifile.WriteString('global', 'repo_url', edrepo_url.Text);
          inifile.WriteString('global','verify_cert',EdServerCertificate.Text);

          inifile.WriteString('global', 'http_proxy', edhttp_proxy.Text);
          inifile.WriteString('global', 'default_package_prefix',
            LowerCase(eddefault_package_prefix.Text));
          inifile.WriteString('global', 'wapt_server', edwapt_server.Text);
          inifile.WriteString('global', 'default_sources_root',
            eddefault_sources_root.Text);
          inifile.WriteString('global', 'personal_certificate_path', edPersonalCertificatePath.Text);
          inifile.WriteBool('global', 'use_http_proxy_for_server',
            cbUseProxyForServer.Checked);
          inifile.WriteBool('global', 'use_http_proxy_for_repo',
            cbUseProxyForRepo.Checked);
          inifile.WriteBool('global', 'send_usage_report',
            cbSendStats.Checked);
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
  if Gridhosts.FocusedRow<>Nil then
    GridHostSoftwares.Data := FilterSoftwares(Gridhosts.FocusedRow['installed_softwares']);
end;

procedure TVisWaptGUI.cbNewestOnlyClick(Sender: TObject);
begin
  ActSearchPackage.Execute;
end;

procedure TVisWaptGUI.cbADOUDropDown(Sender: TObject);
begin
  {$ifdef ENTERPRISE}
  try
    FillcbADOUDropDown;
  except
    ShowMessage('Please upgrade your server');
  end;
  {$endif}
end;

procedure TVisWaptGUI.cbSearchAllClick(Sender: TObject);
begin
  Gridhosts.Clear;
  if cbSearchAll.Checked then
  begin
    cbSearchDMI.Checked := True;
    cbSearchSoftwares.Checked := True;
    cbSearchPackages.Checked := True;
    cbSearchHost.Checked := True;
  end
  else
  if not cbSearchAll.Checked then
  begin
    cbSearchDMI.Checked := False;
    cbSearchSoftwares.Checked := False;
    cbSearchPackages.Checked := False;
    cbSearchHost.Checked := False;
  end;
end;

function checkReadWriteAccess(dir: Utf8string): boolean;
var
  fn: Utf8string;
begin
  try
    fn := LazFileUtils.GetTempFileNameUTF8(dir, 'test');
    StringToFile(fn, '');
    FileUtil.DeleteFileUTF8(fn);
    Result := True;
  except
    Result := False;
  end;
end;

procedure TVisWaptGUI.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
  ScaleImageList(ImageList1,96);
  ScaleImageList(ActionsImages24,96);
  HostsLimit := 2000;
  DMPython.PythonOutput.OnSendData := @PythonOutputSendData;

  {$ifdef ENTERPRISE }
  IsEnterpriseEdition:=True;
  {$else}
  IsEnterpriseEdition:=False;
  {$endif}
  ActProprietary.Enabled := IsEnterpriseEdition;
  ActProprietary.Checked := IsEnterpriseEdition;
end;

procedure TVisWaptGUI.FormDragOver(Sender, Source: TObject; X, Y: Integer;
  State: TDragState; var Accept: Boolean);
begin
  if MainPages.ActivePage = pgPrivateRepo then
    Accept:=True;
end;

procedure TVisWaptGUI.FormDropFiles(Sender: TObject;
  const FileNames: array of String);
begin
  if MainPages.ActivePage = pgPrivateRepo then
  begin
    MakePackageTemplate(FileNames[0]);
  end;
end;

procedure TVisWaptGUI.MakePackageTemplate(AInstallerFileName: String);
begin
  With TVisPackageWizard.Create(self) do
  try
    InstallerFilename:=AInstallerFileName;
    if ShowModal <> mrCancel then
      actRefresh.Execute;
  finally
    Free;
  end;
end;

function TVisWaptGUI.Login: boolean;
var
  cred, sores: ISuperObject;
  localfn: utf8string;
begin
  Result := False;
  // Initialize user local config file with global wapt settings
  localfn := AppIniFilename;

  if not FileExistsUTF8(localfn) then
  begin
    if not DirectoryExistsUTF8(ExtractFileDir(localFn)) then
       ForceDirectoriesUTF8(ExtractFileDir(localFn));
    CopyFile(Utf8ToAnsi(WaptIniFilename), Utf8ToAnsi(localfn), True);
  end;

  ActReloadConfig.Execute;

  while (GetWaptServerURL = '') do
  begin
    if EditIniFile then
      ActReloadConfig.Execute
    else
      Halt;
  end;

  with TVisLogin.Create(Self) do
    while not result do
    try
      edWaptServerName.Text := GetWaptServerURL;
      edUser.Text:= WaptServerUser;
      if ShowModal = mrOk then
      begin
        // reload config file if another is choosen in login dialog
        if AppIniFilename<>dmpython.WaptConfigFileName  then
        begin
          dmpython.WaptConfigFileName:='';
          waptcommon.ReadWaptConfig(AppIniFilename);
          dmpython.WaptConfigFileName:=AppIniFilename;
        end;

        // recreate new session
        if Assigned(WaptServerSession) then FreeAndNil(WaptServerSession);
        waptServerUser := edUser.Text;
        waptServerPassword := edPassword.Text;

        // Auth using certificates or basic auth
        cred := SO();
        cred.S['user'] := waptServerUser;
        cred.S['password'] := UTF8Decode(waptServerPassword);

        sores := WAPTServerJsonPost('api/v3/login', [],cred);
        if sores.B['success'] then
        begin
            waptServerUUID := sores['result'].S['server_uuid'];
            Result := True;
            if (CompareVersion(sores['result'].S['version'],WAPTServerMinVersion)<0) then
              ShowMessageFmt(rsWaptServerOldVersion,[sores['result'].S['version'],WAPTServerMinVersion]);
            break;
        end
        else
        begin
            if Assigned(WaptServerSession) then FreeAndNil(WaptServerSession);
            waptServerPassword := '';
            Result := False;
        end
      end
      else
      begin
        if Assigned(WaptServerSession) then FreeAndNil(WaptServerSession);
        waptServerPassword := '';
        Result := False;
        break;
      end
    except
      on E:Exception do
        ShowMessageFmt(rsWaptServerError,[e.Message]);
    end;
end;

procedure TVisWaptGUI.FormShow(Sender: TObject);
var
  i:integer;
  sores: ISuperObject;
  CB:TComponent;
  ini:TIniFile;

begin
  CurrentVisLoading := TVisLoading.Create(Nil);
  with CurrentVisLoading do
  try
    AppLoading:=True;
    MemoLog.Clear;
    ProgressTitle(rsLoadSettings);
    Start(3);
    ProgressStep(0,3);
    // saves default initial config...
    Gridhosts.SaveSettingsToIni(Appuserinipath+'.default');
    GridPackages.SaveSettingsToIni(Appuserinipath+'.default');
    GridGroups.SaveSettingsToIni(Appuserinipath+'.default');
    GridHostPackages.SaveSettingsToIni(Appuserinipath+'.default');
    GridHostSoftwares.SaveSettingsToIni(Appuserinipath+'.default');

    // don't load grid settings if old ini version
    if IniReadString(Appuserinipath,self.name,'waptconsole.version','') <> '' then
    begin
      Gridhosts.LoadSettingsFromIni(Appuserinipath);
      GridPackages.LoadSettingsFromIni(Appuserinipath);
      GridGroups.LoadSettingsFromIni(Appuserinipath);
      GridHostPackages.LoadSettingsFromIni(Appuserinipath);
      GridHostSoftwares.LoadSettingsFromIni(Appuserinipath);
      ini := TIniFile.Create(Appuserinipath);
      try
        for CB in VarArrayOf([cbAdvancedSearch,cbSearchAll,cbSearchDMI,cbSearchHost,cbSearchPackages,cbSearchSoftwares,cbReachable]) do
          TCheckBox(CB).Checked := ini.ReadBool(self.Name,CB.Name,TCheckBox(CB).Checked);

        HostsLimit := ini.ReadInteger(self.name,'HostsLimit',2000);
        //ShowMessage(Appuserinipath+'/'+self.Name+'/'+EdHostsLimit.Name+'/'+ini.ReadString(name,EdHostsLimit.Name,'not found'));
        HostPages.Width := ini.ReadInteger(self.name,HostPages.Name+'.width',HostPages.Width);

        Self.Left := ini.ReadInteger(self.name,'Left',Integer(Self.Left));
        Self.Top := ini.ReadInteger(self.name,'Top',Integer(Self.Top));
        Self.Width := ini.ReadInteger(self.name,'Width',Integer(Self.Width));
        Self.Height := ini.ReadInteger(self.name,'Height',Integer(Self.Height));

        Self.WindowState := TWindowState(ini.ReadInteger(self.name,'WindowState',Integer(Self.WindowState)));

        self.cbGroups.Text := ini.ReadString(self.name,'cbGroups.Text',self.cbGroups.Text);

        {$ifdef ENTERPRISE}
        self.cbADSite.Text := ini.ReadString(self.name,'cbADSite.Text',self.cbADSite.Text);
        self.cbADOU.Text := ini.ReadString(self.name,'cbADOU.Text',self.cbADOU.Text);
        {$endif}

      finally
        ini.Free;
      end;
    end
    else
      // be sure other forms will not use it.
      if FileExists(Appuserinipath) then
        SysUtils.DeleteFile(Appuserinipath);

    pgWindowsUpdates.TabVisible:=waptcommon.waptwua_enabled;
    pgHostWUA.TabVisible:=waptcommon.waptwua_enabled;
    for i:=0 to WSUSActions.ActionCount-1 do
    begin
      (WSUSActions.Actions[i] as TAction).Visible:=waptcommon.waptwua_enabled;
    end;

    plStatusBar1.Panels[0].Text := ApplicationName+' '+GetApplicationVersion+' WAPT '+wapt_edition+' Edition, (c) 2012-2017 Tranquil IT Systems. (Configuration:'+AppIniFilename+')';

    //ProgressTitle(rsLoadPackages);
    ProgressStep(2,3);
    //ActPackagesUpdate.Execute;

    cbAdvancedSearchClick(self);

    MainPages.ActivePage := pgInventory;
    MainPagesChange(Sender);
    HostPages.ActivePage := pgPackages;

    AppLoading:=False;
    ProgressTitle(rsLoadInventory);
    ProgressStep(3,3);
    ActSearchHost.Execute;

    // check waptagent version
    sores := WAPTServerJsonGet('api/v2/waptagent_version', []);
    try
      if sores.B['success'] then
        if sores['result'].S['waptagent_version'] = '' then
          ShowMessageFmt(rsWaptAgentNotPresent,[])
        else if (CompareVersion(sores['result'].S['waptagent_version'],sores['result'].S['waptsetup_version'])<0) then
        begin
            MessageDlg('waptgent.exe / waptsetup mismatch',
              Format(rsWaptAgentOldVersion,[sores['result'].S['waptagent_version'],sores['result'].S['waptsetup_version']]),
              mtWarning,
              [mbOK],'');
        end;
    except
        on E:Exception do
          ShowMessageFmt(rsWaptAgentNotPresent,[]);
    end;
  finally
    AppLoading:=False;
    Free;
  end;
end;

procedure TVisWaptGUI.GridGroupsColumnDblClick(Sender: TBaseVirtualTree;
  Column: TColumnIndex; Shift: TShiftState);
begin
  ActEditGroup.Execute;
end;

procedure TVisWaptGUI.GridGroupsGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; RowData, CellData: ISuperObject; Column: TColumnIndex;
  TextType: TVSTTextType; var CellText: string);
var
  colname:String;
begin
  if celltext<>'' then
  begin
    colname := ((Sender as TSOGrid).Header.Columns[Column] as TSOGridColumn).PropertyName;
    if  (colname = 'depends') or (colname = 'conflicts') then
      StrReplace(CellText, ',', #13#10, [rfReplaceAll]);
    if (colname = 'size') or (colname ='installed_size') then
      CellText := FormatFloat('# ##0 kB',StrToInt64(CellText) div 1024);

    // awfull hack to workaround the bad wordwrap break of last line for multilines cells...
    // the problem is probably in the LCL... ?
    if  (colname = 'description') or (colname = 'depends') or (colname = 'conflicts') then
      CellText := CellText + #13#10;
    if (colname = 'description') then
      CellText := UTF8Encode(Celltext);

    if (colname = 'signature_date') then
      CellText := copy(Celltext,1,16);

  end;
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
        'ERROR-UPGRADE','ERROR': ImageIndex := 2;
        'NEED-UPGRADE': ImageIndex := 1;
        'RUNNING': ImageIndex := 6;
        'MISSING': ImageIndex := 7;
      end;
    end;
  end;
end;

procedure TVisWaptGUI.GridHostPackagesGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; RowData, CellData: ISuperObject; Column: TColumnIndex;
  TextType: TVSTTextType; var CellText: string);
var
  propName:String;
begin
  if (Node = nil) or (CellData=Nil) then
    CellText := ''
  else
  begin
    propName:=TSOGridColumn(GridHostPackages.Header.Columns[Column]).PropertyName;

    if (CellData <> nil) and (CellData.DataType = stArray) then
      CellText := soutils.Join(',', CellData);

    if (propName='install_date') then
        CellText := Copy(StrReplaceChar(CellText,'T',' '),1,16);
  end;
end;

procedure TVisWaptGUI.GridHostsChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
begin
  UpdateHostPages(Sender);
  UpdateSelectedHostsActions(Sender);
  if GridHosts.Data<>Nil then
    LabelComputersNumber.Caption := Format(rsHostsSelectedTotal,[GridHosts.SelectedCount,GridHosts.Data.AsArray.Length])
  else
    LabelComputersNumber.Caption := '';
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
      {else if (pos('connected_ips', propname) > 0) then
          Result := CompareVersion(Join('-',d1),Join('-',d2))
      else
      if (pos('mac_addresses', propname) > 0) then
        Result := UTF8CompareText(d1.AsString, d2.AsString)
      }
      else
      begin
        CompResult := d1.Compare(d2);
        case compresult of
          cpLess: Result := -1;
          cpEqu: Result := 0;
          cpGreat: Result := 1;
          cpError: Result := UTF8CompareText(n1.S[propname], n2.S[propname]);
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
    propname := GridhostInventory.Path(GridhostInventory.FocusedNode, 0, ttNormal, '/');
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
    propname := GridhostInventory.Path(GridhostInventory.FocusedNode, 0, ttNormal, '/');
    propname := copy(propname, 1, length(propname) - 1);

    Accept := (GridHosts.FindColumnByPropertyName(propname) = nil);
  end;
end;

procedure TVisWaptGUI.GridHostsEditing(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; var Allowed: boolean);
var
  col: TSOGridColumn;
begin
  if column>=0 then
  begin
    col := GridHosts.Header.Columns[Column] as TSOGridColumn;
    Allowed := (col<>Nil) and (col.PropertyName = 'description');
  end
  else
    Allowed := False;

end;

procedure TVisWaptGUI.GridHostsGetHint(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex;
  var LineBreakStyle: TVTTooltipLineBreakStyle; var HintText: String);
begin
  If Column = 0 then
    HintText := GridHosts.GetCellStrValue(Node,'host_status')
  else if Column = 1 then
    HintText := GridHosts.GetCellStrValue(Node,'reachable');

end;

procedure TVisWaptGUI.GridLoadData(grid: TSOGrid; jsondata: string);
begin
  if (jsondata <> '') then
    try
      Grid.Data := SO(jsondata);
    finally
    end;
end;

procedure TVisWaptGUI.TreeLoadData(tree: TVirtualJSONInspector; jsondata: ISuperObject);
var
  jsp: TJSONParser;

begin
  tree.Clear;
  if (jsondata <> Nil) then
  try
    tree.BeginUpdate;
    jsp := TJSONParser.Create(jsondata.AsJSon);
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
  registration_auth_user,reachable: ISuperObject;
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
        if status.AsString = 'RUNNING' then
          ImageIndex := 6
        else if status.AsString = 'ERROR' then
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
    reachable := GridHostPackages.GetCellData(Node, 'reachable', Nil);
    if (reachable<>Nil)then
    begin
      if (reachable.AsString = 'OK') then
        ImageIndex := 4
      else if (reachable.AsString = 'UNREACHABLE') or (reachable.AsString = 'UNKNOWN') or (reachable.AsString = 'DISCONNECTED') then
        ImageIndex := 5
      else
        ImageIndex := 6;
    end
    else
      ImageIndex := 6
  end
  else if TSOGridColumn(GridHosts.Header.Columns[Column]).PropertyName = 'registration_auth_user' then
  begin
    ImageIndex:=-1;
    registration_auth_user := GridHostPackages.GetCellData(Node, 'registration_auth_user', Nil);

    if (registration_auth_user = Nil) or (registration_auth_user.AsString='') or (copy(registration_auth_user.AsString,1,5) = 'None:') then
      ImageIndex := 9
    else
      ImageIndex := 10
  end;

end;

procedure TVisWaptGUI.GridHostsGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; RowData, CellData: ISuperObject; Column: TColumnIndex;
  TextType: TVSTTextType; var CellText: string);

var
  propName:String;
begin
  if (Node = nil) or (CellData=Nil) then
    CellText := ''
  else
  begin
    propName:=TSOGridColumn(GridHosts.Header.Columns[Column]).PropertyName;
    if (RowData.AsObject<>nil) then
    begin
      // Hack to workaround automatix SO path decoding with .. dots in property names are replaced by ~
      if (pos('.',propName)>0) then
      begin
        if pos('computer_fqdn',propName)>0 then
          propname:=propName;
        propName := StrReplaceChar(propName,'.','-');
        if RowData.AsObject.Find(propName,Celldata) then
          CellText := CellData.AsString;
      end;
    end;

    if (CellData <> nil) and (CellData.DataType = stArray) then
      CellText := soutils.Join(',', CellData);

    if (propName='last_seen_on') or (propName='listening_timestamp') then
        CellText := Copy(StrReplaceChar(CellText,'T',' '),1,16);
  end;
end;

procedure TVisWaptGUI.GridHostsHeaderDblClick(Sender: TVTHeader;
  HitInfo: TVTHeaderHitInfo);
begin
  exit;
end;

function TVisWaptGUI.TriggerChangeHostDescription(uuid, description: String
  ): Boolean;
var
  args: ISuperObject;
  taskresult,uuids: ISuperObject;
begin
  if MessageDlg(rsConfirmCaption,'Do you really want to change description to '+description+' ?',mtConfirmation, mbYesNoCancel,0) = mrYes then
  begin
    uuids := TSuperObject.Create(stArray);;
    uuids.AsArray.Add(uuid);
    args := SO();
    args.S['computer_description'] := UTF8Decode(description){%H-};
    taskresult := TriggerActionOnHosts(uuids,'trigger_change_description',args,'Change host description and register','Error changing host description');
    result := taskresult.B['success'];
  end
  else
    result := False;
end;

procedure TVisWaptGUI.GridHostsNewText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; const NewText: String);
begin
  if (GridHosts.Header.Columns[Column]  as TSOGridColumn).PropertyName = 'description' then
  begin
    if not TriggerChangeHostDescription(GridHosts.FocusedRow.S['uuid'],newtext) then
    begin
      GridHosts.CancelEditNode;
      Abort;
    end
    else
      UpdateHostPages(GridHosts);
  end;
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

procedure TVisWaptGUI.GridPackagesColumnDblClick(Sender: TBaseVirtualTree;
  Column: TColumnIndex; Shift: TShiftState);
begin
  if ActEditpackage.Enabled and (GridPackages.FocusedRow<>Nil) and (MessageDlg(rsConfirmCaption, Format(rsConfirmPackageEdit,[GridPackages.FocusedRow.S['package']]),mtConfirmation,mbYesNoCancel ,'') = mrYes) then
    ActEditpackage.Execute;
end;

procedure TVisWaptGUI.PythonOutputSendData(Sender: TObject; const Data: ansistring);
begin
  MemoLog.Lines.Add(Data);
end;

procedure TVisWaptGUI.SetIsEnterpriseEdition(AValue: Boolean);
begin
  if dmpython.IsEnterpriseEdition<>AValue then
    dmpython.IsEnterpriseEdition:=AValue;
  Label20.Visible:=IsEnterpriseEdition;
  cbADOU.Visible:=IsEnterpriseEdition;
  Label21.Visible:=IsEnterpriseEdition;
  cbADSite.Visible:=IsEnterpriseEdition;
  ActLaunchGPUpdate.Visible:=IsEnterpriseEdition;
  ActDisplayUserMessage.Visible:=IsEnterpriseEdition;
  ActLaunchWaptExit.Visible:=IsEnterpriseEdition;
  ActTISHelp.Visible:=IsEnterpriseEdition and FileExists(GetTisSupportPath);

end;

procedure TVisWaptGUI.GridPackagesPaintText(Sender: TBaseVirtualTree;
  const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
  TextType: TVSTTextType);
begin
  if StrIsOneOf(GridPackages.GetCellStrValue(Node, 'status'), ['I', 'U'],False) then
    TargetCanvas.Font.style := TargetCanvas.Font.style + [fsBold]
  else
    TargetCanvas.Font.style := TargetCanvas.Font.style - [fsBold];
end;

procedure TVisWaptGUI.HostPagesChange(Sender: TObject);
begin
  UpdateHostPages(Sender);
end;

procedure TVisWaptGUI.Image1Click(Sender: TObject);
begin
  OpenDocument('https://www.tranquil.it');
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
        cbGroups.Items.Add(group.S['package']{%H-});
    end;
    cbGroups.Text := oldSelect;

  finally
    Screen.Cursor:=crdefault;
  end;
end;

procedure TVisWaptGUI.MainPagesChange(Sender: TObject);
{$ifdef wsus}
var
  wsus_restrictions,wsus_rules,WUAClassifications:ISuperObject;
{$endif}
begin
  if MainPages.ActivePage = pgInventory then
  try
    Screen.Cursor:=crHourGlass;
    CopyMenu(PopupMenuHosts, MenuItem24);
    if GridHosts.Data = nil then
      ActSearchHost.Execute;
    EdSearchHost.SetFocus;
  finally
    Screen.Cursor:=crDefault;
  end
  else if MainPages.ActivePage = pgPrivateRepo then
  begin
    CopyMenu(PopupMenuPackages, MenuItem24);
    if GridPackages.Data = nil then
      ActSearchPackage.Execute;
    EdSearchPackage.SetFocus;
  end
  else if MainPages.ActivePage = pgGroups then
  begin
    CopyMenu(PopupMenuGroups, MenuItem24);
    if GridGroups.Data = nil then
      ActSearchGroups.Execute;
    EdSearchGroups.SetFocus;
  end
  {$ifdef wsus}
  else if MainPages.ActivePage = pgWindowsUpdates then
  begin
    WUAClassifications := WAPTServerJsonGet('api/v2/windows_updates_classifications',[])['result'];
    ActWSUSRefreshCabHistory.Execute;
  end

  else if MainPages.ActivePage = pgWUAProducts then
  begin
    WUAProducts := WAPTServerJsonGet('api/v2/windows_products',[])['result'];
    GridWinproducts.Data := FilterWinproducts(WUAProducts);
    ActWUALoadUpdates.Execute;
  end
  else if MainPages.ActivePage = pgWUABundles then
  begin
      wsus_rules := WAPTServerJsonGet('api/v2/windows_updates_rules',[])['result'];
      GridWUAGroups.data := wsus_rules;
  end}
  {$endif wsus}
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

procedure TVisWaptGUI.cbADSiteDropDown(Sender: TObject);
begin
  {$ifdef ENTERPRISE}
  try
    FillcbADSiteDropDown;
  except
    ShowMessage('Please upgrade your server');
  end;
  {$endif}
end;

procedure TVisWaptGUI.cbWUAPendingChange(Sender: TObject);
begin
  {$ifdef wsus}
  if (Gridhosts.FocusedRow <> nil) then
    GridHostWinUpdates.Data := FilterHostWinUpdates(Gridhosts.FocusedRow['waptwua.updates']);
  {$endif wsus}
end;

procedure TVisWaptGUI.cbWUCriticalClick(Sender: TObject);
begin
  {$ifdef wsus}
  TimerWUALoadWinUpdatesTimer(sender);
  {$endif wsus}
end;

procedure TVisWaptGUI.CBWUProductsShowAllClick(Sender: TObject);
begin
  {$ifdef wsus}
  GridWinproducts.Data := FilterWinProducts(WUAProducts);
  {$endif wsus}
end;


procedure TVisWaptGUI.FillcbADOUDropDown;
var
  OU,OUDN:ISuperObject;
  oldSelect:String;
begin
  {$ifdef ENTERPRISE}
  try
    Screen.Cursor:=crHourGlass;

    oldSelect:=cbADOU.Text;
    cbADOU.Items.Clear;
    cbADOU.Items.Add(rsFilterAll);

    OUDN := WAPTServerJsonGet('api/v3/get_ad_ou',[])['result'];
    if OUDN<>Nil then
    begin
      for OU in OUDN do
        cbADOU.Items.Add(OU.AsString{%H-});
    end;
    cbADOU.Text:= oldSelect;

  finally
    Screen.Cursor:=crdefault;
  end;
  {$endif}
end;


procedure TVisWaptGUI.FillcbADSiteDropDown;
var
  Site,Sites:ISuperObject;
  oldSelect:String;
begin
  {$ifdef ENTERPRISE}
  try
    Screen.Cursor:=crHourGlass;

    oldSelect:=cbADSite.Text;
    cbADSite.Items.Clear;
    cbADSite.Items.Add(rsFilterAll);

    Sites := WAPTServerJsonGet('api/v3/get_ad_sites',[])['result'];
    if Sites <> Nil then
    begin
      for Site in Sites do
        cbADSite.Items.Add(Site.AsString{%H-});
    end;
    cbADSite.Text:= oldSelect;

  finally
    Screen.Cursor:=crdefault;
  end;
  {$endif}
end;

procedure TVisWaptGUI.GridWinproductsChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  {$ifdef wsus}
  GridWSUSAllowedWindowsUpdates.Data := Nil;
  TimerWUALoadWinUpdates.Enabled:=False;
  TimerWUALoadWinUpdates.Enabled:=True;
  {$endif}
end;

procedure TVisWaptGUI.GridWinUpdatesGetImageIndexEx(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
  var Ghosted: Boolean; var ImageIndex: Integer; var ImageList: TCustomImageList
  );
var
  row: ISuperObject;
begin
  {$ifdef wsus}
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
  {$endif}
end;

procedure TVisWaptGUI.GridWSUSAllowedClassificationsFreeNode(
  Sender: TBaseVirtualTree; Node: PVirtualNode);
begin
  {$ifdef wsus}
  windows_updates_rulesUpdated:=True;
  {$endif wsus}
end;

procedure TVisWaptGUI.GridWSUSAllowedWindowsUpdatesFreeNode(
  Sender: TBaseVirtualTree; Node: PVirtualNode);
begin
   {$ifdef wsus}
   windows_updates_rulesUpdated:=True;
   {$endif wsus}
end;

procedure TVisWaptGUI.GridWSUSForbiddenWindowsUpdatesFreeNode(
  Sender: TBaseVirtualTree; Node: PVirtualNode);
begin
  {$ifdef wsus}
  windows_updates_rulesUpdated:=True;
  {$endif wsus}
end;

function TVisWaptGUI.FilterHostWinUpdates(wua: ISuperObject): ISuperObject;
{$ifdef wsus}
var
  wupdate: ISuperObject;
  accept: boolean;
  {$endif wsus}
begin
  Result := TSuperObject.Create(stArray);
  {$ifdef wsus}
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
  {$endif wsus}
end;

function TVisWaptGUI.FilterWindowsUpdate(wua: ISuperObject
  ): ISuperObject;
{$ifdef wsus}
var
  wupdate: ISuperObject;
  accept: boolean;
  {$endif wsus}
begin
  Result := TSuperObject.Create(stArray);
  {$ifdef wsus}
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
  {$endif wsus}
end;

function TVisWaptGUI.FilterWinProducts(products: ISuperObject): ISuperObject;
{$ifdef wsus}
var
  wproduct: ISuperObject;
  accept: boolean;
  {$endif wsus}
begin
  {$ifdef wsus}
  Result := TSuperObject.Create(stArray);
  if (products = nil) or (products.AsArray = Nil) then
    Exit;
  for wproduct in products do
  begin
    Accept := CBWUProductsShowAll.Checked or wproduct.B['favourite'];
    if accept then
      Result.AsArray.Add(wproduct);
  end;
  {$else}
  result := Nil;
  {$endif wsus}
end;

procedure TVisWaptGUI.ActTISHelpExecute(Sender: TObject);
var
  taskresult,uuids: ISuperObject;
  currhost,computer_name: ansistring;
begin
  {$ifdef ENTERPRISE}
  if GridHosts.FocusedRow<>Nil then
  try
    Screen.Cursor:=crHourGlass;
    uuids := TSuperObject.Create(stArray);;
    currhost := GridHosts.FocusedRow.S['uuid'];
    computer_name := lowercase(GridHosts.FocusedRow.S['computer_name']);
    uuids.AsArray.Add(currhost);
    taskresult := TriggerActionOnHosts(uuids,'trigger_start_tishelp',Nil,'','Error starting TISHelp',False,False);
    if taskresult.B['success'] then
      ShellExecute(0, '', PAnsiChar(GetTisSupportPath),
        PAnsichar('-open '+computer_name), nil, SW_SHOW);
  finally
    Screen.Cursor := crDefault;
  end;
  {$endif ENTERPRISE}
end;


end.
