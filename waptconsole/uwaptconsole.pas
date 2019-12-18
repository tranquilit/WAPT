unit uwaptconsole;

{$mode objfpc}{$H+}
{$modeswitch ADVANCEDRECORDS}

interface

uses
  Classes, SysUtils, Windows, ActiveX, Types, Forms, Controls, Graphics,
  Dialogs, Buttons, LazUTF8, SynEdit, SynHighlighterPython, SynHighlighterSQL,
  SynCompletion, vte_json, vte_dbtreeex, ExtCtrls, StdCtrls, ComCtrls, ActnList,
  Menus, jsonparser, superobject, VirtualTrees, VarPyth, ImgList, SOGrid,
  uvisloading, IdComponent, DefaultTranslator, IniPropStorage, DBGrids,
  ShellCtrls, CheckLst, EditBtn, GetText, uWaptConsoleRes, db,
  BufDataset, SearchEdit, tisstrings;

type

  TPollTasksThread = Class;

  { TVisWaptGUI }

  TVisWaptGUI = class(TForm)
    ActCancelRunningTask: TAction;
    ActDisplayPreferences: TAction;
    ActExternalRepositoriesSettings: TAction;
    ActAddHWPropertyToGrid: TAction;
    ActDisplayUserMessage: TAction;
    ActEditOrgUnitPackage: TAction;
    ActInstallLicence: TAction;
    ActAddProfile: TAction;
    ActSuppr: TAction;
    ActManageUsers: TAction;
    ActSaveRules: TAction;
    ActUpRule: TAction;
    ActDownRule: TAction;
    ActDeleteRule: TAction;
    ActEditRule: TAction;
    ActDisplayDebug: TAction;
    ActRepositoriesGetSecondRepos: TAction;
    ActNewRule: TAction;
    ActRepositoriesGetUpdateRules: TAction;
    cbAdvancedMode: TCheckBox;
    EdSearchOrgUnits: TSearchEdit;
    Label16: TLabel;
    Label19: TLabel;
    LabLogsKB: TLabel;
    GridRules: TSOGrid;
    MenuItem117: TMenuItem;
    MenuItemCheckFiles: TMenuItem;
    MenuItemShowErrors: TMenuItem;
    MenuItemSync: TMenuItem;
    MenuItemSyncForce: TMenuItem;
    Panel1: TPanel;
    PanelKBLogs: TPanel;
    PanelRules: TPanel;
    PanelAgentRepos: TPanel;
    PanelRepositories: TPanel;
    PopupMenu1: TPopupMenu;
    PopupSecRepo: TPopupMenu;
    ActRefreshHostsForPackage: TAction;
    ActTriggerWaptwua_uninstall: TAction;
    ActSoftwaresNormalization: TAction;
    ActReportingQueryExport: TAction;
    ActReportingQueryImport: TAction;
    ActWUAShowDownloadTasks: TAction;
    ActSelfServiceNewPackage: TAction;
    ActSelfServiceSearchPackage: TAction;
    btAddGroup: TBitBtn;
    btAddGroup1: TBitBtn;
    ButCancelHostTask: TBitBtn;
    ButPackagesUpdate1: TBitBtn;
    ButShowDownloadTasks: TBitBtn;
    ButRefreshHostsForPackage: TButton;
    cbHostsHasErrors: TCheckBox;
    cbHostsNeedUpgrade: TCheckBox;
    cbHostsReachable: TCheckBox;
    cbNewestOnlyGroups: TCheckBox;
    cbNewestOnlyWUA: TCheckBox;
    cbNewestOnlySelfService: TCheckBox;
    EdSearchHostsForPackage: TSearchEdit;
    EdWUASearchWindowsUpdate: TSearchEdit;
    GridHostsForPackage: TSOGrid;
    HostRunningTask: TLabeledEdit;
    HostRunningTaskLog: TMemo;
    HostTaskRunningProgress: TProgressBar;
    ImgHostsConnected: TImage;
    ImgHostsHasErrors: TImage;
    ImgHostsNeedUpgrade: TImage;
    MemoInstallOutput1: TMemo;
    MenuItem105: TMenuItem;
    MenuItem106: TMenuItem;
    MenuItem108: TMenuItem;
    MenuItem109: TMenuItem;
    MenuItem110: TMenuItem;
    MenuItem111: TMenuItem;
    MenuItem112: TMenuItem;
    MenuItem113: TMenuItem;
    MenuItem114: TMenuItem;
    MenuItem115: TMenuItem;
    MenuItem4: TMenuItem;
    MenuItem76: TMenuItem;
    PanTaskTop: TPanel;
    PanFilterHosts: TPanel;
    PanHostsForPackage: TPanel;
    PanLeftReporting: TPanel;
    PanWUASearchClassifications: TPanel;
    PopupMenuReportingQueries: TPopupMenu;
    GridAgentRepo: TSOGrid;
    SpeedButton1: TSpeedButton;
    SpeedButton2: TSpeedButton;
    SpeedButton3: TSpeedButton;
    SpeedButton4: TSpeedButton;
    SplitGridUnitsHosts1: TSplitter;
    SplitHostsForPackage: TSplitter;
    Splitter1: TSplitter;
    Splitter12: TSplitter;
    Splitter13: TSplitter;
    Splitter4: TSplitter;
    SplitterRepo: TSplitter;
    SplitTopTaskTaskGrid: TSplitter;
    pgRepositories: TTabSheet;
    SplitHostTaskLog: TSplitter;
    tbDeleteRule: TToolButton;
    tbDownRule: TToolButton;
    tbEditRule: TToolButton;
    TbLeftTopreporting: TToolBar;
    tbNewRule: TToolButton;
    tbRefresh: TToolButton;
    TbRepos: TToolBar;
    tbSaveRules: TToolButton;
    tbSoftwaresNormalization: TToolButton;
    tbUpRule: TToolButton;
    tbAgentRepos: TToolBar;
    TimerSearchHosts: TTimer;
    ToolButton1: TToolButton;
    ToolButton11: TToolButton;
    tbRefeshAgentRepos: TToolButton;
    tbSyncSelected: TToolButton;
    tbSyncAll: TToolButton;
    ToolButton14: TToolButton;
    tbUpdateFileSync: TToolButton;
    tbSyncChangelog: TToolButton;
    ToolButton4: TToolButton;
    ToolButton5: TToolButton;
    ToolButton8: TToolButton;
    ToolButton9: TToolButton;
    ToolButtonReportingQueryDuplicate1: TToolButton;
    ToolButtonSep2: TToolButton;
    WUAConfigPages: TPageControl;
    SelfServiceActions: TActionList;
    ActWUASearchPackage: TAction;
    ActWUAEditPackage: TAction;
    ActVeyon: TAction;
    ActReportingQueryDuplicate: TAction;
    ActTriggerTestLongTask: TAction;
    ActReportingQuerySaveAll: TAction;
    ActReportingQueryDesign: TAction;
    ActReportingQueryNew: TAction;
    ActReportingQueryDelete: TAction;
    btAddGroup3: TBitBtn;
    btAddSelfServicePackage: TBitBtn;
    ButWUAPackagesSearch: TBitBtn;
    ButSelfServicePackagesSearch: TBitBtn;
    cbFilterPackagesArch: TCheckGroup;
    cbFilterPackagesLocales: TCheckGroup;
    CBShowHostsForWUAPackage: TCheckBox;
    CBShowHostsForSelfServicePackage: TCheckBox;
    EdWUASearchPackage: TSearchEdit;
    EdSelfServiceSearchPackage: TSearchEdit;
    GridWUAPackages: TSOGrid;
    GridReportingQueries: TSOGrid;
    GridSelfServicePackages: TSOGrid;
    LabelReportingNumber: TLabel;
    MenuItem107: TMenuItem;
    PanTopWAPTWuaPackages: TPanel;
    PanTopSelfService: TPanel;
    pgSelfService: TTabSheet;
    pgWindowsUpdates: TTabSheet;
    pgWAPTWuaPackages: TTabSheet;
    ToolButton3: TToolButton;
    MenuGridHostsPlugins: TMenuItem;
    VeyonConnect: TMenuItem;
    ActReportingQueryReload: TAction;
    ActReportingQueryExportToExcel: TAction;
    ActReportingQueryExecute: TAction;
    Panel18: TPanel;
    PanReportingRight: TPanel;
    PanelReportingGrid: TPanel;
    PanelReportingEditSQL: TPanel;
    ReportingActions: TActionList;
    ActResetWebsocketConnections: TAction;
    ActRunCleanMgr: TAction;
    ActWUAShowMSUpdatesHelp: TAction;
    ActPackagesAudit: TAction;
    ActTriggerHostAudit: TAction;
    ActTriggerUpgradesOrgUnit: TAction;
    ActTriggerUpdateOrgUnit: TAction;
    ActTriggerWaptServiceRestart: TAction;
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
    ActWSUSRefresh: TAction;
    ApplicationProperties1: TApplicationProperties;
    ButImportFromRepo: TBitBtn;
    ButRefreshWindowsUpdates: TBitBtn;
    ButImportFromFile: TBitBtn;
    ButDownloadWsusscn2cab: TBitBtn;
    ButHostSearch: TBitBtn;
    ButPackagesUpdate: TBitBtn;
    butSearchGroups: TBitBtn;
    Button1: TButton;
    cbAdvancedSearch: TCheckBox;
    cbAllClassifications: TCheckBox;
    cbAllproducts: TCheckBox;
    cbGroups: TComboBox;
    cbHasErrors: TCheckBox;
    CBIncludeSubOU: TCheckBox;
    CBInverseSelect: TCheckBox;
    cbMaskSystemComponents: TCheckBox;
    cbNeedUpgrade: TCheckBox;
    cbReachable: TCheckBox;
    cbAuthorizedHosts: TCheckBox;
    cbSearchAll: TCheckBox;
    cbSearchDMI: TCheckBox;
    cbSearchHost: TCheckBox;
    cbSearchPackages: TCheckBox;
    cbSearchSoftwares: TCheckBox;
    cbADSite: TComboBox;
    cbNewestOnly: TCheckBox;
    CBShowHostsForPackages: TCheckBox;
    cbWUACriticalOnly: TCheckBox;
    cbWUADiscarded: TCheckBox;
    cbWUAInstalled: TCheckBox;
    cbWUAPending: TCheckBox;
    CBWUClassifications: TCheckListBox;
    cbWUCritical: TCheckBox;
    CBShowHostsForGroups: TCheckBox;
    CBWUProducts: TCheckListBox;
    DBOrgUnits: TBufDataset;
    DBOrgUnitsDepth: TLongintField;
    DBOrgUnitsDescription: TStringField;
    DBOrgUnitsDN: TStringField;
    DBOrgUnitsID: TLongintField;
    DBOrgUnitsImageID: TLongintField;
    DBOrgUnitsParentDN: TStringField;
    DBOrgUnitsParentID: TLongintField;
    EdWUAStatus: TEdit;
    EdWAPTWUAEnabled: TEdit;
    EdWUAAgentVersion: TEdit;
    EdWsusscn2cabDate: TEdit;
    EdLastScanDate: TEdit;
    EdLastScanDuration: TEdit;
    GridHostWinUpdatesHistory: TSOGrid;
    GridPackages: TSOGrid;
    GridWUUpdates: TSOGrid;
    Label10: TLabel;
    Label17: TLabel;
    Label18: TLabel;
    Label21: TLabel;
    Label22: TLabel;
    Label4: TLabel;
    LabUser1: TLabel;
    MenuItem100: TMenuItem;
    MenuItem101: TMenuItem;
    MenuItem102: TMenuItem;
    MenuItem103: TMenuItem;
    MenuItem103CheckAll: TMenuItem;
    MenuItem105UncheclAll: TMenuItem;
    MenuItemProductsCheckAll: TMenuItem;
    MenuItem104: TMenuItem;
    MenuItem88: TMenuItem;
    MenuItem89: TMenuItem;
    MenuItem90: TMenuItem;
    MenuItem91: TMenuItem;
    MenuItem92: TMenuItem;
    MenuItem93: TMenuItem;
    MenuItem94: TMenuItem;
    MenuItem95: TMenuItem;
    MenuItem96: TMenuItem;
    MenuItem97: TMenuItem;
    MenuItem98: TMenuItem;
    MenuItem99: TMenuItem;
    Panel17: TPanel;
    Panel9: TPanel;
    PanWUALeft: TPanel;
    PanTopWindowsUpdates: TPanel;
    PanWUAMain: TPanel;
    PanWUASearchProducts: TPanel;
    PopupWUAClassifications: TPopupMenu;
    PopupMenuOrgUnits: TPopupMenu;
    PopupHostWUAUpdates: TPopupMenu;
    GridReportingResult: TSOGrid;
    SplitQueriesReport: TSplitter;
    SplitterReportingHorizontal: TSplitter;
    SplitWinupdateHost: TSplitter;
    SrcOrgUnits: TDataSource;
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
    GridWSUSScan: TSOGrid;
    ActionsImages24: TImageList;
    Image1: TImage;
    Image2: TImage;
    Image3: TImage;
    Image4: TImage;
    Label1: TLabel;
    Label11: TLabel;
    Label12: TLabel;
    Label15: TLabel;
    Label2: TLabel;
    LabFilterSite: TLabel;
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
    PanOUFilter: TPanel;
    PanOrgUnits: TPanel;
    PanTopHosts: TPanel;
    panFilterStatus: TPanel;
    PanHostsFilters: TPanel;
    PanTopFilterInventory: TPanel;
    Panel15: TPanel;
    Panel16: TPanel;
    PanFilterGroups: TPanel;
    PanHostsSubFilters: TPanel;
    PanHosts: TPanel;
    PanSearch: TPanel;
    PanSearchIn: TPanel;
    PopupGridWSUSScan: TPopupMenu;
    MenuItem70: TMenuItem;
    MenuItem71: TMenuItem;
    MenuItem72: TMenuItem;
    MenuItem73: TMenuItem;
    pgWaptWUAConfig: TTabSheet;
    SplitGridUnitsHosts: TSplitter;
    PgReports: TTabSheet;
    SynCompletion1: TSynCompletion;
    SynEditReportsSQL: TSynEdit;
    SynSQLSyn: TSynSQLSyn;
    tbReportingExportExcel: TToolButton;
    TimerSearchPackages: TTimer;
    TimerWUALoadWinUpdates: TTimer;
    ToolBar1: TToolBar;
    TbReport: TToolBar;
    ToolButtonDesignQuery: TToolButton;
    ToolButtonUpgrade: TToolButton;
    ToolButton2: TToolButton;
    ToolButtonRefresh: TToolButton;
    ToolButtonUpdate: TToolButton;
    ToolButton6: TToolButton;
    ToolButtonSep1: TToolButton;
    GridOrgUnits: TVirtualDBTreeEx;
    WSUSActions: TActionList;
    ActWUANewPackage: TAction;
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
    MainActionList: TActionList;
    butInitWapt: TBitBtn;
    butRun: TBitBtn;
    butSearchPackages: TBitBtn;
    cbShowHostPackagesSoft: TCheckBox;
    cbShowHostPackagesGroup: TCheckBox;
    cbShowLog: TCheckBox;
    GridGroups: TSOGrid;
    GridHostWinUpdates: TSOGrid;
    GridHostTasksPending: TSOGrid;
    GridHostTasksDone: TSOGrid;
    GridHostTasksErrors: TSOGrid;
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
    PagesTasks: TPageControl;
    PanTopGroups: TPanel;
    Panel12: TPanel;
    PopupWUAProducts: TPopupMenu;
    Panel3: TPanel;
    Panel5: TPanel;
    PanLog: TPanel;
    plStatusBar1: TPanel;
    PopupHostPackages: TPopupMenu;
    PopupWUAUpdates: TPopupMenu;
    PopupMenuGroups: TPopupMenu;
    ProgressBar: TProgressBar;
    EdRun: TEdit;
    EdSearchPackage: TSearchEdit;
    ImageList1: TImageList;
    pgGroups: TTabSheet;
    Splitter3: TSplitter;
    pgTasks: TTabSheet;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    TabSheet3: TTabSheet;
    pgHostWUA: TTabSheet;
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
    MenuItem5: TMenuItem;
    MenuItem6: TMenuItem;
    MenuItem7: TMenuItem;
    MenuItem8: TMenuItem;
    MenuItem9: TMenuItem;
    MainPages: TPageControl;
    HostPages: TPageControl;
    PanSourcesTop: TPanel;
    PanDebug: TPanel;
    Panel4: TPanel;
    Panel7: TPanel;
    PopupMenuHosts: TPopupMenu;
    PopupMenuPackages: TPopupMenu;
    SplitBottomDebug: TSplitter;
    Splitter2: TSplitter;
    SynPythonSyn1: TSynPythonSyn;
    pgSources: TTabSheet;
    pgPrivateRepo: TTabSheet;
    pgInventory: TTabSheet;
    pgPackages: TTabSheet;
    pgSoftwares: TTabSheet;
    pgHostInventory: TTabSheet;
    MemoEditSourcesTest: TSynEdit;
    jsonlog: TVirtualJSONInspector;
    GridHostPackages: TSOGrid;
    GridHostSoftwares: TSOGrid;
    procedure ActAddADSGroupsExecute(Sender: TObject);
    procedure ActAddConflictsExecute(Sender: TObject);
    procedure ActAddDependsExecute(Sender: TObject);
    procedure ActAddDependsUpdate(Sender: TObject);
    procedure ActAddHWPropertyToGridExecute(Sender: TObject);
    procedure ActAddHWPropertyToGridUpdate(Sender: TObject);
    procedure ActAddProfileExecute(Sender: TObject);
    procedure ActSupprExecute(Sender: TObject);
    procedure ActManageUsersExecute(Sender: TObject);
    procedure ActSaveRulesExecute(Sender: TObject);
    procedure ActUpRuleExecute(Sender: TObject);
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
    procedure ActDeleteRuleExecute(Sender: TObject);
    procedure ActDownRuleExecute(Sender: TObject);
    procedure ActDisplayDebugExecute(Sender: TObject);
    procedure ActDisplayPreferencesExecute(Sender: TObject);
    procedure ActDisplayUserMessageExecute(Sender: TObject);
    procedure ActEditGroupUpdate(Sender: TObject);
    procedure ActEditHostPackageUpdate(Sender: TObject);
    procedure ActEditOrgUnitPackageExecute(Sender: TObject);
    procedure ActEditOrgUnitPackageUpdate(Sender: TObject);
    procedure ActEditRuleExecute(Sender: TObject);
    procedure ActForgetPackagesUpdate(Sender: TObject);
    procedure ActGermanExecute(Sender: TObject);
    procedure ActGermanUpdate(Sender: TObject);
    procedure ActHostsDeletePackageUpdate(Sender: TObject);
    procedure ActHostsDeleteUpdate(Sender: TObject);
    procedure ActNewRuleExecute(Sender: TObject);
    procedure ActRefreshHostsForPackageExecute(Sender: TObject);
    procedure ActReportingQueryExportExecute(Sender: TObject);
    procedure ActReportingQueryImportExecute(Sender: TObject);
    procedure ActReportingQueryImportUpdate(Sender: TObject);
    procedure ActRepositoriesGetSecondReposExecute(Sender: TObject);
    procedure ActRepositoriesGetUpdateRulesExecute(Sender: TObject);
    procedure ActSelfServiceNewPackageExecute(Sender: TObject);
    procedure ActSelfServiceSearchPackageExecute(Sender: TObject);
    procedure ActLaunchGPUpdateExecute(Sender: TObject);
    procedure ActLaunchWaptExitExecute(Sender: TObject);
    procedure ActmakePackageTemplateExecute(Sender: TObject);
    procedure ActPackagesAuditExecute(Sender: TObject);
    procedure ActPackagesForceInstallExecute(Sender: TObject);
    procedure ActPackagesRemoveUpdate(Sender: TObject);
    procedure ActProprietaryExecute(Sender: TObject);
    procedure ActRemoteAssistExecute(Sender: TObject);
    procedure ActRemoteAssistUpdate(Sender: TObject);
    procedure ActExternalRepositoriesSettingsExecute(Sender: TObject);
    procedure ActReportingQueryDesignUpdate(Sender: TObject);
    procedure ActReportingQueryDuplicateExecute(Sender: TObject);
    procedure ActReportingQueryDuplicateUpdate(Sender: TObject);
    procedure ActReportingQueryDesignExecute(Sender: TObject);
    procedure ActReportingQueryNewUpdate(Sender: TObject);
    procedure ActReportingQuerySaveAllExecute(Sender: TObject);
    procedure ActReportingQuerySaveAllUpdate(Sender: TObject);
    procedure ActReportingQueryDeleteExecute(Sender: TObject);
    procedure ActReportingQueryNewExecute(Sender: TObject);
    procedure ActReportingQueryDeleteUpdate(Sender: TObject);
    procedure ActReportingQueryExecuteExecute(Sender: TObject);
    procedure ActReportingQueryExecuteUpdate(Sender: TObject);
    procedure ActReportingQueryExportToExcelExecute(Sender: TObject);
    procedure ActReportingQueryExportToExcelUpdate(Sender: TObject);
    procedure ActReportingQueryReloadExecute(Sender: TObject);
    procedure ActResetWebsocketConnectionsExecute(Sender: TObject);
    procedure ActRunCleanMgrExecute(Sender: TObject);
    procedure ActTISHelpExecute(Sender: TObject);
    procedure ActTISHelpUpdate(Sender: TObject);
    procedure ActTriggerBurstUpdatesExecute(Sender: TObject);
    procedure ActTriggerBurstUpgradesExecute(Sender: TObject);
    procedure ActTriggerHostAuditExecute(Sender: TObject);
    procedure ActTriggerTestLongTaskExecute(Sender: TObject);
    procedure ActTriggerUpdateOrgUnitExecute(Sender: TObject);
    procedure ActTriggerUpgradesOrgUnitExecute(Sender: TObject);
    procedure ActTriggerUpgradesOrgUnitUpdate(Sender: TObject);
    procedure ActTriggerWakeOnLanExecute(Sender: TObject);
    procedure ActTriggerWaptServiceRestartExecute(Sender: TObject);
    procedure ActTriggerWaptwua_downloadExecute(Sender: TObject);
    procedure ActTriggerWaptwua_installExecute(Sender: TObject);
    procedure ActTriggerWaptwua_scanExecute(Sender: TObject);
    procedure ActTriggerWaptwua_scanUpdate(Sender: TObject);
    procedure ActTriggerWaptwua_uninstallExecute(Sender: TObject);
    procedure ActVeyonExecute(Sender: TObject);
    procedure ActVeyonUpdate(Sender: TObject);
    procedure ActWSUSDowloadWSUSScanExecute(Sender: TObject);
    procedure ActWSUSRefreshExecute(Sender: TObject);
    procedure ActWSUSSaveBuildRulesExecute(Sender: TObject);
    procedure ActWSUSSaveBuildRulesUpdate(Sender: TObject);
    procedure ActWUAAddAllowedClassificationExecute(Sender: TObject);
    procedure ActWUAAddAllowedUpdateExecute(Sender: TObject);
    procedure ActWUAAddForbiddenUpdateExecute(Sender: TObject);
    procedure ActWUADownloadSelectedUpdateExecute(Sender: TObject);
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
    procedure ActWUANewPackageExecute(Sender: TObject);
    procedure ActWUAProductHideExecute(Sender: TObject);
    procedure ActWUAProductShowExecute(Sender: TObject);
    procedure ActWUAProductsSelectionExecute(Sender: TObject);
    procedure ActRestoreDefaultLayoutExecute(Sender: TObject);
    procedure ActSearchGroupsExecute(Sender: TObject);
    procedure ActTriggerHostUpdateExecute(Sender: TObject);
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
    procedure ActWUASearchPackageExecute(Sender: TObject);
    procedure ActWUAShowDownloadTasksExecute(Sender: TObject);
    procedure ActWUAShowMSUpdatesHelpExecute(Sender: TObject);
    procedure ApplicationProperties1Exception(Sender: TObject; E: Exception);
    procedure cbADOUSelect(Sender: TObject);
    procedure cbADSiteSelect(Sender: TObject);
    procedure cbAdvancedModeClick(Sender: TObject);
    procedure cbAdvancedSearchClick(Sender: TObject);
    procedure cbAllClassificationsClick(Sender: TObject);
    procedure cbAllproductsClick(Sender: TObject);
    procedure cbFilterPackagesArchItemClick(Sender: TObject; Index: integer);
    procedure cbFilterPackagesLocalesItemClick(Sender: TObject; Index: integer);
    procedure cbGroupsDropDown(Sender: TObject);
    procedure cbGroupsKeyPress(Sender: TObject; var Key: char);
    procedure cbGroupsSelect(Sender: TObject);
    procedure cbHostsHasErrorsClick(Sender: TObject);
    procedure CBIncludeSubOUClick(Sender: TObject);
    procedure CBInverseSelectClick(Sender: TObject);
    procedure cbMaskSystemComponentsClick(Sender: TObject);
    procedure cbNewestOnlyClick(Sender: TObject);
    procedure cbNewestOnlySelfServiceClick(Sender: TObject);
    procedure cbNewestOnlyWUAClick(Sender: TObject);
    procedure cbSearchAllClick(Sender: TObject);
    procedure CBShowHostsForGroupsClick(Sender: TObject);
    procedure CBShowHostsForPackagesClick(Sender: TObject);
    procedure CBShowHostsForWUAPackageClick(Sender: TObject);
    procedure CBShowHostsForSelfServicePackageClick(Sender: TObject);
    procedure cbShowLogClick(Sender: TObject);
    procedure cbADSiteDropDown(Sender: TObject);
    procedure cbWUAPendingChange(Sender: TObject);
    procedure CBWUClassificationsClick(Sender: TObject);
    procedure cbWUCriticalClick(Sender: TObject);
    procedure CBWUProductsClick(Sender: TObject);
    procedure CBWUProductsShowAllClick(Sender: TObject);
    procedure CheckBoxMajChange(Sender: TObject);
    procedure cbNeedUpgradeClick(Sender: TObject);
    procedure CheckBox_errorChange(Sender: TObject);
    procedure DBOrgUnitsFilterRecord(DataSet: TDataSet; var Accept: Boolean);
    procedure EdDescriptionExit(Sender: TObject);
    procedure EdDescriptionKeyPress(Sender: TObject; var Key: char);
    procedure EdHardwareFilterChange(Sender: TObject);
    procedure EdRunKeyPress(Sender: TObject; var Key: char);
    procedure EdSearchHostsForPackageKeyPress(Sender: TObject; var Key: char);
    procedure EdSearchOrgUnitsChange(Sender: TObject);
    procedure EdSearchOrgUnitsKeyPress(Sender: TObject; var Key: char);
    procedure EdSearchPackageExecute(Sender: TObject);
    procedure EdSearchGroupsExecute(Sender: TObject);
    procedure EdSearchGroupsKeyPress(Sender: TObject; var Key: char);
    procedure EdSearchHostExecute(Sender: TObject);
    procedure EdSearchHostKeyPress(Sender: TObject; var Key: char);
    procedure EdSoftwaresFilterChange(Sender: TObject);
    procedure EdWUASearchPackageKeyPress(Sender: TObject; var Key: char);
    procedure EdWUASearchWindowsUpdateKeyPress(Sender: TObject; var Key: char);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormDragOver(Sender, Source: TObject; X, Y: Integer;
      State: TDragState; var Accept: Boolean);
    procedure FormDropFiles(Sender: TObject; const FileNames: array of String);
    procedure FormShow(Sender: TObject);
    procedure GridAgentRepoChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
    procedure GridAgentRepoGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: Boolean; var ImageIndex: Integer;
      var ImageList: TCustomImageList);
    procedure GridGroupsChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
    procedure GridGroupsColumnDblClick(Sender: TBaseVirtualTree;
      Column: TColumnIndex; Shift: TShiftState);
    procedure GridGroupsGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      RowData, CellData: ISuperObject; Column: TColumnIndex;
      TextType: TVSTTextType; var CellText: string);
    procedure GridGroupsInitNode(Sender: TBaseVirtualTree;
      ParentNode, Node: PVirtualNode; var InitialStates: TVirtualNodeInitStates);
    procedure GridGroupsMeasureItem(Sender: TBaseVirtualTree;
      TargetCanvas: TCanvas; Node: PVirtualNode; var NodeHeight: integer);
    procedure GridGroupsSOCompareNodes(Sender: TSOGrid; Node1,
      Node2: ISuperObject; const Columns: array of String; var Result: Integer);
    procedure GridHostPackagesChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
    procedure GridHostPackagesClick(Sender: TObject);
    procedure GridHostPackagesFocusChanged(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Column: TColumnIndex);
    procedure GridHostPackagesGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: boolean; var ImageIndex: integer;
      var ImageList: TCustomImageList);
    procedure GridHostPackagesGetText(Sender: TBaseVirtualTree;
      Node: PVirtualNode; RowData, CellData: ISuperObject;
      Column: TColumnIndex; TextType: TVSTTextType; var CellText: string);
    procedure GridHostPackagesNodesDelete(Sender: TSOGrid; Nodes: ISuperObject);
    procedure GridHostsChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
    procedure GridHostsClick(Sender: TObject);
    procedure GridHostsColumnDblClick(Sender: TBaseVirtualTree;
      Column: TColumnIndex; Shift: TShiftState);
    procedure GridHostsDragDrop(Sender: TBaseVirtualTree; Source: TObject;
      DataObject: IDataObject; Formats: TFormatArray; Shift: TShiftState;
      const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
    procedure GridHostsDragOver(Sender: TBaseVirtualTree; Source: TObject;
      Shift: TShiftState; State: TDragState; const Pt: TPoint;
      Mode: TDropMode; var Effect: DWORD; var Accept: boolean);
    procedure GridHostsEditing(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; var Allowed: boolean);
    procedure GridHostsForPackageChange(Sender: TBaseVirtualTree;
      Node: PVirtualNode);
    procedure GridHostsForPackageFocusChanged(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Column: TColumnIndex);
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
    procedure GridHostsSOCompareNodes(Sender: TSOGrid; Node1,
      Node2: ISuperObject; const Columns: array of String; var Result: Integer);
    procedure GridHostTasksPendingClick(Sender: TObject);
    procedure GridHostWinUpdatesChange(Sender: TBaseVirtualTree;
      Node: PVirtualNode);
    procedure GridHostTasksPendingChange(Sender: TBaseVirtualTree;
      Node: PVirtualNode);
    procedure GridHostWinUpdatesClick(Sender: TObject);
    procedure GridHostWinUpdatesGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: Boolean; var ImageIndex: Integer;
      var ImageList: TCustomImageList);
    procedure GridHostWinUpdatesGetText(Sender: TBaseVirtualTree;
      Node: PVirtualNode; RowData, CellData: ISuperObject;
      Column: TColumnIndex; TextType: TVSTTextType; var CellText: string);
    procedure GridOrgUnitsChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
    procedure GridOrgUnitsGetHint(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; var LineBreakStyle: TVTTooltipLineBreakStyle;
      var HintText: String);
    procedure GridPackagesChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
    procedure GridPackagesColumnDblClick(Sender: TBaseVirtualTree;
      Column: TColumnIndex; Shift: TShiftState);
    procedure GridPackagesPaintText(Sender: TBaseVirtualTree;
      const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
      TextType: TVSTTextType);
    function GridReportingQueriesBeforePaste(Sender: TSOGrid; Row: ISuperObject
      ): boolean;
    procedure GridReportingQueriesChange(Sender: TBaseVirtualTree;
      Node: PVirtualNode);
    procedure GridReportingQueriesDrawText(Sender: TBaseVirtualTree;
      TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
      const AText: String; const CellRect: TRect; var DefaultDraw: Boolean);
    procedure GridReportingQueriesEdited(Sender: TBaseVirtualTree;
      Node : PVirtualNode; Column: TColumnIndex);
    procedure GridReportingQueriesEditing(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Column: TColumnIndex; var Allowed: Boolean);
    procedure GridReportingQueriesKeyPress(Sender: TObject; var Key: char);
    procedure GridReportingResultChange(Sender: TBaseVirtualTree;
      Node: PVirtualNode);
    procedure GridReportingResultColumnResize(Sender: TVTHeader;
      Column: TColumnIndex);
    procedure GridReportingResultGetText(Sender: TBaseVirtualTree;
      Node: PVirtualNode; RowData, CellData: ISuperObject;
      Column: TColumnIndex; TextType: TVSTTextType; var CellText: string);
    procedure GridReportingResultHeaderClick(Sender: TVTHeader;
      HitInfo: TVTHeaderHitInfo);
    procedure GridReportingResultHeaderDragged(Sender: TVTHeader;
      Column: TColumnIndex; OldPosition: Integer);
    procedure GridReportingResultSOCompareNodes(Sender: TSOGrid; Node1,
      Node2: ISuperObject; const Columns: array of String; var Result: Integer);
    procedure GridRulesChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
    procedure GridRulesDblClick(Sender: TObject);
    procedure GridRulesGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
        RowData, CellData: ISuperObject; Column: TColumnIndex;
        TextType: TVSTTextType; var CellText: string);
    procedure GridSelfServicePackagesChange(Sender: TBaseVirtualTree;
      Node: PVirtualNode);
    procedure GridSelfServicePackagesColumnDblClick(Sender: TBaseVirtualTree;
      Column: TColumnIndex; Shift: TShiftState);
    procedure GridUsersDrawText(Sender: TBaseVirtualTree;
      TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
      const AText: String; const CellRect: TRect; var DefaultDraw: Boolean);
    procedure GridUsersKeyDown(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure GridWinproductsChange(Sender: TBaseVirtualTree; Node: PVirtualNode );
    procedure GridWinUpdatesGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: Boolean; var ImageIndex: Integer;
      var ImageList: TCustomImageList);
    procedure GridWUAPackagesChange(Sender: TBaseVirtualTree; Node: PVirtualNode
      );
    procedure GridWUAPackagesColumnDblClick(Sender: TBaseVirtualTree;
      Column: TColumnIndex; Shift: TShiftState);
    procedure GridWUAPackagesNodesDelete(Sender: TSOGrid; Nodes: ISuperObject);
    procedure GridWUUpdatesNodesDelete(Sender: TSOGrid; Nodes: ISuperObject);
    procedure HostPagesChange(Sender: TObject);
    procedure Image1Click(Sender: TObject);
    procedure MainPagesChange(Sender: TObject);
    procedure MenuItem103CheckAllClick(Sender: TObject);
    procedure MenuItem104Click(Sender: TObject);
    procedure MenuItem105UncheclAllClick(Sender: TObject);
    procedure MenuItem27Click(Sender: TObject);
    procedure MenuItem74Click(Sender: TObject);
    procedure MenuItemCheckFilesClick(Sender: TObject);
    procedure MenuItemProductsCheckAllClick(Sender: TObject);
    procedure MenuItemShowErrorsClick(Sender: TObject);
    procedure MenuItemSyncClick(Sender: TObject);
    procedure MenuItemSyncForceClick(Sender: TObject);
    procedure PagesTasksChange(Sender: TObject);
    procedure PopupMenuHostsPopup(Sender: TObject);
    procedure SpeedButton1Click(Sender: TObject);
    procedure SpeedButton2Click(Sender: TObject);
    procedure SpeedButton3Click(Sender: TObject);
    procedure SpeedButton4Click(Sender: TObject);
    procedure SynEditReportsSQLChange(Sender: TObject);
    procedure tbSyncAllClick(Sender: TObject);
    procedure tbSyncChangelogClick(Sender: TObject);
    procedure tbSyncSelectedClick(Sender: TObject);
    procedure tbUpdateFileSyncClick(Sender: TObject);
    procedure TimerSearchHostsTimer(Sender: TObject);
    procedure TimerSearchPackagesTimer(Sender: TObject);
    procedure TimerWUALoadWinUpdatesTimer(Sender: TObject);
    procedure WUAConfigPagesChange(Sender: TObject);
    procedure ActSoftwaresNormalizationExecute(Sender: TObject);
  private
    { private declarations }
    CurrentVisLoading: TVisLoading;
    FCurrentPackageForGridHostsForPackage: String;
    FReportingEditMode: Boolean;
    FWUAClassifications: ISuperObject;
    FWUAProducts: ISuperObject;
    FWUAWinUpdates: ISuperObject;
    FWUAWinUpdatesLookup: ISuperObject;
    FReportingLoadingQuery : boolean;
    FReportingQueryTmpId: Integer;
    FGridHostsPlugins: ISuperObject;

    procedure DoProgress(ASender: TObject);
    function EditHostPackageEntry(host: ISuperObject): Variant;
    procedure ExecuteHostsGruidPlugin(Sender: TObject);
    procedure FillcbADSiteDropDown;
    procedure FillcbGroups;
    function MaxSeq:Integer;
    procedure FilterDBOrgUnits;
    function FilterHostsForPackage(HostsData: ISuperObject): ISuperObject;
    function FilterSoftwares(softs: ISuperObject): ISuperObject;
    function FilterHardware(data: ISuperObject): ISuperObject;
    function FilterHostWinUpdates(wua: ISuperObject): ISuperObject;
    procedure FilterGridWindowsUpdates(Sender: TObject);
    function FilterWinProducts(products: ISuperObject): ISuperObject;
    function GetGridHostsPlugins: ISuperObject;
    function GetWUAClassifications: ISuperObject;
    function GetWUAProducts: ISuperObject;
    function GetWUAWinUpdates: ISuperObject;
    procedure GridReportingSaveSettings(Report: ISuperObject);
    Function LoadHostInventory(host:ISuperObject): ISuperObject;
    function OneHostHasConnectedIP(GridHostsIPs:TSOGrid=Nil): Boolean;
    function OneHostIsConnected(GridHostsReachable:TSOGrid=Nil): Boolean;
    function GetSelectedOrgUnits: TDynStringArray;
    function ReportingQueryAppend(AName: String='New query'; sql: String='SELEC'
      +'T 1'): ISuperObject;
    procedure SelectOrgUnits(Search: String);
    procedure SetCurrentPackageForGridHostsForPackage(AValue: String);
    procedure SetGridHostsPlugins(AValue: ISuperObject);
    procedure SetIsEnterpriseEdition(AValue: Boolean);
    function GetIsEnterpriseEdition: Boolean;
    function GetSelectedUUID: ISuperObject;
    procedure GridLoadData(grid: TSOGrid; jsondata: string);
    procedure HandleServerResult(ServerResult: ISuperObject);
    procedure IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: int64);
    function InventoryData(uuid: String): ISuperObject;
    procedure MakePackageTemplate(AInstallerFileName: String);
    procedure SetReportingEditMode(AValue: Boolean);
    function TriggerChangeHostDescription(uuid, description: String): Boolean;
    procedure UpdateHostPages(Sender: TObject);
    procedure UpdateSelectedHostsActions(Sender: TObject);
    procedure PythonOutputSendData(Sender: TObject; const Data: ansistring);
    procedure TreeLoadData(tree: TVirtualJSONInspector; jsondata: ISuperObject);

    procedure LoadOrgUnitsTree(Sender: TObject);

    function ApplyUpdates(const datasets: array of ISuperObject):Boolean;
    function IsUpdated(const datasets: Array of ISuperObject):Boolean;
    function CheckUpdates(const datasets: Array of ISuperObject):Boolean;

    procedure UpdateTasksReport(tasksresult: ISuperObject);
    procedure SetGridReportingData( data : ISuperObject );
    procedure SetReportingDirty(Report:ISuperObject);
    function DesassociationTranslationCondRules(trans:String):String;
    function AssociationTranslationCondRules(origin:String):String;
  public
    { public declarations }
    MainRepoUrl, WaptServer, TemplatesRepoUrl: string;
    HostsLimit: Integer;

    AppLoading:Boolean;
    inSearchHosts:Boolean;

    OrgUnitsHash:Integer;
    OrgUnitsSelectionHash:Integer;
    FilteredOrgUnits:TDynStringArray;

    WUAPreferredProducts,
    WUAPreferredClassifications : TDynStringArray;

    PollTasksThread: TPollTasksThread;

    HostsForPackageData: ISuperObject;
    SyncVersion : Integer;
    SyncID : Integer;

    property GridHostsPlugins: ISuperObject read GetGridHostsPlugins write SetGridHostsPlugins;

    property WUAClassifications : ISuperObject read GetWUAClassifications write FWUAClassifications;
    property WUAProducts : ISuperObject read GetWUAProducts write FWUAProducts;
    property WUAWinUpdates : ISuperObject read GetWUAWinUpdates write FWUAWinUpdates;

    constructor Create(TheOwner: TComponent); override;

    function Login: boolean;
    function EditIniFile: boolean;
    function updateprogress(receiver: TObject; current, total: integer): boolean;
    function TriggerActionOnHosts(uuids: ISuperObject;AAction:String;Args:ISuperObject;title,errortitle:String;Force:Boolean=False;NotifyServer:Boolean=True):ISuperObject;
    procedure TriggerActionOnHostPackages(APackagesStatusGrid:TSOGrid;HostUUIDs:ISuperObject;AAction, title, errortitle: String;Force:Boolean=False);
    function DownloadPackage(RepoUrl, Filename: String): Variant;

    property IsEnterpriseEdition:Boolean read GetIsEnterpriseEdition write SetIsEnterpriseEdition;
    property ReportingEditMode:Boolean read FReportingEditMode write SetReportingEditMode;

    function EditPackageEntry(Entry: ISuperObject): Variant;
    procedure ImportPackageFromFiles(Filenames: TStrings);

    property CurrentPackageForGridHostsForPackage:String read FCurrentPackageForGridHostsForPackage write SetCurrentPackageForGridHostsForPackage;


  end;


  { TPollTasksThread }
  TPollTasksThread = Class(TThread)
    procedure HandleTasks;

  public
    PollTimeout:Integer;
    ErrorSleepTime:Integer;

    ErrorMessage:String;

    WaptConsole:TVisWaptGUI;
    Tasks: ISuperObject;
    HostUUID:String;
    LastEventId: Integer;

    constructor Create(aWaptconsole:TVisWaptGUI;aHostUUID:String);
    destructor Destroy; override;
    procedure Execute; override;
  end;


var
  VisWaptGUI: TVisWaptGUI;

implementation

uses LCLIntf, LCLType, IniFiles, variants, LazFileUtils,FileUtil, base64,
  strutils,
  uvisprivatekeyauth, soutils,
  waptcommon, waptwinutils, tiscommon, uVisCreateKey, uVisCreateWaptSetup,
  dmwaptpython, uviseditpackage, uvislogin, uviswaptconfig, uvischangepassword,
  uvisgroupchoice, uvistriggerhostsaction, uVisAPropos,
  uVisImportPackage, PythonEngine, Clipbrd, RegExpr, tisinifiles, IdURI,
  uVisPackageWizard, uVisChangeKeyPassword, uVisDisplayPreferences,
  uvisrepositories, uVisHostDelete, windirs,winutils,uWaptPythonUtils
  {$ifdef ENTERPRISE}
  ,uVisWUAGroup,uviswuadownloads,uvissoftwaresnormalization,uvisselfservicegroup,
  uviseditcreaterule,uvissyncchangelog, uVisErrorsRepos, uviswaptusers
  {$endif}
  {$ifdef wsus},uVisWAPTWUAProducts, uviswuapackageselect,
  uVisWUAClassificationsSelect
  {$endif};

{$R *.lfm}

const
  IMG_CHECKBOX_ENABLE_CHECKED   = 15;
  IMG_CHECKBOX_ENABLE_UNCHECKED = 16;
  IMG_CHECKBOX_DISABLE_CHECKED  = 17;
  IMG_CHECKBOX_DISABLE_UNCHECKED= 18;

type TComponentsArray=Array of TComponent;

{ TVisWaptGUI }

function GetCheckListBoxItemsChecked(LB:TCheckListBox):TDynStringArray;
var
  i:integer;
begin
  SetLength(Result,0);
  for i := 0 to LB.Items.Count-1 do
    if LB.Checked[i] then
      StrAppend(Result,LB.Items[i]);
end;

Procedure SetCheckListBoxItemsChecked(LB:TCheckListBox;checked:TDynStringArray);
var
  i:integer;
begin
  for i := 0 to LB.Items.Count-1 do
    LB.Checked[i] := StrIsOneOf(LB.Items[i],checked);
end;



procedure SetSOGridVisible(Grid:TSOGrid;PropertyName:String;Visible:Boolean);
var
  Acol: TSOGridColumn;
begin
  ACol := Grid.FindColumnByPropertyName(PropertyName);
  If Acol<>Nil then
  begin
    if Visible then
      ACol.Options := ACol.Options+[coVisible]
    else
      ACol.Options := ACol.Options-[coVisible]
  end;
end;

procedure SetSOGridEnabled(Grid:TSOGrid;PropertyName:String;Enabled:Boolean);
var
  Acol: TSOGridColumn;
begin
  ACol := Grid.FindColumnByPropertyName(PropertyName);
  If Acol<>Nil then
  begin
    if Enabled then
      ACol.Options := ACol.Options+[coEnabled,coEditable,coResizable]
    else
      ACol.Options := ACol.Options-[coEnabled,coEditable,coResizable]
  end;
end;

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
  vncpathes: Array[0..6] of String = ('C:\Program Files\uvnc bvba\UltraVNC\vncviewer.exe',
    'C:\Program Files (x86)\uvnc bvba\UltraVNC\vncviewer.exe',
    'C:\Program Files (x86)\UltraVNC\vncviewer.exe',
    'C:\Program Files\UltraVNC\vncviewer.exe',
    'C:\Program Files\TightVNC\tvnviewer.exe',
    'C:\Program Files\TightVNC\tvnviewer64.exe',
    'C:\Program Files (x86)\TightVNC\tvnviewer.exe');
var
  p:String;
begin
  Result := '';
  for p in vncpathes do
    if FileExistsUTF8(p) then
    begin
      Result := p;
      Break;
    end;
end;

function GetVeyonPath:String;
const
  veyonpathes: Array[0..1] of String = ('C:\Program Files\Veyon\veyon-cli.exe',
  'C:\Program Files (x86)\Veyon\veyon-cli.exe');
var
  p:String;
begin
  Result := '';
  for p in veyonpathes do
    if FileExistsUTF8(p) then
    begin
      Result := p;
      Break;
    end;
end;

{ TPollTasksThread }

procedure TPollTasksThread.HandleTasks;
var
  RowSO:ISuperObject;
  CurrHost:String;
begin
  if Terminated then
  begin
    if Waptconsole.PollTasksThread = Self then
      Waptconsole.PollTasksThread := Nil;
  end
  else
  begin
    RowSO := WaptConsole.Gridhosts.FocusedRow;
    if (RowSO <> nil) then
      currhost := UTF8Encode(RowSO.S['uuid'])
    else
      currhost := '';

    // Drop result of the request as it is no more needed.
    if  (CurrHost='') or (CurrHost<>HostUUID) or (Waptconsole.PollTasksThread<>Self) or
        (WaptConsole.HostPages.ActivePage <> WaptConsole.pgTasks) or
        (WaptConsole.MainPages.ActivePage <> WaptConsole.pgInventory) then
    begin
      if Waptconsole.PollTasksThread = Self then
        Waptconsole.PollTasksThread := Nil;
      Terminate;
    end
    else
    begin
      WaptConsole.UpdateTasksReport(Tasks);
      if ErrorMessage<>'' then
        WaptConsole.HostRunningTask.Text:=ErrorMessage;
    end
  end;
end;

constructor TPollTasksThread.Create(aWaptconsole: TVisWaptGUI;aHostUUID:String);
begin
  WaptConsole := aWaptconsole;
  PollTimeout := 10;
  ErrorSleepTime := 1000;
  ErrorMessage:= '';
  HostUUID:=aHostUUID;
  LastEventId:=-1;
  FreeOnTerminate:=True;
  inherited Create(False);
end;

destructor TPollTasksThread.Destroy;
begin
  Synchronize(@HandleTasks);
  inherited Destroy;
end;

procedure TPollTasksThread.Execute;
var
  sores:ISuperObject;
begin
  while not Terminated do
    try
      if HostUUID <> '' then
      begin
        sores := WAPTServerJsonGet('api/v3/host_tasks_status?uuid=%S&timeout=%D&client_tasks_timeout=%D&last_event_id=%D', [HostUUID,PollTimeout,PollTimeout+5,LastEventId],'GET',4000,60000,PollTimeout*1000);
        if sores.B['success'] then
        begin
          Tasks := sores['result'];
          ErrorMessage := '';
          If Tasks <> Nil then
          begin
            LastEventId := Tasks.I['last_event_id'];
            Synchronize(@HandleTasks);
            // Old client without long polling
            if Tasks['last_event_id'] = Nil then
              Sleep(ErrorSleepTime);
          end;
        end
        else
        begin
          Tasks := Nil;
          ErrorMessage := rsFatalError+' '+UTF8Encode(sores.S['msg']);
          Synchronize(@HandleTasks);
          Sleep(ErrorSleepTime);
        end;
      end;
    except
      on E:Exception do
      begin
        Tasks := Nil;

        ErrorMessage := rsFatalError+' '+E.Message;
        Synchronize(@HandleTasks);
        Sleep(ErrorSleepTime);
      end;
    end;
end;


procedure TVisWaptGUI.DoProgress(ASender: TObject);
begin
  if CurrentVisLoading <> nil then
    CurrentVisLoading.DoProgress(ASender)
  else
  begin
    {if ProgressBar1.Position >= ProgressBar1.Max then
      ProgressBar1.Position := 0
    else
      ProgressBar1.Position := ProgressBar1.Position + 1;
    Application.ProcessMessages;}
  end;
end;


procedure TVisWaptGUI.IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode;
  AWorkCount: int64);
begin
  if CurrentVisLoading <> nil then
    CurrentVisLoading.DoProgress(ASender);
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
  ActSearchHostExecute(Sender);
end;

procedure TVisWaptGUI.CheckBox_errorChange(Sender: TObject);
begin
  ActHostSearchPackage.Execute;
end;

procedure TVisWaptGUI.DBOrgUnitsFilterRecord(DataSet: TDataSet;
  var Accept: Boolean);
begin
  Accept := (EdSearchOrgUnits.Text='') or StrIsOneOf(DBOrgUnits['ID'],FilteredOrgUnits);
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
       if TriggerChangeHostDescription(UTF8Encode(GridHosts.FocusedRow.S['uuid']),EdDescription.Text) then
       begin
          if GridHosts.FocusedRow<>Nil then
            GridHosts.FocusedRow.S['description'] := UTF8Decode(EdDescription.Text);
          GridHosts.InvalidateFordata(GridHosts.FocusedRow);
       end
       else
          if GridHosts.FocusedRow<>Nil then
            EdDescription.Text := UTF8Encode(GridHosts.FocusedRow.S['description']);
    end;
end;

procedure TVisWaptGUI.EdHardwareFilterChange(Sender: TObject);
var
  data : ISuperObject;
begin
  if (Gridhosts.FocusedRow <> nil) then
  begin
    data := LoadHostInventory(Gridhosts.FocusedRow);
    TreeLoadData(GridhostInventory, FilterHardware(data));
    GridhostInventory.FullExpand;
  end;
end;

procedure TVisWaptGUI.EdRunKeyPress(Sender: TObject; var Key: char);
begin
  if Key = #13 then
    ActEvaluate.Execute;
end;

procedure TVisWaptGUI.EdSearchHostsForPackageKeyPress(Sender: TObject; var Key: char);
begin
  if key = #13 then
    GridHostsForPackage.Data := FilterHostsForPackage(HostsForPackageData)
  else
    if CharIsAlphaNum(Key) then
      GridHostsForPackage.Clear;
end;

procedure TVisWaptGUI.EdSearchOrgUnitsChange(Sender: TObject);
begin
  if EdSearchOrgUnits.Modified and DBOrgUnits.Active and not inSearchHosts then
  try
    inSearchHosts:=True;
    FilterDBOrgUnits;
    EdSearchOrgUnits.Modified := False;
    GridOrgUnits.ExpandAll;
    GridOrgUnits.ClearSelection;
  finally
    inSearchHosts:=False;
  end;
end;

procedure TVisWaptGUI.EdSearchOrgUnitsKeyPress(Sender: TObject; var Key: char);
begin
  if Key=#13 then
    SelectOrgUnits(EdSearchOrgUnits.Text);
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
  begin
    TimerSearchHosts.Enabled:=False;
    ActSearchHost.execute
  end
  else
    if CharIsAlphaNum(Key) or  (key = #8) then
    begin
      TimerSearchHosts.Enabled:=False;
      TimerSearchHosts.Enabled:=True;
    end;
end;

procedure TVisWaptGUI.EdSoftwaresFilterChange(Sender: TObject);
begin
  if (Gridhosts.FocusedRow <> nil) then
    GridHostSoftwares.Data := FilterSoftwares(Gridhosts.FocusedRow['installed_softwares']);
end;

procedure TVisWaptGUI.EdWUASearchPackageKeyPress(Sender: TObject; var Key: char
  );
begin
  If Key=#13 then
  begin
    EdWUASearchPackage.SelectAll;
    ActWUASearchPackage.Execute;
  end;
end;

procedure TVisWaptGUI.EdWUASearchWindowsUpdateKeyPress(Sender: TObject;
  var Key: char);
begin
  if key=#13 then
  begin
    EdWUASearchWindowsUpdate.SelectAll;
    ActWSUSRefresh.Execute;
  end;
end;


procedure TVisWaptGUI.FormClose(Sender: TObject; var CloseAction: TCloseAction);
var
  i: Integer;
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
  GridHostsForPackage.SaveSettingsToIni(Appuserinipath);

  // %APPDATA%\waptconsole\waptconsole.ini
  ini := TIniFile.Create(Appuserinipath);
  try
    for CB in VarArrayOf([cbAdvancedSearch,cbSearchAll,cbSearchDMI,cbSearchHost,cbSearchPackages,cbSearchSoftwares,cbReachable]) do
      ini.WriteBool(self.name,CB.Name,TCheckBox(CB).Checked);

    for i:=0 to cbFilterPackagesLocales.Items.Count-1 do
      ini.WriteBool(self.Name,cbFilterPackagesLocales.Items[i],cbFilterPackagesLocales.Checked[i]);

    for i:=0 to cbFilterPackagesArch.Items.Count-1 do
      ini.WriteBool(self.Name,cbFilterPackagesArch.Items[i],cbFilterPackagesArch.Checked[i]);

    ini.WriteInteger(self.name,'HostsLimit',HostsLimit);
    ini.WriteInteger(self.name,HostPages.Name+'.width',HostPages.Width);

    ini.WriteInteger(self.name,'WindowState',Integer(Self.WindowState));

    ini.WriteInteger(self.name,'Left',Self.Left);
    ini.WriteInteger(self.name,'Top',Self.Top);
    ini.WriteInteger(self.name,'Width',Self.Width);
    ini.WriteInteger(self.name,'Height',Self.Height);

    ini.WriteString(self.name,'cbGroups.Text',cbGroups.Text);

    {$ifdef ENTERPRISE}
    {$include ..\waptenterprise\includes\uwaptconsole.formclose.inc};
    {$endif}

    ini.WriteString(self.name,'waptconsole.version',GetApplicationVersion);
    ini.WriteString(self.name,'lastappinifilename',AppIniFilename);
    ini.WriteString(self.name,'lastwaptserveruser',WaptServerUser);

  finally
    ini.Free;
  end;

  {$ifdef ENTERPRISE}
  if IsEnterpriseEdition then
  begin
    GridWUUpdates.SaveSettingsToIni(Appuserinipath);
    GridHostWinUpdates.SaveSettingsToIni(Appuserinipath);
    GridReportingQueries.SaveSettingsToIni(Appuserinipath);
  end;
  {$endif}


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
        {$ifdef ENTERPRISE}
        stats.S['edition'] := 'enterprise';
        {$else}
        stats.S['edition'] := 'community';
        {$endif}
        IdHttpPostData(stats_report_url,UTF8Encode(stats.AsJSon),'POST',Proxy,4000,60000,60000,'','','Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko');
        ini.WriteDateTime('global','last_usage_report',Now);
      except
        ini.WriteDateTime('global','last_usage_report',Now);
      end;
    end;
  finally
    ini.Free;
  end;

end;

procedure TVisWaptGUI.FormCloseQuery(Sender: TObject; var CanClose: boolean);
begin
  CanClose := CheckUpdates([GridReportingQueries.Data]);
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

      accept := accept and (ExecRegExpr(reg, UTF8Encode(soft.S['name'])) or
        ExecRegExpr(reg, UTF8Encode(soft.S['key'])));
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
    if not Assigned(item) then
      Res := Nil
    else
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
          if ExecRegExpr('(?i)' +EdHardwareFilter.Text, Utf8Encode(k.AsString)) then
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

//Retrieve all inventory data from server
function TVisWaptGUI.InventoryData(uuid:String):ISuperObject;
var
  sores:ISuperObject;
begin
  result := Nil;
  try
    sores := WAPTServerJsonGet('api/v1/hosts?columns=dmi,wmi,host_info,host_metrics,waptwua_status,wuauserv_status,host_capabilities,wapt_status&uuid=%S',[uuid]);
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

//Cache inventory data into host row
function TVisWaptGUI.LoadHostInventory(host: ISuperObject): ISuperObject;
var
  key,inventory_keys: ISuperObject;
begin
  inventory_keys := host['_inventory_keys'];
  if (inventory_keys = Nil) then
  begin
    Result := InventoryData(UTF8Encode(host.S['uuid']));
    host.Merge(Result);
    host['_inventory_keys'] := Result.AsObject.GetNames;
  end
  else
  begin
    Result := TSuperObject.Create(stObject);
    for key in inventory_keys do
      Result[key.AsString] := host[key.AsString];
  end;
end;

type

{ TPackageReq }
 TPackageReq=record
  package:String;
  op:String;
  version:String;

  function FromSOPackage(sopackage:ISuperObject):TPackageReq;
  function FromString(req:String):TPackageReq;
  function AsString:String;
end;

{ TPackageReq }

function TPackageReq.FromSOPackage(sopackage: ISUperObject):TPackageReq;
begin
  self.package := UTF8Encode(sopackage.S['package']);
  self.version := UTF8Encode(sopackage.S['version']);
  self.op := '=';
  result := Self;
end;

function TPackageReq.FromString(req: String):TPackageReq;
var
  re: TRegExpr;
begin
  // optional version
  re := TRegExpr.Create('([^()]+)\s*(\(\s*([<=>]*)\s*(\S+)\s*\))?.*');
  try
    if re.Exec(req) then
    begin
      self.package := re.Match[1];
      self.op := re.Match[3];
      self.version := re.Match[4];
    end;
  finally
    re.Free;
  end;
  result := Self;
end;

function TPackageReq.AsString: String;
begin
  Result := Format('%s(%s%s)',[package,op,version]);
end;

procedure TVisWaptGUI.UpdateHostPages(Sender: TObject);
var
  currhost : String;
  RowSO, packages, softwares: ISuperObject;
  waptwua_status,wuauserv_status,wsusupdates: ISuperObject;
  sores: ISuperObject;
begin
  RowSO := Gridhosts.FocusedRow;

  if (RowSO <> nil) then
  begin
    currhost := UTF8Encode(RowSO.S['uuid']);

    if pgTasks.TabVisible and (RowSO.S['reachable'] <> 'OK') and (HostPages.ActivePage = pgTasks) then
      HostPages.ActivePage := pgPackages;
    pgTasks.TabVisible := RowSO.S['reachable'] = 'OK';

    if not ((RowSO.S['platform'] = 'Windows') or (RowSO.S['platform'] = '')) and pgHostWUA.TabVisible and (HostPages.ActivePage = pgHostWUA) then
        HostPages.ActivePage:= pgPackages;

    pgHostWUA.TabVisible:=EnableWaptWUAFeatures and ((RowSO.S['platform'] = 'Windows') or (RowSO.S['platform'] = ''));

    if HostPages.ActivePage = pgPackages then
    begin
      packages := RowSO['installed_packages'];
      if (packages = nil) or (packages.AsArray = nil) then
      try
        sores := WAPTServerJsonGet('api/v1/host_data?field=installed_packages&uuid=%S',[currhost]);
        if sores.B['success'] then
          RowSO['installed_packages'] := sores['result']
        else
          RowSO['installed_packages'] := nil;
      except
        RowSO['installed_packages'] := nil;
      end;

      EdUUID.Text := UTF8Encode(RowSO.S['uuid']);
      EdHostname.Text := UTF8Encode(RowSO.S['computer_name']);
      EdDescription.Text := UTF8Encode(RowSO.S['description']);
      EdOS.Text := UTF8Encode(RowSO.S['os_name']);
      if RowSO['connected_ips'].DataType=stArray then
        EdIPAddress.Text := soutils.join(',',RowSO['connected_ips'])
      else
        EdIPAddress.Text := Utf8Encode(RowSO.S['connected_ips']);
      EdManufacturer.Text := UTF8Encode(RowSO.S['manufacturer']);
      EdModelName.Text := UTF8Encode(RowSO.S['productname']);
      EdUpdateDate.Text :=  Copy(StrReplaceChar(UTF8Encode(RowSO.S['last_seen_on']),'T',' '),1,16);
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
      wsusupdates := RowSO['wsusupdates'];
      if (wsusupdates = nil) or (wsusupdates.AsArray = nil) then
      try
        sores := WAPTServerJsonGet('api/v1/host_data?field=wsusupdates&uuid=%S',[currhost]);
        if sores.B['success'] then
          wsusupdates := sores['result']
        else
          wsusupdates := nil;
      except
        wsusupdates := nil;
      end;

      RowSO['wsusupdates'] := wsusupdates;
      if wsusupdates<>Nil then
        GridHostWinUpdates.Data := FilterHostWinUpdates(wsusupdates)
      else
        GridHostWinUpdates.Data := Nil;

      // get wuauserv and waptwua status if they have not been already retrieved
      waptwua_status := RowSO['waptwua_status'];
      if (waptwua_status = nil) then
      try
        sores := WAPTServerJsonGet('api/v1/host_data?field=waptwua_status&uuid=%S',[currhost]);
        if sores.B['success'] then
          waptwua_status := sores['result']
        else
          waptwua_status := TSuperObject.Create(stObject);
      except
        waptwua_status := TSuperObject.Create(stObject);
      end;
      RowSO['waptwua_status'] := waptwua_status;

      wuauserv_status := RowSO['wuauserv_status'];
      if (wuauserv_status = nil) then
      try
        sores := WAPTServerJsonGet('api/v1/host_data?field=wuauserv_status&uuid=%S',[currhost]);
        if sores.B['success'] then
          wuauserv_status := sores['result']
        else
          wuauserv_status := TSuperObject.Create(stObject);
      except
        wuauserv_status := TSuperObject.Create(stObject);
      end;
      RowSO['wuauserv_status'] := wuauserv_status;

      EdWUAStatus.Text := UTF8Encode(waptwua_status.S['status']);
      EdWAPTWUAEnabled.Text := UTF8Encode(waptwua_status.S['enabled']);
      EdWsusscn2cabDate.Text:= UTF8Encode(waptwua_status.S['wsusscn2cab_date']);
      EdLastScanDate.Text:= UTF8Encode(waptwua_status.S['last_scan_date']);
      EdLastScanDuration.Text:= UTF8Encode(waptwua_status.S['last_scan_duration']);

      EdWUAAgentVersion.Text := UTF8Encode(wuauserv_status.S['agent_version']);

    end
    else if HostPages.ActivePage = pgHostInventory then
    begin
      GridhostInventory.Clear;
      if GridHosts.FocusedRow <> Nil then
        EdHardwareFilterChange(EdHardwareFilter)
    end
    else if HostPages.ActivePage = pgTasks then
    begin
      if (PollTasksThread<>Nil) and (PollTasksThread.HostUUID<>currhost) then
        PollTasksThread := Nil;

      if (PollTasksThread = Nil) then
      begin
        UpdateTasksReport(Nil);
        HostRunningTask.Text:=Format(rsLoadingHostTasks,[currhost]);
        Application.ProcessMessages;
        PollTasksThread := TPollTasksThread.Create(Self,CurrHost);
      end;
    end;
  end
  else
  begin
    HostRunningTask.Text := '';
    HostTaskRunningProgress.Position := 0;
    GridHostPackages.Clear;
    GridHostsForPackage.Clear;
    GridHostSoftwares.Clear;
    HostRunningTaskLog.Clear;
    GridHostTasksPending.Data := nil;
    GridHostTasksDone.Data := nil;
    GridHostTasksErrors.Data := nil;
  end;
end;


// Update the tasks page with informations retrieved from host .
procedure TVisWaptGUI.UpdateTasksReport(tasksresult:ISuperObject);
var
  running:ISuperObject;
begin
  if tasksresult <> nil then
  begin
    running := tasksresult['running'];
    if (tasksresult['pending']<>Nil) or (GridHostTasksPending.Data=Nil) then
      GridHostTasksPending.Data := tasksresult['pending'];
    if (tasksresult['done']<>Nil) or (GridHostTasksDone.Data=Nil) then
      GridHostTasksDone.Data := tasksresult['done'];
    if (tasksresult['errors']<>Nil) or (GridHostTasksErrors.Data=Nil) then
      GridHostTasksErrors.Data := tasksresult['errors'];
    if running <> nil then
    begin
      ActCancelRunningTask.Enabled:= running['description'] <> Nil;

      HostTaskRunningProgress.Position := running.I['progress'];
      HostRunningTask.Text := UTF8Encode(running.S['description']);
      HostRunningTaskLog.Text := UTF8Encode(running.S['logs']);
      Windows.SendMessage(HostRunningTaskLog.Handle, EM_LINESCROLL, 0, HostRunningTaskLog.Lines.Count)
    end
    else
    begin
      ActCancelRunningTask.Enabled:=False;
      HostTaskRunningProgress.Position := 0;
      HostRunningTask.Text := 'Idle';
      HostRunningTaskLog.Clear;
    end;
  end
  else
  begin
    HostRunningTask.Text := '';
    HostTaskRunningProgress.Position := 0;
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
  OneIsConnected:=OneHostIsConnected(GridHosts);
  OneHasConnectedIP:=OneHostHasConnectedIP(GridHosts);
  OneIsFocused:=(Gridhosts.FocusedRow <> nil);

  ActTriggerHostUpdate.Visible := not HideUnavailableActions or (OneIsFocused  and OneIsConnected);
  ActTriggerHostUpgrade.Visible := not HideUnavailableActions or (OneIsFocused  and OneIsConnected);
  ActPackagesInstall.Visible := not HideUnavailableActions or (OneIsFocused  and OneIsConnected);
  ActPackagesRemove.Visible := not HideUnavailableActions or (OneIsFocused  and OneIsConnected);
  ActPackagesForget.Visible := not HideUnavailableActions or (OneIsFocused  and OneIsConnected);
  ActRefreshHostInventory.Visible := not HideUnavailableActions or (OneIsFocused  and OneIsConnected);

  ActAddADSGroups.Visible := OneIsFocused  and EnableExternalTools;

  ActRDP.Visible := OneIsFocused  and OneHasConnectedIP and EnableExternalTools;
  ActVNC.Visible := OneIsFocused  and OneHasConnectedIP and FileExistsUTF8(GetVNCViewerPath) and EnableExternalTools;
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
    ActWSUSRefresh.Execute
  else
    ShowMessageFmt(rsErrorWithMessage,[res.S['error']]);
end;

procedure TVisWaptGUI.ActAddGroupExecute(Sender: TObject);
begin
  if Assigned(CreateGroup('agroup', AdvancedMode, 'group')) then
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
    begin
      //update groups filter combobox
      if cbGroups.ItemIndex>=0 then
        FillcbGroups;

      LoadOrgUnitsTree(Sender);
      ActSearchHost.Execute
    end
    else
    if MainPages.ActivePage = pgPrivateRepo then
      ActPackagesUpdate.Execute
    else
    if MainPages.ActivePage = pgGroups then
      ActPackagesUpdate.Execute
    else
    if MainPages.ActivePage = PgReports then
      ActReportingQueryExecute.Execute
    else
    if MainPages.ActivePage = pgRepositories then
       ActRepositoriesGetSecondRepos.Execute;



  finally
    Screen.Cursor := crDefault;
  end;
end;


function TVisWaptGUI.DownloadPackage(RepoUrl,Filename:String):Variant;
var
  filePath, proxy: string;
  vFilePath,vDevPath: Variant;
  cabundle: Variant;
  DevRoot,Devpath : String;
begin
  DevRoot:=IniReadString(AppIniFilename,'global','default_sources_root');
  try
    with TVisLoading.Create(Self) do
    try
      ProgressTitle(rsDownloading);
      Application.ProcessMessages;
      try
        filePath := AppLocalDir + 'cache\' + filename;
        if not DirectoryExists(AppLocalDir + 'cache') then
          mkdir(AppLocalDir + 'cache');

        Proxy := DMPython.MainWaptRepo.http_proxy;
        cabundle:= VarPyth.None;
        // if check package signature...
        //cabundle:=DMPython.PackagesAuthorizedCA;
        if not IdWget(UTF8Encode(RepoUrl+'/'+filename), filePath,
            ProgressForm, @updateprogress, Proxy,
              DefaultUserAgent,GetWaptServerCertificateFilename(),Nil,
              WaptClientCertFilename,WaptClientKeyFilename) then
            Raise Exception.CreateFmt('Unable to download %s',[UTF8Encode(RepoUrl+'/'+filename)]);

        vFilePath := PyUTF8Decode(filePath);
        Result := DMPython.waptpackage.PackageEntry(waptfile := vFilePath);
        if devroot <> '' then
          DevPath := AppendPathDelim(DevRoot)+VarPythonAsString(Result.make_package_edit_directory('--noarg--'))
        else
          DevPath := GetTempFileNameUTF8('',VarPythonAsString(Result.package));
        vDevPath:= PyUTF8Decode(DevPath);
        Result.unzip_package(cabundle := cabundle, target_dir := vDevPath);
        //DMPython.WAPT.add_pyscripter_project(vDevPath);
        //DMPython.common.wapt_sources_edit( wapt_sources_dir := vDevPath);
      except
        ShowMessage(rsDlCanceled);
        if FileExistsUTF8(filePath) then
          DeleteFileUTF8(filePath);
        raise;
      end;
    finally
      Free;
    end;
  except
    on E:Exception do
    begin
      ShowMessageFmt(rsErrorWithMessage,[e.Message]);
      exit;
    end;
  end;
end;

procedure TVisWaptGUI.ActEditPackageExecute(Sender: TObject);
var
  RepoUrl,Filename: string;
  cabundle,vDevPath,PackageEdited: Variant;
  Devpath : String;
begin
  if DefaultSourcesRoot='' then
  begin
    ShowMessage(rsDefineWaptdevPath);
    ActWAPTConsoleConfig.Execute;
    if (DefaultSourcesRoot='') then
      Exit;
  end;

  if GridPackages.FocusedNode <> nil then
  begin
    Filename := UTF8Encode(GridPackages.FocusedRow.S['filename']);
    RepoUrl := UTF8Encode(GridPackages.FocusedRow.S['repo_url']);
    PackageEdited := DownloadPackage(RepoUrl,Filename);
    DevPath := AppendPathDelim(DefaultSourcesRoot)+VarPythonAsString(PackageEdited.make_package_edit_directory('--noarg--'));
    vDevPath:= PyUTF8Decode(DevPath);
    cabundle := None();
    PackageEdited.unzip_package(cabundle := cabundle, target_dir := vDevPath);
    DMPython.WAPT.add_pyscripter_project(vDevPath);
    DMPython.common.wapt_sources_edit( wapt_sources_dir := vDevPath);
  end;
end;


function TVisWaptGUI.EditPackageEntry(Entry: ISuperObject): Variant;
var
  RepoUrl,Filename: string;
  cabundle,vDevPath,PackageEdited: Variant;
  Devpath : String;
begin
  if Entry <> nil then
  begin
    case Entry.S['section'] of
      'host': ;
      'group','profile': ;
      {$ifdef enterprise}
      'wsus':;
      {$endif}
      else
      begin
        Filename := UTF8Encode(Entry.S['filename']);
        RepoUrl := UTF8Encode(Entry.S['repo_url']);
        PackageEdited := DownloadPackage(RepoUrl,Filename);
        DevPath := AppendPathDelim(DefaultSourcesRoot)+VarPythonAsString(PackageEdited.make_package_edit_directory('--noarg--'));
        vDevPath:= PyUTF8Decode(DevPath);
        cabundle := None();
        PackageEdited.unzip_package(cabundle := cabundle, target_dir := vDevPath);
        DMPython.WAPT.add_pyscripter_project(vDevPath);
        DMPython.common.wapt_sources_edit( wapt_sources_dir := vDevPath);
        Result := PackageEdited;
      end;
    end;
  end;
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
        if WaptPersonalCertificatePath = '' then
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
      if not IsWindowsAdminLoggedIn then
        ShowMessageFmt(rsNotRunningAsAdminCanNotSSL,[AppendPathDelim(WaptBaseDir)+'ssl']);

      if CBIsCA.Checked and (MessageDlg(Format(rsWriteCertOnLocalMachine,[AppendPathDelim(WaptBaseDir)+'ssl']), mtConfirmation, [mbYes, mbNo],0) = mrYes) then
      begin
        if CopyFile(CertificateFilename,
          WaptBaseDir() + '\ssl\' + ExtractFileName(CertificateFilename), True) then
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
  WAPTSetupPath,
  TmpBuildDir: string;
begin
  if not IsWindowsAdminLoggedIn then
    ShowMessage(rsNotRunningAsAdmin);

  if (waptcommon.DefaultPackagePrefix = '') then
  begin
    ShowMessage(rsWaptPackagePrefixMissing);
    ActWAPTConsoleConfig.Execute;
    exit;
  end;

  if not FileExistsUTF8(WaptPersonalCertificatePath) then
  begin
    ShowMessageFmt(rsPrivateKeyDoesntExist, [WaptPersonalCertificatePath]);
    ActWAPTConsoleConfig.Execute;
    exit;
  end;

  with TVisCreateWaptSetup.Create(self) do
  try
    if ShowModal = mrOk then
    try
      TmpBuildDir := GetTempFileNameUTF8('','wapt'+FormatDateTime('yyyymmdd"T"hhnnss',Now));
      try
        CurrentVisLoading.Start;
        CurrentVisLoading.ExceptionOnStop := True;

        WAPTSetupPath := BuildWaptSetup(TmpBuildDir);
        BuildWaptUpgrade(AppendPathDelim(TmpBuildDir)+'waptupgrade');
        UploadWaptSetup(WAPTSetupPath);
        ActPackagesUpdate.Execute;
      except
        on E:Exception do
          ShowMessageFmt(rsWaptAgentSetupError,[E.Message]);
      end;
    finally
      if DirectoryExistsUTF8(TmpBuildDir) then
        DeleteDirectory(TmpBuildDir,False);
      CurrentVisLoading.Finish;
    end;
  finally
    Free;
  end;
end;

procedure TVisWaptGUI.ActCreateWaptSetupUpdate(Sender: TObject);
begin
  ActCreateWaptSetup.Enabled:= dmpython.PersonalCertificateIsCodeSigning and EnableManagementFeatures;
      //    CertificateIsCodeSigning(WaptPersonalCertificatePath)
end;

procedure TVisWaptGUI.ActAddConflictsExecute(Sender: TObject);
var
  Res, packages, hosts: ISuperObject;
  VHosts,VPackages,VWaptIniFilename,VPrivateKeyPassword,ResVar: Variant;
begin
  if GridHosts.Focused then
  begin
    with TvisGroupChoice.Create(self) do
    try
      Caption := rsSelectAddConflicts;
      res := Nil;

      if ShowModal = mrOk then
      try
        Screen.Cursor := crHourGlass;
        packages := SelectedPackages;
        Hosts := ExtractField(GridHosts.SelectedRows,'uuid');

        VHosts := SuperObjectToPyVar(Hosts);
        VPackages := SuperObjectToPyVar(packages);
        VWaptIniFilename := PyUTF8Decode(AppIniFilename);
        VPrivateKeyPassword := PyUTF8Decode(dmpython.privateKeyPassword);

        resVar := DMPython.waptdevutils.edit_hosts_depends(
           waptconfigfile := VWaptIniFilename,
           hosts_list := VHosts,
           append_conflicts := VPackages,
           sign_certs := DMPython.WAPT.personal_certificate('--noarg--'),
           sign_key := DMPython.WAPT.private_key(private_key_password := VPrivateKeyPassword),
           wapt_server_user := waptServerUser,
           wapt_server_passwd := waptServerPassword,
           cabundle := DMPython.WaptHostRepo.cabundle
           );

        res := PyVarToSuperObject(ResVar);
      finally
        Screen.cursor := crDefault;
        if res <> Nil then
          ShowMessageFmt(rsNbModifiedHosts, [res.A['updated'].Length,res.A['discarded'].Length,res.A['unchanged'].Length]);
      end;
    finally
      Free;
    end;
  end;
end;


procedure TVisWaptGUI.ActAddADSGroupsExecute(Sender: TObject);
var
  Res, hosts, host,HostMin: ISuperObject;
  VHosts,VWaptIniFilename,VPrivateKeyPassword,ResVar: Variant;
begin
  if GridHosts.Focused and (MessageDlg(rsAddADSGroups, mtConfirmation, [mbYes, mbNo, mbCancel],0) = mrYes) then
  try
    Screen.Cursor := crHourGlass;
    Hosts := TSuperObject.Create(stArray);
    for host in GridHosts.SelectedRows do
    begin
      HostMin := TSuperObject.Create(stObject);
      HostMin['uuid'] := host['uuid'];
      HostMin['computer_fqdn'] := host['computer_fqdn'];
      HostMin['computer_name'] := host['computer_name'];
      HostMin['depends'] := host['depends'];
      HostMin['conflicts'] := host['conflicts'];
      Hosts.AsArray.Add(HostMin);
    end;

    VHosts := SuperObjectToPyVar(Hosts);
    VWaptIniFilename := PyUTF8Decode(AppIniFilename);
    VPrivateKeyPassword := PyUTF8Decode(dmpython.privateKeyPassword);

    resVar := DMPython.waptdevutils.add_ads_groups(
       waptconfigfile := VWaptIniFilename,
       hostdicts_list := VHosts,
       sign_certs := DMPython.WAPT.personal_certificate('--noarg--'),
       sign_key := DMPython.WAPT.private_key(private_key_password := VPrivateKeyPassword),
       wapt_server_user := waptServerUser,
       wapt_server_passwd := waptServerPassword,
       cabundle := DMPython.WaptHostRepo.cabundle
       );

    res := PyVarToSuperObject(ResVar);
  finally
    Screen.cursor := crDefault;
    if res <> Nil then
      ShowMessageFmt(rsNbModifiedHosts, [res.A['updated'].Length,res.A['discarded'].Length,res.A['unchanged'].Length]);
  end;
end;

procedure TVisWaptGUI.ActAddDependsExecute(Sender: TObject);
var
  Res, packages, hosts: ISuperObject;
  VHosts,VPackages,VWaptIniFilename,VPrivateKeyPassword,ResVar: Variant;
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

        VHosts := SuperObjectToPyVar(Hosts);
        VPackages := SuperObjectToPyVar(packages);
        VWaptIniFilename := PyUTF8Decode(AppIniFilename);
        VPrivateKeyPassword := PyUTF8Decode(dmpython.privateKeyPassword);

        resVar := DMPython.waptdevutils.edit_hosts_depends(
           waptconfigfile := VWaptIniFilename,
           hosts_list := VHosts,
           append_depends := VPackages,
           sign_certs := DMPython.WAPT.personal_certificate('--noarg--'),
           sign_key := DMPython.WAPT.private_key(private_key_password := VPrivateKeyPassword),
           wapt_server_user := waptServerUser,
           wapt_server_passwd := waptServerPassword,
           cabundle := DMPython.WaptHostRepo.cabundle
           );

        res := PyVarToSuperObject(ResVar);
      finally
        Screen.cursor := crDefault;
        if res <> Nil then
          ShowMessageFmt(rsNbModifiedHosts, [res.A['updated'].Length,res.A['discarded'].Length,res.A['unchanged'].Length]);
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

procedure TVisWaptGUI.ActAddProfileExecute(Sender: TObject);
begin
  if Assigned(CreateGroup('agroup', AdvancedMode, 'profile')) then
    ActPackagesUpdate.Execute;
end;

procedure TVisWaptGUI.ActSupprExecute(Sender: TObject);
begin
  if MainPages.ActivePage= pgPrivateRepo then
    ActDeletePackage.Execute();
  if MainPages.ActivePage= pgRepositories then
    ActDeleteRule.Execute();
end;

procedure TVisWaptGUI.ActCancelRunningTaskExecute(Sender: TObject);
var
  uuids: ISuperObject;
  currhost: String;
begin
  if GridHosts.FocusedRow<>Nil then
  begin
    uuids := TSuperObject.Create(stArray);
    currhost := UTF8Encode(GridHosts.FocusedRow.S['uuid']);
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
  ActChangePrivateKeypassword.Enabled := FileExistsUTF8(WaptPersonalCertificatePath);
end;

procedure TVisWaptGUI.ActCleanCacheExecute(Sender: TObject);
var
  waptpackages:TStringList;
  fn:String;
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
  ip: String;
  Args: WideString;
begin
  if (Gridhosts.FocusedRow <> nil) and
    (Gridhosts.FocusedRow.S['connected_ips'] <> '') then
  begin
    ip := GetReachableIP(Gridhosts.FocusedRow['connected_ips'],135);
    if ip <> '' then
    begin
      Args := ' -a /computer=' + ip;
      ShellExecuteW(0, '', PWideChar('compmgmt.msc'), PWideChar(Args), nil, SW_SHOW)
    end
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
  ip: String;
  Args: WideString;
begin
  if (Gridhosts.FocusedRow <> nil) and
    (Gridhosts.FocusedRow.S['connected_ips'] <> '') then
  begin
    ip := GetReachableIP(Gridhosts.FocusedRow['connected_ips'],135);
    if ip <> '' then
    begin
      Args := ' -a /computer=' + ip;
      ShellExecuteW(0, '', PWideChar('services.msc'), PWideChar(Args), nil, SW_SHOW);
    end
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
  ip: String;
  Args: WideString;
begin
  if (Gridhosts.FocusedRow <> nil) and
    (Gridhosts.FocusedRow.S['connected_ips'] <> '') then
  begin
    ip := GetReachableIP(Gridhosts.FocusedRow['connected_ips'],135);
    if ip <> '' then
    begin
      Args := ' -a /computer=' + ip;
      ShellExecuteW(0, '', PWideChar('Lusrmgr.msc'), PWideChar(Args), nil, SW_SHOW)
    end
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
  packages,res: ISuperObject;
begin
  if GridGroups.SelectedCount > 1 then
    message := format(rsConfirmRmMultiplePackages,[GridGroups.SelectedCount]);

  if MessageDlg(rsConfirmRmPackageCaption, message, mtConfirmation,
    mbYesNoCancel, 0) = mrYes then

    with TVisLoading.Create(Self) do
      try
        ProgressTitle(rsDeletionInProgress);
        packages := soutils.ExtractField(GridGroups.SelectedRows,'filename');
        ProgressTitle(format(rsDeletingElement, [Join(',',packages) ]));
        res := WAPTServerJsonPost('/api/v3/packages_delete',[],packages);
        if not res.B['success'] then
           ShowMessageFmt('Error deleting packages: %S',[UTF8Encode(res.S['msg'])]);
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

      {$ifdef enterprise}
      cbEnableWAPTWUAFeatures.Checked :=
        inifile.ReadBool('global', 'waptwua_enabled', EnableWaptWUAFeatures);
      {$else}
      cbEnableWAPTWUAFeatures.Visible :=False;
      {$endif}

      cbDebugWindow.Checked:= inifile.ReadBool('global','advanced_mode',AdvancedMode);

      lang := inifile.ReadString('global','language',DMPython.Language);
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

        {$ifdef enterprise}
        inifile.WriteBool('global', 'waptwua_enabled',
          cbEnableWAPTWUAFeatures.Checked);
        {$endif}

        if cbLanguage.ItemIndex=0 then
          DMPython.Language := 'en'
        else if cbLanguage.ItemIndex=1 then
          DMPython.Language := 'fr'
        else if cbLanguage.ItemIndex=2 then
          DMPython.Language := 'de'
        else
          DMPython.Language := '';

        Language := DMPython.Language;

        inifile.WriteString('global','language',DMPython.Language);

        inifile.WriteBool('global', 'advanced_mode',cbDebugWindow.Checked);

        AdvancedMode := cbDebugWindow.Checked;
        pgSources.TabVisible := AdvancedMode;
        PanDebug.Visible := AdvancedMode;
        SplitBottomDebug.Visible:= AdvancedMode;
        if AdvancedMode then
            cbAdvancedMode.State:=cbChecked
        else
            cbAdvancedMode.State:=cbUnchecked;

        Gridhosts.ShowAdvancedColumnsCustomize:= AdvancedMode;
        GridGroups.ShowAdvancedColumnsCustomize:=AdvancedMode;
        GridPackages.ShowAdvancedColumnsCustomize:=AdvancedMode;
        GridHostPackages.ShowAdvancedColumnsCustomize:=AdvancedMode;


        EnableExternalTools := cbEnableExternalTools.Checked;
        EnableManagementFeatures := cbEnableManagementFeatures.Checked;
        HideUnavailableActions := cbHideUnavailableActions.Checked;
        EnableWaptWUAFeatures := cbEnableWAPTWUAFeatures.Checked;
        SetIsEnterpriseEdition(GetIsEnterpriseEdition);

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

procedure TVisWaptGUI.cbAdvancedModeClick(Sender: TObject);
begin
    ActDisplayDebug.Execute;
end;

procedure TVisWaptGUI.ActDisplayUserMessageExecute(Sender: TObject);
var
  AMessage: String;
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

procedure TVisWaptGUI.ActmakePackageTemplateExecute(Sender: TObject);
begin
  MakePackageTemplate('');
end;

procedure TVisWaptGUI.ActPackagesForceInstallExecute(Sender: TObject);
begin
  if GridHostPackages.Focused then
    TriggerActionOnHostPackages(GridHostPackages,ExtractField(GridHosts.SelectedRows,'uuid'),
        'trigger_install_packages',rsConfirmPackageInstall,rsPackageInstallError,True)
  else if GridHostsForPackage.Focused then
    TriggerActionOnHostPackages(GridHostsForPackage,ExtractField(GridHostsForPackage.SelectedRows,'host'),
        'trigger_install_packages',rsConfirmPackageInstall,rsPackageInstallError,True)
  else
    Exit;
end;

procedure TVisWaptGUI.ActPackagesRemoveUpdate(Sender: TObject);
begin
  if GridHostPackages.Focused then
    (Sender as TAction).Enabled:=OneHostIsConnected(GridHosts) and FileExistsUTF8(WaptPersonalCertificatePath)
  else if GridHostsForPackage.Focused then
    (Sender as TAction).Enabled:=OneHostIsConnected(GridHostsForPackage) and FileExistsUTF8(WaptPersonalCertificatePath)
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

procedure TVisWaptGUI.ActResetWebsocketConnectionsExecute(Sender: TObject);
var
  data: ISuperObject;
begin
  data := SO();
  data['uuids'] := GetSelectedUUID;
  HandleServerResult(WAPTServerJsonPost('api/v3/reset_hosts_sid',[],data));
end;

function TVisWaptGUI.OneHostHasConnectedIP(GridHostsIPs:TSOGrid=Nil):Boolean;
var
  host : ISuperObject;
begin
  Result:=False;
  if GridHostsIPs = Nil then
    GridHostsIPs := GridHosts;
  for host in GridHostsIPs.SelectedRows do
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
  ActTISHelp.Enabled:=FileExistsUTF8(GetTisSupportPath) and OneHostHasConnectedIP;
end;

procedure TVisWaptGUI.ActTriggerBurstUpdatesExecute(Sender: TObject);
begin
  if (GridHosts.SelectedCount>=1) and
    (MessageDlg(Format(rsConfirmBurstUpdate,[GridHosts.SelectedCount]),mtConfirmation,mbYesNoCancel, 0) = mrYes) then
      TriggerActionOnHosts(ExtractField(GridHosts.SelectedRows,'uuid'),'trigger_host_update',Nil,rsTriggerHostsUpdate,'Error checking for updates %s',True)
end;

procedure TVisWaptGUI.ActTriggerBurstUpgradesExecute(Sender: TObject);
begin
  if (GridHosts.SelectedCount>=1) and
    (MessageDlg(Format(rsConfirmBurstUpgrades,[GridHosts.SelectedCount]),mtConfirmation,mbYesNoCancel, 0) = mrYes) then
      TriggerActionOnHosts(ExtractField(GridHosts.SelectedRows,'uuid'),'trigger_host_upgrade',Nil,rsUpgradingHost,'Error applying upgrades %s',True)

end;

procedure TVisWaptGUI.ActTriggerUpgradesOrgUnitUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled := GridHosts.Data.AsArray.Length>0 ;
end;

procedure TVisWaptGUI.ActTriggerWakeOnLanExecute(Sender: TObject);
var
  data: ISuperObject;
begin
  data := SO();
  data['uuids'] := GetSelectedUUID;
  HandleServerResult(WAPTServerJsonPost('api/v3/trigger_wakeonlan',[],data));
end;

procedure TVisWaptGUI.ActTriggerWaptServiceRestartExecute(Sender: TObject);
begin
  if (GridHosts.SelectedCount>=1) and
    (MessageDlg(Format(rsConfirmWaptServiceRestart,[GridHosts.SelectedCount]),mtConfirmation,mbYesNoCancel, 0) = mrYes) then
      TriggerActionOnHosts(ExtractField(GridHosts.SelectedRows,'uuid'),'trigger_waptservicerestart',Nil,rsRestartingWaptservice,'Error restarting waptservice %s',True)
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

function TVisWaptGUI.EditHostPackageEntry(host: ISuperObject): Variant;
var
  hostname,uuid,HostPackageVersion: String;
  uuids: ISuperObject;
  ApplyUpdatesImmediately:Boolean;
  Package,HostPackages:ISuperObject;
begin
  if Host<>Nil then
  try
    // Be sure edited package's version is at least installed one.
    // Better use a dedicated API on server ?
    HostPackageVersion :='';
    HostPackages := host['installed_packages'];
    if HostPackages <> Nil then
    begin
      for Package in HostPackages do
      begin
        if UTF8Encode(Package.S['package']) = uuid then
        begin
          HostPackageVersion := UTF8Encode(Package.S['version']);
          break;
        end;
      end;
    end;

    if not host.AsObject.Exists('host_capabilities') then
      LoadHostInventory(host);

    result := EditHost(host, AdvancedMode, ApplyUpdatesImmediately, HostPackageVersion);

    if not VarIsNone(result) and ApplyUpdatesImmediately and (host.S['uuid']<>'')  then
    begin
      uuids := SA([host['uuid']]);
      TriggerActionOnHosts(uuids,'trigger_host_upgrade',Nil,rsUpgradingHost,rsErrorLaunchingUpgrade);
    end;

  except
    on E:Exception do
      ShowMessageFmt(rsEditHostError+#13#10#13#10+e.Message,[hostname]);
  end;
end;

procedure TVisWaptGUI.ActEditHostPackageExecute(Sender: TObject);
begin
  EditHostPackageEntry(GridHosts.FocusedRow);
end;

procedure TVisWaptGUI.ActEnglishExecute(Sender: TObject);
begin
  DMPython.Language:='en';
end;

procedure TVisWaptGUI.HandleServerResult(ServerResult:ISuperObject);
begin
  if (ServerResult<>Nil) and ServerResult.AsObject.Exists('success') then
  begin
    MemoLog.Append(UTF8Encode(ServerResult.AsString));
    if ServerResult.AsObject.Exists('msg') then
      ShowMessage(UTF8Encode(ServerResult.S['msg']));
  end
  else
    if not ServerResult.B['success'] or (ServerResult['result'].A['errors'].Length>0) then
      Raise Exception.Create(UTF8Encode(ServerResult.S['msg']));
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
  VPrivateKeyPassword: Variant;
  Message: String;
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
      actions_json := UTF8Encode(SOActions.AsString);

      VPrivateKeyPassword := PyUTF8Decode(dmpython.privateKeyPassword);

      signed_actions_json := VarPythonAsString(DMPython.waptdevutils.sign_actions(
          actions:=actions_json,
          sign_certs := DMPython.WAPT.personal_certificate('--noarg--'),
          sign_key := DMPython.WAPT.private_key(private_key_password := VPrivateKeyPassword)));
      SOActions := SO(signed_actions_json);

      result := WAPTServerJsonPost('/api/v3/trigger_host_action?timeout=%D',[waptservice_timeout],SOActions);
      if (result<>Nil) then
      begin
        if result.AsObject.Exists('success') then
        begin
          MemoLog.Append(UTF8Encode(result.AsString));
          if result.AsObject.Exists('msg') and (title<>'') then
          begin
            Message:=copy(UTF8Encode(result.S['msg']),1,250);
            if 'actions launched'<>rsActionsLaunched then
               Message:=Message.Replace('actions launched',rsActionsLaunched).Replace('server errors',rsActionsServerErrors).Replace('errors',rsActionsErrors).Replace('skipped',rsActionsSkipped);
            ShowMessage(Message);
          end;
        end
        else
          if not result.B['success'] or (result['result'].A['errors'].Length>0) then
            Raise Exception.Create(UTF8Encode(result.S['msg']));
      end
      else
        Raise Exception.Create('Unknown error. Trigger action returned no result.');
    except
      on E:Exception do
        ShowMessage(Format(errortitle,
            [ e.Message]));
    end;

  finally
    Screen.Cursor:=crDefault;
  end;
end;

function StringArray2SO(A:TDynStringArray):ISuperObject;
var
  s:String;
begin
  Result := TSuperObject.Create(stArray);
  for s in A do
    Result.AsArray.Add(s);
end;


procedure TVisWaptGUI.TriggerActionOnHostPackages(APackagesStatusGrid:TSOGrid;HostUUIDs:ISuperObject;AAction,title,errortitle:String;Force:Boolean=False);
var
  sel, packages : ISuperObject;
  SOAction, SOActions,res,HostUUID:ISuperObject;
  actions_json,
  signed_actions_json:String;
  VPrivateKeyPassword:Variant;
begin
  if APackagesStatusGrid.Focused and (HostUUIDs.AsArray <> Nil) then
  begin
    sel := APackagesStatusGrid.SelectedRows;
    if Dialogs.MessageDlg(
       rsConfirmCaption,
       format(title, [IntToStr(sel.AsArray.Length), Join(',',HostUUIDs)]),
       mtConfirmation,
       mbYesNoCancel,
       0) = mrYes then
    begin
      packages := ExtractField(sel,'package');
      try
        SOActions := TSuperObject.Create(stArray);
        for HostUUID in HostUUIDs do
        begin
          SOAction := SO();
          SOAction.S['action'] := AAction;
          SOAction['uuid'] := HostUUID;
          SOAction.B['notify_server'] := True;
          SOAction.B['force'] := Force;
          SOAction['packages'] := packages;
          SOActions.AsArray.Add(SOAction);
        end;

        //transfer actions as json string to python
        actions_json := UTF8Encode(SOActions.AsString);

        VPrivateKeyPassword := PyUTF8Decode(dmpython.privateKeyPassword);

        signed_actions_json := VarPythonAsString(DMPython.waptdevutils.sign_actions(
            actions:=actions_json,
            sign_certs := DMPython.WAPT.personal_certificate('--noarg--'),
            sign_key := DMPython.WAPT.private_key(private_key_password := VPrivateKeyPassword)));
        SOActions := SO(signed_actions_json);

        res := WAPTServerJsonPost('/api/v3/trigger_host_action?timeout=%D',[waptservice_timeout],SOActions);
        if (res<>Nil) and res.AsObject.Exists('success') then
        begin
          MemoLog.Append(UTF8Encode(res.AsString));
          if res.AsObject.Exists('msg') then
            ShowMessage(UTF8Encode(res.S['msg']));
        end
        else
          if not res.B['success'] or (res['result'].A['errors'].Length>0) then
            Raise Exception.Create(UTF8Encode(res.S['msg']));
      except
        on E:Exception do
          ShowMessage(Format(errortitle,
              [ Join(',',packages),e.Message]));
      end;
    end;
    //UpdateHostPages(Nil);
  end;
end;

procedure TVisWaptGUI.ActPackagesForgetExecute(Sender: TObject);
begin
  if GridHostPackages.Focused then
    TriggerActionOnHostPackages(GridHostPackages,ExtractField(GridHosts.SelectedRows,'uuid'),
        'trigger_forget_packages',rsConfirmHostForgetsPackages,rsForgetPackageError,True)
  else if GridHostsForPackage.Focused then
    TriggerActionOnHostPackages(GridHostsForPackage,ExtractField(GridHostsForPackage.SelectedRows,'host'),
        'trigger_forget_packages',rsConfirmHostForgetsPackages,rsForgetPackageError,True)
  else
    Exit;
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
  OpenDocument('https://doc.wapt.fr');
end;


function TVisWaptGUI.OneHostIsConnected(GridHostsReachable:TSOGrid=Nil):Boolean;
var
  host : ISuperObject;
begin
  if GridHostsReachable = Nil then
    GridHostsReachable := GridHosts;
  Result:=False;
  for host in GridHostsReachable.SelectedRows do
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
  (Sender as TAction).Enabled:= (GridHosts.SelectedCount>0) and OneHostIsConnected(GridHosts) and FileExistsUTF8(WaptPersonalCertificatePath);
end;


procedure TVisWaptGUI.ImportPackageFromFiles(Filenames:TStrings);
var
  i: integer;
  sourceDir: string;
  Sources, uploadResult: ISuperObject;
  SourcesVar: Variant;

begin
  if MessageDlg(rsConfirmImportCaption,
    format(rsConfirmImport,
    [Filenames.Text]), mtConfirmation, mbYesNoCancel, 0) <> mrYes then
    Exit;
  with TVisLoading.Create(Self) do
  try
    Sources := TSuperObject.Create(stArray);
    for i := 0 to Filenames.Count - 1 do
    begin
      ProgressTitle(format(rsImportingFile, [Filenames[i]]));
      ProgressStep(i, Filenames.Count - 1);
      Application.ProcessMessages;
      sourceDir := VarPythonAsString(DMPython.waptdevutils.duplicate_from_file(
        package_filename := Filenames[i],new_prefix:=DefaultPackagePrefix));
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

procedure TVisWaptGUI.ActImportFromFileExecute(Sender: TObject);
begin
  if not FileExistsUTF8(WaptPersonalCertificatePath) then
  begin
    ShowMessageFmt(rsPrivateKeyDoesntExist, [WaptPersonalCertificatePath]);
    exit;
  end;

  if DefaultPackagePrefix='' then
  begin
    ShowMessage(rsWaptPackagePrefixMissing);
    ActWAPTConsoleConfig.Execute;
    Exit;
  end;

  if OpenDialogWapt.Execute then
    ImportPackageFromFiles(OpenDialogWapt.Files);
end;

procedure TVisWaptGUI.ActImportFromRepoExecute(Sender: TObject);
var
  i: Integer;
begin
  with TVisImportPackage.Create(Self) do
  try
    for i := 0 to self.cbFilterPackagesArch.Items.Count-1 do
      cbFilterPackagesArch.Checked[i] := self.cbFilterPackagesArch.Checked[i];
    for i := 0 to self.cbFilterPackagesLocales.Items.Count-1 do
      cbFilterPackagesLocales.Checked[i] := self.cbFilterPackagesLocales.Checked[i];
    if ShowModal = mrOk then
    begin
      ActPackagesUpdate.Execute;
    end;
  finally
    Free;
  end;
end;

procedure TVisWaptGUI.ActWUALoadUpdatesExecute(Sender: TObject);
{$ifdef wsus2}
var
  soresult,winupdates,winupdate,urlParams,product,products,idx,severities: ISuperObject;
  update_id:String;
{$endif wsus2}
begin
  {$ifdef wsus2}
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

    GridWUUpdates.Data := winupdates;

  finally
    Screen.Cursor:=crDefault;
  end;
  {$endif wsus2}
end;

procedure TVisWaptGUI.ActWUALoadUpdatesUpdate(Sender: TObject);
begin
  {$ifdef wsus2}
  ActWUALoadUpdates.Enabled:=GridWinproducts.SelectedCount>0;
  {$endif wsus2}
end;

procedure TVisWaptGUI.ActPackagesInstallExecute(Sender: TObject);
begin
  if GridHostPackages.Focused then
    TriggerActionOnHostPackages(GridHostPackages,ExtractField(GridHosts.SelectedRows,'uuid'),
        'trigger_install_packages',rsConfirmPackageInstall,rsPackageInstallError,False)
  else if GridHostsForPackage.Focused then
    TriggerActionOnHostPackages(GridHostsForPackage,ExtractField(GridHostsForPackage.SelectedRows,'host'),
        'trigger_install_packages',rsConfirmPackageInstall,rsPackageInstallError,False)
end;

procedure TVisWaptGUI.ActPackagesRemoveExecute(Sender: TObject);
begin
  if GridHostPackages.Focused then
    TriggerActionOnHostPackages(GridHostPackages,ExtractField(GridHosts.SelectedRows,'uuid'),
        'trigger_remove_packages',rsConfirmRmPackagesFromHost,rsPackageRemoveError)
  else if GridHostsForPackage.Focused then
    TriggerActionOnHostPackages(GridHostsForPackage,ExtractField(GridHostsForPackage.SelectedRows,'host'),
        'trigger_remove_packages',rsConfirmRmPackagesFromHost,rsPackageRemoveError)
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
  with TVisTriggerHostsAction.Create(Self) do
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
  VHosts,VPackages,VWaptIniFilename,VPrivateKeyPassword,ResVar: Variant;
begin
  if GridHosts.Focused then
  begin
    with TvisGroupChoice.Create(self) do
    try
      Caption := rsSelectRemoveConflicts;
      res := Nil;

      if ShowModal = mrOk then
      try
        Screen.Cursor := crHourGlass;
        packages := SelectedPackages;
        Hosts := ExtractField(GridHosts.SelectedRows,'uuid');

        VHosts := SuperObjectToPyVar(Hosts);
        VPackages := SuperObjectToPyVar(packages);
        VWaptIniFilename := PyUTF8Decode(AppIniFilename);
        VPrivateKeyPassword := PyUTF8Decode(dmpython.privateKeyPassword);

        resVar := DMPython.waptdevutils.edit_hosts_depends(
           waptconfigfile := VWaptIniFilename,
           hosts_list := VHosts,
           remove_conflicts := VPackages,
           sign_certs := DMPython.WAPT.personal_certificate('--noarg--'),
           sign_key := DMPython.WAPT.private_key(private_key_password := VPrivateKeyPassword),
           wapt_server_user := waptServerUser,
           wapt_server_passwd := waptServerPassword,
           cabundle := DMPython.WaptHostRepo.cabundle
           );

        res := PyVarToSuperObject(ResVar);
      finally
        Screen.cursor := crDefault;
        if res <> Nil then
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
  VHosts,VPackages,VWaptIniFilename,VPrivateKeyPassword,ResVar: Variant;
begin
  if GridHosts.Focused then
  begin
    with TvisGroupChoice.Create(self) do
    try
      Caption := rsSelectRemoveDepends;
      res := Nil;

      if ShowModal = mrOk then
      try
        Screen.Cursor := crHourGlass;
        packages := SelectedPackages;
        Hosts := ExtractField(GridHosts.SelectedRows,'uuid');

        VHosts := SuperObjectToPyVar(Hosts);
        VPackages := SuperObjectToPyVar(packages);
        VWaptIniFilename := PyUTF8Decode(AppIniFilename);
        VPrivateKeyPassword := PyUTF8Decode(dmpython.privateKeyPassword);

        resVar := DMPython.waptdevutils.edit_hosts_depends(
           waptconfigfile := VWaptIniFilename,
           hosts_list := VHosts,
           remove_depends := VPackages,
           sign_certs := DMPython.WAPT.personal_certificate('--noarg--'),
           sign_key := DMPython.WAPT.private_key(private_key_password := VPrivateKeyPassword),
           wapt_server_user := waptServerUser,
           wapt_server_passwd := waptServerPassword,
           cabundle := DMPython.WaptHostRepo.cabundle
           );

        res := PyVarToSuperObject(ResVar);
      finally
        Screen.cursor := crDefault;
        if res <> Nil then
          ShowMessageFmt(rsNbModifiedHosts, [res.A['updated'].Length,res.A['discarded'].Length,res.A['unchanged'].Length]);
      end;
    finally
      Free;
    end;
  end;
end;


procedure TVisWaptGUI.ActWUAProductHideExecute(Sender: TObject);
{$ifdef wsus2}
var
  wproduct:ISuperobject;
{$endif wsus2}
begin
  {$ifdef wsus2}
  for wproduct in GridWinproducts.SelectedRows do
    wproduct.B['favourite'] := False;
  GridWinproducts.Data := FilterWinProducts(WUAProducts);
  {$endif wsus2}
end;

procedure TVisWaptGUI.ActWUAProductShowExecute(Sender: TObject);
{$ifdef wsus}
var
  wproduct:ISuperobject;
{$endif wsus2}
begin
  {$ifdef wsus2}
  for wproduct in GridWinproducts.SelectedRows do
    wproduct.B['favourite'] := True;
  GridWinproducts.Data := FilterWinProducts(WUAProducts);
  {$endif wsus2}
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
  GridHostsForPackage.LoadSettingsFromIni(Appuserinipath+'.default');

  {$ifdef enterprise}
  GridWUUpdates.LoadSettingsFromIni(Appuserinipath+'.default');
  GridHostWinUpdates.LoadSettingsFromIni(Appuserinipath+'.default');
  GridReportingQueries.LoadSettingsFromIni(Appuserinipath+'.default');
  {$endif}

end;

procedure TVisWaptGUI.ActSearchGroupsExecute(Sender: TObject);
begin
  EdSearchGroups.Modified := False;
  GridGroups.Data := PyVarToSuperObject(DMPython.MainWaptRepo.search(searchwords := EdSearchGroups.Text, sections := 'group,unit,profile',
      description_locale := Language, newest_only := cbNewestOnlyGroups.Checked));
  //GridGroups.CreateColumnsFromData(False,True);
  //GridGroupsChange(GridGroups,GridGroups.FocusedNode);
end;

procedure TVisWaptGUI.ActTriggerHostUpdateExecute(Sender: TObject);
begin
  if (GridHosts.SelectedCount>=1) and (GridHosts.SelectedCount<=5) then
    TriggerActionOnHosts(ExtractField(GridHosts.SelectedRows,'uuid'),'trigger_host_update',Nil,rsTriggerHostsUpdate,'Error checking for updates',True)
  else
    with TVisTriggerHostsAction.Create(Self) do
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
  DMPython.PythonEng.ExecString(MemoEditSourcesTest.Lines.Text);
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
  soresult,columns,urlParams, Hosts,fields: ISuperObject;
  prop: string;
  HostsCount,i: integer;
const
  DefaultColumns:Array[0..14] of String = ('uuid','os_name','connected_ips','computer_fqdn',
    'computer_name','manufacturer','description','productname','serialnr','mac_addresses','connected_users','last_logged_on_user',
    'computer_ad_ou','computer_ad_site','platform');
begin
  if AppLoading then
    Exit;
  try
    inSearchHosts := True;
    Screen.cursor := crHourGlass;
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

    if IsEnterpriseEdition then
    begin
      columns.AsArray.Add('waptwua_status');
      columns.AsArray.Add('wuauserv_status');
    end;

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
        fields.AsArray.Add('platform');
		fields.AsArray.Add('os_name');
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

    end;

    if CBInverseSelect.Checked then
      urlParams.AsArray.Add(format('not_filter=1',[]));

    if cbHasErrors.Checked then
      urlParams.AsArray.Add('has_errors=1');

    if cbReachable.Checked then
      urlParams.AsArray.Add('reachable=1');

    if cbNeedUpgrade.Checked then
      urlParams.AsArray.Add('need_upgrade=1');

    if (cbGroups.Text<>rsFilterAll) and (cbGroups.Text<>'*') and (cbGroups.Text<>'') then
      urlParams.AsArray.Add(UTF8Decode(Format('groups=%s',[EncodeURIComponent(cbGroups.Text)])));

    {$ifdef ENTERPRISE}
    {$include ..\waptenterprise\includes\uwaptconsole.searchhost.filter.inc}
    {$endif}

    urlParams.AsArray.Add(UTF8Decode('columns='+join(',',columns)));
    urlParams.AsArray.Add(UTF8Decode(Format('limit=%d',[HostsLimit])));

    soresult := WAPTServerJsonGet('api/v1/hosts?%s',[soutils.Join('&', urlParams)]);
    if (soresult<>Nil) and (soresult.B['success']) then
    begin
      hosts := soresult['result'];
      GridHosts.Data := hosts;
      if (hosts <> nil) and (hosts.AsArray <> nil) then
      begin
        HostsCount := hosts.AsArray.Length;
        {$ifdef ENTERPRISE}
        {$include ..\waptenterprise\includes\uwaptconsole.searchhost.check_count.inc}
        {$endif}
        LabelComputersNumber.Caption := IntToStr(HostsCount);
        if PollTasksThread <> Nil then
        begin
          PollTasksThread.Terminate;
          PollTasksThread := Nil;
        end;
      end;
    end
    else
    begin
      GridHosts.Data := Nil;
      if soresult <> Nil then
        ShowMessageFmt('Unable to get hosts list : %s',[soresult.S['msg']])
      else
        ShowMessageFmt('Unable to get hosts list : %s',['Invalid data']);
    end;
  finally
    Screen.Cursor:=crDefault;
    inSearchHosts:=False;;
  end;
end;

procedure TVisWaptGUI.ActSearchPackageExecute(Sender: TObject);
var
  ASA, RequestFilter: ISuperObject;
  vRequestFilter: Variant;

  function AtLeastOne(cg:TCheckGroup):Boolean;
  var
    i: Integer;
  begin
    for i:=0 to cg.Items.Count-1 do
      if cg.Checked[i] then
      begin
        Result := True;
        Exit;
      end;
    Result := False;
  end;

begin
  try
    Screen.Cursor:=crHourGlass;

    RequestFilter := SO();

    if AtLeastOne(cbFilterPackagesArch) then
    begin
      ASA := TSuperObject.Create(stArray);
      if cbFilterPackagesArch.Checked[0] then ASA.AsArray.Add('x86');
      if cbFilterPackagesArch.Checked[1] then ASA.AsArray.Add('x64');
      RequestFilter['architectures'] := ASA;
    end;

    if AtLeastOne(cbFilterPackagesLocales) then
    begin
      ASA := TSuperObject.Create(stArray);
      if cbFilterPackagesLocales.Checked[0] then ASA.AsArray.Add('en');
      if cbFilterPackagesLocales.Checked[1] then ASA.AsArray.Add('fr');
      if cbFilterPackagesLocales.Checked[2] then ASA.AsArray.Add('de');
      if cbFilterPackagesLocales.Checked[3] then ASA.AsArray.Add('it');
      if cbFilterPackagesLocales.Checked[4] then ASA.AsArray.Add('es');
      RequestFilter['locales'] := ASA;
    end;

    vRequestFilter:=SuperObjectToPyVar(RequestFilter);
    EdSearchPackage.Modified:=False;

    GridPackages.Data :=
      PyVarToSuperObject(DMPython.MainWaptRepo.search(searchwords := EdSearchPackage.Text,
         exclude_sections := 'host,group,unit,wsus,profile,selfservice',
         newest_only := cbNewestOnly.Checked,
         description_locale := Language,
         package_request := vRequestFilter));
  finally
    Screen.Cursor:=crDefault;
  end;
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
    {$ifdef ENTERPRISE}
    ShowProgress('Filter WAPT WUA packages',4);
    ActWUASearchPackage.Execute;
    {$endif}
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
  SplitBottomDebug.Visible := AdvancedMode;
  if AdvancedMode then
      cbAdvancedMode.State:=cbChecked
  else
      cbAdvancedMode.State:=cbUnchecked;
  Gridhosts.ShowAdvancedColumnsCustomize:= AdvancedMode;
  GridGroups.ShowAdvancedColumnsCustomize:=AdvancedMode;
  GridPackages.ShowAdvancedColumnsCustomize:=AdvancedMode;
  GridHostPackages.ShowAdvancedColumnsCustomize:=AdvancedMode;
  GridHostsForPackage.ShowAdvancedColumnsCustomize:=AdvancedMode;

  if IsEnterpriseEdition then
  begin
    GridHostWinUpdates.ShowAdvancedColumnsCustomize:=AdvancedMode;
    GridWUUpdates.ShowAdvancedColumnsCustomize:=AdvancedMode;
    GridHostsForPackage.ShowAdvancedColumnsCustomize:=AdvancedMode;
  end;

  //ActPackagesUpdate.Execute;
  GridPackages.Data := Nil;
  GridGroups.Data := Nil;
  GridHosts.Data := Nil;
  GridHostsForPackage.Data := Nil;

  if IsEnterpriseEdition then
  begin
    GridHostWinUpdates.Data := Nil;
    GridWUUpdates.Data := Nil;
  end;
end;

procedure TVisWaptGUI.ActDisplayDebugExecute(Sender: TObject);
var
  inifile:TIniFile;
begin
  try
    inifile := TIniFile.Create(AppIniFilename);
    AdvancedMode:=not(AdvancedMode);
    inifile.WriteBool('global', 'advanced_mode',AdvancedMode);
    pgSources.TabVisible := AdvancedMode;
      PanDebug.Visible := AdvancedMode;
      SplitBottomDebug.Visible := AdvancedMode;
      if AdvancedMode then
          cbAdvancedMode.State:=cbChecked
      else
          cbAdvancedMode.State:=cbUnchecked;
      Gridhosts.ShowAdvancedColumnsCustomize:= AdvancedMode;
      GridGroups.ShowAdvancedColumnsCustomize:=AdvancedMode;
      GridPackages.ShowAdvancedColumnsCustomize:=AdvancedMode;
      GridHostPackages.ShowAdvancedColumnsCustomize:=AdvancedMode;
      GridHostsForPackage.ShowAdvancedColumnsCustomize:=AdvancedMode;

      if IsEnterpriseEdition then
      begin
        GridHostWinUpdates.ShowAdvancedColumnsCustomize:=AdvancedMode;
        GridWUUpdates.ShowAdvancedColumnsCustomize:=AdvancedMode;
        GridHostsForPackage.ShowAdvancedColumnsCustomize:=AdvancedMode;
      end;
  finally
    FreeAndNil(inifile);
  end;
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
      FileExistsUTF8(GetVNCViewerPath);
  except
    ActVNC.Enabled := False;
  end;
end;

procedure TVisWaptGUI.ActWAPTConsoleConfigExecute(Sender: TObject);
begin
  if EditIniFile then
  begin
    GridHostsPlugins := Nil;
    ActReloadConfig.Execute;
    GridPackages.Clear;
    GridGroups.Clear;
    GridHosts.Clear;
    GridhostInventory.Clear;
    GridHostPackages.Clear;
    GridHostsForPackage.Clear;
    GridHostSoftwares.Clear;
    { TODO : Remove use of WAPT instance, use waptpackage.PackageEntry instead }
    if not VarIsEmpty(DMPython.WAPT) then
      DMPython.WAPT := Unassigned;
    // put somewhere else
    MainPagesChange(MainPages);
  end;
end;



procedure TVisWaptGUI.ApplicationProperties1Exception(Sender: TObject;
  E: Exception);
begin
  MessageDlg('Error in application',E.Message,mtError,[mbOK],'');
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
    cbGroups.Text:='';

    {$ifdef ENTERPRISE}
    cbADSite.ItemIndex:=-1;
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

procedure TVisWaptGUI.cbGroupsKeyPress(Sender: TObject; var Key: char);
var
  st:String;
  select:TDynStringArray;
begin
  if key=#13 then
  begin
    if cbGroups.Items.IndexOf(cbGroups.Text)<0 then
    begin
      if StrRight(cbGroups.Text,1)='*' then
        cbGroups.Text := StrLeft(cbGroups.Text,length(cbGroups.Text)-1);
      if cbGroups.Items.Count=0 then
        FillcbGroups;
      for st in cbGroups.Items do
        if pos(lowercase(cbGroups.Text),lowercase(st))>0 then
          StrAppend(Select,St);
      cbGroups.Text:=StrJoin(',',Select);
      cbGroups.SelectAll;
    end;
    ActSearchHost.Execute;
  end;
end;

procedure TVisWaptGUI.cbGroupsSelect(Sender: TObject);
begin
  ActSearchHost.Execute;
end;

procedure TVisWaptGUI.cbHostsHasErrorsClick(Sender: TObject);
begin
  ActRefreshHostsForPackage.Execute;
end;

procedure TVisWaptGUI.CBIncludeSubOUClick(Sender: TObject);
begin
  GridOrgUnits.OnChange(GridOrgUnits,GridOrgUnits.FocusedNode);
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
begin
  Result := False;
  with TVisWAPTConfig.Create(self) do
  try
    IniFileName:=AppIniFilename;
    if ShowModal = mrOk then
    begin
      DMPython.privateKeyPassword:='';
      Result := True;
    end;
  finally
    Free;
  end;
end;

procedure TVisWaptGUI.cbMaskSystemComponentsClick(Sender: TObject);
begin
  if Gridhosts.FocusedRow<>Nil then
    GridHostSoftwares.Data := FilterSoftwares(Gridhosts.FocusedRow['installed_softwares']);
end;

procedure TVisWaptGUI.cbNewestOnlyClick(Sender: TObject);
begin
  TimerSearchPackages.Enabled:=False;
  TimerSearchPackages.Enabled:=True;
end;

procedure TVisWaptGUI.cbNewestOnlySelfServiceClick(Sender: TObject);
begin
  ActSelfServiceSearchPackage.Execute;
end;

procedure TVisWaptGUI.cbNewestOnlyWUAClick(Sender: TObject);
begin
  ActWUASearchPackage.Execute;
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

function checkReadWriteAccess(dir: String): boolean;
var
  fn: String;
begin
  try
    fn := LazFileUtils.GetTempFileNameUTF8(dir, 'test');
    StringToFile(fn, '');
    DeleteFileUTF8(fn);
    Result := True;
  except
    Result := False;
  end;
end;

procedure TVisWaptGUI.FormCreate(Sender: TObject);
begin
  WaptServerUser := IniReadString(Appuserinipath,self.name,'lastwaptserveruser','admin');
  HostsLimit := 2000;
  DMPython.PythonOutput.OnSendData := @PythonOutputSendData;
  cbFilterPackagesArch.Checked[0] := False;
  cbFilterPackagesArch.Checked[1] := True;
  if cbFilterPackagesLocales.Items.IndexOf(Language)>=0 then
    cbFilterPackagesLocales.Checked[cbFilterPackagesLocales.Items.IndexOf(Language)] := True;
  EdSearchHost.EmptyText:=rsSearch;
  EdSearchOrgUnits.EmptyText:=rsSearchOU;
end;

procedure TVisWaptGUI.FormDestroy(Sender: TObject);
begin
  If PollTasksThread <> Nil then
    PollTasksThread.Terminate;
end;

procedure TVisWaptGUI.FormDragOver(Sender, Source: TObject; X, Y: Integer;
  State: TDragState; var Accept: Boolean);
begin
  if MainPages.ActivePage = pgPrivateRepo then
    Accept:=True;
end;

procedure TVisWaptGUI.FormDropFiles(Sender: TObject;
  const FileNames: array of String);
var
  Filename,ext: String;
  WaptFiles,SetupFiles: TStringList;
begin
  if MainPages.ActivePage = pgPrivateRepo then
  try
    WaptFiles := TStringList.Create;
    SetupFiles := TStringList.Create;

    for Filename in FileNames do
    begin
      Ext := ExtractFileExt(FileName);
      if lowercase(Ext) = '.wapt' then
        WaptFiles.Add(Filename)
      else if lowercase(Ext) = '.msi' then
        SetupFiles.Add(Filename);
    end;
    if WaptFiles.Count>0 then
      ImportPackageFromFiles(WaptFiles);

    if SetupFiles.Count>0 then
      MakePackageTemplate(SetupFiles[0]);
  finally
    WaptFiles.Free;
    SetupFiles.Free;
  end;
end;

procedure TVisWaptGUI.MakePackageTemplate(AInstallerFileName: String);
begin
  if DefaultSourcesRoot='' then
  begin
    ShowMessage(rsDefineWaptdevPath);
    ActWAPTConsoleConfig.Execute;
    if (DefaultSourcesRoot='') then
      Exit;
  end;

  With TVisPackageWizard.Create(self) do
  try
    InstallerFilename:=AInstallerFileName;
    if ShowModal <> mrCancel then
      actRefresh.Execute;
  finally
    Free;
  end;
end;

procedure TVisWaptGUI.SetReportingEditMode(AValue: Boolean);
begin
  if not AValue and (GridReportingResult.FocusedRow<>Nil) then
    SynEditReportsSQLChange(SynEditReportsSQL);

  FReportingEditMode:=AValue;

  ToolButtonDesignQuery.Down := FReportingEditMode;

  PanelReportingEditSQL.Visible := FReportingEditMode;
  SplitterReportingHorizontal.Visible:= FReportingEditMode;

  ActReportingQueryNew.Visible:= FReportingEditMode;
  ActReportingQueryDuplicate.Visible:= FReportingEditMode;
  ActReportingQueryDelete.Visible:= FReportingEditMode;
  ActReportingQuerySaveAll.Visible:= FReportingEditMode;


  if FReportingEditMode then
    SplitterReportingHorizontal.Top := PanelReportingEditSQL.Top+PanelReportingEditSQL.Height;
end;

function TVisWaptGUI.Login: boolean;
var
  cred, sores: ISuperObject;
  localfn: String;
  LicencesLog:String;
  HostsCount: Integer;
begin
  Result := False;
  // Initialize user local config file with global wapt settings
  localfn := AppIniFilename;

  if not FileExistsUTF8(localfn) then
  begin
    if not DirectoryExistsUTF8(ExtractFileDir(localFn)) then
       ForceDirectoriesUTF8(ExtractFileDir(localFn));
    CopyFile(WaptIniFilename,localfn, True);
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
      {$ifdef ENTERPRISE }
      if ExtractFileDir(AppIniFilename)+'\' = GetAppConfigDir(False) then
        CBConfiguration.Text := ExtractFileNameWithoutExt(ExtractFileNameOnly(AppIniFilename))
      else
        CBConfiguration.Text := AppIniFilename;
      {$endif}
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
            WaptServerUUID := UTF8Encode(sores['result'].S['server_uuid']);
            WaptServerEdition := UTF8Encode(sores['result'].S['edition']);
            HostsCount := sores['result'].I['hosts_count'];
            {$ifdef ENTERPRISE}
            {$include ..\waptenterprise\includes\uwaptconsole.login.check_licence.inc}
            {$endif}
            Result := True;
            if (CompareVersion(UTF8Encode(sores['result'].S['version']),WAPTServerMinVersion)<0) then
              ShowMessageFmt(rsWaptServerOldVersion,[UTF8Encode(sores['result'].S['version']),WAPTServerMinVersion]);
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
  i: Integer;
  sores: ISuperObject;
  CB:TComponent;
  ini:TIniFile;
  WaptAgentCurrentVersion,WaptAgentExpectedVersion:String;
begin
  {$ifdef ENTERPRISE}
  IsEnterpriseEdition:=True;
  ActProprietary.Enabled := True;
  ActProprietary.Checked := True;
  ReportingEditMode := False;
  {$else}
  IsEnterpriseEdition:=False;
  ActProprietary.Enabled := False;
  ActProprietary.Checked := False;
  {$endif}

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
    GridHostsForPackage.SaveSettingsToIni(Appuserinipath+'.default');
    GridHostSoftwares.SaveSettingsToIni(Appuserinipath+'.default');

    {$ifdef ENTERPRISE}
    if IsEnterpriseEdition then
    begin
      GridWUUpdates.SaveSettingsToIni(Appuserinipath+'.default');
      GridHostWinUpdates.SaveSettingsToIni(Appuserinipath+'.default');
      GridReportingQueries.SaveSettingsToIni(Appuserinipath+'.default');
    end;
    {$endif}

    // don't load grid settings if old ini version
    if IniReadString(Appuserinipath,self.name,'waptconsole.version','') <> '' then
    begin
      Gridhosts.LoadSettingsFromIni(Appuserinipath);
      GridPackages.LoadSettingsFromIni(Appuserinipath);
      GridGroups.LoadSettingsFromIni(Appuserinipath);
      GridHostPackages.LoadSettingsFromIni(Appuserinipath);
      GridHostsForPackage.LoadSettingsFromIni(Appuserinipath);
      GridHostSoftwares.LoadSettingsFromIni(Appuserinipath);
      ini := TIniFile.Create(Appuserinipath);
      try
        for CB in VarArrayOf([cbAdvancedSearch,cbSearchAll,cbSearchDMI,cbSearchHost,cbSearchPackages,cbSearchSoftwares,cbReachable]) do
          TCheckBox(CB).Checked := ini.ReadBool(self.Name,CB.Name,TCheckBox(CB).Checked);

        for i:=0 to cbFilterPackagesLocales.Items.Count-1 do
          cbFilterPackagesLocales.Checked[i] := ini.ReadBool(self.Name,cbFilterPackagesLocales.Items[i],cbFilterPackagesLocales.Checked[i]);

        for i:=0 to cbFilterPackagesArch.Items.Count-1 do
          cbFilterPackagesArch.Checked[i] := ini.ReadBool(self.Name,cbFilterPackagesArch.Items[i],cbFilterPackagesArch.Checked[i]);
        HostsLimit := ini.ReadInteger(self.name,'HostsLimit',2000);
        //ShowMessage(Appuserinipath+'/'+self.Name+'/'+EdHostsLimit.Name+'/'+ini.ReadString(name,EdHostsLimit.Name,'not found'));
        HostPages.Width := ini.ReadInteger(self.name,HostPages.Name+'.width',HostPages.Width);

        Self.Left := ini.ReadInteger(self.name,'Left',Integer(Self.Left));
        Self.Top := ini.ReadInteger(self.name,'Top',Integer(Self.Top));
        Self.Width := ini.ReadInteger(self.name,'Width',Integer(Self.Width));
        Self.Height := ini.ReadInteger(self.name,'Height',Integer(Self.Height));
        Self.MakeFullyVisible;

        Self.WindowState := TWindowState(ini.ReadInteger(self.Name,'WindowState',Integer(Self.WindowState)));


        self.cbGroups.Text := ini.ReadString(self.Name,'cbGroups.Text',self.cbGroups.Text);

        pgSources.TabVisible := AdvancedMode;
        PanDebug.Visible := AdvancedMode;
        SplitBottomDebug.Visible := AdvancedMode;
        if AdvancedMode then
            cbAdvancedMode.State:=cbChecked
        else
            cbAdvancedMode.State:=cbUnchecked;
        Gridhosts.ShowAdvancedColumnsCustomize:= AdvancedMode;
        GridGroups.ShowAdvancedColumnsCustomize:=AdvancedMode;
        GridPackages.ShowAdvancedColumnsCustomize:=AdvancedMode;
        GridHostPackages.ShowAdvancedColumnsCustomize:=AdvancedMode;
        GridHostsForPackage.ShowAdvancedColumnsCustomize:=AdvancedMode;

        {$ifdef ENTERPRISE}
        {$include ..\waptenterprise\includes\uwaptconsole.formshow.inc}
        {$endif}

      finally
        ini.Free;
      end;
    end
    else
      // be sure other forms will not use it.
      if FileExistsUTF8(Appuserinipath) then
        DeleteFileUTF8(Appuserinipath);

    plStatusBar1.Caption := WaptServerUser+' on '+ApplicationName+' '+
      GetApplicationVersion+' WAPT '+WaptEdition+' Edition, (c) 2012-2019 Tranquil IT. (Conf:'+
      AppIniFilename+')';
    {$ifdef ENTERPRISE}
    plStatusBar1.Caption := plStatusBar1.Caption + ' ' + Format(rsLicencedTo,[dmPython.LicensedTo]);
    {$endif}

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

    // check minimum settings : prefix and personal certificate
    if (WaptPersonalCertificatePath='') or not FileExistsUTF8(WaptPersonalCertificatePath) then
      if MessageDlg(rsMissingPersonalCertificate,rsMissingPersonalCertificateQuestion,mtConfirmation,mbYesNoCancel,'') = mrYes then
        ActWAPTConsoleConfig.Execute;

    if (DefaultPackagePrefix='') then
      if MessageDlg(rsWaptPackagePrefix,rsWaptPackagePrefixMissingQuestion,mtConfirmation,mbYesNoCancel,'') = mrYes then
        ActWAPTConsoleConfig.Execute;

    ActSearchHost.Execute;

    // check waptagent version
    sores := WAPTServerJsonGet('api/v2/waptagent_version', []);
    try
      if sores.B['success'] then
      begin
        WaptAgentCurrentVersion := UTF8Encode(sores['result'].S['waptagent_version']);
        WaptAgentExpectedVersion := UTF8Encode(sores['result'].S['waptsetup_version']);
        // for windows server without waptsetup-tis
        if WaptAgentExpectedVersion = '' then
          WaptAgentExpectedVersion := WAPTServerMinVersion;

        if ((WaptAgentCurrentVersion='') and (MessageDlg('waptagent check',rsWaptAgentNotPresent,mtConfirmation,mbYesNoCancel,'') = mrYes)) // needs to be created
          or
           ((WaptAgentCurrentVersion<>'') and (CompareVersion(WaptAgentCurrentVersion,WaptAgentExpectedVersion) < 0 ) and (MessageDlg(rsWaptAgentCheck,
                Format(rsWaptAgentOldVersion,[sores['result'].S['waptagent_version'],sores['result'].S['waptsetup_version']]),              // needs to be upgraded
                mtConfirmation,
                mbYesNoCancel,'') = mrYes)) then
          ActCreateWaptSetup.Execute;
      end;
    except
        on E:Exception do
          ShowMessageFmt(rsWaptAgentUnableToCheck,[E.Message]);
    end;
  finally
    AppLoading:=False;
    Free;
  end;
    if Screen.PixelsPerInch<>96 then
    begin
        GridHosts.Header.Height:=trunc((GridHosts.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridHostPackages.Header.Height:=trunc((GridHostPackages.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridHostSoftwares.Header.Height:=trunc((GridHostSoftwares.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridHostWinUpdates.Header.Height:=trunc((GridHostWinUpdates.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridHostWinUpdatesHistory.Header.Height:=trunc((GridHostWinUpdatesHistory.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridHostTasksPending.Header.Height:=trunc((GridHostTasksPending.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridHostTasksDone.Header.Height:=trunc((GridHostTasksDone.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridHostTasksErrors.Header.Height:=trunc((GridHostTasksErrors.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridGroups.Header.Height:=trunc((GridGroups.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridPackages.Header.Height:=trunc((GridPackages.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridHostsForPackage.Header.Height:=trunc((GridHostsForPackage.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridWUAPackages.Header.Height:=trunc((GridWUAPackages.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridWSUSScan.Header.Height:=trunc((GridWSUSScan.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridWUUpdates.Header.Height:=trunc((GridWUUpdates.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridSelfServicePackages.Header.Height:=trunc((GridSelfServicePackages.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridReportingResult.Header.Height:=trunc((GridReportingResult.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridReportingQueries.Header.Height:=trunc((GridReportingQueries.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridRules.Header.Height:=trunc((GridRules.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridAgentRepo.Header.Height:=trunc((GridAgentRepo.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridhostInventory.Header.Height:=trunc((GridhostInventory.Header.MinHeight*Screen.PixelsPerInch)/96);
        GridOrgUnits.Header.Height:=trunc((GridOrgUnits.Header.MinHeight*Screen.PixelsPerInch)/96);
        jsonlog.Header.Height:=trunc((jsonlog.Header.MinHeight*Screen.PixelsPerInch)/96);
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
  if maxheight > 6 *(Sender as TSOGrid).DefaultNodeHeight then
    maxheight := 6 *(Sender as TSOGrid).DefaultNodeHeight;
  NodeHeight := maxheight + 4;
end;

procedure TVisWaptGUI.GridGroupsSOCompareNodes(Sender: TSOGrid; Node1,
  Node2: ISuperObject; const Columns: array of String; var Result: Integer);
begin
  if (length(Columns) > 0) and (Node1 <> nil) and (Node2 <> nil) then
  begin
    if length(Columns) = 1 then
    begin
      if pos('package',Columns[0])>0 then
      begin
        Result:=CompareStr(Node1.S[Columns[0]],Node2.S[Columns[0]]);
        If Result = 0 then
          Result:= CompareVersion(Node1.S['version'],Node2.S['version']);
        If Result = 0 then
          Result:= CompareStr(Node1.S['architecture'],Node2.S['architecture']);
        If Result = 0 then
          Result:= CompareStr(Node1.S['locale'],Node2.S['locale']);
        If Result = 0 then
          Result:= CompareStr(Node1.S['maturity'],Node2.S['maturity']);
      end
      else if pos('size',Columns[0])>0 then
        Result:=CompareInt(Node1.I[Columns[0]],Node2.I[Columns[0]])
      else if pos('version',Columns[0])>0 then
        Result:= CompareVersion(Node1.S[Columns[0]],Node2.S[Columns[0]])
      else
        Result := integer(SOCompareByKeys(Node1,Node2,Columns)) - 1;
    end
    else
      Result := integer(SOCompareByKeys(Node1,Node2,Columns)) - 1;
  end
  else
    Result := -1;
end;

procedure TVisWaptGUI.GridHostPackagesChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  if Assigned(GridHostPackages.FocusedRow) then
  begin
    if IsEnterpriseEdition and (GridHostPackages.FocusedColumnObject.PropertyName = 'last_audit_status') then
    begin
      Label16.Caption:=Format(rsAuditPackages,[GridHostPackages.FocusedRow.S['package']]);
      MemoInstallOutput.Text := UTF8Encode(GridHostPackages.FocusedRow.S['last_audit_output'])
    end
    else
    begin
      MemoInstallOutput.Text := UTF8Encode(GridHostPackages.FocusedRow.S['install_output']);
      Label16.Caption:=Format(rsInstallPackages,[GridHostPackages.FocusedRow.S['package']]);
    end;
    MemoInstallOutput.CaretPos := Point(1, 65535);
    MemoInstallOutput.SelStart := 65535;
    MemoInstallOutput.SelLength := 0;
    MemoInstallOutput.ScrollBy(0, 65535);
    Panel5.Show;
    Splitter4.Show;
    Splitter4.AnchorParallel(akBottom,0,pgPackages);
  end
  else
  begin
    MemoInstallOutput.Clear;
    Panel5.Hide;
    Splitter4.Hide;
  end;
end;

procedure TVisWaptGUI.GridHostPackagesClick(Sender: TObject);
begin
  if Assigned(GridHostPackages.FocusedRow) then
  begin
    Panel5.Show;
    Splitter4.Show;
    Splitter4.AnchorParallel(akBottom,0,pgPackages);
  end
  else
  begin
    Panel5.Hide;
    Splitter4.Hide;
  end;
end;

procedure TVisWaptGUI.GridHostPackagesFocusChanged(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex);
begin
  GridHostPackagesChange(Sender,Node);
end;


procedure TVisWaptGUI.GridHostPackagesGetImageIndexEx(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
  var Ghosted: boolean; var ImageIndex: integer; var ImageList: TCustomImageList);
var
  reachable,install_status: ISuperObject;
  propname: String;
  aGrid:TSOGrid;
begin
  aGrid := (Sender as TSOGrid);
  propName:=TSOGridColumn(aGrid.Header.Columns[Column]).PropertyName;

  if propName='reachable' then
  begin
    ImageIndex:=-1;
    reachable := aGrid.GetCellData(Node, 'reachable', Nil);
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
  else if propName='install_status' then
  begin
    install_status := aGrid.GetCellData(Node, 'install_status', nil);
    if (install_status <> nil) then
    begin
      case install_status.AsString of
        'OK': ImageIndex := 0;
        'ERROR-UPGRADE','ERROR','ERROR-INSTALL': ImageIndex := 2;
        'NEED-UPGRADE': ImageIndex := 1;
        'NEED-REMOVE': ImageIndex := 8;
        'RUNNING': ImageIndex := 6;
        'MISSING','NEED-INSTALL': ImageIndex := 7;
      end;
    end;
  end
  else
  if IsEnterpriseEdition and (propName='last_audit_status') then
  begin
    install_status := aGrid.GetCellData(Node, 'last_audit_status', nil);
    if (install_status <> nil) then
    begin
      case install_status.AsString of
        'OK': ImageIndex := 0;
        'ERROR': ImageIndex := 2;
        'WARNING': ImageIndex := 1;
        'UNKNOWN': ImageIndex := 14;
        'RUNNING': ImageIndex := 6;
      end;
    end;
  end;
end;

procedure TVisWaptGUI.GridHostPackagesGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; RowData, CellData: ISuperObject; Column: TColumnIndex;
  TextType: TVSTTextType; var CellText: string);
var
  propName:String;
  aGrid:TSOGrid;
begin
  aGrid := (Sender as TSOGrid);

  if (Node = nil) or (CellData=Nil) then
    CellText := ''
  else
  begin
    propName:=TSOGridColumn(aGrid.Header.Columns[Column]).PropertyName;

    if (CellData <> nil) and (CellData.DataType = stArray) then
      CellText := soutils.Join(',', CellData);

    if StrIsOneOf(propName,['install_date','last_audit_on','next_audit_on','created_on','updated_on']) then
        CellText := Copy(StrReplaceChar(CellText,'T',' '),1,16);
  end;
end;

procedure TVisWaptGUI.GridHostPackagesNodesDelete(Sender: TSOGrid;
  Nodes: ISuperObject);
begin
  if ActPackagesRemove.Enabled then
    ActPackagesRemove.Execute;
end;

procedure TVisWaptGUI.GridHostsChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
begin
  HostPages.Visible:=Assigned(GridHosts.FocusedRow);
  Panel1.Visible:=Assigned(GridHosts.FocusedRow);
  SplitGridUnitsHosts1.Visible:=Assigned(GridHosts.FocusedRow);
  SplitGridUnitsHosts1.AnchorParallel(akRight,0,HostPages);
  UpdateHostPages(Sender);
  UpdateSelectedHostsActions(Sender);
  if GridHosts.Data<>Nil then
    LabelComputersNumber.Caption := Format(rsHostsSelectedTotal,[GridHosts.SelectedCount,GridHosts.Data.AsArray.Length])
  else
    LabelComputersNumber.Caption := '';
end;

procedure TVisWaptGUI.GridHostsClick(Sender: TObject);
begin
  HostPages.Visible:=Assigned(GridHosts.FocusedRow);
  Panel1.Visible:=Assigned(GridHosts.FocusedRow);
  SplitGridUnitsHosts1.Visible:=Assigned(GridHosts.FocusedRow);
  SplitGridUnitsHosts1.AnchorParallel(akRight,0,HostPages);
end;

procedure TVisWaptGUI.GridHostsColumnDblClick(Sender: TBaseVirtualTree;
  Column: TColumnIndex; Shift: TShiftState);
begin
  ActEditHostPackage.Execute;
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

procedure TVisWaptGUI.GridHostsForPackageChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  if (GridHostsForPackage.FocusedRow <> nil) and (GridHostsForPackage.FocusedColumnObject<>Nil) then
  begin
    if IsEnterpriseEdition and (GridHostsForPackage.FocusedColumnObject.PropertyName = 'last_audit_status') then
      MemoInstallOutput1.Text := UTF8Encode(GridHostsForPackage.FocusedRow.S['last_audit_output'])
    else
      MemoInstallOutput1.Text := UTF8Encode(GridHostsForPackage.FocusedRow.S['install_output']);
    MemoInstallOutput1.CaretPos := Point(1, 65535);
    MemoInstallOutput1.SelStart := 65535;
    MemoInstallOutput1.SelLength := 0;
    MemoInstallOutput1.ScrollBy(0, 65535);
  end
  else
    MemoInstallOutput1.Clear;
end;

procedure TVisWaptGUI.GridHostsForPackageFocusChanged(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex);
begin
  GridHostsForPackageChange(Sender,Node);
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
      Grid.Data := SO(UTF8Decode(jsondata));
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
    jsp := TJSONParser.Create(UTF8Encode(jsondata.AsJSon));
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
  registration_auth_user,reachable,platform: ISuperObject;
begin
  if TSOGridColumn(GridHosts.Header.Columns[Column]).PropertyName = 'host_status' then
  begin
    RowSO := GridHosts.GetNodeSOData(Node);
    if RowSO <> nil then
    begin
      status := RowSO['host_status'];
      if (status <> nil) then
      begin
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
      else if reachable.AsString = 'RUNNING' then
          ImageIndex := 6
      else
        ImageIndex := -1;
    end
    else
      ImageIndex := -1;
  end
  else if TSOGridColumn(GridHosts.Header.Columns[Column]).PropertyName = 'platform' then
  begin
    platform := GridHostPackages.GetCellData(Node, 'platform', Nil);
    if (platform<>Nil)then
    begin
      if (platform.AsString = 'Linux') then
        ImageIndex := 21
      else if (platform.AsString = 'Windows') then
        ImageIndex := 20
      else if (platform.AsString = 'macOS') then
          ImageIndex := 19;
    end
    else
      ImageIndex := -1;
  end
  else if TSOGridColumn(GridHosts.Header.Columns[Column]).PropertyName = 'registration_auth_user' then
  begin
    ImageIndex:=10;
    registration_auth_user := GridHostPackages.GetCellData(Node, 'registration_auth_user', Nil);

    if (registration_auth_user = Nil) or (registration_auth_user.AsString='') or (copy(registration_auth_user.AsString,1,5) = 'None:') then
      ImageIndex := 9
    else
      ImageIndex := 10
  end
  else if IsEnterpriseEdition and (TSOGridColumn(GridHosts.Header.Columns[Column]).PropertyName = 'audit_status') then
  begin
    status := GridHostPackages.GetCellData(Node, 'audit_status', nil);
    if (status <> nil) then
    begin
      case status.AsString of
        'OK': ImageIndex := 0;
        'ERROR': ImageIndex := 2;
        'WARNING': ImageIndex := 1;
        'UNKNOWN': ImageIndex := 14;
        'RUNNING': ImageIndex := 6;
      end;
    end;
  end
  else if IsEnterpriseEdition and (TSOGridColumn(GridHosts.Header.Columns[Column]).PropertyName = 'waptwua_status.status') then
  begin
    status := GridHostPackages.GetCellData(Node, 'waptwua_status.status', nil);
    if (status <> nil) then
    begin
      case status.AsString of
        'OK': ImageIndex := 0;
        'ERROR': ImageIndex := 2;
        'PENDING_UPDATES': ImageIndex := 1;
      else
        ImageIndex := 14;
      end

    end;
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
        propName := StrReplaceChar(propName,'.','~');
        if RowData.AsObject.Find(propName,Celldata) then
          CellText := UTF8Encode(CellData.AsString);
      end;
    end;

    if (CellData <> nil) and (CellData.DataType = stArray) then
      CellText := soutils.Join(',', CellData);

    if StrIsOneOf(propname,['file_date','changetime','started_on','finished_on','created_on','last_audit_on',
        'updated_on','last_seen_on','listening_timestamp']) then
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
    uuids.AsArray.Add(UTF8Decode(uuid));
    args := SO();
    args.S['computer_description'] := UTF8Decode(description){%H-};
    taskresult := TriggerActionOnHosts(uuids,'trigger_change_description',args,'Change host description and register','Error changing host description');
    result := (taskresult<>Nil) and taskresult.B['success'];
  end
  else
    result := False;
end;

procedure TVisWaptGUI.GridHostsNewText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; const NewText: String);
begin
  if (GridHosts.Header.Columns[Column]  as TSOGridColumn).PropertyName = 'description' then
  begin
    if not TriggerChangeHostDescription(UTF8Encode(GridHosts.FocusedRow.S['uuid']),newtext) then
    begin
      GridHosts.CancelEditNode;
      Abort;
    end
    else
      UpdateHostPages(GridHosts);
  end;
end;

procedure TVisWaptGUI.GridHostsSOCompareNodes(Sender: TSOGrid; Node1,
  Node2: ISuperObject; const Columns: array of String; var Result: Integer);
var
  d1, d2: ISuperObject;
  propname: String;
  compresult: TSuperCompareResult;
begin
  Result := 0;

  if (length(Columns) > 0) and (Node1 <> nil) and (Node2 <> nil) then
  begin
    propname := Columns[0];
    d1 := Node1[propname];
    d2 := Node2[propname];
    if d1 = nil then
      d1 := SO('""');
    if d2 = nil then
      d2 := SO('""');
    if (d1 <> nil) and (d2 <> nil) then
    begin
      if (pos('version', propname) > 0) then
        Result := CompareVersion(UTF8Encode(d1.AsString), UTF8Encode(d2.AsString))
      else if (pos('connected_ips', propname) > 0) then
          Result := CompareVersion(UTF8Encode(d1.AsArray.S[0]),UTF8Encode(d2.AsArray.S[0]))
      else
      if (pos('mac_addresses', propname) > 0) then
        Result := UTF8CompareText(UTF8Encode(d1.AsArray.S[0]), UTF8Encode(d2.AsArray.S[0]))
      else
      begin
        CompResult := d1.Compare(d2);
        case compresult of
          cpLess: Result := -1;
          cpEqu: Result := 0;
          cpGreat: Result := 1;
          cpError: Result := UTF8CompareText(UTF8Encode(Node1.S[propname]), UTF8Encode(Node2.S[propname]));
        end;
      end;
    end
    else
      Result := -1;
  end
  else
    Result := 0;
end;

procedure TVisWaptGUI.GridHostTasksPendingClick(Sender: TObject);
begin
  if Assigned((Sender as TSOGrid).FocusedRow) then
  begin
    PanLog.Show;
    SplitHostTaskLog.AnchorParallel(akBottom,0,pgTasks);
    SplitHostTaskLog.Show;
  end
  else
  begin
    PanLog.Hide;
    SplitHostTaskLog.Hide;
  end;
end;


procedure TVisWaptGUI.GridHostTasksPendingChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  if Assigned((Sender as TSOGrid).FocusedRow) then
  begin
    PanLog.Show;
    SplitHostTaskLog.AnchorParallel(akBottom,0,pgTasks);
    SplitHostTaskLog.Show;
    Label19.Caption:=Format(rsLogTasks,[UTF8Encode((Sender as TSOGrid).FocusedRow.S['description']),UTF8Encode((Sender as TSOGrid).FocusedRow.S['id'])]);
    MemoTaskLog.Text := UTF8Encode((Sender as TSOGrid).FocusedRow.S['logs']);
    MemoTaskLog.SelStart := 65535;
    MemoTaskLog.ScrollBy(0, 65535);
  end
  else
  begin
    PanLog.Hide;
    SplitHostTaskLog.Hide;
    MemoTaskLog.Clear;
  end;
end;

procedure TVisWaptGUI.GridHostWinUpdatesClick(Sender: TObject);
begin
  if Assigned(GridHostWinUpdates.FocusedRow) then
  begin
    PanelKBLogs.Visible:=GridHostWinUpdatesHistory.Data.AsArray.Length>=1;
    SplitWinupdateHost.Visible:=GridHostWinUpdatesHistory.Data.AsArray.Length>=1;
    SplitWinupdateHost.AnchorParallel(akBottom,0,pgHostWUA);
  end
  else
  begin
    PanelKBLogs.Hide;
    SplitWinupdateHost.Hide;
  end;
end;

procedure TVisWaptGUI.GridHostWinUpdatesChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  if Assigned(GridHostWinUpdates.FocusedRow) then
  begin
    GridHostWinUpdatesHistory.Data := GridHostWinUpdates.FocusedRow['local_status_history'];
    PanelKBLogs.Visible:=GridHostWinUpdatesHistory.Data.AsArray.Length>=1;
    SplitWinupdateHost.Visible:=GridHostWinUpdatesHistory.Data.AsArray.Length>=1;
    SplitWinupdateHost.AnchorParallel(akBottom,0,pgHostWUA);
    LabLogsKB.Caption:=Format(rsLabLogsKB,['KB'+soutils.Join(',KB', GridHostWinUpdates.FocusedRow['kbids'])]);
  end
  else
  begin
    GridHostWinUpdatesHistory.Data := Nil;
    PanelKBLogs.Visible:=False;
    SplitWinupdateHost.Visible:=False;
  end;
end;

procedure TVisWaptGUI.GridHostWinUpdatesGetImageIndexEx(
  Sender: TBaseVirtualTree; Node: PVirtualNode; Kind: TVTImageKind;
  Column: TColumnIndex; var Ghosted: Boolean; var ImageIndex: Integer;
  var ImageList: TCustomImageList);
var
  row: ISuperObject;
begin
  if TSOGridColumn((Sender as TSOGrid).Header.Columns[Column]).PropertyName = 'local_status_status' then
  begin
    row := (Sender as TSOGrid).GetNodeSOData(Node);
    if row.B['local_status_installed'] then
      ImageIndex := 0
    else
    if not row.B['local_status_installed'] and not row.B['local_status_hidden'] then
      ImageIndex := 7
    else
      ImageIndex := 8
  end;
end;

procedure TVisWaptGUI.GridHostWinUpdatesGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; RowData, CellData: ISuperObject; Column: TColumnIndex;
  TextType: TVSTTextType; var CellText: string);
var
  propname:String;
begin
  if Node = nil then
    CellText := ''
  else if Celltext <>'' then
  begin
    propname:=TSOGridColumn(TSOGrid(Sender).Header.Columns[Column]).PropertyName;
    if StrIsOneOf(propname,['local_status_install_date','downloaded_on','file_date','changetime','started_on','finished_on','created_on','updated_on']) then
        CellText := Copy(StrReplaceChar(CellText,'T',' '),1,19)
    else if (propname = 'kbids') then
      CellText := 'KB'+soutils.Join(',KB', CellData)
    else if (CellData <> nil) and (CellData.DataType = stArray) then
      CellText := soutils.Join(',', CellData)
    else if StrIsOneOf(propname,['file_size','download_size','max_download_size','min_download_size','target_size','size','installed_size']) then
    begin
      if CellData.DataType = stInt then
        CellText := FormatFloat('# ### ##0 kB',CellData.AsInteger div 1024)
      else
        CellText := FormatFloat('# ### ##0 kB',StrToInt64(CellText) div 1024);
    end;

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
var
  i: Integer;
begin
  {$ifdef ENTERPRISE}
  {$include ..\waptenterprise\includes\uwaptconsole.setenterprise.inc}

  {$else}
  dmpython.IsEnterpriseEdition:=False;
  LabFilterSite.Visible:=False;
  PanOrgUnits.Visible:=False;
  cbADSite.Visible:=False;
  cbAuthorizedHosts.Visible:=False;
  ActLaunchGPUpdate.Visible:=False;
  ActDisplayUserMessage.Visible:=False;
  ActLaunchWaptExit.Visible:=False;
  ActTISHelp.Visible:=False;
  PgReports.TabVisible := False;
  pgRepositories.TabVisible:=False;
  pgSelfService.TabVisible:=False;
  pgWaptWUAConfig.TabVisible:=False;
  pgHostWUA.TabVisible:=False;
  pgWindowsUpdates.TabVisible:=False;
  ActTriggerHostAudit.Visible:=False;
  ActPackagesAudit.Visible:=False;
  ActWUANewPackage.Visible := False;
  ActSoftwaresNormalization.Visible := False;
  ActAddProfile.Visible:=False;
  SetSOGridVisible(GridHosts,'audit_status',False);
  SetSOGridVisible(GridHosts,'waptwua.status',False);

  SetSOGridEnabled(GridHosts,'audit_status',False);
  SetSOGridEnabled(GridHosts,'waptwua.status',False);

  SetSOGridVisible(GridHostsForPackage,'last_audit_status',False);
  SetSOGridVisible(GridHostsForPackage,'last_audit_status',False);
  SetSOGridVisible(GridHostsForPackage,'last_audit_on',False);
  SetSOGridVisible(GridHostsForPackage,'next_audit_on',False);

  SetSOGridEnabled(GridHostsForPackage,'last_audit_status',False);
  SetSOGridEnabled(GridHostsForPackage,'last_audit_status',False);
  SetSOGridEnabled(GridHostsForPackage,'last_audit_on',False);
  SetSOGridEnabled(GridHostsForPackage,'next_audit_on',False);

  SetSOGridVisible(GridHostPackages,'last_audit_status',False);
  SetSOGridVisible(GridHostPackages,'last_audit_on',False);
  SetSOGridVisible(GridHostPackages,'next_audit_on',False);

  SetSOGridEnabled(GridHostPackages,'last_audit_status',False);
  SetSOGridEnabled(GridHostPackages,'last_audit_on',False);
  SetSOGridEnabled(GridHostPackages,'next_audit_on',False);

  cbAuthorizedHosts.Checked := False;

  CBShowHostsForGroups.Visible := False;

  CBShowHostsForPackages.Visible := False;
  CBShowHostsForGroups.Checked := False;
  CBShowHostsForPackages.Checked := False;

  ActTriggerWaptwua_scan.Visible:=False;
  ActTriggerWaptwua_download.Visible:=False;
  ActTriggerWaptwua_install.Visible:=False;
  ActTriggerWaptwua_uninstall.Visible:=False;

  PanHostsForPackage.Visible:=False;
  {$endif}
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
    CBShowHostsForPackagesClick(Self);
    if GridPackages.Data = nil then
      ActSearchPackage.Execute;
    EdSearchPackage.SetFocus;
  end
  else if MainPages.ActivePage = pgWaptWUAConfig then
  begin
    WUAConfigPages.OnChange(WUAConfigPages);
  end
  else if MainPages.ActivePage = pgSelfService then
  begin
    CopyMenu(PopupMenuPackages, MenuItem24);
    if GridSelfServicePackages.Data = nil then
       ActSelfServiceSearchPackage.Execute;
    EdSelfServiceSearchPackage.SetFocus;
  end
  else if MainPages.ActivePage = pgGroups then
  begin
    CBShowHostsForGroupsClick(Self);
    CopyMenu(PopupMenuGroups, MenuItem24);
    if GridGroups.Data = nil then
      ActSearchGroups.Execute;
    EdSearchGroups.SetFocus;
  end
  else if MainPages.ActivePage = pgWaptWUAConfig then
  begin
    CBShowHostsForWUAPackageClick(Self);
    WUAClassifications;
    WUAProducts;
    if GridWUUpdates.Data = Nil then
      ActWSUSRefresh.Execute
  end
  else if MainPages.ActivePage = PgReports then
  begin
    if not ReportingEditMode then
    begin
      if not Assigned(GridReportingQueries.Data) then
        ActReportingQueryReload.Execute
      else
        ActReportingQueryExecute.Execute;
    end;
  end
  else if MainPages.ActivePage = pgRepositories then
  begin
    if not Assigned(GridRules.Data) then
       ActRepositoriesGetUpdateRules.Execute;
    if not Assigned(GridAgentRepo.Data) then
       ActRepositoriesGetSecondRepos.Execute;
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

procedure TVisWaptGUI.GridPackagesChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  if (MainPages.ActivePage = pgPrivateRepo) and CBShowHostsForPackages.Checked then
    if (GridPackages.FocusedRow <> Nil) then
      CurrentPackageForGridHostsForPackage := UTF8Encode(GridPackages.FocusedRow.S['package'])
    else
      CurrentPackageForGridHostsForPackage := '';
end;

procedure TVisWaptGUI.GridGroupsChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  if (MainPages.ActivePage = pgGroups) and CBShowHostsForGroups.Checked then
    if (GridGroups.FocusedRow <> Nil) then
      CurrentPackageForGridHostsForPackage := UTF8Encode(GridGroups.FocusedRow.S['package'])
    else
      CurrentPackageForGridHostsForPackage := '';
end;

function TVisWaptGUI.IsUpdated(const datasets: array of ISuperObject): Boolean;
var
  ADataset,Rec: ISuperObject;
begin
  Result := False;
  for ADataset in datasets do
  begin
    if ADataset <> Nil then
      for Rec in ADataset do
        if Rec.B['_edited'] then
        begin
          Result := True;
          Exit;
        end;
  end;
end;

function TVisWaptGUI.CheckUpdates(const datasets: array of ISuperObject
  ): Boolean;
var
  res: TModalResult;
begin
  Result := not IsUpdated(datasets);
  if not Result then
  begin
    res := MessageDlg(Format(rsQueryApplyUpdates,[]),mtWarning,mbYesNoCancel, 0);
    if res = mrYes then
      result := ApplyUpdates(datasets)
    else if res=mrCancel then
      Result := False
    else
      Result := True;
  end;
end;


function TVisWaptGUI.ApplyUpdates(const datasets: array of ISuperObject): Boolean;
var
  ADataset: ISuperObject;
begin
  for ADataset in datasets do
    if IsUpdated([ADataset]) then
    begin
      if ADataset = GridReportingQueries.Data then
        ActReportingQuerySaveAll.Execute;
    end;
  result := not IsUpdated(datasets);
end;

procedure TVisWaptGUI.ActTriggerTestLongTaskExecute(Sender: TObject);
begin
  if (GridHosts.SelectedCount>=1) then
    TriggerActionOnHosts(ExtractField(GridHosts.SelectedRows,'uuid'),'trigger_longtask',Nil,'Trigger debug long task','Error triggering longtask %s',True)
end;

procedure TVisWaptGUI.cbFilterPackagesArchItemClick(Sender: TObject;
  Index: integer);
begin
  TimerSearchPackages.Enabled:=False;
  TimerSearchPackages.Enabled:=True;
end;

procedure TVisWaptGUI.cbFilterPackagesLocalesItemClick(Sender: TObject;
  Index: integer);
begin
  TimerSearchPackages.Enabled:=False;
  TimerSearchPackages.Enabled:=True;
end;

procedure TVisWaptGUI.TimerSearchPackagesTimer(Sender: TObject);
begin
  TimerSearchPackages.Enabled:=False;
  ActSearchPackage.Execute;
end;

procedure TVisWaptGUI.TimerSearchHostsTimer(Sender: TObject);
begin
   TimerSearchHosts.Enabled:=False;
   ActSearchHost.execute
end;

procedure TVisWaptGUI.ActVeyonExecute(Sender: TObject);
var
  ip: ansistring;
begin
  if (Gridhosts.FocusedRow <> nil) and
    (Gridhosts.FocusedRow.S['connected_ips'] <> '') then
  begin
    ip := GetReachableIP(Gridhosts.FocusedRow['connected_ips'],11100,2000);
    if ip<>'' then
      ShellExecuteA(0, '', PAnsiChar(GetVeyonPath),PAnsiChar('remoteaccess control ' + ip),
      nil, SW_SHOW)
    else
      ShowMessage(rsNoReachableIP);
  end;
end;

procedure TVisWaptGUI.ActVeyonUpdate(Sender: TObject);
begin
  try
    ActVeyon.Visible := (Gridhosts.FocusedRow <> nil) and
      (Gridhosts.FocusedRow.S['connected_ips'] <> '') and
      FileExistsUTF8(GetVeyonPath);
  except
    ActVeyon.Visible := False;
  end;
end;

function TVisWaptGUI.GetGridHostsPlugins: ISuperObject;
var
  b64: string;
  inifile: TIniFile;
begin
  // external commands list is stored as base64 encoded json in waptconsole.ini file
  if not Assigned(FGridHostsPlugins) then
  begin
    IniFile := TIniFile.Create(waptcommon.AppIniFilename());
    try
      b64 := inifile.readString('global','grid_hosts_plugins', '');
      if b64 <> '' then
         FGridHostsPlugins := SO(DecodeStringBase64(b64))
      else
         FGridHostsPlugins := TSuperObject.Create(stArray);
    finally
      FreeAndNil(iniFile);
    end;
  end;
  Result := FGridHostsPlugins;
end;

procedure TVisWaptGUI.ExecuteHostsGruidPlugin(Sender: TObject);
var
  PluginName: String;
  Executable,ExpandedExecutable: WideString;
  Arguments,ExpandedArguments: WideString;
  host,plugin : ISuperObject;
begin
  PluginName:=(Sender as TMenuItem).Caption;
  for plugin in GridHostsPlugins do
    if plugin.S['name']=UTF8Decode(PluginName) then
    begin
      Executable := plugin.S['executable'];
      Arguments := plugin.S['arguments'];
      break;
    end;

  for host in GridHosts.SelectedRows do
  begin
    ExpandedExecutable:= UTF8Decode(StringsReplace(Executable,
      ['{ip}',                '{uuid}', '{computer_fqdn}'],
      [UTF8Encode(host.A['connected_ips'].S[0]),UTF8Encode(host.S['uuid']),UTF8Encode(host.S['computer_fqdn'])]
      ,[rfReplaceAll]));

    ExpandedArguments:= UTF8Decode(StringsReplace(Arguments,
      ['{ip}',                '{uuid}', '{computer_fqdn}'],
      [UTF8Encode(host.A['connected_ips'].S[0]),UTF8Encode(host.S['uuid']),UTF8Encode(host.S['computer_fqdn'])]
      ,[rfReplaceAll]));

    ShellExecuteW(0,'',PWideChar(ExpandedExecutable),PWideChar(ExpandedArguments),
      Nil, SW_SHOW);
  end;


end;

procedure TVisWaptGUI.PopupMenuHostsPopup(Sender: TObject);
var
  plugin : ISuperObject;
  AMenuItem : TMenuItem;


begin
  if GridHostsPlugins.AsArray.Length = 0 then
     MenuGridHostsPlugins.Visible:=False
  else
  begin
    MenuGridHostsPlugins.Clear;
    MenuGridHostsPlugins.Visible:=True;
    for plugin in GridHostsPlugins do
    begin
      AMenuItem:= TMenuItem.Create(Self);
      AMenuItem.Caption:=UTF8Encode(plugin.S['name']);
      AMenuItem.OnClick:= @ExecuteHostsGruidPlugin ;
      MenuGridHostsPlugins.Add(AMenuItem);
    end;
  end;
end;

procedure TVisWaptGUI.SpeedButton1Click(Sender: TObject);
begin
   HostPages.Hide;
   Panel1.Hide;
end;

procedure TVisWaptGUI.SpeedButton2Click(Sender: TObject);
begin
    Panel5.Hide;
    Splitter4.Hide;
end;

procedure TVisWaptGUI.SpeedButton3Click(Sender: TObject);
begin
    PanelKBLogs.Hide;
    SplitWinupdateHost.Hide;
end;

procedure TVisWaptGUI.SpeedButton4Click(Sender: TObject);
begin
    PanLog.Hide;
    SplitHostTaskLog.Hide;
end;

procedure TVisWaptGUI.SetGridHostsPlugins(AValue: ISuperObject);
begin
  FGridHostsPlugins := AValue;
  if Assigned(MenuGridHostsPlugins) then
    MenuGridHostsPlugins.Clear;
end;

procedure TVisWaptGUI.PagesTasksChange(Sender: TObject);
var
  agrid:TSOGrid;
begin
   case PagesTasks.TabIndex of
        0:agrid:=GridHostTasksPending;
        1:agrid:=GridHostTasksDone;
        2:agrid:=GridHostTasksErrors;
   end;
   PanLog.Visible:=Assigned(agrid.FocusedRow);
   SplitHostTaskLog.Visible:=Assigned(agrid.FocusedRow);
end;

{$ifdef ENTERPRISE}
{$include ..\waptenterprise\includes\uwaptconsole.inc}
{$else}
procedure TVisWaptGUI.GridOrgUnitsGetHint(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex;
  var LineBreakStyle: TVTTooltipLineBreakStyle; var HintText: String);
begin
  ;;
end;


procedure TVisWaptGUI.ActEditOrgUnitPackageExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActEditOrgUnitPackageUpdate(Sender: TObject);
begin
  ActEditOrgUnitPackage.Enabled := False
end;

procedure TVisWaptGUI.ActProprietaryExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.GridOrgUnitsChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  ;;
end;

function TVisWaptGUI.GetSelectedOrgUnits:TDynStringArray;
begin
  ;;
end;

procedure TVisWaptGUI.ActTISHelpExecute(Sender: TObject);
begin
  ;;
end;

function TVisWaptGUI.FilterWinProducts(products: ISuperObject): ISuperObject;
begin
  result := Nil;
end;

function TVisWaptGUI.FilterHostWinUpdates(wua: ISuperObject): ISuperObject;
begin
  Result := Nil;
end;

procedure TVisWaptGUI.GridWinUpdatesGetImageIndexEx(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
  var Ghosted: Boolean; var ImageIndex: Integer; var ImageList: TCustomImageList
  );
begin
  ;;
end;

procedure TVisWaptGUI.GridWinproductsChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  ;;
end;

procedure TVisWaptGUI.FillcbADSiteDropDown;
begin
  ;;
end;

procedure TVisWaptGUI.CBWUProductsShowAllClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.cbWUCriticalClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.cbWUAPendingChange(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.cbADSiteDropDown(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.LoadOrgUnitsTree(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.FilterDBOrgUnits;
begin
  ;;
end;

procedure TVisWaptGUI.SelectOrgUnits(Search: String);
begin
  ;;
end;

procedure TVisWaptGUI.cbADOUSelect(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.cbADSiteSelect(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActPackagesAuditExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActTriggerHostAuditExecute(Sender: TObject);
begin
  ;;
end;

// WSUS
procedure TVisWaptGUI.ActTriggerWaptwua_downloadExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActTriggerWaptwua_installExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActTriggerWaptwua_scanExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActWSUSDowloadWSUSScanExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActWSUSSaveBuildRulesUpdate(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActWUAAddAllowedClassificationExecute(Sender: TObject);
begin
  ;;
end;


procedure TVisWaptGUI.ActWUAAddAllowedUpdateExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActWUAAddForbiddenUpdateExecute(Sender: TObject);
begin
  ;;
end;


procedure TVisWaptGUI.ActWUADownloadSelectedUpdateUpdate(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActWUADownloadSelectedUpdateExecute(Sender: TObject);
begin
  ;;
end;


procedure TVisWaptGUI.ActWUAShowMSUpdatesHelpExecute(Sender: TObject);
begin
  ;;
end;


procedure TVisWaptGUI.ActLaunchGPUpdateExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActLaunchWaptExitExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActRunCleanMgrExecute(Sender: TObject);
begin
  ;;
end;

function TVisWaptGUI.GetWUAClassifications: ISuperObject;
begin
  ;;
end;

function TVisWaptGUI.GetWUAProducts: ISuperObject;
begin
  ;;
end;

function TVisWaptGUI.GetWUAWinUpdates: ISuperObject;
begin
  ;;
end;

procedure TVisWaptGUI.MenuItem103CheckAllClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.MenuItem104Click(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.MenuItem105UncheclAllClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.MenuItemProductsCheckAllClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.SynEditReportsSQLChange(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.TimerWUALoadWinUpdatesTimer(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.WUAConfigPagesChange(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActWSUSRefreshExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActWSUSSaveBuildRulesExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.CBWUClassificationsClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.CBWUProductsClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.cbAllClassificationsClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.cbAllproductsClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.FilterGridWindowsUpdates(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActTriggerUpgradesOrgUnitExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActTriggerUpdateOrgUnitExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.CBShowHostsForGroupsClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.CBShowHostsForPackagesClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActReportingQueryDeleteExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActReportingQueryNewExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActReportingQueryDeleteUpdate(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActReportingQueryExecuteExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActReportingQueryExecuteUpdate(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActReportingQueryExportToExcelExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActReportingQueryExportToExcelUpdate(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActReportingQueryReloadExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.SetGridReportingData(data: ISuperObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActReportingQueryDesignExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActReportingQuerySaveAllExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActReportingQuerySaveAllUpdate(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.SetReportingDirty(Report:ISuperObject);
begin
  ;;
end;


procedure TVisWaptGUI.GridReportingSaveSettings(Report:ISuperObject);
begin
  ;;
end;


procedure TVisWaptGUI.ActReportingQueryDuplicateExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActReportingQueryDuplicateUpdate(Sender: TObject);
begin
  ;;
end;


procedure TVisWaptGUI.GridReportingQueriesKeyPress(Sender: TObject;
  var Key: char);
begin
  ;;
end;

procedure TVisWaptGUI.GridReportingResultSOCompareNodes(Sender: TSOGrid; Node1,
  Node2: ISuperObject; const Columns: array of String; var Result: Integer);
begin
  ;;
end;

function TVisWaptGUI.GridReportingQueriesBeforePaste(Sender: TSOGrid;
  Row: ISuperObject): boolean;
begin
  ;;
end;

procedure TVisWaptGUI.GridReportingQueriesChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  ;;
end;

procedure TVisWaptGUI.GridReportingQueriesDrawText(Sender: TBaseVirtualTree;
  TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
  const AText: String; const CellRect: TRect; var DefaultDraw: Boolean);
begin
  ;;
end;

procedure TVisWaptGUI.GridReportingQueriesEdited(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex);
begin
  ;;
end;

procedure TVisWaptGUI.GridReportingQueriesEditing(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; var Allowed: Boolean);
begin
  ;;
end;

procedure TVisWaptGUI.ActReportingQueryNewUpdate(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActReportingQueryDesignUpdate(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActTriggerWaptwua_scanUpdate(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.GridWUUpdatesNodesDelete(Sender: TSOGrid;
  Nodes: ISuperObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActWUASearchPackageExecute(Sender: TObject);
begin
 ;;
end;

procedure TVisWaptGUI.ActWUAShowDownloadTasksExecute(Sender: TObject);
begin
  ;;
end;


procedure TVisWaptGUI.ActWUANewPackageExecute(Sender: TObject);
begin
;;
end;

procedure TVisWaptGUI.GridWUAPackagesColumnDblClick(Sender: TBaseVirtualTree;
  Column: TColumnIndex; Shift: TShiftState);
begin
;;
end;


procedure TVisWaptGUI.GridWUAPackagesNodesDelete(Sender: TSOGrid;
  Nodes: ISuperObject);
begin
;;
end;

procedure TVisWaptGUI.CBShowHostsForWUAPackageClick(Sender: TObject);
begin
;;
end;

procedure TVisWaptGUI.GridWUAPackagesChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
;;
end;

procedure TVisWaptGUI.CBShowHostsForSelfServicePackageClick(Sender: TObject);
begin
;;
end;

procedure TVisWaptGUI.ActSelfServiceNewPackageExecute(Sender: TObject);
begin
;;
end;

procedure TVisWaptGUI.ActSelfServiceSearchPackageExecute(Sender: TObject);
begin
;;
end;

procedure TVisWaptGUI.ActReportingQueryExportExecute(Sender: TObject);
begin
;;
end;

procedure TVisWaptGUI.ActReportingQueryImportExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActSoftwaresNormalizationExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.GridReportingResultColumnResize(Sender: TVTHeader; Column: TColumnIndex);
begin
  ;;
end;


procedure TVisWaptGUI.GridReportingResultGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; RowData, CellData: ISuperObject; Column: TColumnIndex;
  TextType: TVSTTextType; var CellText: string);
begin
  ;;
end;

procedure TVisWaptGUI.GridReportingResultHeaderClick(Sender: TVTHeader;
  HitInfo: TVTHeaderHitInfo);
begin
;;
end;


procedure TVisWaptGUI.GridReportingResultHeaderDragged(Sender: TVTHeader;
  Column: TColumnIndex; OldPosition: Integer);
begin
;;
end;

procedure TVisWaptGUI.GridReportingResultChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
;;
end;

procedure TVisWaptGUI.GridSelfServicePackagesColumnDblClick(
  Sender: TBaseVirtualTree; Column: TColumnIndex; Shift: TShiftState);
begin
;;
end;

function TVisWaptGUI.FilterHostsForPackage(HostsData:ISuperObject):ISuperObject;
begin
;;
end;

procedure TVisWaptGUI.GridSelfServicePackagesChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
;;
end;

procedure TVisWaptGUI.ActReportingQueryImportUpdate(Sender: TObject);
begin
;;
end;

Function TVisWaptGUI.ReportingQueryAppend(AName:String= 'New query'; sql:String='SELECT 1'): ISuperObject;
begin
;;
end;

procedure TVisWaptGUI.ActTriggerWaptwua_uninstallExecute(Sender: TObject);
begin
;;
end;

procedure TVisWaptGUI.ActRefreshHostsForPackageExecute(Sender: TObject);
begin
;;
end;

procedure TVisWaptGUI.SetCurrentPackageForGridHostsForPackage(AValue: String);
begin
;;
end;

procedure TVisWaptGUI.ActNewRuleExecute(Sender: TObject);
begin
;;
end;

procedure TVisWaptGUI.ActRepositoriesGetUpdateRulesExecute(Sender: TObject);
begin
;;
end;


procedure TVisWaptGUI.ActUpRuleExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActDownRuleExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActEditRuleExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActDeleteRuleExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.GridRulesChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  ;;
end;


procedure TVisWaptGUI.GridRulesDblClick(Sender: TObject);
begin
  ;;
end;

function TVisWaptGUI.DesassociationTranslationCondRules(trans: String): String;
begin
  ;;
end;


function TVisWaptGUI.AssociationTranslationCondRules(origin: String): String;
begin
  ;;
end;

procedure TVisWaptGUI.ActRepositoriesGetSecondReposExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.tbSyncAllClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.tbSyncSelectedClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.tbUpdateFileSyncClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.tbSyncChangelogClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.MenuItemSyncClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.MenuItemSyncForceClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.MenuItemShowErrorsClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.MenuItemCheckFilesClick(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.GridAgentRepoChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  ;;
end;

procedure TVisWaptGUI.GridAgentRepoGetImageIndexEx(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
  var Ghosted: Boolean; var ImageIndex: Integer; var ImageList: TCustomImageList
  );
begin
  ;;
end;

procedure TVisWaptGUI.ActReloadAccountsExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.GridUsersKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  ;;
end;

procedure TVisWaptGUI.GridUsersDrawText(Sender: TBaseVirtualTree;
  TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
  const AText: String; const CellRect: TRect; var DefaultDraw: Boolean);
begin
  ;;
end;

procedure TVisWAPTGUI.ActSaveAccountsExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWAPTGUI.MergeUsersCertificates(Users:ISuperObject);
begin
   ;;
end;

function TVisWaptGUI.MaxSeq: Integer;
begin
    ;;
end;

procedure ActSaveRulesExecute(Sender: TObject);
begin
  ;;
end;

procedure TVisWaptGUI.ActManageUsersExecute(Sender: TObject);
begin
  ;;
end;



{$endif}

end.
