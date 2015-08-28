unit uviswuarules;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ActnList,
  Menus, ExtCtrls, StdCtrls, Buttons, sogrid, uVisWUAGroup;

type

  { TVisWUARules }

  TVisWUARules = class(TForm)
    ActAddADSGroups: TAction;
    ActAddConflicts: TAction;
    ActAddGroup: TAction;
    ActAddPackageGroup: TAction;
    ActAdvancedMode: TAction;
    ActBuildUpload: TAction;
    ActCancelRunningTask: TAction;
    ActChangePassword: TAction;
    ActCleanCache: TAction;
    ActCreateCertificate: TAction;
    ActCreateWaptSetup: TAction;
    ActCreateWaptSetupPy: TAction;
    ActDeleteGroup: TAction;
    ActDeletePackage: TAction;
    ActDeployWapt: TAction;
    ActEditGroup: TAction;
    ActEditHostPackage: TAction;
    ActEditpackage: TAction;
    ActEnglish: TAction;
    ActEvaluate: TAction;
    ActEvaluateVar: TAction;
    ActExecCode: TAction;
    ActForgetPackages: TAction;
    ActFrench: TAction;
    ActGotoHost: TAction;
    ActHelp: TAction;
    ActHostsDelete: TAction;
    ActHostsDeleteHostPackage: TAction;
    ActHostWaptUpgrade: TAction;
    ActImportFromFile: TAction;
    ActImportFromRepo: TAction;
    ActionList1: TActionList;
    ActionsImages: TImageList;
    ActLocalhostInstall: TAction;
    ActLocalhostRemove: TAction;
    ActLocalhostUpgrade: TAction;
    ActPackageInstall: TAction;
    ActPackageRemove: TAction;
    ActPackagesUpdate: TAction;
    actQuit: TAction;
    ActRDP: TAction;
    actRefresh: TAction;
    ActRefreshHostInventory: TAction;
    ActReloadConfig: TAction;
    ActRemoveConflicts: TAction;
    ActRemoveDepends: TAction;
    ActRestoreDefaultLayout: TAction;
    ActSearchGroups: TAction;
    ActSearchHost: TAction;
    ActSearchPackage: TAction;
    ActSearchSoftwares: TAction;
    ActTriggerHostsListening: TAction;
    ActTriggerHostUpdate: TAction;
    ActTriggerHostUpgrade: TAction;
    ActTriggerWaptwua_download: TAction;
    ActTriggerWaptwua_install: TAction;
    ActTriggerWaptwua_scan: TAction;
    ActVNC: TAction;
    ActWAPTLocalConfig: TAction;
    ActWSUSDowloadWSUSScan: TAction;
    ActWSUSRefreshCabHistory: TAction;
    ActWUAAllowSelectedUpdates: TAction;
    ActWUADownloadSelectedUpdate: TAction;
    ActWUAEditGroup: TAction;
    ActWUAForbidSelectedUpdates: TAction;
    ActWUALoadGroups: TAction;
    ActWUALoadUpdates: TAction;
    ActWUANewGroup: TAction;
    ActWUAProductAllow: TAction;
    ActWUAProductAllowSeverity: TAction;
    ActWUAProductForbid: TAction;
    ActWUAProductForbidSeverity: TAction;
    ActWUAProductHide: TAction;
    ActWUAProductShow: TAction;
    ActWUAProductsSelection: TAction;
    ActWUAResetSelectedUpdates: TAction;
    ActWUASaveUpdatesGroup: TAction;
    BitBtn3: TBitBtn;
    BitBtn4: TBitBtn;
    BitBtn5: TBitBtn;
    BitBtn6: TBitBtn;
    BitBtn7: TBitBtn;
    btAddGroup1: TBitBtn;
    btAddGroup2: TBitBtn;
    btAddGroup3: TBitBtn;
    cbWUCritical: TCheckBox;
    cbWUImportant: TCheckBox;
    cbWULow: TCheckBox;
    cbWUModerate: TCheckBox;
    cbWUOther: TCheckBox;
    CBWUProductsShowAll: TCheckBox;
    GridWinproducts: TSOGrid;
    GridWinUpdates: TSOGrid;
    GridWUContent1: TSOGrid;
    ImageList1: TImageList;
    Label17: TLabel;
    MenuItem58: TMenuItem;
    MenuItem59: TMenuItem;
    MenuItem60: TMenuItem;
    MenuItem61: TMenuItem;
    MenuItem63: TMenuItem;
    MenuItem64: TMenuItem;
    MenuItem65: TMenuItem;
    MenuItem66: TMenuItem;
    MenuItem67: TMenuItem;
    MenuItem68: TMenuItem;
    MenuItem69: TMenuItem;
    panbaswinupdates: TPanel;
    Panel1: TPanel;
    Panel13: TPanel;
    Panel15: TPanel;
    Panel16: TPanel;
    Panel17: TPanel;
    Panel8: TPanel;
    PopupWUAProducts: TPopupMenu;
    PopupWUAUpdates: TPopupMenu;
    Splitter6: TSplitter;
    WSUSActions: TActionList;
    wupanright: TPanel;
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisWUARules: TVisWUARules;

implementation

{$R *.lfm}

end.

