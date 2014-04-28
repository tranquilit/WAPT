unit uwaptconsole;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil,
  Forms, Controls, Graphics, Dialogs, ExtCtrls,
  StdCtrls, ComCtrls, ActnList, Menus, superobject,
  VirtualTrees, Windows, ImgList, Buttons, SOGrid, types,ActiveX;

type

  { TVisWaptGUI }

  TVisWaptGUI = class(TForm)
    ActSearchInstalled: TAction;
    ActLocalhostInstall: TAction;
    ActBuildUpload: TAction;
    ActHostSearchPackage: TAction;
    ActHostsAddPackages: TAction;
    ActDeletePackage: TAction;
    actRefresh: TAction;
    actQuit: TAction;
    ActPackageDuplicate: TAction;
    ActRegisterHost: TAction;
    ActLocalhostUpgrade: TAction;
    ActPackagesUpdate: TAction;
    ActLocalhostRemove: TAction;
    ActSearchPackage: TAction;
    ActionList1: TActionList;
    BitBtn1: TBitBtn;
    butSearchPackages: TButton;
    butSearchPackages1: TButton;
    Button1: TButton;
    Button2: TButton;
    Button8: TButton;
    cbShowHostPackagesSoft: TCheckBox;
    cbShowHostPackagesGroup: TCheckBox;
    EdSearch1: TEdit;
    GridInstalled: TSOGrid;
    Label10: TLabel;
    MemoGroupeDescription: TMemo;
    MenuItem18: TMenuItem;
    MenuItem28: TMenuItem;
    MenuItem4: TMenuItem;
    Panel2: TPanel;
    Panel5: TPanel;
    PopupMenuHost: TPopupMenu;
    ProgressBar: TProgressBar;
    EdSearch: TEdit;
    ImageList1: TImageList;
    SOPackages: TSODataSource;
    SOInstalled: TSODataSource;
    Splitter3: TSplitter;
    MainMenu1: TMainMenu;
    MenuItem1: TMenuItem;
    MenuItem10: TMenuItem;
    MenuItem11: TMenuItem;
    MenuItem12: TMenuItem;
    MenuItem13: TMenuItem;
    MenuItem14: TMenuItem;
    MenuItem15: TMenuItem;
    MenuItem16: TMenuItem;
    MenuItem17: TMenuItem;
    MenuItem2: TMenuItem;
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
    MenuItem5: TMenuItem;
    MenuItem6: TMenuItem;
    MenuItem7: TMenuItem;
    MenuItem8: TMenuItem;
    MenuItem9: TMenuItem;
    MainPages: TPageControl;
    Panel4: TPanel;
    PopupMenuPackages: TPopupMenu;
    Splitter1: TSplitter;
    pgPackages: TTabSheet;
    GridPackages: TSOGrid;
    pgInstalledPackages: TTabSheet;
    procedure ActLocalhostInstallExecute(Sender: TObject);
    procedure ActLocalhostRemoveExecute(Sender: TObject);
    procedure ActLocalhostUpgradeExecute(Sender: TObject);
    procedure ActPackagesUpdateExecute(Sender: TObject);
    procedure actQuitExecute(Sender: TObject);
    procedure actRefreshExecute(Sender: TObject);
    procedure ActRegisterHostExecute(Sender: TObject);
    procedure ActSearchInstalledExecute(Sender: TObject);
    procedure ActSearchPackageExecute(Sender: TObject);
    procedure EdSearchKeyPress(Sender: TObject; var Key: char);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure GridPackagesChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
    procedure GridPackagesPaintText(Sender: TBaseVirtualTree;
      const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
      TextType: TVSTTextType);

    procedure MenuItem27Click(Sender: TObject);
  private
    { private declarations }
    function EditIniFile: boolean;
  public
    { public declarations }
    waptpath: string;
  end;

var
  VisWaptGUI: TVisWaptGUI;

implementation

uses LCLIntf, LCLType,IniFiles, tisstrings, soutils,
  waptcommon, tiscommon,uviswaptconfig, uDMLocalWapt,Clipbrd;

{$R *.lfm}

{ TVisWaptGUI }

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
  GridPackages.SaveSettingsToIni(Appuserinipath) ;
end;

procedure TVisWaptGUI.actQuitExecute(Sender: TObject);
begin
  Close;
end;

procedure TVisWaptGUI.ActLocalhostInstallExecute(Sender: TObject);
var
  r,args,res:ISuperObject;
  g:TSOGrid;

begin
  args := SO;
  if GridInstalled.Focused then
    g := GridInstalled
  else if GridPackages.Focused then
    g := GridPackages
  else
    exit;
  for r in g.SelectedRows do
  begin
    args.S['package'] := r.S['package']+'(='+r.S['version']+')';
    if g = GridInstalled then
      args.S['force'] := '1';
    res := SO(DMLocalWapt.LocalWapt.CallServerMethod('GET',['install.json'],args));
  end;
end;

procedure TVisWaptGUI.ActLocalhostRemoveExecute(Sender: TObject);
var
  r,args,res:ISuperObject;
  g:TSOGrid;
begin
  args := SO;
  if GridInstalled.Focused then
    g := GridInstalled
  else if GridPackages.Focused then
    g := GridPackages
  else
    exit;
  for r in g.SelectedRows do
  begin
    args.S['package'] := r.S['package'];
   res := SO(DMLocalWapt.LocalWapt.CallServerMethod('GET',['remove.json'],args));
  end;
end;

procedure TVisWaptGUI.ActLocalhostUpgradeExecute(Sender: TObject);
var
  res,args: ISuperObject;
begin
  args := SO();
  res := SO(DMLocalWapt.LocalWapt.CallServerMethod('GET',['upgrade.json'],args));
end;

procedure TVisWaptGUI.ActPackagesUpdateExecute(Sender: TObject);
var
  res,args: ISuperObject;
begin
  args := SO();
  res := SO(DMLocalWapt.LocalWapt.CallServerMethod('GET',['update.json'],args));
end;

procedure TVisWaptGUI.actRefreshExecute(Sender: TObject);
begin
  Screen.Cursor := crHourGlass;
  try
    if MainPages.ActivePage = pgPackages then
    begin
      ActPackagesUpdate.Execute;
      ActSearchPackage.Execute;
    end
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TVisWaptGUI.ActRegisterHostExecute(Sender: TObject);
var
  res,args: ISuperObject;
begin
  args := SO();
  res := SO(DMLocalWapt.LocalWapt.CallServerMethod('GET',['register.json'],args));
end;

procedure TVisWaptGUI.ActSearchInstalledExecute(Sender: TObject);
begin
  SOInstalled.Refresh;
end;

procedure TVisWaptGUI.ActSearchPackageExecute(Sender: TObject);
begin
  SOPackages.Refresh;
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


procedure TVisWaptGUI.FormShow(Sender: TObject);
begin
  GridPackages.LoadSettingsFromIni(Appuserinipath) ;
end;

procedure TVisWaptGUI.GridPackagesChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  MemoGroupeDescription.Lines.Text:= GridPackages.GetCellStrValue(Node,'description');
end;

function CompareVersion(v1, v2: string): integer;
var
  vtok1, vtok2: string;
begin
  Result := CompareText(v1, v2);
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

procedure TVisWaptGUI.MenuItem27Click(Sender: TObject);
begin
  ShowMessage('Tranquil IT Systems: http://www.tranquil-it-systems.fr/'+#13#10+'Version Waptconsole:'+GetApplicationVersion+#13#10+'Version Wapt-get:'+GetApplicationVersion(WaptgetPath));
end;


end.
