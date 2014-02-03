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
    Label10: TLabel;
    Label11: TLabel;
    Label12: TLabel;
    LabelComputersNumber: TLabel;
    MemoGroupeDescription: TMemo;
    MenuItem28: TMenuItem;
    MenuItem33: TMenuItem;
    MenuItem34: TMenuItem;
    MenuItem35: TMenuItem;
    MenuItem36: TMenuItem;
    MenuItem38: TMenuItem;
    MenuItem40: TMenuItem;
    Panel11: TPanel;
    Panel2: TPanel;
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
    GridhostAttribs: TVirtualJSONInspector;
    GridExternalPackages: TSOGrid;
    ImageList1: TImageList;
    Label1: TLabel;
    pgGroups: TTabSheet;
    Splitter3: TSplitter;
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
    procedure GridHostsDragDrop(Sender: TBaseVirtualTree; Source: TObject;
      DataObject: IDataObject; Formats: TFormatArray; Shift: TShiftState;
      const Pt: TPoint; var Effect: DWORD; Mode: TDropMode);
    procedure GridHostsDragOver(Sender: TBaseVirtualTree; Source: TObject;
      Shift: TShiftState; State: TDragState; const Pt: TPoint; Mode: TDropMode;
      var Effect: DWORD; var Accept: Boolean);
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
    procedure MenuItem27Click(Sender: TObject);
    procedure MainPagesChange(Sender: TObject);
    procedure InstallPackage(Grid: TSOGrid);
  private
    { private declarations }
    procedure GridLoadData(grid: TSOGrid; jsondata: string);
    procedure Login;
    procedure PythonOutputSendData(Sender: TObject; const Data: ansistring);
    procedure TreeLoadData(tree: TVirtualJSONInspector; jsondata: string);
    procedure UpdateHostPages(Sender: TObject);
  public
    { public declarations }
    Hosts, PackageEdited: ISuperObject;
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
  currhost: string;
  attribs, packages, softwares: ISuperObject;
  node: PVirtualNode;
begin
  Node := GridHosts.FocusedNode;
  if Node <> nil then
  begin
    currhost := GridHosts.GetCellStrValue(Node, 'uuid');
    if HostPages.ActivePage = pgPackages then
    begin
      packages := GridHosts.GetNodeSOData(Node)['packages'];
      if (packages = nil) or (packages.AsArray = nil) then
      begin
        packages := WAPTServerJsonGet('client_package_list/%s', [currhost], WaptUseLocalConnectionProxy);
        GridHosts.GetNodeSOData(Node)['packages'] := packages;
      end;
      EdHostname.Text := GridHosts.GetCellStrValue(Node, 'host.computer_name');
      EdDescription.Text := GridHosts.GetCellStrValue(Node, 'host.description');
      EdOS.Text := GridHosts.GetCellStrValue(Node, 'host.windows_product_infos.version');
      EdIPAddress.Text := GridHosts.GetCellStrValue(Node, 'host.connected_ips');
      EdManufacturer.Text := GridHosts.GetCellStrValue(Node, 'host.system_manufacturer');
      EdModelName.Text := GridHosts.GetCellStrValue(Node, 'host.system_productname');
      EdUpdateDate.Text := GridHosts.GetCellStrValue(Node, 'last_query_date');
      EdUser.Text := GridHosts.GetCellStrValue(Node, 'host.current_user');
      EdRunningStatus.Text:=GridHosts.GetCellStrValue(node,'update_status.runstatus');
      GridHostPackages.Data := packages;
    end
    else if HostPages.ActivePage = pgSoftwares then
    begin
      softwares := GridHosts.GetNodeSOData(Node)['softwares'];
      if (softwares = nil) or (softwares.AsArray = nil) then
      begin
        softwares := WAPTServerJsonGet('client_software_list/%s', [currhost],WaptUseLocalConnectionProxy);
        GridHostSoftwares.GetNodeSOData(Node)['softwares'] := softwares;
      end;
      GridHostSoftwares.Data := softwares;
    end
    else if HostPages.ActivePage = pgHostPackage then
    begin
      attribs := GridHosts.GetNodeSOData(Node);
      TreeLoadData(GridhostAttribs, attribs.AsJSon());
    end;
  end
  else
  begin
    GridHostPackages.Clear;
    GridHostSoftwares.Clear;
    GridhostAttribs.Clear;
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
        DMPython.RunJSON(format('mywapt.install("%s")', [package]), jsonlog);
        N := Grid.GetNextSelected(N);
      end;
    finally
      Self.Enabled := True;
      Free;
    end;

end;

procedure TVisWaptGUI.ActLocalhostInstallUpdate(Sender: TObject);
begin
  ActLocalhostInstall.Enabled := GridPackages.SelectedCount > 0;
end;

procedure TVisWaptGUI.ActPackageDuplicateExecute(Sender: TObject);
var
  filename, filenameDepends, oldName, filePath, sourceDir, depends: string;
  uploadResult, dependsList, dependsPath, listPackages: ISuperObject;
  done: boolean = False;
  multiplePackages      :boolean = False;
  i: integer;
  isEncrypt: boolean;
  N: PVirtualNode;

begin

  multiplePackages := GridExternalPackages.SelectedCount > 1;
  if multiplePackages then
  begin
    listPackages := TSuperObject.Create(stArray);
       N := GridExternalPackages.GetFirstSelected;
       while N <> nil do
       begin
            listPackages.AsArray.Add(GridExternalPackages.GetCellStrValue(N, 'package'));
            N := GridExternalPackages.GetNextSelected(N);
       end;

         if MessageDlg('Confirmer la duplication', format('Etes vous sûr de vouloir dupliquer %s dans votre dépot ?', [Join(',', listPackages)]),
         mtConfirmation, mbYesNoCancel, 0) <> mrYes then
         Exit;
       listPackages.Clear();
  end;



  N := GridExternalPackages.GetFirstSelected;
  while N <> nil do
  begin
    oldName := GridExternalPackages.GetCellStrValue(N, 'package');
    filename := GridExternalPackages.GetCellStrValue(N, 'filename');
    depends := GridExternalPackages.GetCellStrValue(N, 'depends');
    filePath := AppLocalDir + 'cache\' + filename;
    if not DirectoryExists(AppLocalDir + 'cache') then
      mkdir(AppLocalDir + 'cache');

    if not multiplePackages then
    begin
    if MessageDlg('Confirmer la duplication', format('Etes vous sûr de vouloir dupliquer %s dans votre dépot ?', [oldName]),
      mtConfirmation, mbYesNoCancel, 0) <> mrYes then
      Exit;

    end;

    with  Tvisloading.Create(Self) do
      try
        Self.Enabled := False;
        ProgressTitle('Téléchargement en cours de ' + oldName);
        Application.ProcessMessages;
        try
          if not FileExists(filePath) then
            Wget(WaptExternalRepo + '/' + filename, filePath, ProgressForm,
            @updateprogress, True);
        except
          ShowMessage('Téléchargement annulé');
          exit;
        end;

        dependsPath := TSuperObject.Create(stArray);
        if depends <> '' then
        begin
          dependsList := DMPython.RunJSON(
            format('waptdevutils.searchLastPackageTisRepo(r"%s".decode(''utf8''),"%s")',
            [AppIniFilename, depends]));
          for i := 0 to dependsList.AsArray.Length - 1 do
          begin
            ProgressTitle(
              'Téléchargement en cours de ' + dependsList.AsArray.S[i]);
            dependsPath.AsArray.Add(AppLocalDir + 'cache\' + dependsList.AsArray.S[i]);
            if not DirectoryExists(AppLocalDir + 'cache') then
              mkdir(AppLocalDir + 'cache');
            try
              if not FileExists(dependsPath.AsArray.S[i]) then
                Wget(WaptExternalRepo + '/' + dependsList.AsArray.S[i],
                  dependsPath.AsArray.S[i], ProgressForm, @updateprogress, True);
            except
              ShowMessage('Téléchargement annulé');
              exit;
            end;
          end;
        end;
        sourceDir := DMPython.RunJSON(
          Format('waptdevutils.duplicate_from_tis_repo(r"%s",r"%s",%S)',
          [AppIniFilename, filePath, dependsPath.AsString])).AsString;

        if sourceDir <> 'error' then
        begin
          if not FileExists(GetWaptPrivateKey) then
          begin
            ShowMessage('la clé privé n''existe pas: ' + GetWaptPrivateKey);
            exit;
          end;
          isEncrypt := StrToBool(DMPython.RunJSON(
            format('waptdevutils.is_encrypt_private_key(r"%s")',
            [GetWaptPrivateKey])).AsString);
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


          ProgressTitle('Upload en cours');
          Application.ProcessMessages;

          uploadResult := DMPython.RunJSON(
            format('mywapt.build_upload(%s,r"%s",r"%s",r"%s",False,True)',
            [sourceDir, privateKeyPassword, waptServerUser, waptServerPassword]),
            jsonlog);
          if uploadResult.AsString <> '' then
          begin
            if not multiplePackages then
               ShowMessage(format('%s dupliqué avec succès.', [oldName]))
            else
              listPackages.AsArray.Add(oldName);
            ActPackagesUpdate.Execute;
          end
          else
            ShowMessage('Erreur lors de la duplication.');

          ModalResult := mrOk;

        end;
      finally
        Self.Enabled := True;
        Free;
      end;
    N := GridExternalPackages.GetNextSelected(N);
  end;
   if multiplePackages then
      ShowMessage(format('%s dupliqué avec succès.', [ Join(',', listPackages)])) ;


  GridExternalPackages.ClearSelection;
  MainPages.ActivePage := pgPrivateRepo;

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
begin
  if GridPackages.FocusedNode<>Nil then
  begin
    Selpackage := GridPackages.GetCellStrValue(GridPackages.FocusedNode, 'package');
    if EditPackage(Selpackage, ActAdvancedMode.Checked) <> nil then
      ActPackagesUpdate.Execute;
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
            DMPython.PythonEng.ExecString('import waptdevutils');
            params := '';
            params := params + format('orgname=r"%s",', [edOrgName.Text]);
            params := params + format('destdir=r"%s",', [DirectoryCert.Directory]);
            params := params + format('country=r"%s".decode(''utf8''),', [edCountry.Text]);
            params := params + format('locality=r"%s".decode(''utf8''),', [edLocality.Text]);
            params := params + format('organization=r"%s".decode(''utf8''),', [edOrganization.Text]);
            params := params + format('unit=r"%s".decode(''utf8''),', [edUnit.Text]);
            params := params + format('commonname=r"%s",', [edCommonName.Text]);
            params := params + format('email=r"%s",', [edEmail.Text]);
            Result := DMPython.RunJSON(
              format('waptdevutils.create_self_signed_key(mywapt,%s)',
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
  Result, groups, host: ISuperObject;
  N:PVirtualNode;
  i: word;
begin
  if GridHosts.Focused then
  begin
    with TvisGroupChoice.Create(self) do
    try
      ActSearchGroupsExecute(self);
      if groupGrid.Data.AsArray.Length = 0 then
      begin
        ShowMessage('Il n''y a aucuns groupes.');
        Exit;
      end;
      if ShowModal = mrOk then
      begin
        groups := TSuperObject.Create(stArray);
        N := groupGrid.GetFirstChecked();
        while N <> nil do
        begin
          groups.AsArray.Add(groupGrid.GetCellStrValue(N, 'package'));
          N := groupGrid.GetNextChecked(N);
        end;
      end;
    finally
      Free;
    end;
    if (groups = nil) or (groups.AsArray.Length = 0) then
      Exit;

    for host in GridHosts.SelectedRows do
      EditHostDepends(host.S['host.computer_fqdn'],
        Join(',', groups));
  end;
end;

procedure TVisWaptGUI.ActAdvancedModeExecute(Sender: TObject);
begin
  ActAdvancedMode.Checked := not ActAdvancedMode.Checked;
  pgSources.TabVisible := ActAdvancedMode.Checked;
  Panel3.Visible := ActAdvancedMode.Checked;
end;

procedure TVisWaptGUI.ActChangePasswordExecute(Sender: TObject);
var
  newPass, Result: string;
begin
  with TvisChangePassword.Create(self) do
    try
      waptServerPassword := uviseditpackage.waptServerPassword;
      if ShowModal = mrOk then
      begin
        newPass := edNewPassword2.Text;
        Result := DMPython.RunJSON(
          format('waptdevutils.login_to_waptserver("%s","%s","%s","%s")',
          [GetWaptServerURL + '/login', waptServerUser, waptServerPassword,
          newPass])).AsString;

        if Result = 'True' then
        begin
          uviseditpackage.waptServerPassword := newPass;
          ShowMessage('Le mot de passe a été changé avec succès !');
        end;
      end;
    finally
      Free;
    end;
end;

procedure TVisWaptGUI.ActCreateWaptSetupExecute(Sender: TObject);
var
  params, waptsetupPath, Result: string;
  done: boolean;
  ini: TIniFile;
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
              with  Tvisloading.Create(Self) do
                try
                  ProgressTitle('Création en cours');
                  Application.ProcessMessages;
                  try
                    waptsetupPath :=
                      DMPython.RunJSON(
                      format('waptdevutils.create_wapt_setup(mywapt,%s)', [params]),
                      jsonlog).AsString;
                    if FileExists(waptsetupPath) then
                    begin
                      ProgressStep(1, 2);
                      ProgressTitle('Dépôt sur le serveur WAPT en cours');
                      Result :=
                        DMPython.RunJSON(format(
                        'waptdevutils.upload_wapt_setup(mywapt,r"%s","%s","%s")',
                        [waptsetupPath, waptServerUser, waptServerPassword])).AsString;
                      if Result = 'ok' then
                        ShowMessage('Waptsetup envoyé avec succès')
                      else
                        ShowMessage('Erreur lors de l''envoie de waptsetup: ' + Result);
                      done := True;
                    end;

                  except
                    ShowMessage('Création annulé');
                  end;
                finally
                  Free;
                end;
              if done then
                Screen.Cursor := crDefault;
              ShowMessage('waptsetup.exe créé avec succès: ' + waptsetupPath);
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
          res := WAPTServerJsonGet('/delete_package/' + group, [],WaptUseLocalConnectionProxy);
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
          res := WAPTServerJsonGet('/delete_package/' + package, [],WaptUseLocalConnectionProxy);
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
  hostname: string;
  Result: ISuperObject;
begin
  hostname := GridHosts.GetCellStrValue(GridHosts.FocusedNode, 'host.computer_fqdn');
  if EditHost(hostname, ActAdvancedMode.Checked) <> nil then
    ActSearchHost.Execute;
end;

procedure TVisWaptGUI.ActGotoHostExecute(Sender: TObject);
begin
  EdSearchHost.SetFocus;
  EdSearchHost.SelectAll;

end;

procedure TVisWaptGUI.ActSearchGroupsExecute(Sender: TObject);
var
  expr, res: UTF8String;
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
  res: string;
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
        WAPTServerJsonGet('/delete_host/' + host.S['uuid'], [],WaptUseLocalConnectionProxy);
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
  expr, res: string;
  package: string;
  i: integer = 0;
  selects: integer;
  N: PVirtualNode;
begin
  if GridPackages.Focused then
  begin
    N := GridPackages.GetFirstSelected;
    selects := GridPackages.SelectedCount;
    with  Tvisloading.Create(Self) do
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
  urlParams: ISuperObject;
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
  hosts := WAPTServerJsonGet(req, [], WaptUseLocalConnectionProxy);
  GridHosts.Data := hosts;
  LabelComputersNumber.Caption := IntToStr(hosts.AsArray.Length);
end;

procedure TVisWaptGUI.ActSearchPackageExecute(Sender: TObject);
var
  expr, res: UTF8String;
  packages: ISuperObject;
  p2: variant;
begin
  //packages := VarPythonEval(Format('"%s".split()',[EdSearch.Text]));
  //packages := MainModule.mywapt.search(VarPythonEval(Format('"%s".split()',[EdSearch.Text])));
  expr := format('mywapt.search(r"%s".decode(''utf8'').split(),section_filter="base")', [EdSearch.Text]);
  packages := DMPython.RunJSON(expr);

  GridPackages.Data := packages;
end;

procedure TVisWaptGUI.ActPackagesUpdateExecute(Sender: TObject);
var
  l, res, i: variant;
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
  expr, res: UTF8String;
  packages: ISuperObject;
begin
  expr := format('waptdevutils.updateTisRepo(r"%s","%s")',
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
  {if not checkReadWriteAccess(ExtractFileDir(WaptDBPath)) then
  begin
    ShowMessage('Vous n''etes pas administrateur de la machine');
    halt;
  end;}
  waptpath := ExtractFileDir(ParamStr(0));
end;

procedure TVisWaptGUI.Login;
var
  done: boolean = False;
  resp: ISuperObject;
  localfn: string;

begin
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

  if waptServerPassword = '' then
  begin
    with TVisLogin.Create(Self) do
      try
        edWaptServerName.Text := GetWaptServerURL;
        repeat
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
                halt;
              end;
            end;
            try
              done := StrToBool(resp.AsString);
              if not done then
                ShowMessage('Mauvais mot de passe');
            except
              ShowMessage(UTF8Encode(resp.AsString));
            end;
          end
          else
            halt;
        until done;
      finally
        Free;
      end;
  end;
end;

procedure TVisWaptGUI.FormShow(Sender: TObject);
begin
  MemoLog.Clear;
  DMPython.WaptConfigFileName := AppIniFilename;
  DMPython.PythonOutput.OnSendData := @PythonOutputSendData;
  ActUpdateWaptGetINIExecute(Self);
  Login;
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
var
  selgroup : String;
  N: PVirtualNode;
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
  propname : String;
  col : TSOGridColumn;
begin
  if (Source = GridhostAttribs) then
  begin
    // drop d'un nouvel attribut
    propname := GridhostAttribs.Path(GridhostAttribs.FocusedNode,0,ttNormal,'.');
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
  if (Source = GridhostAttribs) then
  begin
    propname := GridhostAttribs.Path(GridhostAttribs.FocusedNode,0,ttNormal,'.');
    propname := copy(propname,1,length(propname)-1);

    Accept := (GridHosts.FindColumnByPropertyName(propname)=Nil);
  end;
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
  update_status, upgrades, errors: ISuperObject;
begin
  if GridHosts.Header.Columns[Column].Text='Status' then
  begin
    update_status := GridHosts.GetNodeSOData(Node)['update_status'];
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

procedure TVisWaptGUI.GridHostsGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; RowData, CellData: ISuperObject; Column: TColumnIndex;
  TextType: TVSTTextType; var CellText: string);
var
  update_status,errors,Upgrades : ISuperObject;
begin
  if (CellData <> nil) and (CellData.DataType = stArray) then
    CellText := Join(',', CellData);
  if GridHosts.Header.Columns[Column].Text='Status' then
  begin
    update_status := GridHosts.GetNodeSOData(Node)['update_status'];
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

procedure TVisWaptGUI.HostPagesChange(Sender: TObject);
begin
  UpdateHostPages(Sender);
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
