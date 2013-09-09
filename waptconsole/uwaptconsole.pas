unit uwaptconsole;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, SynHighlighterPython, SynEdit, SynGutterBase,
  SynGutterMarks, SynGutterLineNumber, SynGutterChanges, SynGutter,
  SynGutterCodeFolding, vte_json, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  StdCtrls, ComCtrls, ActnList, Menus, fpJson, jsonparser, superobject,
  UniqueInstance, VirtualTrees, VarPyth, Windows, LMessages, ImgList, SOGrid;

type

  { TVisWaptGUI }

  TVisWaptGUI = class(TForm)
    ActInstall: TAction;
    ActEditpackage: TAction;
    ActExecCode: TAction;
    ActEvaluate: TAction;
    ActBuildUpload: TAction;
    ActCreateCertificate: TAction;
    ActCreateWaptSetup: TAction;
    ActEvaluateVar: TAction;
    ActEditHostPackage: TAction;
    actHostSelectAll: TAction;
    ActAddRemoveOptionIniFile: TAction;
    ActHostSearchPackage: TAction;
    ActHostsAddPackages: TAction;
    ActHostsCopy: TAction;
    ActHostsDelete: TAction;
    ActDeletePackage: TAction;
    ActAdvancedMode: TAction;
    ActChangePassword: TAction;
    ActGotoHost: TAction;
    Action1: TAction;
    ActWAPTLocalConfig: TAction;
    ActUpdateWaptGetINI: TAction;
    actRefresh: TAction;
    actQuit: TAction;
    ActPackageGroupAdd: TAction;
    ActPackageDuplicate: TAction;
    ActRegisterHost: TAction;
    ActSearchHost: TAction;
    ActUpgrade: TAction;
    ActUpdate: TAction;
    ActRemove: TAction;
    ActSearchPackage: TAction;
    ActionList1: TActionList;
    butInitWapt: TButton;
    butRun: TButton;
    butSearchPackages: TButton;
    butSearchPackages1: TButton;
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
    ProgressBar: TProgressBar;
    Edit1: TEdit;
    Edit2: TEdit;
    Edit3: TEdit;
    Edit4: TEdit;
    Edit5: TEdit;
    Edit6: TEdit;
    Edit7: TEdit;
    Edit8: TEdit;
    EdSearch1: TEdit;
    EdSearchHost: TEdit;
    EdRun: TEdit;
    EdSearch: TEdit;
    GridHosts: TSOGrid;
    GridhostAttribs: TVirtualJSONInspector;
    GridPackages1: TSOGrid;
    ImageList1: TImageList;
    Label1: TLabel;
    urlExternalRepo: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    Label6: TLabel;
    Label7: TLabel;
    Label8: TLabel;
    Label9: TLabel;
    LabHostCnt: TLabel;
    LabHostCnt1: TLabel;
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
    MenuItem19: TMenuItem;
    MenuItem2: TMenuItem;
    MenuItem20: TMenuItem;
    MenuItem21: TMenuItem;
    MenuItem22: TMenuItem;
    MenuItem23: TMenuItem;
    MenuItem24: TMenuItem;
    MenuItem25: TMenuItem;
    MenuItem26: TMenuItem;
    MenuItem27: TMenuItem;
    MenuItem28: TMenuItem;
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
    PageControl1: TPageControl;
    HostPages: TPageControl;
    Panel1: TPanel;
    Panel10: TPanel;
    Panel3: TPanel;
    Panel4: TPanel;
    Panel5: TPanel;
    Panel6: TPanel;
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
    TabSheet1: TTabSheet;
    pgPrivateRepo: TTabSheet;
    pgInventory: TTabSheet;
    pgPackages: TTabSheet;
    pgSoftwares: TTabSheet;
    pgHostPackage: TTabSheet;
    pgTISRepo: TTabSheet;
    testedit: TSynEdit;
    jsonlog: TVirtualJSONInspector;
    UniqueInstance1: TUniqueInstance;
    GridPackages: TSOGrid;
    GridHostPackages: TSOGrid;
    GridHostSoftwares: TSOGrid;
    procedure ActAddRemoveOptionIniFileExecute(Sender: TObject);
    procedure ActAdvancedModeExecute(Sender: TObject);
    procedure ActChangePasswordExecute(Sender: TObject);
    procedure ActCreateCertificateExecute(Sender: TObject);
    procedure ActCreateWaptSetupExecute(Sender: TObject);
    procedure ActDeletePackageExecute(Sender: TObject);
    procedure ActDeletePackageUpdate(Sender: TObject);
    procedure ActEditHostPackageExecute(Sender: TObject);
    procedure ActGotoHostExecute(Sender: TObject);
    procedure ActPackageEdit(Sender: TObject);
    procedure ActEditpackageUpdate(Sender: TObject);
    procedure ActEvaluateExecute(Sender: TObject);
    procedure ActExecCodeExecute(Sender: TObject);
    procedure ActHostsCopyExecute(Sender: TObject);
    procedure ActHostsDeleteExecute(Sender: TObject);
    procedure actHostSelectAllExecute(Sender: TObject);
    procedure ActInstallExecute(Sender: TObject);
    procedure ActInstallUpdate(Sender: TObject);
    procedure ActPackageDuplicateExecute(Sender: TObject);
    procedure ActPackageGroupAddExecute(Sender: TObject);
    procedure actQuitExecute(Sender: TObject);
    procedure actRefreshExecute(Sender: TObject);
    procedure ActRegisterHostExecute(Sender: TObject);
    procedure ActRemoveExecute(Sender: TObject);
    procedure ActRemoveUpdate(Sender: TObject);
    procedure ActSearchHostExecute(Sender: TObject);
    procedure ActSearchPackageExecute(Sender: TObject);
    procedure ActUpdateExecute(Sender: TObject);
    procedure ActUpdateWaptGetINIExecute(Sender: TObject);
    procedure ActUpgradeExecute(Sender: TObject);
    procedure ActWAPTLocalConfigExecute(Sender: TObject);
    procedure butSearchPackages1Click(Sender: TObject);
    procedure Button4Click(Sender: TObject);
    procedure Button5Click(Sender: TObject);
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
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure GridHostPackagesGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: boolean; var ImageIndex: integer;
      var ImageList: TCustomImageList);
    procedure GridHostsFocusChanged(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Column: TColumnIndex);
    procedure GridHostsGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: boolean; var ImageIndex: integer;
      var ImageList: TCustomImageList);
    procedure GridPackagesPaintText(Sender: TBaseVirtualTree;
      const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
      TextType: TVSTTextType);

    procedure HostPagesChange(Sender: TObject);
    procedure MenuItem27Click(Sender: TObject);
    procedure PageControl1Change(Sender: TObject);
    function updateprogress(current, total: integer): boolean;
    procedure stopDownload(bool: boolean);

  private
    { private declarations }
    downloadStopped: boolean;
    procedure GridLoadData(grid: TSOGrid; jsondata: string);
    procedure PythonOutputSendData(Sender: TObject; const Data: ansistring);
    procedure TreeLoadData(tree: TVirtualJSONInspector; jsondata: string);
    procedure UpdateHostPages(Sender: TObject);
  public
    { public declarations }
    Hosts, PackageEdited: ISuperObject;
    waptpath: string;
  end;

var
  VisWaptGUI: TVisWaptGUI;

implementation

uses LCLIntf, IniFiles, uvisprivatekeyauth, uvisloading, tisstrings, soutils,
  waptcommon, tiscommon, uVisCreateKey, uVisCreateWaptSetup, uvisOptionIniFile,
  dmwaptpython, uviseditpackage, uvispassword, uviswaptconfig,uvischangepassword;

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
    butSearchPackages1.Click;
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

procedure TVisWaptGUI.UpdateHostPages(Sender: TObject);
var
  currhost: string;
  attribs, packages, softwares: ISuperObject;
  node: PVirtualNode;
begin
  LabHostCnt.Caption := format('Nombre d''enregistrements : %d',
    [GridHosts.SelectedCount]);
  Node := GridHosts.FocusedNode;
  if Node <> nil then
  begin
    currhost := GridHosts.GetColumnValue(Node, 'uuid');
    if HostPages.ActivePage = pgPackages then
    begin
      packages := GridHosts.GetData(Node)['packages'];
      if (packages = nil) or (packages.AsArray = nil) then
      begin
        packages := WAPTServerJsonGet('client_package_list/%s', [currhost]);
        GridHosts.GetData(Node)['packages'] := packages;
      end;
      Edit1.Text := GridHosts.GetColumnValue(Node, 'host.computer_name');
      Edit2.Text := GridHosts.GetColumnValue(Node, 'host.description');
      Edit3.Text := GridHosts.GetColumnValue(Node, 'host.windows_product_infos.version');
      Edit4.Text := GridHosts.GetColumnValue(Node, 'host.connected_ips');
      Edit5.Text := GridHosts.GetColumnValue(Node, 'host.system_manufacturer');
      Edit6.Text := GridHosts.GetColumnValue(Node, 'host.system_productname');
      Edit7.Text := GridHosts.GetColumnValue(Node, 'last_query_date');
      Edit8.Text := GridHosts.GetColumnValue(Node, 'host.current_user');
      GridHostPackages.Data := packages;
      GridHostPackages.Header.AutoFitColumns(False);
    end
    else if HostPages.ActivePage = pgSoftwares then
    begin
      softwares := GridHosts.GetData(Node)['softwares'];
      if (softwares = nil) or (softwares.AsArray = nil) then
      begin
        softwares := WAPTServerJsonGet('client_software_list/%s', [currhost]);
        GridHostSoftwares.GetData(Node)['softwares'] := softwares;
      end;
      GridHostSoftwares.Data := softwares;
      GridHostSoftwares.Header.AutoFitColumns(False);
    end
    else if HostPages.ActivePage = pgHostPackage then
    begin
      attribs := GridHosts.GetData(Node);
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

procedure TVisWaptGUI.ActInstallExecute(Sender: TObject);
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
        while N <> nil do
        begin
          package := GridPackages.GetColumnValue(N, 'package') +
            ' (=' + GridPackages.GetColumnValue(N, 'version') + ')';
          Chargement.Caption :=
            'Installation de ' + GridPackages.GetColumnValue(N, 'package') +
            ' en cours ...';
          ProgressBar1.Position := trunc((i / selects) * 100);
          Application.ProcessMessages;
          i := i + 1;
          DMPython.RunJSON(format('mywapt.install("%s")', [package]), jsonlog);
          N := GridPackages.GetNextSelected(N);
        end;
      finally
        Free;
      end;
    ActSearchPackage.Execute;
  end;
end;

procedure TVisWaptGUI.ActInstallUpdate(Sender: TObject);
begin
  ActInstall.Enabled := GridPackages.SelectedCount > 0;
end;

procedure TVisWaptGUI.ActPackageDuplicateExecute(Sender: TObject);
var
  filename, filenameDepends, oldName, filePath, sourceDir, depends: string;
  uploadResult, dependsList, dependsPath: ISuperObject;
  done: boolean = False;
  i: integer;
  isEncrypt: boolean;
  Load: Tvisloading;
  N: PVirtualNode;

begin

  N := GridPackages1.GetFirstSelected;
  while N <> nil do
  begin
    oldName := GridPackages1.GetColumnValue(N, 'package');
    filename := GridPackages1.GetColumnValue(N, 'filename');
    depends := GridPackages1.GetColumnValue(N, 'depends');
    filePath := waptpath + '\cache\' + filename;

    if MessageDlg('Confirmer la duplication',
      format('Etes vous sûr de vouloir dupliquer %s dans votre dépot ?', [oldName]),
      mtConfirmation, mbYesNoCancel, 0) <> mrYes then
      Exit;

    with  Tvisloading.Create(Self) do
      try
        Chargement.Caption := 'Téléchargement en cours de ' + oldName;
        ProgressBar := ProgressBar1;
        downloadStopped := False;
        Application.ProcessMessages;
        try
          if not FileExists(filePath) then
            Wget(WaptExternalRepo + '/' + filename, filePath, @updateprogress);
        except
          ShowMessage('Téléchargement annulé');
          exit;
        end;

        dependsPath := TSuperObject.Create(stArray);
        if depends <> '' then
        begin
          dependsList := DMPython.RunJSON(
            format('waptdevutils.searchLastPackageTisRepo(r"%s","%s")',
            [waptpath + '\wapt-get.ini', depends]));
          for i := 0 to dependsList.AsArray.Length - 1 do
          begin
            chargement.Caption :=
              'Téléchargement en cours de ' + dependsList.AsArray.S[i];
            dependsPath.AsArray.Add(waptpath + '\cache\' + dependsList.AsArray.S[i]);

            try
              if not FileExists(dependsPath.AsArray.S[i]) then
                Wget(WaptExternalRepo + '/' + dependsList.AsArray.S[i],
                  dependsPath.AsArray.S[i], @updateprogress);
            except
              ShowMessage('Téléchargement annulé');
              exit;
            end;
          end;
        end;
        sourceDir := DMPython.RunJSON(
          Format('waptdevutils.duplicate_from_tis_repo(r"%s",r"%s",%S)',
          [waptpath + '\wapt-get.ini', filePath, dependsPath.AsString])).AsString;

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


          Chargement.Caption := 'Upload en cours';
          Application.ProcessMessages;

          uploadResult := DMPython.RunJSON(
            format('mywapt.build_upload(%s,r"%s",r"%s",r"%s","False","True")',
            [sourceDir, privateKeyPassword, waptServerUser, waptServerPassword]),
            jsonlog);
          if uploadResult.AsString <> '' then
          begin
            ShowMessage(format('%s dupliqué avec succès.', [oldName]));
            ActUpdate.Execute;
          end
          else
            ShowMessage('Erreur lors de la duplication.');

          ModalResult := mrOk;

        end;
      finally
        Free;
      end;
    N := GridPackages1.GetNextSelected(N);
  end;

  GridPackages1.ClearSelection;
  PageControl1.ActivePage := pgPrivateRepo;

end;

procedure TVisWaptGUI.ActPackageGroupAddExecute(Sender: TObject);
begin
  CreatePackage('agroup', ActAdvancedMode.Checked);
  ActUpdate.Execute;

end;

procedure TVisWaptGUI.actQuitExecute(Sender: TObject);
begin
  Close;
end;

procedure TVisWaptGUI.actRefreshExecute(Sender: TObject);
begin
  Screen.Cursor := crHourGlass;
  try
    ActSearchHost.Execute;
    ActSearchPackage.Execute;

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
  expr, res, depends, dep: string;
  Selpackage: string;
  Result: ISuperObject;
  N: PVirtualNode;
begin
  if GridPackages.Focused then
  begin
    N := GridPackages.GetFirstSelected;
    Selpackage := GridPackages.GetColumnValue(N, 'package');
    if EditPackage(Selpackage, ActAdvancedMode.Checked) <> nil then
      ActSearchPackage.Execute;
  end;
end;

procedure TVisWaptGUI.ActEditpackageUpdate(Sender: TObject);
begin
  ActEditpackage.Enabled := GridPackages.SelectedCount > 0;
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
            params := params + format('country=r"%s",', [edCountry.Text]);
            params := params + format('locality=r"%s",', [edLocality.Text]);
            params := params + format('organization=r"%s",', [edOrganization.Text]);
            params := params + format('unit=r"%s",', [edUnit.Text]);
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

              with TINIFile.Create(WaptIniFilename) do
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

procedure TVisWaptGUI.ActAdvancedModeExecute(Sender: TObject);
begin
  ActAdvancedMode.Checked := not ActAdvancedMode.Checked;
  TabSheet1.TabVisible := ActAdvancedMode.Checked;
  Panel3.Visible := ActAdvancedMode.Checked;
  if TabSheet1.TabVisible then
    PageControl1.ActivePage := TabSheet1;
end;

procedure TVisWaptGUI.ActChangePasswordExecute(Sender: TObject);
var
  newPass, result: string;
begin
  with TvisChangePassword.Create(self)  do
    try
      waptServerPassword := uviseditpackage.waptServerPassword;
      if ShowModal=mrOK then
      begin
        newPass:= edNewPassword2.Text;
        result := DMPython.RunJSON(
          format('waptdevutils.login_to_waptserver("%s","%s","%s","%s")',
          [GetWaptServerURL + '/login', waptServerUser, waptServerPassword,
          newPass])).AsString;
          waptServerPassword:= newPass;
          if result = 'True' then
             ShowMessage('Le mot de passe a été changé avec succès !');
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
begin
  with TVisCreateWaptSetup.Create(self) do
    try
      ini := TIniFile.Create(WaptIniFilename);
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
              DMPython.PythonEng.ExecString('import waptdevutils');
              params := '';
              params := params + format('default_public_cert=r"%s",',
                [fnPublicCert.FileName]);
              params := params + format('default_repo_url=r"%s",', [edRepoUrl.Text]);
              params := params + format('default_wapt_server=r"%s",',
                [edWaptServerUrl.Text]);
              params := params + format('destination=r"%s",',
                [fnWaptDirectory.Directory]);
              params := params + format('company=r"%s",', [edOrgName.Text]);
              waptsetupPath :=
                DMPython.RunJSON(format('waptdevutils.create_wapt_setup(mywapt,%s)',
                [params]), jsonlog).AsString;
              done := FileExists(waptsetupPath);
              if done then
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

      finally
        ini.Free;
      end;
    finally
      Free;
    end;
end;

procedure TVisWaptGUI.ActDeletePackageExecute(Sender: TObject);
var
  expr: string;
  res: ISuperObject;
  package: string;
  i: integer;
  N: PVirtualNode;
begin
  if MessageDlg('Confirmer la suppression',
    'Etes vous sûr de vouloir supprimer ce(s) package(s) du serveur ?',
    mtConfirmation, mbYesNoCancel, 0) = mrYes then
  begin
    N := GridPackages.GetFirstSelected;
    while N <> nil do
    begin
      package := GridPackages.GetColumnValue(N, 'filename');
      res := WAPTServerJsonGet('/delete_package/' + package, []);
      if not ObjectIsNull(res['error']) then
        raise Exception.Create(res.S['error']);
      N := GridPackages.GetNextSelected(N);
    end;
    ActUpdate.Execute;
    ActSearchPackage.Execute;
  end;
end;

procedure TVisWaptGUI.ActDeletePackageUpdate(Sender: TObject);
begin
  ActDeletePackage.Enabled := GridPackages.SelectedCount > 0;
end;

procedure TVisWaptGUI.ActEditHostPackageExecute(Sender: TObject);
var
  hostname: string;
  Result: ISuperObject;
begin
  hostname := GridHosts.GetColumnValue(GridHosts.FocusedNode, 'host.computer_fqdn');
  if EditHost(hostname, ActAdvancedMode.Checked) <> nil then
    ActSearchHost.Execute;
end;

procedure TVisWaptGUI.ActGotoHostExecute(Sender: TObject);
begin
  EdSearchHost.SetFocus;
  EdSearchHost.SelectAll;

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
begin
  GridHosts.CopyToClipBoard;
end;

procedure TVisWaptGUI.ActHostsDeleteExecute(Sender: TObject);
var
  expr, res: string;
  host: string;
  i: integer;
  N: PVirtualNode;
begin
  if GridHosts.Focused then
  begin
    N := GridHosts.GetFirstSelected;
    while N <> nil do
    begin
      host := GridHosts.GetColumnValue(N, 'uuid');
      WAPTServerJsonGet('/delete_host/' + host, []).AsJson;
      N := GridHosts.GetNextSelected(N);
    end;
    ActSearchHost.Execute;
  end;
end;

procedure TVisWaptGUI.actHostSelectAllExecute(Sender: TObject);
begin
  TSOGrid(GridHosts).SelectAll(False);
end;

procedure TVisWaptGUI.ActRemoveExecute(Sender: TObject);
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
        while N <> nil do
        begin
          package := GridPackages.GetColumnValue(N, 'package');
          Chargement.Caption := 'Désinstallation de ' + package + ' en cours ...';
          ProgressBar1.Position := trunc((i / selects) * 100);
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

procedure TVisWaptGUI.ActRemoveUpdate(Sender: TObject);
begin
  ActRemove.Enabled := GridPackages.SelectedCount > 0;
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

  hosts := WAPTServerJsonGet(req, []);
  GridHosts.Data := hosts;
end;

procedure TVisWaptGUI.ActSearchPackageExecute(Sender: TObject);
var
  expr, res: UTF8String;
  packages: ISuperObject;
begin
  expr := format('mywapt.search("%s".split())', [EdSearch.Text]);
  packages := DMPython.RunJSON(expr);
  GridPackages.Data := packages;
end;

procedure TVisWaptGUI.ActUpdateExecute(Sender: TObject);
var
  res: variant;
begin
  res := MainModule.mywapt.update(NOARGS);
  ActSearchPackageExecute(Sender);
end;

procedure TVisWaptGUI.ActUpdateWaptGetINIExecute(Sender: TObject);
begin
  DMPython.RunJSON('mywapt.load_config()', jsonlog);
  urlExternalRepo.Caption := 'Url: ' + WaptExternalRepo;
end;

procedure TVisWaptGUI.ActUpgradeExecute(Sender: TObject);
begin
  DMPython.RunJSON('mywapt.upgrade()', jsonlog);
end;

procedure TVisWaptGUI.ActWAPTLocalConfigExecute(Sender: TObject);
var
  inifile: TIniFile;
begin
  inifile := TIniFile.Create(WaptIniFilename);
  try

    with TVisWAPTConfig.Create(self) do
      try
        //wapt := VarPyth.VarPythonEval('mywapt') ;
        //conf := wapt.config;

        edrepo_url.Text := inifile.ReadString('global', 'repo_url', '');
        edhttp_proxy.Text := inifile.ReadString('global', 'proxy_http', '');
        //edrepo_url.text := VarPythonAsString(conf.get('global','repo_url'));
        eddefault_package_prefix.Text :=
          inifile.ReadString('global', 'default_package_prefix', '');
        edwapt_server.Text := inifile.ReadString('global', 'wapt_server', '');
        eddefault_sources_root.Text :=
          inifile.ReadString('global', 'default_sources_root', '');
        edprivate_key.Text := inifile.ReadString('global', 'private_key', '');
        edtemplates_repo_url.Text :=
          inifile.readString('global', 'templates_repo_url', '');
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
          //inifile.WriteString('global','default_sources_url',eddefault_sources_url.text);
          ActUpdateWaptGetINI.Execute;
          ActUpdate.Execute;
        end;
      finally
        Free;
      end;

  finally
    inifile.Free;
  end;
end;

procedure TVisWaptGUI.butSearchPackages1Click(Sender: TObject);
var
  expr, res: UTF8String;
  packages: ISuperObject;
begin
  expr := format('waptdevutils.updateTisRepo(r"%s","%s")',
    [waptpath + '\wapt-get.ini', EdSearch1.Text]);
  packages := DMPython.RunJSON(expr);
  GridPackages1.Data := packages;
end;

procedure TVisWaptGUI.Button4Click(Sender: TObject);
begin
  with  Tvisloading.Create(Self) do
    try
      ProgressBar := ProgressBar1;
      Chargement.Caption := 'Téléchargement en cours';
      downloadStopped := False;
      try
        Wget('http://wapt/wapt/tis-libreoffice_4.0.4-0_all.wapt',
          'c:\tmp\lo.zip', @updateprogress);
      except
        ShowMessage('Téléchargement annulé')
      end;

    finally
      ProgressBar.Free;
      Free;
    end;
end;

procedure TVisWaptGUI.Button5Click(Sender: TObject);
begin
  downloadStopped := True;
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
var
  done: boolean = False;
  resp: ISuperObject;

begin
  if not checkReadWriteAccess(ExtractFileDir(WaptDBPath)) then
  begin
    ShowMessage('Vous n''etes pas administrateur de la machine');
    halt;
  end;

  waptpath := ExtractFileDir(ParamStr(0));

  DMPython.WaptConfigFileName := waptpath + '\wapt-get.ini';
  DMPython.PythonOutput.OnSendData := @PythonOutputSendData;

  ActUpdateWaptGetINIExecute(Self);

  MemoLog.Clear;

  PageControl1.ActivePage := pgInventory;
  if waptServerPassword = '' then
  begin
    with TVisPassword.Create(Self) do
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

  urlExternalRepo.Caption := 'Url: ' + WaptExternalRepo;

end;

procedure TVisWaptGUI.FormShow(Sender: TObject);
begin
  PageControl1Change(Sender);
end;

procedure TVisWaptGUI.GridHostPackagesGetImageIndexEx(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
  var Ghosted: boolean; var ImageIndex: integer; var ImageList: TCustomImageList);
var
  install_status: ISuperObject;
begin
  if Column = 0 then
  begin
    install_status := GridHostPackages.GetData(Node)['install_status'];
    if (install_status <> nil) then
    begin
      case install_status.AsString of
        'OK': ImageIndex := 0;
        'ERROR': ImageIndex := 2;
        'UPGRADE': ImageIndex := 1;
      end;
    end;
  end;
end;

procedure TVisWaptGUI.GridHostsFocusChanged(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex);
begin
  UpdateHostPages(Sender);
end;

procedure TVisWaptGUI.GridLoadData(grid: TSOGrid; jsondata: string);
begin
  if (jsondata <> '') then
    try
      Grid.JSonData := jsondata;
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
  if Column = 0 then
  begin
    update_status := GridHosts.GetData(Node)['update_status'];
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
  if StrIsOneOf(GridPackages.GetColumnValue(Node, 'status'), ['I', 'U']) then
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
  ShowMessage('Tranquil IT Systems: http://www.tranquil-it-systems.fr/');
end;

procedure TVisWaptGUI.stopDownload(bool: boolean);
begin
  downloadStopped := bool;
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

procedure TVisWaptGUI.PageControl1Change(Sender: TObject);
begin
  if PageControl1.ActivePage = pgInventory then
  begin
    CopyMenu(PopupMenuHosts, MenuItem24);
    if GridHosts.Data = nil then
      ActSearchHost.Execute;
  end
  else if PageControl1.ActivePage = pgPrivateRepo then
  begin
    CopyMenu(PopupMenuPackages, MenuItem24);
    if GridPackages.Data = nil then
      ActSearchPackage.Execute;
  end
  else if PageControl1.ActivePage = pgTISRepo then
  begin
    CopyMenu(PopupMenuPackagesTIS, MenuItem24);
    if GridPackages1.Data = nil then
      butSearchPackages1.Click;
  end;
end;

function TVisWaptGUI.updateprogress(current, total: integer): boolean;
begin

  ProgressBar.Max := total;
  ProgressBar.Position := current;
  Application.ProcessMessages;
  Result := not downloadStopped;
end;

end.
