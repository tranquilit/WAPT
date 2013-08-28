unit uwaptconsole;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, SynHighlighterPython, SynEdit,
  vte_json, Forms,
  Controls, Graphics, Dialogs, ExtCtrls, StdCtrls, ComCtrls, ActnList, Menus, fpJson, jsonparser, superobject,
  UniqueInstance, VirtualTrees, VarPyth, Windows, LMessages, ImgList;

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
    Button6: TButton;
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
    GridHosts: TVirtualJSONListView;
    GridhostAttribs: TVirtualJSONInspector;
    GridPackages1: TVirtualJSONListView;
    ImageList1: TImageList;
    Label1: TLabel;
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
    GridPackages: TVirtualJSONListView;
    GridHostPackages: TVirtualJSONListView;
    GridHostSoftwares: TVirtualJSONListView;
    procedure ActAddRemoveOptionIniFileExecute(Sender: TObject);
    procedure ActAdvancedModeExecute(Sender: TObject);
    procedure ActChangePasswordExecute(Sender: TObject);
    procedure ActCreateCertificateExecute(Sender: TObject);
    procedure ActCreateWaptSetupExecute(Sender: TObject);
    procedure ActDeletePackageExecute(Sender: TObject);
    procedure ActDeletePackageUpdate(Sender: TObject);
    procedure ActEditHostPackageExecute(Sender: TObject);
    procedure ActPackageEdit(Sender: TObject);
    procedure ActEditpackageUpdate(Sender: TObject);
    procedure ActEvaluateExecute(Sender: TObject);
    procedure ActEvaluateVarExecute(Sender: TObject);
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
    procedure butSearchPackages1Click(Sender: TObject);
    procedure cbSearchAllChange(Sender: TObject);
    procedure cbShowLogClick(Sender: TObject);
    procedure CheckBoxMajChange(Sender: TObject);
    procedure CheckBoxMajClick(Sender: TObject);
    procedure CheckBox_errorChange(Sender: TObject);
    procedure EdRunKeyPress(Sender: TObject; var Key: char);
    procedure EdSearch1KeyPress(Sender: TObject; var Key: char);
    procedure EdSearchHostKeyPress(Sender: TObject; var Key: char);
    procedure EdSearchKeyPress(Sender: TObject; var Key: char);
    procedure FormCreate(Sender: TObject);
    procedure GridHostsChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
    procedure GridHostsGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: boolean; var ImageIndex: integer;
      var ImageList: TCustomImageList);
    procedure GridHostsGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Data: TJSONData; Column: TColumnIndex; TextType: TVSTTextType;
      var CellText: string);
    procedure GridPackagesCompareNodes(Sender: TBaseVirtualTree;
      Node1, Node2: PVirtualNode; Column: TColumnIndex; var Result: integer);
    procedure GridPackagesHeaderClick(Sender: TVTHeader; HitInfo: TVTHeaderHitInfo);
    procedure GridPackagesPaintText(Sender: TBaseVirtualTree;
      const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
      TextType: TVSTTextType);

    procedure HostPagesChange(Sender: TObject);
    procedure MenuItem27Click(Sender: TObject);
    procedure PageControl1Change(Sender: TObject);
  private
    { private declarations }
    procedure GridLoadData(grid: TVirtualJSONListView; jsondata: string);
    procedure PythonOutputSendData(Sender: TObject; const Data: ansistring);
    procedure TreeLoadData(tree: TVirtualJSONInspector; jsondata: string);
    procedure UpdateHostPages(Sender: TObject);
  public
    { public declarations }
    PackageEdited: ISuperObject;
    waptpath: string;
  end;

function isAdvancedMode: boolean;

var
  VisWaptGUI: TVisWaptGUI;

implementation

uses LCLIntf, IniFiles, uvisprivatekeyauth, uvisloading, tisstrings, soutils, waptcommon,
  uVisCreateKey, uVisCreateWaptSetup,
  uvisOptionIniFile, dmwaptpython, uviseditpackage, uvispassword;

{$R *.lfm}

{ TVisWaptGUI }

function GetValue(ListView: TVirtualJSONListView; N: PVirtualNode;
  FieldName: string; Default: string = ''): string;
var
  js: ISuperObject;
begin
  js := SO(ListView.GetData(N).AsJSON);
  if js <> nil then
  begin
    if FieldName = '' then
      Result := js.AsJSon
    else
      Result := js.S[FieldName];
  end
  else
    Result := Default;
end;

function GetGridSOValue(ListView: TVirtualJSONListView; N: PVirtualNode;
  FieldName: string): ISuperObject;
var
  js: ISuperObject;
begin
  js := SO(ListView.GetData(N).AsJSON);
  if js <> nil then
  begin
    if FieldName = '' then
      Result := js
    else
      Result := js[FieldName];
  end
  else
    Result := nil;
end;


procedure SetValue(ListView: TVirtualJSONListView; N: PVirtualNode;
  FieldName: string; Value: string);
var
  js: TJSONData;
begin
  TJSONObject(ListView.GetData(N)).Add(FieldName, Value);
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
  currhost, attribs_json, packages_json, softwares_json: string;
  node: PVirtualNode;
begin
  LabHostCnt.Caption := format('Nombre d''enregistrements : %d',
    [GridHosts.SelectedCount]);
  Node := GridHosts.FocusedNode;
  if Node <> nil then
  begin
    currhost := GetValue(GridHosts, Node, 'uuid');
    if HostPages.ActivePage = pgPackages then
    begin
      packages_json := GetValue(GridHosts, Node, 'packages');
      if packages_json = '' then
      begin
        packages_json := WAPTServerJsonGet('client_package_list/%s',
          [currhost]).AsJSon();
        SetValue(GridHosts, Node, 'packages', packages_JSon);
      end;
      Edit1.Text := GetValue(GridHosts, Node, 'host.computer_name');
      Edit2.Text := GetValue(GridHosts, Node, 'host.description');
      Edit3.Text := GetValue(GridHosts, Node, 'host.windows_product_infos.version');
      Edit4.Text := GetValue(GridHosts, Node, 'host.connected_ips');
      Edit5.Text := GetValue(GridHosts, Node, 'host.system_manufacturer');
      Edit6.Text := GetValue(GridHosts, Node, 'host.system_productname');
      Edit7.Text := GetValue(GridHosts, Node, 'last_query_date');
      Edit8.Text := GetValue(GridHosts, Node, 'host.user');
      GridLoadData(GridHostPackages, packages_json);
    end
    else if HostPages.ActivePage = pgSoftwares then
    begin
      softwares_json := GetValue(GridHosts, Node, 'softwares');
      if softwares_json = '' then
      begin
        softwares_json := WAPTServerJsonGet('client_software_list/%s',
          [currhost]).AsJSon();
        SetValue(GridHosts, Node, 'softwares', softwares_json);
      end;
      GridLoadData(GridHostSoftwares, softwares_json);
    end
    else if HostPages.ActivePage = pgHostPackage then
    begin
      attribs_json := GetValue(GridHosts, Node, '');
      TreeLoadData(GridhostAttribs, attribs_json);
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
          package := GetValue(GridPackages, N, 'package') + ' (=' +
            GetValue(GridPackages, N, 'version') + ')';
          Chargement.Caption :=
            'Installation de ' + GetValue(GridPackages, N, 'package') + ' en cours ...';
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
  prefix, oldName, newName, sourceDir: string;
  uploadResult: ISuperObject;
  done: boolean = False;
  isEncrypt: boolean;
  Load: Tvisloading;

begin

  prefix := DMPython.RunJSON(
    'mywapt.config.get("global","default_package_prefix")').AsString;
  {if prefix = 'tis' then
  begin
    ShowMessage(Format(
      'Attention: votre préfixe est "default_package_prefix=%s" dans wapt-get.ini',
      [prefix]));
  end;}
  oldName := GetValue(GridPackages1, GridPackages1.GetFirstSelected, 'package');
  newName := oldName;
  StrReplace(newName, 'tis-', prefix + '-');

  if MessageDlg('Confirmer la duplication',
    format('Etes vous sûr de vouloir dupliquer %s dans votre dépot ?', [oldName]),
    mtConfirmation, mbYesNoCancel, 0) <> mrYes then
    Exit;


  with  Tvisloading.Create(Self) do
    try
      Chargement.Caption := 'Téléchargement en cours';
      Application.ProcessMessages;


      sourceDir := DMPython.RunJSON(
        Format('waptdevutils.duplicate_from_tis_repo(r"%s","%s","%s")',
        [waptpath + '\wapt-get-public.ini', oldName, newName])).AsString;
      if sourceDir <> 'error' then
      begin
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

        ProgressBar1.Position := 50;
        Chargement.Caption := 'Upload en cours';
        Application.ProcessMessages;


        uploadResult := DMPython.RunJSON(
          format('mywapt.build_upload(r"%s",r"%s",r"%s",r"%s","False","True")',
          [sourceDir, privateKeyPassword, waptServerUser, waptServerPassword]), jsonlog);
        if uploadResult.AsString <> '' then
        begin
          ShowMessage(format('%s dupliqué avec succès.', [newName]));
          ActUpdate.Execute;
        end
        else
          ShowMessage('Erreur lors de la duplication.');

        ModalResult := mrOk;

      end;
    finally
      Free;
    end;
end;

procedure TVisWaptGUI.ActPackageGroupAddExecute(Sender: TObject);
begin
  CreatePackage('test');
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
    Selpackage := GetValue(GridPackages, N, 'package');
    if EditPackage(Selpackage) <> nil then
      ActSearchPackage.Execute;
  end;
end;

procedure TVisWaptGUI.ActEditpackageUpdate(Sender: TObject);
begin
  ActEditpackage.Enabled := GridPackages.SelectedCount > 0;
end;

function gridFind(grid: TVirtualJSONListView; Fieldname, AText: string): PVirtualNode;
var
  n: PVirtualNode;
begin
  Result := nil;
  n := grid.GetFirst;
  while n <> nil do
  begin
    if GetValue(grid, n, Fieldname) = AText then
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
  newPass: string;
begin
  with TvisPrivateKeyAuth.Create(self) do
    try
      newPass := PasswordBox('Serveur WAPT', 'Nouveau mot de passe');
      DMPython.RunJSON(
        format('waptdevutils.login_to_waptserver("%s","%s","%s","%s")',
        [GetWaptServerURL + '/login', waptServerUser, waptServerPassword,
        newPass]));

    finally
      Free;
    end;
end;

procedure TVisWaptGUI.ActCreateWaptSetupExecute(Sender: TObject);
var
  params, waptsetupPath: string;
  done: boolean;
begin
  with TVisCreateWaptSetup.Create(self) do
    try
      repeat
        if ShowModal = mrOk then
        begin
          try
            DMPython.PythonEng.ExecString('import waptdevutils');
            params := '';
            params := params + format('default_public_cert=r"%s",',
              [fnPublicCert.FileName]);
            params := params + format('default_repo_url=r"%s",', [edRepoUrl.Text]);
            params := params + format('default_wapt_server=r"%s",', [edWaptServerUrl.Text]);
            params := params + format('destination=r"%s",', [fnWaptDirectory.Directory]);
            params := params + format('company=r"%s",', [edOrgName.Text]);
            waptsetupPath := DMPython.RunJSON(
              format('waptdevutils.create_wapt_setup(mywapt,%s)', [params]),
              jsonlog).AsString;
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
      package := GetValue(GridPackages, N, 'filename');
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
  hostname := GetValue(GridHosts, GridHosts.FocusedNode, 'host.computer_fqdn');
  if EditHost(hostname) <> nil then
    ActSearchHost.Execute;
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

procedure TVisWaptGUI.ActEvaluateVarExecute(Sender: TObject);
var
  res, r, myiter, w: variant;
  i: integer;
begin
  {w := MainModule.Wapt(config_filename:='c:\wapt\wapt-get.ini');
  res := w.update(NOARGS);
  ShowMessage(res.getitem('added'));
  res :=  MainModule.installed_softwares('office');
  myiter:=iter(res);
  for i:=0 to len(res)-1 do
  begin
    r := myiter.next(NOARGS);
    //r := res.GetItem(i);
    showmessage(inttostr(len(r)));
    showmessage(r.Keys(NOARGS).getitem(0));
    showmessage(r.Getitem('publisher'));
  end;}
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
      host := GetValue(GridHosts, N, 'uuid');
      WAPTServerJsonGet('/delete_host/' + host, []).AsJson;
      N := GridHosts.GetNextSelected(N);
    end;
    ActSearchHost.Execute;
  end;
end;

procedure TVisWaptGUI.actHostSelectAllExecute(Sender: TObject);
begin
  TVirtualJSONListView(GridHosts).SelectAll(False);
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
          package := GetValue(GridPackages, N, 'package');
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
  req, hosts, filter: string;
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

  hosts := WAPTServerJsonGet(req, []).AsJson;
  GridLoadData(GridHosts, hosts);
end;

procedure TVisWaptGUI.ActSearchPackageExecute(Sender: TObject);
var
  expr, res: UTF8String;
  packages, package: ISuperObject;
  jsp: TJSONParser;
begin
  expr := format('mywapt.search("%s".split())', [EdSearch.Text]);
  packages := DMPython.RunJSON(expr);
  GridLoadData(GridPackages, packages.AsJSon);
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
end;

procedure TVisWaptGUI.ActUpgradeExecute(Sender: TObject);
begin
  DMPython.RunJSON('mywapt.upgrade()', jsonlog);
end;

procedure TVisWaptGUI.butSearchPackages1Click(Sender: TObject);
var
  expr, res: UTF8String;
  packages, package: ISuperObject;
  jsp: TJSONParser;
begin
  expr := format('waptdevutils.updateTisRepo(r"%s","%s")',
    [waptpath + '\wapt-get-public.ini', EdSearch1.Text]);
  packages := DMPython.RunJSON(expr);
  GridLoadData(GridPackages1, packages.AsJSon);
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
  GridPackages.Clear;
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

  ActSearchHost.Execute;
  ActSearchPackage.Execute;
  butSearchPackages1.Click;
end;

procedure TVisWaptGUI.GridLoadData(grid: TVirtualJSONListView; jsondata: string);
var
  jsp: TJSONParser;
begin
  grid.Clear;
  if (jsondata <> '') then
    try
      grid.BeginUpdate;
      jsp := TJSONParser.Create(jsondata);
      if assigned(grid.Data) then
        grid.Data.Free;
      grid.Data := jsp.Parse;
      grid.LoadData;
      grid.Header.AutoFitColumns;
      jsp.Free;
    finally
      grid.EndUpdate;
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

procedure TVisWaptGUI.GridHostsChange(Sender: TBaseVirtualTree; Node: PVirtualNode);
begin
  UpdateHostPages(Sender);
end;

procedure TVisWaptGUI.GridHostsGetImageIndexEx(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
  var Ghosted: boolean; var ImageIndex: integer; var ImageList: TCustomImageList);
var
  update_status, upgrades, errors: ISuperObject;
begin
  if Column = 0 then
  begin
    update_status := GetGridSOValue(GridHosts, Node, 'update_status');
    if (update_status <> nil) then
    begin
      ImageList := ImageList1;
      errors := update_status['errors'];
      upgrades := update_status['upgrades'];
      if (errors <> nil) and (errors.AsArray.Length > 0) then
        ImageIndex := 1
      else
      if (upgrades <> nil) and (upgrades.AsArray.Length > 0) then
        ImageIndex := 0
      else
        ImageIndex := -1;

    end;
  end;
end;

procedure TVisWaptGUI.GridHostsGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Data: TJSONData; Column: TColumnIndex;
  TextType: TVSTTextType; var CellText: string);
var
  js: ISuperObject;
begin
  js := SO(Data.AsJSON);
  CellText := js.S[TVirtualJSONListViewColumn(GridHosts.Header.Columns[column]).PropertyName];
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

procedure TVisWaptGUI.GridPackagesCompareNodes(Sender: TBaseVirtualTree;
  Node1, Node2: PVirtualNode; Column: TColumnIndex; var Result: integer);
var
  propname: string;
begin
  if column >= 0 then
    propname := TVirtualJSONListViewColumn(TVirtualJSONListView(
      Sender).Header.Columns[Column]).PropertyName
  else
    propname := 'name';
  Result := CompareText(GetValue(TVirtualJSONListView(Sender), Node1, propname),
    GetValue(TVirtualJSONListView(Sender), Node2, propname));
end;

procedure TVisWaptGUI.GridPackagesHeaderClick(Sender: TVTHeader;
  HitInfo: TVTHeaderHitInfo);
begin
  if Sender.SortColumn <> HitInfo.Column then
    Sender.SortColumn := HitInfo.Column
  else
  if Sender.SortDirection = sdAscending then
    Sender.SortDirection := sdDescending
  else
    Sender.SortDirection := sdAscending;
  Sender.Treeview.Invalidate;
end;

procedure TVisWaptGUI.GridPackagesPaintText(Sender: TBaseVirtualTree;
  const TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
  TextType: TVSTTextType);
begin
  if StrIsOneOf(GetValue(GridPackages, Node, 'status'), ['I', 'U']) then
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
    CopyMenu(PopupMenuHosts, MenuItem24)
  else if PageControl1.ActivePage = pgPrivateRepo then
    CopyMenu(PopupMenuPackages, MenuItem24)
  else if PageControl1.ActivePage = pgTISRepo then
    CopyMenu(PopupMenuPackagesTIS, MenuItem24);
end;

function isAdvancedMode: boolean;
begin
  Result := VisWaptGUI.ActAdvancedMode.Checked;
end;

end.
