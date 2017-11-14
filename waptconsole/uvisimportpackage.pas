unit uVisImportPackage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, RTTICtrls, RTTIGrids, vte_rttigrid, Forms,
  Controls, Graphics, Dialogs, ExtCtrls, Buttons, ComCtrls, StdCtrls, ActnList,
  Menus, sogrid, DefaultTranslator, VirtualTrees, superobject, SearchEdit,
  waptcommon;

type

  { TVisImportPackage }

  TVisImportPackage = class(TForm)
    ActWAPTSettings: TAction;
    ActRepositoriesSettings: TAction;
    ActPackageEdit: TAction;
    ActionList1: TActionList;
    ActionsImages: TImageList;
    ActPackageDuplicate: TAction;
    actRefresh: TAction;
    ActSearchExternalPackage: TAction;
    BitBtn2: TBitBtn;
    ButExtRepoChange: TBitBtn;
    ButPackageDuplicate: TBitBtn;
    ButPackageDuplicate1: TBitBtn;
    butSearchExternalPackages: TBitBtn;
    cbNewerThanMine: TCheckBox;
    cbNewestOnly: TCheckBox;
    EdRepoName: TComboBox;
    EdSearchPackage: TSearchEdit;
    GridExternalPackages: TSOGrid;
    LabServerCABundle: TTILabel;
    MenuItem1: TMenuItem;
    MenuItem25: TMenuItem;
    Panel1: TPanel;
    Panel2: TPanel;
    Panel4: TPanel;
    Panel5: TPanel;
    Panel8: TPanel;
    PopupMenuPackages: TPopupMenu;
    LabRepoURL: TTILabel;
    procedure ActPackageDuplicateExecute(Sender: TObject);
    procedure ActPackageDuplicateUpdate(Sender: TObject);
    procedure ActPackageEditExecute(Sender: TObject);
    procedure ActPackageEditUpdate(Sender: TObject);
    procedure ActRepositoriesSettingsExecute(Sender: TObject);
    procedure ActSearchExternalPackageExecute(Sender: TObject);
    procedure ActWAPTLocalConfigExecute(Sender: TObject);
    procedure cbNewerThanMineClick(Sender: TObject);
    procedure EdRepoNameSelect(Sender: TObject);
    procedure EdSearch1Execute(Sender: TObject);
    procedure EdSearchPackageKeyPress(Sender: TObject; var Key: char);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure GridExternalPackagesGetText(Sender: TBaseVirtualTree;
      Node: PVirtualNode; RowData, CellData: ISuperObject;
      Column: TColumnIndex; TextType: TVSTTextType; var CellText: string);
    procedure LabRepoURLClick(Sender: TObject);
  private
    FRepoName: String;
    FWaptrepo: TWaptRepo;
    procedure FillReposList;
    function GetRepoName: String;
    function GetWaptrepo: TWaptRepo;
    procedure SetRepoName(AValue: String);
    procedure SetWaptrepo(AValue: TWaptRepo);
    function updateprogress(receiver: TObject; current, total: integer
      ): boolean;
    { private declarations }
  public
    { public declarations }
    property RepoName:String read GetRepoName write SetRepoName;
    property Waptrepo:TWaptRepo read GetWaptrepo write SetWaptrepo;
  end;

var
  VisImportPackage: TVisImportPackage;

implementation

uses uwaptconsole, tiscommon, soutils, VarPyth, PythonEngine,
  dmwaptpython, uvisloading, uvisprivatekeyauth, uWaptRes, md5, uScaleDPI,
  uWaptConsoleRes, uvisrepositories, inifiles, tisinifiles,LCLIntf;

{$R *.lfm}

{ TVisImportPackage }

procedure TVisImportPackage.cbNewerThanMineClick(Sender: TObject);
begin
  ActSearchExternalPackageExecute(Sender);
end;

procedure TVisImportPackage.EdRepoNameSelect(Sender: TObject);
begin
  if EdRepoName.ItemIndex >= 0 then
    RepoName:=EdRepoName.Items[EdRepoName.ItemIndex]
end;

procedure TVisImportPackage.EdSearch1Execute(Sender: TObject);
begin
  if EdSearchPackage.Modified then
    ActSearchExternalPackageExecute(Sender);
  EdSearchPackage.Modified:=False;
end;

procedure TVisImportPackage.EdSearchPackageKeyPress(Sender: TObject; var Key: char);
begin
  if Key = #13 then
  begin
    EdSearchPackage.SelectAll;
    ActSearchExternalPackage.Execute;
  end;
end;

procedure TVisImportPackage.FormClose(Sender: TObject;
  var CloseAction: TCloseAction);
begin
  IniWriteInteger(Appuserinipath,Name,'Top',Top);
  IniWriteInteger(Appuserinipath,Name,'Left',Left);
  IniWriteInteger(Appuserinipath,Name,'Width',Width);
  IniWriteInteger(Appuserinipath,Name,'Height',Height);
  IniWriteInteger(Appuserinipath,Name,'EdRepoName.ItemIndex',EdRepoName.ItemIndex);
  GridExternalPackages.SaveSettingsToIni(Appuserinipath);

end;

procedure TVisImportPackage.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
  ScaleImageList(ActionsImages,96);
end;

procedure TVisImportPackage.FillReposList;
var
  inifile: TIniFile;
begin
  inifile := TIniFile.Create(AppIniFilename);
  try
    inifile.ReadSections(EdRepoName.Items);
    if EdRepoName.Items.IndexOf('global') >= 0 then
      EdRepoName.Items.Delete(EdRepoName.Items.IndexOf('global'));
  finally
    inifile.Free;
  end;
end;

function TVisImportPackage.GetRepoName: String;
begin
  Result := WaptRepo.Name;

end;

function TVisImportPackage.GetWaptrepo: TWaptRepo;
begin
  if not Assigned(FWaptrepo) or (FWaptrepo.Name <> FRepoName) then
  begin
    if Assigned(FWaptrepo) then
      FreeAndNil(FWaptRepo);

    FWaptrepo :=  TWaptRepo.Create(FRepoName);
    FWaptrepo.LoadFromInifile(WaptIniFilename,FRepoName);

    LabRepoURL.Link.TIObject := Waptrepo;
    LabServerCABundle.Link.TIObject := Waptrepo;
  end;
  Result := FWaptrepo;
end;

procedure TVisImportPackage.SetRepoName(AValue: String);
begin
  if FRepoName=AValue then Exit;
  EdRepoName.ItemIndex := EdRepoName.Items.IndexOf(AValue);
  GridExternalPackages.Data := Nil;
  FRepoName:=AValue;
  WaptRepo.LoadFromInifile(WaptIniFilename,FRepoName);
end;

procedure TVisImportPackage.SetWaptrepo(AValue: TWaptRepo);
begin
  if FWaptrepo=AValue then Exit;
  if Assigned(FWaptrepo) then
    FWaptrepo.Free;

  FWaptrepo:=AValue;
  GridExternalPackages.Data := Nil;
  if AValue<> Nil then
    EdRepoName.Text := AValue.Name;
end;

procedure TVisImportPackage.FormShow(Sender: TObject);
begin
  FillReposList;

  GridExternalPackages.LoadSettingsFromIni(Appuserinipath);
  Top := IniReadInteger(Appuserinipath,Name,'Top',Top);
  Left := IniReadInteger(Appuserinipath,Name,'Left',Left);
  Width := IniReadInteger(Appuserinipath,Name,'Width',Width);
  Height := IniReadInteger(Appuserinipath,Name,'Height',Height);

  EdRepoName.ItemIndex := IniReadInteger(Appuserinipath,Name,'EdRepoName.ItemIndex',0);
  if EdRepoName.ItemIndex<0 then
    EdRepoName.ItemIndex := 0;
  EdRepoName.OnSelect(Sender);
  ActSearchExternalPackage.Execute;
end;

procedure TVisImportPackage.GridExternalPackagesGetText(
  Sender: TBaseVirtualTree; Node: PVirtualNode; RowData,
  CellData: ISuperObject; Column: TColumnIndex; TextType: TVSTTextType;
  var CellText: string);
begin
  if (CellText<>'') and  ( ((Sender as TSOGrid).Header.Columns[Column] as TSOGridColumn).PropertyName = 'size') then
  begin
    CellText := FormatFloat('# ##0 kB',StrToInt64(CellText) div 1024);
  end;
end;

procedure TVisImportPackage.LabRepoURLClick(Sender: TObject);
begin
   OpenDocument(WaptRepo.RepoURL);
end;

procedure TVisImportPackage.ActWAPTLocalConfigExecute(Sender: TObject);
begin
  if (VisWaptGUI<>Nil) and  VisWaptGUI.EditIniFile then
  begin
    dmpython.WaptConfigFileName:='';
    waptcommon.ReadWaptConfig(AppIniFilename);
    dmpython.WaptConfigFileName:=AppIniFilename;
    DMPython.WAPT.update(Register := False);
  end;
end;

procedure TVisImportPackage.ActSearchExternalPackageExecute(Sender: TObject);
var
  expr: String;
  http_proxy,packages_python,verify_cert,wapt: Variant;

begin
  EdSearchPackage.Modified:=False;
  http_proxy := Waptrepo.HttpProxy;
  if (Waptrepo.ServerCABundle='') or (Waptrepo.ServerCABundle='0') or (LowerCase(Waptrepo.ServerCABundle)='false') then
    verify_cert:=False
  else if (Waptrepo.ServerCABundle='1') or (LowerCase(Waptrepo.ServerCABundle)='true') then
    verify_cert:=CARoot()
  else
    verify_cert:=Waptrepo.ServerCABundle;

  if http_proxy = '' then
    http_proxy := None;

  if Waptrepo.RepoURL <>'' then
  try
    try
      Screen.Cursor:=crHourGlass;
      expr := UTF8Decode(EdSearchPackage.Text);
      packages_python := Nil;
      if cbNewerThanMine.Checked then
        wapt := DMPython.WAPT
      else
        wapt := None();
      packages_python := DMPython.waptdevutils.update_external_repo(
        repourl := Waptrepo.RepoURL,
        search_string := expr,
        proxy := http_proxy,
        mywapt := wapt,
        newer_only := cbNewerThanMine.Checked,
        newest_only := cbNewestOnly.Checked,
        verify_cert := verify_cert);

      // todo : pass directly from python dict to TSuperObject
      GridExternalPackages.Data := PyVarToSuperObject(packages_python);
    finally
      Screen.Cursor:=crDefault;
    end;
  except
    on E:Exception do ShowMessageFmt(rsFailedExternalRepoUpdate+#13#10#13#10+E.Message,[Waptrepo.RepoURL]);
  end
  else
    ActRepositoriesSettings.Execute;
end;

procedure TVisImportPackage.ActPackageDuplicateExecute(Sender: TObject);
var
  target,sourceDir,http_proxy: string;
  package,uploadResult, FileName, FileNames, ListPackages,Sources,aDir: ISuperObject;
  SourcesVar,SignersCABundle,ListPackagesVar: Variant;

  PackageFilename:String;
begin
  http_proxy:=Waptrepo.HttpProxy;

  if not FileExists(GetWaptPersonalCertificatePath) then
  begin
    ShowMessageFmt(rsPrivateKeyDoesntExist, [GetWaptPersonalCertificatePath]);
    exit;
  end;

  if DefaultPackagePrefix='' then
  begin
    ShowMessage(rsWaptPackagePrefixMissing);
    ActWAPTSettings.Execute;
    Exit;
  end;

  ListPackages := TSuperObject.create(stArray);
  for package in GridExternalPackages.SelectedRows do
    ListPackages.AsArray.Add(package.S['package']+'(='+package.S['version']+')');

  ListPackagesVar := SuperObjectToPyVar(ListPackages);

  FileNames := PyVarToSuperObject(DMPython.waptdevutils.get_packages_filenames(
        packages_names := ListPackagesVar,
        waptconfigfile := AppIniFilename,
        repo_name := RepoName ));

  if MessageDlg(rsPackageDuplicateConfirmCaption, format(rsPackageDuplicateConfirm, [Join(',', ListPackages)+' '+intToStr(Filenames.AsArray.Length)+' packages']),
        mtConfirmation, mbYesNoCancel, 0) <> mrYes then
    Exit;

  if not DirectoryExists(AppLocalDir + 'cache') then
    mkdir(AppLocalDir + 'cache');

  try
    with  TVisLoading.Create(Self) do
    try
      Sources := TSuperObject.Create(stArray) ;
      //Téléchargement en batchs
      for Filename in FileNames do
      begin
        Application.ProcessMessages;
        ProgressTitle(
          format(rsDownloadingPackage, [Filename.AsArray[0].AsString]));
        target := AppLocalDir + 'cache\' + Filename.AsArray[0].AsString;
        try
          if not FileExists(target) or (MD5Print(MD5File(target)) <> Filename.AsArray[1].AsString) then
          begin
            IdWget(Waptrepo.RepoURL + '/' + Filename.AsArray[0].AsString,
              target, ProgressForm, @updateprogress, (http_proxy<>''));
            if (MD5Print(MD5File(target)) <> Filename.AsArray[1].AsString) then
              raise Exception.CreateFmt(rsDownloadCurrupted,[Filename.AsArray[0].AsString]);
          end;
        except
          on e:Exception do
          begin
            ShowMessage(rsDlCanceled+' : '+e.Message);
            if FileExists(target) then
              DeleteFileUTF8(Target);
            exit;
          end;
        end;
      end;

      for Filename in FileNames do
      begin
        ProgressTitle(format(rsDuplicating, [Filename.AsArray[0].AsString]));
        Application.ProcessMessages;
        if (Waptrepo.SignersCABundle ='') or (Waptrepo.SignersCABundle ='0') then
          SignersCABundle := None()
        else
          SignersCABundle := Waptrepo.SignersCABundle;

        PackageFilename := AppLocalDir + 'cache\' + Filename.AsArray[0].AsString;

        sourceDir := VarPyth.VarPythonAsString(
          DMPython.waptdevutils.duplicate_from_file(
            package_filename := PackageFilename,
            new_prefix := DefaultPackagePrefix,
            authorized_certs := SignersCABundle
            ));
        sources.AsArray.Add(sourceDir);
      end;

      ProgressTitle(format(rsUploadingPackagesToWaptSrv, [IntToStr(Sources.AsArray.Length)]));
      Application.ProcessMessages;

      SourcesVar := SuperObjectToPyVar(sources);

      uploadResult := PyVarToSuperObject(
        DMPython.WAPT.build_upload(
          sources_directories := SourcesVar,
          private_key_passwd := dmpython.privateKeyPassword,
          wapt_server_user := waptServerUser,
          wapt_server_passwd := waptServerPassword,
          inc_package_release := False));

      if (uploadResult <> Nil) and (uploadResult.AsArray.length=Sources.AsArray.Length) then
      begin
        ShowMessage(format(rsDuplicateSuccess, [ Join(',', ListPackages)])) ;
        ModalResult := mrOk;
      end
      else
        ShowMessage(rsDuplicateFailure);
    finally
      for aDir in Sources do
        DeleteDirectory(copy(aDir.AsString,3,length(aDir.AsString)-3),False);
      Free;
    end;
    ModalResult:=mrOK;

  except
      on E:Exception do
        ShowMessageFmt('Unable to import package : %s',[e.Message]);
  end;
end;

procedure TVisImportPackage.ActPackageDuplicateUpdate(Sender: TObject);
begin
  ActPackageDuplicate.Enabled:=GridExternalPackages.SelectedCount>0;
end;

procedure TVisImportPackage.ActPackageEditExecute(Sender: TObject);
var
  SourceDir,target,DevDirectory: string;
  Sources,package,FileName, FileNames, listPackages: ISuperObject;

  ListPackagesVar: Variant;

begin
  if DefaultPackagePrefix='' then
  begin
    ShowMessage(rsWaptPackagePrefixMissing);
    ActWAPTSettings.Execute;
    Exit;
  end;

  listPackages := TSuperObject.create(stArray);
  for package in GridExternalPackages.SelectedRows do
    listPackages.AsArray.Add(package.S['package']+'(='+package.S['version']+')');


  ListPackagesVar := SuperObjectToPyVar(ListPackages);

  FileNames := PyVarToSuperObject(DMPython.waptdevutils.get_packages_filenames(
        packages_names := ListPackagesVar,
        waptconfigfile := AppIniFilename,
        repo_name := RepoName ));

  if not DirectoryExists(AppLocalDir + 'cache') then
    mkdir(AppLocalDir + 'cache');

  try
    with  TVisLoading.Create(Self) do
    try
      Sources := TSuperObject.Create(stArray) ;
      //Téléchargement en batchs
      for Filename in FileNames do
      begin
        Application.ProcessMessages;
        ProgressTitle(
          format(rsDownloadingPackage, [Filename.AsArray[0].AsString]));
        target := AppLocalDir + 'cache\' + Filename.AsArray[0].AsString;
        try
          if not FileExists(target) or (MD5Print(MD5File(target)) <> Filename.AsArray[1].AsString) then
          begin
            IdWget(Waptrepo.RepoURL + '/' + Filename.AsArray[0].AsString,
              target, ProgressForm, @updateprogress, HttpProxy<>'');
            if (MD5Print(MD5File(target)) <> Filename.AsArray[1].AsString) then
              raise Exception.CreateFmt(rsDownloadCurrupted,[Filename.AsArray[0].AsString]);
          end;
        except
          on e:Exception do
          begin
            ShowMessage(rsDlCanceled+' : '+e.Message);
            if FileExists(target) then
              DeleteFileUTF8(Target);
            exit;
          end;
        end;
      end;

      for Filename in FileNames do
      begin
        ProgressTitle(format(rsDuplicating, [Filename.AsArray[0].AsString]));
        Application.ProcessMessages;
        target := AppLocalDir + 'cache\' + Filename.AsArray[0].AsString;
        DevDirectory :=  AppendPathDelim(DefaultSourcesRoot)+ExtractFileNameWithoutExt(Filename.AsArray[0].AsString)+'-wapt';
        sourceDir := VarPythonAsString(DMPython.waptdevutils.duplicate_from_file(
          package_filename := target,
          new_prefix := DefaultPackagePrefix,
          target_directory := DevDirectory,
          authorized_certs := Waptrepo.SignersCABundle
          ));

        dmpython.WAPT.add_pyscripter_project(sourceDir);
        DMPython.common.wapt_sources_edit(sourceDir);
      end;
    finally
      Free;
    end;
    ModalResult:=mrOK;
  except
      on E:Exception do
        ShowMessageFmt('Unable to import package : %s',[e.Message]);
  end;
end;

procedure TVisImportPackage.ActPackageEditUpdate(Sender: TObject);
begin
  ActPackageEdit.Enabled:=GridExternalPackages.SelectedCount = 1;
end;

procedure TVisImportPackage.ActRepositoriesSettingsExecute(Sender: TObject);
var
  rs:TVisRepositories;
begin
  rs := TVisRepositories.Create(Self);
  try
    rs.RepoName := Waptrepo.Name;
    if rs.ShowModal = mrOk then
    begin
      //urlExternalRepo.Caption := format(rsUrl, [IniReadString(WaptIniFilename,EdRepoName.Text,'repo_url','https://store.wapt.fr/wapt')]);
      FillReposList;
      RepoName:='';
      RepoName:=rs.RepoName;
      ActSearchExternalPackage.Execute;
    end;
  finally
    rs.Free;
  end;

end;

function TVisImportPackage.updateprogress(receiver: TObject;
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

