unit uVisImportPackage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, LazUTF8, RTTICtrls, RTTIGrids, Forms,
  Controls, Graphics, Dialogs, ExtCtrls, Buttons, ComCtrls, StdCtrls, ActnList,
  Menus, sogrid, DefaultTranslator, VirtualTrees, superobject, SearchEdit,
  waptcommon,uvisloading,IdComponent, ImgList;

type

  { TVisImportPackage }

  TVisImportPackage = class(TForm)
    ActionsImages24: TImageList;
    ActWAPTSettings: TAction;
    ActRepositoriesSettings: TAction;
    ActPackageEdit: TAction;
    ActionList1: TActionList;
    ActPackageDuplicate: TAction;
    actRefresh: TAction;
    ActSearchExternalPackage: TAction;
    BitBtn2: TBitBtn;
    ButExtRepoChange: TBitBtn;
    ButPackageDuplicate: TBitBtn;
    ButPackageDuplicate1: TBitBtn;
    butSearchExternalPackages: TBitBtn;
    cbFilterPackagesArch: TCheckGroup;
    cbFilterPackagesLocales: TCheckGroup;
    cbNewerThanMine: TCheckBox;
    cbNewestOnly: TCheckBox;
    CBImportDependencies: TCheckBox;
    EdMaturity: TComboBox;
    EdRepoName: TComboBox;
    EdSearchPackage: TSearchEdit;
    GridExternalPackages: TSOGrid;
    Label7: TLabel;
    LabRepoURL: TTILabel;
    LabServerCABundle: TTILabel;
    LabSignersCABundle: TTILabel;
    MenuItem1: TMenuItem;
    MenuItem25: TMenuItem;
    PanBas: TPanel;
    Panel2: TPanel;
    PanHaut: TPanel;
    PanRepoParams: TPanel;
    PanSearch: TPanel;
    PanSettings: TPanel;
    PopupMenuPackages: TPopupMenu;
    procedure ActPackageDuplicateExecute(Sender: TObject);
    procedure ActPackageDuplicateUpdate(Sender: TObject);
    procedure ActPackageEditExecute(Sender: TObject);
    procedure ActPackageEditUpdate(Sender: TObject);
    procedure ActRepositoriesSettingsExecute(Sender: TObject);
    procedure ActSearchExternalPackageExecute(Sender: TObject);
    procedure ActWAPTLocalConfigExecute(Sender: TObject);
    procedure cbFilterPackagesArchClick(Sender: TObject);
    procedure cbFilterPackagesArchItemClick(Sender: TObject; Index: integer);
    procedure cbFilterPackagesLocalesClick(Sender: TObject);
    procedure cbFilterPackagesLocalesItemClick(Sender: TObject; Index: integer);
    procedure cbNewerThanMineClick(Sender: TObject);
    procedure EdRepoNameSelect(Sender: TObject);
    procedure EdSearch1Execute(Sender: TObject);
    procedure EdSearchPackageKeyPress(Sender: TObject; var Key: char);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure GridExternalPackagesGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: Boolean; var ImageIndex: Integer;
      var ImageList: TCustomImageList);
    procedure GridExternalPackagesGetText(Sender: TBaseVirtualTree;
      Node: PVirtualNode; RowData, CellData: ISuperObject;
      Column: TColumnIndex; TextType: TVSTTextType; var CellText: string);
    procedure GridExternalPackagesInitNode(Sender: TBaseVirtualTree;
      ParentNode, Node: PVirtualNode; var InitialStates: TVirtualNodeInitStates
      );
    procedure GridExternalPackagesMeasureItem(Sender: TBaseVirtualTree;
      TargetCanvas: TCanvas; Node: PVirtualNode; var NodeHeight: Integer);
    procedure GridExternalPackagesSOCompareNodes(Sender: TSOGrid; Node1,
      Node2: ISuperObject; const Columns: array of String; var Result: Integer);
    procedure LabRepoURLClick(Sender: TObject);
  private
    FRepoName: String;
    FWaptrepo: TWaptRepo;
    FCurrentVisLoading: TVisLoading;
    FUploadSize: LongInt;
    procedure FillReposList;
    function GetCurrentVisLoading: TVisLoading;
    function GetRepoName: String;
    function GetWaptrepo: TWaptRepo;
    procedure SetRepoName(AValue: String);
    procedure SetWaptrepo(AValue: TWaptRepo);
    function updateprogress(receiver: TObject; current, total: integer
      ): boolean;
    procedure IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode; AWorkCount: int64);
    { private declarations }
    function GetRequestFilter:Variant;
  public
    { public declarations }
    property RepoName:String read GetRepoName write SetRepoName;
    property Waptrepo:TWaptRepo read GetWaptrepo write SetWaptrepo;
    property CurrentVisLoading: TVisLoading read GetCurrentVisLoading;
  end;

var
  VisImportPackage: TVisImportPackage;

implementation

uses Variants, VarPyth, PythonEngine, uwaptconsole, tiscommon, soutils,
  dmwaptpython, uvisprivatekeyauth, uWaptRes, md5,
  uWaptConsoleRes, uvisrepositories, inifiles, tisstrings,
  tisinifiles,LCLIntf,LazFileUtils,FileUtil, uWaptPythonUtils;

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
  IniWriteBool(Appuserinipath,Name,'CBImportDependencies',CBImportDependencies.Checked);
  GridExternalPackages.SaveSettingsToIni(Appuserinipath);
end;

procedure TVisImportPackage.FormCreate(Sender: TObject);
begin
  EdMaturity.Text:=DefaultMaturity;
end;

procedure TVisImportPackage.FormDestroy(Sender: TObject);
begin
  if FCurrentVisLoading <> Nil then
    FreeAndNil(FCurrentVisLoading);
end;

procedure TVisImportPackage.FillReposList;
var
  inifile: TIniFile;
  section: String;
const
  RepoExceptions : Array[0..4] of String = ('global','options','wapt','waptwua','wapt-host');
begin
  inifile := TIniFile.Create(AppIniFilename);
  try
    inifile.ReadSections(EdRepoName.Items);
    for section in RepoExceptions do
      if EdRepoName.Items.IndexOf(section) >= 0 then
        EdRepoName.Items.Delete(EdRepoName.Items.IndexOf(section));
  finally
    inifile.Free;
  end;
end;

function TVisImportPackage.GetCurrentVisLoading: TVisLoading;
begin
  if FCurrentVisLoading=Nil then
    FCurrentVisLoading:=TVisLoading.Create(Nil);
  Result := FCurrentVisLoading;
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
    LabSignersCABundle.Link.TIObject := Waptrepo;
  end;
  Result := FWaptrepo;
end;

procedure TVisImportPackage.SetRepoName(AValue: String);
begin
  if FRepoName=AValue then Exit;

  FRepoName:=AValue;
  GridExternalPackages.Data := Nil;
  if AValue<>'' then
  begin
    EdRepoName.ItemIndex := EdRepoName.Items.IndexOf(AValue);
    WaptRepo.LoadFromInifile(WaptIniFilename,FRepoName);
    ActSearchExternalPackageExecute(Nil);
  ;end
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

  CBImportDependencies.Checked:=IniReadBool(Appuserinipath,Name,'CBImportDependencies',CBImportDependencies.Checked);

  if Screen.PixelsPerInch<>96 then
    GridExternalPackages.Header.Height:=trunc((GridExternalPackages.Header.MinHeight*Screen.PixelsPerInch)/96);

  MakeFullyVisible;

  EdRepoName.ItemIndex := IniReadInteger(Appuserinipath,Name,'EdRepoName.ItemIndex',0);
  if EdRepoName.ItemIndex<0 then
    EdRepoName.ItemIndex := 0;
  EdRepoName.OnSelect(Sender);
end;

procedure TVisImportPackage.GridExternalPackagesGetImageIndexEx(
  Sender: TBaseVirtualTree; Node: PVirtualNode; Kind: TVTImageKind;
  Column: TColumnIndex; var Ghosted: Boolean; var ImageIndex: Integer;
  var ImageList: TCustomImageList);
var
  targetOS: ISuperObject;
begin
  if TSOGridColumn(GridExternalPackages.Header.Columns[Column]).PropertyName = 'target_os' then
  begin
    targetOS := GridExternalPackages.GetCellData(Node, 'target_os', Nil);
    if (targetOS<>Nil)then
    begin
      if Pos('linux',lowerCase(targetOS.AsString))>0 then
        ImageIndex := 21
      else if Pos('windows',lowerCase(targetOS.AsString))>0 then
        ImageIndex := 20
      else if (Pos('darwin',lowerCase(targetOS.AsString))>0) or (Pos('macos',lowerCase(targetOS.AsString))>0) then
          ImageIndex := 19
      else
          ImageIndex := 22;
    end
    else
      ImageIndex := -1;
  end;
end;

procedure TVisImportPackage.GridExternalPackagesGetText(
  Sender: TBaseVirtualTree; Node: PVirtualNode; RowData,
  CellData: ISuperObject; Column: TColumnIndex; TextType: TVSTTextType;
  var CellText: string);
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

procedure TVisImportPackage.GridExternalPackagesInitNode(
  Sender: TBaseVirtualTree; ParentNode, Node: PVirtualNode;
  var InitialStates: TVirtualNodeInitStates);
begin
  InitialStates := InitialStates + [ivsMultiline];
end;

procedure TVisImportPackage.GridExternalPackagesMeasureItem(
  Sender: TBaseVirtualTree; TargetCanvas: TCanvas; Node: PVirtualNode;
  var NodeHeight: Integer);
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
  NodeHeight := maxheight + 4;

end;

procedure TVisImportPackage.GridExternalPackagesSOCompareNodes(Sender: TSOGrid;
  Node1, Node2: ISuperObject; const Columns: array of String;
  var Result: Integer);
begin
  if (length(Columns) > 0) and (Node1 <> nil) and (Node2 <> nil) then
  begin
    if length(Columns) = 1 then
    begin
      if pos('package',Columns[0])>0 then
      begin
        Result:=CompareStr(Node1.S[Columns[0]],Node2.S[Columns[0]]);
        If Result = 0 then
          Result:= CompareVersion(UTF8Encode(Node1.S['version']),UTF8Encode(Node2.S['version']));
        If Result = 0 then
          Result:= CompareStr(UTF8Encode(Node1.S['architecture']),UTF8Encode(Node2.S['architecture']));
        If Result = 0 then
          Result:= CompareStr(UTF8Encode(Node1.S['locale']),UTF8Encode(Node2.S['locale']));
        If Result = 0 then
          Result:= CompareStr(UTF8Encode(Node1.S['maturity']),UTF8Encode(Node2.S['maturity']));
      end else
      if pos('size',Columns[0])>0 then
      {$IFDEF WINDOWS}
        Result:=CompareInt(Node1.I[Columns[0]],Node2.I[Columns[0]])
      {$ELSE}
        Result := 0 // TODO change
      {$ENDIF}
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
    { TODO : Remove use of WAPT instance, use waptpackage.PackageEntry instead }
    if not VarIsEmpty(DMPython.WAPT) then
      DMPython.WAPT := Unassigned;
  end;
end;

procedure TVisImportPackage.cbFilterPackagesArchClick(Sender: TObject);
begin
   ActSearchExternalPackageExecute(Sender);
end;

procedure TVisImportPackage.cbFilterPackagesArchItemClick(Sender: TObject;
  Index: integer);
begin
   ActSearchExternalPackageExecute(Sender);
end;

procedure TVisImportPackage.cbFilterPackagesLocalesClick(Sender: TObject);
begin
   ActSearchExternalPackageExecute(Sender);
end;

procedure TVisImportPackage.cbFilterPackagesLocalesItemClick(Sender: TObject;
  Index: integer);
begin
   ActSearchExternalPackageExecute(Sender);
end;

function TVisImportPackage.GetRequestFilter:Variant;
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
  RequestFilter := SO();

  if AtLeastOne(cbFilterPackagesArch) then begin
    ASA := TSuperObject.Create(stArray);
    if cbFilterPackagesArch.Checked[0] then ASA.AsArray.Add('x86');
    if cbFilterPackagesArch.Checked[1] then ASA.AsArray.Add('x64');
    RequestFilter['architectures'] := ASA;
  end;

  if AtLeastOne(cbFilterPackagesLocales) then begin
    ASA := TSuperObject.Create(stArray);
    if cbFilterPackagesLocales.Checked[0] then ASA.AsArray.Add('en');
    if cbFilterPackagesLocales.Checked[1] then ASA.AsArray.Add('fr');
    if cbFilterPackagesLocales.Checked[2] then ASA.AsArray.Add('de');
    if cbFilterPackagesLocales.Checked[3] then ASA.AsArray.Add('it');
    if cbFilterPackagesLocales.Checked[4] then ASA.AsArray.Add('es');
    RequestFilter['locales'] := ASA;
  end;

  vRequestFilter:=SuperObjectToPyVar(RequestFilter);
  result := vRequestFilter;
end;


procedure TVisImportPackage.ActSearchExternalPackageExecute(Sender: TObject);
var
  prefix,expr: String;
  TemplatesRepoName,packages_python,myrepo,RequestFilter: Variant;

begin
  EdSearchPackage.Modified:=False;
  if Waptrepo.RepoURL <>'' then
  try
    try
      Screen.Cursor:=crHourGlass;
      expr := EdSearchPackage.Text;
      packages_python := Nil;
      if cbNewerThanMine.Checked then
      begin
        myrepo := DMPython.MainWaptRepo;
        prefix := DefaultPackagePrefix;
      end
      else
      begin
        myrepo := None();
        prefix := '';
      end;

      TemplatesRepoName := Waptrepo.Name;
      RequestFilter := GetRequestFilter;

      packages_python := DMPython.waptdevutils.update_external_repo(
        config_filename := WaptIniFilename,
        repo_name := TemplatesRepoName,
        search_string := expr,
        myrepo := myrepo,
        my_prefix := prefix,
        newer_only := cbNewerThanMine.Checked,
        newest_only := cbNewestOnly.Checked,
        description_locale := Language,
        package_request := RequestFilter);

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
  target,sourceDir,buildfilename,http_proxy: string;
  NewPackagesFilenames,package,FileName, FileNames, ListPackages,Sources,aDir: ISuperObject;
  PackageEdited,VPackageFilePath,VCABundle,VPrivateKeyPassword,
  SignersCABundle,ListPackagesVar,WithDependencies,PrivateRepo,RemoteRepo: Variant;
  RequestFilter: Variant;
  PackageFilename:String;
begin
  Sources := Nil;
  http_proxy:=Waptrepo.HttpProxy;

  if not FileExistsUTF8(WaptPersonalCertificatePath) then
  begin
    ShowMessageFmt(rsPrivateKeyDoesntExist, [WaptPersonalCertificatePath]);
    exit;
  end;

  VPrivateKeyPassword := PyUTF8Decode(dmpython.privateKeyPassword);

  if DefaultPackagePrefix='' then
  begin
    ShowMessage(rsWaptPackagePrefixMissing);
    ActWAPTSettings.Execute;
    Exit;
  end;

  ListPackages := TSuperObject.create(stArray);
  for package in GridExternalPackages.SelectedRows do
    ListPackages.AsArray.Add(package);

  ListPackagesVar := SuperObjectToPyVar(ListPackages);
  RequestFilter := GetRequestFilter();
  WithDependencies := Integer(CBImportDependencies.Checked);
  PrivateRepo := dmpython.MainWaptRepo;
  FileNames := PyVarToSuperObject(DMPython.waptdevutils.get_packages_filenames(
        packages := ListPackagesVar,
        waptconfigfile := AppIniFilename,
        repo_name := RepoName,
        package_request := RequestFilter,
        with_depends := WithDependencies,
        privaterepo := PrivateRepo,
        local_prefix := DefaultPackagePrefix ));

  if MessageDlg(rsPackageDuplicateConfirmCaption, format(rsPackageDuplicateConfirm, [Join(','+#13#10,ExtractField(FileNames,'0')) + ' '+intToStr(Filenames.AsArray.Length)+ ' ' + rsPackages]),
        mtConfirmation, mbYesNoCancel, 0) <> mrYes then
    Exit;

  if not DirectoryExists(AppLocalDir + 'cache') then
    mkdir(AppLocalDir + 'cache');

  try
    with CurrentVisLoading do
    try
      Sources := TSuperObject.Create(stArray) ;
      NewPackagesFilenames := TSuperObject.create(stArray);
      //Téléchargement en batchs
      for Filename in FileNames do
      begin
        Application.ProcessMessages;
        ProgressTitle(
          format(rsDownloadingPackage, [Filename.AsArray[0].AsString]));
        target := AppLocalDir + 'cache\' + UTF8Encode(Filename.AsArray[0].AsString);
        try
          if not FileExistsUTF8(target) or (MD5Print(MD5File(target)) <> UTF8Encode(Filename.AsArray[1].AsString)) then
          begin
            if not IdWget(Waptrepo.RepoURL + '/' + UTF8Encode(Filename.AsArray[0].AsString),
              target, ProgressForm, @updateprogress, http_proxy,
              DefaultUserAgent,Waptrepo.ServerCABundle,Nil,
              Waptrepo.ClientCertificatePath,Waptrepo.ClientPrivateKeyPath) then
                Raise Exception.CreateFmt('Unable to download %s',[Waptrepo.RepoURL + '/' + UTF8Encode(Filename.AsArray[0].AsString)]);

            if (MD5Print(MD5File(target)) <> Filename.AsArray[1].AsString) then
              raise Exception.CreateFmt(rsDownloadCurrupted,[UTF8Encode(Filename.AsArray[0].AsString)]);
          end;
        except
          on e:Exception do
          begin
            ShowMessage(rsDlCanceled+' : '+e.Message);
            if FileExistsUTF8(target) then
              DeleteFileUTF8(Target);
            exit;
          end;
        end;
      end;

      for Filename in FileNames do
      try
        sourceDir := '';
        buildfilename := '';

        ProgressTitle(format(rsDuplicating, [Filename.AsArray[0].AsString]));
        Application.ProcessMessages;
        if (Waptrepo.SignersCABundle ='') or (Waptrepo.SignersCABundle ='0') then
        begin
          SignersCABundle := None();
          VCABundle := None();
        end
        else
        begin
          SignersCABundle := Waptrepo.SignersCABundle;
          VCABundle := DMPython.waptcrypto.SSLCABundle('--noargs--');
          VCABundle.add_pems(SignersCABundle);
        end;

        // bundle to check downloaded packages when unzipping
        PackageFilename := AppLocalDir + 'cache\' + UTF8Encode(Filename.AsArray[0].AsString);
        VPackageFilePath := PyUTF8Decode(PackageFilename);
        PackageEdited := DMPython.waptpackage.PackageEntry(waptfile := VPackageFilePath);
        ProgressTitle(format(rsUnzipping, [Filename.AsArray[0].AsString]));
        sourceDir := PackageEdited.unzip_package(cabundle := VCABundle);
        PackageEdited.invalidate_signature('--noarg--');

        sources.AsArray.Add(sourceDir);
        PackageEdited.change_prefix(DefaultPackagePrefix);
        PackageEdited.change_depends_conflicts_prefix(DefaultPackagePrefix);
        PackageEdited.maturity := EdMaturity.Text;
        ProgressTitle(format(rsBuilding, [Filename.AsArray[0].AsString]));
        buildfilename := VarPyth.VarPythonAsString(PackageEdited.build_package('--noarg--'));
        NewPackagesFilenames.AsArray.Add(buildfilename);
        ProgressTitle(format(rsSigning, [sourceDir]));
        PackageEdited.sign_package(
          certificate := DMPython.WAPT.personal_certificate('--noarg--'),
          private_key := DMPython.WAPT.private_key(private_key_password := VPrivateKeyPassword));
        FUploadSize:=FileSize(buildfilename);
        ProgressTitle(format(rsUploadingFile, [buildfilename]));
        WAPTServerJsonMultipartFilePost(
          GetWaptServerURL, 'api/v3/upload_packages', [], 'file',buildfilename ,
          WaptServerUser, WaptServerPassword, @IdHTTPWork,GetWaptServerCertificateFilename);

      finally
        if DirectoryExistsUTF8(sourceDir) then
          DeleteDirectory(sourceDir,False);
        if FileExistsUTF8(buildfilename) then
          DeleteFileUTF8(buildfilename);
      end;

      if (NewPackagesFilenames <> Nil) and (NewPackagesFilenames.AsArray.length=Sources.AsArray.Length) then
      begin
        ShowMessageFmt(rsDuplicateSuccess, [ Join(',', NewPackagesFilenames)]);
        ModalResult := mrOk;
      end
      else
        ShowMessage(rsDuplicateFailure);

    finally
      Finish;
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
  http_proxy:String;
  SourceDir,target,DevDirectory: string;
  package,FileName, FileNames, listPackages: ISuperObject;
  RequestFilter,WithDepends,PrivateRepo,RemoteRepo: Variant;
  ListPackagesVar: Variant;

begin
  http_proxy:=Waptrepo.HttpProxy;

  if DefaultPackagePrefix='' then
  begin
    ShowMessage(rsWaptPackagePrefixMissing);
    ActWAPTSettings.Execute;
    Exit;
  end;

  listPackages := TSuperObject.create(stArray);
  for package in GridExternalPackages.SelectedRows do
    listPackages.AsArray.Add(package);

  ListPackagesVar := SuperObjectToPyVar(ListPackages);
  RequestFilter := GetRequestFilter;
  WithDepends := Integer(CBImportDependencies.Checked);
  PrivateRepo := dmpython.MainWaptRepo;
  FileNames := PyVarToSuperObject(DMPython.waptdevutils.get_packages_filenames(
        packages := ListPackagesVar,
        waptconfigfile := AppIniFilename,
        repo_name := RepoName,
        package_request := RequestFilter,
        with_depends := WithDepends,
        local_prefix := DefaultPackagePrefix,
        privaterepo := PrivateRepo
        ));

  if not DirectoryExists(AppLocalDir + 'cache') then
    mkdir(AppLocalDir + 'cache');

  try
    with  TVisLoading.Create(Self) do
    try
      //Téléchargement en batchs
      for Filename in FileNames do
      begin
        Application.ProcessMessages;
        ProgressTitle(
          format(rsDownloadingPackage, [UTF8Encode(Filename.AsArray[0].AsString)]));
        target := AppLocalDir + 'cache\' + UTF8Encode(Filename.AsArray[0].AsString);
        try
          if not FileExistsUTF8(target) or (MD5Print(MD5File(target)) <> Filename.AsArray[1].AsString) then
          begin
            if not IdWget(Waptrepo.RepoURL + '/' + UTF8Encode(Filename.AsArray[0].AsString),
              target, ProgressForm, @updateprogress, http_proxy,
              DefaultUserAgent,Waptrepo.ServerCABundle,Nil,
              Waptrepo.ClientCertificatePath,Waptrepo.ClientPrivateKeyPath) then
                Raise Exception.CreateFmt('Unable to download %s',[Waptrepo.RepoURL + '/' + UTF8Encode(Filename.AsArray[0].AsString)]);

            if (MD5Print(MD5File(target)) <> UTF8Encode(Filename.AsArray[1].AsString)) then
              raise Exception.CreateFmt(rsDownloadCurrupted,[UTF8Encode(Filename.AsArray[0].AsString)]);
          end;
        except
          on e:Exception do
          begin
            ShowMessage(rsDlCanceled+' : '+e.Message);
            if FileExistsUTF8(target) then
              DeleteFileUTF8(target);
            exit;
          end;
        end;
      end;

      for Filename in FileNames do
      begin
        ProgressTitle(format(rsDuplicating, [Filename.AsArray[0].AsString]));
        Application.ProcessMessages;
        target := AppLocalDir + 'cache\' + UTF8Encode(Filename.AsArray[0].AsString);
        DevDirectory := AppendPathDelim(DefaultSourcesRoot)+ExtractFileNameWithoutExt(UTF8Encode(Filename.AsArray[0].AsString))+'-wapt';
        sourceDir := VarPythonAsString(DMPython.waptdevutils.duplicate_from_file(
          package_filename := target,
          new_prefix := DefaultPackagePrefix,
          target_directory := DevDirectory,
          authorized_certs := Waptrepo.SignersCABundle,
          set_maturity := EdMaturity.Text
          ));
        { TODO : Remove use of WAPT instance, use waptpackage.PackageEntry instead }
        dmpython.WAPT.add_pyscripter_project(sourceDir);
        dmpython.WAPT.add_vscode_project(sourceDir);
        DMPython.common.wapt_sources_edit(wapt_sources_dir:=sourceDir,editor_for_packages:=dmpython.WAPT.editor_for_packages);
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

procedure TVisImportPackage.IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode;
  AWorkCount: int64);
begin
  if CurrentVisLoading <> nil then
  begin
    CurrentVisLoading.ProgressStep(AWorkCount,FUploadSize);
    if CurrentVisLoading.StopRequired then
      raise Exception.Create('Canceled');
  end;

end;



end.

