unit uVisImportPackage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  Buttons, ComCtrls, StdCtrls, ActnList, Menus, sogrid, DefaultTranslator,
  uWaptConsoleRes;

type

  { TVisImportPackage }

  TVisImportPackage = class(TForm)
    ActionList1: TActionList;
    ActionsImages: TImageList;
    ActPackageDuplicate: TAction;
    actRefresh: TAction;
    ActSearchExternalPackage: TAction;
    ActWAPTLocalConfig: TAction;
    BitBtn2: TBitBtn;
    ButExtRepoChange: TBitBtn;
    ButPackageDuplicate: TBitBtn;
    butSearchExternalPackages: TBitBtn;
    EdSearch1: TEdit;
    GridExternalPackages: TSOGrid;
    MenuItem25: TMenuItem;
    Panel1: TPanel;
    Panel8: TPanel;
    PopupMenuPackages: TPopupMenu;
    urlExternalRepo: TLabel;
    procedure ActPackageDuplicateExecute(Sender: TObject);
    procedure ActSearchExternalPackageExecute(Sender: TObject);
    procedure ActWAPTLocalConfigExecute(Sender: TObject);
    procedure ButExtRepoChangeClick(Sender: TObject);
    procedure EdSearch1KeyPress(Sender: TObject; var Key: char);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormShow(Sender: TObject);
  private
    function updateprogress(receiver: TObject; current, total: integer
      ): boolean;
    { private declarations }
  public
    { public declarations }
  end;

var
  VisImportPackage: TVisImportPackage;

implementation

uses uwaptconsole,tiscommon,soutils,waptcommon,
    dmwaptpython,superobject,uvisloading,uvisprivatekeyauth, uWaptRes;

{$R *.lfm}

{ TVisImportPackage }

procedure TVisImportPackage.ButExtRepoChangeClick(Sender: TObject);
begin
  ActWAPTLocalConfigExecute(self);
  urlExternalRepo.Caption := format(rsUrl, [WaptTemplatesRepo]);
end;

procedure TVisImportPackage.EdSearch1KeyPress(Sender: TObject; var Key: char);
begin
  if Key = #13 then
  begin
    EdSearch1.SelectAll;
    ActSearchExternalPackage.Execute;
  end;
end;

procedure TVisImportPackage.FormClose(Sender: TObject;
  var CloseAction: TCloseAction);
begin
  GridExternalPackages.SaveSettingsToIni(Appuserinipath) ;
end;

procedure TVisImportPackage.FormShow(Sender: TObject);
begin
  GridExternalPackages.LoadSettingsFromIni(Appuserinipath) ;
  urlExternalRepo.Caption:=  WaptTemplatesRepo;
  ActSearchExternalPackage.Execute;
end;

procedure TVisImportPackage.ActWAPTLocalConfigExecute(Sender: TObject);
begin
  if (VisWaptGUI<>Nil) and  VisWaptGUI.EditIniFile then
  begin
    GridExternalPackages.Clear;
    ActSearchExternalPackage.Execute;
  end;
end;

procedure TVisImportPackage.ActSearchExternalPackageExecute(Sender: TObject);
var
  expr: UTF8String;
  packages: ISuperObject;
begin
  expr := format('waptdevutils.update_external_repo(r"%s","%s")',
    [AppIniFilename, EdSearch1.Text]);
  packages := DMPython.RunJSON(expr);
  GridExternalPackages.Data := packages;
end;

procedure TVisImportPackage.ActPackageDuplicateExecute(Sender: TObject);
var
  target,sourceDir: string;
  package,uploadResult, FileName, FileNames, listPackages,Sources,aDir: ISuperObject;

begin
  if not FileExists(GetWaptPrivateKeyPath) then
  begin
    ShowMessageFmt(rsPrivateKeyDoesntExist, [GetWaptPrivateKeyPath]);
    exit;
  end;

  listPackages := TSuperObject.create(stArray);
  for package in GridExternalPackages.SelectedRows do
    listPackages.AsArray.Add(package.S['package']+'(='+package.S['version']+')');
  //calcule liste de tous les fichiers wapt nécessaires y compris les dépendances
  FileNames := DMPython.RunJSON(format('waptdevutils.get_packages_filenames(r"%s".decode(''utf8''),"%s")',
        [AppIniFilename,Join(',',listPackages)]));

  if MessageDlg(rsPackageDuplicateConfirmCaption, format(rsPackageDuplicateConfirm, [Join(',', FileNames)]),
        mtConfirmation, mbYesNoCancel, 0) <> mrYes then
    Exit;

  if not DirectoryExists(AppLocalDir + 'cache') then
    mkdir(AppLocalDir + 'cache');


  with  TVisLoading.Create(Self) do
  try
    Sources := TSuperObject.Create(stArray) ;
    //Téléchargement en batchs
    for Filename in FileNames do
    begin
      Application.ProcessMessages;
      ProgressTitle(
        format(rsDownloadingPackage, [Filename.AsString]));
      target := AppLocalDir + 'cache\' + Filename.AsString;
      try
        if not FileExists(target) then
          IdWget(WaptTemplatesRepo + '/' + FileName.AsString,
            target, ProgressForm, @updateprogress, UseProxyForTemplates);
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
      ProgressTitle(format(rsDuplicating, [FileName.AsString]));
      Application.ProcessMessages;
      sourceDir := DMPython.RunJSON(
        Format('waptdevutils.duplicate_from_external_repo(r"%s",r"%s")',
        [AppIniFilename,AppLocalDir + 'cache\' + Filename.AsString])).AsString;
      sources.AsArray.Add('r"'+sourceDir+'"');
    end;

    ProgressTitle(format(rsUploadingPackagesToWaptSrv, [IntToStr(Sources.AsArray.Length)]));
    Application.ProcessMessages;

    uploadResult := DMPython.RunJSON(
      format('mywapt.build_upload([%s],private_key_passwd=r"%s",wapt_server_user=r"%s",wapt_server_passwd=r"%s",inc_package_release=False)',
      [Join(',',sources) , privateKeyPassword, waptServerUser, waptServerPassword]),
      VisWaptGUI.jsonlog);
    if (uploadResult <> Nil) and (uploadResult.AsArray.length=Sources.AsArray.Length) then
    begin
      ShowMessage(format(rsDuplicateSuccess, [ Join(',', listPackages)])) ;
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

