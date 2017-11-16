unit uVisPackageWizard;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Forms, Controls, ButtonPanel, ExtCtrls, EditBtn, StdCtrls, Classes,
  DefaultTranslator, Buttons, ActnList;

type

  { TVisPackageWizard }

  TVisPackageWizard = class(TForm)
    ActMakeAndEdit: TAction;
    ActMakeUpload: TAction;
    ActionList1: TActionList;
    ActionsImages24: TImageList;
    ButCancel: TBitBtn;
    ButPackageDuplicate: TBitBtn;
    ButOK: TBitBtn;
    EdArchitecture: TComboBox;
    EdSection: TComboBox;
    EdDescription: TLabeledEdit;
    EdInstallerPath: TFileNameEdit;
    EdSilentFlags: TLabeledEdit;
    EdUninstallKey: TLabeledEdit;
    EdVersion: TLabeledEdit;
    Label1: TLabel;
    EdPackageName: TLabeledEdit;
    Label2: TLabel;
    Label3: TLabel;
    Panel1: TPanel;
    Panel2: TPanel;
    procedure ActMakeAndEditExecute(Sender: TObject);
    procedure ActMakeAndEditUpdate(Sender: TObject);
    procedure ActMakeUploadExecute(Sender: TObject);
    procedure ActMakeUploadUpdate(Sender: TObject);
    procedure EdInstallerPathAcceptFileName(Sender: TObject; var Value: String);
    procedure FormCreate(Sender: TObject);
  private
    FInstallerFilename: String;
    procedure SetInstallerFilename(AValue: String);
    { private declarations }
  public
    { public declarations }
    property InstallerFilename:String read FInstallerFilename write SetInstallerFilename;
  end;

var
  VisPackageWizard: TVisPackageWizard;

implementation

uses Dialogs,dmwaptpython,superobject,uWaptRes,uWaptConsoleRes,waptcommon,UScaleDPI,VarPyth;

{$R *.lfm}

{ TVisPackageWizard }

procedure TVisPackageWizard.EdInstallerPathAcceptFileName(Sender: TObject;
  var Value: String);
begin
  InstallerFilename:=Value;
end;

procedure TVisPackageWizard.ActMakeUploadUpdate(Sender: TObject);
begin
  ActMakeUpload.Enabled := ExtractFileExt(FInstallerFilename) ='.msi'
end;

procedure TVisPackageWizard.ActMakeAndEditUpdate(Sender: TObject);
begin
  ActMakeAndEdit.Enabled := (EdPackageName.Text <> '') and (EdSection.Text<>'') and (EdArchitecture.text<>'') and (EdVersion.text<>'');
end;

procedure TVisPackageWizard.ActMakeAndEditExecute(Sender: TObject);
begin
  ActMakeUploadExecute(Sender);
end;

procedure TVisPackageWizard.ActMakeUploadExecute(Sender: TObject);
var
  packageSources,PackageName,Version,Description,Section,UninstallKey: String;
  wapt,SilentFlags:Variant;
  UploadResult : ISuperObject;
begin
  Screen.cursor := crHourGlass;
  if EdSilentFlags.Text <>'' then
    SilentFlags:= EdSilentFlags.Text
  else
    SilentFlags := None();

  if FileExists(EdInstallerPath.FileName) then
  try
    wapt := dmpython.WAPT;
    Version := EdVersion.Text;
    PackageName := EdPackageName.Text;
    Description := EdDescription.Text;
    UninstallKey := EdUninstallKey.Text;
    Section:=EdSection.Text;

    packageSources := VarPythonAsString(wapt.make_package_template(
      installer_path := InstallerFilename,
      packagename := PackageName,
      description := Description,
      version := Version,
      uninstallkey := UninstallKey,
      silentflags := SilentFlags));

    if Sender = ActMakeAndEdit then
    begin
      DMPython.common.wapt_sources_edit(wapt_sources_dir := packageSources);
      ShowMessageFmt(rsPackageSourcesAvailable,[packageSources]);
      ModalResult := mrOk;
    end
    else
    begin
      uploadResult := PyVarToSuperObject(wapt.build_upload(
        sources_directories := packageSources,
        private_key_passwd := dmpython.privateKeyPassword,
        wapt_server_user := waptServerUser,
        wapt_server_passwd := waptServerPassword,
        inc_package_release := True));

      if (uploadResult.AsArray=nil) or (uploadResult.AsArray.Length <=0) then
        raise Exception.Create('Error building or uploading package');
      ShowMessageFmt(rsPackageBuiltSourcesAvailable,[packageSources]);
      ModalResult := mrOk;
    end;
  finally
    Screen.cursor := crDefault;
  end
  else
    ShowMessageFmt(rsInstallerFileNotFound,[EdInstallerPath.FileName]);
end;

procedure TVisPackageWizard.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
  //ScaleImageList(ImageList1,96);
  //ScaleImageList(ActionsImages,96);

end;

procedure TVisPackageWizard.SetInstallerFilename(AValue: String);
var
  installInfos:ISUperObject;
begin
  if FInstallerFilename=AValue then Exit;
  FInstallerFilename:=AValue;
  EdInstallerPath.FileName:=FInstallerFilename;
  if (AValue <> '') and FileExists(AValue) then
  begin
    installInfos := PyVarToSuperObject(DMPython.setuphelpers.get_installer_defaults(AValue));
    EdPackageName.text := DefaultPackagePrefix+'-'+installInfos.S['simplename'];
    EdDescription.Text := UTF8Encode(installInfos.S['description']);
    EdVersion.Text := installInfos.S['version'];
    EdSilentFlags.Text := installInfos.S['silentflags'];
    EdUninstallKey.Text := installInfos.S['uninstallkey'];
  end;
end;

end.

