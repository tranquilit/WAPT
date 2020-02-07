unit uVisPackageWizard;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Forms, Controls, LazUTF8,LazFileUtils,ButtonPanel, ExtCtrls, EditBtn, StdCtrls, Classes,
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
    EdMaturity: TComboBox;
    EdSection: TComboBox;
    EdDescription: TLabeledEdit;
    EdInstallerPath: TFileNameEdit;
    EdSilentFlags: TLabeledEdit;
    EdUninstallKey: TLabeledEdit;
    EdVersion: TLabeledEdit;
    LabSetupFilename: TLabel;
    EdPackageName: TLabeledEdit;
    LabArcgitecture: TLabel;
    LabSection: TLabel;
    LabMaturity: TLabel;
    Panel1: TPanel;
    Panel2: TPanel;
    Panel3: TPanel;
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

uses Dialogs,dmwaptpython,superobject,uWaptRes,uWaptConsoleRes,waptcommon,
  VarPyth, uWaptPythonUtils,tisstrings;

{$R *.lfm}

{ TVisPackageWizard }

procedure TVisPackageWizard.EdInstallerPathAcceptFileName(Sender: TObject;
  var Value: String);
begin
  InstallerFilename:=Value;
end;

procedure TVisPackageWizard.FormCreate(Sender: TObject);
begin
  EdMaturity.Text:=DefaultMaturity;
end;

operator in (const x: String;const y: Array of String):Boolean;
begin
  Result := StrIsOneOf(x,y);
end;

procedure TVisPackageWizard.ActMakeUploadUpdate(Sender: TObject);
begin
  ActMakeUpload.Enabled := StrIsOneOf(ExtractFileExt(FInstallerFilename),['.msi','.msu'])
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
  packageSources,PackageName,Version,Description,Section,UninstallKey,Maturity,
    Architecture: Variant;
  wapt,SilentFlags,VWaptServerPassword,VInstallerFilename:Variant;
  UploadResult : ISuperObject;
begin
  Screen.cursor := crHourGlass;
  if EdSilentFlags.Text <>'' then
    SilentFlags:= EdSilentFlags.Text
  else
    SilentFlags := None();

  EdPackageName.Text := MakeValidPackageName(EdPackageName.Text);

  try
    wapt := dmpython.WAPT;
    Version := EdVersion.Text;
    PackageName := PyUTF8Decode(EdPackageName.Text);
    Description := PyUTF8Decode(EdDescription.Text);
    UninstallKey := PyUTF8Decode(EdUninstallKey.Text);
    Section :=  PyUTF8Decode(EdSection.Text);
    Architecture :=  PyUTF8Decode(EdArchitecture.Text);
    Maturity := PyUTF8Decode(EdMaturity.Text);;

    VInstallerFilename := PyUTF8Decode(InstallerFilename);
    VWaptServerPassword := PyUTF8Decode(WaptServerPassword);

    packageSources := VarPythonAsString(wapt.make_package_template(
      installer_path := VInstallerFilename,
      packagename :=PackageName,
      description := Description,
      version := Version,
      uninstallkey := UninstallKey,
      silentflags := SilentFlags,
      maturity := Maturity,
      section := Section,
      architecture := Architecture));

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
        wapt_server_passwd := VWaptServerPassword,
        inc_package_release := True));

      if (uploadResult.AsArray=nil) or (uploadResult.AsArray.Length <=0) then
        raise Exception.CreateFmt(rsErrorBuildingUploadPackage,[packageSources]);
      ShowMessageFmt(rsPackageBuiltSourcesAvailable,[packageSources]);
      ModalResult := mrOk;
    end;
  finally
    Screen.cursor := crDefault;
  end
end;

procedure TVisPackageWizard.SetInstallerFilename(AValue: String);
var
  installInfos:ISUperObject;
  VInstallerPath:Variant;
begin
  if FInstallerFilename=AValue then Exit;
  FInstallerFilename:=AValue;
  EdInstallerPath.FileName:=FInstallerFilename;
  if (AValue <> '') and FileExistsUTF8(AValue) then
  begin
    VInstallerPath:=UTF8Decode(AValue);
    installInfos := PyVarToSuperObject(DMPython.setuphelpers.get_installer_defaults(VInstallerPath));
    EdPackageName.text := MakeValidPackageName(DefaultPackagePrefix+'-'+installInfos.S['simplename']);
    EdDescription.Text := UTF8Encode(installInfos.S['description']);
    EdVersion.Text := installInfos.S['version'];
    EdSilentFlags.Text := installInfos.S['silentflags'];
    EdUninstallKey.Text := installInfos.S['uninstallkey'];
  end;
end;

end.

