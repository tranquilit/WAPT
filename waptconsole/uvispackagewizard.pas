unit uVisPackageWizard;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Forms, Controls,
  ButtonPanel, ExtCtrls, EditBtn, StdCtrls, Classes,DefaultTranslator;

type

  { TVisPackageWizard }

  TVisPackageWizard = class(TForm)
    ButtonPanel1: TButtonPanel;
    EdArchitecture: TComboBox;
    EdDescription: TLabeledEdit;
    EdInstallerPath: TFileNameEdit;
    EdSilentFlags: TLabeledEdit;
    EdUninstallKey: TLabeledEdit;
    EdVersion: TLabeledEdit;
    Label1: TLabel;
    EdPackageName: TLabeledEdit;
    Label2: TLabel;
    Panel1: TPanel;
    procedure EdInstallerPathAcceptFileName(Sender: TObject; var Value: String);
    procedure FormCreate(Sender: TObject);
    procedure HelpButtonClick(Sender: TObject);
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

uses dmwaptpython,superobject,uWaptRes,uWaptConsoleRes,waptcommon,UScaleDPI;

{$R *.lfm}

{ TVisPackageWizard }

procedure TVisPackageWizard.EdInstallerPathAcceptFileName(Sender: TObject;
  var Value: String);
begin
  InstallerFilename:=Value;
end;

procedure TVisPackageWizard.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
  //ScaleImageList(ImageList1,96);
  //ScaleImageList(ActionsImages,96);

end;

procedure TVisPackageWizard.HelpButtonClick(Sender: TObject);
begin
  ModalResult:=mrYes;
end;

procedure TVisPackageWizard.SetInstallerFilename(AValue: String);
var
  installInfos,sores:ISUperObject;
begin
  if FInstallerFilename=AValue then Exit;
  FInstallerFilename:=AValue;
  EdInstallerPath.FileName:=FInstallerFilename;
  if (AValue <> '') and FileExists(AValue) then
  begin
    installInfos := DMPython.RunJSON(Format('setuphelpers.get_installer_defaults(r"%s".decode("utf8"))',[AValue]));
    EdPackageName.text := DefaultPackagePrefix+'-'+installInfos.S['simplename'];
    EdDescription.Text := UTF8Encode(installInfos.S['description']);
    EdVersion.Text := installInfos.S['version'];
    EdSilentFlags.Text := installInfos.S['silentflags'];
    EdUninstallKey.Text := installInfos.S['uninstallkey'];

    ButtonPanel1.HelpButton.Enabled:= ExtractFileExt(FInstallerFilename) ='.msi';
  end;
end;

end.

