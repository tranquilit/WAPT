unit uVisPackageWizard;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, SynEdit, Forms, Controls, Graphics, Dialogs,
  ButtonPanel, ExtCtrls, EditBtn, StdCtrls;

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

uses dmwaptpython,superobject,waptcommon;

{$R *.lfm}

{ TVisPackageWizard }

procedure TVisPackageWizard.EdInstallerPathAcceptFileName(Sender: TObject;
  var Value: String);
begin
  InstallerFilename:=Value;
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
    installInfos := DMPython.RunJSON(Format('setuphelpers.get_installer_defaults(r"%s")',[AValue]));
    EdPackageName.text := DefaultPackagePrefix+'-'+installInfos.S['simplename'];
    EdDescription.Text := installInfos.S['description'];
    EdVersion.Text := installInfos.S['version'];
    EdSilentFlags.Text := installInfos.S['silentflags'];
    EdUninstallKey.Text := installInfos.S['uninstallkey'];
  end;
end;

end.

