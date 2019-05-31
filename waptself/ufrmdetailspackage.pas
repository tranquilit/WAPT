unit uFrmDetailsPackage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, ExtCtrls, StdCtrls, LCLIntf, Graphics;

type

  { TFrmDetailsPackage }

  TFrmDetailsPackage = class(TFrame)
    ImgPackage: TImage;
    Editor: TLabel;
    LabDependency: TLabel;
    LabConflicts: TLabel;
    LabSignatureDate: TLabel;
    LabSection: TLabel;
    LabCategories: TLabel;
    LabSigner: TLabel;
    LabPackageName: TLabel;
    LabSize: TLabel;
    LabSizeInstalled: TLabel;
    LabRepository: TLabel;
    Dependency: TLabel;
    Conflicts: TLabel;
    SignatureDate: TLabel;
    Section: TLabel;
    PanelDetails: TPanel;
    Categories: TLabel;
    Signer: TLabel;
    PackageName: TLabel;
    Size: TLabel;
    LabMaintainer: TLabel;
    Maintainer: TLabel;
    LabLicence: TLabel;
    LabEditor: TLabel;
    LabLastVersion: TLabel;
    LabImpactedProcess: TLabel;
    LabOfficialWebsite: TLabel;
    LabDescription: TLabel;
    LastVersion: TLabel;
    ImpactedProcess: TLabel;
    OfficialWebsite: TLabel;
    Description: TLabel;
    LabName: TLabel;
    Licence: TLabel;
    SizeInstalled: TLabel;
    Repository: TLabel;
    procedure LabOfficialWebsiteClick(Sender: TObject);
    procedure LabOfficialWebsiteMouseEnter(Sender: TObject);
    procedure LabOfficialWebsiteMouseLeave(Sender: TObject);
    procedure PanelDetailsPaint(Sender: TObject);
  private

  public
  end;

implementation

{$R *.lfm}

{ TFrmDetailsPackage }

procedure TFrmDetailsPackage.LabOfficialWebsiteClick(Sender: TObject);
begin
  OpenDocument(LabOfficialWebsite.Caption);
end;

procedure TFrmDetailsPackage.LabOfficialWebsiteMouseEnter(Sender: TObject);
begin
  if (LabOfficialWebsite.Caption<>'') then
  begin
    LabOfficialWebsite.Font.Color:=clHighlight;
    Screen.Cursor:=crHandPoint;
  end;
end;

procedure TFrmDetailsPackage.LabOfficialWebsiteMouseLeave(Sender: TObject);
begin
  LabOfficialWebsite.Font.Color:=clDefault;
  Screen.Cursor:=crDefault;
end;

procedure TFrmDetailsPackage.PanelDetailsPaint(Sender: TObject);
begin
  LabName.AdjustFontForOptimalFill;
end;

end.

