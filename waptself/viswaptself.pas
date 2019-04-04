unit VisWaptSelf;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  EditBtn, StdCtrls, Buttons, SearchEdit, AdvancedLabel, BCListBox,
  BCMaterialDesignButton, BCLabel, FXMaterialButton, FXProgressBar;

type

  { TForm1 }

  TForm1 = class(TForm)
    BCLabel1: TBCLabel;
    EdSearch: TEditButton;
    FlowPackages: TFlowPanel;
    Panel1: TPanel;
    Panel2: TPanel;
    Panel7: TPanel;
    ScrollBox1: TScrollBox;
    procedure EdSearchButtonClick(Sender: TObject);
    procedure EdSearchKeyPress(Sender: TObject; var Key: char);
    procedure FormCreate(Sender: TObject);
  private

  public
    LstIcons: TStringList;
  end;

var
  Form1: TForm1;

implementation
uses uFrmPackage,waptcommon,superobject;
{$R *.lfm}

{ TForm1 }

procedure TForm1.EdSearchButtonClick(Sender: TObject);
var
  packages,package:ISuperObject;
  AFrmPackage:TFrmPackage;
  Idx,IconIdx:Integer;
  g: TBitmap;
begin
  try
    Screen.Cursor:=crHourGlass;
    FlowPackages.DisableAlign;

    for idx := FlowPackages.ControlCount-1 downto 0 do
      FlowPackages.Controls[Idx].Free;
    FlowPackages.ControlList.Clear;
    packages := WAPTLocalJsonGet(Format('packages.json?q=%s&latest=1',[EdSearch.Text]),'admin','calimero');
    idx := 0;
    for package in packages do
    begin
      AFrmPackage := TFrmPackage.Create(FlowPackages);
      AFrmPackage.Parent := FlowPackages;
      //AFrmPackage.Show;
      AFrmPackage.Name:='package'+IntToStr(idx) ;
      AFrmPackage.LabPackageName.Caption:=package.S['package'];
      AFrmPackage.AdjustFont(AFrmPackage.LabPackageName);
      AFrmPackage.LabVersion.Caption:=package.S['version'];
      AFrmPackage.AdjustFont(AFrmPackage.LabVersion);
      AFrmPackage.LabDescription.Caption:=package.S['description'];
      //AFrmPackage.AdjustFont(AFrmPackage.LabDescription);

      AFrmPackage.LabMaintainer.Caption:='by '+package.S['maintainer'];
      AFrmPackage.AdjustFont(AFrmPackage.LabMaintainer);

      IconIdx := LstIcons.IndexOf(package.S['package']+'.png');
      if IconIdx<0 then
        IconIdx:=LstIcons.IndexOf('unknown.png');

      if IconIdx>=0 then;
        AFrmPackage.ImgPackage.Picture.Assign(LstIcons.Objects[IconIdx] as TPicture);

      if (package.S['install_status'] = 'OK') then
        if (package.S['install_version'] = package.S['version']) then
          with AFrmPackage  do
          begin
            BCMaterialDesignButton1.Caption:='Installed';
            BCMaterialDesignButton1.NormalColor:=clGreen;
          end
        else
          with AFrmPackage  do
          begin
            BCMaterialDesignButton1.Caption:='Upgrade';
            BCMaterialDesignButton1.NormalColor:=$004080FF;
            AFrmPackage.LabInstallVersion.Caption:='(over '+package.S['install_version']+')';
            AFrmPackage.AdjustFont(AFrmPackage.LabInstallVersion);
            AFrmPackage.LabInstallVersion.Visible:=True;
          end;


      inc(idx);
    end;
  finally
    FlowPackages.EnableAlign;
    Screen.Cursor:=crDefault;
  end;
end;

procedure TForm1.EdSearchKeyPress(Sender: TObject; var Key: char);
begin
  if Key = #13 then
  begin
    EdSearch.SelectAll;
    EdSearchButtonClick(Sender);
  end;
end;

procedure TForm1.FormCreate(Sender: TObject);
var
  i:integer;
  g:TPicture;
begin
  LstIcons := FindAllFiles('c:\wapt\cache\icons','*.png',False);
  for i := 0 to LstIcons.Count-1 do
    try
      g := TPicture.Create;
      g.LoadFromFile(LstIcons[i]);
      LstIcons.Objects[i] := g;
      LstIcons[i] := ExtractFileName(LstIcons[i]);
    except

    end;
end;

{ TForm1 }

end.

