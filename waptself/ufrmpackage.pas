unit uFrmPackage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, ExtCtrls, BCListBox,
  BCLabel,BCMaterialDesignButton,FXProgressBar,superobject,waptcommon;

type

  { TFrmPackage }

  TFrmPackage = class(TFrame)
    BtnInstallUpgrade: TBCMaterialDesignButton;
    BtnRemove: TBCMaterialDesignButton;
    BCPaperPanel1: TBCPaperPanel;
    FXProgressBarInstall: TFXProgressBar;
    ImgPackage: TImage;
    LabDescription: TBCLabel;
    LabelProgressionInstall: TBCLabel;
    LabInstallVersion: TBCLabel;
    LabPackageName: TBCLabel;
    LabVersion: TBCLabel;
    LabMaintainer: TBCLabel;
    TextWaitInstall: TStaticText;
    TimerInstallRemoveFinished: TTimer;
    procedure ActInstallUpgradePackage(Sender: TObject);
    procedure ActRemovePackage(Sender: TObject);
    procedure ActTimerInstallRemoveFinished(Sender: TObject);
  private
    function LaunchActionPackage(ActionPackage:String;Package:ISuperObject):ISuperObject;
  public
    Package : ISuperObject;
    Task : ISuperObject;
    login : String;
    password : String;
    OnLocalServiceAuth : THTTPSendAuthorization;
    ActionPackage : String;
    constructor Create(TheOwner: TComponent); override;
    procedure AdjustFont(ALabel:TBCLabel);
  end;

implementation
uses Graphics,BCTools;
{$R *.lfm}

{ TFrmPackage }

procedure TFrmPackage.ActInstallUpgradePackage(Sender: TObject);
begin
  Task:=LaunchActionPackage(ActionPackage,Package);
  BtnInstallUpgrade.Enabled:=false;
  BtnInstallUpgrade.NormalColor:=$00C4C4C4;
  TextWaitInstall.Caption:='Waiting for install...';
  TextWaitInstall.Show;
end;

procedure TFrmPackage.ActRemovePackage(Sender: TObject);
begin
  Task:=LaunchActionPackage('remove',Package).O['0'];
  ActionPackage:='remove';
  BtnRemove.Enabled:=false;
  BtnRemove.NormalColor:=$00C4C4C4;
  TextWaitInstall.Caption:='Waiting for uninstall...';
  TextWaitInstall.Show;
end;

procedure TFrmPackage.ActTimerInstallRemoveFinished(Sender: TObject);
begin
  if (ActionPackage='remove') then
  begin
    BtnInstallUpgrade.Caption:='Install';
    BtnInstallUpgrade.NormalColor:=clGreen;
    BtnInstallUpgrade.Enabled:=true;
    ActionPackage:='install';
  end
  else
  begin
    BtnRemove.NormalColor:=clRed;
    BtnRemove.Enabled:=true;
    ActionPackage:='remove';
    BtnInstallUpgrade.Caption:='Installed';
  end;
  FXProgressBarInstall.Value:=0;
  FXProgressBarInstall.Hide;
  LabelProgressionInstall.Caption:='0%';
  LabelProgressionInstall.Hide;
  TimerInstallRemoveFinished.Enabled:=false;
end;

function TFrmPackage.LaunchActionPackage(ActionPackage:String;Package: ISuperObject): ISuperObject;
begin
  Result:=WAPTLocalJsonGet(format('%s.json?package=%s',[ActionPackage,Package.S['package']]),login,password,-1,OnLocalServiceAuth,2);
end;

constructor TFrmPackage.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  FXProgressBarInstall.Hide;
  TimerInstallRemoveFinished.Enabled:=false;
end;

procedure TFrmPackage.AdjustFont(ALabel: TBCLabel);
var
  PreferredWidth, PreferredHeight: integer;
  newfs:Integer;
begin
  With ALabel  do
  begin
    CalculateTextSize(Caption, FontEx, PreferredWidth, PreferredHeight);
    if FontEx.WordBreak then
    begin
      if (PreferredHeight > Height) then
        newfs := (Height  * FontEx.Height) div PreferredHeight
      else
        newfs := FontEx.Height;
    end
    else
    begin
      if (PreferredWidth > Width) then
        newfs := (Width  * FontEx.Height) div PreferredWidth
      else
        newfs := FontEx.Height;
    end;

    if newfs <> FontEx.Height then
      FontEx.Height := newfs;
  end;
end;

end.

