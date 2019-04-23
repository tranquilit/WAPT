unit uFrmPackage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, ExtCtrls, BCListBox,
  BCLabel, BCMaterialDesignButton, BGRAFlashProgressBar, superobject,
  waptcommon;

type

  { TFrmPackage }

  TFrmPackage = class(TFrame)
    FXProgressBarInstall: TBGRAFlashProgressBar;
    BtnInstallUpgrade: TBCMaterialDesignButton;
    BtnRemove: TBCMaterialDesignButton;
    BCPaperPanel1: TBCPaperPanel;
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
    function Impacted_process():boolean;
    function Accept_Impacted_process():boolean;
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
uses Graphics,BCTools,JwaTlHelp32, Windows,uVisImpactedProcess;
{$R *.lfm}

{ TFrmPackage }

procedure TFrmPackage.ActInstallUpgradePackage(Sender: TObject);
begin
  if Accept_Impacted_process() then
  begin
    Task:=LaunchActionPackage(ActionPackage,Package);
    BtnInstallUpgrade.Enabled:=false;
    BtnInstallUpgrade.NormalColor:=$00C4C4C4;
    TextWaitInstall.Caption:='Waiting for install...';
    TextWaitInstall.Show;
  end;
end;

procedure TFrmPackage.ActRemovePackage(Sender: TObject);
begin
  if Accept_Impacted_process() then
  begin
    Task:=LaunchActionPackage('remove',Package).O['0'];
    ActionPackage:='remove';
    BtnRemove.Enabled:=false;
    BtnRemove.NormalColor:=$00C4C4C4;
    TextWaitInstall.Caption:='Waiting for uninstall...';
    TextWaitInstall.Show;
  end;
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

function TFrmPackage.Impacted_process(): boolean;
var
  ContinueLoop: boolean;
  FSnapshotHandle: THandle;
  FProcessEntry32: TProcessEntry32;
  ExeFileName:String;
  ListExe:TStringList;
begin
  FSnapshotHandle := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  FProcessEntry32.dwSize := SizeOf(FProcessEntry32);
  ContinueLoop := Process32First(FSnapshotHandle, FProcessEntry32);
  Result:=False;
  ListExe:=TStringList.Create;
  ListExe.Delimiter:=',';
  ListExe.DelimitedText:=UTF8Encode(Package.S['impacted_process']);

  while ContinueLoop do
  begin
    for ExeFileName in ListExe do
      if ((UpperCase(ExtractFileName(FProcessEntry32.szExeFile)) = UpperCase(Trim(ExeFileName))) or (UpperCase(FProcessEntry32.szExeFile) = UpperCase(Trim(ExeFileName)))) then
      begin
        ListExe.Free;
        CloseHandle(FSnapshotHandle);
        Exit(True);
      end;
    ContinueLoop:=Process32Next(FSnapshotHandle,FProcessEntry32);
  end;
  ListExe.Free;
  CloseHandle(FSnapshotHandle);
end;

function TFrmPackage.Accept_Impacted_process(): boolean;
var
  VisImpactedProcess : TImpactedProcess;
begin
  if Impacted_process()=false then
    Exit(True)
  else
  begin
    VisImpactedProcess:=TImpactedProcess.Create(Self);
    VisImpactedProcess.ShowListProcesses(UTF8Encode(Package.S['impacted_process']));
    if VisImpactedProcess.ShowModal=mrOk then
    begin
      VisImpactedProcess.Free;
      Exit(true);
    end
    else
    begin
      VisImpactedProcess.Free;
      Exit(False);
    end;
  end;
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

